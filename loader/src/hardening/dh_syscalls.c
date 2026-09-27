// Direct-syscall resolver (SysWhispers2-style) for one hot API:
// NtQuerySystemInformation. Called by dh_rpm to fetch ntoskrnl base — the
// telltale "external cheat" syscall. Bypassing any user-mode ntdll hook
// removes the most reliable behavior signature Defender/EDR watch for.
//
// Resolution: parse ntdll's IMAGE_EXPORT_DIRECTORY, gather every Nt* export
// with its RVA, sort by RVA. The nth entry's syscall number is n (a stable
// property of ntdll layout on x64 Windows since Vista).

#include "../../inc/dh_common.h"
#include <windows.h>
#include <string.h>

// Symbol read by dh_syscalls.asm — patched at DhInitSyscalls().
DWORD g_ssn_NtQSI = 0;

// x64 stub is defined in dh_syscalls.asm.
extern NTSTATUS DhDirectNtQuerySystemInformation(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength);

typedef struct { DWORD rva; const char* name; } NtEntry;

// qsort comparator — ascending RVA.
static int cmp_rva(const void* a, const void* b)
{
    DWORD ra = ((const NtEntry*)a)->rva;
    DWORD rb = ((const NtEntry*)b)->rva;
    return (ra < rb) ? -1 : (ra > rb) ? 1 : 0;
}

void DhInitSyscalls(void)
{
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return;

    BYTE* base = (BYTE*)ntdll;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;

    DWORD expRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!expRva) return;
    PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)(base + expRva);
    DWORD* names   = (DWORD*)(base + exp->AddressOfNames);
    WORD*  ordinals= (WORD*) (base + exp->AddressOfNameOrdinals);
    DWORD* funcs   = (DWORD*)(base + exp->AddressOfFunctions);

    // Gather all Nt* exports (excluding Ntdll* and other prefixes).
    NtEntry* list = (NtEntry*)HeapAlloc(GetProcessHeap(), 0,
                                        sizeof(NtEntry) * exp->NumberOfNames);
    if (!list) return;
    DWORD n = 0;
    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        const char* nm = (const char*)(base + names[i]);
        // Match "Nt" then uppercase letter (Nt* stubs, not Ntdll*).
        if (nm[0] == 'N' && nm[1] == 't' &&
            nm[2] >= 'A' && nm[2] <= 'Z') {
            list[n].rva  = funcs[ordinals[i]];
            list[n].name = nm;
            n++;
        }
    }

    // Sort ascending by RVA. Syscall # = position in sorted list on x64 Windows.
    qsort(list, n, sizeof(NtEntry), cmp_rva);

    for (DWORD i = 0; i < n; i++) {
        if (strcmp(list[i].name, "NtQuerySystemInformation") == 0) {
            g_ssn_NtQSI = i;
            break;
        }
    }

    HeapFree(GetProcessHeap(), 0, list);
}

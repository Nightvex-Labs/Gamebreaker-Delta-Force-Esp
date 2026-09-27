// DeltaHack — runtime PE-header sanitizer (implementation).
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "../inc/dh_mz_wipe.h"

int DhWipeOwnPeHeaders(void)
{
    HMODULE base = GetModuleHandleW(NULL);
    if (!base) return 0;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    LONG   nt_off  = dos->e_lfanew;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)base + nt_off);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

    // MINIMAL wipe: MZ signature (2 bytes) + PE\0\0 signature (4 bytes).
    // Do NOT wipe the full page — DataDirectory contains IMAGE_LOAD_CONFIG
    // (CFG function pointers used by CreateThread and every indirect call);
    // wiping it caused CreateThread → err=193 (ERROR_BAD_EXE_FORMAT) on
    // 25H2 with CFG-enforcing binaries.
    //
    // 6 bytes is enough to break "MZ..PE" pattern scanners in memory —
    // any Yara rule looking for those two magic numbers at page boundaries
    // misses. Everything CFG / unwind / RTTI needs stays intact.
    DWORD old_prot_dos = 0, old_prot_nt = 0;
    if (VirtualProtect((LPVOID)&dos->e_magic, 2, PAGE_READWRITE, &old_prot_dos)) {
        dos->e_magic = 0;   // "MZ" -> 0
        VirtualProtect((LPVOID)&dos->e_magic, 2, old_prot_dos, &old_prot_dos);
    }
    if (VirtualProtect((LPVOID)&nt->Signature, 4, PAGE_READWRITE, &old_prot_nt)) {
        nt->Signature = 0;  // "PE\0\0" -> 0
        VirtualProtect((LPVOID)&nt->Signature, 4, old_prot_nt, &old_prot_nt);
    }
    return 1;
}

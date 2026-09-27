#include "../../inc/dh_rpm.h"
#include "../../inc/dh_phys.h"
#include "../../inc/dh_vmprotect.h"
#include <windows.h>

// Cached System EPROCESS pointer (PsInitialSystemProcess). Populated by
// RpmFindProcess on first successful walk; consumed by RpmHideOwnProcess.
u64 g_rpm_psisp = 0;

// Direct-syscall exports (see src/hardening/dh_syscalls.{asm,c}).
extern DWORD g_ssn_NtQSI;
extern NTSTATUS DhDirectNtQuerySystemInformation(ULONG, PVOID, ULONG, PULONG);

#define PHY_MASK          0x000FFFFFFFFFF000ull
#define PHY_MASK_1G       0x000FFFFFC0000000ull
#define PHY_MASK_2M       0x000FFFFFFFE00000ull
#define VA_MASK_1G        0x000000003FFFFFFFull
#define VA_MASK_2M        0x00000001FFFFFull
#define VA_MASK_4K        0x0000000000000FFFull
#define PTE_PRESENT       1ull
#define PTE_LARGE_PAGE    0x80ull

// ---- CR3 discovery via PROCESSOR_START_BLOCK in first 1MB ----

// PROCESSOR_START_BLOCK signature: E9 xx 06 00 01 00 00 00
// Mask: 0xffffffffffff00ff, Value: 0x00000001000600E9
#define PSB_SIG_MASK  0xFFFFFFFFFFFF00FFull
#define PSB_SIG_VAL   0x00000001000600E9ull

// Offsets within PROCESSOR_START_BLOCK (x64, Win10+):
// LmTarget = 0x70, ProcessorState.SpecialRegisters.Cr3 varies by build.
// Safe approach: ProcessorState starts after SelfMap+MsrPat+MsrEFER.
// Known offset of Cr3 within the block: computed from struct layout.
// On Win11 24H2/25H2 (26100/26200), the PSB CR3 offset = 0xC0.
// Cross-reference: MemProcFS vmmwininit.c uses PSB+0xA0 for older builds,
// newer builds shifted to 0xC0 due to added fields.
// We try both offsets.

static u64 TryPSBCr3(const u8* page, u32 offset)
{
    u64 val = *(const u64*)(page + offset);
    // CR3 must be page-aligned and in low physical range (< 512 GB)
    if ((val & 0xFFF) == 0 && val != 0 && val < 0x8000000000ull)
        return val;
    return 0;
}

BOOL RpmFindSystemCR3(HANDLE hDev, u64* cr3Out)
{
    VMProtectBeginUltra("RpmFindSystemCR3");
    *cr3Out = 0;

    // Map first 1MB physical
    u8* buf = (u8*)HeapAlloc(GetProcessHeap(), 0, 0x100000);
    if (!buf) { VMProtectEnd(); return FALSE; }

    BOOL ok = PhysRead(hDev, 0, buf, 0x100000);
    if (!ok) {
        HeapFree(GetProcessHeap(), 0, buf);
        DH_ERROR("failed to read first 1MB physical");
        VMProtectEnd();
        return FALSE;
    }

    u64 cr3 = 0;
    for (u32 off = 0x1000; off < 0x100000; off += 0x1000) {
        u64 sig = *(u64*)(buf + off);
        if ((sig & PSB_SIG_MASK) != PSB_SIG_VAL)
            continue;

        // Validate LmTarget is a canonical kernel address
        u64 lmTarget = *(u64*)(buf + off + 0x70);
        if ((lmTarget >> 47) != 0x1FFFF && (lmTarget >> 47) != 0x0)
            continue; // not canonical

        // Try known CR3 offsets
        static const u32 cr3_offsets[] = { 0xA0, 0xC0, 0xB0 };
        for (u32 i = 0; i < DH_ARR_LEN(cr3_offsets); i++) {
            cr3 = TryPSBCr3(buf + off, cr3_offsets[i]);
            if (cr3) {
                DH_INFO("CR3 found at PSB+0x%X: 0x%llX (stub @ phys 0x%X)",
                        cr3_offsets[i], cr3, off);
                break;
            }
        }
        if (cr3) break;
    }

    HeapFree(GetProcessHeap(), 0, buf);
    if (!cr3) {
        DH_ERROR("no valid CR3 found in low stub");
        VMProtectEnd();
        return FALSE;
    }
    *cr3Out = cr3;
    VMProtectEnd();
    return TRUE;
}

// ---- Page walk: PML4 → PDPT → PD → PT ----

BOOL RpmVirtToPhys(HANDLE hDev, u64 cr3, u64 va, u64* paOut)
{
    *paOut = 0;
    u64 table = cr3 & PHY_MASK;

    for (int level = 0; level < 4; level++) {
        int shift = 39 - level * 9;
        u64 idx = (va >> shift) & 0x1FF;
        u64 entry = 0;

        if (!PhysRead(hDev, table + idx * 8, &entry, 8))
            return FALSE;

        if (!(entry & PTE_PRESENT))
            return FALSE;

        table = entry & PHY_MASK;

        if (entry & PTE_LARGE_PAGE) {
            if (shift == 30) { // 1GB page
                *paOut = (entry & PHY_MASK_1G) + (va & VA_MASK_1G);
                return TRUE;
            }
            if (shift == 21) { // 2MB page
                *paOut = (entry & PHY_MASK_2M) + (va & VA_MASK_2M);
                return TRUE;
            }
        }
    }

    // 4KB page
    *paOut = table + (va & VA_MASK_4K);
    return TRUE;
}

// ---- Read virtual memory ----

// VA→PA translation cache. Each hit saves 4 page-table PhysReads (= 8 IOCTLs).
// Keyed by (cr3 << 12) ^ (va & ~0xFFF). Generation-based invalidation — cache
// valid only within one main-tick generation. Caller bumps g_rpm_generation
// at tick start to invalidate. No race conditions possible within a generation
// since PT walks are deterministic for a given (cr3, va) at any single moment.
#define VA_PA_CACHE_SLOTS 4096
volatile u64 g_rpm_generation = 1;
static struct { u64 key; u64 pa_page; u64 gen; } g_vapa_cache[VA_PA_CACHE_SLOTS] = {0};

void RpmBumpGeneration(void) {
    g_rpm_generation++;
    if (g_rpm_generation == 0) g_rpm_generation = 1;   // never 0
}

BOOL RpmReadVirtual(HANDLE hDev, u64 cr3, u64 va, void* buf, u32 size)
{
    u8* dst = (u8*)buf;
    u32 remaining = size;

    while (remaining > 0) {
        u32 pageOff = (u32)(va & 0xFFF);
        u32 chunk   = 0x1000 - pageOff;
        if (chunk > remaining) chunk = remaining;

        // VA→PA cache lookup — key by cr3 + page-aligned VA.
        u64 va_page = va & ~0xFFFULL;
        u64 key = (cr3 << 12) ^ va_page;
        u32 slot = (u32)((key * 0x9E3779B97F4A7C15ULL) >> 52) & (VA_PA_CACHE_SLOTS - 1);
        u64 pa = 0;
        u64 cur_gen = g_rpm_generation;
        // Double-check pattern — read key/gen twice to defend against
        // concurrent writer torn read.
        u64 k1 = g_vapa_cache[slot].key;
        u64 pa_page = g_vapa_cache[slot].pa_page;
        u64 g1 = g_vapa_cache[slot].gen;
        u64 k2 = g_vapa_cache[slot].key;
        if (k1 == key && k1 == k2 && g1 == cur_gen) {
            pa = pa_page | pageOff;
        } else {
            if (!RpmVirtToPhys(hDev, cr3, va, &pa))
                return FALSE;
            g_vapa_cache[slot].key     = key;
            g_vapa_cache[slot].pa_page = pa & ~0xFFFULL;
            g_vapa_cache[slot].gen     = cur_gen;
        }
        if (!PhysRead(hDev, pa, dst, chunk))
            return FALSE;

        dst       += chunk;
        va        += chunk;
        remaining -= chunk;
    }
    return TRUE;
}

// Virtual-write mirror — walks page tables per VA, splits per-page write.
// Only used for kernel-space writes (PID unlink, handle strip, etc).
BOOL RpmWriteVirtual(HANDLE hDev, u64 cr3, u64 va, const void* buf, u32 size)
{
    const u8* src = (const u8*)buf;
    u32 remaining = size;

    while (remaining > 0) {
        u32 pageOff = (u32)(va & 0xFFF);
        u32 chunk   = 0x1000 - pageOff;
        if (chunk > remaining) chunk = remaining;

        u64 pa = 0;
        if (!RpmVirtToPhys(hDev, cr3, va, &pa))
            return FALSE;
        if (!PhysWrite(hDev, pa, src, chunk))
            return FALSE;

        src       += chunk;
        va        += chunk;
        remaining -= chunk;
    }
    return TRUE;
}

// ---- EPROCESS walk ----

// EPROCESS offsets vary by Windows build. Germanium (24H2/25H2) did a major
// layout realign — Cobalt/Nickel (22H2/23H2) uses a very different set.
// Source: Vergilius Project (Microsoft PDB).
//
// KPROCESS.DirectoryTableBase is stable at 0x28 across every x64 build from
// Vista through 25H2 (KPROCESS header layout hasn't shifted). Everything else
// moves.

typedef struct {
    u32 min_build;
    u32 max_build;
    u32 dtb;         // KPROCESS.DirectoryTableBase
    u32 pid;         // EPROCESS.UniqueProcessId
    u32 links;       // EPROCESS.ActiveProcessLinks (LIST_ENTRY)
    u32 imgname;     // EPROCESS.ImageFileName (15-char)
    u32 peb_default; // EPROCESS.Peb — starting guess; DiscoverPebOffset() may refine
    const char* label;
} DhEprocLayout;

static const DhEprocLayout kEprocLayouts[] = {
    // Cobalt / Nickel / Vibranium — pre-Germanium layout. Range covers common
    // LTSC / preview / SAC releases inside each named version so a patched
    // build like 22000.4123 doesn't kick the operator into "not in known-good
    // table" error even though the EPROCESS layout hasn't drifted.
    // Win10 20H1..22H2 (19041..19045) share the exact same EPROCESS layout
    // as Win11 21H2 (22000) — the kernel body was only realigned in Germanium
    // (24H2+), so the same DTB/PID/LINKS/IMGNAME/PEB offsets work verbatim.
    { 19041, 19045, 0x28, 0x440, 0x448, 0x5A8, 0x550, "Win10 20H1-22H2" },
    { 22000, 22000, 0x28, 0x440, 0x448, 0x5A8, 0x550, "Win11 21H2" },
    { 22621, 22621, 0x28, 0x440, 0x448, 0x5A8, 0x550, "Win11 22H2" },
    { 22631, 22631, 0x28, 0x440, 0x448, 0x5A8, 0x550, "Win11 23H2" },
    // Germanium — realigned layout (Win11 24H2 / 25H2 / 26H2).
    // Range 26100..30000 covers every current + upcoming Germanium build:
    //   26100  = 24H2 initial   (PID=0x1D0 LINKS=0x1D8 PEB=0x2E0 — verified)
    //   26200  = 25H2 launch    (PID=0x1D0 LINKS=0x1D8 PEB=0x2E0 — verified)
    //   28000  = 26H2 preview   (PID=0x1D0 LINKS=0x1D8 PEB=0x2E0 — verified)
    //   catch-all up to 30000 for KB updates & Insider drift.
    // Source: github.com/I3r1h0n/eprocess_offsets + live probe on client
    // machines (DiscoverPebOffset returned +0x2E0 on 26100 + 26200).
    // DTB (KPROCESS.DirectoryTableBase) = 0x28 has been stable since Vista.
    // ImageFileName = 0x338 across Germanium (private probe on 26200 client).
    // DiscoverPebOffset() is a belt-and-suspenders refinement — with the
    // correct default 0x2E0 baked here it becomes a no-op instead of the
    // fallback lookup path.
    { 26100, 30000, 0x28, 0x1D0, 0x1D8, 0x338, 0x2E0, "Win11 24H2/25H2/26H2" },
};

// Populated by EprocInit() on first RpmFindProcess. Zero = uninitialised.
static u32 g_eproc_dtb     = 0;
static u32 g_eproc_pid     = 0;
static u32 g_eproc_links   = 0;
static u32 g_eproc_imgname = 0;

// EPROCESS.Peb offset varies per build (26100=0x550, 26200 may differ, 22H2
// nominally 0x550 as well). Starting guess is set by EprocInit(), then
// DiscoverPebOffset() refines by walking to OUR OWN EPROCESS and matching
// gs:[0x60].
u32 g_eproc_peb_off = 0x550;

// Reads OUR own PEB via TEB (gs:[0x60] on x64), returns non-zero on success.
static u64 GetOwnPeb(void) {
#if defined(_M_X64) || defined(__x86_64__)
    // NT_TIB.Self at gs:[0x30], PEB at gs:[0x60]
    return (u64)__readgsqword(0x60);
#else
    return 0;
#endif
}

// Walk EPROCESS list once, find OUR process by PID, scan offsets 0x300-0x700
// for one that matches our own known PEB. Caches into g_eproc_peb_off.
// Called lazily on first RpmFindProcess. Returns TRUE on success.
static BOOL DiscoverPebOffset(HANDLE hDev, u64 sysCR3, u64 psisp) {
    u64 our_peb = GetOwnPeb();
    u64 our_pid = (u64)GetCurrentProcessId();
    DH_INFO("DiscoverPebOffset: self PID=%llu PEB=0x%llX (via gs:[0x60])",
            our_pid, our_peb);
    if (!our_peb) {
        DH_ERROR("DiscoverPebOffset: own PEB via gs:[0x60] is 0 - cannot calibrate");
        return FALSE;
    }

    u64 head = psisp + g_eproc_links;
    u64 cur;
    if (!RpmRead64(hDev, sysCR3, head, &cur)) {
        DH_ERROR("DiscoverPebOffset: first flink read failed");
        return FALSE;
    }

    int count = 0;
    while (cur != head && count < 2048) {
        u64 eproc = cur - g_eproc_links;
        u64 pid = 0;
        RpmRead64(hDev, sysCR3, eproc + g_eproc_pid, &pid);
        if (pid == our_pid) {
            DH_INFO("DiscoverPebOffset: found self EPROCESS @ 0x%llX (scanned %d)",
                    eproc, count);
            // Scan wider — 25H2 may place PEB at 0x5A8 or higher
            for (u32 off = 0x200; off < 0xA00; off += 8) {
                u64 candidate = 0;
                if (RpmRead64(hDev, sysCR3, eproc + off, &candidate)
                    && candidate == our_peb) {
                    g_eproc_peb_off = off;
                    DH_INFO("DiscoverPebOffset: EPROCESS.Peb = +0x%X (matched self PEB=0x%llX)",
                            off, our_peb);
                    return TRUE;
                }
            }
            // Dump every 8-byte value in the plausible range so we see WHERE
            // our_peb landed (or if it landed at all)
            DH_WARN("DiscoverPebOffset: PEB=0x%llX not found in 0x200-0xA00 — dumping candidates:",
                    our_peb);
            for (u32 off = 0x200; off < 0xA00; off += 8) {
                u64 v = 0;
                if (RpmRead64(hDev, sysCR3, eproc + off, &v) &&
                    v > 0x00007FF000000000ULL && v < 0x00008000000000ULL) {
                    DH_INFO("  eproc+0x%03X = 0x%llX (user-space candidate)", off, v);
                }
            }
            return FALSE;
        }
        u64 flink = 0;
        if (!RpmRead64(hDev, sysCR3, cur, &flink) || flink == cur) break;
        cur = flink;
        count++;
    }
    DH_ERROR("DiscoverPebOffset: self PID=%llu not found in EPROCESS list (%d scanned)",
             our_pid, count);
    return FALSE;
}

// Fill g_eproc_* from the layout table for the running Windows build.
// Called lazily on first RpmFindProcess. Idempotent — re-calls short-circuit.
static BOOL EprocInit(void) {
    if (g_eproc_links) return TRUE;   // already initialised

    typedef LONG (WINAPI *pfnRtlGetVersion)(PRTL_OSVERSIONINFOW);
    pfnRtlGetVersion pRGV = (pfnRtlGetVersion)GetProcAddress(
        GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion");
    RTL_OSVERSIONINFOW vi = { sizeof(vi) };
    if (pRGV) pRGV(&vi);
    u32 build = vi.dwBuildNumber;

    for (int i = 0; i < (int)DH_ARR_LEN(kEprocLayouts); i++) {
        const DhEprocLayout* l = &kEprocLayouts[i];
        if (build >= l->min_build && build <= l->max_build) {
            g_eproc_dtb     = l->dtb;
            g_eproc_pid     = l->pid;
            g_eproc_links   = l->links;
            g_eproc_imgname = l->imgname;
            g_eproc_peb_off = l->peb_default;
            DH_INFO("EprocInit: %s (build=%u) — DTB=0x%X PID=0x%X LINKS=0x%X IMGNAME=0x%X PEB=0x%X",
                    l->label, build,
                    l->dtb, l->pid, l->links, l->imgname, l->peb_default);
            return TRUE;
        }
    }
    DH_ERROR("EprocInit: Windows build %u not in known-good table. "
             "Supported: Win10 20H1-22H2 (19041-19045), Win11 21H2/22H2/23H2/24H2/25H2 "
             "(22000, 22621, 22631, 26100, 26200). Add a row to kEprocLayouts for other builds.",
             (unsigned)build);
    return FALSE;
}

BOOL RpmFindProcess(HANDLE hDev, u64 sysCR3,
                    const char* procName, u64* procCR3, u64* eprocessOut)
{
    *procCR3 = 0;
    if (eprocessOut) *eprocessOut = 0;
    if (!EprocInit()) return FALSE;

    // Step 1: find PsInitialSystemProcess via ntoskrnl export
    // Simpler approach: use NtQuerySystemInformation to get ntoskrnl base,
    // then walk PE exports to find PsInitialSystemProcess, read via phys.

    // Get ntoskrnl base from SystemModuleInformation
    typedef struct {
        PVOID  Reserved[2];
        PVOID  Base;
        ULONG  Size;
        ULONG  Flags;
        USHORT Index;
        USHORT Unknown;
        USHORT LoadCount;
        USHORT NameOffset;
        CHAR   Name[256];
    } RTL_SYSTEM_MODULE;

    typedef struct {
        ULONG Count;
        RTL_SYSTEM_MODULE Modules[1];
    } RTL_SYSTEM_MODULES;

    typedef NTSTATUS (NTAPI *pfnNtQuerySystemInformation)(
        ULONG, PVOID, ULONG, PULONG);

    // Direct syscall stub (SysWhispers2-style) — bypasses ntdll wrapper so any
    // user-mode hook Defender / EDR installed on ntdll!NtQuerySystemInformation
    // never sees this call. Falls back to GetProcAddress if syscall # is
    // unresolved (empty ntdll — shouldn't happen but keep the safety net).
    pfnNtQuerySystemInformation pNtQSI = g_ssn_NtQSI
        ? (pfnNtQuerySystemInformation)DhDirectNtQuerySystemInformation
        : (pfnNtQuerySystemInformation)GetProcAddress(
              GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation");
    if (!pNtQSI) {
        DH_ERROR("NtQuerySystemInformation not found");
        return FALSE;
    }

    ULONG needed = 0;
    pNtQSI(11 /*SystemModuleInformation*/, NULL, 0, &needed);
    if (!needed) return FALSE;

    RTL_SYSTEM_MODULES* mods = (RTL_SYSTEM_MODULES*)HeapAlloc(
        GetProcessHeap(), HEAP_ZERO_MEMORY, needed);
    if (!mods) return FALSE;

    NTSTATUS st = pNtQSI(11, mods, needed, &needed);
    if (st < 0 || mods->Count == 0) {
        HeapFree(GetProcessHeap(), 0, mods);
        DH_ERROR("NtQuerySystemInformation(11) failed: 0x%lX", st);
        return FALSE;
    }

    u64 ntBase = (u64)mods->Modules[0].Base;
    DH_INFO("ntoskrnl base: 0x%llX", ntBase);
    HeapFree(GetProcessHeap(), 0, mods);

    // Step 2: read ntoskrnl PE to find PsInitialSystemProcess export
    IMAGE_DOS_HEADER dos;
    if (!RpmReadVirtual(hDev, sysCR3, ntBase, &dos, sizeof(dos)) ||
        dos.e_magic != IMAGE_DOS_SIGNATURE) {
        DH_ERROR("failed to read ntoskrnl DOS header");
        return FALSE;
    }

    IMAGE_NT_HEADERS64 nt;
    if (!RpmReadVirtual(hDev, sysCR3, ntBase + dos.e_lfanew, &nt, sizeof(nt)) ||
        nt.Signature != IMAGE_NT_SIGNATURE) {
        DH_ERROR("failed to read ntoskrnl NT header");
        return FALSE;
    }

    DWORD expRVA  = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    DWORD expSize = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    if (!expRVA || !expSize) {
        DH_ERROR("no export directory in ntoskrnl");
        return FALSE;
    }

    IMAGE_EXPORT_DIRECTORY expDir;
    if (!RpmReadVirtual(hDev, sysCR3, ntBase + expRVA, &expDir, sizeof(expDir)))
        return FALSE;

    u64 psisp = 0;
    const char* target = "PsInitialSystemProcess";
    DWORD targetLen = (DWORD)strlen(target);

    // Walk export name table
    for (DWORD i = 0; i < expDir.NumberOfNames; i++) {
        DWORD nameRVA = 0;
        if (!RpmReadVirtual(hDev, sysCR3,
            ntBase + expDir.AddressOfNames + i * 4, &nameRVA, 4))
            continue;

        char name[64] = {0};
        if (!RpmReadVirtual(hDev, sysCR3, ntBase + nameRVA, name, 63))
            continue;

        if (strncmp(name, target, targetLen) == 0 && name[targetLen] == 0) {
            USHORT ordIdx = 0;
            RpmReadVirtual(hDev, sysCR3,
                ntBase + expDir.AddressOfNameOrdinals + i * 2, &ordIdx, 2);

            DWORD funcRVA = 0;
            RpmReadVirtual(hDev, sysCR3,
                ntBase + expDir.AddressOfFunctions + ordIdx * 4, &funcRVA, 4);

            // PsInitialSystemProcess is a pointer — read the pointer value
            RpmRead64(hDev, sysCR3, ntBase + funcRVA, &psisp);
            break;
        }
    }

    if (!psisp) {
        DH_ERROR("PsInitialSystemProcess not found in exports");
        return FALSE;
    }

    DH_INFO("PsInitialSystemProcess -> EPROCESS @ 0x%llX", psisp);

    // Cache for later reuse (RpmHideOwnProcess doesn't need to re-resolve).
    g_rpm_psisp = psisp;

    // Sanity-check the layout table row: read System's KPROCESS.DirectoryTableBase
    // from g_eproc_dtb — must equal the CR3 we walked in with. Mismatch = wrong
    // offsets for this build, bail with actionable error instead of walking a
    // wrong LIST_ENTRY chain into garbage.
    {
        u64 sys_dtb = 0;
        if (!RpmRead64(hDev, sysCR3, psisp + g_eproc_dtb, &sys_dtb)) {
            DH_ERROR("layout probe: read System EPROCESS+DTB(0x%X) failed",
                     g_eproc_dtb);
            return FALSE;
        }
        if ((sys_dtb & ~0xFFFULL) != (sysCR3 & ~0xFFFULL)) {
            DH_ERROR("layout probe FAILED: EPROCESS+0x%X = 0x%llX, expected sysCR3=0x%llX. "
                     "kEprocLayouts row for this build is wrong — verify offsets against "
                     "Vergilius Project.",
                     g_eproc_dtb, sys_dtb, sysCR3);
            return FALSE;
        }
        DH_INFO("layout probe OK: System DTB @ +0x%X matches sysCR3", g_eproc_dtb);
    }

    // Lazy-discover EPROCESS.Peb offset from OUR OWN process. First call per
    // run pays a one-time list-walk cost. If discovery fails, g_eproc_peb_off
    // keeps its default (0x550) which is right on 26100 but wrong on 26200.
    static BOOL s_peb_off_discovered = FALSE;
    if (!s_peb_off_discovered) {
        s_peb_off_discovered = TRUE;
        DiscoverPebOffset(hDev, sysCR3, psisp);
    }

    // Step 3: walk ActiveProcessLinks
    u64 head = psisp + g_eproc_links;
    u64 cur  = head;
    u32 count = 0;

    // Read first link
    u64 flink = 0;
    if (!RpmRead64(hDev, sysCR3, cur, &flink))
        return FALSE;

    cur = flink;
    while (cur != head && count < 1024) {
        u64 eproc = cur - g_eproc_links;

        char imgName[16] = {0};
        if (!RpmReadVirtual(hDev, sysCR3, eproc + g_eproc_imgname, imgName, 15))
            goto next;

        if (_strnicmp(imgName, procName, strlen(procName)) == 0) {
            u64 dtb = 0;
            RpmRead64(hDev, sysCR3, eproc + g_eproc_dtb, &dtb);
            if (dtb) {
                u64 pid = 0;
                RpmRead64(hDev, sysCR3, eproc + g_eproc_pid, &pid);
                // ACE spawns 6-7 decoy DeltaForceClie processes whose user
                // page tables translate to zero via manual walk (defense
                // against external readers). The REAL game process is the
                // one whose 0x140000000 has "MZ". Pick that one; ignore
                // decoys that read as all-zeros.
                u16 mz140 = 0;
                BOOL is_real = RpmReadVirtual(hDev, dtb, 0x140000000ULL,
                                              &mz140, 2)
                               && mz140 == 0x5A4D;
                if (is_real) {
                    DH_INFO("found REAL '%s' PID=%llu EPROCESS=0x%llX CR3=0x%llX "
                            "(MZ@0x140000000 OK, past ACE decoy filter)",
                            imgName, pid, eproc, dtb);
                    *procCR3 = dtb;
                    if (eprocessOut) *eprocessOut = eproc;
                    return TRUE;
                }
                DH_INFO("skip decoy '%s' PID=%llu CR3=0x%llX "
                        "(no MZ@0x140000000 — ACE-obfuscated DTB)",
                        imgName, pid, dtb);
            }
        }

    next:
        if (!RpmRead64(hDev, sysCR3, cur, &flink) || flink == cur)
            break;
        cur = flink;
        count++;
    }

    DH_ERROR("process '%s' not found in EPROCESS list (%u scanned) — "
             "all candidates were ACE decoys",
             procName, count);
    return FALSE;
}

// ---- Userspace PEB.Ldr walking ----
//
// PEB layout (x64, stable across Win10/11):
//   +0x018  Ldr:  PPEB_LDR_DATA
//   +0x010  ImageBaseAddress: PVOID
//
// PEB_LDR_DATA layout (x64, stable):
//   +0x010  InLoadOrderModuleList: LIST_ENTRY
//
// LDR_DATA_TABLE_ENTRY layout (x64, stable Win10+):
//   +0x000  InLoadOrderLinks: LIST_ENTRY
//   +0x030  DllBase: PVOID
//   +0x040  SizeOfImage: ULONG
//   +0x058  BaseDllName: UNICODE_STRING { u16 Length, u16 MaxLength, u32 pad, PWSTR Buffer }

#define PEB_LDR_OFFSET              0x018
#define PEB_IMAGEBASE_OFFSET        0x010
#define PEB_LDR_INLOAD_OFFSET       0x010
#define LDR_ENTRY_DLLBASE           0x030
#define LDR_ENTRY_SIZEOFIMAGE       0x040
#define LDR_ENTRY_BASEDLLNAME       0x058

BOOL RpmGetMainImageBase(HANDLE hDev, u64 procCR3, u64 pebVA,
                         u64* baseOut, u64* sizeOut)
{
    if (baseOut) *baseOut = 0;
    if (sizeOut) *sizeOut = 0;
    if (!pebVA) return FALSE;

    u64 base = 0;
    if (!RpmRead64(hDev, procCR3, pebVA + PEB_IMAGEBASE_OFFSET, &base) || !base)
        return FALSE;
    if (baseOut) *baseOut = base;

    if (sizeOut) {
        // PE size from OptionalHeader.SizeOfImage — read IMAGE_NT_HEADERS64
        DWORD e_lfanew = 0;
        if (!RpmReadVirtual(hDev, procCR3, base + 0x3C, &e_lfanew, 4))
            return TRUE;
        u32 sizeOfImage = 0;
        if (!RpmReadVirtual(hDev, procCR3, base + e_lfanew + 0x50, &sizeOfImage, 4))
            return TRUE;
        *sizeOut = sizeOfImage;
    }
    return TRUE;
}

// ANSI-fold WCHAR for case-insensitive short-name compare (module names are ASCII).
static int wcs_ieq_ascii(const wchar_t* a, const wchar_t* b) {
    while (*a && *b) {
        wchar_t ca = *a, cb = *b;
        if (ca >= L'A' && ca <= L'Z') ca += 32;
        if (cb >= L'A' && cb <= L'Z') cb += 32;
        if (ca != cb) return 0;
        a++; b++;
    }
    return *a == 0 && *b == 0;
}

BOOL RpmEnumModules(HANDLE hDev, u64 procCR3, u64 pebVA,
                    RpmModuleCb cb, void* ctx)
{
    if (!pebVA) return FALSE;

    u64 ldr = 0;
    if (!RpmRead64(hDev, procCR3, pebVA + PEB_LDR_OFFSET, &ldr) || !ldr)
        return FALSE;

    u64 head = ldr + PEB_LDR_INLOAD_OFFSET;
    u64 flink = 0;
    if (!RpmRead64(hDev, procCR3, head, &flink) || flink == head)
        return FALSE;

    u64 cur = flink;
    u32 count = 0;
    while (cur != head && count < 512) {
        u64 entry = cur;  // InLoadOrderLinks is at offset 0

        u64 dllBase = 0;
        u32 sizeOfImage = 0;
        u16 nameLen = 0;
        u64 nameBuf = 0;

        RpmRead64(hDev, procCR3, entry + LDR_ENTRY_DLLBASE, &dllBase);
        RpmReadVirtual(hDev, procCR3, entry + LDR_ENTRY_SIZEOFIMAGE, &sizeOfImage, 4);
        RpmReadVirtual(hDev, procCR3, entry + LDR_ENTRY_BASEDLLNAME, &nameLen, 2);
        RpmRead64(hDev, procCR3, entry + LDR_ENTRY_BASEDLLNAME + 8, &nameBuf);

        wchar_t name[128] = {0};
        u32 copyLen = nameLen;
        if (copyLen > sizeof(name) - 2) copyLen = sizeof(name) - 2;
        if (nameBuf && copyLen)
            RpmReadVirtual(hDev, procCR3, nameBuf, name, copyLen);

        if (dllBase) {
            if (!cb(name, dllBase, sizeOfImage, ctx))
                return TRUE;
        }

        u64 next = 0;
        if (!RpmRead64(hDev, procCR3, cur, &next) || next == cur)
            break;
        cur = next;
        count++;
    }
    return TRUE;
}

typedef struct {
    const wchar_t* target;
    u64 base;
    u64 size;
    BOOL found;
} FindModCtx;

static BOOL find_mod_cb(const wchar_t* name, u64 base, u64 size, void* ctxp) {
    FindModCtx* ctx = (FindModCtx*)ctxp;
    if (wcs_ieq_ascii(name, ctx->target)) {
        ctx->base = base;
        ctx->size = size;
        ctx->found = TRUE;
        return FALSE;
    }
    return TRUE;
}

BOOL RpmFindModule(HANDLE hDev, u64 procCR3, u64 pebVA,
                   const wchar_t* dllName, u64* baseOut, u64* sizeOut)
{
    if (baseOut) *baseOut = 0;
    if (sizeOut) *sizeOut = 0;

    FindModCtx ctx = { dllName, 0, 0, FALSE };
    RpmEnumModules(hDev, procCR3, pebVA, find_mod_cb, &ctx);
    if (!ctx.found) return FALSE;

    if (baseOut) *baseOut = ctx.base;
    if (sizeOut) *sizeOut = ctx.size;
    return TRUE;
}

// ---- UE4 UObject / FUObjectArray access ----

BOOL RpmGetUObjectByIndex(HANDLE hDev, u64 procCR3, u64 gObjectsVA,
                          i32 index, u64* outObj)
{
    *outObj = 0;
    if (index < 0) return FALSE;

    u64 chunksPtr = 0;
    if (!RpmRead64(hDev, procCR3, gObjectsVA + GOBJ_CHUNKS_PTR, &chunksPtr) || !chunksPtr)
        return FALSE;

    i32 chunkIdx = index / GOBJ_ELEMENTS_PER_CHUNK;
    i32 inChunk  = index % GOBJ_ELEMENTS_PER_CHUNK;

    u64 chunk = 0;
    if (!RpmRead64(hDev, procCR3, chunksPtr + (u64)chunkIdx * 8, &chunk) || !chunk)
        return FALSE;

    u64 itemVA = chunk + (u64)inChunk * GOBJ_ITEM_SIZE;
    u64 obj = 0;
    if (!RpmRead64(hDev, procCR3, itemVA, &obj))
        return FALSE;

    *outObj = obj;
    return TRUE;
}

// ---- FNamePool reader (Delta UE4.24 with UE5-style header + XOR 0xFF) ----
//
// Empirically-verified Delta FNamePool layout (from live dump on 25H2):
//   +0x00: 8 zero bytes (header/pad)
//   +0x08: uint8* Blocks[N]   — pointer array of ~1MB block pointers
//
// FNameEntry header (UE5-style, 16 bits little-endian):
//   bit  0    : bIsWide
//   bits 1..5 : LowercaseProbeHash (ignored)
//   bits 6..15: Length (10 bits, max 1023)
//
// FNameEntry layout:
//   +0x00: uint16 Header
//   +0x02: chars (ANSI 1B each, Length count) — XORed with 0xFF
//   Next entry is 2-byte aligned.
//
// FName encoding: ComparisonIndex = (BlockIdx << 18) | SlotIdx
//   Delta uses 14-bit block index, 18-bit slot index (verified by
//   cold-RE of FName::AppendString @ 0x150D47780).

#define FNAMEPOOL_BLOCKS_OFF   0x08
#define FNAMEPOOL_STRIDE       2      // FNameEntryHandle stride (each unit = 2 bytes)
#define FNAME_ENTRY_HEADER_SZ  2

// Delta's FName cipher — length-derived XOR key. Ported from DErDYAST1R
// binary dump (2025-12-17). Same key XORed against every byte of the name.
// key ends up in {0x7F, 0xFF} across all 9 branches.
static u8 DeltaFNameXorKey(u32 length)
{
    u32 r9d = (u32)length;
    // Fast div-by-9: (0x38E38E39 * r9d) >> 32 >> 1 == r9d / 9.
    u32 quot = (u32)(((u64)0x38E38E39ULL * (u64)r9d) >> 32) >> 1;
    u32 rem  = r9d - quot * 9;
    u8  k;
    switch (rem) {
        case 0: k = (u8)((r9d & 0x1F) + 0x80); k = (u8)(k + r9d); return k | 0x7F;
        case 1: k = (u8)((r9d ^ 0xDF) + 0x80); k = (u8)(k + r9d); return k | 0x7F;
        case 2: k = (u8)((r9d | 0xCF) + 0x80); k = (u8)(k + r9d); return k | 0x7F;
        case 3: {
            int8_t s = (int8_t)r9d;
            k = (u8)((u8)(s * 0x21) + 0x80);
            return k | 0x7F;
        }
        case 4: k = (u8)(((u8)r9d >> 2) + 0x80); k = (u8)(k + r9d); return k | 0x7F;
        case 5: {
            u8 base = (u8)(r9d - 0x29);
            k = (u8)(base + base + base);
            return k | 0x7F;
        }
        case 6: k = (u8)((((u8)r9d << 2) | 0x05) + 0x80); k = (u8)(k + r9d); return k | 0x7F;
        case 7: k = (u8)((((u8)r9d >> 4) | 0x07) + 0x80); k = (u8)(k + r9d); return k | 0x7F;
        case 8: k = (u8)(((u8)r9d ^ 0x0C) + 0x80); k = (u8)(k + r9d); return k | 0x7F;
    }
    return 0xFF;   // unreachable — rem is always in [0..8]
}

BOOL RpmResolveFName(HANDLE hDev, u64 procCR3, u64 gNamesVA,
                     u32 comparisonIndex, char* out, u32 outSize)
{
    if (!out || outSize == 0) return FALSE;
    out[0] = 0;
    if (comparisonIndex == 0) { strcpy_s(out, outSize, "None"); return TRUE; }

    // Delta: 14-bit block index, 18-bit slot index (NOT 16/16).
    u32 blockIdx = comparisonIndex >> 18;
    u32 offset   = (comparisonIndex & 0x3FFFF) * FNAMEPOOL_STRIDE;

    u64 blockPtr = 0;
    if (!RpmRead64(hDev, procCR3, gNamesVA + FNAMEPOOL_BLOCKS_OFF + blockIdx * 8, &blockPtr)
        || !blockPtr)
        return FALSE;

    u64 entryVA = blockPtr + offset;

    u16 header = 0;
    if (!RpmReadVirtual(hDev, procCR3, entryVA, &header, 2))
        return FALSE;

    u8  bIsWide = header & 1;
    u16 nameLen = header >> 6;   // UE5-style: bits 6..15 = Length (10 bits)

    if (nameLen == 0) { strcpy_s(out, outSize, ""); return TRUE; }
    if (nameLen >= outSize) nameLen = (u16)(outSize - 1);
    // Engine caps FName Length at 1023 (10-bit field). We cap at 128 —
    // covers every class / weapon / operator / map name in DFM. Bump
    // caller buffers to match if you expect longer.
    if (nameLen > 256) nameLen = 256;

    u8 xorKey = DeltaFNameXorKey((u32)nameLen);

    if (bIsWide) {
        wchar_t wbuf[512];
        if (nameLen > 511) nameLen = 511;
        if (!RpmReadVirtual(hDev, procCR3, entryVA + FNAME_ENTRY_HEADER_SZ,
                            wbuf, nameLen * 2))
            return FALSE;
        // Cold-RE @ 0x150D4B7D0: 'add eax, 2 ; xor [r8+rax*2], dx' — the
        // decrypt only XORs every OTHER wchar (indices 0, 2, 4, ...).
        // Value is a 16-bit widened xorKey (same key both bytes).
        u16 wideKey = (u16)((u16)xorKey | ((u16)xorKey << 8));
        for (u16 i = 0; i < nameLen; i += 2) wbuf[i] ^= wideKey;
        wbuf[nameLen] = 0;
        WideCharToMultiByte(CP_UTF8, 0, wbuf, -1, out, outSize, NULL, NULL);
    } else {
        if (!RpmReadVirtual(hDev, procCR3, entryVA + FNAME_ENTRY_HEADER_SZ,
                            out, nameLen))
            return FALSE;
        u32 nBytes = nameLen;
        if (nBytes > 0x400) nBytes = 0x400;
        for (u32 i = 0; i < nBytes; i++) out[i] ^= xorKey;
        out[nameLen] = 0;
    }
    return TRUE;
}

BOOL RpmGetObjectName(HANDLE hDev, u64 procCR3, u64 gNamesVA,
                      u64 obj, char* out, u32 outSize)
{
    if (!obj || !out || !outSize) return FALSE;
    out[0] = 0;

    u32 fname[2] = {0};
    if (!RpmReadVirtual(hDev, procCR3, obj + UOBJ_NAME, fname, 8))
        return FALSE;

    return RpmResolveFName(hDev, procCR3, gNamesVA, fname[0], out, outSize);
}

BOOL RpmGetObjectClassName(HANDLE hDev, u64 procCR3, u64 gNamesVA,
                           u64 obj, char* out, u32 outSize)
{
    if (!obj || !out || !outSize) return FALSE;
    out[0] = 0;

    u64 classObj = 0;
    if (!RpmRead64(hDev, procCR3, obj + UOBJ_CLASS, &classObj) || !classObj)
        return FALSE;

    return RpmGetObjectName(hDev, procCR3, gNamesVA, classObj, out, outSize);
}

// ---- FEncVector decoder ----

// ---- GObjects class-name lookup + SuperStruct-chain filter ----
//
// The pickup class filter uses these two primitives:
//   1. RpmFindUClassByName — lazy-init locator for "PickupBase" UClass*.
//   2. RpmIsClassDescendantOf — per-actor ancestry check against the base.
// Together they form a structural gate that admits ONLY actors whose class
// inherits from APickupBase (native subclasses + BP InventoryPickup_C).
// This replaces the field-shape heuristic which admitted AActor descendants
// whose 0xFC0..0x1020 band happened to hold pickup-like flag/int/float
// patterns (the density-cluster FP case).

u64 RpmFindUClassByName(HANDLE hDev, u64 procCR3, u64 gObjectsVA,
                       u64 gNamesVA, const char* targetName)
{
    if (!gObjectsVA || !gNamesVA || !targetName || !targetName[0]) return 0;

    // Read FUObjectArray header: Chunks@+0x10, NumElements@+0x04.
    // (Delta uses +0x04 for live element count — verified by walk-gobjects
    // resolving 479k here; the old +0x24 offset was wrong and aborted us.)
    u8 hdr[0x30] = {0};
    if (!RpmReadVirtual(hDev, procCR3, gObjectsVA, hdr, sizeof(hdr))) return 0;
    u64 chunksPtr = *(u64*)(hdr + GOBJ_CHUNKS_PTR);
    i32 numElem   = *(i32*)(hdr + 0x04);
    if (!chunksPtr || numElem <= 0 || numElem > 0x400000) return 0;

    i32 numChunks = (numElem + (i32)GOBJ_ELEMENTS_PER_CHUNK - 1) /
                    (i32)GOBJ_ELEMENTS_PER_CHUNK;
    if (numChunks <= 0 || numChunks > 128) numChunks = numChunks > 128 ? 128 : 0;
    if (!numChunks) return 0;

    u64 chunkPtrs[128] = {0};
    if (!RpmReadVirtual(hDev, procCR3, chunksPtr, chunkPtrs,
                        (u32)(numChunks * (i32)sizeof(u64)))) return 0;

    // 1.5 MB static scratch — one full chunk of FUObjectItems at a time.
    static u8 s_items[GOBJ_ELEMENTS_PER_CHUNK * GOBJ_ITEM_SIZE];
    u64 found = 0;
    for (i32 ci = 0; ci < numChunks && !found; ci++) {
        u64 chunk = chunkPtrs[ci];
        if (!chunk) continue;
        i32 lo = ci * (i32)GOBJ_ELEMENTS_PER_CHUNK;
        i32 hi = lo + (i32)GOBJ_ELEMENTS_PER_CHUNK;
        if (hi > numElem) hi = numElem;
        u32 nItems = (u32)(hi - lo);
        if (!RpmReadVirtual(hDev, procCR3, chunk, s_items,
                            nItems * (u32)GOBJ_ITEM_SIZE)) continue;
        for (u32 ii = 0; ii < nItems && !found; ii++) {
            u64 obj = *(u64*)(s_items + ii * GOBJ_ITEM_SIZE);
            if (!obj) continue;
            u32 nameIdx = 0;
            if (!RpmReadVirtual(hDev, procCR3, obj + UOBJ_NAME, &nameIdx, 4))
                continue;
            if (!nameIdx) continue;
            char nameBuf[64] = {0};
            if (!RpmResolveFName(hDev, procCR3, gNamesVA, nameIdx,
                                 nameBuf, sizeof(nameBuf))) continue;
            if (nameBuf[0] && strcmp(nameBuf, targetName) == 0)
                found = obj;
        }
    }
    return found;
}

BOOL RpmIsClassDescendantOf(HANDLE hDev, u64 procCR3,
                            u64 classPtr, u64 ancestorClass)
{
    if (!classPtr || !ancestorClass) return FALSE;
    u64 cur = classPtr;
    for (int hop = 0; hop < 8; hop++) {
        if (cur == ancestorClass) return TRUE;
        u64 sup = 0;
        if (!RpmRead64(hDev, procCR3, cur + USTRUCT_SUPER, &sup) || !sup)
            return FALSE;
        cur = sup;
    }
    return FALSE;
}

BOOL RpmReadEncVector(HANDLE hDev, u64 procCR3, u64 vecVA,
                      float* xOut, float* yOut, float* zOut,
                      u8* bEncryptedOut)
{
    u8 buf[16] = {0};
    if (!RpmReadVirtual(hDev, procCR3, vecVA, buf, 16)) return FALSE;

    float x = *(float*)(buf + 0);
    float y = *(float*)(buf + 4);
    float z = *(float*)(buf + 8);
    // FEncHandler @ +0x0C: u16 Index, i8 bEncrypted, u8 flags
    u8 bEnc = buf[14];

    if (bEncryptedOut) *bEncryptedOut = bEnc;

    if (bEnc != 0) {
        // TODO: real decrypt algo — for now just return raw floats.
        // The algorithm lives in UKismetMathLibrary::DecVector.
        // Live RE will fill this in; for now the caller inspects bEncrypted.
    }

    if (xOut) *xOut = x;
    if (yOut) *yOut = y;
    if (zOut) *zOut = z;
    return TRUE;
}

// ---------------------------------------------------------------------------
// RpmHideOwnProcess — unlink our own EPROCESS from ActiveProcessLinks so
// Task Manager, tasklist.exe, Process Hacker and every tool walking
// SystemProcessInformation cannot see us.
//
// Requires:
//   - EprocInit() has been called (g_eproc_* populated)
//   - RpmFindProcess() has run at least once (g_rpm_psisp cached)
//   - Kernel virtual-write path works (RpmWriteVirtual → PhysWrite via kdu)
//
// Mechanics:
//   LIST_ENTRY layout: { Flink, Blink }
//   our.Flink → &next.LIST_ENTRY
//   our.Blink → &prev.LIST_ENTRY
//   To unlink:
//     write our.Flink at address our.Blink  → prev.Flink = our.Flink
//     write our.Blink at address our.Flink+8 → next.Blink = our.Blink
//   Post-unlink: our.Flink/Blink point to self so any late deref stays safe.
// ---------------------------------------------------------------------------

BOOL RpmHideOwnProcess(HANDLE hDev, u64 sysCR3)
{
    // NOTE: VMProtect markers not applied here — multiple return paths make
    // single-basic-block requirement impossible without heavy refactor.
    // Function is disabled anyway (see main.c) so lower priority.
    if (!g_rpm_psisp || !g_eproc_links) {
        DH_ERROR("HideOwnProcess: psisp/eproc not initialized");
        return FALSE;
    }

    u64 our_pid = (u64)GetCurrentProcessId();
    u64 head = g_rpm_psisp + g_eproc_links;
    u64 cur = 0;
    if (!RpmRead64(hDev, sysCR3, head, &cur)) {
        DH_ERROR("HideOwnProcess: read first Flink failed");
        return FALSE;
    }

    u64 our_eproc = 0;
    int scanned = 0;
    while (cur != head && scanned < 4096) {
        u64 eproc = cur - g_eproc_links;
        u64 pid = 0;
        if (RpmRead64(hDev, sysCR3, eproc + g_eproc_pid, &pid) && pid == our_pid) {
            our_eproc = eproc;
            break;
        }
        u64 flink = 0;
        if (!RpmRead64(hDev, sysCR3, cur, &flink) || flink == cur) break;
        cur = flink;
        scanned++;
    }
    if (!our_eproc) {
        DH_ERROR("HideOwnProcess: own PID=%llu not found (%d scanned)",
                 our_pid, scanned);
        return FALSE;
    }

    u64 our_links = our_eproc + g_eproc_links;
    u64 our_flink = 0, our_blink = 0;
    if (!RpmRead64(hDev, sysCR3, our_links, &our_flink) ||
        !RpmRead64(hDev, sysCR3, our_links + 8, &our_blink)) {
        DH_ERROR("HideOwnProcess: read own Flink/Blink failed");
        return FALSE;
    }
    DH_INFO("HideOwnProcess: PID=%llu eproc=0x%llX Flink=0x%llX Blink=0x%llX",
            our_pid, our_eproc, our_flink, our_blink);

    // Write prev.Flink = our.Flink   (address = our.Blink)
    if (!RpmWrite64(hDev, sysCR3, our_blink, our_flink)) {
        DH_ERROR("HideOwnProcess: write prev.Flink failed — kernel write "
                 "probably not supported by provider");
        return FALSE;
    }
    // Write next.Blink = our.Blink   (address = our.Flink + 8)
    if (!RpmWrite64(hDev, sysCR3, our_flink + 8, our_blink)) {
        DH_ERROR("HideOwnProcess: write next.Blink failed");
        // Try to relink prev so we don't leave list corrupted.
        RpmWrite64(hDev, sysCR3, our_blink, our_links);
        return FALSE;
    }
    // Point our own Flink/Blink at ourselves — safe if kernel dereferences
    // during our process teardown.
    RpmWrite64(hDev, sysCR3, our_links, our_links);
    RpmWrite64(hDev, sysCR3, our_links + 8, our_links);

    DH_INFO("HideOwnProcess: unlinked from ActiveProcessLinks — invisible to "
            "Task Manager / tasklist / Process Hacker");
    return TRUE;
}

// ---------------------------------------------------------------------------
// RpmHideAllByImageName — walk ActiveProcessLinks, find every EPROCESS
// whose ImageFileName starts with `nameA` (case-insensitive), and unlink
// each one from the list. Returns number of processes newly hidden.
//
// Design: daemon calls this periodically. Own EPROCESS is already unlinked
// (from RpmHideOwnProcess) so it doesn't re-appear in the walk. Overlay
// (same exe name, different PID) gets hidden the first time daemon spots it.
// Late-arriving instances also get caught on the next call.
// ---------------------------------------------------------------------------

int RpmHideAllByImageName(HANDLE hDev, u64 sysCR3, const char* nameA)
{
    if (!g_rpm_psisp || !g_eproc_links || !nameA || !nameA[0]) return 0;

    size_t nameLen = strlen(nameA);
    if (nameLen > 14) nameLen = 14;   // ImageFileName is 15 chars incl. NUL

    u64 head = g_rpm_psisp + g_eproc_links;
    u64 cur = 0;
    if (!RpmRead64(hDev, sysCR3, head, &cur)) return 0;

    int hidden = 0;
    int scanned = 0;
    while (cur != head && scanned < 4096) {
        u64 eproc = cur - g_eproc_links;
        u64 next_flink = 0;
        // Cache next link BEFORE we unlink current — the write invalidates cur.
        if (!RpmRead64(hDev, sysCR3, cur, &next_flink) || next_flink == cur) break;

        char imgName[16] = {0};
        if (!RpmReadVirtual(hDev, sysCR3, eproc + g_eproc_imgname, imgName, 15)) {
            cur = next_flink; scanned++; continue;
        }
        imgName[15] = 0;

        if (_strnicmp(imgName, nameA, nameLen) == 0) {
            u64 our_links = eproc + g_eproc_links;
            u64 our_flink = 0, our_blink = 0;
            if (RpmRead64(hDev, sysCR3, our_links, &our_flink) &&
                RpmRead64(hDev, sysCR3, our_links + 8, &our_blink)) {
                u64 pid = 0;
                RpmRead64(hDev, sysCR3, eproc + g_eproc_pid, &pid);
                // Unlink: prev.Flink = our.Flink, next.Blink = our.Blink
                if (RpmWrite64(hDev, sysCR3, our_blink, our_flink) &&
                    RpmWrite64(hDev, sysCR3, our_flink + 8, our_blink)) {
                    // Self-loop own links for safe teardown.
                    RpmWrite64(hDev, sysCR3, our_links, our_links);
                    RpmWrite64(hDev, sysCR3, our_links + 8, our_links);
                    DH_INFO("HideAllByName: hid PID=%llu name=\"%s\"",
                            pid, imgName);
                    hidden++;
                }
            }
        }
        cur = next_flink;
        scanned++;
    }
    return hidden;
}

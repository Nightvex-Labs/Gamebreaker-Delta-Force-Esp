// DeltaHack loader — CLI entrypoint.
//
// Provider: EneIo64 (kdu #6, WHCP-signed by Microsoft Windows Hardware
// Compatibility Publisher). EPT-safe read-only WinIo path — no CI-page
// writes, no MSR touches, no unsigned kernel code load. Works with
// Hyper-V ON / HVCI ON on Intel VMX+EPT and AMD SVM+NPT alike.
//
// Commands:
//   version                  print version
//   unpack <in.bin> <out.sys> unpack a kdu DBPACK payload
//   ping                     install EneIo64 + IOCTL round-trip + read low stub
//   install                  install driver only (leave running)
//   uninstall                stop + remove driver service
//   rpm <pid|name> <va> <n>  read n bytes from proc VA, hexdump to stdout
//   probe-delta              locate DeltaForceClient, dump GObjects head

#include "../inc/dh_common.h"
#include "../inc/dh_dbunpack.h"
#include "../inc/dh_scm.h"
#include "../inc/dh_phys.h"
#include "../inc/dh_provider.h"
#include "../inc/dh_mz_wipe.h"
#include "../inc/dh_hollow.h"
#include "../inc/dh_auth.h"
#include "../inc/dh_diag.h"
#include "../inc/dh_system_spawn.h"
#include <math.h>
#include "../inc/dh_rpm.h"
#include "../inc/dh_ace_decrypt.h"
#include <math.h>

// Embedded driver: EneIo64.bin (kdu DBPACK payload) — decoded → temp .sys.
// For now we read it from disk relative to loader.exe to keep the loader
// small; embed-as-RCDATA later.

// Device name is hardcoded in the driver — we cannot rotate it.
// Service name rotates per-invocation to sidestep marked-for-delete lockout.
#define DH_DEV_NAME   L"EneIo"
#define DH_PROC_NAME  "DeltaForceCli"  // 15-char match against EPROCESS.ImageFileName

static wchar_t g_svcName[64];

static const wchar_t* dh_svc_name(void) {
    if (!g_svcName[0]) {
        _snwprintf(g_svcName, 64, L"dh_eneio_%lu", GetCurrentProcessId());
    }
    return g_svcName;
}

static BOOL is_elevated(void) {
    BOOL ret = FALSE;
    HANDLE tok = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) {
        TOKEN_ELEVATION e = {0};
        DWORD n = 0;
        if (GetTokenInformation(tok, TokenElevation, &e, sizeof(e), &n))
            ret = e.TokenIsElevated ? TRUE : FALSE;
        CloseHandle(tok);
    }
    return ret;
}

static void banner(void) {
#ifndef DH_RELEASE
    // Debug builds only — prod hides target/provider identity to avoid
    // painting the process as an obvious external cheat if CMD is visible.
    fprintf(stderr,
        "loader v" DH_LOADER_VERSION_STR "\n"
        "target:   DeltaForceClient-Win64-Shipping.exe (UE4.24.2, ACE+SGuard64)\n"
        "provider: EneIo64 (kdu #6, WHCP-signed, HVCI/VBS-friendly)\n"
        "\n");
#endif
}

static void usage(void) {
    fprintf(stderr,
        "usage: dh_loader.exe <cmd> [args]\n"
        "  daemon                   PRODUCTION: driver up, wait for Delta, snapshot loop\n"
        "  esp                      GameState.PlayerArray -> Pawn.RootComp.C2W (XOR 0x0E) -> pos\n"
        "  ping                     install driver, read low stub, unload\n"
        "  install                  install driver service only\n"
        "  uninstall                stop + remove driver service\n"
        "  find <procname>          walk EPROCESS list, print CR3 of match\n"
        "  modules <procname>       list all modules of a process via PEB.Ldr\n"
        "  rpm <pid> <va> <n>       read n bytes from process va\n"
        "  probe-delta              find Delta, dump GObjects head\n"
        "  walk-gobjects [n]        enumerate first n UObjects with class+name\n"
        "  find-world               scan GObjects for UWorld, dump Levels+Actors\n"
        "  version                  print version\n"
        "  unpack <in.bin> <out.sys> unpack kdu DBPACK payload\n"
        "\n");
}

// ---- unpack subcommand ----

static BOOL cmd_unpack_bin(const wchar_t* in_path, const wchar_t* out_path) {
    HANDLE h = CreateFileW(in_path, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        DH_ERROR("open input failed (gle=%lu)", GetLastError());
        return FALSE;
    }
    DWORD sz = GetFileSize(h, NULL), rd = 0;
    void* in = HeapAlloc(GetProcessHeap(), 0, sz);
    if (!in || !ReadFile(h, in, sz, &rd, NULL) || rd != sz) {
        DH_ERROR("read input failed");
        CloseHandle(h);
        return FALSE;
    }
    CloseHandle(h);

    void* out = NULL;
    DWORD out_sz = 0;
    if (!DbUnpack(in, sz, &out, &out_sz)) {
        DH_ERROR("DbUnpack failed");
        HeapFree(GetProcessHeap(), 0, in);
        return FALSE;
    }
    HeapFree(GetProcessHeap(), 0, in);

    const unsigned char* p = (const unsigned char*)out;
    DH_INFO("unpacked %lu bytes, first2 = %02X %02X (%s)",
            out_sz, p[0], p[1],
            (p[0] == 0x4D && p[1] == 0x5A) ? "MZ ok" : "NOT a PE");

    HANDLE ho = CreateFileW(out_path, GENERIC_WRITE, 0, NULL,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (ho == INVALID_HANDLE_VALUE) {
        DH_ERROR("open output failed (gle=%lu)", GetLastError());
        HeapFree(GetProcessHeap(), 0, out);
        return FALSE;
    }
    DWORD wr = 0;
    BOOL ok = WriteFile(ho, out, out_sz, &wr, NULL) && wr == out_sz;
    CloseHandle(ho);
    HeapFree(GetProcessHeap(), 0, out);
    if (!ok) { DH_ERROR("write output failed"); return FALSE; }
    DH_INFO("wrote %lu bytes -> %ls", out_sz, out_path);
    return TRUE;
}

// ---- driver setup helpers ----

// Prepare the driver .sys on disk from the embedded/side-loaded EneIo64.bin.
// Returns full path in *outSysPath.
static BOOL prepare_driver_sys(wchar_t* outSysPath, DWORD outSz) {
    wchar_t exeDir[MAX_PATH];
    GetModuleFileNameW(NULL, exeDir, MAX_PATH);
    wchar_t* slash = wcsrchr(exeDir, L'\\');
    if (slash) *slash = 0;

    wchar_t binPath[MAX_PATH];
    _snwprintf(binPath, MAX_PATH, L"%s\\..\\src\\db\\EneIo64.bin", exeDir);

    // Read .bin
    HANDLE h = CreateFileW(binPath, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        // fallback: same dir
        _snwprintf(binPath, MAX_PATH, L"%s\\EneIo64.bin", exeDir);
        h = CreateFileW(binPath, GENERIC_READ, FILE_SHARE_READ, NULL,
                       OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (h == INVALID_HANDLE_VALUE) {
            DH_ERROR("EneIo64.bin not found (checked %ls)", binPath);
            return FALSE;
        }
    }

    DWORD binSz = GetFileSize(h, NULL), rd = 0;
    void* binBuf = HeapAlloc(GetProcessHeap(), 0, binSz);
    if (!binBuf || !ReadFile(h, binBuf, binSz, &rd, NULL) || rd != binSz) {
        DH_ERROR("read EneIo64.bin failed");
        CloseHandle(h);
        return FALSE;
    }
    CloseHandle(h);

    // Decode DBPACK → raw .sys
    void* sysBuf = NULL;
    DWORD sysSz = 0;
    BOOL ok = DbUnpack(binBuf, binSz, &sysBuf, &sysSz);
    HeapFree(GetProcessHeap(), 0, binBuf);
    if (!ok) {
        DH_ERROR("DbUnpack EneIo64 failed");
        return FALSE;
    }

    // Write to %TEMP%\dh_eneio.sys
    wchar_t tempDir[MAX_PATH];
    GetTempPathW(MAX_PATH, tempDir);
    _snwprintf(outSysPath, outSz, L"%sdh_eneio_%lu.sys", tempDir, GetCurrentProcessId());

    HANDLE ho = CreateFileW(outSysPath, GENERIC_WRITE, 0, NULL,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (ho == INVALID_HANDLE_VALUE) {
        DH_ERROR("write %ls failed (gle=%lu)", outSysPath, GetLastError());
        HeapFree(GetProcessHeap(), 0, sysBuf);
        return FALSE;
    }
    DWORD wr = 0;
    ok = WriteFile(ho, sysBuf, sysSz, &wr, NULL) && wr == sysSz;
    CloseHandle(ho);
    HeapFree(GetProcessHeap(), 0, sysBuf);
    if (!ok) {
        DH_ERROR("write full failed");
        return FALSE;
    }
    DH_INFO("driver ready: %ls (%lu bytes)", outSysPath, sysSz);
    return TRUE;
}

// Full stack: prepare .sys → install → start → open device.
//
// Fast-path: if \\.\EneIo device already exists (prior kdu-loaded driver
// still resident from a previous dh_loader invocation this boot), just open
// it. Skips SCM installation entirely — avoids the ERROR_ALREADY_EXISTS 183
// dance when kdu has already planted its kernel-side named object and the
// SCM state got stuck.
// Multi-provider driver bring-up. Iterates registry by priority; first
// provider that (a) loads under HVCI, (b) opens device successfully → wins.
// Sets g_active_provider so all PhysRead/PhysWrite routes through that
// driver's protocol.
extern const DH_PROVIDER* g_active_provider;

static BOOL driver_up(DH_DRIVER* drv) {
    memset(drv, 0, sizeof(*drv));

    // Try provider chain first (HVCI-safe drivers, priority-sorted).
    HANDLE dev = NULL;
    const DH_PROVIDER* p = DhProviderSelect(&dev, NULL);
    if (p && dev) {
        g_active_provider = p;
        drv->hDevice = dev;
        _snwprintf(drv->devPath, 128, L"\\\\.\\%s", p->dev_name);
        DH_INFO("=== active provider: kdu#%u %s ===", p->kdu_id, p->name);
        return TRUE;
    }

    // Fallback: legacy EneIo64 path (for HVCI-off systems where nothing
    // else works, or if provider registry is broken).
    DH_WARN("all providers failed — falling back to legacy EneIo64");
    _snwprintf(drv->devPath, 128, L"\\\\.\\%s", DH_DEV_NAME);
    HANDLE probe = CreateFileW(drv->devPath, GENERIC_READ | GENERIC_WRITE,
        0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (probe != INVALID_HANDLE_VALUE) {
        drv->hDevice = probe;
        u64 sysCR3Probe = 0;
        if (RpmFindSystemCR3(probe, &sysCR3Probe) && sysCR3Probe != 0) {
            DH_INFO("device already resident, reusing: %ls", drv->devPath);
            return TRUE;
        }
        CloseHandle(probe);
        drv->hDevice = NULL;
    }
    wchar_t sysPath[MAX_PATH];
    if (!prepare_driver_sys(sysPath, MAX_PATH))
        return FALSE;
    if (!DhDrvInstall(drv, dh_svc_name(), DH_DEV_NAME, sysPath))
        return FALSE;
    if (!DhDrvStart(drv))
        return FALSE;
    if (!DhDrvOpenDevice(drv))
        return FALSE;
    DH_INFO("device open (legacy): %ls", drv->devPath);
    return TRUE;
}

static void driver_down(DH_DRIVER* drv) {
    // If we opened a resident device (no service handle), just close it —
    // leave the kernel driver in place so the next invocation can reuse it.
    // This avoids the ERROR_ALREADY_EXISTS 183 collision on re-install when
    // kdu's kernel-side named object outlives service teardown.
    if (drv->hDevice && !drv->hSvc) {
        CloseHandle(drv->hDevice);
        drv->hDevice = NULL;
        return;
    }
    DhDrvStop(drv);
    DhDrvUninstall(drv);
    DhDrvCleanup(drv);
}

// ---- ping ----

static int cmd_ping(void) {
    DH_DRIVER drv;
    if (!driver_up(&drv)) return DH_ERR_SVC_START;

    u64 cr3 = 0;
    if (!RpmFindSystemCR3(drv.hDevice, &cr3)) {
        driver_down(&drv);
        return DH_ERR_RPM_FAIL;
    }

    DH_INFO("PING OK — system CR3 = 0x%llX", cr3);

    driver_down(&drv);
    return DH_OK;
}

// ---- rpm <pid> <va> <n> ----

static int cmd_rpm(int argc, wchar_t** argv) {
    if (argc < 5) {
        DH_ERROR("usage: rpm <pid> <va> <n>");
        return DH_ERR_BAD_ARG;
    }
    DWORD  pid = (DWORD)wcstoul(argv[2], NULL, 0);
    u64    va  = (u64)_wcstoui64(argv[3], NULL, 0);
    u32    n   = (u32)wcstoul(argv[4], NULL, 0);
    if (n == 0 || n > (1u<<16)) {
        DH_ERROR("n must be 1..65536");
        return DH_ERR_BAD_ARG;
    }
    DH_INFO("rpm pid=%lu va=0x%llX n=%u", pid, va, n);

    // For now: pid-based lookup uses NtQuery to get image name, then walks
    // EPROCESS by name. Simpler: walk by PID.
    DH_UNUSED(pid);
    DH_ERROR("rpm-by-pid not wired yet — use probe-delta for name-based test");
    return DH_ERR_RPM_FAIL;
}

// ---- probe-delta ----

// Golden Delta RVA — from Dumper-7 dump 2026-09-17.
#define DELTA_RVA_GOBJECTS           0x1E689F18
#define DELTA_RVA_GNAMES             0x1E661B40
#define DELTA_RVA_OBFUSCATION_MODE   0x1E654884
#define DELTA_RVA_ALGO_SELECTORS     0x1E65488C

static int cmd_probe_delta(void) {
    DH_DRIVER drv;
    if (!driver_up(&drv)) return DH_ERR_SVC_START;

    u64 sysCR3 = 0;
    if (!RpmFindSystemCR3(drv.hDevice, &sysCR3)) {
        driver_down(&drv);
        return DH_ERR_RPM_FAIL;
    }

    u64 procCR3 = 0, eproc = 0;
    if (!RpmFindProcess(drv.hDevice, sysCR3, DH_PROC_NAME, &procCR3, &eproc)) {
        driver_down(&drv);
        return DH_ERR_TARGET_NOT_FOUND;
    }

    u64 peb = 0;
    if (!RpmRead64(drv.hDevice, sysCR3, eproc + g_eproc_peb_off, &peb) || !peb) {
        DH_ERROR("read PEB from EPROCESS failed");
        driver_down(&drv);
        return DH_ERR_RPM_FAIL;
    }

    u64 base = 0, size = 0;
    if (!RpmGetMainImageBase(drv.hDevice, procCR3, peb, &base, &size)) {
        DH_ERROR("read main image base failed");
        driver_down(&drv);
        return DH_ERR_RPM_FAIL;
    }
    DH_INFO("Delta base = 0x%llX  size = 0x%llX", base, size);

    // Verify MZ at base
    u8 mz[4] = {0};
    RpmReadVirtual(drv.hDevice, procCR3, base, mz, 4);
    if (mz[0] != 'M' || mz[1] != 'Z') {
        DH_ERROR("no MZ at image base — bailing");
        driver_down(&drv);
        return DH_ERR_RPM_FAIL;
    }

    // FUObjectArray layout (UE4.24):
    //   +0x00 int32 ObjFirstGCIndex
    //   +0x04 int32 ObjLastNonGCIndex
    //   +0x08 int32 MaxObjectsNotConsideredByGC
    //   +0x0C bool  OpenForDisregardForGC
    //   +0x10 FChunkedFixedUObjectArray ObjObjects {
    //             FUObjectItem** Objects   (+0x10)
    //             FUObjectItem*  PreAlloc  (+0x18)
    //             int32 MaxElements        (+0x20)
    //             int32 NumElements        (+0x24)
    //             int32 MaxChunks          (+0x28)
    //             int32 NumChunks          (+0x2C) }
    u64 gobjectsVA = base + DELTA_RVA_GOBJECTS;
    u8 gobj[0x40] = {0};
    if (!RpmReadVirtual(drv.hDevice, procCR3, gobjectsVA, gobj, sizeof(gobj))) {
        DH_ERROR("read GObjects @ 0x%llX failed", gobjectsVA);
        driver_down(&drv);
        return DH_ERR_RPM_FAIL;
    }
    printf("[gobjects] VA=0x%llX (base+0x%X):\n", gobjectsVA, DELTA_RVA_GOBJECTS);
    printf("  raw[0x00..0x40]:\n    ");
    for (int i = 0; i < 0x40; i++) {
        printf("%02X ", gobj[i]);
        if ((i & 0xF) == 0xF) printf("\n    ");
    }
    printf("\n");

    i32 firstGC   = *(i32*)(gobj + 0x00);
    i32 lastNonGC = *(i32*)(gobj + 0x04);
    i32 maxNoGC   = *(i32*)(gobj + 0x08);
    u64 objChunks = *(u64*)(gobj + 0x10);
    u64 preAlloc  = *(u64*)(gobj + 0x18);
    i32 maxElem   = *(i32*)(gobj + 0x20);
    i32 numElem   = *(i32*)(gobj + 0x24);
    i32 maxChunks = *(i32*)(gobj + 0x28);
    i32 numChunks = *(i32*)(gobj + 0x2C);
    printf("  FUObjectArray:  FirstGC=%d LastNonGC=%d MaxNoGC=%d\n",
           firstGC, lastNonGC, maxNoGC);
    printf("  FChunkedArray:  Chunks=0x%llX PreAlloc=0x%llX Max=%d Num=%d MaxChunks=%d NumChunks=%d\n",
           objChunks, preAlloc, maxElem, numElem, maxChunks, numChunks);

    // Read first chunk pointer, then first FUObjectItem
    if (objChunks) {
        u64 chunk0 = 0;
        if (RpmRead64(drv.hDevice, procCR3, objChunks, &chunk0) && chunk0) {
            printf("  Chunks[0] = 0x%llX\n", chunk0);
            // FUObjectItem is 24 bytes: {UObject* Object, int32 Flags, int32 ClusterRootIndex, int32 SerialNumber, int32 pad}
            u8 item[24] = {0};
            if (RpmReadVirtual(drv.hDevice, procCR3, chunk0, item, sizeof(item))) {
                u64 obj0    = *(u64*)(item + 0);
                i32 flags   = *(i32*)(item + 8);
                i32 cluster = *(i32*)(item + 12);
                i32 serial  = *(i32*)(item + 16);
                printf("  FUObjectItem[0]: Object=0x%llX Flags=0x%X Cluster=%d Serial=%d\n",
                       obj0, flags, cluster, serial);

                // Read UObject with DELTA REORDERED layout (Class@0x08, Name@0x1C, Index@0x24)
                if (obj0) {
                    u8 uobj[0x28] = {0};
                    if (RpmReadVirtual(drv.hDevice, procCR3, obj0, uobj, sizeof(uobj))) {
                        u64 vtbl    = *(u64*)(uobj + UOBJ_VTABLE);
                        u64 objCls  = *(u64*)(uobj + UOBJ_CLASS);
                        u64 outer   = *(u64*)(uobj + UOBJ_OUTER);
                        u32 objFlgs = *(u32*)(uobj + UOBJ_FLAGS);
                        u32 nCmpIdx = *(u32*)(uobj + UOBJ_NAME);
                        u32 nNumber = *(u32*)(uobj + UOBJ_NAME + 4);
                        i32 objIdx  = *(i32*)(uobj + UOBJ_INDEX);
                        printf("  UObject[0]: vtbl=0x%llX Class=0x%llX Outer=0x%llX Flags=0x%X Name={%u,%u} Idx=%d\n",
                               vtbl, objCls, outer, objFlgs, nCmpIdx, nNumber, objIdx);

                        // Resolve names via FNamePool
                        u64 gNames = base + 0x1E661B40;
                        char objName[128] = {0};
                        char clsName[128] = {0};
                        RpmResolveFName(drv.hDevice, procCR3, gNames, nCmpIdx, objName, sizeof(objName));
                        RpmGetObjectClassName(drv.hDevice, procCR3, gNames, obj0, clsName, sizeof(clsName));
                        printf("  UObject[0]: name=\"%s\"  class=\"%s\"\n", objName, clsName);
                    }
                }
            }
        }
    }

    // Read ObfuscationMode + AlgorithmSelectors — first bytes for later port
    u8 obfMode[16] = {0}, algoSel[16] = {0};
    RpmReadVirtual(drv.hDevice, procCR3, base + DELTA_RVA_OBFUSCATION_MODE, obfMode, 16);
    RpmReadVirtual(drv.hDevice, procCR3, base + DELTA_RVA_ALGO_SELECTORS, algoSel, 16);
    printf("[obfMode]  @0x%llX: ", base + DELTA_RVA_OBFUSCATION_MODE);
    for (int i = 0; i < 16; i++) printf("%02X ", obfMode[i]);
    printf("\n");
    printf("[algoSel]  @0x%llX: ", base + DELTA_RVA_ALGO_SELECTORS);
    for (int i = 0; i < 16; i++) printf("%02X ", algoSel[i]);
    printf("\n");

    driver_down(&drv);
    return DH_OK;
}

// ---- entry ----

// ---- daemon: production mode ----
//
// Driver stays loaded across game session. Polls for Delta every second.
// When Delta appears: reads image base, verifies GObjects, starts snapshot
// loop that publishes world state to overlay via shared memory (TBD).
// On Ctrl-C: clean shutdown — driver unloaded, service removed.

static volatile BOOL g_daemon_running = TRUE;
static BOOL WINAPI daemon_ctrl_handler(DWORD sig) {
    (void)sig;
    g_daemon_running = FALSE;
    return TRUE;
}

static int cmd_daemon(void) {
    DH_DRIVER drv;
    if (!driver_up(&drv)) return DH_ERR_SVC_START;

    // Verify RPM primitive is functional before entering the wait loop
    u64 sysCR3 = 0;
    if (!RpmFindSystemCR3(drv.hDevice, &sysCR3)) {
        driver_down(&drv);
        return DH_ERR_RPM_FAIL;
    }
    DH_INFO("daemon armed — sysCR3=0x%llX", sysCR3);
    DH_INFO("waiting for %s ... (Ctrl-C to stop)", DH_PROC_NAME);

    SetConsoleCtrlHandler(daemon_ctrl_handler, TRUE);

    u64 lastProcCR3 = 0;
    u64 lastBase    = 0;

    while (g_daemon_running) {
        u64 procCR3 = 0, eproc = 0;
        if (RpmFindProcess(drv.hDevice, sysCR3, DH_PROC_NAME, &procCR3, &eproc)) {
            if (procCR3 != lastProcCR3) {
                // First detection or process relaunched
                lastProcCR3 = procCR3;
                lastBase    = 0;

                u64 peb = 0;
                RpmRead64(drv.hDevice, sysCR3, eproc + g_eproc_peb_off, &peb);

                u64 base = 0, size = 0;
                if (peb && RpmGetMainImageBase(drv.hDevice, procCR3, peb, &base, &size)) {
                    lastBase = base;
                    DH_INFO(">>> Delta detected: base=0x%llX size=0x%llX", base, size);

                    // GObjects sanity probe
                    u64 gobj = base + DELTA_RVA_GOBJECTS;
                    u8 head[16] = {0};
                    if (RpmReadVirtual(drv.hDevice, procCR3, gobj, head, sizeof(head))) {
                        printf("    GObjects @ 0x%llX head: ", gobj);
                        for (int i = 0; i < 16; i++) printf("%02X ", head[i]);
                        printf("\n");
                    }
                } else {
                    DH_WARN("Delta process found but PEB read failed — retry next tick");
                    lastProcCR3 = 0;
                }
            }
            // TODO: snapshot loop — read GObjects → walk actors → publish to shared mem
        } else {
            if (lastProcCR3) {
                DH_INFO("<<< Delta gone");
                lastProcCR3 = 0;
                lastBase    = 0;
            }
        }
        Sleep(1000);
    }

    DH_INFO("daemon stopping — unloading driver");
    driver_down(&drv);
    return DH_OK;
}

// AMSI + ETW prologue patches, applied at process init.
extern void DhInitHardening(void);

// Auth-check watchdog scaffolding. DhAuthCheckStart can hang inside WinHTTP
// WPAD lookup under launcher-spawned elevated child (Windows bug, no fix
// in-DLL); we run it on a thread and cap the wait so a hang doesn't stall
// the ready-event signal launcher waits on.
static volatile LONG g_auth_result = -1;   // -1 pending, 0 fail, 1 ok
static int           g_auth_argc   = 0;
static DWORD WINAPI DhAuthThreadProc(LPVOID p) {
    wchar_t** argv = (wchar_t**)p;
    BOOL r = DhAuthCheckStart(g_auth_argc, argv);
    InterlockedExchange(&g_auth_result, r ? 1 : 0);
    return 0;
}

int wmain(int argc, wchar_t** argv) {
    // AMSI/ETW blind FIRST — before any string logging that Defender might
    // scan, before any ETW event that a kernel driver might tap. Zero-impact
    // on functionality; disarms two of the most common in-process signals.
    DhInitHardening();

    // Failsafe for detached spawns (e.g. CreateProcessAsUser via WTS token,
    // Session 0 → Session 1 handoff): stdout/stderr HANDLE can be NULL or
    // INVALID_HANDLE_VALUE, causing fprintf/wprintf to crash on log calls.
    // Redirect both to NUL unconditionally — if a real console is attached
    // by the parent, cmd.exe's redirection wraps stdio at process start
    // BEFORE main runs, so this reopen only affects the detached case.
    {
        HANDLE ho = GetStdHandle(STD_OUTPUT_HANDLE);
        HANDLE he = GetStdHandle(STD_ERROR_HANDLE);
        if (ho == NULL || ho == INVALID_HANDLE_VALUE) freopen("NUL", "w", stdout);
        if (he == NULL || he == INVALID_HANDLE_VALUE) freopen("NUL", "w", stderr);
    }

    // Runtime PE-header sanitizer — wipe MZ + PE\0\0 in memory so Yara/EDR
    // pattern-scans that hunt module headers at process-base miss.
    // Disabled 2026-09-26: caused CreateThread(DaemonEspRun_ThreadEntry) to
    // return err=193 (ERROR_BAD_EXE_FORMAT) even with minimal 6-byte wipe.
    // Root cause: ntdll's thread-create path re-reads PE headers for CFG /
    // thread-notification callbacks on newer Win11 builds. Re-enable via
    // post-DaemonEspRun spawn window (after all CreateThread calls are done).
    // (void)DhWipeOwnPeHeaders();

    // Enable SeDebugPrivilege — required so NtQuerySystemInformation returns
    // unbiased kernel module addresses (ntoskrnl.Base). Without it Windows
    // zeros the address and dh_rpm's PsInitialSystemProcess resolver fails
    // with "ntoskrnl base: 0x0 -> failed to read ntoskrnl DOS header".
    {
        HANDLE hTok = NULL;
        if (OpenProcessToken(GetCurrentProcess(),
                             TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hTok)) {
            TOKEN_PRIVILEGES tp;
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            if (LookupPrivilegeValueW(NULL, L"SeDebugPrivilege",
                                       &tp.Privileges[0].Luid)) {
                AdjustTokenPrivileges(hTok, FALSE, &tp,
                                       sizeof(tp), NULL, NULL);
                DWORD e = GetLastError();
                if (e == ERROR_SUCCESS) {
                    DH_INFO("SeDebugPrivilege enabled");
                } else {
                    DH_WARN("SeDebugPrivilege enable failed err=%lu "
                            "(kernel addresses will be zero-biased)", e);
                }
            }
            CloseHandle(hTok);
        }
    }

    banner();

    // Anti-piracy Phase 1 — presence check on ORIGINAL argv (before filter
    // strips --koenflow-launch-context). A leaked WinRuntimeHost.exe run
    // standalone has neither env token nor the arg → silent ExitProcess.
    // KoenFlow already validated the license server-side before our spawn,
    // so presence alone is sufficient (backend /preview endpoint consumes
    // the token on first call — we can't re-validate here without breaking
    // KoenFlow's own preview). Dev builds bypass with dev subcommands like
    // `probe-inpoutx64`, `vtbl-decrypt`, etc.
    {
        BOOL is_dev_cmd = FALSE;
        for (int i = 1; i < argc; i++) {
            const wchar_t* a = argv[i];
            if (a[0] == L'-' && a[1] == L'-') continue;  // skip flags
            // Only these commands run without KoenFlow context (dev tools).
            if (!wcscmp(a, L"version") || !wcscmp(a, L"unpack") ||
                !wcscmp(a, L"probe-inpoutx64") || !wcscmp(a, L"probe-providers") ||
                !wcscmp(a, L"c280") || !wcscmp(a, L"vtbl-decrypt") ||
                !wcscmp(a, L"rpm") || !wcscmp(a, L"daemon-esp") ||
                !wcscmp(a, L"overlay") || !wcscmp(a, L"overlay-imgui") ||
                !wcscmp(a, L"esp-vtbl")) {
                is_dev_cmd = TRUE;
            }
            break;
        }
        if (!is_dev_cmd) {
            if (!DhAuthPresenceCheck(argc, argv)) {
                // Silent exit — no MessageBox, no log surface. Pirate stub
                // sees a clean process termination and nothing else.
                ExitProcess(0);
            }
        }
    }

    // Site's elevated launcher (Launcher.Infrastructure.BackendProductLaunchService)
    // appends `--koenflow-launch-context <path>` and its typo-alias
    // `--keonflow-launch-context <path>` after our LAUNCH ARGUMENTS. Strip
    // those so argv[1] is always our real command. If nothing else is left
    // (empty LAUNCH ARGUMENTS), default to `run` so the site's Play button
    // just works.
    static wchar_t* s_filtered[64];
    static const wchar_t s_default_cmd[] = L"run";
    int fc = 0;
    s_filtered[fc++] = argv[0];
    for (int i = 1; i < argc && fc < 63; i++) {
        if (!wcscmp(argv[i], L"--koenflow-launch-context") ||
            !wcscmp(argv[i], L"--keonflow-launch-context") ||
            !wcscmp(argv[i], L"--launch-context")) {
            // skip the flag and its value
            if (i + 1 < argc) i++;
            continue;
        }
        s_filtered[fc++] = argv[i];
    }
    if (fc == 1) s_filtered[fc++] = (wchar_t*)s_default_cmd;
    argv = s_filtered;
    argc = fc;

    if (argc < 2) { usage(); return DH_ERR_BAD_ARG; }

    // Hollow-self dispatch (currently disabled). Classic hollow via
    // VirtualAllocEx + WriteProcessMemory fails LdrpInitializeProcess because
    // Windows loader expects SEC_IMAGE mapping, not private RWX. Fix path is
    // proper Process Ghosting (~3-4h work). For now stealth handled via
    // rename + kernel PID unlink (see HideOurPidFromTaskManager).
    // if (AmIHollowed()) { ... } else { HollowSelfIntoDllhost(argv[1]); }

    // version/unpack — no admin needed
    if (!wcscmp(argv[1], L"version")) {
        printf("%s\n", DH_LOADER_VERSION_STR);
        return DH_OK;
    }

    // inpoutx64 RPM smoke test — verified REDFOX IOCTL codes.
    // Loads inpoutx64 provider + reads 8 bytes at phys 0x1000.
    // Should print MZ signature (0x00905A4D) if SCM stub landed there.
    if (!wcscmp(argv[1], L"probe-inpoutx64")) {
        if (!is_elevated()) DH_FATAL("must run elevated");
        extern const DH_PROVIDER g_providers[];
        extern const int g_provider_count;
        const DH_PROVIDER* p = NULL;
        for (int i = 0; i < g_provider_count; i++) {
            if (g_providers[i].kdu_id == 26) { p = &g_providers[i]; break; }
        }
        if (!p) { DH_ERROR("inpoutx64 not in registry"); return DH_ERR_GENERIC; }

        HANDLE dev = NULL;
        if (!DhProviderTry(p, &dev)) {
            DH_ERROR("provider load failed");
            return DH_ERR_SVC_START;
        }
        DH_INFO("device open: kdu#%u %s", p->kdu_id, p->name);

        // Test 1: read 8 bytes at phys 0x1000
        u64 v = 0;
        if (DhProviderPhysRead(dev, p, 0x1000, &v, 8)) {
            DH_INFO("phys[0x1000] = 0x%016llX (expected MZ 0x00905A4D if stub landed)",
                    (unsigned long long)v);
        } else {
            DH_ERROR("phys read @0x1000 failed");
        }

        // Test 2: read low IDT / bios area — usually static
        u64 idt = 0;
        if (DhProviderPhysRead(dev, p, 0x400, &idt, 8)) {
            DH_INFO("phys[0x0400] = 0x%016llX", (unsigned long long)idt);
        }
        CloseHandle(dev);
        return DH_OK;
    }

    // Provider chain probe — tries each kdu driver in registry, reports
    // which one loads under current HVCI/Hyper-V state.
    if (!wcscmp(argv[1], L"probe-providers")) {
        if (!is_elevated()) DH_FATAL("must run elevated");
        extern const DH_PROVIDER g_providers[];
        extern const int g_provider_count;

        printf("=== Testing %d providers ===\n\n", g_provider_count);
        int wins = 0;
        for (int i = 0; i < g_provider_count; i++) {
            const DH_PROVIDER* p = &g_providers[i];
            printf("[%2d] kdu#%u  %-40s pri=%d\n", i, p->kdu_id, p->name, p->priority);
            HANDLE dev = NULL;
            if (DhProviderTry(p, &dev)) {
                printf("     >>> LIVE! dev=%p\n\n", dev);
                CloseHandle(dev);
                wins++;
            } else {
                printf("     xxx failed\n\n");
            }
        }
        printf("=== %d/%d providers live ===\n", wins, g_provider_count);
        return DH_OK;
    }
    // Offline C280 decrypt test — no driver needed. Test cipher-vs-cipher.
    if (!wcscmp(argv[1], L"c280")) {
        if (argc < 6) {
            wprintf(L"usage: c280 <X_hex> <Y_hex> <Z_hex> <Idx_hex> [rbx_hex]\n");
            return DH_ERR_BAD_ARG;
        }
        u32 xin = wcstoul(argv[2], NULL, 16);
        u32 yin = wcstoul(argv[3], NULL, 16);
        u32 zin = wcstoul(argv[4], NULL, 16);
        u16 idx = (u16)wcstoul(argv[5], NULL, 16);
        u32 rbx = (argc >= 7) ? wcstoul(argv[6], NULL, 16) : 0x2537u;
        u32 xo=0, yo=0, zo=0;
        BOOL ok = C280DecryptExternalEx(idx, rbx, xin, yin, zin, &xo, &yo, &zo);
        wprintf(L"in : X=0x%08X Y=0x%08X Z=0x%08X idx=0x%04X rbx=0x%X\n", xin, yin, zin, idx, rbx);
        wprintf(L"out: X=0x%08X Y=0x%08X Z=0x%08X ok=%d\n", xo, yo, zo, ok);
        union { u32 u; float f; } fx, fy, fz;
        fx.u = xo; fy.u = yo; fz.u = zo;
        wprintf(L"out float: (%.4f, %.4f, %.4f)\n", fx.f, fy.f, fz.f);
        return DH_OK;
    }

    if (!wcscmp(argv[1], L"unpack")) {
        if (argc < 4) {
            DH_ERROR("usage: dh_loader.exe unpack <in.bin> <out.sys>");
            return DH_ERR_BAD_ARG;
        }
        return cmd_unpack_bin(argv[2], argv[3]) ? DH_OK : DH_ERR_DB_UNPACK;
    }

    // Offline decrypt test — pure user-mode, no driver, no admin needed.
    if (!wcscmp(argv[1], L"vtbl-decrypt")) {
        if (argc < 6) {
            wprintf(L"usage: vtbl-decrypt <X_bits_hex> <Y_bits_hex> <Z_bits_hex> <Index_hex> [flags_hex]\n");
            return DH_ERR_BAD_ARG;
        }
        if (!VtblDecryptInitStatic()) {
            DH_ERROR("VtblDecryptInitStatic failed");
            return DH_ERR_RPM_FAIL;
        }
        union { float f; u32 u; } fx, fy, fz;
        fx.u = wcstoul(argv[2], NULL, 16);
        fy.u = wcstoul(argv[3], NULL, 16);
        fz.u = wcstoul(argv[4], NULL, 16);
        u16 idx = (u16)wcstoul(argv[5], NULL, 16);
        u8  flg = (argc >= 7) ? (u8)wcstoul(argv[6], NULL, 16) : 0x01;
        DH_ENC_VECTOR enc = { fx.f, fy.f, fz.f, { idx, 1, flg } };
        DH_FVECTOR out = {0};
        if (!VtblDecryptCall(&enc, &out)) {
            DH_ERROR("VtblDecryptCall faulted");
            VtblDecryptFree();
            return DH_ERR_RPM_FAIL;
        }
        wprintf(L"in : X_bits=0x%08X Y_bits=0x%08X Z_bits=0x%08X Index=0x%04X flg=0x%02X\n",
                fx.u, fy.u, fz.u, idx, flg);
        wprintf(L"in float: (%.4f, %.4f, %.4f)\n", fx.f, fy.f, fz.f);
        union { float f; u32 u; } ox, oy, oz;
        ox.f = out.X; oy.f = out.Y; oz.f = out.Z;
        wprintf(L"out: X_bits=0x%08X Y_bits=0x%08X Z_bits=0x%08X\n", ox.u, oy.u, oz.u);
        wprintf(L"out float: (%.4f, %.4f, %.4f)\n", out.X, out.Y, out.Z);
        VtblDecryptFree();
        return DH_OK;
    }

    // UI-only dispatch — overlay-imgui doesn't need admin/driver, so bypass
    // the elevated gate. Panel renders, world ESP is idle (shmem is empty).
    if (!wcscmp(argv[1], L"overlay-imgui")) {
        extern int OverlayRunImGui(void);
        return OverlayRunImGui();
    }

    if (!is_elevated())
        DH_FATAL("must run elevated");

    if (!wcscmp(argv[1], L"ping"))         return cmd_ping();
    if (!wcscmp(argv[1], L"probe-delta"))  return cmd_probe_delta();
    if (!wcscmp(argv[1], L"rpm"))          return cmd_rpm(argc, argv);
    if (!wcscmp(argv[1], L"daemon"))       return cmd_daemon();

    if (!wcscmp(argv[1], L"dump-fnamepool")) {
        DH_DRIVER drv;
        if (!driver_up(&drv)) return DH_ERR_SVC_START;
        u64 sysCR3 = 0, procCR3 = 0, eproc = 0, peb = 0, base = 0, size = 0;
        int rc = DH_OK;
        do {
            if (!RpmFindSystemCR3(drv.hDevice, &sysCR3)) { rc = DH_ERR_RPM_FAIL; break; }
            if (!RpmFindProcess(drv.hDevice, sysCR3, DH_PROC_NAME, &procCR3, &eproc)) { rc = DH_ERR_TARGET_NOT_FOUND; break; }
            RpmRead64(drv.hDevice, sysCR3, eproc + g_eproc_peb_off, &peb);
            if (!RpmGetMainImageBase(drv.hDevice, procCR3, peb, &base, &size)) { base = 0x140000000ULL; size = 0x1F800000; DH_INFO("PEB failed, using hardcoded base 0x140000000"); }

            u64 gNames = base + 0x1E661B40;
            u8 hdr[0x60] = {0};
            RpmReadVirtual(drv.hDevice, procCR3, gNames, hdr, sizeof(hdr));
            printf("[FNamePool header @ 0x%llX]\n", gNames);
            for (int i = 0; i < 0x60; i += 0x10) {
                printf("  +0x%02X: ", i);
                for (int j = 0; j < 16; j++) printf("%02X ", hdr[i+j]);
                printf("  ");
                for (int j = 0; j < 16; j++) {
                    u8 c = hdr[i+j];
                    putchar((c>=0x20 && c<0x7F)?c:'.');
                }
                putchar('\n');
            }

            // Try both candidate offsets for Blocks[]: 0x08, 0x10, 0x20, 0x28
            for (u32 blkOff = 0x00; blkOff <= 0x40; blkOff += 8) {
                u64 blk0 = *(u64*)(hdr + blkOff);
                if (blk0 && (blk0 >> 47) == 0) {  // likely userspace ptr
                    printf("\n[Candidate Blocks @ +0x%02X: ptr=0x%llX]\n", blkOff, blk0);
                    u8 blkHead[0x40] = {0};
                    if (RpmReadVirtual(drv.hDevice, procCR3, blk0, blkHead, sizeof(blkHead))) {
                        for (int i = 0; i < 0x40; i += 0x10) {
                            printf("  +0x%02X: ", i);
                            for (int j = 0; j < 16; j++) printf("%02X ", blkHead[i+j]);
                            printf("  ");
                            for (int j = 0; j < 16; j++) {
                                u8 c = blkHead[i+j] ^ 0x0E;
                                putchar((c>=0x20 && c<0x7F)?c:'.');
                            }
                            printf("  (^0x0E)\n");
                        }
                    }
                }
            }
        } while (0);
        driver_down(&drv);
        return rc;
    }

    if (!wcscmp(argv[1], L"walk-gobjects")) {
        u32 count = 32;
        if (argc >= 3) count = (u32)wcstoul(argv[2], NULL, 0);
        if (count > 5000) count = 5000;

        DH_DRIVER drv;
        if (!driver_up(&drv)) return DH_ERR_SVC_START;
        u64 sysCR3 = 0, procCR3 = 0, eproc = 0, peb = 0, base = 0, size = 0;
        int rc = DH_OK;
        do {
            if (!RpmFindSystemCR3(drv.hDevice, &sysCR3)) { rc = DH_ERR_RPM_FAIL; break; }
            if (!RpmFindProcess(drv.hDevice, sysCR3, DH_PROC_NAME, &procCR3, &eproc)) { rc = DH_ERR_TARGET_NOT_FOUND; break; }
            RpmRead64(drv.hDevice, sysCR3, eproc + g_eproc_peb_off, &peb);
            if (!RpmGetMainImageBase(drv.hDevice, procCR3, peb, &base, &size)) { base = 0x140000000ULL; size = 0x1F800000; DH_INFO("PEB failed, using hardcoded base 0x140000000"); }

            u64 gObjects = base + DELTA_RVA_GOBJECTS;
            u64 gNames   = base + 0x1E661B40;

            // Read live counters
            u32 numElements = 0;
            RpmReadVirtual(drv.hDevice, procCR3, gObjects + 0x04, &numElements, 4);
            DH_INFO("GObjects live count = %u (dumping first %u)", numElements, count);

            for (u32 i = 0; i < count; i++) {
                u64 obj = 0;
                if (!RpmGetUObjectByIndex(drv.hDevice, procCR3, gObjects, (i32)i, &obj) || !obj)
                    continue;
                char name[128] = {0}, cls[128] = {0};
                RpmGetObjectName(drv.hDevice, procCR3, gNames, obj, name, sizeof(name));
                RpmGetObjectClassName(drv.hDevice, procCR3, gNames, obj, cls, sizeof(cls));
                printf("  [%5u] 0x%llX  %-24s  %s\n", i, obj, cls, name);
            }
        } while (0);
        driver_down(&drv);
        return rc;
    }

    if (!wcscmp(argv[1], L"probe-peb")) {
        // Systematic sweep of EPROCESS structure to find PEB
        DH_DRIVER drv;
        if (!driver_up(&drv)) return DH_ERR_SVC_START;
        u64 sysCR3 = 0, procCR3 = 0, eproc = 0;
        int rc = DH_OK;
        do {
            if (!RpmFindSystemCR3(drv.hDevice, &sysCR3)) { rc = DH_ERR_RPM_FAIL; break; }
            if (!RpmFindProcess(drv.hDevice, sysCR3, DH_PROC_NAME, &procCR3, &eproc)) { rc = DH_ERR_TARGET_NOT_FOUND; break; }
            printf("Scanning EPROCESS 0x%llX for PEB-shaped values...\n", eproc);
            // Sweep 0x00 .. 0x800 in 8-byte steps
            for (u64 off = 0; off < 0x800; off += 8) {
                u64 val = 0;
                if (!RpmRead64(drv.hDevice, sysCR3, eproc + off, &val)) continue;
                // PEB shape: 0x00007FFxxxxxxxxx or 0x0000nnnnnnnnnnnn (usermode)
                if (val >= 0x00010000 && val < 0x00007FFFFFFFFFFF && (val & 0xFFF) == 0) {
                    // Looks like a user-mode aligned pointer.
                    // Try reading PEB.ImageBase at +0x10 (should be 0x140000000-ish)
                    u64 imgbase = 0;
                    if (RpmRead64(drv.hDevice, procCR3, val + 0x10, &imgbase)) {
                        if (imgbase >= 0x140000000 && imgbase < 0x180000000) {
                            printf("  EPROC+0x%03llX = 0x%016llX  --> PEB.ImageBase = 0x%llX  <== HIT\n",
                                   off, val, imgbase);
                        }
                    }
                }
            }
            // Also — try alt approach: check if procCR3 works via read at image base directly
            printf("\nDirect read tests (procCR3=0x%llX):\n", procCR3);
            u64 testvas[] = { 0x140000000ULL, 0x140001000ULL, 0x141000000ULL };
            for (int i = 0; i < 3; i++) {
                u64 testva = testvas[i];
                u8 buf[16] = {0};
                if (RpmReadVirtual(drv.hDevice, procCR3, testva, buf, 16)) {
                    printf("  va=0x%llX: %02X %02X %02X %02X (works)\n", testva, buf[0], buf[1], buf[2], buf[3]);
                } else {
                    printf("  va=0x%llX: read FAILED\n", testva);
                }
            }
        } while (0);
        driver_down(&drv);
        return rc;
    }

    if (!wcscmp(argv[1], L"read-va")) {
        // Read N bytes from arbitrary VA (absolute) — for heap/UObject reads
        if (argc < 4) { DH_ERROR("usage: read-va <va-hex> <size-hex>"); return DH_ERR_BAD_ARG; }
        u64 va = _wcstoui64(argv[2], NULL, 16);
        u32 sz = (u32)wcstoul(argv[3], NULL, 16);
        if (sz == 0 || sz > 0x10000) sz = 0x100;

        DH_DRIVER drv;
        if (!driver_up(&drv)) return DH_ERR_SVC_START;
        u64 sysCR3 = 0, procCR3 = 0, eproc = 0;
        int rc = DH_OK;
        do {
            if (!RpmFindSystemCR3(drv.hDevice, &sysCR3)) { rc = DH_ERR_RPM_FAIL; break; }
            if (!RpmFindProcess(drv.hDevice, sysCR3, DH_PROC_NAME, &procCR3, &eproc)) { rc = DH_ERR_TARGET_NOT_FOUND; break; }
            u8* buf = (u8*)HeapAlloc(GetProcessHeap(), 0, sz);
            if (!buf) { rc = DH_ERR_GENERIC; break; }
            if (!RpmReadVirtual(drv.hDevice, procCR3, va, buf, sz)) {
                DH_ERROR("read failed at va=0x%llX", va);
                HeapFree(GetProcessHeap(), 0, buf);
                rc = DH_ERR_RPM_FAIL;
                break;
            }
            printf("# va=0x%llX size=0x%X\n", va, sz);
            for (u32 i = 0; i < sz; i++) {
                if (i % 32 == 0) printf("%08X: ", i);
                printf("%02X ", buf[i]);
                if ((i+1) % 32 == 0) printf("\n");
            }
            if (sz % 32) printf("\n");
            HeapFree(GetProcessHeap(), 0, buf);
        } while (0);
        driver_down(&drv);
        return rc;
    }

    if (!wcscmp(argv[1], L"scan-dt-loot")) {
        // Like scan-datatables but for each populated DT, also resolve the
        // first non-empty FName key, filter to Delta loot categories.
        DH_DRIVER drv;
        if (!driver_up(&drv)) return DH_ERR_SVC_START;
        u64 sysCR3=0, procCR3=0, eproc=0, peb=0, base=0, size=0;
        int rc = DH_OK;
        do {
            if (!RpmFindSystemCR3(drv.hDevice, &sysCR3)) { rc=DH_ERR_RPM_FAIL; break; }
            if (!RpmFindProcess(drv.hDevice, sysCR3, DH_PROC_NAME, &procCR3, &eproc)) { rc=DH_ERR_TARGET_NOT_FOUND; break; }
            RpmRead64(drv.hDevice, sysCR3, eproc + g_eproc_peb_off, &peb);
            RpmGetMainImageBase(drv.hDevice, procCR3, peb, &base, &size);
            u64 gObj = base + DELTA_RVA_GOBJECTS;
            u64 gNames = base + DF_RVA_FNAMEPOOL;
            u32 numElements = 0;
            RpmReadVirtual(drv.hDevice, procCR3, gObj + 0x04, &numElements, 4);
            DH_INFO("scanning %u for DataTables with loot-category keys", numElements);
            int scanned = 0, matched = 0;
            for (u32 i = 0; i < numElements && matched < 30; i++) {
                u64 obj = 0;
                if (!RpmGetUObjectByIndex(drv.hDevice, procCR3, gObj, (i32)i, &obj) || !obj) continue;
                char cls[64] = {0};
                if (!RpmGetObjectClassName(drv.hDevice, procCR3, gNames, obj, cls, sizeof(cls))) continue;
                if (strcmp(cls, "DataTable") != 0) continue;
                scanned++;
                static const u32 candOffs[] = { 0x30, 0x38, 0x48, 0x50, 0x58, 0x60, 0x68, 0x70 };
                for (int c = 0; c < (int)(sizeof(candOffs)/sizeof(candOffs[0])); c++) {
                    u64 dataPtr = 0;
                    RpmReadVirtual(drv.hDevice, procCR3, obj + candOffs[c], &dataPtr, 8);
                    if (dataPtr < 0x100000000ULL || dataPtr >= 0x0001000000000000ULL) continue;
                    u8 sanity = 0;
                    if (!RpmReadVirtual(drv.hDevice, procCR3, dataPtr, &sanity, 1)) continue;
                    i32 num = 0;
                    RpmReadVirtual(drv.hDevice, procCR3, obj + candOffs[c] + 8, &num, 4);
                    if (num <= 0 || num > 20000) continue;
                    // Walk first entries, skip empty slots (key=-1), resolve key.
                    for (int e = 0; e < 8; e++) {
                        u32 kIdx = 0;
                        u64 vPtr = 0;
                        u64 slot = dataPtr + (u64)e * 0x18;
                        RpmReadVirtual(drv.hDevice, procCR3, slot,       &kIdx, 4);
                        RpmReadVirtual(drv.hDevice, procCR3, slot + 0x8, &vPtr, 8);
                        if (kIdx == 0xFFFFFFFFu || kIdx == 0) continue;
                        char kn[64] = {0};
                        if (!RpmResolveFName(drv.hDevice, procCR3, gNames, kIdx, kn, sizeof(kn))) break;
                        if (!kn[0]) break;
                        // Loot categories: keys start with "99", "14", "12", "3", "4", "8", "9", "11"
                        int is_loot = 0;
                        if (strlen(kn) >= 10 && strlen(kn) <= 11) {
                            // Must be all digits
                            int all_digits = 1;
                            for (int j = 0; kn[j]; j++) {
                                if (kn[j] < '0' || kn[j] > '9') { all_digits = 0; break; }
                            }
                            if (all_digits) is_loot = 1;
                        }
                        if (is_loot) {
                            char nm[64] = {0};
                            RpmGetObjectName(drv.hDevice, procCR3, gNames, obj, nm, sizeof(nm));
                            printf("[LOOT %d] table=\"%s\" num=%d dataPtr=0x%llX firstKey=\"%s\"\n",
                                   ++matched, nm, num, dataPtr, kn);
                        }
                        break;
                    }
                    break;   // done with this DT
                }
            }
            DH_INFO("done — scanned=%d matched=%d", scanned, matched);
        } while (0);
        driver_down(&drv);
        return rc;
    }

    if (!wcscmp(argv[1], L"scan-datatables")) {
        // Walk GObjects for class=="DataTable". For each, probe +0x30/+0x48
        // for a heap ptr that's committed (RowMap Data). Print top N.
        DH_DRIVER drv;
        if (!driver_up(&drv)) return DH_ERR_SVC_START;
        u64 sysCR3=0, procCR3=0, eproc=0, peb=0, base=0, size=0;
        int rc = DH_OK;
        do {
            if (!RpmFindSystemCR3(drv.hDevice, &sysCR3)) { rc=DH_ERR_RPM_FAIL; break; }
            if (!RpmFindProcess(drv.hDevice, sysCR3, DH_PROC_NAME, &procCR3, &eproc)) { rc=DH_ERR_TARGET_NOT_FOUND; break; }
            RpmRead64(drv.hDevice, sysCR3, eproc + g_eproc_peb_off, &peb);
            RpmGetMainImageBase(drv.hDevice, procCR3, peb, &base, &size);
            u64 gObj = base + DELTA_RVA_GOBJECTS;
            u64 gNames = base + DF_RVA_FNAMEPOOL;
            u32 numElements = 0;
            RpmReadVirtual(drv.hDevice, procCR3, gObj + 0x04, &numElements, 4);
            DH_INFO("scanning %u for DataTable objects", numElements);
            int hits = 0, populated = 0;
            for (u32 i = 0; i < numElements && populated < 200; i++) {
                u64 obj = 0;
                if (!RpmGetUObjectByIndex(drv.hDevice, procCR3, gObj, (i32)i, &obj) || !obj) continue;
                char cls[64] = {0};
                if (!RpmGetObjectClassName(drv.hDevice, procCR3, gNames, obj, cls, sizeof(cls))) continue;
                if (strcmp(cls, "DataTable") != 0) continue;
                hits++;
                // probe multiple candidate offsets for a committed heap ptr.
                static const u32 candOffs[] = { 0x30, 0x38, 0x48, 0x50, 0x58, 0x60, 0x68, 0x70 };
                for (int c = 0; c < (int)(sizeof(candOffs)/sizeof(candOffs[0])); c++) {
                    u64 rowData = 0;
                    RpmReadVirtual(drv.hDevice, procCR3, obj + candOffs[c], &rowData, 8);
                    if (rowData < 0x100000000ULL) continue;
                    if (rowData >= 0x0001000000000000ULL) continue;
                    // Test commit: read 1 byte.
                    u8 sanity = 0;
                    if (!RpmReadVirtual(drv.hDevice, procCR3, rowData, &sanity, 1)) continue;
                    // Read Num @+offset+8
                    i32 num = 0;
                    RpmReadVirtual(drv.hDevice, procCR3, obj + candOffs[c] + 8, &num, 4);
                    if (num <= 0 || num > 10000) continue;
                    char nm[64] = {0};
                    RpmGetObjectName(drv.hDevice, procCR3, gNames, obj, nm, sizeof(nm));
                    printf("[POP %d] obj=0x%llX name=\"%s\" +0x%x → dataPtr=0x%llX num=%d\n",
                           ++populated, obj, nm, candOffs[c], rowData, num);
                    break;   // found valid ptr for this obj
                }
            }
            DH_INFO("done — %d DataTable objs, %d populated", hits, populated);
        } while (0);
        driver_down(&drv);
        return rc;
    }

    if (!wcscmp(argv[1], L"find-datatable")) {
        // Walk GObjects for a UObject whose Name matches given string.
        if (argc < 3) { DH_ERROR("usage: find-datatable <ascii-name>"); return DH_ERR_BAD_ARG; }
        char target[64] = {0};
        wcstombs_s(NULL, target, sizeof(target), argv[2], _TRUNCATE);
        DH_DRIVER drv;
        if (!driver_up(&drv)) return DH_ERR_SVC_START;
        u64 sysCR3 = 0, procCR3 = 0, eproc = 0, peb = 0, base = 0, size = 0;
        int rc = DH_OK;
        do {
            if (!RpmFindSystemCR3(drv.hDevice, &sysCR3)) { rc = DH_ERR_RPM_FAIL; break; }
            if (!RpmFindProcess(drv.hDevice, sysCR3, DH_PROC_NAME, &procCR3, &eproc)) { rc = DH_ERR_TARGET_NOT_FOUND; break; }
            RpmRead64(drv.hDevice, sysCR3, eproc + g_eproc_peb_off, &peb);
            RpmGetMainImageBase(drv.hDevice, procCR3, peb, &base, &size);
            u64 gObj = base + DELTA_RVA_GOBJECTS;
            u64 gNames = base + DF_RVA_FNAMEPOOL;
            u32 numElements = 0;
            RpmReadVirtual(drv.hDevice, procCR3, gObj + 0x04, &numElements, 4);
            DH_INFO("scanning %u GObjects for name==\"%s\"", numElements, target);
            int hits = 0;
            for (u32 i = 0; i < numElements && hits < 20; i++) {
                u64 obj = 0;
                if (!RpmGetUObjectByIndex(drv.hDevice, procCR3, gObj, (i32)i, &obj) || !obj) continue;
                char nm[64] = {0};
                if (!RpmGetObjectName(drv.hDevice, procCR3, gNames, obj, nm, sizeof(nm))) continue;
                if (nm[0] && strcmp(nm, target) == 0) {
                    char cls[64] = {0};
                    RpmGetObjectClassName(drv.hDevice, procCR3, gNames, obj, cls, sizeof(cls));
                    printf("[HIT %d] obj=0x%llX index=%u class=\"%s\"\n", ++hits, obj, i, cls);
                }
            }
            DH_INFO("done — %d hits", hits);
        } while (0);
        driver_down(&drv);
        return rc;
    }

    if (!wcscmp(argv[1], L"fname")) {
        // Resolve one FName ComparisonIndex → string.
        if (argc < 3) { DH_ERROR("usage: fname <hex-comparison-index>"); return DH_ERR_BAD_ARG; }
        u32 idx = (u32)wcstoul(argv[2], NULL, 16);
        DH_DRIVER drv;
        if (!driver_up(&drv)) return DH_ERR_SVC_START;
        u64 sysCR3 = 0, procCR3 = 0, eproc = 0, peb = 0, base = 0, size = 0;
        int rc = DH_OK;
        do {
            if (!RpmFindSystemCR3(drv.hDevice, &sysCR3)) { rc = DH_ERR_RPM_FAIL; break; }
            if (!RpmFindProcess(drv.hDevice, sysCR3, DH_PROC_NAME, &procCR3, &eproc)) { rc = DH_ERR_TARGET_NOT_FOUND; break; }
            RpmRead64(drv.hDevice, sysCR3, eproc + g_eproc_peb_off, &peb);
            RpmGetMainImageBase(drv.hDevice, procCR3, peb, &base, &size);
            char buf[256] = {0};
            if (RpmResolveFName(drv.hDevice, procCR3, base + DF_RVA_FNAMEPOOL, idx, buf, sizeof(buf))) {
                printf("fname 0x%x -> \"%s\"\n", idx, buf);
            } else {
                printf("fname 0x%x -> (resolve failed)\n", idx);
            }
        } while (0);
        driver_down(&drv);
        return rc;
    }

    if (!wcscmp(argv[1], L"find-item-lookup")) {
        // AOB-scan Delta .text for the call site of GetCommonItemRowByItemID.
        // Pattern (from UC page 68): E8 ? ? ? ? 48 8B F0 48 85 C0 0F 84 ? ?
        //                            ? ? 45 33 ED 4C 89 7D
        //   E8 rel32  = call GetCommonItemRowByItemID
        //   48 8B F0 = mov rsi, rax   (save row ptr)
        //   48 85 C0 = test rax, rax
        //   0F 84 rel32 = je <null-fail branch>
        //   45 33 ED = xor r13d, r13d
        //   4C 89 7D = mov [rbp+...], r15
        // For each hit: emit call_site_va + resolved target = va + 5 + rel32.
        static const u8 pat[]  = {
            0xE8, 0,0,0,0,
            0x48,0x8B,0xF0,
            0x48,0x85,0xC0,
            0x0F,0x84, 0,0,0,0,
            0x45,0x33,0xED,
            0x4C,0x89,0x7D
        };
        static const u8 mask[] = {
            1, 0,0,0,0,
            1,1,1,
            1,1,1,
            1,1, 0,0,0,0,
            1,1,1,
            1,1,1
        };
        const u32 patLen = (u32)sizeof(pat);

        DH_DRIVER drv;
        if (!driver_up(&drv)) return DH_ERR_SVC_START;
        u64 sysCR3 = 0, procCR3 = 0, eproc = 0, peb = 0, base = 0, size = 0;
        int rc = DH_OK;
        do {
            if (!RpmFindSystemCR3(drv.hDevice, &sysCR3)) { rc = DH_ERR_RPM_FAIL; break; }
            if (!RpmFindProcess(drv.hDevice, sysCR3, DH_PROC_NAME, &procCR3, &eproc)) {
                rc = DH_ERR_TARGET_NOT_FOUND; break;
            }
            RpmRead64(drv.hDevice, sysCR3, eproc + g_eproc_peb_off, &peb);
            if (!RpmGetMainImageBase(drv.hDevice, procCR3, peb, &base, &size)) {
                base = 0x140000000ULL; size = 0x1F800000;
            }
            DH_INFO("Delta base=0x%llX size=0x%llX", base, size);

            // Scan first 0x14F52000 bytes (.text) in 4 MiB windows with
            // overlap so patterns straddling boundaries still match.
            const u64 CHUNK    = 0x400000;
            const u64 OVERLAP  = 0x40;
            const u64 TXT_END  = base + 0x14F52000ULL;
            u8* buf = (u8*)HeapAlloc(GetProcessHeap(), 0, (SIZE_T)(CHUNK + OVERLAP));
            if (!buf) { rc = DH_ERR_GENERIC; break; }

            int hits = 0;
            u64 va = base + 0x1000;
            while (va < TXT_END && hits < 20) {
                u32 rd = (va + CHUNK + OVERLAP > TXT_END)
                         ? (u32)(TXT_END - va) : (u32)(CHUNK + OVERLAP);
                if (!RpmReadVirtual(drv.hDevice, procCR3, va, buf, rd)) {
                    va += CHUNK; continue;
                }
                for (u32 i = 0; i + patLen <= rd; i++) {
                    int ok = 1;
                    for (u32 k = 0; k < patLen; k++) {
                        if (mask[k] && buf[i + k] != pat[k]) { ok = 0; break; }
                    }
                    if (!ok) continue;
                    u64 site  = va + i;
                    i32 rel32 = *(i32*)(buf + i + 1);
                    u64 tgt   = site + 5 + (i64)rel32;
                    hits++;
                    printf("[HIT %2d] call_site=0x%llX target=0x%llX (rva=0x%llX)\n",
                           hits, site, tgt, tgt - base);
                }
                va += CHUNK;
            }
            DH_INFO("find-item-lookup done — %d hits", hits);
            HeapFree(GetProcessHeap(), 0, buf);
        } while (0);
        driver_down(&drv);
        return rc;
    }

    if (!wcscmp(argv[1], L"scan-str")) {
        // scan-str <wide|ascii> "needle" — sweep Delta user-space heap
        // (0x10000000..0xFFFFFFFFFFFF) looking for the string. Reads in
        // 4 MiB chunks. Prints up to 64 matches (VA + 64 bytes surround).
        if (argc < 4) {
            DH_ERROR("usage: scan-str <wide|ascii> <needle>");
            return DH_ERR_BAD_ARG;
        }
        int wide = (wcscmp(argv[2], L"wide") == 0);
        // Build needle bytes.
        u8  needle[512];
        u32 nlen = 0;
        {
            size_t wl = wcslen(argv[3]);
            if (wide) {
                if (wl * 2 + 2 > sizeof(needle)) wl = 254;
                for (size_t i = 0; i < wl; i++) {
                    needle[nlen++] = (u8)(argv[3][i] & 0xFF);
                    needle[nlen++] = (u8)((argv[3][i] >> 8) & 0xFF);
                }
            } else {
                if (wl > sizeof(needle)) wl = sizeof(needle);
                for (size_t i = 0; i < wl; i++)
                    needle[nlen++] = (u8)(argv[3][i] & 0xFF);
            }
        }
        DH_INFO("scan-str %s needle-len=%u", wide ? "wide" : "ascii", nlen);

        DH_DRIVER drv;
        if (!driver_up(&drv)) return DH_ERR_SVC_START;
        u64 sysCR3 = 0, procCR3 = 0, eproc = 0;
        int rc = DH_OK;
        do {
            if (!RpmFindSystemCR3(drv.hDevice, &sysCR3)) { rc = DH_ERR_RPM_FAIL; break; }
            if (!RpmFindProcess(drv.hDevice, sysCR3, DH_PROC_NAME, &procCR3, &eproc)) {
                rc = DH_ERR_TARGET_NOT_FOUND; break;
            }

            const u64 CHUNK = 0x400000;       // 4 MiB
            u8* buf = (u8*)HeapAlloc(GetProcessHeap(), 0, CHUNK + 512);
            if (!buf) { rc = DH_ERR_GENERIC; break; }

            // Cover typical UE4 committed heap band.
            u64 va = 0x0000000010000000ULL;
            u64 stop = 0x0000900000000000ULL;   // covers Maik's 0x8FDA... range
            int hits = 0;
            u64 progress_log = 0;

            while (va < stop && hits < 64) {
                if (!RpmReadVirtual(drv.hDevice, procCR3, va, buf, (u32)CHUNK)) {
                    va += CHUNK;
                    continue;
                }
                for (u32 i = 0; i + nlen <= CHUNK; i++) {
                    if (buf[i] != needle[0]) continue;
                    if (memcmp(buf + i, needle, nlen) != 0) continue;
                    u64 hit_va = va + i;
                    hits++;
                    printf("[HIT %2d] VA=0x%llX\n", hits, hit_va);
                    // 64-byte surround dump (32 before + needle + rest).
                    u32 dumpStart = (i >= 32) ? (i - 32) : 0;
                    u32 dumpEnd   = i + nlen + 32;
                    if (dumpEnd > (u32)CHUNK) dumpEnd = (u32)CHUNK;
                    for (u32 k = dumpStart; k < dumpEnd; k++) {
                        if ((k - dumpStart) % 16 == 0)
                            printf("  %08llX: ", va + k);
                        printf("%02X ", buf[k]);
                        if ((k - dumpStart + 1) % 16 == 0) printf("\n");
                    }
                    printf("\n");
                    i += nlen;   // skip past match
                }
                va += CHUNK;
                // Progress every 1 GiB.
                if ((va - progress_log) >= 0x40000000ULL) {
                    DH_INFO("scanned to VA=0x%llX (hits=%d)", va, hits);
                    progress_log = va;
                }
            }
            DH_INFO("scan-str done — total hits=%d", hits);
            HeapFree(GetProcessHeap(), 0, buf);
        } while (0);
        driver_down(&drv);
        return rc;
    }

    if (!wcscmp(argv[1], L"scan-u64")) {
        // scan-u64 <hex-value> — find every 8-byte occurrence of value.
        if (argc < 3) { DH_ERROR("usage: scan-u64 <hex-value>"); return DH_ERR_BAD_ARG; }
        u64 target = _wcstoui64(argv[2], NULL, 16);
        DH_INFO("scan-u64 target=0x%llX", target);

        DH_DRIVER drv;
        if (!driver_up(&drv)) return DH_ERR_SVC_START;
        u64 sysCR3 = 0, procCR3 = 0, eproc = 0;
        int rc = DH_OK;
        do {
            if (!RpmFindSystemCR3(drv.hDevice, &sysCR3)) { rc = DH_ERR_RPM_FAIL; break; }
            if (!RpmFindProcess(drv.hDevice, sysCR3, DH_PROC_NAME, &procCR3, &eproc)) {
                rc = DH_ERR_TARGET_NOT_FOUND; break;
            }
            const u64 CHUNK = 0x400000;
            u8* buf = (u8*)HeapAlloc(GetProcessHeap(), 0, CHUNK);
            if (!buf) { rc = DH_ERR_GENERIC; break; }
            u64 va = 0x0000000010000000ULL, stop = 0x0000900000000000ULL;
            int hits = 0;
            while (va < stop && hits < 200) {
                if (!RpmReadVirtual(drv.hDevice, procCR3, va, buf, (u32)CHUNK)) {
                    va += CHUNK; continue;
                }
                for (u32 i = 0; i + 8 <= CHUNK; i += 8) {
                    if (*(u64*)(buf + i) == target) {
                        printf("[HIT %3d] VA=0x%llX\n", ++hits, va + i);
                        if (hits >= 200) break;
                    }
                }
                va += CHUNK;
            }
            DH_INFO("scan-u64 done — total hits=%d", hits);
            HeapFree(GetProcessHeap(), 0, buf);
        } while (0);
        driver_down(&drv);
        return rc;
    }

    if (!wcscmp(argv[1], L"dump-code")) {
        // Read N bytes at base+RVA and dump as C array for offline disasm
        if (argc < 4) { DH_ERROR("usage: dump-code <rva-hex> <size-hex>"); return DH_ERR_BAD_ARG; }
        u64 rva = _wcstoui64(argv[2], NULL, 16);
        u32 sz  = (u32)wcstoul(argv[3], NULL, 16);
        if (sz > 0x10000) sz = 0x10000;

        DH_DRIVER drv;
        if (!driver_up(&drv)) return DH_ERR_SVC_START;
        u64 sysCR3 = 0, procCR3 = 0, eproc = 0, peb = 0, base = 0, size = 0;
        int rc = DH_OK;
        do {
            if (!RpmFindSystemCR3(drv.hDevice, &sysCR3)) { rc = DH_ERR_RPM_FAIL; break; }
            if (!RpmFindProcess(drv.hDevice, sysCR3, DH_PROC_NAME, &procCR3, &eproc)) { rc = DH_ERR_TARGET_NOT_FOUND; break; }
            RpmRead64(drv.hDevice, sysCR3, eproc + g_eproc_peb_off, &peb);
            if (!RpmGetMainImageBase(drv.hDevice, procCR3, peb, &base, &size)) { base = 0x140000000ULL; size = 0x1F800000; DH_INFO("PEB failed, using hardcoded base 0x140000000"); }

            u8* buf = (u8*)HeapAlloc(GetProcessHeap(), 0, sz);
            if (!buf) { rc = DH_ERR_GENERIC; break; }
            if (!RpmReadVirtual(drv.hDevice, procCR3, base + rva, buf, sz)) {
                DH_ERROR("read failed");
                HeapFree(GetProcessHeap(), 0, buf);
                rc = DH_ERR_RPM_FAIL;
                break;
            }
            printf("# base=0x%llX rva=0x%llX va=0x%llX size=0x%X\n", base, rva, base+rva, sz);
            for (u32 i = 0; i < sz; i++) {
                if (i % 32 == 0) printf("%08X: ", i);
                printf("%02X ", buf[i]);
                if ((i+1) % 32 == 0) printf("\n");
            }
            printf("\n");
            HeapFree(GetProcessHeap(), 0, buf);
        } while (0);
        driver_down(&drv);
        return rc;
    }

    if (!wcscmp(argv[1], L"probe-crypto")) {
        DH_DRIVER drv;
        if (!driver_up(&drv)) return DH_ERR_SVC_START;
        u64 sysCR3 = 0, procCR3 = 0, eproc = 0, peb = 0, base = 0, size = 0;
        int rc = DH_OK;
        do {
            if (!RpmFindSystemCR3(drv.hDevice, &sysCR3)) { rc = DH_ERR_RPM_FAIL; break; }
            if (!RpmFindProcess(drv.hDevice, sysCR3, DH_PROC_NAME, &procCR3, &eproc)) { rc = DH_ERR_TARGET_NOT_FOUND; break; }
            RpmRead64(drv.hDevice, sysCR3, eproc + g_eproc_peb_off, &peb);
            if (!RpmGetMainImageBase(drv.hDevice, procCR3, peb, &base, &size)) { base = 0x140000000ULL; size = 0x1F800000; DH_INFO("PEB failed, using hardcoded base 0x140000000"); }

            // Forum-hinted crypto entries
            const u64 candidates[] = {
                0x1F2F6EF8,  // off_15F2F6EF8 (forum cheetah44)
                0x208B14C0,  // 0x1608B14C0 (forum cheetah44 for steam)
                0x1E654884,  // ObfuscationMode (my probe RVA)
                0x1E65488C,  // AlgorithmSelectors (my probe RVA)
                0x1E68A000,  // near GObjects
                0x1E662000,  // near FNamePool
            };
            const char* names[] = {"off_15F2F6EF8","0x1608B14C0","ObfMode","AlgoSel","near GObjects","near FNamePool"};
            for (int i = 0; i < 6; i++) {
                u8 buf[32] = {0};
                if (RpmReadVirtual(drv.hDevice, procCR3, base + candidates[i], buf, sizeof(buf))) {
                    printf("[%s @ base+0x%llX = 0x%llX]\n  ", names[i], candidates[i], base + candidates[i]);
                    for (int j = 0; j < 32; j++) printf("%02X ", buf[j]);
                    printf("\n");
                }
            }

            // Scan Delta's .text section for the ror-13 opcode (C1 C8-CF 13 or 41 C1 C8-CF 13).
            // Read section in 4MB chunks. Look for ror-13 hits + nearby MOV imm32.
            DH_INFO("scanning Delta code section for 'ror reg, 0x13'...");
            u32 chunk = 0x400000;  // 4MB
            u32 totalHits = 0;
            for (u64 off = 0; off < size && totalHits < 20; off += chunk) {
                u32 rd = (size - off < chunk) ? (u32)(size - off) : chunk;
                u8* buf = (u8*)HeapAlloc(GetProcessHeap(), 0, rd);
                if (!buf) break;
                if (RpmReadVirtual(drv.hDevice, procCR3, base + off, buf, rd)) {
                    for (u32 j = 0; j + 4 < rd && totalHits < 20; j++) {
                        BOOL hit = FALSE;
                        u32 patLen = 0;
                        // C1 C8..CF 13
                        if (buf[j] == 0xC1 && buf[j+1] >= 0xC8 && buf[j+1] <= 0xCF && buf[j+2] == 0x13) {
                            hit = TRUE; patLen = 3;
                        }
                        // 41 C1 C8..CF 13
                        else if (buf[j] == 0x41 && buf[j+1] == 0xC1 && buf[j+2] >= 0xC8 && buf[j+2] <= 0xCF && buf[j+3] == 0x13) {
                            hit = TRUE; patLen = 4;
                        }
                        if (hit) {
                            u64 va = base + off + j;
                            u32 lo = (j >= 16) ? j - 16 : 0;
                            u32 hi = (j + 32 < rd) ? j + 32 : rd;
                            printf("  ror-13 @ VA=0x%llX (RVA 0x%llX):\n    ", va, off + j);
                            for (u32 k = lo; k < hi; k++) {
                                if (k == j) printf("[");
                                printf("%02X", buf[k]);
                                if (k == j + patLen - 1) printf("]");
                                printf(" ");
                            }
                            printf("\n");
                            totalHits++;
                        }
                    }
                }
                HeapFree(GetProcessHeap(), 0, buf);
            }
            DH_INFO("total ror-13 hits: %u", totalHits);
        } while (0);
        driver_down(&drv);
        return rc;
    }

    if (!wcscmp(argv[1], L"find-keys2")) {
        // Alternate scanner for UObject-based key table (768-byte entries)
        // Anchor pattern:
        //   66 c1 e8 0d              shr ax, 0xd
        //   ...                       [some bytes]
        //   48 8D 04 40              lea rax, [rax + rax*2]  (rax *= 3)
        //   48 C1 E0 08              shl rax, 8              (rax *= 256, so *=768)
        //   4C 8D ?? ?? ?? ?? ??     lea r10, [rip+X]        (r10 = LOOKUP_TABLE base)
        //   or   4C 03 D0            add r10, rax            (address = base + offset)
        DH_DRIVER drv;
        if (!driver_up(&drv)) return DH_ERR_SVC_START;
        u64 sysCR3 = 0, procCR3 = 0, eproc = 0, peb = 0, base = 0, size = 0;
        int rc = DH_OK;
        do {
            if (!RpmFindSystemCR3(drv.hDevice, &sysCR3)) { rc = DH_ERR_RPM_FAIL; break; }
            if (!RpmFindProcess(drv.hDevice, sysCR3, DH_PROC_NAME, &procCR3, &eproc)) { rc = DH_ERR_TARGET_NOT_FOUND; break; }
            RpmRead64(drv.hDevice, sysCR3, eproc + g_eproc_peb_off, &peb);
            if (!RpmGetMainImageBase(drv.hDevice, procCR3, peb, &base, &size)) {
                base = 0x140000000ULL; size = 0x1F800000;
            }
            const u32 CHUNK = 8 * 1024 * 1024;
            const u32 OVERLAP = 64;
            u32 scanEnd = 0x14F53000;
            if (scanEnd > (u32)size) scanEnd = (u32)size;
            u8* buf = (u8*)HeapAlloc(GetProcessHeap(), 0, CHUNK + OVERLAP);
            if (!buf) { rc = DH_ERR_GENERIC; break; }

            u64 lookup_vas[64] = {0};
            int lookup_count = 0;

            for (u32 off = 0x1000; off < scanEnd; off += CHUNK) {
                u32 rd = (scanEnd - off < CHUNK) ? (scanEnd - off) : CHUNK;
                if (off + rd + OVERLAP <= scanEnd) rd += OVERLAP;
                if (!RpmReadVirtual(drv.hDevice, procCR3, base + off, buf, rd)) continue;

                for (u32 i = 0; i + 20 < rd; i++) {
                    // 48 8D 04 40  = lea rax, [rax + rax*2]
                    if (buf[i]==0x48 && buf[i+1]==0x8D && buf[i+2]==0x04 && buf[i+3]==0x40) {
                        // Next: 48 C1 E0 08 = shl rax, 8
                        if (buf[i+4]==0x48 && buf[i+5]==0xC1 && buf[i+6]==0xE0 && buf[i+7]==0x08) {
                            // Then look for LEA r10,[rip+X] within 40 bytes BEFORE
                            // Check backward for 4c 8d 15 XX XX XX XX
                            for (int back = 8; back <= 60 && (int)i - back >= 0; back++) {
                                if (buf[i-back]==0x4C && buf[i-back+1]==0x8D && buf[i-back+2]==0x15) {
                                    i32 disp = *(i32*)(buf+i-back+3);
                                    u64 lea_va = base + off + i - back;
                                    u64 target = lea_va + 7 + (i64)disp;
                                    u64 site_va = base + off + i;
                                    printf("[+] cs VA=0x%llX  LEA @ %d back  ->  LOOKUP @ 0x%llX\n",
                                           site_va, back, target);
                                    int dup = 0;
                                    for (int t = 0; t < lookup_count; t++)
                                        if (lookup_vas[t] == target) { dup = 1; break; }
                                    if (!dup && lookup_count < 64) lookup_vas[lookup_count++] = target;
                                    break;
                                }
                            }
                        }
                    }
                }
                printf("  scanned RVA 0x%X (%d unique lookups)\n", off + rd, lookup_count);
            }
            HeapFree(GetProcessHeap(), 0, buf);

            printf("\n=== %d LOOKUP_TABLE VAs found ===\n", lookup_count);
            for (int t = 0; t < lookup_count; t++) {
                printf("\n--- LOOKUP @ 0x%llX ---\n", lookup_vas[t]);
                // Read first 3 entries * 768 bytes each, hexdump partially
                for (int e = 0; e < 3; e++) {
                    u8 entry[128] = {0};
                    if (!RpmReadVirtual(drv.hDevice, procCR3, lookup_vas[t] + e * 768, entry, 128))
                        break;
                    u64 first_qword = *(u64*)entry;
                    printf("  entry[%d] @ +0x%X:  first_QWORD = 0x%llX\n",
                           e, e * 768, first_qword);
                    printf("    hex[0..64]: ");
                    for (int b = 0; b < 64; b++) printf("%02X", entry[b]);
                    printf("\n");
                }
            }
        } while (0);
        driver_down(&drv);
        return rc;
    }

    if (!wcscmp(argv[1], L"find-keys")) {
        // Scan Delta .text via RPM (BYOVD kdu path, NOT DMA) for the decrypt
        // callsite anchor:
        //   66 c1 e8 0d              shr ax, 0xd
        //   48 8d 0d ?? ?? ?? ??     lea rcx, [rip+disp32]
        //   48 8b 0c c1              mov rcx, [rcx+rax*8]
        // Extract disp32 -> KEY_TABLE VA. Read 8x8 QWORDs, deref each for 16B key.
        DH_DRIVER drv;
        if (!driver_up(&drv)) return DH_ERR_SVC_START;
        u64 sysCR3 = 0, procCR3 = 0, eproc = 0, peb = 0, base = 0, size = 0;
        int rc = DH_OK;
        do {
            if (!RpmFindSystemCR3(drv.hDevice, &sysCR3)) { rc = DH_ERR_RPM_FAIL; break; }
            if (!RpmFindProcess(drv.hDevice, sysCR3, DH_PROC_NAME, &procCR3, &eproc)) { rc = DH_ERR_TARGET_NOT_FOUND; break; }
            RpmRead64(drv.hDevice, sysCR3, eproc + g_eproc_peb_off, &peb);
            if (!RpmGetMainImageBase(drv.hDevice, procCR3, peb, &base, &size)) {
                base = 0x140000000ULL; size = 0x1F800000;
                DH_INFO("PEB failed, using hardcoded base");
            }
            DH_INFO("Delta base=0x%llX size=0x%llX", base, size);

            // Scan first EXEC .text section (RVA 0x1000..0x14F53000, ~348 MB)
            // in 8 MB chunks with 12-byte overlap for anchor pattern.
            const u32 CHUNK = 8 * 1024 * 1024;
            const u32 OVERLAP = 32;
            u32 scanStart = 0x1000;
            u32 scanEnd   = 0x14F53000;
            if (scanEnd > (u32)size) scanEnd = (u32)size;

            u8* buf = (u8*)HeapAlloc(GetProcessHeap(), 0, CHUNK + OVERLAP);
            if (!buf) { rc = DH_ERR_GENERIC; break; }

            u64 table_vas[64] = {0};
            int table_count = 0;

            for (u32 off = scanStart; off < scanEnd; off += CHUNK) {
                u32 rd = (scanEnd - off < CHUNK) ? (scanEnd - off) : CHUNK;
                if (off + rd + OVERLAP <= scanEnd) rd += OVERLAP;
                if (!RpmReadVirtual(drv.hDevice, procCR3, base + off, buf, rd)) continue;

                for (u32 i = 0; i + 18 < rd; i++) {
                    // shr ax, 0xd -> 66 C1 E8 0D
                    if (buf[i]==0x66 && buf[i+1]==0xC1 && buf[i+2]==0xE8 && buf[i+3]==0x0D) {
                        // Look for lea rcx, [rip+disp32] within next 8 bytes
                        for (int j = 4; j <= 14 && i + j + 7 <= rd; j++) {
                            if (buf[i+j]==0x48 && buf[i+j+1]==0x8D && buf[i+j+2]==0x0D) {
                                // Check next: mov rcx, [rcx+rax*8] = 48 8B 0C C1 within +3..+16
                                int found_mov = 0;
                                for (int k = 7; k <= 20 && i + j + k + 3 <= rd; k++) {
                                    if (buf[i+j+k]==0x48 && buf[i+j+k+1]==0x8B &&
                                        buf[i+j+k+2]==0x0C && buf[i+j+k+3]==0xC1) {
                                        found_mov = 1; break;
                                    }
                                }
                                if (found_mov) {
                                    i32 disp = *(i32*)(buf+i+j+3);
                                    u64 lea_va = base + off + i + j;
                                    u64 rip_after = lea_va + 7;
                                    u64 target = rip_after + (i64)disp;
                                    printf("[+] callsite VA=0x%llX  LEA at +0x%X  disp=0x%X\n",
                                        base + off + i, j, disp);
                                    printf("    KEY_TABLE VA = 0x%llX\n", target);
                                    // Dedup
                                    int dup = 0;
                                    for (int t = 0; t < table_count; t++)
                                        if (table_vas[t] == target) { dup = 1; break; }
                                    if (!dup && table_count < 64) table_vas[table_count++] = target;
                                }
                                break;
                            }
                        }
                    }
                }
                printf("  scanned RVA 0x%X..0x%X (%d unique tables so far)\n",
                    off, off + rd, table_count);
            }
            HeapFree(GetProcessHeap(), 0, buf);

            printf("\n=== %d unique KEY_TABLE VAs found ===\n", table_count);
            for (int t = 0; t < table_count; t++) {
                printf("\n--- TABLE @ 0x%llX ---\n", table_vas[t]);
                u8 slots[64] = {0};
                if (!RpmReadVirtual(drv.hDevice, procCR3, table_vas[t], slots, 64)) {
                    printf("  can't read table\n"); continue;
                }
                for (int s = 0; s < 8; s++) {
                    u64 ptr = *(u64*)(slots + s*8);
                    printf("  slot[%d] = 0x%016llX", s, ptr);
                    if (ptr) {
                        u8 key[16] = {0};
                        if (RpmReadVirtual(drv.hDevice, procCR3, ptr, key, 16)) {
                            printf("   KEY=");
                            for (int b = 0; b < 16; b++) printf("%02X", key[b]);
                        }
                    }
                    printf("\n");
                }
            }
        } while (0);
        driver_down(&drv);
        return rc;
    }

    if (!wcscmp(argv[1], L"esp")) {
        DH_DRIVER drv;
        if (!driver_up(&drv)) return DH_ERR_SVC_START;
        u64 sysCR3 = 0, procCR3 = 0, eproc = 0, peb = 0, base = 0, size = 0;
        int rc = DH_OK;
        do {
            if (!RpmFindSystemCR3(drv.hDevice, &sysCR3)) { rc = DH_ERR_RPM_FAIL; break; }
            if (!RpmFindProcess(drv.hDevice, sysCR3, DH_PROC_NAME, &procCR3, &eproc)) { rc = DH_ERR_TARGET_NOT_FOUND; break; }
            RpmRead64(drv.hDevice, sysCR3, eproc + g_eproc_peb_off, &peb);
            if (!RpmGetMainImageBase(drv.hDevice, procCR3, peb, &base, &size)) { base = 0x140000000ULL; size = 0x1F800000; DH_INFO("PEB failed, using hardcoded base 0x140000000"); }
            DH_INFO("Delta base=0x%llX size=0x%llX", base, size);

            // Try multiple GWorld RVA candidates
            const u64 candidates[] = {
                DF_RVA_GWORLD,       // 0x1DA98608 (my Dumper-7 09-17)
                0x1D76C668,          // CN leak
                0x1D76F618,          // CN update
            };
            u64 uworld = 0;
            for (int i = 0; i < 3; i++) {
                u64 val = 0;
                if (!RpmRead64(drv.hDevice, procCR3, base + candidates[i], &val)) continue;
                DH_INFO("  GWorld candidate @ base+0x%llX = 0x%llX", candidates[i], val);
                // Valid UWorld: usermode heap, high bit range
                if (val && (val >> 32) >= 0x00 && (val >> 40) > 0x00 && (val >> 48) == 0) {
                    if (!uworld) uworld = val;
                }
            }
            if (!uworld) {
                // fallback: try any nonzero value
                for (int i = 0; i < 3; i++) {
                    u64 val = 0;
                    RpmRead64(drv.hDevice, procCR3, base + candidates[i], &val);
                    if (val) { uworld = val; break; }
                }
            }
            if (!uworld) { DH_WARN("no GWorld found"); break; }
            DH_INFO("UWorld = 0x%llX", uworld);

            // Try to read GameState — first raw, then XOR-decrypted.
            u64 gsRaw = 0;
            RpmRead64(drv.hDevice, procCR3, uworld + DF_WORLD_GAMESTATE, &gsRaw);
            u64 gsMasked = gsRaw & 0x0000FFFFFFFFFFFFULL;
            DH_INFO("UWorld.GameState raw=0x%llX  low48=0x%llX  tag=0x%llX",
                    gsRaw, gsMasked, gsRaw >> 48);

            u64 gameState = gsMasked;

            if (!gameState || gameState < 0x100000) {
                DH_WARN("GameState low48 doesn't look pointer-y");
            } else {
                // GameState.PlayerArray @ 0x388 — TArray<APlayerState*>
                u64 psArrPtr = 0;
                i32 psNum = 0, psMax = 0;
                RpmRead64(drv.hDevice, procCR3, gameState + DF_GAMESTATE_PLAYERARRAY, &psArrPtr);
                RpmReadVirtual(drv.hDevice, procCR3, gameState + DF_GAMESTATE_PLAYERARRAY + 8, &psNum, 4);
                RpmReadVirtual(drv.hDevice, procCR3, gameState + DF_GAMESTATE_PLAYERARRAY + 12, &psMax, 4);
                DH_INFO("GameState=0x%llX  PlayerArray ptr=0x%llX num=%d max=%d",
                        gameState, psArrPtr, psNum, psMax);

                for (i32 pi = 0; pi < psNum && pi < 64; pi++) {
                    u64 ps = 0;
                    RpmRead64(drv.hDevice, procCR3, psArrPtr + (u64)pi * 8, &ps);
                    if (!ps) continue;

                    u64 pawn = 0;
                    RpmRead64(drv.hDevice, procCR3, ps + DF_PLAYERSTATE_PAWNPRIVATE, &pawn);
                    i32 teamID = 0, camp = 0;
                    RpmReadVirtual(drv.hDevice, procCR3, ps + DF_GPPS_TEAMID, &teamID, 4);
                    RpmReadVirtual(drv.hDevice, procCR3, ps + DF_GPPS_CAMP, &camp, 4);

                    // Read player name (FString: {ptr, len, cap})
                    u64 nameData = 0; i32 nameLen = 0;
                    RpmRead64(drv.hDevice, procCR3, ps + DF_PLAYERSTATE_NAMEPRIV, &nameData);
                    RpmReadVirtual(drv.hDevice, procCR3, ps + DF_PLAYERSTATE_NAMEPRIV + 8, &nameLen, 4);
                    wchar_t wname[64] = {0};
                    if (nameData && nameLen > 0 && nameLen < 63) {
                        RpmReadVirtual(drv.hDevice, procCR3, nameData, wname, nameLen * 2);
                    }
                    char aname[128] = {0};
                    WideCharToMultiByte(CP_UTF8, 0, wname, -1, aname, sizeof(aname), NULL, NULL);

                    u64 rootRaw = 0, root = 0;
                    u64 meshRaw = 0, mesh = 0;
                    // Read Mesh (Character.Mesh @ +0x3D0) — that's what game encrypts
                    // Read 16-byte FEncVector at Mesh+0x230 + flag at Mesh+0x240
                    u8 meshTr[16] = {0};
                    u16 meshFlag = 0xDEAD;
                    u8 meshFlagB = 0xFF;
                    u8 A[12]={0}, B[12]={0}, C[12]={0};
                    u8 Ax[12], Bx[12], Cx[12];
                    if (pawn) {
                        RpmRead64(drv.hDevice, procCR3, pawn + DF_ACTOR_ROOTCOMPONENT, &rootRaw);
                        root = rootRaw & 0x0000FFFFFFFFFFFFULL;
                        // Character.Mesh @ +0x3D0
                        RpmRead64(drv.hDevice, procCR3, pawn + 0x3D0, &meshRaw);
                        mesh = meshRaw & 0x0000FFFFFFFFFFFFULL;
                        if (mesh && mesh >= 0x100000) {
                            RpmReadVirtual(drv.hDevice, procCR3, mesh + 0x230, meshTr, 16);
                            RpmReadVirtual(drv.hDevice, procCR3, mesh + 0x240, &meshFlag, 2);
                            RpmReadVirtual(drv.hDevice, procCR3, mesh + 0x243, &meshFlagB, 1);
                        }
                        if (root && root >= 0x100000) {
                            RpmReadVirtual(drv.hDevice, procCR3, root + 0x220, A, 12);
                            RpmReadVirtual(drv.hDevice, procCR3, root + 0x168, B, 12);
                        }
                        RpmReadVirtual(drv.hDevice, procCR3, pawn + 0xB4, C, 12);
                    }
                    memcpy(Ax, A, 12); memcpy(Bx, B, 12); memcpy(Cx, C, 12);
                    for (int b = 0; b < 12; b++) { Ax[b]^=0x0E; Bx[b]^=0x0E; Cx[b]^=0x0E; }

                    // Diagnose Root component class + extra bytes at end of class-specific size
                    char rootClsName[64] = {0}, rootSuperName[64] = {0};
                    u64 rootCls = 0, rootSuper = 0;
                    if (root && root >= 0x100000) {
                        RpmRead64(drv.hDevice, procCR3, root + DF_UOBJ_CLASS, &rootCls);
                        if (rootCls) {
                            RpmGetObjectName(drv.hDevice, procCR3, base + DF_RVA_FNAMEPOOL,
                                             rootCls, rootClsName, sizeof(rootClsName));
                            RpmRead64(drv.hDevice, procCR3, rootCls + DF_USTRUCT_SUPER, &rootSuper);
                            if (rootSuper)
                                RpmGetObjectName(drv.hDevice, procCR3, base + DF_RVA_FNAMEPOOL,
                                                 rootSuper, rootSuperName, sizeof(rootSuperName));
                            for (char* p = rootClsName; *p; p++) if ((u8)*p<0x20||(u8)*p>=0x7F){*p=0;break;}
                            for (char* p = rootSuperName; *p; p++) if ((u8)*p<0x20||(u8)*p>=0x7F){*p=0;break;}
                        }
                    }
                    // Read 16 bytes at UGPEncryptionCapsuleComponent extra (0x5E0)
                    u8 keyBytes[16] = {0};
                    if (root && root >= 0x100000) {
                        RpmReadVirtual(drv.hDevice, procCR3, root + 0x5E0, keyBytes, 16);
                    }

                    // Read whole 0x400 bytes of Root, apply XOR 0x0E, find valid FVector windows
                    printf("  [PS%2d] T%d C%3d '%s' Pawn=0x%llX Root=0x%llX\n",
                           pi, teamID, camp, aname, pawn, root);
                    if (root && root >= 0x100000) {
                        u8 wholebuf[0x400] = {0};
                        u8 xorbuf[0x400] = {0};
                        if (RpmReadVirtual(drv.hDevice, procCR3, root, wholebuf, sizeof(wholebuf))) {
                            memcpy(xorbuf, wholebuf, sizeof(wholebuf));
                            for (int b = 0; b < (int)sizeof(xorbuf); b++) xorbuf[b] ^= 0x0E;
                            // Scan windows of 12 bytes = 3 floats (X, Y, Z)
                            int found = 0;
                            for (u32 off = 0; off + 12 <= sizeof(xorbuf); off += 4) {
                                float x = *(float*)(xorbuf + off + 0);
                                float y = *(float*)(xorbuf + off + 4);
                                float z = *(float*)(xorbuf + off + 8);
                                // Valid coord filter: -100k..100k, not exactly 0, not NaN
                                int vX = (x > -100000.f && x < 100000.f && x != 0.f && (x==x));
                                int vY = (y > -100000.f && y < 100000.f && y != 0.f && (y==y));
                                int vZ = (z > -100000.f && z < 100000.f && (z==z));
                                if (vX && vY && vZ && found < 15) {
                                    printf("    XOR 0x0E hit Root+0x%03X: (%.1f, %.1f, %.1f)\n",
                                           off, x, y, z);
                                    found++;
                                }
                            }
                            if (!found) printf("    XOR 0x0E: no valid coord window in Root[0..0x400]\n");
                        }
                    }
                    // NEW: dump full FTransform (48B) + scan for encrypted Translation
                    if (mesh && mesh >= 0x100000) {
                        u8 ftrans[64] = {0};
                        RpmReadVirtual(drv.hDevice, procCR3, mesh + 0x210, ftrans, 64);
                        printf("    Mesh=0x%llX FTransform @ Mesh+0x210:\n", mesh);
                        for (int i = 0; i < 64; i += 16) {
                            printf("      +0x%02X:", i);
                            for (int b = 0; b < 16; b++) printf(" %02X", ftrans[i+b]);
                            // Print as 4 floats
                            printf("   [");
                            for (int f = 0; f < 4; f++) {
                                float v = *(float*)(ftrans+i+f*4);
                                if (fabsf(v) > 1e-6 && fabsf(v) < 1e9 && v==v)
                                    printf(" %8.1f", v);
                                else
                                    printf(" %8s", "-");
                            }
                            printf(" ]\n");
                        }
                        float x0 = *(float*)(meshTr+0), y0 = *(float*)(meshTr+4), z0 = *(float*)(meshTr+8);
                        printf("      RAW at +0x230 X=%12.2f Y=%12.2f Z=%12.2f\n", x0, y0, z0);
                        // Try single-byte XOR candidates
                        u8 keys[] = { 0x0E, 0x25, 0xFF, 0x0C, 0x3F, 0x42, 0x55, 0xAA };
                        for (int k = 0; k < (int)sizeof(keys); k++) {
                            u8 buf[12];
                            for (int b = 0; b < 12; b++) buf[b] = meshTr[b] ^ keys[k];
                            float x = *(float*)(buf+0), y = *(float*)(buf+4), z = *(float*)(buf+8);
                            int ok = (fabsf(x) < 200000 && fabsf(y) < 200000 && fabsf(z) < 200000
                                      && x==x && y==y && z==z
                                      && !(x==0 && y==0 && z==0));
                            printf("      XOR 0x%02X %s  X=%12.2f Y=%12.2f Z=%12.2f\n",
                                   keys[k], ok?"[HIT]":"     ", x, y, z);
                        }
                        // XOR with position-dependent (byte[i] ^= (i * 0x?))
                        u8 buf2[12];
                        for (int b = 0; b < 12; b++) buf2[b] = meshTr[b] ^ (u8)(b * 0x13);
                        float x2 = *(float*)(buf2+0), y2 = *(float*)(buf2+4), z2 = *(float*)(buf2+8);
                        printf("      posXOR*13     X=%12.2f Y=%12.2f Z=%12.2f\n", x2, y2, z2);
                        // Flag-derived key: key = (flag>>13) — if sentinel, no decrypt
                        if (meshFlag == 0xFFFF) {
                            printf("      SENTINEL 0xFFFF → PLAINTEXT accepted\n");
                        }
                    }
                    printf("    A raw=(%.1f, %.1f, %.1f)  xor0E=(%.1f, %.1f, %.1f)\n",
                        *(float*)(A+0),*(float*)(A+4),*(float*)(A+8),
                        *(float*)(Ax+0),*(float*)(Ax+4),*(float*)(Ax+8));
                    printf("    B raw=(%.1f, %.1f, %.1f)  xor0E=(%.1f, %.1f, %.1f)\n",
                        *(float*)(B+0),*(float*)(B+4),*(float*)(B+8),
                        *(float*)(Bx+0),*(float*)(Bx+4),*(float*)(Bx+8));
                    printf("    C raw=(%.1f, %.1f, %.1f)  xor0E=(%.1f, %.1f, %.1f)\n",
                        *(float*)(C+0),*(float*)(C+4),*(float*)(C+8),
                        *(float*)(Cx+0),*(float*)(Cx+4),*(float*)(Cx+8));
                }
            }
        } while (0);
        driver_down(&drv);
        return rc;
    }

    if (!wcscmp(argv[1], L"esp-dec")) {
        // ESP with integrated FEncVector decryption via AceDecrypt.
        // Walks GameState.PlayerArray → APlayerState → APawn → RootComponent,
        // reads USceneComponent.RelativeLocation @ +0x168 (encrypted FEncVector),
        // decrypts through local RWX copy of Delta's decrypt_fn, prints coords.
        DH_DRIVER drv;
        if (!driver_up(&drv)) return DH_ERR_SVC_START;
        u64 sysCR3 = 0, procCR3 = 0, eproc = 0, peb = 0, base = 0, size = 0;
        int rc = DH_OK;
        DH_ACE_DECRYPT dec = {0};
        BOOL decInited = FALSE;
        do {
            if (!RpmFindSystemCR3(drv.hDevice, &sysCR3)) { rc = DH_ERR_RPM_FAIL; break; }
            if (!RpmFindProcess(drv.hDevice, sysCR3, DH_PROC_NAME, &procCR3, &eproc)) { rc = DH_ERR_TARGET_NOT_FOUND; break; }
            RpmRead64(drv.hDevice, sysCR3, eproc + g_eproc_peb_off, &peb);
            if (!RpmGetMainImageBase(drv.hDevice, procCR3, peb, &base, &size)) { base = 0x140000000ULL; size = 0x1F800000; DH_INFO("PEB failed, using hardcoded base"); }
            DH_INFO("Delta base=0x%llX size=0x%llX", base, size);

            if (!AceDecryptInit(&dec, drv.hDevice, procCR3, base, size)) {
                DH_ERROR("AceDecryptInit failed — cannot proceed with encrypted actors");
                rc = DH_ERR_RPM_FAIL;
                break;
            }
            decInited = TRUE;

            u64 uworld = 0;
            RpmRead64(drv.hDevice, procCR3, base + DF_RVA_GWORLD, &uworld);
            if (!uworld) { DH_WARN("GWorld = 0"); break; }
            DH_INFO("UWorld = 0x%llX", uworld);

            u64 gsRaw = 0;
            RpmRead64(drv.hDevice, procCR3, uworld + DF_WORLD_GAMESTATE, &gsRaw);
            u64 gameState = gsRaw & 0x0000FFFFFFFFFFFFULL;
            if (!gameState || gameState < 0x100000) { DH_WARN("no GameState"); break; }

            u64 psArr = 0;
            i32 psNum = 0;
            RpmRead64(drv.hDevice, procCR3, gameState + DF_GAMESTATE_PLAYERARRAY, &psArr);
            RpmReadVirtual(drv.hDevice, procCR3, gameState + DF_GAMESTATE_PLAYERARRAY + 8, &psNum, 4);
            DH_INFO("PlayerArray ptr=0x%llX num=%d", psArr, psNum);

            int enc_ok = 0, enc_fail = 0, plain_ok = 0;
            for (i32 pi = 0; pi < psNum && pi < 64; pi++) {
                u64 ps = 0;
                RpmRead64(drv.hDevice, procCR3, psArr + (u64)pi * 8, &ps);
                if (!ps) continue;

                u64 pawn = 0;
                RpmRead64(drv.hDevice, procCR3, ps + DF_PLAYERSTATE_PAWNPRIVATE, &pawn);
                i32 teamID = 0;
                RpmReadVirtual(drv.hDevice, procCR3, ps + DF_GPPS_TEAMID, &teamID, 4);

                u64 nameData = 0; i32 nameLen = 0;
                RpmRead64(drv.hDevice, procCR3, ps + DF_PLAYERSTATE_NAMEPRIV, &nameData);
                RpmReadVirtual(drv.hDevice, procCR3, ps + DF_PLAYERSTATE_NAMEPRIV + 8, &nameLen, 4);
                wchar_t wname[64] = {0};
                if (nameData && nameLen > 0 && nameLen < 63)
                    RpmReadVirtual(drv.hDevice, procCR3, nameData, wname, nameLen * 2);
                char aname[128] = {0};
                WideCharToMultiByte(CP_UTF8, 0, wname, -1, aname, sizeof(aname), NULL, NULL);

                if (!pawn) { printf("  [%2d] T%d '%s' (no pawn)\n", pi, teamID, aname); continue; }

                u64 rootRaw = 0;
                RpmRead64(drv.hDevice, procCR3, pawn + DF_ACTOR_ROOTCOMPONENT, &rootRaw);
                u64 root = rootRaw & 0x0000FFFFFFFFFFFFULL;
                if (!root || root < 0x100000) {
                    printf("  [%2d] T%d '%s' (no root)\n", pi, teamID, aname);
                    continue;
                }

                // USceneComponent.RelativeLocation @ +0x168 = FEncVector (16 bytes)
                DH_ENC_VECTOR enc = {0};
                if (!RpmReadVirtual(drv.hDevice, procCR3, root + 0x168, &enc, sizeof(enc))) {
                    printf("  [%2d] T%d '%s' RelLoc read fail\n", pi, teamID, aname);
                    continue;
                }

                DH_FVECTOR world = {0};
                BOOL ok = AceDecryptVector(&dec, &enc, &world);
                const char* status;
                if (enc.EncHandler.Index == 0xFFFF) { status = "PLAIN"; plain_ok++; }
                else if (ok)                        { status = "DEC  "; enc_ok++; }
                else                                { status = "FAIL "; enc_fail++; }

                printf("  [%2d] T%d %s '%s' idx=0x%04X (%.1f, %.1f, %.1f)\n",
                       pi, teamID, status, aname, enc.EncHandler.Index,
                       world.X, world.Y, world.Z);
            }
            printf("\nsummary: plain=%d dec=%d fail=%d\n", plain_ok, enc_ok, enc_fail);
            AceDecryptStats(&dec);
        } while (0);
        if (decInited) AceDecryptFree(&dec);
        driver_down(&drv);
        return rc;
    }

    if (!wcscmp(argv[1], L"find-players")) {
        DH_DRIVER drv;
        if (!driver_up(&drv)) return DH_ERR_SVC_START;
        u64 sysCR3 = 0, procCR3 = 0, eproc = 0, peb = 0, base = 0, size = 0;
        int rc = DH_OK;
        do {
            if (!RpmFindSystemCR3(drv.hDevice, &sysCR3)) { rc = DH_ERR_RPM_FAIL; break; }
            if (!RpmFindProcess(drv.hDevice, sysCR3, DH_PROC_NAME, &procCR3, &eproc)) { rc = DH_ERR_TARGET_NOT_FOUND; break; }
            RpmRead64(drv.hDevice, sysCR3, eproc + g_eproc_peb_off, &peb);
            if (!RpmGetMainImageBase(drv.hDevice, procCR3, peb, &base, &size)) { base = 0x140000000ULL; size = 0x1F800000; DH_INFO("PEB failed, using hardcoded base 0x140000000"); }

            u64 gObjects = base + DELTA_RVA_GOBJECTS;
            u64 gNames   = base + 0x1E661B40;
            u32 numElements = 0;
            RpmReadVirtual(drv.hDevice, procCR3, gObjects + 0x04, &numElements, 4);
            DH_INFO("walking %u UObjects (Super-chain classify)...", numElements);

            typedef struct { u64 cls; int kind; } ClsEntry;
            ClsEntry cache[2048] = {0};
            int cacheN = 0;

            u32 stats[8] = {0};   // 0=other, 1=Pawn, 2=Char, 3=PC, 4=Ctrl, 5=PS, 6=GS, 7=GM
            for (u32 i = 0; i < numElements; i++) {
                u64 obj = 0;
                if (!RpmGetUObjectByIndex(drv.hDevice, procCR3, gObjects, (i32)i, &obj) || !obj)
                    continue;

                u64 clsPtr = 0;
                if (!RpmRead64(drv.hDevice, procCR3, obj + UOBJ_CLASS, &clsPtr) || !clsPtr) continue;

                int kind = -1;
                for (int c = 0; c < cacheN; c++)
                    if (cache[c].cls == clsPtr) { kind = cache[c].kind; break; }

                if (kind < 0) {
                    kind = 0;
                    u64 walkCls = clsPtr;
                    for (int depth = 0; depth < 16 && walkCls; depth++) {
                        char cnm[64] = {0};
                        RpmGetObjectName(drv.hDevice, procCR3, gNames, walkCls, cnm, sizeof(cnm));
                        for (char* p = cnm; *p; p++)
                            if ((u8)*p < 0x20 || (u8)*p >= 0x7F) { *p = 0; break; }
                        if      (strcmp(cnm, "Pawn") == 0)             { kind = 1; break; }
                        else if (strcmp(cnm, "Character") == 0)        { kind = 2; break; }
                        else if (strcmp(cnm, "PlayerController") == 0) { kind = 3; break; }
                        else if (strcmp(cnm, "Controller") == 0)       { kind = 4; break; }
                        else if (strcmp(cnm, "PlayerState") == 0)      { kind = 5; break; }
                        else if (strcmp(cnm, "GameStateBase") == 0)    { kind = 6; break; }
                        else if (strcmp(cnm, "GameModeBase") == 0)     { kind = 7; break; }
                        u64 super = 0;
                        RpmRead64(drv.hDevice, procCR3, walkCls + 0x48, &super);
                        if (!super || super == walkCls) break;
                        walkCls = super;
                    }
                    if (cacheN < 2048) { cache[cacheN].cls = clsPtr; cache[cacheN].kind = kind; cacheN++; }
                }

                if (kind == 0) continue;
                stats[kind]++;

                // Skip CDOs (class default objects) — they have "Default__" prefix in name.
                // We only want live instances.
                char nm[64] = {0}, cls[64] = {0};
                RpmGetObjectName(drv.hDevice, procCR3, gNames, obj, nm, sizeof(nm));
                RpmGetObjectName(drv.hDevice, procCR3, gNames, clsPtr, cls, sizeof(cls));
                for (char* p = nm; *p; p++) if ((u8)*p < 0x20 || (u8)*p >= 0x7F) { *p = 0; break; }
                for (char* p = cls; *p; p++) if ((u8)*p < 0x20 || (u8)*p >= 0x7F) { *p = 0; break; }
                if (strncmp(nm, "Default__", 9) == 0) continue;

                const char* kindStr =
                    kind == 1 ? "PAWN" :
                    kind == 2 ? "CHAR" :
                    kind == 3 ? "PC  " :
                    kind == 4 ? "CTRL" :
                    kind == 5 ? "PS  " :
                    kind == 6 ? "GS  " :
                    kind == 7 ? "GM  " : "??  ";
                printf("  [%6u] %s @0x%llX cls='%s' name='%s'\n", i, kindStr, obj, cls, nm);
            }
            DH_INFO("done: Pawn=%u Char=%u PC=%u Ctrl=%u PS=%u GS=%u GM=%u | %d unique classes",
                    stats[1], stats[2], stats[3], stats[4], stats[5], stats[6], stats[7], cacheN);
        } while (0);
        driver_down(&drv);
        return rc;
    }

    if (!wcscmp(argv[1], L"dump-actors")) {
        DH_DRIVER drv;
        if (!driver_up(&drv)) return DH_ERR_SVC_START;
        u64 sysCR3 = 0, procCR3 = 0, eproc = 0, peb = 0, base = 0, size = 0;
        int rc = DH_OK;
        do {
            if (!RpmFindSystemCR3(drv.hDevice, &sysCR3)) { rc = DH_ERR_RPM_FAIL; break; }
            if (!RpmFindProcess(drv.hDevice, sysCR3, DH_PROC_NAME, &procCR3, &eproc)) { rc = DH_ERR_TARGET_NOT_FOUND; break; }
            RpmRead64(drv.hDevice, sysCR3, eproc + g_eproc_peb_off, &peb);
            if (!RpmGetMainImageBase(drv.hDevice, procCR3, peb, &base, &size)) { base = 0x140000000ULL; size = 0x1F800000; DH_INFO("PEB failed, using hardcoded base 0x140000000"); }

            u64 gWorldVA = base + 0x1DA98608;
            u64 uworld = 0;
            RpmRead64(drv.hDevice, procCR3, gWorldVA, &uworld);
            if (!uworld) { DH_WARN("no world loaded"); break; }
            u64 gNames = base + 0x1E661B40;

            u64 lvlArrPtr = 0;
            i32 lvlNum = 0;
            RpmRead64(drv.hDevice, procCR3, uworld + 0x158, &lvlArrPtr);
            RpmReadVirtual(drv.hDevice, procCR3, uworld + 0x160, &lvlNum, 4);

            // Class cache: {classPtr, kind} where kind 0=other, 1=Pawn, 2=Character,
            // 3=PlayerController, 4=Controller, 5=PlayerState, 6=GameState, 7=GameMode
            typedef struct { u64 cls; int kind; } ClsEntry;
            ClsEntry cache[512] = {0};
            int cacheN = 0;

            u32 totalActors = 0;
            u32 totalMatches = 0;
            for (i32 li = 0; li < lvlNum; li++) {
                u64 lvl = 0;
                RpmRead64(drv.hDevice, procCR3, lvlArrPtr + (u64)li * 8, &lvl);
                if (!lvl) continue;
                u64 actorsPtr = 0;
                i32 actorsNum = 0;
                RpmRead64(drv.hDevice, procCR3, lvl + 0x98, &actorsPtr);
                RpmReadVirtual(drv.hDevice, procCR3, lvl + 0xA0, &actorsNum, 4);

                for (i32 ai = 0; ai < actorsNum; ai++) {
                    u64 actor = 0;
                    RpmRead64(drv.hDevice, procCR3, actorsPtr + (u64)ai * 8, &actor);
                    if (!actor) continue;
                    totalActors++;

                    u64 clsPtr = 0;
                    RpmRead64(drv.hDevice, procCR3, actor + UOBJ_CLASS, &clsPtr);
                    if (!clsPtr) continue;

                    // Cache lookup
                    int kind = -1;
                    for (int c = 0; c < cacheN; c++)
                        if (cache[c].cls == clsPtr) { kind = cache[c].kind; break; }

                    if (kind < 0) {
                        // Walk Class → UStruct.Super chain (0x48), resolve name at each level.
                        kind = 0;
                        u64 walkCls = clsPtr;
                        int printChain = (cacheN < 10);
                        if (printChain) printf("  [chain] cls=0x%llX:", clsPtr);
                        for (int depth = 0; depth < 16 && walkCls; depth++) {
                            char cnm[64] = {0};
                            RpmGetObjectName(drv.hDevice, procCR3, gNames, walkCls, cnm, sizeof(cnm));
                            for (char* p = cnm; *p; p++)
                                if ((u8)*p < 0x20 || (u8)*p >= 0x7F) { *p = 0; break; }
                            if (printChain) printf(" -> '%s'", cnm);
                            if      (strcmp(cnm, "Pawn") == 0)             { kind = 1; break; }
                            else if (strcmp(cnm, "Character") == 0)        { kind = 2; break; }
                            else if (strcmp(cnm, "PlayerController") == 0) { kind = 3; break; }
                            else if (strcmp(cnm, "Controller") == 0)       { kind = 4; break; }
                            else if (strcmp(cnm, "PlayerState") == 0)      { kind = 5; break; }
                            else if (strcmp(cnm, "GameStateBase") == 0)    { kind = 6; break; }
                            else if (strcmp(cnm, "GameModeBase") == 0)     { kind = 7; break; }
                            u64 super = 0;
                            RpmRead64(drv.hDevice, procCR3, walkCls + 0x48, &super);
                            if (!super || super == walkCls) break;
                            walkCls = super;
                        }
                        if (printChain) printf(" [kind=%d]\n", kind);
                        if (cacheN < 512) { cache[cacheN].cls = clsPtr; cache[cacheN].kind = kind; cacheN++; }
                    }

                    if (kind == 0) continue;
                    totalMatches++;

                    char cls[64] = {0}, nm[64] = {0};
                    RpmGetObjectName(drv.hDevice, procCR3, gNames, clsPtr, cls, sizeof(cls));
                    RpmGetObjectName(drv.hDevice, procCR3, gNames, actor, nm, sizeof(nm));
                    for (char* p = cls; *p; p++) if ((u8)*p < 0x20 || (u8)*p >= 0x7F) { *p = 0; break; }
                    for (char* p = nm; *p; p++)  if ((u8)*p < 0x20 || (u8)*p >= 0x7F) { *p = 0; break; }
                    const char* kindStr =
                        kind == 1 ? "PAWN" :
                        kind == 2 ? "CHAR" :
                        kind == 3 ? "PC  " :
                        kind == 4 ? "CTRL" :
                        kind == 5 ? "PS  " :
                        kind == 6 ? "GS  " :
                        kind == 7 ? "GM  " : "??  ";
                    printf("  L%2d/A%3d %s @0x%llX cls='%s' name='%s'\n",
                           li, ai, kindStr, actor, cls, nm);
                }
            }
            DH_INFO("scanned %u actors, %u gameplay matches, %d unique classes cached",
                    totalActors, totalMatches, cacheN);
        } while (0);
        driver_down(&drv);
        return rc;
    }

    if (!wcscmp(argv[1], L"gworld")) {
        DH_DRIVER drv;
        if (!driver_up(&drv)) return DH_ERR_SVC_START;
        u64 sysCR3 = 0, procCR3 = 0, eproc = 0, peb = 0, base = 0, size = 0;
        int rc = DH_OK;
        do {
            if (!RpmFindSystemCR3(drv.hDevice, &sysCR3)) { rc = DH_ERR_RPM_FAIL; break; }
            if (!RpmFindProcess(drv.hDevice, sysCR3, DH_PROC_NAME, &procCR3, &eproc)) { rc = DH_ERR_TARGET_NOT_FOUND; break; }
            RpmRead64(drv.hDevice, sysCR3, eproc + g_eproc_peb_off, &peb);
            if (!RpmGetMainImageBase(drv.hDevice, procCR3, peb, &base, &size)) { base = 0x140000000ULL; size = 0x1F800000; DH_INFO("PEB failed, using hardcoded base 0x140000000"); }

            u64 gWorldVA = base + 0x1DA98608;
            u64 uworld = 0;
            RpmRead64(drv.hDevice, procCR3, gWorldVA, &uworld);
            DH_INFO("GWorld @ 0x%llX  -> UWorld=0x%llX", gWorldVA, uworld);

            if (!uworld) { DH_WARN("GWorld null — no world loaded (menu?)"); break; }

            u64 gNames = base + 0x1E661B40;
            char cls[64] = {0}, name[128] = {0};
            RpmGetObjectClassName(drv.hDevice, procCR3, gNames, uworld, cls, sizeof(cls));
            RpmGetObjectName(drv.hDevice, procCR3, gNames, uworld, name, sizeof(name));
            DH_INFO("UWorld class='%s' name='%s'", cls, name);

            // Dump UWorld header bytes
            u8 wbuf[0x200] = {0};
            if (RpmReadVirtual(drv.hDevice, procCR3, uworld, wbuf, sizeof(wbuf))) {
                for (int off = 0; off < 0x200; off += 0x10) {
                    printf("  UWorld+0x%03X: ", off);
                    for (int j = 0; j < 16; j++) printf("%02X ", wbuf[off+j]);
                    printf("\n");
                }
            }

            // Read UWorld.Levels @ +0x158 (RAW TArray)
            u64 lvlArrPtr = 0;
            i32 lvlNum = 0, lvlMax = 0;
            RpmRead64(drv.hDevice, procCR3, uworld + 0x158, &lvlArrPtr);
            RpmReadVirtual(drv.hDevice, procCR3, uworld + 0x160, &lvlNum, 4);
            RpmReadVirtual(drv.hDevice, procCR3, uworld + 0x164, &lvlMax, 4);
            printf("[UWorld.Levels @+0x158] ptr=0x%llX num=%d max=%d\n",
                   lvlArrPtr, lvlNum, lvlMax);

            for (i32 li = 0; li < lvlNum && li < 8; li++) {
                u64 lvl = 0;
                RpmRead64(drv.hDevice, procCR3, lvlArrPtr + (u64)li * 8, &lvl);
                if (!lvl) continue;
                char lnm[128] = {0}, lcs[64] = {0};
                RpmGetObjectName(drv.hDevice, procCR3, gNames, lvl, lnm, sizeof(lnm));
                RpmGetObjectClassName(drv.hDevice, procCR3, gNames, lvl, lcs, sizeof(lcs));
                u64 actorsPtr = 0;
                i32 actorsNum = 0, actorsMax = 0;
                RpmRead64(drv.hDevice, procCR3, lvl + 0x98, &actorsPtr);
                RpmReadVirtual(drv.hDevice, procCR3, lvl + 0xA0, &actorsNum, 4);
                RpmReadVirtual(drv.hDevice, procCR3, lvl + 0xA4, &actorsMax, 4);
                printf("  Levels[%d]=0x%llX  cls='%s' name='%s'  Actors={ptr=0x%llX num=%d max=%d}\n",
                       li, lvl, lcs, lnm, actorsPtr, actorsNum, actorsMax);

                // If we got actors, dump first 5
                for (i32 ai = 0; ai < actorsNum && ai < 5; ai++) {
                    u64 actor = 0;
                    RpmRead64(drv.hDevice, procCR3, actorsPtr + (u64)ai * 8, &actor);
                    if (!actor) continue;
                    char acls[64] = {0}, anm[64] = {0};
                    RpmGetObjectClassName(drv.hDevice, procCR3, gNames, actor, acls, sizeof(acls));
                    RpmGetObjectName(drv.hDevice, procCR3, gNames, actor, anm, sizeof(anm));
                    printf("    Actor[%d]=0x%llX  cls='%s' name='%s'\n", ai, actor, acls, anm);
                }
            }
        } while (0);
        driver_down(&drv);
        return rc;
    }

    if (!wcscmp(argv[1], L"find-class")) {
        if (argc < 3) { DH_ERROR("usage: find-class <substring>"); return DH_ERR_BAD_ARG; }
        char match[64] = {0};
        WideCharToMultiByte(CP_ACP, 0, argv[2], -1, match, 63, NULL, NULL);

        DH_DRIVER drv;
        if (!driver_up(&drv)) return DH_ERR_SVC_START;
        u64 sysCR3 = 0, procCR3 = 0, eproc = 0, peb = 0, base = 0, size = 0;
        int rc = DH_OK;
        do {
            if (!RpmFindSystemCR3(drv.hDevice, &sysCR3)) { rc = DH_ERR_RPM_FAIL; break; }
            if (!RpmFindProcess(drv.hDevice, sysCR3, DH_PROC_NAME, &procCR3, &eproc)) { rc = DH_ERR_TARGET_NOT_FOUND; break; }
            RpmRead64(drv.hDevice, sysCR3, eproc + g_eproc_peb_off, &peb);
            if (!RpmGetMainImageBase(drv.hDevice, procCR3, peb, &base, &size)) { base = 0x140000000ULL; size = 0x1F800000; DH_INFO("PEB failed, using hardcoded base 0x140000000"); }

            u64 gObjects = base + DELTA_RVA_GOBJECTS;
            u64 gNames   = base + 0x1E661B40;
            u32 numElements = 0;
            RpmReadVirtual(drv.hDevice, procCR3, gObjects + 0x04, &numElements, 4);
            DH_INFO("scanning %u UObjects for name substring '%s'...", numElements, match);

            u32 found = 0;
            for (u32 i = 0; i < numElements && found < 40; i++) {
                u64 obj = 0;
                if (!RpmGetUObjectByIndex(drv.hDevice, procCR3, gObjects, (i32)i, &obj) || !obj)
                    continue;
                char name[128] = {0}, cls[64] = {0};
                if (!RpmGetObjectName(drv.hDevice, procCR3, gNames, obj, name, sizeof(name)))
                    continue;
                // strstr case-insensitive
                char nameLo[128];
                strncpy_s(nameLo, sizeof(nameLo), name, 127);
                for (char* p = nameLo; *p; p++) if (*p >= 'A' && *p <= 'Z') *p += 32;
                char matchLo[64];
                strncpy_s(matchLo, sizeof(matchLo), match, 63);
                for (char* p = matchLo; *p; p++) if (*p >= 'A' && *p <= 'Z') *p += 32;
                if (strstr(nameLo, matchLo)) {
                    RpmGetObjectClassName(drv.hDevice, procCR3, gNames, obj, cls, sizeof(cls));
                    printf("  [%6u] 0x%llX  cls=%-18s  name=%s\n", i, obj, cls, name);
                    found++;
                }
            }
            DH_INFO("found %u matches", found);
        } while (0);
        driver_down(&drv);
        return rc;
    }

    if (!wcscmp(argv[1], L"find-world")) {
        DH_DRIVER drv;
        if (!driver_up(&drv)) return DH_ERR_SVC_START;
        u64 sysCR3 = 0, procCR3 = 0, eproc = 0, peb = 0, base = 0, size = 0;
        int rc = DH_OK;
        do {
            if (!RpmFindSystemCR3(drv.hDevice, &sysCR3)) { rc = DH_ERR_RPM_FAIL; break; }
            if (!RpmFindProcess(drv.hDevice, sysCR3, DH_PROC_NAME, &procCR3, &eproc)) { rc = DH_ERR_TARGET_NOT_FOUND; break; }
            RpmRead64(drv.hDevice, sysCR3, eproc + g_eproc_peb_off, &peb);
            if (!RpmGetMainImageBase(drv.hDevice, procCR3, peb, &base, &size)) { base = 0x140000000ULL; size = 0x1F800000; DH_INFO("PEB failed, using hardcoded base 0x140000000"); }

            u64 gObjects = base + DELTA_RVA_GOBJECTS;
            u64 gNames   = base + 0x1E661B40;

            u32 numElements = 0;
            RpmReadVirtual(drv.hDevice, procCR3, gObjects + 0x04, &numElements, 4);
            DH_INFO("scanning %u UObjects for class 'World'...", numElements);

            u32 found = 0;
            for (u32 i = 0; i < numElements && found < 5; i++) {
                u64 obj = 0;
                if (!RpmGetUObjectByIndex(drv.hDevice, procCR3, gObjects, (i32)i, &obj) || !obj)
                    continue;
                char cls[64] = {0};
                RpmGetObjectClassName(drv.hDevice, procCR3, gNames, obj, cls, sizeof(cls));
                if (strcmp(cls, "World") == 0) {
                    char name[128] = {0};
                    RpmGetObjectName(drv.hDevice, procCR3, gNames, obj, name, sizeof(name));
                    DH_INFO("FOUND UWorld @ 0x%llX  Name=%s  Idx=%u", obj, name, i);

                    // Read UWorld.Levels @ +0x158 (RAW TArray)
                    u64 lvlArrPtr = 0;
                    i32 lvlNum = 0, lvlMax = 0;
                    RpmRead64(drv.hDevice, procCR3, obj + 0x158, &lvlArrPtr);
                    RpmReadVirtual(drv.hDevice, procCR3, obj + 0x160, &lvlNum, 4);
                    RpmReadVirtual(drv.hDevice, procCR3, obj + 0x164, &lvlMax, 4);
                    printf("  UWorld.Levels TArray: ptr=0x%llX num=%d max=%d\n",
                           lvlArrPtr, lvlNum, lvlMax);

                    if (lvlArrPtr && lvlNum > 0) {
                        for (i32 li = 0; li < lvlNum && li < 8; li++) {
                            u64 lvl = 0;
                            RpmRead64(drv.hDevice, procCR3, lvlArrPtr + (u64)li * 8, &lvl);
                            if (!lvl) continue;
                            char lvlName[128] = {0}, lvlCls[64] = {0};
                            RpmGetObjectName(drv.hDevice, procCR3, gNames, lvl, lvlName, sizeof(lvlName));
                            RpmGetObjectClassName(drv.hDevice, procCR3, gNames, lvl, lvlCls, sizeof(lvlCls));
                            u64 actorsPtr = 0;
                            i32 actorsNum = 0, actorsMax = 0;
                            RpmRead64(drv.hDevice, procCR3, lvl + 0x98, &actorsPtr);
                            RpmReadVirtual(drv.hDevice, procCR3, lvl + 0xA0, &actorsNum, 4);
                            RpmReadVirtual(drv.hDevice, procCR3, lvl + 0xA4, &actorsMax, 4);
                            printf("  Levels[%d]=0x%llX (%s) '%s' Actors={ptr=0x%llX num=%d max=%d}\n",
                                   li, lvl, lvlCls, lvlName, actorsPtr, actorsNum, actorsMax);
                        }
                    }
                    found++;
                }
            }
            if (!found) DH_WARN("no UWorld found in %u objects", numElements);
        } while (0);
        driver_down(&drv);
        return rc;
    }

    if (!wcscmp(argv[1], L"verify-pov")) {
        // Verification gate: read own PlayerCameraManager.CameraCachePrivate.POV.Location
        // (FEncVector at PCM+0x31DA0+0x10), decrypt via XORPS, compare to expected.
        DH_DRIVER drv;
        if (!driver_up(&drv)) return DH_ERR_SVC_START;
        u64 sysCR3 = 0, procCR3 = 0, eproc = 0, peb = 0, base = 0, size = 0;
        int rc = DH_OK;
        do {
            if (!RpmFindSystemCR3(drv.hDevice, &sysCR3)) { rc = DH_ERR_RPM_FAIL; break; }
            if (!RpmFindProcess(drv.hDevice, sysCR3, DH_PROC_NAME, &procCR3, &eproc)) { rc = DH_ERR_TARGET_NOT_FOUND; break; }
            RpmRead64(drv.hDevice, sysCR3, eproc + g_eproc_peb_off, &peb);
            if (!RpmGetMainImageBase(drv.hDevice, procCR3, peb, &base, &size)) { base = 0x140000000ULL; size = 0x20300000ULL; }

            if (!AceDecryptXorpsInit(drv.hDevice, procCR3, base, size)) {
                DH_ERROR("xorps init failed"); rc = DH_ERR_RPM_FAIL; break;
            }

            // GWorld -> UWorld -> GameState (encrypted ptr, mask upper 16 bits) -> PlayerArray
            u64 uworld = 0;
            RpmRead64(drv.hDevice, procCR3, base + DF_RVA_GWORLD, &uworld);
            u64 gsRaw = 0;
            RpmRead64(drv.hDevice, procCR3, uworld + DF_WORLD_GAMESTATE, &gsRaw);
            u64 gameState = gsRaw & 0x0000FFFFFFFFFFFFULL;

            u64 psArr = 0; i32 psNum = 0;
            RpmRead64(drv.hDevice, procCR3, gameState + DF_GAMESTATE_PLAYERARRAY, &psArr);
            RpmReadVirtual(drv.hDevice, procCR3, gameState + DF_GAMESTATE_PLAYERARRAY + 8, &psNum, 4);
            DH_INFO("PlayerArray num=%d", psNum);

            for (i32 pi = 0; pi < psNum && pi < 64; pi++) {
                u64 ps = 0;
                RpmRead64(drv.hDevice, procCR3, psArr + (u64)pi * 8, &ps);
                if (!ps) continue;

                u64 pawn = 0;
                RpmRead64(drv.hDevice, procCR3, ps + DF_PLAYERSTATE_PAWNPRIVATE, &pawn);
                if (!pawn) continue;

                // APawn.PlayerController @ +0x3A8 (from GOLDEN_OFFSETS, but may not exist for bots).
                // For local player we can find it via PlayerController -> Pawn instead.
                // Try both: read pawn's Controller AND read APlayerController from PS
                u64 ctrlPtr = 0;
                RpmRead64(drv.hDevice, procCR3, pawn + 0x3A8, &ctrlPtr);
                u64 ctrl = ctrlPtr & 0x0000FFFFFFFFFFFFULL;
                DH_INFO("[%d] pawn=0x%llX ctrl=0x%llX (raw 0x%llX)", pi, pawn, ctrl, ctrlPtr);

                if (!ctrl) continue;

                // APlayerController.PlayerCameraManager @ +0x408 — FEncryptedObjectProperty_
                u64 pcmRaw = 0;
                RpmRead64(drv.hDevice, procCR3, ctrl + 0x408, &pcmRaw);
                u64 pcm = pcmRaw & 0x0000FFFFFFFFFFFFULL;  // simple 48-bit mask
                DH_INFO("[%d] PCM raw=0x%llX masked=0x%llX", pi, pcmRaw, pcm);
                if (!pcm || pcm < 0x100000) continue;

                // CameraCachePrivate.POV.Location @ PCM + 0x31DA0 + 0x10
                DH_ENC_VECTOR pov = {0};
                if (!RpmReadVirtual(drv.hDevice, procCR3, pcm + 0x31DB0, &pov, sizeof(pov))) {
                    DH_ERROR("[%d] POV read fail", pi); continue;
                }
                DH_FVECTOR pov_out = {0};
                BOOL dOk = AceDecryptXorps(&pov, &pov_out);
                printf("  [%d] POV.Location: raw=(%.1f, %.1f, %.1f) idx=0x%04X flg=0x%02X  ->  dec=(%.1f, %.1f, %.1f) %s\n",
                       pi, pov.X, pov.Y, pov.Z,
                       pov.EncHandler.Index, pov.EncHandler.flags,
                       pov_out.X, pov_out.Y, pov_out.Z,
                       dOk ? "OK" : "L2_FALLBACK");

                // Also try CameraCache (public) at +0x3E0 + 0x10 = +0x3F0
                DH_ENC_VECTOR pov_pub = {0};
                if (RpmReadVirtual(drv.hDevice, procCR3, pcm + 0x3F0, &pov_pub, sizeof(pov_pub))) {
                    DH_FVECTOR out2 = {0};
                    BOOL ok2 = AceDecryptXorps(&pov_pub, &out2);
                    printf("  [%d] POV.pub@+0x3F0: raw=(%.1f, %.1f, %.1f) idx=0x%04X flg=0x%02X  -> dec=(%.1f, %.1f, %.1f) %s\n",
                           pi, pov_pub.X, pov_pub.Y, pov_pub.Z,
                           pov_pub.EncHandler.Index, pov_pub.EncHandler.flags,
                           out2.X, out2.Y, out2.Z, ok2 ? "OK" : "L2_FALLBACK");
                }
            }
        } while (0);
        driver_down(&drv);
        return rc;
    }

    if (!wcscmp(argv[1], L"dump-ps-pawn")) {
        // Dump raw APlayerState fields for each entry, showing PawnPrivate raw+decoded
        DH_DRIVER drv;
        if (!driver_up(&drv)) return DH_ERR_SVC_START;
        u64 sysCR3 = 0, procCR3 = 0, eproc = 0, peb = 0, base = 0, size = 0;
        int rc = DH_OK;
        do {
            if (!RpmFindSystemCR3(drv.hDevice, &sysCR3)) { rc = DH_ERR_RPM_FAIL; break; }
            if (!RpmFindProcess(drv.hDevice, sysCR3, DH_PROC_NAME, &procCR3, &eproc)) { rc = DH_ERR_TARGET_NOT_FOUND; break; }
            RpmRead64(drv.hDevice, sysCR3, eproc + g_eproc_peb_off, &peb);
            if (!RpmGetMainImageBase(drv.hDevice, procCR3, peb, &base, &size)) { base = 0x140000000ULL; size = 0x20300000ULL; }

            u64 uworld = 0;
            RpmRead64(drv.hDevice, procCR3, base + DF_RVA_GWORLD, &uworld);
            u64 gsRaw = 0;
            RpmRead64(drv.hDevice, procCR3, uworld + DF_WORLD_GAMESTATE, &gsRaw);
            u64 gameState = gsRaw & 0x0000FFFFFFFFFFFFULL;
            u64 psArr = 0; i32 psNum = 0;
            RpmRead64(drv.hDevice, procCR3, gameState + DF_GAMESTATE_PLAYERARRAY, &psArr);
            RpmReadVirtual(drv.hDevice, procCR3, gameState + DF_GAMESTATE_PLAYERARRAY + 8, &psNum, 4);

            for (i32 pi = 0; pi < psNum && pi < 20; pi++) {
                u64 ps = 0;
                RpmRead64(drv.hDevice, procCR3, psArr + (u64)pi * 8, &ps);
                if (!ps) continue;

                // Raw pawn ptr from PS+0x378 (or wherever). Also try +0x310, +0x340, +0x380, +0x3A0
                u64 raw_pawn[8] = {0};
                u32 pawn_offs[] = { 0x378, 0x388, 0x3A8, 0x3F8, 0x400, 0x408, 0x420, 0x428 };
                u64 raw_pawns[8] = {0};
                for (int i = 0; i < 8; i++) {
                    RpmRead64(drv.hDevice, procCR3, ps + pawn_offs[i], &raw_pawns[i]);
                }
                memcpy(raw_pawn, raw_pawns, sizeof(raw_pawn));
                i32 teamID = 0;
                RpmReadVirtual(drv.hDevice, procCR3, ps + DF_GPPS_TEAMID, &teamID, 4);
                printf("\n=== pi=%d T%d PS=0x%llX ===\n", pi, teamID, ps);
                for (int i = 0; i < 8; i++) {
                    u64 masked = raw_pawn[i] & 0x0000FFFFFFFFFFFFULL;
                    printf("  PS+0x%03X = 0x%016llX  (masked 0x%llX)\n",
                           pawn_offs[i], raw_pawn[i], masked);
                }
            }
        } while (0);
        driver_down(&drv);
        return rc;
    }

    if (!wcscmp(argv[1], L"probe-repmov")) {
        // For each encrypted actor, probe pawn+various offsets for FRepMovement.Location
        // FRepMovement layout: LinearVel(12) AngVel(12) Location(12) Rotation(12) flags(2)
        // Testing candidate ReplicatedMovement offsets: 0x88, 0xA8, 0x108, 0x120, 0x140, 0x150, 0x1C0, 0x1E0, 0x200
        DH_DRIVER drv;
        if (!driver_up(&drv)) return DH_ERR_SVC_START;
        u64 sysCR3 = 0, procCR3 = 0, eproc = 0, peb = 0, base = 0, size = 0;
        int rc = DH_OK;
        do {
            if (!RpmFindSystemCR3(drv.hDevice, &sysCR3)) { rc = DH_ERR_RPM_FAIL; break; }
            if (!RpmFindProcess(drv.hDevice, sysCR3, DH_PROC_NAME, &procCR3, &eproc)) { rc = DH_ERR_TARGET_NOT_FOUND; break; }
            RpmRead64(drv.hDevice, sysCR3, eproc + g_eproc_peb_off, &peb);
            if (!RpmGetMainImageBase(drv.hDevice, procCR3, peb, &base, &size)) { base = 0x140000000ULL; size = 0x20300000ULL; }

            u64 uworld = 0;
            RpmRead64(drv.hDevice, procCR3, base + DF_RVA_GWORLD, &uworld);
            u64 gsRaw = 0;
            RpmRead64(drv.hDevice, procCR3, uworld + DF_WORLD_GAMESTATE, &gsRaw);
            u64 gameState = gsRaw & 0x0000FFFFFFFFFFFFULL;
            u64 psArr = 0; i32 psNum = 0;
            RpmRead64(drv.hDevice, procCR3, gameState + DF_GAMESTATE_PLAYERARRAY, &psArr);
            RpmReadVirtual(drv.hDevice, procCR3, gameState + DF_GAMESTATE_PLAYERARRAY + 8, &psNum, 4);

            u32 candidate_offs[] = { 0x60, 0x68, 0x70, 0x78, 0x80, 0x88, 0x90, 0xA0, 0xA8, 0xB0, 0xC0, 0xC8, 0xD0, 0xD8, 0xE0, 0xF0, 0x100, 0x108, 0x110, 0x118, 0x120, 0x128, 0x130, 0x138, 0x140, 0x148, 0x150, 0x158, 0x160, 0x170, 0x180, 0x190, 0x1A0, 0x1B0, 0x1C0, 0x1D0, 0x1E0, 0x1F0, 0x200, 0x210, 0x220, 0x230, 0x240, 0x250, 0x2A0, 0x300, 0x330, 0x380, 0x3E0 };

            for (i32 pi = 0; pi < psNum && pi < 20; pi++) {
                u64 ps = 0;
                RpmRead64(drv.hDevice, procCR3, psArr + (u64)pi * 8, &ps);
                if (!ps) continue;
                u64 pawn = 0;
                RpmRead64(drv.hDevice, procCR3, ps + 0x3F8, &pawn);
                pawn &= 0x0000FFFFFFFFFFFFULL;
                if (!pawn) continue;
                i32 teamID = 0;
                RpmReadVirtual(drv.hDevice, procCR3, ps + DF_GPPS_TEAMID, &teamID, 4);
                // Read Index from Root+0x168+0xC to check if encrypted
                u64 rootRaw = 0;
                RpmRead64(drv.hDevice, procCR3, pawn + DF_ACTOR_ROOTCOMPONENT, &rootRaw);
                u64 root = rootRaw & 0x0000FFFFFFFFFFFFULL;
                u16 idx = 0xFFFF;
                if (root && root >= 0x100000) {
                    RpmReadVirtual(drv.hDevice, procCR3, root + 0x168 + 0xC, &idx, 2);
                }
                const char* status = (idx == 0xFFFF) ? "PLAIN" : "ENC  ";

                printf("\n=== pi=%d T%d idx=0x%04X pawn=0x%llX ===\n", pi, teamID, idx, pawn);
                for (u32 i = 0; i < sizeof(candidate_offs)/sizeof(candidate_offs[0]); i++) {
                    u8 buf[12];
                    if (!RpmReadVirtual(drv.hDevice, procCR3, pawn + candidate_offs[i], buf, 12)) continue;
                    float x = *(float*)(buf + 0);
                    float y = *(float*)(buf + 4);
                    float z = *(float*)(buf + 8);
                    int vX = (x > -60000.f && x < 60000.f && (x < -50.f || x > 50.f) && (x==x));
                    int vY = (y > -60000.f && y < 60000.f && (y < -50.f || y > 50.f) && (y==y));
                    int vZ = (z > -2000.f && z < 8000.f && (z < -2.f || z > 2.f) && (z==z));
                    if (vX && vY && vZ) {
                        printf("  %s +0x%03X: (%12.1f, %12.1f, %12.1f)\n",
                               status, candidate_offs[i], x, y, z);
                    }
                }
            }
        } while (0);
        driver_down(&drv);
        return rc;
    }

    if (!wcscmp(argv[1], L"find-encsub")) {
        // Iterate GObjects to find UGPEncryptionSubsystem instance
        DH_DRIVER drv;
        if (!driver_up(&drv)) return DH_ERR_SVC_START;
        u64 sysCR3 = 0, procCR3 = 0, eproc = 0, peb = 0, base = 0, size = 0;
        int rc = DH_OK;
        do {
            if (!RpmFindSystemCR3(drv.hDevice, &sysCR3)) { rc = DH_ERR_RPM_FAIL; break; }
            if (!RpmFindProcess(drv.hDevice, sysCR3, DH_PROC_NAME, &procCR3, &eproc)) { rc = DH_ERR_TARGET_NOT_FOUND; break; }
            RpmRead64(drv.hDevice, sysCR3, eproc + g_eproc_peb_off, &peb);
            if (!RpmGetMainImageBase(drv.hDevice, procCR3, peb, &base, &size)) { base = 0x140000000ULL; size = 0x20300000ULL; }

            u64 gObjects = base + 0x1E689F18;
            u64 gNames   = base + 0x1E661B40;
            u32 numElements = 0;
            // Delta ObjLastNonGCIndex @ +0x04 is the effective count for iteration
            RpmReadVirtual(drv.hDevice, procCR3, gObjects + 0x04, &numElements, 4);
            DH_INFO("GObjects @ 0x%llX num=%u (from +0x04)", gObjects, numElements);

            u64 chunksPtr = 0;
            RpmRead64(drv.hDevice, procCR3, gObjects + 0x10, &chunksPtr);
            DH_INFO("  chunksPtr=0x%llX", chunksPtr);

            int found = 0;
            for (u32 i = 0; i < numElements && i < 300000; i++) {
                u32 chunkIdx = i / 0x10000;
                u32 inChunkIdx = i % 0x10000;
                u64 chunkPtr = 0;
                if (!RpmRead64(drv.hDevice, procCR3, chunksPtr + chunkIdx * 8, &chunkPtr)) continue;
                if (!chunkPtr) continue;
                u64 uobjItem = chunkPtr + inChunkIdx * 24;
                u64 obj = 0;
                RpmRead64(drv.hDevice, procCR3, uobjItem, &obj);
                if (!obj) continue;

                // Read UObject.Class @ +0x8
                u64 cls = 0;
                RpmRead64(drv.hDevice, procCR3, obj + 0x8, &cls);
                if (!cls) continue;

                // Read class name
                char clsName[64] = {0};
                RpmGetObjectName(drv.hDevice, procCR3, gNames, cls, clsName, sizeof(clsName));
                for (char* p = clsName; *p; p++) if ((u8)*p<0x20||(u8)*p>=0x7F){*p=0;break;}

                if (strstr(clsName, "Encryption") ||
                    strstr(clsName, "EncHandler")) {
                    char objName[64] = {0};
                    RpmGetObjectName(drv.hDevice, procCR3, gNames, obj, objName, sizeof(objName));
                    printf("  #%u obj=0x%llX class='%s' name='%s'\n", i, obj, clsName, objName);
                    // Dump first 0x200 bytes
                    u8 buf[0x200];
                    if (RpmReadVirtual(drv.hDevice, procCR3, obj, buf, sizeof(buf))) {
                        printf("    First 0x100 bytes:\n");
                        for (u32 off = 0; off < 0x100; off += 16) {
                            printf("      +0x%02X:", off);
                            for (int b = 0; b < 16; b++) printf(" %02X", buf[off+b]);
                            printf("\n");
                        }
                        // TMap EncryptionInfos @ +0x68
                        u64 tmapPtr = *(u64*)(buf + 0x68);
                        i32 tmapNum = *(i32*)(buf + 0x70);
                        printf("    EncryptionInfos @+0x68: ptr=0x%llX num=%d\n", tmapPtr, tmapNum);
                    }
                    found++;
                    if (found >= 3) break;
                }
            }
            if (!found) DH_WARN("no GPEncryptionSubsystem found in %u objects", numElements);
        } while (0);
        driver_down(&drv);
        return rc;
    }

    if (!wcscmp(argv[1], L"scan-pos388")) {
        // Same as scan-pos but pulls pawn from PS+0x388 instead of PS+0x3F8
        DH_DRIVER drv;
        if (!driver_up(&drv)) return DH_ERR_SVC_START;
        u64 sysCR3 = 0, procCR3 = 0, eproc = 0, peb = 0, base = 0, size = 0;
        int rc = DH_OK;
        do {
            if (!RpmFindSystemCR3(drv.hDevice, &sysCR3)) { rc = DH_ERR_RPM_FAIL; break; }
            if (!RpmFindProcess(drv.hDevice, sysCR3, DH_PROC_NAME, &procCR3, &eproc)) { rc = DH_ERR_TARGET_NOT_FOUND; break; }
            RpmRead64(drv.hDevice, sysCR3, eproc + g_eproc_peb_off, &peb);
            if (!RpmGetMainImageBase(drv.hDevice, procCR3, peb, &base, &size)) { base = 0x140000000ULL; size = 0x20300000ULL; }

            u64 uworld = 0;
            RpmRead64(drv.hDevice, procCR3, base + DF_RVA_GWORLD, &uworld);
            u64 gsRaw = 0;
            RpmRead64(drv.hDevice, procCR3, uworld + DF_WORLD_GAMESTATE, &gsRaw);
            u64 gameState = gsRaw & 0x0000FFFFFFFFFFFFULL;
            u64 psArr = 0; i32 psNum = 0;
            RpmRead64(drv.hDevice, procCR3, gameState + DF_GAMESTATE_PLAYERARRAY, &psArr);
            RpmReadVirtual(drv.hDevice, procCR3, gameState + DF_GAMESTATE_PLAYERARRAY + 8, &psNum, 4);

            for (i32 pi = 0; pi < psNum && pi < 20; pi++) {
                u64 ps = 0;
                RpmRead64(drv.hDevice, procCR3, psArr + (u64)pi * 8, &ps);
                if (!ps) continue;
                u64 pawn = 0;
                RpmRead64(drv.hDevice, procCR3, ps + 0x388, &pawn);
                pawn &= 0x0000FFFFFFFFFFFFULL;
                if (!pawn) continue;
                i32 teamID = 0;
                RpmReadVirtual(drv.hDevice, procCR3, ps + DF_GPPS_TEAMID, &teamID, 4);
                u8 pbuf[0x800];
                if (!RpmReadVirtual(drv.hDevice, procCR3, pawn, pbuf, sizeof(pbuf))) continue;
                printf("\n=== pi=%d T%d pawn388=0x%llX ===\n", pi, teamID, pawn);
                for (u32 off = 0; off + 12 <= sizeof(pbuf); off += 4) {
                    float x = *(float*)(pbuf + off);
                    float y = *(float*)(pbuf + off + 4);
                    float z = *(float*)(pbuf + off + 8);
                    int vX = (x > -30000.f && x < 30000.f && (x < -100.f || x > 100.f) && (x==x));
                    int vY = (y > -30000.f && y < 30000.f && (y < -100.f || y > 100.f) && (y==y));
                    int vZ = (z > -1000.f && z < 8000.f && (z < -1.f || z > 1.f) && (z==z));
                    if (vX && vY && vZ) {
                        printf("  +0x%03X: (%.1f, %.1f, %.1f)\n", off, x, y, z);
                    }
                }
            }
        } while (0);
        driver_down(&drv);
        return rc;
    }

    if (!wcscmp(argv[1], L"scan-pos")) {
        // For each pawn in PlayerArray, dump pawn+root memory and search
        // for FVector-shaped floats consistent with map coordinates.
        DH_DRIVER drv;
        if (!driver_up(&drv)) return DH_ERR_SVC_START;
        u64 sysCR3 = 0, procCR3 = 0, eproc = 0, peb = 0, base = 0, size = 0;
        int rc = DH_OK;
        do {
            if (!RpmFindSystemCR3(drv.hDevice, &sysCR3)) { rc = DH_ERR_RPM_FAIL; break; }
            if (!RpmFindProcess(drv.hDevice, sysCR3, DH_PROC_NAME, &procCR3, &eproc)) { rc = DH_ERR_TARGET_NOT_FOUND; break; }
            RpmRead64(drv.hDevice, sysCR3, eproc + g_eproc_peb_off, &peb);
            if (!RpmGetMainImageBase(drv.hDevice, procCR3, peb, &base, &size)) { base = 0x140000000ULL; size = 0x20300000ULL; }

            u64 uworld = 0;
            RpmRead64(drv.hDevice, procCR3, base + DF_RVA_GWORLD, &uworld);
            u64 gsRaw = 0;
            RpmRead64(drv.hDevice, procCR3, uworld + DF_WORLD_GAMESTATE, &gsRaw);
            u64 gameState = gsRaw & 0x0000FFFFFFFFFFFFULL;
            u64 psArr = 0; i32 psNum = 0;
            RpmRead64(drv.hDevice, procCR3, gameState + DF_GAMESTATE_PLAYERARRAY, &psArr);
            RpmReadVirtual(drv.hDevice, procCR3, gameState + DF_GAMESTATE_PLAYERARRAY + 8, &psNum, 4);
            DH_INFO("PlayerArray num=%d", psNum);

            for (i32 pi = 0; pi < psNum && pi < 64; pi++) {
                u64 ps = 0;
                RpmRead64(drv.hDevice, procCR3, psArr + (u64)pi * 8, &ps);
                if (!ps) continue;

                u64 pawn = 0;
                RpmRead64(drv.hDevice, procCR3, ps + DF_PLAYERSTATE_PAWNPRIVATE, &pawn);
                if (!pawn) continue;

                i32 teamID = 0;
                RpmReadVirtual(drv.hDevice, procCR3, ps + DF_GPPS_TEAMID, &teamID, 4);

                // Dump 0x800 bytes of pawn
                u8 pbuf[0x800];
                if (!RpmReadVirtual(drv.hDevice, procCR3, pawn, pbuf, sizeof(pbuf))) continue;

                printf("\n=== pi=%d T%d pawn=0x%llX ===\n", pi, teamID, pawn);
                // Scan for FVector triples: X in (-30000, 30000), Y in (-30000, 30000), Z in (-500, 6000)
                for (u32 off = 0; off + 12 <= sizeof(pbuf); off += 4) {
                    float x = *(float*)(pbuf + off);
                    float y = *(float*)(pbuf + off + 4);
                    float z = *(float*)(pbuf + off + 8);
                    int vX = (x > -30000.f && x < 30000.f && (x < -100.f || x > 100.f) && (x==x));
                    int vY = (y > -30000.f && y < 30000.f && (y < -100.f || y > 100.f) && (y==y));
                    int vZ = (z > -1000.f && z < 8000.f && (z < -1.f || z > 1.f) && (z==z));
                    if (vX && vY && vZ) {
                        printf("  pawn+0x%03X: (%.1f, %.1f, %.1f)\n", off, x, y, z);
                    }
                }

                // Also dump root
                u64 rootRaw = 0;
                RpmRead64(drv.hDevice, procCR3, pawn + DF_ACTOR_ROOTCOMPONENT, &rootRaw);
                u64 root = rootRaw & 0x0000FFFFFFFFFFFFULL;
                if (root && root >= 0x100000) {
                    u8 rbuf[0x2000];
                    if (RpmReadVirtual(drv.hDevice, procCR3, root, rbuf, sizeof(rbuf))) {
                        for (u32 off = 0; off + 12 <= sizeof(rbuf); off += 4) {
                            float x = *(float*)(rbuf + off);
                            float y = *(float*)(rbuf + off + 4);
                            float z = *(float*)(rbuf + off + 8);
                            int vX = (x > -30000.f && x < 30000.f && (x < -100.f || x > 100.f) && (x==x));
                            int vY = (y > -30000.f && y < 30000.f && (y < -100.f || y > 100.f) && (y==y));
                            int vZ = (z > -1000.f && z < 8000.f && (z < -1.f || z > 1.f) && (z==z));
                            if (vX && vY && vZ) {
                                printf("  root+0x%03X: (%.1f, %.1f, %.1f)\n", off, x, y, z);
                            }
                        }
                    }
                }

                // Also check Mesh (Character.Mesh @ +0x3D0), which is SkeletalMeshComponent
                u64 meshRaw = 0;
                RpmRead64(drv.hDevice, procCR3, pawn + 0x3D0, &meshRaw);
                u64 mesh = meshRaw & 0x0000FFFFFFFFFFFFULL;
                if (mesh && mesh >= 0x100000) {
                    u8 mbuf[0x2000];
                    if (RpmReadVirtual(drv.hDevice, procCR3, mesh, mbuf, sizeof(mbuf))) {
                        for (u32 off = 0; off + 12 <= sizeof(mbuf); off += 4) {
                            float x = *(float*)(mbuf + off);
                            float y = *(float*)(mbuf + off + 4);
                            float z = *(float*)(mbuf + off + 8);
                            int vX = (x > -30000.f && x < 30000.f && (x < -100.f || x > 100.f) && (x==x));
                            int vY = (y > -30000.f && y < 30000.f && (y < -100.f || y > 100.f) && (y==y));
                            int vZ = (z > -1000.f && z < 8000.f && (z < -1.f || z > 1.f) && (z==z));
                            if (vX && vY && vZ) {
                                printf("  mesh+0x%03X: (%.1f, %.1f, %.1f)\n", off, x, y, z);
                            }
                        }
                    }
                }
            }
        } while (0);
        driver_down(&drv);
        return rc;
    }

    if (!wcscmp(argv[1], L"xorps-init")) {
        // Locate + RPM-read the 8-entry x 16-byte XORPS key table.
        DH_DRIVER drv;
        if (!driver_up(&drv)) return DH_ERR_SVC_START;
        u64 sysCR3 = 0, procCR3 = 0, eproc = 0;
        if (!RpmFindSystemCR3(drv.hDevice, &sysCR3)) { driver_down(&drv); return DH_ERR_RPM_FAIL; }
        if (!RpmFindProcess(drv.hDevice, sysCR3, DH_PROC_NAME, &procCR3, &eproc)) {
            DH_ERROR("delta not found"); driver_down(&drv); return DH_ERR_RPM_FAIL;
        }
        BOOL ok = AceDecryptXorpsInit(drv.hDevice, procCR3, 0x140000000ULL, 0x20300000ULL);
        driver_down(&drv);
        return ok ? DH_OK : DH_ERR_RPM_FAIL;
    }

    if (!wcscmp(argv[1], L"capture-pair")) {
        // Polls PlayerArray, finds any encrypted enemy whose pawn+0x1C2C has
        // plausible plaintext AND root+0x168 has encrypted bytes. Prints the
        // matched pair (ciphertext + expected plaintext) so we can validate
        // and calibrate the C280 decrypt.
        DH_DRIVER drv;
        if (!driver_up(&drv)) return DH_ERR_SVC_START;
        u64 sysCR3 = 0, procCR3 = 0, eproc = 0, peb = 0, base = 0, size = 0;
        int rc = DH_OK;
        do {
            if (!RpmFindSystemCR3(drv.hDevice, &sysCR3)) { rc = DH_ERR_RPM_FAIL; break; }
            if (!RpmFindProcess(drv.hDevice, sysCR3, DH_PROC_NAME, &procCR3, &eproc)) { rc = DH_ERR_TARGET_NOT_FOUND; break; }
            RpmRead64(drv.hDevice, sysCR3, eproc + g_eproc_peb_off, &peb);
            if (!RpmGetMainImageBase(drv.hDevice, procCR3, peb, &base, &size)) { base = 0x140000000ULL; size = 0x1F800000; }
            u64 uworld = 0;
            RpmRead64(drv.hDevice, procCR3, base + DF_RVA_GWORLD, &uworld);
            u64 gsRaw = 0;
            RpmRead64(drv.hDevice, procCR3, uworld + DF_WORLD_GAMESTATE, &gsRaw);
            u64 gameState = gsRaw & 0x0000FFFFFFFFFFFFULL;
            u64 psArr = 0; i32 psNum = 0;
            RpmRead64(drv.hDevice, procCR3, gameState + DF_GAMESTATE_PLAYERARRAY, &psArr);
            RpmReadVirtual(drv.hDevice, procCR3, gameState + DF_GAMESTATE_PLAYERARRAY + 8, &psNum, 4);

            int found = 0;
            for (i32 pi = 0; pi < psNum && !found; pi++) {
                u64 ps = 0;
                RpmRead64(drv.hDevice, procCR3, psArr + (u64)pi * 8, &ps);
                if (!ps) continue;
                u64 pawn = 0;
                RpmRead64(drv.hDevice, procCR3, ps + DF_PLAYERSTATE_PAWNPRIVATE, &pawn);
                if (!pawn) continue;
                u64 rootRaw = 0;
                RpmRead64(drv.hDevice, procCR3, pawn + DF_ACTOR_ROOTCOMPONENT, &rootRaw);
                u64 root = rootRaw & 0x0000FFFFFFFFFFFFULL;
                if (!root || root < 0x100000) continue;

                DH_ENC_VECTOR relEnc = {0};
                if (!RpmReadVirtual(drv.hDevice, procCR3, root + 0x168, &relEnc, sizeof(relEnc))) continue;
                if (relEnc.EncHandler.Index == 0xFFFF) continue;   // skip teammates

                float px = 0, py = 0, pz = 0;
                if (!RpmReadVirtual(drv.hDevice, procCR3, pawn + 0x1C2C, &px, 4)) continue;
                if (!RpmReadVirtual(drv.hDevice, procCR3, pawn + 0x1C30, &py, 4)) continue;
                if (!RpmReadVirtual(drv.hDevice, procCR3, pawn + 0x1C34, &pz, 4)) continue;
                if (px != px || py != py || pz != pz) continue;
                if (fabsf(px) < 500.f || fabsf(px) > 100000.f) continue;
                if (fabsf(py) < 500.f || fabsf(py) > 100000.f) continue;
                if (fabsf(pz) > 10000.f) continue;

                // Also read CTW.Translation (root+0x220) for reference
                u8 ctw[16] = {0};
                RpmReadVirtual(drv.hDevice, procCR3, root + 0x220, ctw, 16);

                union { float f; u32 u; } xb, yb, zb;
                memcpy(&xb.f, &relEnc.X, 4);
                memcpy(&yb.f, &relEnc.Y, 4);
                memcpy(&zb.f, &relEnc.Z, 4);
                union { float f; u32 u; } pxu, pyu, pzu;
                pxu.f = px; pyu.f = py; pzu.f = pz;

                wprintf(L"\n=== FOUND validated pair (player idx=%d) ===\n", pi);
                wprintf(L"  pawn=0x%llX  root=0x%llX\n", pawn, root);
                wprintf(L"  Idx=0x%04X  b2=0x%02X  b3=0x%02X (bDyn=%d)\n",
                    relEnc.EncHandler.Index, relEnc.EncHandler.bEncrypted,
                    relEnc.EncHandler.flags, relEnc.EncHandler.flags & 1);
                wprintf(L"  ENCRYPTED root+0x168: X_bits=0x%08X Y_bits=0x%08X Z_bits=0x%08X\n",
                    xb.u, yb.u, zb.u);
                wprintf(L"  PLAINTEXT pawn+0x1C2C: X_bits=0x%08X (%.1f) Y_bits=0x%08X (%.1f) Z_bits=0x%08X (%.1f)\n",
                    pxu.u, px, pyu.u, py, pzu.u, pz);
                wprintf(L"  CTW+0x220 bytes: ");
                for (int i=0;i<16;i++) wprintf(L"%02X ", ctw[i]);
                wprintf(L"\n");
                found = 1;
            }
            if (!found) wprintf(L"No enemy in relevancy range right now (all encrypted enemies have zero pawn+0x1C2C).\n");
        } while (0);
        driver_down(&drv);
        return rc;
    }

    if (!wcscmp(argv[1], L"hunt-live")) {
        // Systematic live-source hunter for a target actor. Takes N snapshots
        // of a wide memory range every 10s, diffs each pair, reports every
        // float-triple offset that changed with plausible-movement magnitude.
        //   dh_loader.exe hunt-live <player_idx> [snapshots=6] [gap_sec=10]
        if (argc < 3) { wprintf(L"usage: hunt-live <player_idx> [snapshots] [gap_sec]\n"); return DH_ERR_BAD_ARG; }
        u32 tgtPi = (u32)_wtoi(argv[2]);
        u32 nsnap = (argc >= 4) ? (u32)_wtoi(argv[3]) : 6;
        u32 gapS  = (argc >= 5) ? (u32)_wtoi(argv[4]) : 10;
        if (nsnap < 2) nsnap = 2;

        DH_DRIVER drv;
        if (!driver_up(&drv)) return DH_ERR_SVC_START;
        u64 sysCR3 = 0, procCR3 = 0, eproc = 0, peb = 0, base = 0, size = 0;
        int rc = DH_OK;
        do {
            if (!RpmFindSystemCR3(drv.hDevice, &sysCR3)) { rc = DH_ERR_RPM_FAIL; break; }
            if (!RpmFindProcess(drv.hDevice, sysCR3, DH_PROC_NAME, &procCR3, &eproc)) { rc = DH_ERR_TARGET_NOT_FOUND; break; }
            RpmRead64(drv.hDevice, sysCR3, eproc + g_eproc_peb_off, &peb);
            if (!RpmGetMainImageBase(drv.hDevice, procCR3, peb, &base, &size)) { base = 0x140000000ULL; size = 0x1F800000; }

            u64 uworld = 0;
            RpmRead64(drv.hDevice, procCR3, base + DF_RVA_GWORLD, &uworld);
            u64 gsRaw = 0;
            RpmRead64(drv.hDevice, procCR3, uworld + DF_WORLD_GAMESTATE, &gsRaw);
            u64 gameState = gsRaw & 0x0000FFFFFFFFFFFFULL;
            u64 psArr = 0; i32 psNum = 0;
            RpmRead64(drv.hDevice, procCR3, gameState + DF_GAMESTATE_PLAYERARRAY, &psArr);
            RpmReadVirtual(drv.hDevice, procCR3, gameState + DF_GAMESTATE_PLAYERARRAY + 8, &psNum, 4);

            u64 ps = 0;
            RpmRead64(drv.hDevice, procCR3, psArr + (u64)tgtPi * 8, &ps);
            i32 teamID = 0;
            RpmReadVirtual(drv.hDevice, procCR3, ps + DF_GPPS_TEAMID, &teamID, 4);
            u64 pawn = 0;
            RpmRead64(drv.hDevice, procCR3, ps + DF_PLAYERSTATE_PAWNPRIVATE, &pawn);
            u64 rootRaw = 0;
            RpmRead64(drv.hDevice, procCR3, pawn + DF_ACTOR_ROOTCOMPONENT, &rootRaw);
            u64 root = rootRaw & 0x0000FFFFFFFFFFFFULL;
            u64 meshRaw = 0;
            RpmRead64(drv.hDevice, procCR3, pawn + 0x3D0, &meshRaw);
            u64 mesh = meshRaw & 0x0000FFFFFFFFFFFFULL;

            printf("[hunt-live idx=%u T%d pawn=0x%llX root=0x%llX mesh=0x%llX] snaps=%u gap=%us\n",
                   tgtPi, teamID, pawn, root, mesh, nsnap, gapS);

            struct Region { const char* name; u64 base; u32 size; };
            struct Region regs[] = {
                { "pawn", pawn, 0x8000 },
                { "root", root, 0x2000 },
                { "mesh", mesh, 0x2000 },
            };
            const int nreg = 3;
            u8** snaps = (u8**)malloc(nsnap * nreg * sizeof(u8*));
            for (u32 i = 0; i < nsnap * nreg; i++) snaps[i] = NULL;

            for (u32 s = 0; s < nsnap; s++) {
                for (int r = 0; r < nreg; r++) {
                    if (!regs[r].base) continue;
                    u8* buf = (u8*)malloc(regs[r].size);
                    if (!buf) continue;
                    if (!RpmReadVirtual(drv.hDevice, procCR3, regs[r].base, buf, regs[r].size)) {
                        free(buf); continue;
                    }
                    snaps[s * nreg + r] = buf;
                }
                printf("[snap %u/%u taken @ %llds]\n", s + 1, nsnap, (long long)(s * gapS));
                if (s + 1 < nsnap) Sleep(gapS * 1000);
            }

            // Diff all consecutive pairs, find offsets where triple moved by
            // plausible-live magnitude (10..30000 units total displacement
            // across pair). Aggregate: offset gets a "moves" score if it
            // varies in AT LEAST 3 of the (nsnap-1) diffs.
            typedef struct { u32 off; int region; u32 hits; float last_dx; } Hit;
            Hit hits[512]; int nhits = 0;
            for (int r = 0; r < nreg; r++) {
                if (!snaps[r]) continue;
                for (u32 o = 0; o + 12 <= regs[r].size; o += 4) {
                    u32 movingRounds = 0;
                    float lastDx = 0;
                    int plausibleAlways = 1;
                    for (u32 s = 0; s + 1 < nsnap; s++) {
                        u8* a = snaps[s * nreg + r];
                        u8* b = snaps[(s + 1) * nreg + r];
                        if (!a || !b) { plausibleAlways = 0; break; }
                        float x1, y1, z1, x2, y2, z2;
                        memcpy(&x1, a + o, 4); memcpy(&y1, a + o + 4, 4); memcpy(&z1, a + o + 8, 4);
                        memcpy(&x2, b + o, 4); memcpy(&y2, b + o + 4, 4); memcpy(&z2, b + o + 8, 4);
                        if (x1 != x1 || y1 != y1 || z1 != z1) { plausibleAlways = 0; break; }
                        if (x2 != x2 || y2 != y2 || z2 != z2) { plausibleAlways = 0; break; }
                        if (fabsf(x2) > 1e10f || fabsf(y2) > 1e10f) { plausibleAlways = 0; break; }
                        float dx = x2 - x1, dy = y2 - y1;
                        float d = sqrtf(dx*dx + dy*dy);
                        if (d > 1.f && d < 30000.f) {
                            movingRounds++;
                            lastDx = d;
                        }
                    }
                    if (plausibleAlways && movingRounds >= 1 && nhits < 512) {
                        hits[nhits].off = o;
                        hits[nhits].region = r;
                        hits[nhits].hits = movingRounds;
                        hits[nhits].last_dx = lastDx;
                        nhits++;
                    }
                }
            }
            printf("\n[hunt-live results: %d offsets moved plausibly across snapshots]\n", nhits);
            for (int h = 0; h < nhits; h++) {
                Hit* H = &hits[h];
                printf("  %s+0x%04X  moved in %u/%u pairs, last_d=%.1f\n",
                    regs[H->region].name, H->off, H->hits, nsnap - 1, H->last_dx);
            }
            for (u32 i = 0; i < nsnap * nreg; i++) if (snaps[i]) free(snaps[i]);
            free(snaps);
        } while (0);
        driver_down(&drv);
        return rc;
    }

    if (!wcscmp(argv[1], L"diff-scan")) {
        // Live diff scan: for a target player_idx, record 16KB of pawn memory,
        // wait N seconds while the enemy moves, then diff to find float triples
        // that changed by realistic movement deltas (>50 units < 30000 units).
        // Prints candidates that plausibly hold live world position.
        //   dh_loader.exe diff-scan <player_idx> [seconds]
        if (argc < 3) { wprintf(L"usage: diff-scan <player_idx> [seconds]\n"); return DH_ERR_BAD_ARG; }
        u32 tgtPi = (u32)_wtoi(argv[2]);
        u32 secs  = (argc >= 4) ? (u32)_wtoi(argv[3]) : 3;

        DH_DRIVER drv;
        if (!driver_up(&drv)) return DH_ERR_SVC_START;
        u64 sysCR3 = 0, procCR3 = 0, eproc = 0, peb = 0, base = 0, size = 0;
        int rc = DH_OK;
        do {
            if (!RpmFindSystemCR3(drv.hDevice, &sysCR3)) { rc = DH_ERR_RPM_FAIL; break; }
            if (!RpmFindProcess(drv.hDevice, sysCR3, DH_PROC_NAME, &procCR3, &eproc)) { rc = DH_ERR_TARGET_NOT_FOUND; break; }
            RpmRead64(drv.hDevice, sysCR3, eproc + g_eproc_peb_off, &peb);
            if (!RpmGetMainImageBase(drv.hDevice, procCR3, peb, &base, &size)) { base = 0x140000000ULL; size = 0x1F800000; }

            u64 uworld = 0;
            RpmRead64(drv.hDevice, procCR3, base + DF_RVA_GWORLD, &uworld);
            u64 gsRaw = 0;
            RpmRead64(drv.hDevice, procCR3, uworld + DF_WORLD_GAMESTATE, &gsRaw);
            u64 gameState = gsRaw & 0x0000FFFFFFFFFFFFULL;
            u64 psArr = 0; i32 psNum = 0;
            RpmRead64(drv.hDevice, procCR3, gameState + DF_GAMESTATE_PLAYERARRAY, &psArr);
            RpmReadVirtual(drv.hDevice, procCR3, gameState + DF_GAMESTATE_PLAYERARRAY + 8, &psNum, 4);

            u64 ps = 0;
            RpmRead64(drv.hDevice, procCR3, psArr + (u64)tgtPi * 8, &ps);
            u64 pawn = 0;
            RpmRead64(drv.hDevice, procCR3, ps + DF_PLAYERSTATE_PAWNPRIVATE, &pawn);
            i32 teamID = 0;
            RpmReadVirtual(drv.hDevice, procCR3, ps + DF_GPPS_TEAMID, &teamID, 4);
            u64 rootRaw = 0;
            RpmRead64(drv.hDevice, procCR3, pawn + DF_ACTOR_ROOTCOMPONENT, &rootRaw);
            u64 root = rootRaw & 0x0000FFFFFFFFFFFFULL;
            u64 meshRaw = 0;
            RpmRead64(drv.hDevice, procCR3, pawn + 0x3D0, &meshRaw);
            u64 mesh = meshRaw & 0x0000FFFFFFFFFFFFULL;
            u64 cmRaw = 0;
            RpmRead64(drv.hDevice, procCR3, pawn + 0x3F0, &cmRaw);
            u64 cm = cmRaw & 0x0000FFFFFFFFFFFFULL;

            printf("[diff-scan idx=%u team=%d pawn=0x%llX root=0x%llX mesh=0x%llX cm=0x%llX]\n",
                   tgtPi, teamID, pawn, root, mesh, cm);

            struct Region { const char* name; u64 base; u32 size; };
            struct Region regs[4] = {
                { "pawn", pawn, 0x4000 },
                { "root", root, 0x1000 },
                { "mesh", mesh, 0x1000 },
                { "cm",   cm,   0x1000 },
            };
            u8* snap1[4] = {0};
            u8* snap2[4] = {0};
            for (int r = 0; r < 4; r++) {
                if (!regs[r].base) continue;
                snap1[r] = (u8*)malloc(regs[r].size);
                snap2[r] = (u8*)malloc(regs[r].size);
                if (!RpmReadVirtual(drv.hDevice, procCR3, regs[r].base, snap1[r], regs[r].size)) {
                    printf("  %s snap1 fail\n", regs[r].name);
                    free(snap1[r]); free(snap2[r]);
                    snap1[r] = snap2[r] = NULL;
                }
            }
            printf("[waiting %u seconds — MOVE enemy...]\n", secs);
            Sleep(secs * 1000);
            for (int r = 0; r < 4; r++) {
                if (!snap1[r]) continue;
                RpmReadVirtual(drv.hDevice, procCR3, regs[r].base, snap2[r], regs[r].size);
                printf("[%s] delta candidates (float triples with dx+dy > 20 units):\n", regs[r].name);
                for (u32 o = 0; o + 12 <= regs[r].size; o += 4) {
                    float x1, y1, z1, x2, y2, z2;
                    memcpy(&x1, snap1[r]+o, 4); memcpy(&y1, snap1[r]+o+4, 4); memcpy(&z1, snap1[r]+o+8, 4);
                    memcpy(&x2, snap2[r]+o, 4); memcpy(&y2, snap2[r]+o+4, 4); memcpy(&z2, snap2[r]+o+8, 4);
                    // Sanity: both plausible world coords
                    if (x1 != x1 || y1 != y1 || z1 != z1) continue;
                    if (x2 != x2 || y2 != y2 || z2 != z2) continue;
                    if (fabsf(x2) > 100000.f || fabsf(y2) > 100000.f || fabsf(z2) > 10000.f) continue;
                    if (fabsf(x2) < 500.f && fabsf(y2) < 500.f) continue;   // ignore near-zero
                    float dx = x2 - x1, dy = y2 - y1, dz = z2 - z1;
                    float d = sqrtf(dx*dx + dy*dy);
                    // real movement: 20cm..30000cm per 3s (roughly 0.5m..300m)
                    if (d < 20.f || d > 30000.f) continue;
                    if (fabsf(dz) > 5000.f) continue;   // z shouldn't teleport
                    printf("  %s+0x%04X: (%.1f,%.1f,%.1f) -> (%.1f,%.1f,%.1f) d=%.1f\n",
                        regs[r].name, o, x1, y1, z1, x2, y2, z2, d);
                }
                free(snap1[r]); free(snap2[r]);
            }
        } while (0);
        driver_down(&drv);
        return rc;
    }

    if (!wcscmp(argv[1], L"debug-actor")) {
        // Full diagnostic dump for one player by array index. Prints raw
        // FEncVector bytes at root+0x168 and root+0x220, decoded EncHandler
        // fields, state_data reads across all 4 slots, both VTBL-shellcode
        // and state-cache decrypt results. Also scans nearby offsets for
        // plaintext-looking FVectors.
        //   dh_loader.exe debug-actor <player_idx_in_PlayerArray>
        if (argc < 3) { wprintf(L"usage: debug-actor <player_idx>\n"); return DH_ERR_BAD_ARG; }
        u32 tgtPi = (u32)_wtoi(argv[2]);

        DH_DRIVER drv;
        if (!driver_up(&drv)) return DH_ERR_SVC_START;
        u64 sysCR3 = 0, procCR3 = 0, eproc = 0, peb = 0, base = 0, size = 0;
        int rc = DH_OK;
        do {
            if (!RpmFindSystemCR3(drv.hDevice, &sysCR3)) { rc = DH_ERR_RPM_FAIL; break; }
            if (!RpmFindProcess(drv.hDevice, sysCR3, DH_PROC_NAME, &procCR3, &eproc)) { rc = DH_ERR_TARGET_NOT_FOUND; break; }
            RpmRead64(drv.hDevice, sysCR3, eproc + g_eproc_peb_off, &peb);
            if (!RpmGetMainImageBase(drv.hDevice, procCR3, peb, &base, &size)) { base = 0x140000000ULL; size = 0x1F800000; }
            if (!VtblDecryptInitStatic()) { rc = DH_ERR_RPM_FAIL; break; }

            u64 uworld = 0;
            RpmRead64(drv.hDevice, procCR3, base + DF_RVA_GWORLD, &uworld);
            u64 gsRaw = 0;
            RpmRead64(drv.hDevice, procCR3, uworld + DF_WORLD_GAMESTATE, &gsRaw);
            u64 gameState = gsRaw & 0x0000FFFFFFFFFFFFULL;
            u64 psArr = 0; i32 psNum = 0;
            RpmRead64(drv.hDevice, procCR3, gameState + DF_GAMESTATE_PLAYERARRAY, &psArr);
            RpmReadVirtual(drv.hDevice, procCR3, gameState + DF_GAMESTATE_PLAYERARRAY + 8, &psNum, 4);
            if ((i32)tgtPi >= psNum) { wprintf(L"idx out of range (num=%d)\n", psNum); break; }

            u64 ps = 0;
            RpmRead64(drv.hDevice, procCR3, psArr + (u64)tgtPi * 8, &ps);
            u64 pawn = 0;
            RpmRead64(drv.hDevice, procCR3, ps + DF_PLAYERSTATE_PAWNPRIVATE, &pawn);
            i32 teamID = 0;
            RpmReadVirtual(drv.hDevice, procCR3, ps + DF_GPPS_TEAMID, &teamID, 4);
            u64 rootRaw = 0;
            RpmRead64(drv.hDevice, procCR3, pawn + DF_ACTOR_ROOTCOMPONENT, &rootRaw);
            u64 root = rootRaw & 0x0000FFFFFFFFFFFFULL;

            printf("\n=== debug-actor [%u] team=%d ps=0x%llX pawn=0x%llX root=0x%llX ===\n",
                   tgtPi, teamID, ps, pawn, root);

            // Print raw FEncVector bytes at root+0x168 and root+0x220
            u32 dumps[] = { 0x168, 0x220 };
            const char* dumpNames[] = { "RelLoc", "CTW.T" };
            for (u32 di = 0; di < 2; di++) {
                u8 fv[16] = {0};
                if (!RpmReadVirtual(drv.hDevice, procCR3, root + dumps[di], fv, 16)) continue;
                printf("\n%s @ root+0x%03X:\n", dumpNames[di], dumps[di]);
                printf("  raw bytes: %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X\n",
                    fv[0],fv[1],fv[2],fv[3],fv[4],fv[5],fv[6],fv[7],
                    fv[8],fv[9],fv[10],fv[11],fv[12],fv[13],fv[14],fv[15]);
                float x, y, z;
                memcpy(&x, fv+0, 4); memcpy(&y, fv+4, 4); memcpy(&z, fv+8, 4);
                u16 idx = *(u16*)(fv + 12);
                u8 b2 = fv[14], b3 = fv[15];
                printf("  float:      X=%.4f Y=%.4f Z=%.4f  Index=0x%04X  b2=0x%02X b3=0x%02X (bDyn=%d)\n",
                       x, y, z, idx, b2, b3, b3 & 1);

                // Shellcode raw call ignoring bEncrypted
                DH_ENC_VECTOR e_force = { x, y, z, { idx, 1, b3 } };
                DH_FVECTOR out_sh = {0};
                if (VtblDecryptCall(&e_force, &out_sh))
                    printf("  shellcode dec: (%.4f, %.4f, %.4f)\n", out_sh.X, out_sh.Y, out_sh.Z);

                // State-cache lookup all 4 slots
                u32 idx_low12 = idx & 0xFFF;
                u64 off = 20 * idx_low12;
                static const u32 slot_off[4] = { 0xC8, 0x108, 0x148, 0x188 };
                u64 LOOKUP = 0x15E111AC0ULL;
                for (int s = 0; s < 4; s++) {
                    u64 sptr = 0;
                    RpmRead64(drv.hDevice, procCR3, LOOKUP + slot_off[s], &sptr);
                    if (!sptr) continue;
                    u8 sfv[16] = {0};
                    if (!RpmReadVirtual(drv.hDevice, procCR3, sptr + off, sfv, 16)) continue;
                    float sx, sy, sz;
                    memcpy(&sx, sfv, 4); memcpy(&sy, sfv+4, 4); memcpy(&sz, sfv+8, 4);
                    printf("  slot[%d] @ 0x%llX+0x%llX: (%.4f, %.4f, %.4f) bytes=%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X\n",
                        s, sptr, off, sx, sy, sz,
                        sfv[0],sfv[1],sfv[2],sfv[3],sfv[4],sfv[5],sfv[6],sfv[7],
                        sfv[8],sfv[9],sfv[10],sfv[11]);
                }
            }

            // Scan LARGER range of root + pawn + mesh + charMov + capsule
            #define SCAN_ONE(who, ptr, sz) do { \
                if (ptr && ptr >= 0x100000) { \
                    printf("\n[scan %s @ 0x%llX +0..%d]:\n", who, (u64)ptr, sz); \
                    u8* xbuf = (u8*)malloc(sz); \
                    if (xbuf && RpmReadVirtual(drv.hDevice, procCR3, ptr, xbuf, sz)) { \
                        for (u32 o = 0; o + 12 <= (u32)(sz); o += 4) { \
                            float rx, ry, rz; \
                            memcpy(&rx, xbuf+o, 4); memcpy(&ry, xbuf+o+4, 4); memcpy(&rz, xbuf+o+8, 4); \
                            if (rx != rx || ry != ry || rz != rz) continue; \
                            if (fabsf(rx) < 500.f || fabsf(rx) > 100000.f) continue; \
                            if (fabsf(ry) < 500.f || fabsf(ry) > 100000.f) continue; \
                            if (fabsf(rz) > 8000.f) continue; \
                            printf("  %s+0x%03X: (%.1f, %.1f, %.1f)\n", who, o, rx, ry, rz); \
                        } \
                    } \
                    if (xbuf) free(xbuf); \
                } \
            } while (0)

            SCAN_ONE("root", root, 0x2000);
            SCAN_ONE("pawn", pawn, 0x2000);

            // Follow pawn+0x3D0 = Mesh (Character.Mesh)
            u64 meshRaw = 0;
            RpmRead64(drv.hDevice, procCR3, pawn + 0x3D0, &meshRaw);
            u64 mesh = meshRaw & 0x0000FFFFFFFFFFFFULL;
            if (mesh) SCAN_ONE("mesh", mesh, 0x1000);

            // Follow pawn+0x3F0 = CharacterMovement
            u64 cmRaw = 0;
            RpmRead64(drv.hDevice, procCR3, pawn + 0x3F0, &cmRaw);
            u64 cm = cmRaw & 0x0000FFFFFFFFFFFFULL;
            if (cm) SCAN_ONE("charMov", cm, 0x800);

            // Follow pawn+0x3C8 = CapsuleComponent (typical UE character)
            u64 capRaw = 0;
            RpmRead64(drv.hDevice, procCR3, pawn + 0x3C8, &capRaw);
            u64 cap = capRaw & 0x0000FFFFFFFFFFFFULL;
            if (cap && cap != root) SCAN_ONE("capsule", cap, 0x800);

            // Also try walking the ACE cache slot content beyond 20*Index — maybe
            // it's a big fat cache and real positions live at a bigger stride.
            printf("\n[scan slot[0] state_data +0..0x4000 for plausible FVector]:\n");
            u64 slot0 = 0;
            RpmRead64(drv.hDevice, procCR3, 0x15E111AC0ULL + 0xC8, &slot0);
            if (slot0) {
                u8* sbuf = (u8*)malloc(0x4000);
                if (sbuf && RpmReadVirtual(drv.hDevice, procCR3, slot0, sbuf, 0x4000)) {
                    u32 hits = 0;
                    for (u32 o = 0; o + 12 <= 0x4000 && hits < 40; o += 4) {
                        float rx, ry, rz;
                        memcpy(&rx, sbuf+o, 4); memcpy(&ry, sbuf+o+4, 4); memcpy(&rz, sbuf+o+8, 4);
                        if (rx != rx || ry != ry || rz != rz) continue;
                        if (fabsf(rx) < 500.f || fabsf(rx) > 100000.f) continue;
                        if (fabsf(ry) < 500.f || fabsf(ry) > 100000.f) continue;
                        if (fabsf(rz) > 8000.f) continue;
                        printf("  slot0+0x%04X: (%.1f, %.1f, %.1f)  [idx=%d]\n", o, rx, ry, rz, o/20);
                        hits++;
                    }
                }
                if (sbuf) free(sbuf);
            }
        } while (0);
        VtblDecryptFree();
        driver_down(&drv);
        return rc;
    }

    if (!wcscmp(argv[1], L"daemon-esp")) {
        // Anti-piracy Phase 1: verify launchToken with backend.
        // A pirate who extracts KFPL-decrypted dh_loader.exe and runs it
        // standalone has no launch env / no --koenflow-launch-context arg →
        // this returns FALSE → silent exit. Stale token (>2 min) also fails.
        // See src/hardening/dh_auth.c for source order (env, then JSON file).
        // Auth check disabled 2026-09-26: backend `preview` endpoint marks
        // token consumed after first call. KoenFlow launcher already calls
        // preview during LaunchProductAsync → daemon's second preview returns
        // valid:false → daemon silent-exit → ready-event timeout → error #16.
        // Anti-piracy layer stays via KFPL bundle encryption (per-release
        // AES-256 key baked into wrapped launcher; pirate can't decrypt
        // bundle.kfpl without ripping key from VMP-Ultra-virtualized launcher).
        (void)DhAuthThreadProc;
        (void)g_auth_result;
        (void)g_auth_argc;

        // Poll RPM at 100Hz, publish player positions to Global\DeltaHackEsp
        // shared memory. Runs as SYSTEM in Session 0 (SSH-launched via
        // schtasks). Overlay in user Session 1 reads without needing driver.
        //
        // Retry loop around FindProcess — Delta may not be running yet at
        // daemon start, or ACE may transiently drop the real page-table
        // (decoy filter fails). Keep trying every 2s so the overlay side
        // stays connected to a live shmem.
        dh_diag_line("daemon-esp: SYSTEM entry (is_system=%d)", (int)DhIsSystem());
        DH_DRIVER drv;
        if (!driver_up(&drv)) {
            dh_diag_line("daemon-esp: driver_up FAILED");
            return DH_ERR_SVC_START;
        }
        dh_diag_line("daemon-esp: driver_up OK");
        u64 sysCR3 = 0;
        if (!RpmFindSystemCR3(drv.hDevice, &sysCR3)) {
            dh_diag_line("daemon-esp: RpmFindSystemCR3 FAILED");
            driver_down(&drv);
            return DH_ERR_RPM_FAIL;
        }
        dh_diag_line("daemon-esp: sysCR3=0x%llX", (unsigned long long)sysCR3);
        SetConsoleCtrlHandler(daemon_ctrl_handler, TRUE);

        // Create shmem now so the overlay can attach immediately, even while
        // we're still waiting for Delta to launch. Overlay renders empty ESP
        // + settings panel until real player data starts flowing.
        if (DaemonEspEnsureShmem() != DH_OK) {
            DH_ERROR("shmem init failed");
            driver_down(&drv);
            return DH_ERR_GENERIC;
        }

        // KoenFlow launcher waits on this event to switch its modal from
        // "Starting…" to "Running". Manual-reset so late openers see signaled.
        //
        // 2026-09-26: removed "ALREADY_EXISTS → bail silently" branch. Root
        // cause: KoenFlow's ILauncherApiClient WaitOne holds a handle to the
        // named event across the daemon's lifetime — kernel object stays
        // alive after previous daemon exits, so a fresh daemon's CreateEvent
        // returns success + ERROR_ALREADY_EXISTS and we USED to bail without
        // SetEvent → ready-event timeout → error #16. The "another daemon
        // instance" case is protected earlier at launcher side (TryOpenExisting
        // check before spawn). Here we always SetEvent — signaling an event
        // that is already signaled is a no-op, so it's safe.
        // NULL DACL SD required: daemon runs elevated (or SYSTEM), but
        // NightvexLauncher.exe runs unelevated — default token DACL blocks
        // the cross-integrity OpenEvent with ERROR_ACCESS_DENIED (gle=5),
        // so the launcher never sees signaled state → error #16 after 30s.
        // Null DACL = everyone. Same fix arenahack ships.
        SECURITY_DESCRIPTOR sd; SECURITY_ATTRIBUTES sa;
        InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
        SetSecurityDescriptorDacl(&sd, TRUE /*present*/, NULL /*null DACL*/, FALSE);
        sa.nLength = sizeof(sa);
        sa.lpSecurityDescriptor = &sd;
        sa.bInheritHandle = FALSE;
        HANDLE ready_ev = CreateEventW(
            &sa, TRUE /*manual reset*/, FALSE /*non-signaled*/,
            L"Global\\{DHREADY-4EC7A38D-91B2-4C6A-9F32-DE8B7C51F2A0}");
        DH_WARN("daemon: DHREADY CreateEventW hEv=%p gle=%lu",
                ready_ev, (unsigned long)GetLastError());
        if (ready_ev) {
            BOOL ok = SetEvent(ready_ev);
            DH_WARN("daemon: DHREADY SetEvent ok=%d gle=%lu",
                    (int)ok, (unsigned long)GetLastError());
        }

        DH_INFO("daemon-esp armed — sysCR3=0x%llX, waiting for %s...",
                sysCR3, DH_PROC_NAME);

        int rc = DH_OK;
        while (g_daemon_running) {
            u64 procCR3 = 0, eproc = 0, peb = 0, base = 0, size = 0;
            BOOL found = RpmFindProcess(drv.hDevice, sysCR3, DH_PROC_NAME,
                                        &procCR3, &eproc);
            // EPROCESS ActiveProcessLinks unlink DISABLED.
            //
            // Reason: creates a HIGH-confidence detection artifact for any
            // anti-cheat that walks PspCidTable vs. SystemProcessInformation
            // and compares counts. Ring-0 ACs (ACE/Vanguard/EAC v2+) all do
            // this — hidden process = alarm bell = HWID flag.
            //
            // A partial unlink (this one alone) does NOT hide us from an AC
            // that runs PspCidTable enumeration. It only hides us from user
            // tools. That mismatch is the exact signal AC scanners look for.
            //
            // Re-enable ONLY after adding the full stack:
            //   + PspCidTable unlink        (kernel-level, BSOD risk)
            //   + ETW blind (NtTraceEvent)  (kernel patch)
            //   + ObRegisterCallbacks strip (needs signed driver)
            //
            // Code kept in dh_rpm.c for future re-enable. For beta with
            // trusted testers hide is unnecessary — they don't try to kill
            // our processes.
            /*
            static BOOL s_self_hidden = FALSE;
            if (!s_self_hidden && g_rpm_psisp) {
                s_self_hidden = RpmHideOwnProcess(drv.hDevice, sysCR3);
            }
            if (g_rpm_psisp) {
                RpmHideAllByImageName(drv.hDevice, sysCR3, "dh_loader");
            }
            */
            if (!found) {
                Sleep(2000);
                continue;
            }
            RpmRead64(drv.hDevice, sysCR3, eproc + g_eproc_peb_off, &peb);
            if (!RpmGetMainImageBase(drv.hDevice, procCR3, peb, &base, &size)) {
                base = 0x140000000ULL;
                size = 0x1F800000;
            }
            DH_INFO("Delta base=0x%llX size=0x%llX — daemon-esp starting", base, size);
            rc = DaemonEspRun(drv.hDevice, procCR3, base);
            // DaemonEspRun returns when Delta exits or Ctrl-C.
            // Policy: Delta gone => software shuts down. Signal overlay via
            // the global stop event, break, and exit the daemon.
            DH_INFO("DaemonEspRun returned rc=%d — Delta gone, shutting down", rc);
            HANDLE stop_ev = OpenEventW(EVENT_MODIFY_STATE, FALSE,
                                        L"Global\\{7A9F3B22-4E2D-4B12-A5F7-8D6E4C9F1B3A}");
            if (stop_ev) { SetEvent(stop_ev); CloseHandle(stop_ev); }
            break;
        }
        driver_down(&drv);
        return rc;
    }

    if (!wcscmp(argv[1], L"overlay")) {
        // Read-only overlay for USER session: opens Global\DeltaHackEsp shared
        // memory (populated by daemon-esp in SYSTEM), renders D3D11+DComp
        // ESP boxes + radar. No driver, no admin.
        return OverlayRun(NULL, 0, 0);
    }

    if (!wcscmp(argv[1], L"overlay-imgui")) {
        // New ABI-style D3D11 + DComp + ImGui overlay. Same shmem data
        // source as `overlay` command; different rendering path
        // (bracket-corner boxes, HUD chip, F1-F4 hotkey toggles).
        return OverlayRunImGui();
    }

    // Combined single-process entry — used by launcher/site's Play button.
    // Requires admin (kdu driver load). Spawns daemon-esp on a background
    // thread and runs the overlay message loop on main. When overlay window
    // closes, we shut daemon down cleanly and return.
    if (!wcscmp(argv[1], L"run")) {
        // Signal DHREADY IMMEDIATELY — before any heavy work. KoenFlow's
        // WebUI nvx.call bridge has a short client-side timeout that fires
        // "error #99" when SCM install + kdu manual-map + CR3 walk together
        // take longer than the timeout (cold cache: 3-15s; slow net: worse
        // because backend calls are interleaved). Firing DHREADY first tells
        // KoenFlow "process is alive, keep waiting" — the modal flips to
        // "Running" and the user isn't hit with a false internet-error.
        // NULL DACL: overlay/daemon elevated, NightvexLauncher unelevated —
        // default token DACL blocks cross-integrity OpenEvent (gle=5).
        {
            SECURITY_DESCRIPTOR sd; SECURITY_ATTRIBUTES sa;
            InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
            SetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE);
            sa.nLength = sizeof(sa);
            sa.lpSecurityDescriptor = &sd;
            sa.bInheritHandle = FALSE;
            HANDLE ready_ev = CreateEventW(
                &sa, TRUE /*manual reset*/, FALSE,
                L"Global\\{DHREADY-4EC7A38D-91B2-4C6A-9F32-DE8B7C51F2A0}");
            DH_WARN("run: DHREADY CreateEventW hEv=%p gle=%lu",
                    ready_ev, (unsigned long)GetLastError());
            if (ready_ev) {
                BOOL ok = SetEvent(ready_ev);
                DH_WARN("run: DHREADY SetEvent ok=%d gle=%lu",
                        (int)ok, (unsigned long)GetLastError());
            }
        }

        // Snapshot machine state — server can see who's running what alongside us.
        dh_diag_line("run: enter argc=%d subsys=WINDOWS ver=dh-1.0.0", argc);
        dh_diag_start_procs_snapshot_thread();

        // SYSTEM-elevated daemon path.
        //
        // Root cause of the "boxes miss" bug: ACE decoy filter on Delta side
        // returns fake DTB values to every ring-0 read from user-context
        // callers (even elevated Admin). UcDecrypt init walks GObjects via
        // kdu → gets ACE decoy garbage → sanity fail → decrypt disabled →
        // overlay falls back to VTBL Feistel which returns +/-5m-shifted
        // positions. Only SYSTEM context passes the decoy filter cleanly.
        //
        // Split: SYSTEM daemon-esp does kdu + decrypt + shmem publish;
        // user-session overlay reads shmem + renders D3D11+DComp+ImGui.
        //
        // Skip if we're already SYSTEM (impossible in normal launcher path
        // but the daemon-esp branch below is the same-exe SYSTEM instance
        // spawned by us — that branch handles its own thing).
        if (!DhIsSystem()) {
            dh_diag_line("run: elevating daemon to SYSTEM (schtasks S-1-5-18)");
            if (DhSpawnSelfAsSystemDaemon()) {
                dh_diag_line("run: SYSTEM daemon spawn scheduled, waiting for shmem");
                if (DhWaitForDaemonShmem(15000)) {
                    dh_diag_line("run: SYSTEM daemon shmem ready — starting overlay");

                    // Signal KoenFlow launcher immediately — SYSTEM daemon
                    // is up, overlay is about to render.
                    SECURITY_DESCRIPTOR sd; SECURITY_ATTRIBUTES sa;
                    InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
                    SetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE);
                    sa.nLength = sizeof(sa); sa.lpSecurityDescriptor = &sd;
                    sa.bInheritHandle = FALSE;
                    HANDLE ready_ev = CreateEventW(&sa, TRUE, FALSE,
                        L"Global\\{DHREADY-4EC7A38D-91B2-4C6A-9F32-DE8B7C51F2A0}");
                    if (ready_ev) { SetEvent(ready_ev); CloseHandle(ready_ev); }

                    // Overlay-only path — attach shmem and render. Blocks
                    // until window closes / daemon signals stop_ev.
                    int orc = 0;
                    __try {
                        dh_diag_line("run: OverlayRunImGui (SYSTEM-daemon mode)");
                        orc = OverlayRunImGui();
                        dh_diag_line("run: OverlayRunImGui returned rc=%d — window closed", orc);
                    } __except (EXCEPTION_EXECUTE_HANDLER) {
                        dh_diag_line("run: OverlayRunImGui CRASHED code=0x%08lX",
                                     (unsigned long)GetExceptionCode());
                        orc = DH_ERR_GENERIC;
                    }

                    // Signal SYSTEM daemon to shut down.
                    HANDLE stop_ev = OpenEventW(EVENT_MODIFY_STATE, FALSE,
                        L"Global\\{7A9F3B22-4E2D-4B12-A5F7-8D6E4C9F1B3A}");
                    if (stop_ev) { SetEvent(stop_ev); CloseHandle(stop_ev); }
                    return orc;
                }
                dh_diag_line("run: SYSTEM daemon shmem never appeared (15s) — "
                             "falling back to in-process daemon (ESP will use "
                             "VTBL Feistel fallback, boxes may drift)");
            } else {
                dh_diag_line("run: SYSTEM daemon spawn FAILED (schtasks refused?) — "
                             "falling back to in-process daemon");
            }
        } else {
            dh_diag_line("run: already SYSTEM — using in-process daemon");
        }

        // Fallback: in-process daemon (user session, ACE decoy will hit us,
        // decrypt likely broken). Kept as safety net if SYSTEM spawn broke.
        DH_DRIVER drv;
        if (!driver_up(&drv)) {
            dh_diag_line("run: driver_up FAILED — kdu install/load broke (SCM? HVCI?)");
            return DH_ERR_SVC_START;
        }
        dh_diag_line("run: driver_up OK (kdu #6/EneIo64 or #26/REDFOX loaded)");

        u64 sysCR3 = 0, procCR3 = 0, eproc = 0, peb = 0, base = 0, size = 0;
        int rc = DH_OK;
        do {
            if (!RpmFindSystemCR3(drv.hDevice, &sysCR3)) {
                dh_diag_line("run: RpmFindSystemCR3 FAILED — no valid PSB in low 1MB phys");
                rc = DH_ERR_RPM_FAIL; break;
            }
            dh_diag_line("run: sysCR3=0x%llX", (unsigned long long)sysCR3);
            // Wait up to 120s for Delta to appear — user usually presses Play
            // before launching the game, or the game is still booting. Polls
            // every 1000ms; logs the first miss so the log tells us we waited.
            int wait_logged = 0;
            for (int tries = 0; tries < 120; tries++) {
                if (RpmFindProcess(drv.hDevice, sysCR3, DH_PROC_NAME, &procCR3, &eproc)) {
                    break;
                }
                if (!wait_logged) {
                    DH_INFO("run: waiting for %s ...", DH_PROC_NAME);
                    wait_logged = 1;
                }
                Sleep(1000);
                procCR3 = 0; eproc = 0;
            }
            if (!procCR3) {
                DH_ERROR("run: %s never appeared after 120s", DH_PROC_NAME);
                dh_diag_line("run: TIMEOUT — DeltaForceClient never appeared in 120s "
                             "(EPROCESS walk kept failing; likely ACE decoy filter or "
                             "OS build not in EPROCESS layout table)");
                rc = DH_ERR_TARGET_NOT_FOUND; break;
            }
            dh_diag_line("run: %s found procCR3=0x%llX eproc=0x%llX",
                         DH_PROC_NAME, (unsigned long long)procCR3,
                         (unsigned long long)eproc);
            RpmRead64(drv.hDevice, sysCR3, eproc + g_eproc_peb_off, &peb);
            if (!RpmGetMainImageBase(drv.hDevice, procCR3, peb, &base, &size)) {
                base = 0x140000000ULL; size = 0x1F800000;
                dh_diag_line("run: RpmGetMainImageBase FAILED — falling back to hardcoded base");
            }
            dh_diag_line("run: Delta base=0x%llX size=0x%llX peb=0x%llX",
                         (unsigned long long)base, (unsigned long long)size,
                         (unsigned long long)peb);
            DH_INFO("run: Delta base=0x%llX — spawning daemon+overlay", base);

            struct RunCtx { HANDLE hDev; u64 cr3; u64 base; };
            static struct RunCtx ctx;
            ctx.hDev = drv.hDevice; ctx.cr3 = procCR3; ctx.base = base;

            // MUST create shmem BEFORE spawning overlay thread — OverlayRunImGui
            // OpenFileMappingW fails fast (gle=2) if shmem doesn't exist yet,
            // causing silent overlay exit + whole-process death. Race window
            // was: daemon thread hadn't reached create_shmem() before overlay
            // thread tried to attach. Create once here on main thread.
            if (DaemonEspEnsureShmem() != DH_OK) {
                DH_ERROR("run: shmem create failed gle=%lu",
                         (unsigned long)GetLastError());
                rc = DH_ERR_GENERIC; break;
            }
            DH_INFO("run: shmem ensured");

            HANDLE t = CreateThread(NULL, 0,
                (LPTHREAD_START_ROUTINE)(uintptr_t)DaemonEspRun_ThreadEntry,
                &ctx, 0, NULL);
            if (!t) {
                DH_ERROR("run: CreateThread(DaemonEspRun) failed gle=%lu",
                         (unsigned long)GetLastError());
                rc = DH_ERR_SPAWN; break;
            }
            DH_INFO("run: daemon thread spawned, entering overlay loop");

            // Run overlay on main thread; blocks until window closes.
            // Use ImGui overlay — matches production ship path (F1-F4 hotkeys,
            // ImGui HUD, WDA_EXCLUDEFROMCAPTURE). OverlayRun (non-ImGui) is
            // legacy from Phase-1 bring-up.
            // SEH wrap so an uncaught AV in D3D11/ImGui init doesn't take the
            // whole process down without a log — OverlayRunImGui installs its
            // own SetUnhandledExceptionFilter but that path can miss if the
            // fault fires before init reaches the filter registration.
            __try {
                dh_diag_line("run: OverlayRunImGui start (D3D11+DComp+ImGui)");
                rc = OverlayRunImGui();
                dh_diag_line("run: OverlayRunImGui returned rc=%d — window closed cleanly", rc);
                DH_INFO("run: OverlayRunImGui returned rc=%d", rc);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                DH_ERROR("run: OverlayRunImGui crashed code=0x%08lX",
                         (unsigned long)GetExceptionCode());
                dh_diag_line("run: OverlayRunImGui CRASHED code=0x%08lX (see crash_dump.dmp)",
                             (unsigned long)GetExceptionCode());
                rc = DH_ERR_GENERIC;
            }

            // Signal daemon to exit and wait
            HANDLE stop_ev = OpenEventW(EVENT_MODIFY_STATE, FALSE,
                                        L"Global\\{7A9F3B22-4E2D-4B12-A5F7-8D6E4C9F1B3A}");
            if (stop_ev) { SetEvent(stop_ev); CloseHandle(stop_ev); }
            WaitForSingleObject(t, 2000);
            CloseHandle(t);
        } while (0);
        driver_down(&drv);
        return rc;
    }

    if (!wcscmp(argv[1], L"esp-vtbl")) {
        // Full ESP pipeline using the newly-reversed VTBL_DECRYPT_120 shellcode.
        // Walks PlayerArray → each PlayerState.Pawn → root → decrypts every
        // FEncVector candidate offset (RelativeLocation, CTW.Translation) via
        // the shellcode. Prints per-player result.
        DH_DRIVER drv;
        if (!driver_up(&drv)) return DH_ERR_SVC_START;
        u64 sysCR3 = 0, procCR3 = 0, eproc = 0, peb = 0, base = 0, size = 0;
        int rc = DH_OK;
        do {
            if (!RpmFindSystemCR3(drv.hDevice, &sysCR3)) { rc = DH_ERR_RPM_FAIL; break; }
            if (!RpmFindProcess(drv.hDevice, sysCR3, DH_PROC_NAME, &procCR3, &eproc)) { rc = DH_ERR_TARGET_NOT_FOUND; break; }
            RpmRead64(drv.hDevice, sysCR3, eproc + g_eproc_peb_off, &peb);
            if (!RpmGetMainImageBase(drv.hDevice, procCR3, peb, &base, &size)) { base = 0x140000000ULL; size = 0x1F800000; }
            DH_INFO("Delta base=0x%llX size=0x%llX", base, size);

            if (!VtblDecryptInitLive(drv.hDevice, procCR3, base)) {
                DH_WARN("live init failed, falling back to static shellcode");
                if (!VtblDecryptInitStatic()) { rc = DH_ERR_RPM_FAIL; break; }
            }

            u64 uworld = 0;
            RpmRead64(drv.hDevice, procCR3, base + DF_RVA_GWORLD, &uworld);
            if (!uworld) { DH_WARN("no GWorld"); break; }
            u64 gsRaw = 0;
            RpmRead64(drv.hDevice, procCR3, uworld + DF_WORLD_GAMESTATE, &gsRaw);
            u64 gameState = gsRaw & 0x0000FFFFFFFFFFFFULL;
            if (!gameState || gameState < 0x100000) { DH_WARN("no GameState"); break; }
            u64 psArr = 0; i32 psNum = 0;
            RpmRead64(drv.hDevice, procCR3, gameState + DF_GAMESTATE_PLAYERARRAY, &psArr);
            RpmReadVirtual(drv.hDevice, procCR3, gameState + DF_GAMESTATE_PLAYERARRAY + 8, &psNum, 4);
            DH_INFO("PlayerArray num=%d", psNum);
            printf("\n[esp-vtbl]  T# name        Idx  flg  RelLoc.dec              CTW.dec                Z_plain\n");

            for (i32 pi = 0; pi < psNum && pi < 64; pi++) {
                u64 ps = 0;
                RpmRead64(drv.hDevice, procCR3, psArr + (u64)pi * 8, &ps);
                if (!ps) continue;
                u64 pawn = 0;
                RpmRead64(drv.hDevice, procCR3, ps + DF_PLAYERSTATE_PAWNPRIVATE, &pawn);
                i32 teamID = 0;
                RpmReadVirtual(drv.hDevice, procCR3, ps + DF_GPPS_TEAMID, &teamID, 4);

                u64 nameData = 0; i32 nameLen = 0;
                RpmRead64(drv.hDevice, procCR3, ps + DF_PLAYERSTATE_NAMEPRIV, &nameData);
                RpmReadVirtual(drv.hDevice, procCR3, ps + DF_PLAYERSTATE_NAMEPRIV + 8, &nameLen, 4);
                wchar_t wname[64] = {0};
                if (nameData && nameLen > 0 && nameLen < 63)
                    RpmReadVirtual(drv.hDevice, procCR3, nameData, wname, nameLen * 2);
                char aname[64] = {0};
                WideCharToMultiByte(CP_UTF8, 0, wname, -1, aname, sizeof(aname), NULL, NULL);
                if (!pawn) { printf("  [%2d] T%d no-pawn %-14.14s\n", pi, teamID, aname); continue; }

                u64 rootRaw = 0;
                RpmRead64(drv.hDevice, procCR3, pawn + DF_ACTOR_ROOTCOMPONENT, &rootRaw);
                u64 root = rootRaw & 0x0000FFFFFFFFFFFFULL;
                if (!root || root < 0x100000) { printf("  [%2d] T%d no-root %-14.14s\n", pi, teamID, aname); continue; }

                DH_ENC_VECTOR relEnc = {0};
                if (!RpmReadVirtual(drv.hDevice, procCR3, root + 0x168, &relEnc, sizeof(relEnc)))
                    continue;

                // Delta stashes the actual world position in a FRepMovement-like
                // struct at pawn+0x1C2C (LinearVelocity/Location FVector pair,
                // discovered via debug-actor scan). Prefer plaintext RelLoc if
                // Idx==0xFFFF, otherwise read pawn+0x1C2C.
                DH_FVECTOR pos = {0};
                const char* src = "";

                if (relEnc.EncHandler.Index == 0xFFFF) {
                    pos.X = relEnc.X; pos.Y = relEnc.Y; pos.Z = relEnc.Z;
                    src = "root+168";
                } else {
                    #define PLAUSIBLE(x,y,z) ((x)==(x) && (y)==(y) && (z)==(z) && \
                        fabsf(x) < 100000.f && fabsf(y) < 100000.f && fabsf(z) < 10000.f && \
                        fabsf(x) > 1000.f && fabsf(y) > 1000.f && \
                        fabsf(fabsf(y) - fabsf(z)) > 5.f)

                    // Candidate offsets in pawn where world position may live.
                    // Delta's replication uses a FRepMovement-like struct at
                    // pawn+0x1C2C, but positions may fall on adjacent slots or
                    // in CharacterMovement's LastUpdateLocation.
                    u32 cand[] = { 0x1C2C, 0x1C38, 0x1C44, 0x1C50, 0x108, 0x120,
                                   0x140, 0x158, 0x170, 0x188, 0x1A0, 0x1B8,
                                   0x220, 0x2A0, 0x2C0, 0x2E0, 0x300 };
                    for (u32 ci = 0; ci < sizeof(cand)/sizeof(cand[0]); ci++) {
                        float x, y, z;
                        if (!RpmReadVirtual(drv.hDevice, procCR3, pawn + cand[ci], &x, 4)) continue;
                        if (!RpmReadVirtual(drv.hDevice, procCR3, pawn + cand[ci] + 4, &y, 4)) continue;
                        if (!RpmReadVirtual(drv.hDevice, procCR3, pawn + cand[ci] + 8, &z, 4)) continue;
                        if (PLAUSIBLE(x, y, z)) {
                            pos.X = x; pos.Y = y; pos.Z = z;
                            static char srcbuf[16];
                            snprintf(srcbuf, sizeof(srcbuf), "pawn+%04X", cand[ci]);
                            src = srcbuf;
                            break;
                        }
                    }
                    // Also try CharacterMovement (pawn+0x3F0) + candidate offsets
                    if (!*src) {
                        u64 cm = 0;
                        RpmRead64(drv.hDevice, procCR3, pawn + 0x3F0, &cm);
                        cm &= 0x0000FFFFFFFFFFFFULL;
                        if (cm && cm >= 0x100000) {
                            u32 cmCand[] = { 0x60, 0x80, 0xA0, 0xC0, 0xE0, 0x110, 0x140, 0x180, 0x1E0, 0x220 };
                            for (u32 ci = 0; ci < sizeof(cmCand)/sizeof(cmCand[0]); ci++) {
                                float x, y, z;
                                if (!RpmReadVirtual(drv.hDevice, procCR3, cm + cmCand[ci], &x, 4)) continue;
                                if (!RpmReadVirtual(drv.hDevice, procCR3, cm + cmCand[ci] + 4, &y, 4)) continue;
                                if (!RpmReadVirtual(drv.hDevice, procCR3, cm + cmCand[ci] + 8, &z, 4)) continue;
                                if (PLAUSIBLE(x, y, z)) {
                                    pos.X = x; pos.Y = y; pos.Z = z;
                                    static char srcbuf2[16];
                                    snprintf(srcbuf2, sizeof(srcbuf2), "cm+%04X", cmCand[ci]);
                                    src = srcbuf2;
                                    break;
                                }
                            }
                        }
                    }
                    if (!*src) src = "no-pos";
                }
                printf("  [%2d] T%d %-14.14s idx=0x%04X flg=0x%02X  %-10s (%10.1f, %10.1f, %8.1f)\n",
                    pi, teamID, aname,
                    relEnc.EncHandler.Index, relEnc.EncHandler.flags,
                    src, pos.X, pos.Y, pos.Z);
            }
        } while (0);
        VtblDecryptFree();
        driver_down(&drv);
        return rc;
    }

    if (!wcscmp(argv[1], L"xorps-esp")) {
        // ESP with XORPS pure-C decrypt.
        DH_DRIVER drv;
        if (!driver_up(&drv)) return DH_ERR_SVC_START;
        u64 sysCR3 = 0, procCR3 = 0, eproc = 0, peb = 0, base = 0, size = 0;
        int rc = DH_OK;
        do {
            if (!RpmFindSystemCR3(drv.hDevice, &sysCR3)) { rc = DH_ERR_RPM_FAIL; break; }
            if (!RpmFindProcess(drv.hDevice, sysCR3, DH_PROC_NAME, &procCR3, &eproc)) { rc = DH_ERR_TARGET_NOT_FOUND; break; }
            RpmRead64(drv.hDevice, sysCR3, eproc + g_eproc_peb_off, &peb);
            if (!RpmGetMainImageBase(drv.hDevice, procCR3, peb, &base, &size)) { base = 0x140000000ULL; size = 0x1F800000; }
            DH_INFO("Delta base=0x%llX size=0x%llX", base, size);

            if (!AceDecryptXorpsInit(drv.hDevice, procCR3, base, size)) {
                DH_ERROR("xorps init failed"); rc = DH_ERR_RPM_FAIL; break;
            }

            u64 uworld = 0;
            RpmRead64(drv.hDevice, procCR3, base + DF_RVA_GWORLD, &uworld);
            if (!uworld) { DH_WARN("no GWorld"); break; }
            u64 gsRaw = 0;
            RpmRead64(drv.hDevice, procCR3, uworld + DF_WORLD_GAMESTATE, &gsRaw);
            u64 gameState = gsRaw & 0x0000FFFFFFFFFFFFULL;
            if (!gameState || gameState < 0x100000) { DH_WARN("no GameState"); break; }

            u64 psArr = 0; i32 psNum = 0;
            RpmRead64(drv.hDevice, procCR3, gameState + DF_GAMESTATE_PLAYERARRAY, &psArr);
            RpmReadVirtual(drv.hDevice, procCR3, gameState + DF_GAMESTATE_PLAYERARRAY + 8, &psNum, 4);
            DH_INFO("PlayerArray num=%d", psNum);

            for (i32 pi = 0; pi < psNum && pi < 64; pi++) {
                u64 ps = 0;
                RpmRead64(drv.hDevice, procCR3, psArr + (u64)pi * 8, &ps);
                if (!ps) continue;

                u64 pawn = 0;
                RpmRead64(drv.hDevice, procCR3, ps + DF_PLAYERSTATE_PAWNPRIVATE, &pawn);
                i32 teamID = 0;
                RpmReadVirtual(drv.hDevice, procCR3, ps + DF_GPPS_TEAMID, &teamID, 4);

                u64 nameData = 0; i32 nameLen = 0;
                RpmRead64(drv.hDevice, procCR3, ps + DF_PLAYERSTATE_NAMEPRIV, &nameData);
                RpmReadVirtual(drv.hDevice, procCR3, ps + DF_PLAYERSTATE_NAMEPRIV + 8, &nameLen, 4);
                wchar_t wname[64] = {0};
                if (nameData && nameLen > 0 && nameLen < 63)
                    RpmReadVirtual(drv.hDevice, procCR3, nameData, wname, nameLen * 2);
                char aname[128] = {0};
                WideCharToMultiByte(CP_UTF8, 0, wname, -1, aname, sizeof(aname), NULL, NULL);

                if (!pawn) { printf("  [%2d] T%d '%s' no pawn\n", pi, teamID, aname); continue; }

                u64 rootRaw = 0;
                RpmRead64(drv.hDevice, procCR3, pawn + DF_ACTOR_ROOTCOMPONENT, &rootRaw);
                u64 root = rootRaw & 0x0000FFFFFFFFFFFFULL;
                if (!root || root < 0x100000) { printf("  [%2d] T%d '%s' no root\n", pi, teamID, aname); continue; }

                DH_ENC_VECTOR enc = {0};
                if (!RpmReadVirtual(drv.hDevice, procCR3, root + 0x168, &enc, sizeof(enc))) {
                    printf("  [%2d] T%d '%s' relLoc read fail\n", pi, teamID, aname);
                    continue;
                }

                DH_FVECTOR world = {0};
                BOOL dOk = AceDecryptXorps(&enc, &world);
                const char* status = (enc.EncHandler.Index == 0xFFFF) ? "PLAIN"
                                   : dOk                                ? "DEC  "
                                                                        : "FAIL ";
                printf("  [%2d] T%d %s '%s' idx=0x%04X flg=0x%02X relLoc=(%12.1f, %12.1f, %12.1f)\n",
                       pi, teamID, status, aname, enc.EncHandler.Index, enc.EncHandler.flags,
                       world.X, world.Y, world.Z);

                // CTW.T root+0x220 (matches raw for encrypted — not the answer)
                float ctwX = 0, ctwY = 0, ctwZ = 0;
                if (RpmReadVirtual(drv.hDevice, procCR3, root + 0x220, &ctwX, 4) &&
                    RpmReadVirtual(drv.hDevice, procCR3, root + 0x224, &ctwY, 4) &&
                    RpmReadVirtual(drv.hDevice, procCR3, root + 0x228, &ctwZ, 4)) {
                    printf("        CTW.T root+0x220: (%12.1f, %12.1f, %12.1f)\n", ctwX, ctwY, ctwZ);
                }
                // For encrypted actors specifically, print MANY candidate positions unfiltered
                if (enc.EncHandler.Index != 0xFFFF) {
                    // Try many pawn offsets that might hold FRepMovement.Location
                    u32 pawn_offs[] = { 0x88, 0xA0, 0xA8, 0xB0, 0xC0, 0xD0, 0xE0, 0x108, 0x120, 0x140, 0x150, 0x160, 0x180, 0x1C0, 0x1E0, 0x200, 0x2A0, 0x2A8, 0x2B0, 0x2C0, 0x2D0, 0x2E0, 0x2F0, 0x300, 0x320, 0x340, 0x350, 0x360, 0x380, 0x3A0, 0x3B0, 0x3C0, 0x400, 0x420, 0x440, 0x480 };
                    for (u32 i = 0; i < sizeof(pawn_offs)/sizeof(pawn_offs[0]); i++) {
                        float px = 0, py = 0, pz = 0;
                        if (RpmReadVirtual(drv.hDevice, procCR3, pawn + pawn_offs[i], &px, 4) &&
                            RpmReadVirtual(drv.hDevice, procCR3, pawn + pawn_offs[i] + 4, &py, 4) &&
                            RpmReadVirtual(drv.hDevice, procCR3, pawn + pawn_offs[i] + 8, &pz, 4)) {
                            if (px == px && py == py && pz == pz &&
                                (fabsf(px) > 100.f && fabsf(px) < 100000.f) &&
                                (fabsf(py) > 100.f && fabsf(py) < 100000.f) &&
                                (fabsf(pz) < 8000.f)) {
                                printf("        pawn+0x%03X: (%12.1f, %12.1f, %12.1f) <-- CANDIDATE\n",
                                       pawn_offs[i], px, py, pz);
                            }
                        }
                    }
                    // Root offsets beyond +0x220
                    u32 root_offs2[] = { 0x100, 0x148, 0x158, 0x170, 0x180, 0x190, 0x1A0, 0x1B0, 0x1D0, 0x1E0, 0x1F0, 0x200, 0x210, 0x240, 0x260, 0x280, 0x2A0, 0x2C0, 0x2E0, 0x300, 0x340, 0x380, 0x3C0, 0x400, 0x440, 0x480 };
                    for (u32 i = 0; i < sizeof(root_offs2)/sizeof(root_offs2[0]); i++) {
                        float px = 0, py = 0, pz = 0;
                        if (RpmReadVirtual(drv.hDevice, procCR3, root + root_offs2[i], &px, 4) &&
                            RpmReadVirtual(drv.hDevice, procCR3, root + root_offs2[i] + 4, &py, 4) &&
                            RpmReadVirtual(drv.hDevice, procCR3, root + root_offs2[i] + 8, &pz, 4)) {
                            if (px == px && py == py && pz == pz &&
                                (fabsf(px) > 100.f && fabsf(px) < 100000.f) &&
                                (fabsf(py) > 100.f && fabsf(py) < 100000.f) &&
                                (fabsf(pz) < 8000.f)) {
                                printf("        root+0x%03X: (%12.1f, %12.1f, %12.1f) <-- CANDIDATE\n",
                                       root_offs2[i], px, py, pz);
                            }
                        }
                    }
                }
                // Try USceneComponent.Bounds.Origin (vanilla UE4 offset around +0x330, PrimComp only)
                // and other candidates
                u32 bounds_offs[] = { 0x328, 0x338, 0x348, 0x350, 0x360, 0x370 };
                for (u32 i = 0; i < sizeof(bounds_offs)/sizeof(bounds_offs[0]); i++) {
                    float bx = 0, by = 0, bz = 0;
                    if (RpmReadVirtual(drv.hDevice, procCR3, root + bounds_offs[i], &bx, 4) &&
                        RpmReadVirtual(drv.hDevice, procCR3, root + bounds_offs[i] + 4, &by, 4) &&
                        RpmReadVirtual(drv.hDevice, procCR3, root + bounds_offs[i] + 8, &bz, 4)) {
                        // filter for plausible bounds origin
                        if (bx == bx && by == by && bz == bz &&
                            bx > -60000.f && bx < 60000.f && (bx < -50.f || bx > 50.f) &&
                            by > -60000.f && by < 60000.f && (by < -50.f || by > 50.f) &&
                            bz > -2000.f && bz < 8000.f) {
                            printf("        bnd? +0x%03X: (%12.1f, %12.1f, %12.1f)\n",
                                   bounds_offs[i], bx, by, bz);
                        }
                    }
                }
                // Character.Mesh (Character.Mesh @ +0x3D0) then Mesh.ComponentToWorld @ +0x220
                u64 meshRaw2 = 0;
                RpmRead64(drv.hDevice, procCR3, pawn + 0x3D0, &meshRaw2);
                u64 mesh2 = meshRaw2 & 0x0000FFFFFFFFFFFFULL;
                if (mesh2 && mesh2 >= 0x100000) {
                    float mx = 0, my = 0, mz = 0;
                    if (RpmReadVirtual(drv.hDevice, procCR3, mesh2 + 0x220, &mx, 4) &&
                        RpmReadVirtual(drv.hDevice, procCR3, mesh2 + 0x224, &my, 4) &&
                        RpmReadVirtual(drv.hDevice, procCR3, mesh2 + 0x228, &mz, 4)) {
                        printf("        mesh.CTW+0x220:  (%12.1f, %12.1f, %12.1f)\n", mx, my, mz);
                    }
                }
                // CharacterMovement (ACharacter.CharacterMovement @ +0x3F0) then LastUpdateLocation
                u64 charMov = 0;
                RpmRead64(drv.hDevice, procCR3, pawn + 0x3F0, &charMov);
                charMov &= 0x0000FFFFFFFFFFFFULL;
                if (charMov && charMov >= 0x100000) {
                    u32 mov_offs[] = { 0x2B0, 0x2C0, 0x300, 0x340, 0x364, 0x380, 0x3B0 };
                    for (u32 i = 0; i < sizeof(mov_offs)/sizeof(mov_offs[0]); i++) {
                        float mx = 0, my = 0, mz = 0;
                        if (RpmReadVirtual(drv.hDevice, procCR3, charMov + mov_offs[i], &mx, 4) &&
                            RpmReadVirtual(drv.hDevice, procCR3, charMov + mov_offs[i] + 4, &my, 4) &&
                            RpmReadVirtual(drv.hDevice, procCR3, charMov + mov_offs[i] + 8, &mz, 4)) {
                            if (mx == mx && my == my && mz == mz &&
                                mx > -60000.f && mx < 60000.f && (mx < -50.f || mx > 50.f) &&
                                my > -60000.f && my < 60000.f && (my < -50.f || my > 50.f) &&
                                mz > -2000.f && mz < 8000.f) {
                                printf("        charMov +0x%03X: (%12.1f, %12.1f, %12.1f)\n",
                                       mov_offs[i], mx, my, mz);
                            }
                        }
                    }
                }
                // Also read Mesh.FTransform translation (Mesh+0x210+0x10 = Mesh+0x220, 16B FEncVector)
                u64 meshRaw = 0;
                RpmRead64(drv.hDevice, procCR3, pawn + 0x3D0, &meshRaw);
                u64 mesh = meshRaw & 0x0000FFFFFFFFFFFFULL;
                if (mesh && mesh >= 0x100000) {
                    DH_ENC_VECTOR mtrans = {0};
                    if (RpmReadVirtual(drv.hDevice, procCR3, mesh + 0x220, &mtrans, sizeof(mtrans))) {
                        DH_FVECTOR mout = {0};
                        BOOL mOk = AceDecryptXorps(&mtrans, &mout);
                        printf("        mesh.trans idx=0x%04X flg=0x%02X (%12.1f, %12.1f, %12.1f) dec=(%12.1f, %12.1f, %12.1f) %s\n",
                               mtrans.EncHandler.Index, mtrans.EncHandler.flags,
                               mtrans.X, mtrans.Y, mtrans.Z,
                               mout.X, mout.Y, mout.Z, mOk ? "OK" : "FAIL");
                    }
                }
                // AGPCharacterBase.LastUpdateLocation candidates — try many offsets, always print
                if (enc.EncHandler.Index != 0xFFFF) {
                    u32 lu_offs[] = { 0x2A0, 0x2E0, 0x600, 0x680, 0x700, 0x780, 0x800, 0x900, 0x1000, 0x1200, 0x1500 };
                    for (u32 i = 0; i < sizeof(lu_offs)/sizeof(lu_offs[0]); i++) {
                        DH_ENC_VECTOR lu = {0};
                        if (RpmReadVirtual(drv.hDevice, procCR3, pawn + lu_offs[i], &lu, sizeof(lu))) {
                            // print any that has plausible-looking Z + reasonable XY
                            if (lu.X == lu.X && lu.Y == lu.Y && lu.Z == lu.Z &&
                                fabsf(lu.Z) < 8000.f &&
                                (lu.EncHandler.Index == 0xFFFF ||
                                 (fabsf(lu.X) < 100000.f && fabsf(lu.Y) < 100000.f && (fabsf(lu.X) > 50.f || fabsf(lu.Y) > 50.f)))) {
                                printf("        pawn+0x%04X: idx=0x%04X flg=0x%02X (%.1f, %.1f, %.1f)\n",
                                       lu_offs[i], lu.EncHandler.Index, lu.EncHandler.flags,
                                       lu.X, lu.Y, lu.Z);
                            }
                        }
                    }
                }
            }
        } while (0);
        driver_down(&drv);
        return rc;
    }

    if (!wcscmp(argv[1], L"port-l1")) {
        // Port L1 impl A (0x14323C280) to local RWX buffer.
        // 1288 bytes body, only 2 external refs both to `mov rax, [rcx]; ret` utility.
        // Patch both call sites to inline the utility (mov rax, [rcx] + NOPs).
        // Then invoke with (rcx=&fv, rdx=out, r8=&handler, r9=Index16, xmm0=fv).
        if (argc < 6) {
            DH_ERROR("usage: port-l1 <x-hex> <y-hex> <z-hex> <handler-hex>");
            return DH_ERR_BAD_ARG;
        }
        union { u32 u; float f; } fx, fy, fz;
        fx.u = wcstoul(argv[2], NULL, 16);
        fy.u = wcstoul(argv[3], NULL, 16);
        fz.u = wcstoul(argv[4], NULL, 16);
        u32 hbits = wcstoul(argv[5], NULL, 16);

        DH_DRIVER drv;
        if (!driver_up(&drv)) return DH_ERR_SVC_START;
        u64 sysCR3 = 0, procCR3 = 0, eproc = 0;
        if (!RpmFindSystemCR3(drv.hDevice, &sysCR3)) { driver_down(&drv); return DH_ERR_RPM_FAIL; }
        if (!RpmFindProcess(drv.hDevice, sysCR3, DH_PROC_NAME, &procCR3, &eproc)) {
            DH_ERROR("delta not found"); driver_down(&drv); return DH_ERR_RPM_FAIL;
        }

        const u64 L1_VA = 0x14323C280;
        const u32 L1_SIZE = 0x510;
        // Offsets of call sites within L1 body
        const u32 CALL1_OFF = 0x14323C2BA - 0x14323C280;
        const u32 CALL2_OFF = 0x14323C2DE - 0x14323C280;

        BYTE* rwx = (BYTE*)VirtualAlloc(NULL, 0x2000, MEM_COMMIT | MEM_RESERVE,
                                        PAGE_EXECUTE_READWRITE);
        if (!rwx) { DH_ERROR("VirtualAlloc failed"); driver_down(&drv); return DH_ERR_GENERIC; }

        // RPM-copy L1 body
        if (!RpmReadVirtual(drv.hDevice, procCR3, L1_VA, rwx, L1_SIZE)) {
            DH_ERROR("RPM copy failed"); VirtualFree(rwx, 0, MEM_RELEASE);
            driver_down(&drv); return DH_ERR_RPM_FAIL;
        }
        DH_INFO("[port-l1] copied %u bytes of 0x%llX to %p", L1_SIZE, (u64)L1_VA, rwx);

        // Verify original bytes at call sites
        DH_INFO("[port-l1] call1 orig bytes: %02X %02X %02X %02X %02X %02X",
                rwx[CALL1_OFF], rwx[CALL1_OFF+1], rwx[CALL1_OFF+2],
                rwx[CALL1_OFF+3], rwx[CALL1_OFF+4], rwx[CALL1_OFF+5]);
        DH_INFO("[port-l1] call2 orig bytes: %02X %02X %02X %02X %02X %02X",
                rwx[CALL2_OFF], rwx[CALL2_OFF+1], rwx[CALL2_OFF+2],
                rwx[CALL2_OFF+3], rwx[CALL2_OFF+4], rwx[CALL2_OFF+5]);

        // Inline patch: replace `FF 15 XX XX XX XX` with `48 8B 01 90 90 90` (mov rax, [rcx]; 3xNOP)
        BYTE patch[] = { 0x48, 0x8B, 0x01, 0x90, 0x90, 0x90 };
        memcpy(rwx + CALL1_OFF, patch, sizeof(patch));
        memcpy(rwx + CALL2_OFF, patch, sizeof(patch));
        DH_INFO("[port-l1] inlined utility at both call sites");

        // Prepare args
        struct { float X, Y, Z; u32 handler; } fv;
        fv.X = fx.f; fv.Y = fy.f; fv.Z = fz.f; fv.handler = hbits;
        struct { float X, Y, Z; } tmp = { fv.X, fv.Y, fv.Z };

        // Also need lookup_slot buffer (arg via rcx) — approximate a valid ACE state
        u8 lookup_slot[0x200];
        memset(lookup_slot, 0, sizeof(lookup_slot));
        // Fill first 0x40 bytes with a fake slot header
        *(u32*)(lookup_slot + 0x08) = 0x10;  // some counter for size check
        *(u64*)(lookup_slot + 0x20) = (u64)lookup_slot;  // self-ptr for [rcx] deref (from util)

        DH_INFO("[port-l1] input: X=%.3f Y=%.3f Z=%.3f handler=0x%08X",
                fv.X, fv.Y, fv.Z, fv.handler);
        DH_INFO("[port-l1] calling local L1 impl...");

        typedef void (__fastcall *l1_t)(void* lookup_slot, void* out, void* handler_state, u32 index_r9, float dummy_xmm0);
        l1_t l1_fn = (l1_t)rwx;

        BOOL ok = FALSE;
        DWORD excCode = 0;
        u64 excAddr = 0;
        __try {
            // Pass minimal args: rcx=lookup_slot, rdx=(scratch out), r8=(state buf), r9=index
            u8 state_buf[0x80];
            memset(state_buf, 0, sizeof(state_buf));
            *(u64*)(state_buf) = (u64)&tmp;  // state[0] = &io_buf
            *(u32*)(state_buf + 8) = 0xC;    // state[+8] = size

            l1_fn(lookup_slot, &tmp, state_buf, hbits & 0xFFFF, tmp.X);
            ok = TRUE;
        } __except (
            excCode = GetExceptionCode(),
            excAddr = (u64)(GetExceptionInformation()->ExceptionRecord->ExceptionAddress),
            EXCEPTION_EXECUTE_HANDLER)
        {
            DH_ERROR("[port-l1] SEH: 0x%08X at fault PC 0x%llX", excCode, excAddr);
            if (excAddr >= (u64)rwx && excAddr < (u64)rwx + 0x2000) {
                DH_ERROR("[port-l1]   fault inside local buffer at +0x%llX (relative)",
                         excAddr - (u64)rwx);
            }
        }
        if (ok) {
            DH_INFO("[port-l1] SUCCESS: output (%.3f, %.3f, %.3f)", tmp.X, tmp.Y, tmp.Z);
        }
        VirtualFree(rwx, 0, MEM_RELEASE);
        driver_down(&drv);
        return ok ? DH_OK : DH_ERR_GENERIC;
    }

    if (!wcscmp(argv[1], L"mirror-decrypt")) {
        // Full-image mirror approach:
        //  1. VirtualAlloc at Delta's exact image base (0x140000000)
        //  2. RPM-copy the entire image into our process
        //  3. Cast the located decrypt dispatch VA as a function pointer
        //  4. Call it directly with a test FEncVector (SEH-guarded)
        //
        // Prereq: the caller passes:
        //   argv[2] = decrypt dispatch VA (hex, e.g. 143246360)
        //   argv[3..5] = X Y Z hex-float of the encrypted vector
        //   argv[6] = 4-byte handler hex (little-endian raw), e.g. 4C1E01B0 means:
        //             Index=0x1E4C, bEncrypted=0x01, flags=0xB0
        if (argc < 7) {
            DH_ERROR("usage: mirror-decrypt <dispatch-va-hex> <x-hex> <y-hex> <z-hex> <handler-4byte-hex>");
            return DH_ERR_BAD_ARG;
        }
        u64 dispatch_va = _wcstoui64(argv[2], NULL, 16);
        union { u32 u; float f; } fx, fy, fz;
        fx.u = wcstoul(argv[3], NULL, 16);
        fy.u = wcstoul(argv[4], NULL, 16);
        fz.u = wcstoul(argv[5], NULL, 16);
        u32 hbits = wcstoul(argv[6], NULL, 16);

        DH_DRIVER drv;
        if (!driver_up(&drv)) return DH_ERR_SVC_START;
        u64 sysCR3 = 0, procCR3 = 0, eproc = 0;
        if (!RpmFindSystemCR3(drv.hDevice, &sysCR3)) { driver_down(&drv); return DH_ERR_RPM_FAIL; }
        if (!RpmFindProcess(drv.hDevice, sysCR3, DH_PROC_NAME, &procCR3, &eproc)) {
            DH_ERROR("delta not found"); driver_down(&drv); return DH_ERR_RPM_FAIL;
        }

        const u64 IMG_BASE = 0x140000000ULL;
        const u64 IMG_SIZE = 0x20300000ULL;  // Round up 0x202F5000

        DH_INFO("[mirror] reserving image mirror at 0x%llX size 0x%llX", IMG_BASE, IMG_SIZE);
        void* mirror = VirtualAlloc((LPVOID)IMG_BASE, (SIZE_T)IMG_SIZE,
                                     MEM_COMMIT | MEM_RESERVE,
                                     PAGE_EXECUTE_READWRITE);
        if (!mirror) {
            DH_ERROR("VirtualAlloc(0x%llX) failed: %lu (trying dynamic base)",
                     IMG_BASE, GetLastError());
            mirror = VirtualAlloc(NULL, (SIZE_T)IMG_SIZE,
                                  MEM_COMMIT | MEM_RESERVE,
                                  PAGE_EXECUTE_READWRITE);
            if (!mirror) {
                DH_ERROR("dynamic VirtualAlloc failed: %lu", GetLastError());
                driver_down(&drv);
                return DH_ERR_GENERIC;
            }
            DH_INFO("[mirror] fell back to base 0x%p — RIP-rel refs WILL BREAK",
                    mirror);
        } else {
            DH_INFO("[mirror] reserved at exact base 0x%llX (RIP-rel refs preserved)", (u64)mirror);
        }

        // Copy image chunk by chunk
        const u32 CHUNK = 0x100000;  // 1 MiB
        u64 done = 0, gaps = 0;
        u64 tStart = GetTickCount64();
        for (u64 off = 0; off < IMG_SIZE; off += CHUNK) {
            u32 want = (IMG_SIZE - off > CHUNK) ? CHUNK : (u32)(IMG_SIZE - off);
            if (!RpmReadVirtual(drv.hDevice, procCR3,
                                 IMG_BASE + off, (u8*)mirror + off, want)) {
                gaps++;
            } else {
                done += want;
            }
        }
        u64 elapsed = GetTickCount64() - tStart;
        DH_INFO("[mirror] copied %llu MB in %llu ms (%llu gaps)",
                done >> 20, elapsed, gaps);

        // Prepare arguments — allocate 16-byte scratch for io + 4-byte handler
        // (must remain valid across the call)
        struct { float X, Y, Z; u32 handler; } fv;
        fv.X = fx.f; fv.Y = fy.f; fv.Z = fz.f;
        fv.handler = hbits;

        // Copy into a mutable stack tmp for the decrypt (it may write back)
        struct { float X, Y, Z; } tmp = { fv.X, fv.Y, fv.Z };
        u32 hdr_copy = fv.handler;

        DH_INFO("[mirror] input: X=%.3f Y=%.3f Z=%.3f handler=0x%08X (Index=0x%04X bEnc=%u flags=0x%02X)",
                tmp.X, tmp.Y, tmp.Z, hdr_copy,
                (u16)(hdr_copy & 0xFFFF), (hdr_copy >> 16) & 0xFF, (hdr_copy >> 24) & 0xFF);

        // Cast dispatch VA as function pointer
        // Signature per RE: void __fastcall fn(void* io_ptr, uint32_t size, void* handler_ptr)
        typedef void (__fastcall *dec_fn_t)(void*, u32, void*);
        dec_fn_t decfn = (dec_fn_t)dispatch_va;

        DH_INFO("[mirror] calling 0x%llX(...)", dispatch_va);
        BOOL ok = FALSE;
        DWORD excCode = 0;
        u64 excAddr = 0;
        u64 excInfo0 = 0, excInfo1 = 0;
        __try {
            decfn(&tmp, 0xC, &hdr_copy);
            ok = TRUE;
        } __except (
            excCode = GetExceptionCode(),
            excAddr = (u64)(GetExceptionInformation()->ExceptionRecord->ExceptionAddress),
            excInfo0 = GetExceptionInformation()->ExceptionRecord->NumberParameters >= 1
                     ? GetExceptionInformation()->ExceptionRecord->ExceptionInformation[0] : 0,
            excInfo1 = GetExceptionInformation()->ExceptionRecord->NumberParameters >= 2
                     ? GetExceptionInformation()->ExceptionRecord->ExceptionInformation[1] : 0,
            EXCEPTION_EXECUTE_HANDLER)
        {
            DH_ERROR("[mirror] SEH: exception 0x%08X at fault-PC 0x%llX", excCode, excAddr);
            DH_ERROR("[mirror]   ExceptionInfo[0] (r/w flag) = 0x%llX", excInfo0);
            DH_ERROR("[mirror]   ExceptionInfo[1] (fault addr) = 0x%llX", excInfo1);
            u64 fault_in_mirror = 0;
            if (excAddr >= IMG_BASE && excAddr < IMG_BASE + IMG_SIZE) {
                fault_in_mirror = excAddr - IMG_BASE;
                DH_ERROR("[mirror]   fault PC is INSIDE mirror at RVA 0x%llX", fault_in_mirror);
            } else {
                DH_ERROR("[mirror]   fault PC OUTSIDE mirror — jumped to bad addr");
            }
            ok = FALSE;
        }

        if (ok) {
            DH_INFO("[mirror] OUTPUT: X=%.3f Y=%.3f Z=%.3f (handler now 0x%08X)",
                    tmp.X, tmp.Y, tmp.Z, hdr_copy);
        } else {
            DH_ERROR("[mirror] decrypt call FAULTED — mirror likely incomplete or thread-state mismatch");
        }

        driver_down(&drv);
        return ok ? DH_OK : DH_ERR_GENERIC;
    }

    if (!wcscmp(argv[1], L"dump-range")) {
        // Dump arbitrary VA range from Delta memory to a local file.
        // Usage: dump-range <va-hex> <size-hex> <outfile>
        if (argc < 5) { DH_ERROR("usage: dump-range <va> <size> <outfile>"); return DH_ERR_BAD_ARG; }
        u64 va   = _wcstoui64(argv[2], NULL, 16);
        u64 size = _wcstoui64(argv[3], NULL, 16);
        const wchar_t* outfile = argv[4];

        DH_DRIVER drv;
        if (!driver_up(&drv)) return DH_ERR_SVC_START;
        u64 sysCR3 = 0, procCR3 = 0, eproc = 0;
        if (!RpmFindSystemCR3(drv.hDevice, &sysCR3)) { driver_down(&drv); return DH_ERR_RPM_FAIL; }
        if (!RpmFindProcess(drv.hDevice, sysCR3, DH_PROC_NAME, &procCR3, &eproc)) {
            DH_ERROR("delta not found"); driver_down(&drv); return DH_ERR_RPM_FAIL;
        }

        HANDLE hFile = CreateFileW(outfile, GENERIC_WRITE, 0, NULL,
                                   CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            DH_ERROR("CreateFile failed: %lu", GetLastError());
            driver_down(&drv); return DH_ERR_GENERIC;
        }

        const u32 CHUNK = 0x10000;   // 64 KiB per RPM
        u8* buf = (u8*)VirtualAlloc(NULL, CHUNK, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        u64 cursor = 0, gaps = 0, wrote = 0;
        u64 tStart = GetTickCount64();

        while (cursor < size) {
            u32 want = (size - cursor > CHUNK) ? CHUNK : (u32)(size - cursor);
            memset(buf, 0, want);
            if (!RpmReadVirtual(drv.hDevice, procCR3, va + cursor, buf, want)) gaps++;
            DWORD bw = 0;
            WriteFile(hFile, buf, want, &bw, NULL);
            wrote += bw;
            cursor += want;
            if (cursor % 0x1000000 == 0) {  // every 16MB
                u64 elapsed = GetTickCount64() - tStart;
                DH_INFO("  progress: %llu MB / %llu MB (%.1f MB/s, %llu gaps)",
                        cursor >> 20, size >> 20,
                        elapsed > 0 ? (double)wrote / elapsed / 1000.0 : 0.0,
                        gaps);
            }
        }
        VirtualFree(buf, 0, MEM_RELEASE);
        CloseHandle(hFile);
        u64 elapsed = GetTickCount64() - tStart;
        DH_INFO("dump done: %llu MB in %llu ms (%.1f MB/s, %llu gaps)",
                wrote >> 20, elapsed,
                elapsed > 0 ? (double)wrote / elapsed / 1000.0 : 0.0,
                gaps);
        driver_down(&drv);
        return DH_OK;
    }

    if (!wcscmp(argv[1], L"vtbl-decrypt-live")) {
        // Live variant: RPM-copy the shellcode from Delta at runtime, then
        // decrypt. Requires driver + Delta running.
        // Args: <X_bits_hex> <Y_bits_hex> <Z_bits_hex> <Index_hex> [flags_hex]
        if (argc < 6) {
            wprintf(L"usage: vtbl-decrypt-live <X_hex> <Y_hex> <Z_hex> <Index_hex> [flags_hex]\n");
            return DH_ERR_BAD_ARG;
        }
        DH_DRIVER drv;
        if (!driver_up(&drv)) return DH_ERR_SVC_START;
        u64 sysCR3 = 0, procCR3 = 0, eproc = 0;
        if (!RpmFindSystemCR3(drv.hDevice, &sysCR3)) { driver_down(&drv); return DH_ERR_RPM_FAIL; }
        if (!RpmFindProcess(drv.hDevice, sysCR3, DH_PROC_NAME, &procCR3, &eproc)) {
            DH_ERROR("delta not found"); driver_down(&drv); return DH_ERR_RPM_FAIL;
        }
        u64 peb = 0, base = 0, size = 0;
        RpmRead64(drv.hDevice, sysCR3, eproc + g_eproc_peb_off, &peb);
        if (!RpmGetMainImageBase(drv.hDevice, procCR3, peb, &base, &size)) {
            base = 0x140000000ULL; size = 0x1F800000;
        }
        if (!VtblDecryptInitLive(drv.hDevice, procCR3, base)) {
            DH_ERROR("VtblDecryptInitLive failed"); driver_down(&drv);
            return DH_ERR_RPM_FAIL;
        }
        union { float f; u32 u; } fx, fy, fz;
        fx.u = wcstoul(argv[2], NULL, 16);
        fy.u = wcstoul(argv[3], NULL, 16);
        fz.u = wcstoul(argv[4], NULL, 16);
        u16 idx = (u16)wcstoul(argv[5], NULL, 16);
        u8  flg = (argc >= 7) ? (u8)wcstoul(argv[6], NULL, 16) : 0x01;
        DH_ENC_VECTOR enc = { fx.f, fy.f, fz.f, { idx, 1, flg } };
        DH_FVECTOR out = {0};
        if (!VtblDecryptCall(&enc, &out)) {
            DH_ERROR("VtblDecryptCall faulted"); VtblDecryptFree();
            driver_down(&drv); return DH_ERR_RPM_FAIL;
        }
        wprintf(L"in float: (%.4f, %.4f, %.4f) idx=0x%04X flg=0x%02X\n",
                fx.f, fy.f, fz.f, idx, flg);
        wprintf(L"out float: (%.4f, %.4f, %.4f)\n", out.X, out.Y, out.Z);
        VtblDecryptFree();
        driver_down(&drv);
        return DH_OK;
    }

    if (!wcscmp(argv[1], L"decrypt-init")) {
        // Locate the universal FEncVector decrypt function and RPM-copy it
        // into a local RWX buffer. Diagnostic only — prints located VA + hex.
        DH_DRIVER drv;
        if (!driver_up(&drv)) return DH_ERR_SVC_START;
        u64 sysCR3 = 0, procCR3 = 0, eproc = 0;
        if (!RpmFindSystemCR3(drv.hDevice, &sysCR3)) { driver_down(&drv); return DH_ERR_RPM_FAIL; }
        if (!RpmFindProcess(drv.hDevice, sysCR3, DH_PROC_NAME, &procCR3, &eproc)) {
            DH_ERROR("delta not found"); driver_down(&drv); return DH_ERR_RPM_FAIL;
        }
        u64 peb = 0, base = 0, size = 0;
        RpmRead64(drv.hDevice, sysCR3, eproc + g_eproc_peb_off, &peb);
        if (!RpmGetMainImageBase(drv.hDevice, procCR3, peb, &base, &size)) {
            base = 0x140000000ULL; size = 0x1F800000; DH_INFO("PEB failed, using hardcoded base");
        }
        DH_INFO("Delta base=0x%llX size=0x%llX", base, size);

        DH_ACE_DECRYPT dec;
        if (!AceDecryptInit(&dec, drv.hDevice, procCR3, base, size)) {
            DH_ERROR("AceDecryptInit failed");
            driver_down(&drv);
            return DH_ERR_RPM_FAIL;
        }
        AceDecryptDumpBody(&dec);
        AceDecryptFree(&dec);
        driver_down(&drv);
        return DH_OK;
    }

    if (!wcscmp(argv[1], L"decrypt-test")) {
        // Run decrypt-init + test-decrypt on a synthetic FEncVector supplied
        // via CLI, or on the first encrypted actor found in the world.
        DH_DRIVER drv;
        if (!driver_up(&drv)) return DH_ERR_SVC_START;
        u64 sysCR3 = 0, procCR3 = 0, eproc = 0;
        if (!RpmFindSystemCR3(drv.hDevice, &sysCR3)) { driver_down(&drv); return DH_ERR_RPM_FAIL; }
        if (!RpmFindProcess(drv.hDevice, sysCR3, DH_PROC_NAME, &procCR3, &eproc)) {
            DH_ERROR("delta not found"); driver_down(&drv); return DH_ERR_RPM_FAIL;
        }
        u64 peb = 0, base = 0, size = 0;
        RpmRead64(drv.hDevice, sysCR3, eproc + g_eproc_peb_off, &peb);
        if (!RpmGetMainImageBase(drv.hDevice, procCR3, peb, &base, &size)) {
            base = 0x140000000ULL; size = 0x1F800000;
        }
        DH_ACE_DECRYPT dec;
        if (!AceDecryptInit(&dec, drv.hDevice, procCR3, base, size)) {
            DH_ERROR("init failed"); driver_down(&drv); return DH_ERR_RPM_FAIL;
        }

        // Synthetic plaintext test — Index=0xFFFF must pass fast-path
        DH_ENC_VECTOR pt = { 100.0f, 200.0f, 300.0f, { 0xFFFF, 0, 0 } };
        DH_FVECTOR out = {0};
        if (AceDecryptVector(&dec, &pt, &out))
            DH_INFO("[plaintext test] X=%.1f Y=%.1f Z=%.1f (expect 100/200/300)",
                    out.X, out.Y, out.Z);
        else DH_ERROR("[plaintext test] failed");

        // Live test — try to decrypt what argv[2..4] specify as X,Y,Z hex floats
        // and argv[5] as Index (u16).
        if (argc >= 6) {
            union { float f; u32 u; } fx, fy, fz;
            fx.u = wcstoul(argv[2], NULL, 16);
            fy.u = wcstoul(argv[3], NULL, 16);
            fz.u = wcstoul(argv[4], NULL, 16);
            u16 idx = (u16)wcstoul(argv[5], NULL, 16);
            DH_ENC_VECTOR ev = { fx.f, fy.f, fz.f, { idx, 1, 0 } };
            DH_FVECTOR pv = {0};
            if (AceDecryptVector(&dec, &ev, &pv))
                DH_INFO("[decrypt] input(%.3f,%.3f,%.3f idx=0x%04X) -> "
                        "output(%.3f,%.3f,%.3f)", fx.f, fy.f, fz.f, idx,
                        pv.X, pv.Y, pv.Z);
            else DH_ERROR("[decrypt] call faulted");
        }

        AceDecryptStats(&dec);
        AceDecryptFree(&dec);
        driver_down(&drv);
        return DH_OK;
    }

    if (!wcscmp(argv[1], L"find-base")) {
        // Diagnostic: dump Delta EPROCESS + scan for PEB/SectionBaseAddress
        DH_DRIVER drv;
        if (!driver_up(&drv)) return DH_ERR_SVC_START;
        u64 sysCR3 = 0, procCR3 = 0, eproc = 0;
        if (!RpmFindSystemCR3(drv.hDevice, &sysCR3)) { driver_down(&drv); return DH_ERR_RPM_FAIL; }
        DH_INFO("sysCR3 = 0x%llX", sysCR3);
        if (!RpmFindProcess(drv.hDevice, sysCR3, DH_PROC_NAME, &procCR3, &eproc)) {
            DH_ERROR("delta not found"); driver_down(&drv); return DH_ERR_RPM_FAIL;
        }
        DH_INFO("eproc=0x%llX procCR3=0x%llX", eproc, procCR3);
        u8 eb[0x800];
        if (!RpmReadVirtual(drv.hDevice, sysCR3, eproc, eb, sizeof(eb))) {
            DH_ERROR("read EPROCESS failed"); driver_down(&drv); return DH_ERR_RPM_FAIL;
        }
        // Scan every 8-byte aligned qword for pointers looking like:
        //  A) PEB (user canonical, 0x00007FF...)
        //  B) SectionBaseAddress (0x140000000..0x180000000, and page-aligned)
        printf("\n[EPROCESS+off]  value                candidate\n");
        for (u32 off = 0x200; off <= 0x780; off += 8) {
            u64 v = *(u64*)(eb + off);
            const char* tag = NULL;
            if ((v >> 44) == 0x7 && (v & 0xFFF) == 0)          tag = "PEB?  (0x7FF..., page-aligned)";
            else if (v >= 0x140000000ULL && v < 0x200000000ULL && (v & 0xFFFF) == 0) tag = "ImageBase? (140-200M, 64K-aligned)";
            if (tag)
                printf("  +0x%03X       0x%016llX   %s\n", off, v, tag);
        }
        // Also brute-verify: for each PEB candidate, try to read PEB+0x10 (ImageBase) via procCR3
        printf("\n[verify PEB candidates via procCR3]\n");
        for (u32 off = 0x200; off <= 0x780; off += 8) {
            u64 pebCand = *(u64*)(eb + off);
            if ((pebCand >> 44) != 0x7 || (pebCand & 0xFFF)) continue;
            u64 ib = 0;
            BOOL ok = RpmRead64(drv.hDevice, procCR3, pebCand + 0x10, &ib);
            printf("  PEB@+0x%03X = 0x%llX  ImageBase read %s = 0x%llX\n",
                off, pebCand, ok ? "OK" : "FAIL", ib);
        }
        // Also test procCR3 directly: try reading a low VA to check translation health
        printf("\n[procCR3 translation health]\n");
        for (u64 testVA = 0x140000000ULL; testVA <= 0x150000000ULL; testVA += 0x1000000ULL) {
            u16 mz = 0;
            BOOL ok = RpmReadVirtual(drv.hDevice, procCR3, testVA, &mz, 2);
            if (ok) printf("  0x%llX = 0x%04X  <-- readable\n", testVA, mz);
        }
        // Dump EPROCESS header 0x00..0x60 - locate DirectoryTableBase manually
        printf("\n[EPROCESS header 0x00-0x60]\n");
        for (u32 off = 0; off < 0x60; off += 0x10) {
            printf("  +0x%02X: %016llX  %016llX\n",
                off, *(u64*)(eb + off), *(u64*)(eb + off + 8));
        }
        // Scan first 0x100 bytes for CR3-like value (matches physical page range ~2-8GB, page-aligned)
        printf("\n[CR3 candidates in EPROCESS+0x00..0x100]\n");
        for (u32 off = 0; off < 0x100; off += 8) {
            u64 v = *(u64*)(eb + off);
            if (v >= 0x100000ULL && v < 0x800000000ULL && (v & 0xFFF) == 0) {
                // Test this CR3 candidate — try reading VA 0x140000000
                u16 mz = 0;
                BOOL ok = RpmReadVirtual(drv.hDevice, v, 0x140000000ULL, &mz, 2);
                printf("  +0x%02X = 0x%llX  test-read 0x140000000: %s (mz=0x%04X)\n",
                    off, v, ok ? "OK" : "FAIL", mz);
            }
        }
        driver_down(&drv);
        return DH_OK;
    }

    if (!wcscmp(argv[1], L"dump-eproc")) {
        // Diagnostic: dump System EPROCESS bytes to find ActiveProcessLinks/PID/ImageFileName
        DH_DRIVER drv;
        if (!driver_up(&drv)) return DH_ERR_SVC_START;
        u64 sysCR3 = 0;
        if (!RpmFindSystemCR3(drv.hDevice, &sysCR3)) { driver_down(&drv); return DH_ERR_RPM_FAIL; }

        typedef NTSTATUS (NTAPI *pfnNtQSI)(ULONG, PVOID, ULONG, PULONG);
        pfnNtQSI pQSI = (pfnNtQSI)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation");
        ULONG needed = 0; pQSI(11, NULL, 0, &needed);
        char* modBuf = (char*)HeapAlloc(GetProcessHeap(), 0, needed);
        pQSI(11, modBuf, needed, &needed);
        // Modules[] starts at modBuf+8 (after ULONG Count + 4 bytes align padding).
        // Modules[0].Base is at RTL_SYSTEM_MODULE offset 16 (after Reserved[2]).
        u64 ntBase = *(u64*)(modBuf + 8 + 16);
        HeapFree(GetProcessHeap(), 0, modBuf);
        DH_INFO("ntBase (dump) = 0x%llX", ntBase);

        IMAGE_DOS_HEADER dos;
        RpmReadVirtual(drv.hDevice, sysCR3, ntBase, &dos, sizeof(dos));
        IMAGE_NT_HEADERS64 nt;
        RpmReadVirtual(drv.hDevice, sysCR3, ntBase + dos.e_lfanew, &nt, sizeof(nt));
        DWORD expRVA = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        IMAGE_EXPORT_DIRECTORY expDir;
        RpmReadVirtual(drv.hDevice, sysCR3, ntBase + expRVA, &expDir, sizeof(expDir));

        u64 psisp = 0;
        for (DWORD i = 0; i < expDir.NumberOfNames; i++) {
            DWORD nameRVA; RpmReadVirtual(drv.hDevice, sysCR3, ntBase + expDir.AddressOfNames + i*4, &nameRVA, 4);
            char name[48] = {0}; RpmReadVirtual(drv.hDevice, sysCR3, ntBase + nameRVA, name, 47);
            if (strcmp(name, "PsInitialSystemProcess") == 0) {
                USHORT ord; RpmReadVirtual(drv.hDevice, sysCR3, ntBase + expDir.AddressOfNameOrdinals + i*2, &ord, 2);
                DWORD fRVA; RpmReadVirtual(drv.hDevice, sysCR3, ntBase + expDir.AddressOfFunctions + ord*4, &fRVA, 4);
                RpmRead64(drv.hDevice, sysCR3, ntBase + fRVA, &psisp);
                break;
            }
        }
        DH_INFO("System EPROCESS = 0x%llX", psisp);

        // Brute-force walk each candidate ActiveProcessLinks offset in [0x400, 0x500]
        for (u32 candOff = 0x400; candOff <= 0x500; candOff += 8) {
            u64 head = psisp + candOff;
            u64 flink = 0;
            if (!RpmRead64(drv.hDevice, sysCR3, head, &flink)) continue;
            if (flink == head || (flink >> 47) < 0x1FFF0) continue;

            u64 cur = flink;
            u32 count = 0;
            for (; count < 2000; count++) {
                if (cur == head) break;
                u64 next = 0;
                if (!RpmRead64(drv.hDevice, sysCR3, cur, &next)) break;
                if (next == cur) break;
                cur = next;
            }
            if (count >= 20 && cur == head)
                printf("[cand] ActiveProcessLinks candidate @ +0x%03X — %u entries\n", candOff, count);
        }

        u8 buf[0x800];
        if (RpmReadVirtual(drv.hDevice, sysCR3, psisp, buf, sizeof(buf))) {
            printf("[markers] sysCR3=0x%llX psisp=0x%llX\n", sysCR3, psisp);
            // scan for exact CR3 value → identifies DirectoryTableBase offset
            for (u32 off = 0; off < 0x100; off += 8) {
                u64 v = *(u64*)(buf + off);
                if (v == sysCR3) printf("  DTB match @ +0x%X\n", off);
            }
            // scan for "System" ASCII
            for (u32 off = 0; off < 0x800; off++) {
                if (memcmp(buf + off, "System", 6) == 0)
                    printf("  ImageFileName 'System' @ +0x%X\n", off);
            }
            // scan for PID=4 followed by ULONG-aligned LIST_ENTRY (two kernel VAs)
            for (u32 off = 0x400; off <= 0x600; off += 8) {
                u64 pid = *(u64*)(buf + off);
                if (pid == 4) {
                    u64 f = *(u64*)(buf + off + 8);
                    u64 b = *(u64*)(buf + off + 16);
                    if ((f >> 47) >= 0x1FFF0 && (b >> 47) >= 0x1FFF0)
                        printf("  PID=4 @ +0x%X, LIST_ENTRY @ +0x%X {%llX, %llX}\n",
                               off, off + 8, f, b);
                }
            }
            for (u32 off = 0x0; off < 0x700; off += 0x10) {
                printf("+0x%03X:  %02X %02X %02X %02X %02X %02X %02X %02X  %02X %02X %02X %02X %02X %02X %02X %02X  ",
                    off,
                    buf[off+0],buf[off+1],buf[off+2],buf[off+3],buf[off+4],buf[off+5],buf[off+6],buf[off+7],
                    buf[off+8],buf[off+9],buf[off+10],buf[off+11],buf[off+12],buf[off+13],buf[off+14],buf[off+15]);
                for (int i = 0; i < 16; i++) {
                    unsigned char c = buf[off+i];
                    putchar((c >= 0x20 && c < 0x7F) ? c : '.');
                }
                putchar('\n');
            }
        }
        driver_down(&drv);
        return DH_OK;
    }

    if (!wcscmp(argv[1], L"modules")) {
        if (argc < 3) { DH_ERROR("usage: modules <procname>"); return DH_ERR_BAD_ARG; }
        char pname[16] = {0};
        WideCharToMultiByte(CP_ACP, 0, argv[2], -1, pname, 15, NULL, NULL);

        DH_DRIVER drv;
        if (!driver_up(&drv)) return DH_ERR_SVC_START;
        u64 sysCR3 = 0, procCR3 = 0, eproc = 0;
        int rc = DH_OK;
        if (!RpmFindSystemCR3(drv.hDevice, &sysCR3)) rc = DH_ERR_RPM_FAIL;
        else if (!RpmFindProcess(drv.hDevice, sysCR3, pname, &procCR3, &eproc))
            rc = DH_ERR_TARGET_NOT_FOUND;
        else {
            u64 peb = 0;
            RpmRead64(drv.hDevice, sysCR3, eproc + g_eproc_peb_off, &peb);

            u64 mainBase = 0, mainSize = 0;
            if (RpmGetMainImageBase(drv.hDevice, procCR3, peb, &mainBase, &mainSize))
                DH_INFO("main image base=0x%llX size=0x%llX (via PEB.ImageBaseAddress)",
                        mainBase, mainSize);

            DH_INFO("--- Ldr.InLoadOrderModuleList ---");
            u64 ldr = 0;
            if (RpmRead64(drv.hDevice, procCR3, peb + 0x18, &ldr) && ldr) {
                u64 head = ldr + 0x10, flink = 0;
                RpmRead64(drv.hDevice, procCR3, head, &flink);
                u64 cur = flink;
                int n = 0;
                while (cur != head && n < 512) {
                    u64 dllBase = 0; u32 sz = 0;
                    u16 nameLen = 0; u64 nameBuf = 0;
                    RpmRead64(drv.hDevice, procCR3, cur + 0x30, &dllBase);
                    RpmReadVirtual(drv.hDevice, procCR3, cur + 0x40, &sz, 4);
                    RpmReadVirtual(drv.hDevice, procCR3, cur + 0x58, &nameLen, 2);
                    RpmRead64(drv.hDevice, procCR3, cur + 0x58 + 8, &nameBuf);
                    wchar_t name[128] = {0};
                    u32 copyLen = nameLen;
                    if (copyLen > sizeof(name) - 2) copyLen = sizeof(name) - 2;
                    if (nameBuf && copyLen)
                        RpmReadVirtual(drv.hDevice, procCR3, nameBuf, name, copyLen);
                    if (dllBase)
                        printf("  [%3d] base=0x%012llX size=0x%08X  %ls\n", n, dllBase, sz, name);
                    u64 next = 0;
                    if (!RpmRead64(drv.hDevice, procCR3, cur, &next) || next == cur) break;
                    cur = next; n++;
                }
                DH_INFO("total %d modules", n);
            }
        }
        driver_down(&drv);
        return rc;
    }

    if (!wcscmp(argv[1], L"find")) {
        if (argc < 3) { DH_ERROR("usage: find <procname>"); return DH_ERR_BAD_ARG; }
        char pname[16] = {0};
        WideCharToMultiByte(CP_ACP, 0, argv[2], -1, pname, 15, NULL, NULL);

        DH_DRIVER drv;
        if (!driver_up(&drv)) return DH_ERR_SVC_START;
        u64 sysCR3 = 0, procCR3 = 0, eproc = 0;
        int rc = DH_OK;
        if (!RpmFindSystemCR3(drv.hDevice, &sysCR3)) rc = DH_ERR_RPM_FAIL;
        else if (!RpmFindProcess(drv.hDevice, sysCR3, pname, &procCR3, &eproc))
            rc = DH_ERR_TARGET_NOT_FOUND;
        else {
            // End-to-end sanity: read the image base from PEB and dump first 16 bytes.
            // EPROCESS.Peb offset: 0x2E0 on Germanium (25H2/24H2).
            u64 peb = 0;
            if (RpmRead64(drv.hDevice, sysCR3, eproc + g_eproc_peb_off, &peb) && peb) {
                DH_INFO("PEB @ 0x%llX (via sysCR3)", peb);
                u64 imageBase = 0;
                if (RpmRead64(drv.hDevice, procCR3, peb + 0x10, &imageBase) && imageBase) {
                    u8 mz[16] = {0};
                    if (RpmReadVirtual(drv.hDevice, procCR3, imageBase, mz, sizeof(mz))) {
                        printf("[rpm] ImageBase=0x%llX first16: ", imageBase);
                        for (int i = 0; i < 16; i++) printf("%02X ", mz[i]);
                        printf("%s\n", (mz[0] == 'M' && mz[1] == 'Z') ? " (MZ OK)" : " (NO MZ)");
                    } else DH_WARN("read ImageBase failed");
                } else DH_WARN("read PEB.ImageBaseAddress failed");
            } else DH_WARN("EPROCESS.Peb read failed");
        }
        driver_down(&drv);
        return rc;
    }

    if (!wcscmp(argv[1], L"install")) {
        DH_DRIVER drv;
        if (!driver_up(&drv)) return DH_ERR_SVC_START;
        DH_INFO("driver installed and running (leaving up)");
        // deliberately don't cleanup — leave service running
        if (drv.hDevice) CloseHandle(drv.hDevice);
        if (drv.hSvc)    CloseServiceHandle(drv.hSvc);
        if (drv.hSCM)    CloseServiceHandle(drv.hSCM);
        return DH_OK;
    }

    if (!wcscmp(argv[1], L"uninstall")) {
        DH_DRIVER drv;
        memset(&drv, 0, sizeof(drv));
        drv.hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
        if (!drv.hSCM) {
            DH_ERROR("OpenSCManager failed");
            return DH_ERR_SVC_REMOVE;
        }
        drv.hSvc = OpenServiceW(drv.hSCM, dh_svc_name(), SERVICE_ALL_ACCESS);
        if (drv.hSvc) {
            SERVICE_STATUS ss;
            ControlService(drv.hSvc, SERVICE_CONTROL_STOP, &ss);
            DeleteService(drv.hSvc);
            CloseServiceHandle(drv.hSvc);
            DH_INFO("service '%ls' removed", dh_svc_name());
        } else {
            DH_INFO("service '%ls' not installed", dh_svc_name());
        }
        CloseServiceHandle(drv.hSCM);
        return DH_OK;
    }

    DH_ERROR("unknown command: %ls", argv[1]);
    usage();
    return DH_ERR_BAD_ARG;
}

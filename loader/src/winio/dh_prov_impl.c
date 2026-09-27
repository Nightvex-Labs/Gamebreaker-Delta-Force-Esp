// DeltaHack — provider runtime implementation.
//
// DhProviderTry — attempts to install + start + open + smoke-test a provider.
// DhProviderSelect — iterates providers by priority, returns first success.
// DhProviderPhysRead/Write — dispatches through the active provider protocol.
//
// Provider-specific protocol details (request struct layout) live in the
// per-family PhysRead/Write handlers below. All WinIo family drivers share
// the same request struct layout; ASUSIO / UCOREW / REDFOX differ slightly.
#include "../../inc/dh_provider.h"
#include "../../inc/dh_scm.h"
#include "../../inc/dh_dbunpack.h"
#include "../../inc/dh_vmprotect.h"

#include <windows.h>
#include <shlwapi.h>
#include <string.h>

// Global "active" provider — set by main after DhProviderSelect succeeds.
// PhysRead/PhysWrite in dh_phys.c consult this to route IOCTLs correctly.
const DH_PROVIDER* g_active_provider = NULL;

// DbUnpack declared in dh_dbunpack.h: BOOL DbUnpack(const void*, DWORD, void**, DWORD*)

// -----------------------------------------------------------------------------
// Request struct layouts (per protocol family)
// -----------------------------------------------------------------------------

#pragma pack(push, 1)
typedef struct {                        // WINIO / ASUSIO family (shared)
    ULONG_PTR ViewSize;
    ULONG_PTR BusAddress;
    HANDLE    SectionHandle;
    PVOID     BaseAddress;
    PVOID     ReferencedObject;
} WINIO_REQ;

typedef struct {                        // REDFOX family (inpoutx64) — 32 bytes
    HANDLE    SectionHandle;    // +0x00
    ULONG_PTR ViewSize;         // +0x08
    ULONG_PTR BusAddress;       // +0x10 — MUST be page-aligned
    PVOID     BaseAddress;      // +0x18 — mapped VA
} REDFOX_REQ;

typedef struct {                        // UCOREW64 family
    ULONG     Size;
    ULONG_PTR BusAddress;
    PVOID     BaseAddress;
    HANDLE    SectionHandle;
    PVOID     ReferencedObject;
} UCOREW_REQ;
#pragma pack(pop)

static BOOL CallIoctl(HANDLE hDev, DWORD ioctl, void* buf, DWORD sz)
{
    DWORD bytes = 0;
    return DeviceIoControl(hDev, ioctl, buf, sz, buf, sz, &bytes, NULL);
}

// -----------------------------------------------------------------------------
// Per-protocol phys map / unmap
// -----------------------------------------------------------------------------

static PVOID MapWinIo(HANDLE hDev, DWORD ioctl_map, u64 phys, u32 size,
                     HANDLE* sec, PVOID* refObj)
{
    WINIO_REQ req = {0};
    req.ViewSize = size;
    req.BusAddress = (ULONG_PTR)phys;
    if (!CallIoctl(hDev, ioctl_map, &req, sizeof(req))) return NULL;
    *sec = req.SectionHandle;
    *refObj = req.ReferencedObject;
    return req.BaseAddress;
}

static void UnmapWinIo(HANDLE hDev, DWORD ioctl_unmap, PVOID base,
                       HANDLE sec, PVOID refObj)
{
    WINIO_REQ req = {0};
    req.BaseAddress = base;
    req.SectionHandle = sec;
    req.ReferencedObject = refObj;
    CallIoctl(hDev, ioctl_unmap, &req, sizeof(req));
}

// REDFOX driver requires page-aligned bus address. Returns page-aligned
// mapped VA — caller must add page_offset to get desired physical byte.
// out_offset receives the intra-page offset for caller convenience.
static PVOID MapRedFox(HANDLE hDev, DWORD ioctl_map, u64 phys, u32 size,
                      HANDLE* sec, PVOID* refObj, u32* out_offset)
{
    u64 pageBase = phys & ~(u64)0xFFF;
    u32 pageOff  = (u32)(phys & 0xFFF);
    u32 mapSize  = ((pageOff + size + 0xFFF) & ~(u32)0xFFF);

    REDFOX_REQ req = {0};
    req.BusAddress = (ULONG_PTR)pageBase;
    req.ViewSize   = mapSize;
    if (!CallIoctl(hDev, ioctl_map, &req, sizeof(req))) return NULL;

    *sec = req.SectionHandle;
    *refObj = NULL;
    if (out_offset) *out_offset = pageOff;
    return req.BaseAddress;
}

static void UnmapRedFox(HANDLE hDev, DWORD ioctl_unmap, PVOID base,
                        HANDLE sec, PVOID refObj)
{
    (void)refObj;
    REDFOX_REQ req = {0};
    req.BaseAddress = base;
    req.SectionHandle = sec;
    CallIoctl(hDev, ioctl_unmap, &req, sizeof(req));
}

// -----------------------------------------------------------------------------
// Public: phys R/W dispatch
// -----------------------------------------------------------------------------

BOOL DhProviderPhysRead(HANDLE hDev, const DH_PROVIDER* prov,
                        u64 phys, void* dst, u32 size)
{
    if (!size || !hDev || !prov) return FALSE;

    HANDLE sec = NULL; PVOID refObj = NULL; PVOID mapped = NULL;
    u32 pageOff = 0;

    switch (prov->protocol) {
    case DH_PROTO_WINIO:
    case DH_PROTO_ASUSIO:
    case DH_PROTO_UCOREW:
        mapped = MapWinIo(hDev, prov->ioctl_map, phys, size, &sec, &refObj);
        break;
    case DH_PROTO_REDFOX:
        mapped = MapRedFox(hDev, prov->ioctl_map, phys, size, &sec, &refObj, &pageOff);
        break;
    default:
        return FALSE;
    }
    if (!mapped) return FALSE;

    BOOL ok = TRUE;
    __try {
        memcpy(dst, (u8*)mapped + pageOff, size);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        ok = FALSE;
    }

    switch (prov->protocol) {
    case DH_PROTO_WINIO:
    case DH_PROTO_ASUSIO:
    case DH_PROTO_UCOREW:
        UnmapWinIo(hDev, prov->ioctl_unmap, mapped, sec, refObj);
        break;
    case DH_PROTO_REDFOX:
        UnmapRedFox(hDev, prov->ioctl_unmap, mapped, sec, refObj);
        break;
    default: break;
    }
    return ok;
}

BOOL DhProviderPhysWrite(HANDLE hDev, const DH_PROVIDER* prov,
                         u64 phys, const void* src, u32 size)
{
    if (!size || !hDev || !prov) return FALSE;

    HANDLE sec = NULL; PVOID refObj = NULL; PVOID mapped = NULL;
    u32 pageOff = 0;

    switch (prov->protocol) {
    case DH_PROTO_WINIO:
    case DH_PROTO_ASUSIO:
    case DH_PROTO_UCOREW:
        mapped = MapWinIo(hDev, prov->ioctl_map, phys, size, &sec, &refObj);
        break;
    case DH_PROTO_REDFOX:
        mapped = MapRedFox(hDev, prov->ioctl_map, phys, size, &sec, &refObj, &pageOff);
        break;
    default:
        return FALSE;
    }
    if (!mapped) return FALSE;

    BOOL ok = TRUE;
    __try {
        memcpy((u8*)mapped + pageOff, src, size);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        ok = FALSE;
    }

    switch (prov->protocol) {
    case DH_PROTO_WINIO:
    case DH_PROTO_ASUSIO:
    case DH_PROTO_UCOREW:
        UnmapWinIo(hDev, prov->ioctl_unmap, mapped, sec, refObj);
        break;
    case DH_PROTO_REDFOX:
        UnmapRedFox(hDev, prov->ioctl_unmap, mapped, sec, refObj);
        break;
    default: break;
    }
    return ok;
}

// -----------------------------------------------------------------------------
// Try one provider: unpack bin -> temp.sys -> SCM install+start -> open device
// -----------------------------------------------------------------------------

BOOL DhProviderTry(const DH_PROVIDER* prov, HANDLE* out_dev)
{
    if (!prov || !out_dev) return FALSE;

    // Locate .bin — try (in order):
    //   1. env %DH_INSTALL_DIR%\db\<name>.bin  — launcher-set install path
    //   2. <exeDir>\db\<name>.bin              — flat install layout
    //   3. <exeDir>\<name>.bin                 — flat next-to-exe
    //   4. <exeDir>\..\src\db\<name>.bin       — dev tree
    //   5. C:\DeltaHack\db\<name>.bin          — hardcoded fallback for
    //                                            launcher-spawned temp exec
    wchar_t exeDir[MAX_PATH] = {0};
    GetModuleFileNameW(NULL, exeDir, MAX_PATH);
    PathRemoveFileSpecW(exeDir);
    wchar_t binPath[MAX_PATH * 2];
    HANDLE h = INVALID_HANDLE_VALUE;

    // 1. Launcher-set install dir (set by App.exe before CreateProcess).
    {
        wchar_t installDir[MAX_PATH] = {0};
        DWORD envLen = GetEnvironmentVariableW(L"DH_INSTALL_DIR",
                                               installDir, MAX_PATH);
        if (envLen > 0 && envLen < MAX_PATH) {
            _snwprintf(binPath, MAX_PATH * 2, L"%ws\\db\\%ws",
                       installDir, prov->bin_filename);
            h = CreateFileW(binPath, GENERIC_READ, FILE_SHARE_READ, NULL,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        }
    }
    if (h == INVALID_HANDLE_VALUE) {
        _snwprintf(binPath, MAX_PATH * 2, L"%ws\\db\\%ws", exeDir, prov->bin_filename);
        h = CreateFileW(binPath, GENERIC_READ, FILE_SHARE_READ, NULL,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    }
    if (h == INVALID_HANDLE_VALUE) {
        _snwprintf(binPath, MAX_PATH * 2, L"%ws\\%ws", exeDir, prov->bin_filename);
        h = CreateFileW(binPath, GENERIC_READ, FILE_SHARE_READ, NULL,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    }
    if (h == INVALID_HANDLE_VALUE) {
        _snwprintf(binPath, MAX_PATH * 2, L"%ws\\..\\src\\db\\%ws", exeDir, prov->bin_filename);
        h = CreateFileW(binPath, GENERIC_READ, FILE_SHARE_READ, NULL,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    }
    if (h == INVALID_HANDLE_VALUE) {
        _snwprintf(binPath, MAX_PATH * 2, L"C:\\DeltaHack\\db\\%ws", prov->bin_filename);
        h = CreateFileW(binPath, GENERIC_READ, FILE_SHARE_READ, NULL,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    }
    if (h == INVALID_HANDLE_VALUE) {
        DH_ERROR("provider %s: bin not found (last tried: %ws)", prov->name, binPath);
        return FALSE;
    }
    DWORD binSize = GetFileSize(h, NULL);
    u8* raw = (u8*)HeapAlloc(GetProcessHeap(), 0, binSize);
    DWORD got = 0;
    if (!ReadFile(h, raw, binSize, &got, NULL) || got != binSize) {
        DH_ERROR("provider %s: read bin failed", prov->name);
        HeapFree(GetProcessHeap(), 0, raw);
        CloseHandle(h);
        return FALSE;
    }
    CloseHandle(h);

    // Optional pre-open callback (AsIO3 zombie proc, etc.)
    if (prov->pre_open && !prov->pre_open()) {
        DH_ERROR("provider %s: pre_open failed", prov->name);
        HeapFree(GetProcessHeap(), 0, raw);
        return FALSE;
    }

    void* decoded = NULL;
    DWORD decSize = 0;
    BOOL unpacked = DbUnpack(raw, binSize, &decoded, &decSize);
    HeapFree(GetProcessHeap(), 0, raw);
    if (!unpacked || !decoded) {
        DH_ERROR("provider %s: DbUnpack failed", prov->name);
        return FALSE;
    }

    // Write .sys to %TEMP%
    wchar_t sysPath[MAX_PATH * 2];
    wchar_t tempDir[MAX_PATH];
    GetTempPathW(MAX_PATH, tempDir);
    _snwprintf(sysPath, MAX_PATH * 2, L"%wsdh_%ws_%lu.sys",
               tempDir, prov->svc_name, GetCurrentProcessId());
    h = CreateFileW(sysPath, GENERIC_WRITE, 0, NULL,
                    CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        DH_ERROR("provider %s: create sys failed", prov->name);
        HeapFree(GetProcessHeap(), 0, decoded);
        return FALSE;
    }
    WriteFile(h, decoded, decSize, &got, NULL);
    CloseHandle(h);
    HeapFree(GetProcessHeap(), 0, decoded);

    // Fast-path: device may already be open from prior session
    wchar_t devPath[128];
    _snwprintf(devPath, 128, L"\\\\.\\%ws", prov->dev_name);
    HANDLE probeDev = CreateFileW(devPath, GENERIC_READ | GENERIC_WRITE,
                                   0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (probeDev != INVALID_HANDLE_VALUE) {
        DH_INFO("provider %s: device already resident, reusing %ws", prov->name, devPath);
        *out_dev = probeDev;
        return TRUE;
    }

    // SCM install + start + open device (fresh install)
    wchar_t svcName[64];
    _snwprintf(svcName, 64, L"%ws_%lu", prov->svc_name, GetCurrentProcessId());
    DH_DRIVER drv = {0};
    if (!DhDrvInstall(&drv, svcName, prov->dev_name, sysPath)) return FALSE;
    if (!DhDrvStart(&drv))  { DhDrvStop(&drv); return FALSE; }

    // Optional unlock handshake
    if (prov->unlock && !prov->unlock(drv.hDevice)) {
        DH_ERROR("provider %s: unlock failed", prov->name);
        DhDrvStop(&drv);
        return FALSE;
    }

    if (!DhDrvOpenDevice(&drv)) {
        DH_ERROR("provider %s: open device '\\\\.\\%ws' failed", prov->name, prov->dev_name);
        DhDrvStop(&drv);
        return FALSE;
    }

    // NO smoke test — sending wrong IOCTL to wrong driver family = BSOD risk.
    // Provider is considered "live" if it opened device successfully.
    // Actual IOCTL verification must happen on caller side after provider selection.
    DH_INFO("provider %s STARTED: dev=\\\\.\\%ws (no smoke test — safety)",
            prov->name, prov->dev_name);
    *out_dev = drv.hDevice;
    return TRUE;
}

// -----------------------------------------------------------------------------
// Iterate providers by priority, pick first that works
// -----------------------------------------------------------------------------

const DH_PROVIDER* DhProviderSelect(HANDLE* out_dev, u32* out_flags)
{
    VMProtectBeginUltra("DhProviderSelect");
    if (out_flags) *out_flags = 0;
    // Sort providers by descending priority (static — done at init once)
    // For simplicity: try in registry order (priority pre-sorted in registry).
    for (int i = 0; i < g_provider_count; i++) {
        const DH_PROVIDER* p = &g_providers[i];
        DH_INFO("trying provider [#%u %s pri=%d]...", p->kdu_id, p->name, p->priority);
        if (DhProviderTry(p, out_dev)) {
            if (out_flags) *out_flags = p->avail_flags;
            VMProtectEnd();
            return p;
        }
    }
    VMProtectEnd();
    return NULL;
}

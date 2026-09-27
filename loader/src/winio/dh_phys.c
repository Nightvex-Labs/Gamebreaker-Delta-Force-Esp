#include "../../inc/dh_phys.h"
#include "../../inc/dh_provider.h"

// If g_active_provider != NULL, PhysRead/PhysWrite dispatch through
// provider layer (multi-driver support). Otherwise falls back to the
// hardcoded EneIo64 protocol below (legacy path).
extern const DH_PROVIDER* g_active_provider;

#define IOCTL_WINIO_MAP   0x80102040u
#define IOCTL_WINIO_UNMAP 0x80102044u

#pragma pack(push, 1)
typedef struct {
    ULONG_PTR ViewSize;
    ULONG_PTR BusAddress;
    HANDLE    SectionHandle;
    PVOID     BaseAddress;
    PVOID     ReferencedObject;
} WINIO_PHYS_INFO;
#pragma pack(pop)

static BOOL CallDriver(HANDLE hDev, DWORD ioctl, void* inBuf, DWORD inSz,
                        void* outBuf, DWORD outSz)
{
    DWORD bytes = 0;
    return DeviceIoControl(hDev, ioctl, inBuf, inSz, outBuf, outSz, &bytes, NULL);
}

static PVOID MapPhys(HANDLE hDev, u64 physAddr, u32 size,
                     HANDLE* secH, PVOID* refObj)
{
    WINIO_PHYS_INFO req;
    memset(&req, 0, sizeof(req));
    req.ViewSize   = size;
    req.BusAddress = (ULONG_PTR)physAddr;

    if (!CallDriver(hDev, IOCTL_WINIO_MAP, &req, sizeof(req), &req, sizeof(req)))
        return NULL;

    *secH   = req.SectionHandle;
    *refObj = req.ReferencedObject;
    return req.BaseAddress;
}

static void UnmapPhys(HANDLE hDev, PVOID base, HANDLE secH, PVOID refObj)
{
    WINIO_PHYS_INFO req;
    memset(&req, 0, sizeof(req));
    req.BaseAddress      = base;
    req.SectionHandle    = secH;
    req.ReferencedObject = refObj;
    CallDriver(hDev, IOCTL_WINIO_UNMAP, &req, sizeof(req), &req, sizeof(req));
}

BOOL PhysRead(HANDLE hDev, u64 physAddr, void* buf, u32 size)
{
    if (!size) return FALSE;

    // If active provider registered (multi-driver mode) → dispatch through it.
    if (g_active_provider) {
        return DhProviderPhysRead(hDev, g_active_provider, physAddr, buf, size);
    }

    // Legacy path: EneIo64 hardcoded IOCTL.
    HANDLE  secH   = NULL;
    PVOID   refObj = NULL;
    PVOID   mapped = MapPhys(hDev, physAddr, size, &secH, &refObj);
    if (!mapped) return FALSE;

    BOOL ok = TRUE;
    __try {
        memcpy(buf, mapped, size);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        ok = FALSE;
    }

    UnmapPhys(hDev, mapped, secH, refObj);
    return ok;
}

BOOL PhysWrite(HANDLE hDev, u64 physAddr, const void* buf, u32 size)
{
    if (!size) return FALSE;

    if (g_active_provider) {
        return DhProviderPhysWrite(hDev, g_active_provider, physAddr, buf, size);
    }

    HANDLE  secH   = NULL;
    PVOID   refObj = NULL;
    PVOID   mapped = MapPhys(hDev, physAddr, size, &secH, &refObj);
    if (!mapped) return FALSE;

    BOOL ok = TRUE;
    __try {
        memcpy(mapped, buf, size);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        ok = FALSE;
    }

    UnmapPhys(hDev, mapped, secH, refObj);
    return ok;
}

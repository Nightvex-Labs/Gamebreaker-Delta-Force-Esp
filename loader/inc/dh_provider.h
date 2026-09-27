// DeltaHack — provider abstraction for kdu-family kernel drivers.
//
// Each provider = one signed vendor driver used as physical R/W primitive.
// Providers vary on: device name, IOCTL codes, request struct layout,
// unlock handshake (some require AES challenge, some don't).
//
// Runtime selection: loader tries providers in priority order, first that
// (1) passes HVCI, (2) CreateFile succeeds, (3) IOCTL smoke test works.
#pragma once
#include "dh_common.h"

// Provider protocol family — dictates request struct layout + IOCTL codes.
typedef enum {
    DH_PROTO_WINIO,     // EneIo64 / MsIo64 / EneTechIo64 / MSI winio / wnBios64 / PGRHostControl
    DH_PROTO_ASUSIO,    // AsIO2 / AsIO3 — ASUS-specific
    DH_PROTO_REDFOX,    // inpoutx64 — HiRes/RedFox
    DH_PROTO_UCOREW,    // ATSZIO64 / older ASUS
    DH_PROTO_CUSTOM,    // provider has its own protocol (needs custom callbacks)
} DH_PROTO;

// Availability flag — what environments this provider passes.
typedef enum {
    DH_AVAIL_HVCI_ON  = (1u << 0),   // survives HVCI + VBS enforcement
    DH_AVAIL_HYPER_V  = (1u << 1),   // safe under Hyper-V root partition
    DH_AVAIL_INTEL    = (1u << 2),   // works on Intel CPUs
    DH_AVAIL_AMD      = (1u << 3),   // works on AMD CPUs
    DH_AVAIL_TESTED   = (1u << 7),   // has been LIVE tested on real hardware
} DH_AVAIL;

// Optional unlock callback — invoked after CreateFile, before first R/W IOCTL.
typedef BOOL (*DhProviderUnlockFn)(HANDLE hDev);

// Optional pre-open callback — invoked BEFORE CreateFile.
// Some drivers require external service setup (e.g. AsIO3 zombie process).
typedef BOOL (*DhProviderPreOpenFn)(void);

// One kdu-family provider description.
typedef struct DH_PROVIDER {
    // Metadata
    u32          kdu_id;         // matches kdu KDU_PROVIDER_* numeric ID
    const char*  name;           // human-readable ("EneIo64", "AsIO3", ...)
    DH_PROTO     protocol;       // which IOCTL family (see below)
    u32          avail_flags;    // OR of DH_AVAIL_*

    // Deploy details
    const wchar_t* svc_name;     // Windows service name (short, no path)
    const wchar_t* dev_name;     // NT device name after `\\.\` (e.g. L"EneIo")
    const wchar_t* bin_filename; // driver .bin (DBPACK-compressed) in src/db/

    // IOCTL codes (protocol-family-specific)
    DWORD        ioctl_map;      // physical memory map IOCTL
    DWORD        ioctl_unmap;    // physical memory unmap IOCTL

    // Optional callbacks
    DhProviderPreOpenFn  pre_open;   // spin up support process / unpack helper
    DhProviderUnlockFn   unlock;     // AES handshake or similar after open

    // Priority hint (higher = try first). Loader sorts by this.
    int          priority;
} DH_PROVIDER;

// Provider registry — populated at compile time in dh_prov_registry.c
extern const DH_PROVIDER g_providers[];
extern const int         g_provider_count;

// Runtime API ---------------------------------------------------------------

// Test one provider: unpack .bin, install service, start, open device,
// probe with a benign IOCTL. Returns TRUE if provider is usable.
// On success, `out_dev` is a HANDLE to the opened device.
BOOL DhProviderTry(const DH_PROVIDER* prov, HANDLE* out_dev);

// Iterate providers by priority and return the first that works.
// Also fills the compat flags observed at runtime.
const DH_PROVIDER* DhProviderSelect(HANDLE* out_dev, u32* out_flags);

// Physical R/W dispatched through the active provider.
BOOL DhProviderPhysRead(HANDLE hDev, const DH_PROVIDER* prov,
                        u64 phys, void* dst, u32 size);
BOOL DhProviderPhysWrite(HANDLE hDev, const DH_PROVIDER* prov,
                         u64 phys, const void* src, u32 size);

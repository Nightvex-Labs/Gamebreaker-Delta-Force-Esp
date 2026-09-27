// DeltaHack — full kdu provider registry.
//
// Every provider from kdu that we may ever want to use, plus HVCI status
// observed on our reference 2PC (AMD Zen4, Win11 25H2, HVCI ON test 2026-09-20).
//
// Priority hierarchy:
//   1000+  HVCI-safe primary  — start here
//    500+  HVCI-safe fallback
//    100+  HVCI-off only (no blocklist by user)
//     50+  requires vendor-specific pre-open (AsIO3 zombie proc)
//      0   unknown / needs live verification
//
// IOCTL codes derived from kdu/Source/Hamakaze/idrv/winio.h:
//   WINIO_MAP     0x80102040  UNMAP  0x80102044
//   ASUSIO_MAP    0xA040A480  UNMAP  0xA0402450
//   UCOREW64_MAP  ...         UNMAP  ...
//   REDFOX_MAP    0x9C402028  UNMAP  0x9C402030
#include "../../inc/dh_provider.h"

// WinIo family standard codes
#define IOCTL_WINIO_MAP     0x80102040u
#define IOCTL_WINIO_UNMAP   0x80102044u

// ASUSIO family
#define IOCTL_ASUSIO_MAP    0xA040A480u
#define IOCTL_ASUSIO_UNMAP  0xA0402450u

// UCOREW64 family (older ASUS ATSZIO)
#define IOCTL_UCOREW_MAP    0x00FA2EE8u
#define IOCTL_UCOREW_UNMAP  0x00FA2EECu

// REDFOX family (HiRes/inpoutx64) — computed from kdu winio.h:
// CTL_CODE(FILE_DEVICE_REDFOX=0x9C40, FUNCID, METHOD_BUFFERED=0, FILE_ANY_ACCESS=0)
#define IOCTL_REDFOX_MAP    0x9C40201Cu   // FUNCID 0x807
#define IOCTL_REDFOX_UNMAP  0x9C402020u   // FUNCID 0x808

// -----------------------------------------------------------------------------
// Provider descriptors — ordered roughly by priority
// -----------------------------------------------------------------------------
const DH_PROVIDER g_providers[] = {
    // ============ HVCI-SAFE — tested on 2PC 2026-09-20 (top priority) =========
    {
        .kdu_id      = 26,
        .name        = "inpoutx64",
        .protocol    = DH_PROTO_REDFOX,
        .avail_flags = DH_AVAIL_HVCI_ON | DH_AVAIL_HYPER_V | DH_AVAIL_INTEL | DH_AVAIL_AMD | DH_AVAIL_TESTED,
        .svc_name    = L"dh_inpoutx",
        .dev_name    = L"inpoutx64",
        .bin_filename = L"inpoutx64.bin",
        .ioctl_map   = IOCTL_REDFOX_MAP,
        .ioctl_unmap = IOCTL_REDFOX_UNMAP,
        .priority    = 1000,
    },
    // pmxdrv64 uses UNIQUE IOCTL codes (not WINIO family). Disabled until
    // proper Intel PMX handler ported. See kdu/idrv/intel.cpp lines 402/445.
    // {  Intel pmxdrv — TODO port  },
    {
        .kdu_id      = 44,
        .name        = "PdFwKrnl (AMD Adrenalin)",
        .protocol    = DH_PROTO_WINIO,
        .avail_flags = DH_AVAIL_HVCI_ON | DH_AVAIL_HYPER_V | DH_AVAIL_AMD | DH_AVAIL_TESTED,
        .svc_name    = L"dh_pdfwkrnl",
        .dev_name    = L"PdFwKrnl",
        .bin_filename = L"PdFwKrnl.bin",
        .ioctl_map   = IOCTL_WINIO_MAP,
        .ioctl_unmap = IOCTL_WINIO_UNMAP,
        .priority    = 900,
    },
    {
        .kdu_id      = 7,
        .name        = "WinRing0x64 (EVGA)",
        .protocol    = DH_PROTO_WINIO,
        .avail_flags = DH_AVAIL_HVCI_ON | DH_AVAIL_HYPER_V | DH_AVAIL_INTEL | DH_AVAIL_AMD | DH_AVAIL_TESTED,
        .svc_name    = L"dh_winring0",
        .dev_name    = L"WinRing0_1_2_0",
        .bin_filename = L"WinRing0x64.bin",
        .ioctl_map   = IOCTL_WINIO_MAP,
        .ioctl_unmap = IOCTL_WINIO_UNMAP,
        .priority    = 850,
    },
    {
        .kdu_id      = 55,
        .name        = "ThrottleStop",
        .protocol    = DH_PROTO_WINIO,
        .avail_flags = DH_AVAIL_HVCI_ON | DH_AVAIL_HYPER_V | DH_AVAIL_INTEL | DH_AVAIL_TESTED,
        .svc_name    = L"dh_throttle",
        .dev_name    = L"ThrottleStop",
        .bin_filename = L"ThrottleStop.bin",
        .ioctl_map   = IOCTL_WINIO_MAP,
        .ioctl_unmap = IOCTL_WINIO_UNMAP,
        .priority    = 800,
    },
    {
        .kdu_id      = 47,
        .name        = "EleetX1 (EVGA)",
        .protocol    = DH_PROTO_WINIO,
        .avail_flags = DH_AVAIL_HVCI_ON | DH_AVAIL_HYPER_V | DH_AVAIL_INTEL | DH_AVAIL_AMD | DH_AVAIL_TESTED,
        .svc_name    = L"dh_eleet",
        .dev_name    = L"EleetX1",
        .bin_filename = L"eleetx1.bin",
        .ioctl_map   = IOCTL_WINIO_MAP,
        .ioctl_unmap = IOCTL_WINIO_UNMAP,
        .priority    = 750,
    },
    {
        .kdu_id      = 33,
        .name        = "Dell pcdsrvc (dbutildrv2)",
        .protocol    = DH_PROTO_WINIO,
        .avail_flags = DH_AVAIL_HVCI_ON | DH_AVAIL_HYPER_V | DH_AVAIL_INTEL | DH_AVAIL_AMD | DH_AVAIL_TESTED,
        .svc_name    = L"dh_dbutil2",
        .dev_name    = L"DBUtilDrv2",
        .bin_filename = L"dbutildrv2.bin",
        .ioctl_map   = IOCTL_WINIO_MAP,
        .ioctl_unmap = IOCTL_WINIO_UNMAP,
        .priority    = 700,
    },
    {
        .kdu_id      = 30,
        .name        = "AMD Ryzen Master",
        .protocol    = DH_PROTO_WINIO,
        .avail_flags = DH_AVAIL_HVCI_ON | DH_AVAIL_HYPER_V | DH_AVAIL_AMD | DH_AVAIL_TESTED,
        .svc_name    = L"dh_ryzenmaster",
        .dev_name    = L"AMDRyzenMasterIODriver",
        .bin_filename = L"AMDRyzenMasterDriver.bin",
        .ioctl_map   = IOCTL_WINIO_MAP,
        .ioctl_unmap = IOCTL_WINIO_UNMAP,
        .priority    = 650,
    },
    {
        .kdu_id      = 45,
        .name        = "AODDriver (AMD OverDrive)",
        .protocol    = DH_PROTO_WINIO,
        .avail_flags = DH_AVAIL_HVCI_ON | DH_AVAIL_HYPER_V | DH_AVAIL_AMD | DH_AVAIL_TESTED,
        .svc_name    = L"dh_aoddriver",
        .dev_name    = L"AODDriver",
        .bin_filename = L"AODDriver215.bin",
        .ioctl_map   = IOCTL_WINIO_MAP,
        .ioctl_unmap = IOCTL_WINIO_UNMAP,
        .priority    = 600,
    },
    {
        .kdu_id      = 29,
        .name        = "ALSysIO64 (Core Temp)",
        .protocol    = DH_PROTO_WINIO,
        .avail_flags = DH_AVAIL_HVCI_ON | DH_AVAIL_HYPER_V | DH_AVAIL_INTEL | DH_AVAIL_AMD | DH_AVAIL_TESTED,
        .svc_name    = L"dh_alsysio",
        .dev_name    = L"ALSysIO",
        .bin_filename = L"ALSysIO64.bin",
        .ioctl_map   = IOCTL_WINIO_MAP,
        .ioctl_unmap = IOCTL_WINIO_UNMAP,
        .priority    = 550,
    },
    {
        .kdu_id      = 53,
        .name        = "HwRwDrv (Jun Liu)",
        .protocol    = DH_PROTO_WINIO,
        .avail_flags = DH_AVAIL_HVCI_ON | DH_AVAIL_HYPER_V | DH_AVAIL_INTEL | DH_AVAIL_AMD | DH_AVAIL_TESTED,
        .svc_name    = L"dh_hwrw",
        .dev_name    = L"HwRwDrv",
        .bin_filename = L"HwRwDrv.x64.bin",
        .ioctl_map   = IOCTL_WINIO_MAP,
        .ioctl_unmap = IOCTL_WINIO_UNMAP,
        .priority    = 520,
    },
    {
        .kdu_id      = 60,
        .name        = "WinHwDrv (Shangke)",
        .protocol    = DH_PROTO_WINIO,
        .avail_flags = DH_AVAIL_HVCI_ON | DH_AVAIL_HYPER_V | DH_AVAIL_INTEL | DH_AVAIL_AMD | DH_AVAIL_TESTED,
        .svc_name    = L"dh_winhwdrv",
        .dev_name    = L"WinHwDrv",
        .bin_filename = L"WinHwDrv64.bin",
        .ioctl_map   = IOCTL_WINIO_MAP,
        .ioctl_unmap = IOCTL_WINIO_UNMAP,
        .priority    = 500,
    },
    // ============ HVCI-SAFE but LnvMSRIO-family: Hyper-V-risky per ABI ==========
    {
        .kdu_id      = 57,
        .name        = "LnvMSRIO (Lenovo)",
        .protocol    = DH_PROTO_WINIO,
        .avail_flags = DH_AVAIL_HVCI_ON | DH_AVAIL_INTEL | DH_AVAIL_AMD | DH_AVAIL_TESTED,
                       /* NOTE: NO DH_AVAIL_HYPER_V — ABI history shows BSOD */
        .svc_name    = L"dh_lnvmsr",
        .dev_name    = L"LnvMSRIO",
        .bin_filename = L"LnvMSRIO.bin",
        .ioctl_map   = IOCTL_WINIO_MAP,
        .ioctl_unmap = IOCTL_WINIO_UNMAP,
        .priority    = 300,
    },
    {
        .kdu_id      = 13,
        .name        = "AsIO2 (ASUSTeK)",
        .protocol    = DH_PROTO_ASUSIO,
        .avail_flags = DH_AVAIL_HVCI_ON | DH_AVAIL_HYPER_V | DH_AVAIL_INTEL | DH_AVAIL_AMD | DH_AVAIL_TESTED,
        .svc_name    = L"dh_asio2",
        .dev_name    = L"Asusgio2",
        .bin_filename = L"AsIO2.bin",
        .ioctl_map   = IOCTL_ASUSIO_MAP,
        .ioctl_unmap = IOCTL_ASUSIO_UNMAP,
        .priority    = 400,
    },
    {
        .kdu_id      = 10,
        .name        = "RtkIo (Realtek)",
        .protocol    = DH_PROTO_WINIO,
        .avail_flags = DH_AVAIL_HVCI_ON | DH_AVAIL_HYPER_V | DH_AVAIL_INTEL | DH_AVAIL_AMD | DH_AVAIL_TESTED,
        .svc_name    = L"dh_rtkio",
        .dev_name    = L"RtkIo",
        .bin_filename = L"rtkio64.bin",
        .ioctl_map   = IOCTL_WINIO_MAP,
        .ioctl_unmap = IOCTL_WINIO_UNMAP,
        .priority    = 470,
    },
    {
        .kdu_id      = 56,
        .name        = "TpwSav (Toshiba)",
        .protocol    = DH_PROTO_WINIO,
        .avail_flags = DH_AVAIL_HVCI_ON | DH_AVAIL_HYPER_V | DH_AVAIL_INTEL | DH_AVAIL_AMD | DH_AVAIL_TESTED,
        .svc_name    = L"dh_tpwsav",
        .dev_name    = L"TpwSav",
        .bin_filename = L"TpwSav.bin",
        .ioctl_map   = IOCTL_WINIO_MAP,
        .ioctl_unmap = IOCTL_WINIO_UNMAP,
        .priority    = 450,
    },
    // ============ HVCI-OFF-ONLY (blocked by Microsoft Vulnerable Driver Blocklist)
    {
        .kdu_id      = 6,
        .name        = "EneIo64 (G.SKILL) [HVCI-OFF]",
        .protocol    = DH_PROTO_WINIO,
        .avail_flags = DH_AVAIL_HYPER_V | DH_AVAIL_INTEL | DH_AVAIL_AMD | DH_AVAIL_TESTED,
                       /* NO DH_AVAIL_HVCI_ON — cert revoked */
        .svc_name    = L"dh_eneio",
        .dev_name    = L"EneIo",
        .bin_filename = L"EneIo64.bin",
        .ioctl_map   = IOCTL_WINIO_MAP,
        .ioctl_unmap = IOCTL_WINIO_UNMAP,
        .priority    = 200,
    },
    {
        .kdu_id      = 11,
        .name        = "EneTechIo64B (MSI Dragon Center) [HVCI-OFF]",
        .protocol    = DH_PROTO_WINIO,
        .avail_flags = DH_AVAIL_HYPER_V | DH_AVAIL_INTEL | DH_AVAIL_AMD | DH_AVAIL_TESTED,
        .svc_name    = L"dh_enetech2",
        .dev_name    = L"EneTechIo",
        .bin_filename = L"ene2.bin",
        .ioctl_map   = IOCTL_WINIO_MAP,
        .ioctl_unmap = IOCTL_WINIO_UNMAP,
        .priority    = 180,
    },
    {
        .kdu_id      = 4,
        .name        = "MsIo64 (Patriot) [HVCI-OFF]",
        .protocol    = DH_PROTO_WINIO,
        .avail_flags = DH_AVAIL_HYPER_V | DH_AVAIL_INTEL | DH_AVAIL_AMD | DH_AVAIL_TESTED,
        .svc_name    = L"dh_msio64",
        .dev_name    = L"MsIo",
        .bin_filename = L"MsIo64.bin",
        .ioctl_map   = IOCTL_WINIO_MAP,
        .ioctl_unmap = IOCTL_WINIO_UNMAP,
        .priority    = 170,
    },
    {
        .kdu_id      = 20,
        .name        = "Dell DBUtil2.7 [HVCI-OFF]",
        .protocol    = DH_PROTO_WINIO,
        .avail_flags = DH_AVAIL_HYPER_V | DH_AVAIL_INTEL | DH_AVAIL_AMD | DH_AVAIL_TESTED,
        .svc_name    = L"dh_dbutil23",
        .dev_name    = L"DBUtil_2_3",
        .bin_filename = L"DbUtil2_3.bin",
        .ioctl_map   = IOCTL_WINIO_MAP,
        .ioctl_unmap = IOCTL_WINIO_UNMAP,
        .priority    = 160,
    },
    {
        .kdu_id      = 12,
        .name        = "LHA (LG Device Manager) [HVCI-OFF]",
        .protocol    = DH_PROTO_WINIO,
        .avail_flags = DH_AVAIL_HYPER_V | DH_AVAIL_INTEL | DH_AVAIL_AMD | DH_AVAIL_TESTED,
        .svc_name    = L"dh_lha",
        .dev_name    = L"LHA",
        .bin_filename = L"LDD.bin",
        .ioctl_map   = IOCTL_WINIO_MAP,
        .ioctl_unmap = IOCTL_WINIO_UNMAP,
        .priority    = 150,
    },
    // NOTE: many more can be added, all follow the same pattern.
    // See kdu/Source/Utils/DBPACK/drv/*.bin for full inventory.
};

const int g_provider_count = (int)(sizeof(g_providers) / sizeof(g_providers[0]));

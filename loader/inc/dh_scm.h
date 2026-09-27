#pragma once
#include "dh_common.h"

typedef struct {
    SC_HANDLE hSCM;
    SC_HANDLE hSvc;
    HANDLE    hDevice;
    wchar_t   svcName[64];
    wchar_t   devPath[128];
    wchar_t   sysPath[MAX_PATH];
} DH_DRIVER;

BOOL DhDrvInstall(DH_DRIVER* d, const wchar_t* svcName,
                  const wchar_t* devName, const wchar_t* sysPath);
BOOL DhDrvStart(DH_DRIVER* d);
BOOL DhDrvOpenDevice(DH_DRIVER* d);
void DhDrvStop(DH_DRIVER* d);
void DhDrvUninstall(DH_DRIVER* d);
void DhDrvCleanup(DH_DRIVER* d);

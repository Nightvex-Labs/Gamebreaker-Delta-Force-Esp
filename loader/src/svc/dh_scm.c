#include "../../inc/dh_scm.h"

BOOL DhDrvInstall(DH_DRIVER* d, const wchar_t* svcName,
                  const wchar_t* devName, const wchar_t* sysPath)
{
    memset(d, 0, sizeof(*d));
    wcscpy_s(d->svcName, 64, svcName);
    _snwprintf(d->devPath, 128, L"\\\\.\\%s", devName);
    wcscpy_s(d->sysPath, MAX_PATH, sysPath);

    d->hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!d->hSCM) {
        DH_ERROR("OpenSCManager failed (gle=%lu)", GetLastError());
        return FALSE;
    }

    // Retry up to ~10s if service is marked-for-delete from a previous run
    for (int attempt = 0; attempt < 20; attempt++) {
        d->hSvc = CreateServiceW(d->hSCM, svcName, svcName,
            SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL, sysPath, NULL, NULL, NULL, NULL, NULL);

        if (d->hSvc) return TRUE;

        DWORD gle = GetLastError();
        if (gle == ERROR_SERVICE_EXISTS) {
            d->hSvc = OpenServiceW(d->hSCM, svcName, SERVICE_ALL_ACCESS);
            if (!d->hSvc) {
                DH_ERROR("OpenService failed (gle=%lu)", GetLastError());
                return FALSE;
            }
            DH_INFO("service '%ls' already exists, reusing", svcName);
            return TRUE;
        }
        if (gle == ERROR_SERVICE_MARKED_FOR_DELETE) {
            if (attempt == 0)
                DH_INFO("service '%ls' marked-for-delete, waiting for purge...", svcName);
            Sleep(500);
            continue;
        }
        DH_ERROR("CreateService failed (gle=%lu)", gle);
        return FALSE;
    }
    DH_ERROR("service '%ls' still marked-for-delete after 10s", svcName);
    return FALSE;
}

BOOL DhDrvStart(DH_DRIVER* d)
{
    if (!d->hSvc) return FALSE;
    if (!StartServiceW(d->hSvc, 0, NULL)) {
        DWORD gle = GetLastError();
        if (gle == ERROR_SERVICE_ALREADY_RUNNING) {
            DH_INFO("service already running");
            return TRUE;
        }
        DH_ERROR("StartService failed (gle=%lu)", gle);
        return FALSE;
    }
    return TRUE;
}

BOOL DhDrvOpenDevice(DH_DRIVER* d)
{
    d->hDevice = CreateFileW(d->devPath, GENERIC_READ | GENERIC_WRITE,
        0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (d->hDevice == INVALID_HANDLE_VALUE) {
        d->hDevice = NULL;
        DH_ERROR("open device '%ls' failed (gle=%lu)", d->devPath, GetLastError());
        return FALSE;
    }
    return TRUE;
}

void DhDrvStop(DH_DRIVER* d)
{
    if (d->hSvc) {
        SERVICE_STATUS ss;
        ControlService(d->hSvc, SERVICE_CONTROL_STOP, &ss);
    }
}

void DhDrvUninstall(DH_DRIVER* d)
{
    if (d->hSvc) {
        DeleteService(d->hSvc);
    }
}

void DhDrvCleanup(DH_DRIVER* d)
{
    if (d->hDevice) { CloseHandle(d->hDevice); d->hDevice = NULL; }
    if (d->hSvc)    { CloseServiceHandle(d->hSvc); d->hSvc = NULL; }
    if (d->hSCM)    { CloseServiceHandle(d->hSCM); d->hSCM = NULL; }
}

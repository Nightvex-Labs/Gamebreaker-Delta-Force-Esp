// dh_system_spawn.c — elevate self to SYSTEM (S-1-5-18) via Task Scheduler.
//
// Why: kdu physical-memory reads from user context (even elevated Admin) get
// hit by ACE decoy filter — EPROCESS DTB comes back as fakes. SYSTEM context
// walks bypass the filter cleanly. Overlay must stay in user session 1 for
// D3D11 rendering, so we split: SYSTEM daemon-esp does kdu + decrypt +
// publishes to shmem; user-session overlay reads shmem + renders.
//
// Method: schtasks /Create with UserId=S-1-5-18 (SYSTEM), RunLevel=HighestAvailable,
// then /Run + /Delete. Task fires once, spawns our own exe with `daemon-esp` arg,
// runs as SYSTEM. Task cleaned up ~500ms later.

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>
#include <string.h>
#include "../../inc/dh_common.h"

#pragma comment(lib, "bcrypt.lib")

extern void dh_diag_line(const char* fmt, ...);

// Detect: are we already SYSTEM? Check via TokenUser SID = S-1-5-18.
BOOL DhIsSystem(void)
{
    HANDLE hTok = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hTok)) return FALSE;

    DWORD needed = 0;
    GetTokenInformation(hTok, TokenUser, NULL, 0, &needed);
    if (needed == 0) { CloseHandle(hTok); return FALSE; }

    TOKEN_USER* tu = (TOKEN_USER*)HeapAlloc(GetProcessHeap(), 0, needed);
    if (!tu) { CloseHandle(hTok); return FALSE; }

    BOOL is_system = FALSE;
    if (GetTokenInformation(hTok, TokenUser, tu, needed, &needed)) {
        // S-1-5-18 = LocalSystem
        SID_IDENTIFIER_AUTHORITY sia = SECURITY_NT_AUTHORITY;
        PSID sys_sid = NULL;
        if (AllocateAndInitializeSid(&sia, 1, SECURITY_LOCAL_SYSTEM_RID,
                                     0,0,0,0,0,0,0, &sys_sid)) {
            is_system = EqualSid(tu->User.Sid, sys_sid);
            FreeSid(sys_sid);
        }
    }
    HeapFree(GetProcessHeap(), 0, tu);
    CloseHandle(hTok);
    return is_system;
}

// Generate a task name that blends with real Windows scheduled tasks.
// Format: "MicrosoftWindowsDiagnosticTask_<8hex>" — mimics MS Diagnostic
// Infrastructure family (blends in tasklist / schtasks /Query output).
static void gen_task_name(wchar_t* out, size_t out_cch)
{
    uint8_t r[4];
    BCryptGenRandom(NULL, r, sizeof(r), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    swprintf(out, out_cch, L"MicrosoftWindowsDiagnosticTask_%02X%02X%02X%02X",
             r[0], r[1], r[2], r[3]);
}

// Write UTF-16LE (with BOM) XML task definition. schtasks /Create /XML
// requires UTF-16 with BOM or it errors "The task XML contains a value
// which is incorrectly formatted".
static BOOL write_task_xml(const wchar_t* xml_path,
                           const wchar_t* self_path,
                           const wchar_t* arg)
{
    HANDLE h = CreateFileW(xml_path, GENERIC_WRITE, 0, NULL,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return FALSE;

    // UTF-16LE BOM
    const uint16_t bom = 0xFEFF;
    DWORD w = 0;
    WriteFile(h, &bom, 2, &w, NULL);

    // XML body — minimal Task Scheduler 1.2 schema (Win7+).
    // Principal UserId=S-1-5-18 → SYSTEM. RunLevel=HighestAvailable to
    // guarantee we get full SYSTEM (not just LocalService).
    // Actions.Exec runs our own exe with "daemon-esp" argument.
    wchar_t xml[4096];
    int n = swprintf(xml, 4096,
        L"<?xml version=\"1.0\" encoding=\"UTF-16\"?>\r\n"
        L"<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\r\n"
        L"  <RegistrationInfo>\r\n"
        L"    <Author>Microsoft Corporation</Author>\r\n"
        L"    <Description>Windows diagnostic data collection.</Description>\r\n"
        L"  </RegistrationInfo>\r\n"
        L"  <Principals>\r\n"
        L"    <Principal id=\"Author\">\r\n"
        L"      <UserId>S-1-5-18</UserId>\r\n"
        L"      <RunLevel>HighestAvailable</RunLevel>\r\n"
        L"    </Principal>\r\n"
        L"  </Principals>\r\n"
        L"  <Settings>\r\n"
        L"    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\r\n"
        L"    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>\r\n"
        L"    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>\r\n"
        L"    <AllowHardTerminate>true</AllowHardTerminate>\r\n"
        L"    <StartWhenAvailable>true</StartWhenAvailable>\r\n"
        L"    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>\r\n"
        L"    <IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd>"
        L"<RestartOnIdle>false</RestartOnIdle></IdleSettings>\r\n"
        L"    <AllowStartOnDemand>true</AllowStartOnDemand>\r\n"
        L"    <Enabled>true</Enabled>\r\n"
        L"    <Hidden>true</Hidden>\r\n"
        L"    <RunOnlyIfIdle>false</RunOnlyIfIdle>\r\n"
        L"    <WakeToRun>false</WakeToRun>\r\n"
        L"    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>\r\n"
        L"    <Priority>4</Priority>\r\n"
        L"  </Settings>\r\n"
        L"  <Actions Context=\"Author\">\r\n"
        L"    <Exec>\r\n"
        L"      <Command>%ls</Command>\r\n"
        L"      <Arguments>%ls</Arguments>\r\n"
        L"    </Exec>\r\n"
        L"  </Actions>\r\n"
        L"</Task>\r\n",
        self_path, arg);
    if (n <= 0) { CloseHandle(h); return FALSE; }
    WriteFile(h, xml, (DWORD)(n * sizeof(wchar_t)), &w, NULL);
    CloseHandle(h);
    return TRUE;
}

// Run schtasks.exe with args, waiting for exit. Returns exit code.
static DWORD run_schtasks(const wchar_t* args)
{
    wchar_t sys32[MAX_PATH];
    GetSystemDirectoryW(sys32, MAX_PATH);
    wchar_t exe[MAX_PATH];
    swprintf(exe, MAX_PATH, L"%s\\schtasks.exe", sys32);

    wchar_t cmdline[4096];
    swprintf(cmdline, 4096, L"\"%s\" %s", exe, args);

    STARTUPINFOW si = { sizeof(si) };
    si.dwFlags     = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = {0};
    if (!CreateProcessW(exe, cmdline, NULL, NULL, FALSE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        return (DWORD)-1;
    }
    WaitForSingleObject(pi.hProcess, 10000);
    DWORD rc = 0;
    GetExitCodeProcess(pi.hProcess, &rc);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return rc;
}

// Spawn our own exe as SYSTEM with argument `daemon-esp`. Uses schtasks
// temp task registered → run → delete. Returns TRUE on schtasks success
// (does NOT verify daemon actually started or shmem got created).
BOOL DhSpawnSelfAsSystemDaemon(void)
{
    // 1. Resolve our own path.
    wchar_t self_path[MAX_PATH];
    if (!GetModuleFileNameW(NULL, self_path, MAX_PATH)) {
        dh_diag_line("sys-spawn: GetModuleFileName failed gle=%lu",
                     (unsigned long)GetLastError());
        return FALSE;
    }

    // 2. Task name + XML path in %TEMP%.
    wchar_t task_name[64];
    gen_task_name(task_name, 64);
    wchar_t tmp_dir[MAX_PATH];
    GetTempPathW(MAX_PATH, tmp_dir);
    wchar_t xml_path[MAX_PATH];
    swprintf(xml_path, MAX_PATH, L"%s%s.xml", tmp_dir, task_name);

    // 3. Write task XML.
    if (!write_task_xml(xml_path, self_path, L"daemon-esp")) {
        dh_diag_line("sys-spawn: write_task_xml failed gle=%lu",
                     (unsigned long)GetLastError());
        return FALSE;
    }
    dh_diag_line("sys-spawn: task xml written -> %ls", xml_path);

    // 4. Create task.
    wchar_t args[8192];
    swprintf(args, 8192, L"/Create /TN \"%s\" /XML \"%s\" /F",
             task_name, xml_path);
    DWORD rc = run_schtasks(args);
    if (rc != 0) {
        dh_diag_line("sys-spawn: schtasks /Create rc=%lu", rc);
        DeleteFileW(xml_path);
        return FALSE;
    }
    dh_diag_line("sys-spawn: task '%ls' created", task_name);

    // 5. Run task.
    swprintf(args, 8192, L"/Run /TN \"%s\"", task_name);
    rc = run_schtasks(args);
    dh_diag_line("sys-spawn: schtasks /Run rc=%lu", rc);

    // 6. Give task ~500ms to actually spawn the process, then delete task.
    Sleep(500);
    swprintf(args, 8192, L"/Delete /TN \"%s\" /F", task_name);
    run_schtasks(args);
    DeleteFileW(xml_path);
    dh_diag_line("sys-spawn: task deleted; SYSTEM daemon spawn attempt done");
    return TRUE;
}

// Wait up to timeout_ms for the daemon-created shmem to appear. Returns TRUE
// if shmem found within timeout.
BOOL DhWaitForDaemonShmem(DWORD timeout_ms)
{
    const wchar_t* SHMEM_NAME = L"Global\\{7A9F3B21-4E2D-4B12-A5F7-8D6E4C9F1B3A}";
    DWORD start = GetTickCount();
    while (GetTickCount() - start < timeout_ms) {
        HANDLE hMap = OpenFileMappingW(FILE_MAP_READ, FALSE, SHMEM_NAME);
        if (hMap) {
            CloseHandle(hMap);
            dh_diag_line("sys-spawn: daemon shmem found after %lu ms",
                         GetTickCount() - start);
            return TRUE;
        }
        Sleep(100);
    }
    dh_diag_line("sys-spawn: daemon shmem NOT found within %lu ms", timeout_ms);
    return FALSE;
}

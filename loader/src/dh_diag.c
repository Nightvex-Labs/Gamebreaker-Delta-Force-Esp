// dh_diag.c — telemetry-friendly per-tick diag writer + periodic process
// snapshot writer. Both target C:\Users\Public\dh_*.log (world-writable,
// so both user-session daemon and any SYSTEM-context spawn append cleanly).
// Launcher stub reads their tails and POSTs them to the koenflow telemetry
// endpoint after the payload exits — see launcher/src/dh_crash_upload.c.
//
// Compile in unconditionally. Silent on file-open failure (private-user
// profile with no C:\Users\Public write = no telemetry, no crash either).

#include <windows.h>
#include <tlhelp32.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>

#define DH_READER_LOG L"C:\\Users\\Public\\dh_reader.log"
#define DH_PROCS_LOG  L"C:\\Users\\Public\\dh_procs.log"
#define DH_LOG_MAX_BYTES  (2 * 1024 * 1024)   // rotate at 2 MB

// Rotate helper — if file grew past cap, truncate to keep last 1 MB (cheap
// approach: read tail into RAM, rewrite file). Runs once per open call.
static void rotate_if_big(const wchar_t* path)
{
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    LARGE_INTEGER sz; GetFileSizeEx(h, &sz);
    if (sz.QuadPart < DH_LOG_MAX_BYTES) { CloseHandle(h); return; }
    DWORD keep = DH_LOG_MAX_BYTES / 2;
    LARGE_INTEGER off; off.QuadPart = sz.QuadPart - keep;
    SetFilePointerEx(h, off, NULL, FILE_BEGIN);
    void* buf = HeapAlloc(GetProcessHeap(), 0, keep);
    if (!buf) { CloseHandle(h); return; }
    DWORD got = 0;
    ReadFile(h, buf, keep, &got, NULL);
    CloseHandle(h);
    if (got == 0) { HeapFree(GetProcessHeap(), 0, buf); return; }
    HANDLE w = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, NULL,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (w != INVALID_HANDLE_VALUE) {
        DWORD wr = 0;
        WriteFile(w, buf, got, &wr, NULL);
        CloseHandle(w);
    }
    HeapFree(GetProcessHeap(), 0, buf);
}

void dh_diag_line(const char* fmt, ...)
{
    // Rotate check on every 512th call to keep amortized cost low.
    static volatile LONG s_call_ctr = 0;
    LONG n = InterlockedIncrement(&s_call_ctr);
    if ((n & 0x1FF) == 0) rotate_if_big(DH_READER_LOG);

    HANDLE h = CreateFileW(DH_READER_LOG, FILE_APPEND_DATA,
                           FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    SetFilePointer(h, 0, NULL, FILE_END);

    char buf[768];
    SYSTEMTIME st; GetLocalTime(&st);
    int hdr = _snprintf_s(buf, sizeof(buf), _TRUNCATE,
        "[%02u:%02u:%02u.%03u pid=%lu] ",
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
        (unsigned long)GetCurrentProcessId());
    va_list ap; va_start(ap, fmt);
    int body_max = (int)sizeof(buf) - hdr - 2;
    if (body_max > 0) {
        _vsnprintf_s(buf + hdr, sizeof(buf) - hdr - 2, _TRUNCATE, fmt, ap);
    }
    va_end(ap);
    size_t total = strnlen_s(buf, sizeof(buf));
    if (total > sizeof(buf) - 2) total = sizeof(buf) - 2;
    buf[total++] = '\r'; buf[total++] = '\n';
    DWORD wr = 0;
    WriteFile(h, buf, (DWORD)total, &wr, NULL);
    CloseHandle(h);
}

// One-shot snapshot: writes tasklist to C:\Users\Public\dh_procs.log with a
// timestamp header. Called every ~30 sec from a dedicated background thread.
static void write_procs_snapshot(void)
{
    rotate_if_big(DH_PROCS_LOG);
    HANDLE h = CreateFileW(DH_PROCS_LOG, FILE_APPEND_DATA,
                           FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    SetFilePointer(h, 0, NULL, FILE_END);

    char hdr[128]; SYSTEMTIME st; GetLocalTime(&st);
    int n = _snprintf_s(hdr, sizeof(hdr), _TRUNCATE,
        "\r\n=== snap %04u-%02u-%02u %02u:%02u:%02u pid=%lu ===\r\n",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
        (unsigned long)GetCurrentProcessId());
    DWORD wr = 0;
    if (n > 0) WriteFile(h, hdr, (DWORD)n, &wr, NULL);

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) { CloseHandle(h); return; }
    PROCESSENTRY32W pe = { sizeof(pe) };
    if (Process32FirstW(snap, &pe)) {
        do {
            char line[512];
            char nameA[128];
            WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1, nameA, sizeof(nameA), NULL, NULL);
            int ln = _snprintf_s(line, sizeof(line), _TRUNCATE,
                "  pid=%-6lu  ppid=%-6lu  threads=%-3lu  %s\r\n",
                (unsigned long)pe.th32ProcessID,
                (unsigned long)pe.th32ParentProcessID,
                (unsigned long)pe.cntThreads,
                nameA);
            if (ln > 0) WriteFile(h, line, (DWORD)ln, &wr, NULL);
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    CloseHandle(h);
}

static DWORD WINAPI procs_snapshot_thread(LPVOID unused)
{
    (void)unused;
    for (;;) {
        write_procs_snapshot();
        Sleep(30 * 1000);   // snapshot every 30s
    }
}

// Kicked off once from main.c after driver_up + before overlay init. No stop:
// thread dies with process. Idempotent — called from any spawn path.
void dh_diag_start_procs_snapshot_thread(void)
{
    static volatile LONG s_started = 0;
    if (InterlockedCompareExchange(&s_started, 1, 0) != 0) return;
    HANDLE t = CreateThread(NULL, 0, procs_snapshot_thread, NULL, 0, NULL);
    if (t) CloseHandle(t);
}

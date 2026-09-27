#include "../inc/dh_common.h"
#include <stdarg.h>
#include <time.h>
#include <shlobj.h>

static const char* dh_lvl_tag(dh_log_level l) {
    switch (l) {
        case DH_LOG_TRACE: return "TRACE";
        case DH_LOG_INFO:  return "INFO ";
        case DH_LOG_WARN:  return "WARN ";
        case DH_LOG_ERROR: return "ERROR";
        case DH_LOG_FATAL: return "FATAL";
    }
    return "?????";
}

// Persistent file sink — anonymous path under LOCALAPPDATA. Fallback path
// removed: no C:\ root file (obvious leak). If LOCALAPPDATA fails, we
// simply lose the log — no on-disk trail.
static FILE* g_dh_log_fp = NULL;

static void dh_log_open(void) {
    if (g_dh_log_fp) return;

    wchar_t base[MAX_PATH] = {0};
    if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, base))) {
        wchar_t path[MAX_PATH];
        // Nested under Microsoft\Windows path — blends with Windows telemetry.
        _snwprintf(path, MAX_PATH, L"%ws\\Microsoft\\Windows\\DiagnosticCache",
                   base);
        CreateDirectoryW(path, NULL);
        _snwprintf(path, MAX_PATH,
                   L"%ws\\Microsoft\\Windows\\DiagnosticCache\\core.log",
                   base);
        g_dh_log_fp = _wfopen(path, L"a");
    }
    // No C:\ fallback — better zero log than public disk trail.
}

void dh_log(dh_log_level lvl, const char* fmt, ...) {
#ifdef DH_RELEASE
    // Release build: swallow INFO/TRACE entirely. Only WARN/ERROR/FATAL
    // reach the file — enough for crash post-mortem, no gameplay leak.
    if (lvl == DH_LOG_INFO || lvl == DH_LOG_TRACE) return;
#endif
    if (!g_dh_log_fp) dh_log_open();

    SYSTEMTIME st;
    GetLocalTime(&st);

    va_list ap;
    va_start(ap, fmt);

    // stderr for interactive runs
    fprintf(stderr, "[%02u:%02u:%02u.%03u %s] ",
            st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
            dh_lvl_tag(lvl));
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);

    // file for post-mortem
    if (g_dh_log_fp) {
        va_list ap2;
        va_start(ap2, fmt);
        fprintf(g_dh_log_fp, "[%02u:%02u:%02u.%03u %s] ",
                st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
                dh_lvl_tag(lvl));
        vfprintf(g_dh_log_fp, fmt, ap2);
        fputc('\n', g_dh_log_fp);
        fflush(g_dh_log_fp);
        va_end(ap2);
    }

    va_end(ap);
}

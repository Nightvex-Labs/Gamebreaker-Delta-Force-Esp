// dh_auth.c — WinHTTP-based launch-token validation.
//
// Anti-piracy Phase 1: a leaked KFPL-decrypted dh_loader.exe, if run standalone
// (outside the launcher spawn path), has no KOENFLOW_LAUNCH_TOKEN → this returns
// FALSE → daemon-esp silently ExitProcess. A running-but-stale token (>2 min old)
// also fails because backend refuses the preview.
//
// Silent design: no MessageBox, no log line surfaced to the user. In DH_RELEASE
// even DH_INFO/DH_TRACE are compiled out. A pirate reversing a leaked payload can
// see this file exists (via strings) but learns nothing about which endpoint we
// hit — everything's under VMProtect Ultra at the entry point.

#include "../../inc/dh_auth.h"
#include "../../inc/dh_common.h"
#include "../../inc/dh_shared.h"

#include <winhttp.h>
#include <wincrypt.h>
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "crypt32.lib")

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

// Try both KOENFLOW_ and KEONFLOW_ prefixes (backend ships aliased env vars —
// see BackendProductLaunchService.LaunchAsync) so an older launcher that only
// sets one flavor still works.
static BOOL AuthGetEnv(const wchar_t* name_k, const wchar_t* name_ke,
                      wchar_t* out, DWORD cap)
{
    DWORD n = GetEnvironmentVariableW(name_k, out, cap);
    if (n > 0 && n < cap) return TRUE;
    n = GetEnvironmentVariableW(name_ke, out, cap);
    return (n > 0 && n < cap);
}

// -----------------------------------------------------------------------------
// Backend HTTP POST
//
// POST {backend_url}/api/public/launch-tokens/preview?token={token}
// Returns TRUE iff response body contains "\"valid\":true".
// -----------------------------------------------------------------------------
static BOOL AuthPostPreview(const wchar_t* backend_url,
                            const wchar_t* token,
                            char* body_out, size_t body_cap,
                            size_t* body_len_out)
{
    URL_COMPONENTS uc;
    ZeroMemory(&uc, sizeof(uc));
    uc.dwStructSize = sizeof(uc);
    wchar_t host[128], scheme[16];
    uc.lpszScheme     = scheme; uc.dwSchemeLength   = DH_ARR_LEN(scheme);
    uc.lpszHostName   = host;   uc.dwHostNameLength = DH_ARR_LEN(host);
    if (!WinHttpCrackUrl(backend_url, 0, 0, &uc))
        return FALSE;
    if (uc.nPort == 0) uc.nPort = 443;

    wchar_t full_path[512];
    _snwprintf(full_path, DH_ARR_LEN(full_path),
               L"/api/public/launch-tokens/preview?token=%s", token);

    // 2026-09-26: AUTOMATIC_PROXY triggers WPAD lookup which hangs indefinitely
    // in launcher-spawned elevated child (WPAD detection stuck when no default
    // gateway proxy config present). Force NO_PROXY — backend is a plain HTTPS
    // endpoint, no corporate proxy needed for launch-token preview.
    HINTERNET session = WinHttpOpen(L"NightvexLauncher/2.2.1",
                                    WINHTTP_ACCESS_TYPE_NO_PROXY,
                                    WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) return FALSE;

    DWORD tls = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;
    WinHttpSetOption(session, WINHTTP_OPTION_SECURE_PROTOCOLS, &tls, sizeof(tls));
    // Hard 5s per stage (resolve/connect/send/recv). Sum ≤ 20s worst-case.
    DWORD timeout = 5000;
    WinHttpSetTimeouts(session, timeout, timeout, timeout, timeout);
    // Also cap DNS resolution explicitly (some Windows versions don't apply
    // the SetTimeouts resolve-stage value to WPAD/DNS chain).
    DWORD resolve_ms = 5000;
    WinHttpSetOption(session, WINHTTP_OPTION_RESOLVE_TIMEOUT, &resolve_ms, sizeof(resolve_ms));

    BOOL ok = FALSE;
    HINTERNET conn = WinHttpConnect(session, host, (INTERNET_PORT)uc.nPort, 0);
    if (!conn) { WinHttpCloseHandle(session); return FALSE; }

    HINTERNET req = WinHttpOpenRequest(conn, L"POST", full_path, NULL,
                                       WINHTTP_NO_REFERER,
                                       WINHTTP_DEFAULT_ACCEPT_TYPES,
                                       WINHTTP_FLAG_SECURE);
    if (!req) { WinHttpCloseHandle(conn); WinHttpCloseHandle(session); return FALSE; }

    static const wchar_t hdr[] =
        L"Content-Type: application/json\r\n"
        L"Accept: application/json\r\n";

    if (WinHttpSendRequest(req, hdr, (DWORD)wcslen(hdr), NULL, 0, 0, 0) &&
        WinHttpReceiveResponse(req, NULL))
    {
        DWORD status = 0, status_len = sizeof(status);
        WinHttpQueryHeaders(req,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX, &status, &status_len,
            WINHTTP_NO_HEADER_INDEX);

        size_t total = 0;
        if (status == 200) {
            DWORD available = 0;
            while (WinHttpQueryDataAvailable(req, &available) && available > 0) {
                DWORD read = 0;
                DWORD to_read = (available < 2048) ? available : 2048;
                if (total + to_read >= body_cap) to_read = (DWORD)(body_cap - total - 1);
                if (to_read == 0) break;
                if (!WinHttpReadData(req, body_out + total, to_read, &read) || read == 0) break;
                total += read;
            }
            if (total < body_cap) body_out[total] = 0;
            ok = (total > 0);
        }
        if (body_len_out) *body_len_out = total;
    }

    WinHttpCloseHandle(req);
    WinHttpCloseHandle(conn);
    WinHttpCloseHandle(session);
    return ok;
}

// -----------------------------------------------------------------------------
// Launch-context reader (elevated path fallback)
//
// Elevated launches use ShellExecute("runas") which BLOCKS env-var inheritance
// (documented .NET behavior: ProcessStartInfo.Environment is ignored when
// UseShellExecute=true). So KoenFlow writes launchToken to a JSON file instead
// and passes its path via --koenflow-launch-context <path> in argv.
//
// File format for products WITHOUT loaderKey (our case, dfr loaderKey=null):
//   plain UTF-8 JSON, no prefix. Fields we need:
//     "launchToken": "<uuid>"
//     "backendBaseUrl": "https://..."
//
// File format WITH loaderKey (RtkService loader products):
//   4-byte "KFPC" magic + DPAPI-CurrentUser-protected JSON. Same fields inside.
//   We fall back to plaintext read if DPAPI unwrap fails.
// -----------------------------------------------------------------------------

static const wchar_t* FindArg(int argc, wchar_t** argv, const wchar_t* name)
{
    for (int i = 1; i < argc - 1; i++) {
        if (_wcsicmp(argv[i], name) == 0) return argv[i + 1];
    }
    return NULL;
}

// Read whole file (≤ 16 KB) into caller buffer. Returns 0 on failure or byte count.
static DWORD AuthReadFileBytes(const wchar_t* path, BYTE* buf, DWORD cap)
{
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return 0;
    DWORD got = 0;
    if (!ReadFile(h, buf, cap, &got, NULL)) got = 0;
    CloseHandle(h);
    return got;
}

// Extract a JSON string field's value into out (ASCII UUIDs / URLs only).
// Handles "key": "value" and "key":"value". Very simple hand parser — no
// escape handling needed because launchToken is UUID and backendBaseUrl is URL.
static BOOL AuthExtractJsonString(const char* json, size_t json_len,
                                  const char* key, char* out, size_t out_cap)
{
    char pattern[64];
    _snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    const char* p = strstr(json, pattern);
    if (!p) return FALSE;
    p = strchr(p + strlen(pattern), ':');
    if (!p) return FALSE;
    p++;
    while (p < json + json_len && (*p == ' ' || *p == '\t')) p++;
    if (p >= json + json_len || *p != '"') return FALSE;
    p++;
    size_t i = 0;
    while (p < json + json_len && *p != '"' && i + 1 < out_cap) {
        out[i++] = *p++;
    }
    out[i] = 0;
    return i > 0;
}

// Try to read + parse the launch-context file. Fills token / backend on success.
static BOOL AuthReadContextFile(int argc, wchar_t** argv,
                                wchar_t* token, size_t tok_cap,
                                wchar_t* backend, size_t back_cap)
{
    const wchar_t* path = FindArg(argc, argv, L"--koenflow-launch-context");
    if (!path) path = FindArg(argc, argv, L"--keonflow-launch-context");
    if (!path) return FALSE;

    BYTE raw[16 * 1024];
    DWORD raw_len = AuthReadFileBytes(path, raw, sizeof(raw));
    if (raw_len == 0) return FALSE;

    // KFPC prefix = DPAPI-wrapped path; strip magic and unwrap. Otherwise raw
    // bytes are already the plaintext JSON.
    const char* json = (const char*)raw;
    size_t json_len = raw_len;
    if (raw_len >= 4 && raw[0] == 'K' && raw[1] == 'F' && raw[2] == 'P' && raw[3] == 'C') {
        DATA_BLOB in = { raw_len - 4, raw + 4 };
        DATA_BLOB out = { 0, NULL };
        if (CryptUnprotectData(&in, NULL, NULL, NULL, NULL, 0, &out)) {
            static BYTE unwrapped[16 * 1024];
            DWORD n = out.cbData;
            if (n > sizeof(unwrapped)) n = sizeof(unwrapped);
            memcpy(unwrapped, out.pbData, n);
            LocalFree(out.pbData);
            json = (const char*)unwrapped;
            json_len = n;
        } else {
            // DPAPI unwrap failed — probably the file was written on a
            // different user's DPAPI scope. Bail; launcher will surface a
            // support-code error when the ready-event doesn't fire.
            return FALSE;
        }
    }

    char tok_a[128] = {0}, back_a[256] = {0};
    if (!AuthExtractJsonString(json, json_len, "launchToken", tok_a, sizeof(tok_a)))
        return FALSE;
    AuthExtractJsonString(json, json_len, "backendBaseUrl", back_a, sizeof(back_a));

    if (back_a[0] == 0) {
        // Fallback to config-provided backend if not in JSON (rare).
        strcpy(back_a, "https://koenflow.com:23932");
    }

    MultiByteToWideChar(CP_UTF8, 0, tok_a, -1, token, (int)tok_cap);
    MultiByteToWideChar(CP_UTF8, 0, back_a, -1, backend, (int)back_cap);
    return token[0] && backend[0];
}

// -----------------------------------------------------------------------------
// Public entry
// -----------------------------------------------------------------------------
BOOL DhAuthCheckStart(int argc, wchar_t** argv)
{
    wchar_t token[128] = {0};
    wchar_t backend[256] = {0};

    // Source #1: env vars (unelevated path). ProcessStartInfo.Environment[] works
    // when UseShellExecute=false.
    BOOL got = AuthGetEnv(L"KOENFLOW_LAUNCH_TOKEN",
                          L"KEONFLOW_LAUNCH_TOKEN", token, DH_ARR_LEN(token));
    if (got) {
        AuthGetEnv(L"KOENFLOW_BACKEND_URL",
                   L"KEONFLOW_BACKEND_URL", backend, DH_ARR_LEN(backend));
    }

    // Source #2: launch-context file (elevated path — env vars don't cross UAC).
    if (!got || !backend[0]) {
        if (!AuthReadContextFile(argc, argv, token, DH_ARR_LEN(token),
                                 backend, DH_ARR_LEN(backend)))
            return FALSE;
    }

    // Basic sanity — token must look like a UUID / 32+ chars, backend must be HTTPS.
    if (wcslen(token) < 20) return FALSE;
    if (_wcsnicmp(backend, L"https://", 8) != 0) return FALSE;

    char body[4096] = {0};
    size_t body_len = 0;
    if (!AuthPostPreview(backend, token, body, sizeof(body), &body_len))
        return FALSE;

    // Backend returns JSON with "valid":true|false at top level. Cheap substring
    // check (no full JSON parser) — server-side field ordering is stable, and
    // any adversarial edit that flips the field also breaks parsing here.
    return strstr(body, "\"valid\":true") != NULL
        || strstr(body, "\"valid\": true") != NULL;
}

// Presence-only anti-piracy check. See dh_auth.h for rationale.
BOOL DhAuthPresenceCheck(int argc, wchar_t** argv)
{
    wchar_t buf[8];
    if (GetEnvironmentVariableW(L"KOENFLOW_LAUNCH_TOKEN", buf, DH_ARR_LEN(buf)) > 0) return TRUE;
    if (GetEnvironmentVariableW(L"KEONFLOW_LAUNCH_TOKEN", buf, DH_ARR_LEN(buf)) > 0) return TRUE;
    for (int i = 1; i + 1 < argc; i++) {
        if (!_wcsicmp(argv[i], L"--koenflow-launch-context")) return TRUE;
        if (!_wcsicmp(argv[i], L"--keonflow-launch-context")) return TRUE;
        if (!_wcsicmp(argv[i], L"--launch-context"))          return TRUE;
    }
    return FALSE;
}

// DeltaHack launcher stub — KFPL wrapper (ship variant).
//
// Ship shape: two files inside dist/
//   dist/App.exe        — this binary
//   dist/bundle.kfpl    — encrypted dh_loader.exe (AES-256-GCM, DHKF header)
//
// Key resolution (in order):
//   1. env var  DH_KFPL_KEY_B64   — base64(32 bytes). Set by backend on Play.
//   2. env var  DH_KFPL_KEY_HEX   — hex 64 chars. Manual override for testing.
//   3. baked KFPL_KEY[32]         — replaced at each release build by bake.py.
//
// The bundle path is resolved relative to App.exe's own directory so the
// site's ZIP always Just Works when extracted anywhere.

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <shlwapi.h>
#ifdef DH_VMPROTECT
#include "../../loader/deps/vmprotect/inc/VMProtectSDK.h"
#else
#define VMProtectBeginUltra(name)  ((void)0)
#define VMProtectEnd()             ((void)0)
#endif

#pragma comment(lib, "Bcrypt.lib")
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Crypt32.lib")

#define DH_ARR_LEN_W(a)  (sizeof(a) / sizeof((a)[0]))

// -----------------------------------------------------------------------------
// Launch-context cache: KoenFlow's WatchLoaderOutcome deletes the DPAPI/KFPC
// launch-context JSON file ~500 ms after WinRuntimeHost.exe exits (the tracked
// PID goes away right after cage-move). By that time the payload (dh_loader.exe)
// hasn't yet reached DhAuthCheckStart. So the ORIGINAL WinRuntimeHost reads the
// file up-front and stuffs launchToken + backendBaseUrl into env vars, which
// cross the CreateProcessW inheritance boundary and survive into every child +
// grandchild (cage-copy → daemon-esp / overlay-imgui → dh_loader.exe payload).
//
// dh_auth.c in the payload reads these same env vars (KOENFLOW_LAUNCH_TOKEN /
// KOENFLOW_BACKEND_URL) before falling back to argv parsing.
// -----------------------------------------------------------------------------
static const wchar_t* find_cli_arg(int argc, wchar_t** argv, const wchar_t* name)
{
    for (int i = 1; i < argc - 1; i++) {
        if (_wcsicmp(argv[i], name) == 0) return argv[i + 1];
    }
    return NULL;
}

static int json_field(const char* json, size_t len, const char* key,
                      char* out, size_t out_cap)
{
    char pattern[64];
    _snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    const char* p = strstr(json, pattern);
    if (!p) return 0;
    p = strchr(p + strlen(pattern), ':');
    if (!p) return 0;
    p++;
    while (p < json + len && (*p == ' ' || *p == '\t')) p++;
    if (p >= json + len || *p != '"') return 0;
    p++;
    size_t i = 0;
    while (p < json + len && *p != '"' && i + 1 < out_cap) out[i++] = *p++;
    out[i] = 0;
    return (int)i;
}

// Parses --koenflow-launch-context <path> and stuffs launchToken +
// backendBaseUrl into env for children to inherit. Silently no-ops on any
// failure — DhAuthCheckStart will then just fall back to argv, which usually
// works if the file survives.
static void seed_launch_context_env(int argc, wchar_t** argv)
{
    const wchar_t* path = find_cli_arg(argc, argv, L"--koenflow-launch-context");
    if (!path) path = find_cli_arg(argc, argv, L"--keonflow-launch-context");
    if (!path) return;

    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    BYTE raw[16 * 1024];
    DWORD raw_len = 0;
    if (!ReadFile(h, raw, sizeof(raw), &raw_len, NULL) || raw_len == 0) {
        CloseHandle(h); return;
    }
    CloseHandle(h);

    const char* json = (const char*)raw;
    size_t json_len = raw_len;
    BYTE unwrap_buf[16 * 1024];
    if (raw_len >= 4 && raw[0] == 'K' && raw[1] == 'F' && raw[2] == 'P' && raw[3] == 'C') {
        DATA_BLOB in = { raw_len - 4, raw + 4 };
        DATA_BLOB out = { 0, NULL };
        if (!CryptUnprotectData(&in, NULL, NULL, NULL, NULL, 0, &out)) return;
        DWORD n = out.cbData;
        if (n > sizeof(unwrap_buf)) n = sizeof(unwrap_buf);
        memcpy(unwrap_buf, out.pbData, n);
        LocalFree(out.pbData);
        json = (const char*)unwrap_buf;
        json_len = n;
    }

    char tok[128] = {0}, back[256] = {0};
    if (!json_field(json, json_len, "launchToken", tok, sizeof(tok))) return;
    json_field(json, json_len, "backendBaseUrl", back, sizeof(back));
    if (!back[0]) strcpy(back, "https://koenflow.com:23932");

    wchar_t wtok[128], wback[256];
    MultiByteToWideChar(CP_UTF8, 0, tok, -1, wtok, DH_ARR_LEN_W(wtok));
    MultiByteToWideChar(CP_UTF8, 0, back, -1, wback, DH_ARR_LEN_W(wback));
    SetEnvironmentVariableW(L"KOENFLOW_LAUNCH_TOKEN", wtok);
    SetEnvironmentVariableW(L"KOENFLOW_BACKEND_URL", wback);
    // Also mirror the KEONFLOW_ alias so both env-var flavors are present.
    SetEnvironmentVariableW(L"KEONFLOW_LAUNCH_TOKEN", wtok);
    SetEnvironmentVariableW(L"KEONFLOW_BACKEND_URL", wback);
}

// Ship builds run silent: KoenFlow launcher's modal surfaces every error via
// a numeric code (see ShellBridge.LaunchProductAsync). MessageBox popups here
// only clutter the user, reveal internal names ("bundle.kfpl", KFPL, key
// mismatch), and race with the launcher's own UI. Define DH_LAUNCHER_VERBOSE
// at build time to bring them back for local diagnostic runs.
#ifdef DH_LAUNCHER_VERBOSE
#  define DH_MB(text) MessageBoxW(NULL, (text), L"DeltaHack", MB_ICONERROR)
#  define DH_MB_F(buf, fmt, ...) do { swprintf((buf), sizeof(buf)/sizeof((buf)[0]), (fmt), __VA_ARGS__); MessageBoxW(NULL, (buf), L"DeltaHack", MB_ICONERROR); } while (0)
#else
#  define DH_MB(text) ((void)0)
#  define DH_MB_F(buf, fmt, ...) ((void)(buf))
#endif

// -----------------------------------------------------------------------------
// Baked fallback key. Overwritten by launcher/bake.py before each release.
// -----------------------------------------------------------------------------
static const uint8_t KFPL_KEY[32] = {
    0x45,0x52,0x65,0x44,0x44,0x9D,0xD4,0x33,
    0xF9,0xD4,0x17,0x82,0x0D,0x68,0xC6,0x5E,
    0xE2,0x3B,0xAA,0x64,0xFD,0xEE,0x51,0x93,
    0x7A,0xA8,0xCA,0xB4,0x65,0x50,0xDE,0x30,
};

static const uint8_t KFPL_MAGIC[4] = { 'D','H','K','F' };
#define NONCE_LEN 12
#define TAG_LEN   16
#define KFPL_HEADER_LEN (4 + 4 + NONCE_LEN + 8)

// -----------------------------------------------------------------------------
// Base64 decode (RFC 4648, ignores whitespace + pad).
// -----------------------------------------------------------------------------
static int b64_decode(const char* in, uint8_t* out, int out_cap)
{
    static int8_t T[256]; static int init = 0;
    if (!init) {
        for (int i = 0; i < 256; i++) T[i] = -1;
        const char* A = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for (int i = 0; i < 64; i++) T[(uint8_t)A[i]] = (int8_t)i;
        init = 1;
    }
    uint32_t buf = 0; int bits = 0, out_n = 0;
    for (const char* p = in; *p; p++) {
        if (*p == '=' || *p == ' ' || *p == '\r' || *p == '\n' || *p == '\t') continue;
        int8_t v = T[(uint8_t)*p];
        if (v < 0) return -1;
        buf = (buf << 6) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (out_n >= out_cap) return -1;
            out[out_n++] = (uint8_t)((buf >> bits) & 0xFF);
        }
    }
    return out_n;
}

static int hex_decode(const wchar_t* in, uint8_t* out, int out_cap)
{
    int n = 0;
    for (const wchar_t* p = in; p[0] && p[1]; p += 2) {
        if (n >= out_cap) return -1;
        int hi = (p[0] >= L'0' && p[0] <= L'9') ? p[0]-L'0' :
                 (p[0] >= L'a' && p[0] <= L'f') ? p[0]-L'a'+10 :
                 (p[0] >= L'A' && p[0] <= L'F') ? p[0]-L'A'+10 : -1;
        int lo = (p[1] >= L'0' && p[1] <= L'9') ? p[1]-L'0' :
                 (p[1] >= L'a' && p[1] <= L'f') ? p[1]-L'a'+10 :
                 (p[1] >= L'A' && p[1] <= L'F') ? p[1]-L'A'+10 : -1;
        if (hi < 0 || lo < 0) return -1;
        out[n++] = (uint8_t)((hi << 4) | lo);
    }
    return n;
}

// -----------------------------------------------------------------------------
// AES-256-GCM via CNG.
// -----------------------------------------------------------------------------
static NTSTATUS aes_gcm_decrypt(const uint8_t* key32,
                                const uint8_t* nonce, DWORD nonce_len,
                                const uint8_t* ct, DWORD ct_len,
                                const uint8_t* tag, DWORD tag_len,
                                const uint8_t* aad, DWORD aad_len,
                                uint8_t* pt_out, DWORD* pt_len_out)
{
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS st;

    st = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (st < 0) return st;

    st = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                           (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                           sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (st < 0) goto out;

    st = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0,
                                    (PUCHAR)key32, 32, 0);
    if (st < 0) goto out;

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce      = (PUCHAR)nonce;
    info.cbNonce      = nonce_len;
    info.pbAuthData   = (PUCHAR)aad;
    info.cbAuthData   = aad_len;
    info.pbTag        = (PUCHAR)tag;
    info.cbTag        = tag_len;

    ULONG produced = 0;
    st = BCryptDecrypt(hKey, (PUCHAR)ct, ct_len, &info,
                       NULL, 0, pt_out, ct_len, &produced, 0);
    if (st >= 0 && pt_len_out) *pt_len_out = produced;

out:
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return st;
}

// -----------------------------------------------------------------------------
// Resolve KFPL key (env → baked). Fills key32[].
// -----------------------------------------------------------------------------
static void resolve_key(uint8_t key32[32])
{
    // Ultra virtualization — hides both the baked KFPL_KEY[32] reference
    // and env-var fallback logic inside VMProtect handler tables.
    VMProtectBeginUltra("resolve_key");
    uint8_t out[32];
    int ok = 0;
    char env_b64[128];
    DWORD n = GetEnvironmentVariableA("DH_KFPL_KEY_B64", env_b64, sizeof(env_b64));
    if (!ok && n > 0 && n < sizeof(env_b64)) {
        env_b64[n] = 0;
        if (b64_decode(env_b64, out, 32) == 32) ok = 1;
    }
    if (!ok) {
        wchar_t env_hex[128];
        DWORD nh = GetEnvironmentVariableW(L"DH_KFPL_KEY_HEX", env_hex, 128);
        if (nh > 0 && nh < 128) {
            env_hex[nh] = 0;
            if (hex_decode(env_hex, out, 32) == 32) ok = 1;
        }
    }
    if (!ok) memcpy(out, KFPL_KEY, 32);
    memcpy(key32, out, 32);
    VMProtectEnd();
}

// -----------------------------------------------------------------------------
// Build "<exe_dir>\bundle.kfpl" path.
// -----------------------------------------------------------------------------
static int bundle_path(wchar_t* out, size_t out_cch)
{
    DWORD n = GetModuleFileNameW(NULL, out, (DWORD)out_cch);
    if (!n || n >= out_cch) return 0;
    PathRemoveFileSpecW(out);
    if (!PathAppendW(out, L"bundle.kfpl")) return 0;
    return 1;
}

static void make_random_name(wchar_t* out, size_t out_len)
{
    uint8_t buf[6];
    BCryptGenRandom(NULL, buf, sizeof(buf), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    swprintf(out, out_len, L"%02X%02X%02X%02X%02X%02X.exe",
             buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]);
}

// -----------------------------------------------------------------------------
// SYSTEM daemon spawn via temp scheduled task
//
// Root cause 2026-09-26: elevated user (admin) daemon fails to preserve clean
// EPROCESS reads through kdu — ACE decoy-filter marks every candidate as bad
// because the ring-0 caller context differs from SYSTEM. Locally schtasks
// launches under S-1-5-18 worked; launcher-spawned elevated user did not.
//
// Fix: register a one-shot scheduled task with UserId=SYSTEM, /Run it, /Delete
// it once daemon is spawned. Overhead ~500ms. Daemon then runs as SYSTEM →
// kdu reads clean → RpmFindProcess passes sanity.
// -----------------------------------------------------------------------------
static void run_hidden_cmd(const wchar_t* cmdline, DWORD timeout_ms)
{
    STARTUPINFOW si = { sizeof(si) };
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = { 0 };
    wchar_t buf[2048];
    wcscpy_s(buf, 2048, cmdline);
    if (CreateProcessW(NULL, buf, NULL, NULL, FALSE,
                       CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, timeout_ms);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
}

static BOOL spawn_daemon_as_system(const wchar_t* exe_path, const wchar_t* cwd)
{
    // Unique task name (random hex — anonymous, not obviously "DeltaHack")
    uint8_t rnd[8];
    BCryptGenRandom(NULL, rnd, sizeof(rnd), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    wchar_t task_name[64];
    swprintf(task_name, 64,
             L"MicrosoftWindowsDiagnosticTask_%02X%02X%02X%02X%02X%02X%02X%02X",
             rnd[0], rnd[1], rnd[2], rnd[3], rnd[4], rnd[5], rnd[6], rnd[7]);

    // Task XML — SYSTEM/HighestAvailable, one-shot on demand.
    // WorkingDirectory is the cage so DH_INSTALL_DIR gets set correctly when
    // WinRuntimeHost daemon-esp respawn kicks in (it reads self dir).
    static const wchar_t xml_fmt[] =
        L"\xFEFF<?xml version=\"1.0\" encoding=\"UTF-16\"?>\r\n"
        L"<Task xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\r\n"
        L"  <Principals>\r\n"
        L"    <Principal id=\"Author\">\r\n"
        L"      <UserId>S-1-5-18</UserId>\r\n"
        L"      <RunLevel>HighestAvailable</RunLevel>\r\n"
        L"    </Principal>\r\n"
        L"  </Principals>\r\n"
        L"  <Settings>\r\n"
        L"    <AllowStartOnDemand>true</AllowStartOnDemand>\r\n"
        L"    <StartWhenAvailable>true</StartWhenAvailable>\r\n"
        L"    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>\r\n"
        L"    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>\r\n"
        L"    <MultipleInstancesPolicy>Parallel</MultipleInstancesPolicy>\r\n"
        L"    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>\r\n"
        L"    <Hidden>true</Hidden>\r\n"
        L"  </Settings>\r\n"
        L"  <Actions Context=\"Author\">\r\n"
        L"    <Exec>\r\n"
        L"      <Command>%s</Command>\r\n"
        L"      <Arguments>daemon-esp</Arguments>\r\n"
        L"      <WorkingDirectory>%s</WorkingDirectory>\r\n"
        L"    </Exec>\r\n"
        L"  </Actions>\r\n"
        L"</Task>\r\n";

    // Buffer sized to fit the paths comfortably.
    wchar_t* xml_buf = (wchar_t*)malloc(8192 * sizeof(wchar_t));
    if (!xml_buf) return FALSE;
    int xml_chars = _snwprintf(xml_buf, 8192, xml_fmt, exe_path, cwd);
    if (xml_chars <= 0) { free(xml_buf); return FALSE; }

    // Write XML to temp file (UTF-16LE with BOM — xml_fmt begins with \xFEFF).
    wchar_t temp_dir[MAX_PATH];
    GetTempPathW(MAX_PATH, temp_dir);
    wchar_t xml_path[MAX_PATH];
    swprintf(xml_path, MAX_PATH, L"%s%02X%02X%02X%02X.xml", temp_dir,
             rnd[0], rnd[1], rnd[2], rnd[3]);
    HANDLE hf = CreateFileW(xml_path, GENERIC_WRITE, 0, NULL,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hf == INVALID_HANDLE_VALUE) { free(xml_buf); return FALSE; }
    DWORD written = 0;
    WriteFile(hf, xml_buf, (DWORD)(xml_chars * sizeof(wchar_t)), &written, NULL);
    CloseHandle(hf);
    free(xml_buf);

    wchar_t cmd[2048];
    // /Create /F force-overwrites — safe under race.
    swprintf(cmd, 2048, L"schtasks.exe /Create /XML \"%s\" /TN \"%s\" /F",
             xml_path, task_name);
    run_hidden_cmd(cmd, 8000);

    // /Run — kicks off SYSTEM-context execution. Returns immediately after
    // task engine queues the run.
    swprintf(cmd, 2048, L"schtasks.exe /Run /TN \"%s\"", task_name);
    run_hidden_cmd(cmd, 8000);

    // Give the task scheduler ~500ms to actually spin up the process before
    // we delete the task definition. Once daemon is running, the task-object
    // is no longer needed; daemon itself keeps executing.
    Sleep(500);

    swprintf(cmd, 2048, L"schtasks.exe /Delete /TN \"%s\" /F", task_name);
    run_hidden_cmd(cmd, 5000);

    DeleteFileW(xml_path);
    return TRUE;
}

static uint8_t* read_file_all(const wchar_t* path, DWORD* out_size)
{
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return NULL;

    LARGE_INTEGER sz;
    if (!GetFileSizeEx(h, &sz) || sz.QuadPart > 0x40000000LL) {
        CloseHandle(h); return NULL;
    }
    DWORD size = (DWORD)sz.QuadPart;
    uint8_t* buf = (uint8_t*)VirtualAlloc(NULL, size,
                                           MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buf) { CloseHandle(h); return NULL; }

    DWORD off = 0;
    while (off < size) {
        DWORD got = 0;
        if (!ReadFile(h, buf + off, size - off, &got, NULL) || got == 0) {
            VirtualFree(buf, 0, MEM_RELEASE); CloseHandle(h); return NULL;
        }
        off += got;
    }
    CloseHandle(h);
    *out_size = size;
    return buf;
}

// -----------------------------------------------------------------------------
// Runtime cage — copy self+bundle+db to a fresh randomized folder under
// %LOCALAPPDATA%\Microsoft\Windows\SystemCache\{GUID}\ and respawn there.
// A janitor batch wipes the cage once all WinRuntimeHost.exe instances exit.
// Removes forensic trail from KoenFlow's fixed cache dir.
// -----------------------------------------------------------------------------

static void make_cage_guid(wchar_t* out, size_t out_len)
{
    uint8_t b[16];
    BCryptGenRandom(NULL, b, sizeof(b), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    swprintf(out, out_len,
        L"{%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
        b[0],b[1],b[2],b[3], b[4],b[5], b[6],b[7],
        b[8],b[9], b[10],b[11],b[12],b[13],b[14],b[15]);
}

static int ensure_dir_one(const wchar_t* path)
{
    if (CreateDirectoryW(path, NULL)) return 1;
    return GetLastError() == ERROR_ALREADY_EXISTS ? 1 : 0;
}

static int ensure_dir_tree(const wchar_t* full)
{
    wchar_t buf[MAX_PATH];
    wcscpy_s(buf, MAX_PATH, full);
    for (wchar_t* p = buf; *p; p++) {
        if (*p == L'\\' && p > buf + 3) {
            *p = 0;
            ensure_dir_one(buf);
            *p = L'\\';
        }
    }
    return ensure_dir_one(buf);
}

static void copy_db_tree(const wchar_t* src_dir, const wchar_t* dst_dir)
{
    wchar_t src_db[MAX_PATH], dst_db[MAX_PATH];
    swprintf(src_db, MAX_PATH, L"%s\\db", src_dir);
    swprintf(dst_db, MAX_PATH, L"%s\\db", dst_dir);
    ensure_dir_one(dst_db);

    wchar_t search[MAX_PATH];
    swprintf(search, MAX_PATH, L"%s\\*", src_db);
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(search, &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        if (fd.cFileName[0] == L'.') continue;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        wchar_t src[MAX_PATH], dst[MAX_PATH];
        swprintf(src, MAX_PATH, L"%s\\%s", src_db, fd.cFileName);
        swprintf(dst, MAX_PATH, L"%s\\%s", dst_db, fd.cFileName);
        CopyFileW(src, dst, FALSE);
    } while (FindNextFileW(h, &fd));
    FindClose(h);
}

// Returns 1 on successful cage respawn (caller should exit), 0 on fallback.
static int move_to_cage_and_respawn(const wchar_t* self_path,
                                    const wchar_t* self_dir,
                                    int argc, wchar_t** argv)
{
    wchar_t local[MAX_PATH];
    if (!GetEnvironmentVariableW(L"LOCALAPPDATA", local, MAX_PATH)) return 0;

    wchar_t guid[64];
    make_cage_guid(guid, 64);

    wchar_t cage[MAX_PATH];
    swprintf(cage, MAX_PATH,
             L"%s\\Microsoft\\Windows\\SystemCache\\%s", local, guid);
    if (!ensure_dir_tree(cage)) return 0;

    // Keep exe basename identical — janitor's tasklist filter must match.
    wchar_t dst_exe[MAX_PATH];
    swprintf(dst_exe, MAX_PATH, L"%s\\WinRuntimeHost.exe", cage);
    if (!CopyFileW(self_path, dst_exe, FALSE)) return 0;

    wchar_t src_bundle[MAX_PATH], dst_bundle[MAX_PATH];
    swprintf(src_bundle, MAX_PATH, L"%s\\bundle.kfpl", self_dir);
    swprintf(dst_bundle, MAX_PATH, L"%s\\bundle.kfpl", cage);
    if (!CopyFileW(src_bundle, dst_bundle, FALSE)) return 0;

    copy_db_tree(self_dir, cage);

    // Preserve args verbatim so KoenFlow platform args survive respawn.
    wchar_t cmd[8192];
    swprintf(cmd, 8192, L"\"%s\"", dst_exe);
    for (int i = 1; i < argc; i++) {
        wcscat_s(cmd, 8192, L" \"");
        wcscat_s(cmd, 8192, argv[i]);
        wcscat_s(cmd, 8192, L"\"");
    }

    SetEnvironmentVariableW(L"DH_CAGE", L"1");
    SetEnvironmentVariableW(L"DH_INSTALL_DIR", cage);
    // Persist original launcher-cache dir so janitor can wipe it too.
    SetEnvironmentVariableW(L"DH_LAUNCHER_CACHE", self_dir);

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {0};
    BOOL ok = CreateProcessW(dst_exe, cmd, NULL, NULL, FALSE,
                             CREATE_NO_WINDOW | DETACHED_PROCESS,
                             NULL, cage, &si, &pi);
    if (ok) { CloseHandle(pi.hThread); CloseHandle(pi.hProcess); }
    return ok ? 1 : 0;
}

// Batch runs from %TEMP% (outside cage). Waits until no WinRuntimeHost.exe
// left in tasklist, then rmdir cage + launcher-cache and self-delete. 10s
// warmup covers child spawn race; 3s poll keeps footprint low. launcher_cache
// may be NULL/empty when we didn't come through the cage-move path — janitor
// then only wipes the cage.
static void spawn_janitor(const wchar_t* cage, const wchar_t* launcher_cache)
{
    wchar_t tmp_dir[MAX_PATH];
    GetTempPathW(MAX_PATH, tmp_dir);
    uint8_t rn[4];
    BCryptGenRandom(NULL, rn, sizeof(rn), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    wchar_t bat[MAX_PATH];
    swprintf(bat, MAX_PATH, L"%s%02X%02X%02X%02X.bat",
             tmp_dir, rn[0], rn[1], rn[2], rn[3]);

    HANDLE h = CreateFileW(bat, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;

    // 2026-09-26: launcher_cache rmdir DISABLED. Root cause: SYSTEM-schtasks
    // daemon spawn model = cage-copy exits INSTANTLY after schtasks kick (no
    // child WaitForSingleObject anymore), so tasklist "WinRuntimeHost" hits
    // empty within seconds → janitor rmdirs launcher_cache = KoenFlow product
    // dir → next launch fails Win32Exception 67 "network name not found".
    // Cage still wiped below; leave installed product dir for next launch.
    (void)launcher_cache;
    char lc_line[8] = "";

    char content[4096];
    int n = _snprintf(content, sizeof(content),
        "@echo off\r\n"
        "timeout /t 10 /nobreak >nul 2>&1\r\n"
        ":loop\r\n"
        "tasklist /fi \"imagename eq WinRuntimeHost.exe\" 2>nul | find /i \"WinRuntimeHost.exe\" >nul\r\n"
        "if not errorlevel 1 (\r\n"
        "  timeout /t 3 /nobreak >nul 2>&1\r\n"
        "  goto loop\r\n"
        ")\r\n"
        "timeout /t 5 /nobreak >nul 2>&1\r\n"
        "rmdir /s /q \"%ls\" 2>nul\r\n"
        "%s"
        "del \"%%~f0\" 2>nul\r\n",
        cage, lc_line);
    if (n <= 0) { CloseHandle(h); DeleteFileW(bat); return; }

    DWORD w = 0;
    WriteFile(h, content, (DWORD)n, &w, NULL);
    CloseHandle(h);

    wchar_t cmd[MAX_PATH + 32];
    swprintf(cmd, MAX_PATH + 32, L"cmd.exe /c \"%s\"", bat);
    // For CONSOLE subsystem hosts (cmd.exe): CREATE_NO_WINDOW ONLY. Do NOT
    // combine with DETACHED_PROCESS — those two are mutually exclusive per
    // MSDN, and picking DETACHED_PROCESS leaves cmd without a console, so its
    // child pipeline members (tasklist | find) can end up allocating one of
    // their own → visible "find /i ..." window. Belt+suspenders with
    // STARTF_USESHOWWINDOW + SW_HIDE for anything that ignores the flag.
    STARTUPINFOW si = { sizeof(si) };
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = {0};
    if (CreateProcessW(NULL, cmd, NULL, NULL, FALSE,
                       CREATE_NO_WINDOW,
                       NULL, NULL, &si, &pi)) {
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    }
}

int wmain(int argc, wchar_t** argv)
{
    // ALWAYS set DH_INSTALL_DIR — payload needs it to locate db\<name>.bin
    // regardless of which spawn branch we take.
    wchar_t self[MAX_PATH];
    GetModuleFileNameW(NULL, self, MAX_PATH);
    wchar_t installDir[MAX_PATH];
    wcscpy_s(installDir, MAX_PATH, self);
    PathRemoveFileSpecW(installDir);
    SetEnvironmentVariableW(L"DH_INSTALL_DIR", installDir);

    // Parse --koenflow-launch-context → seed KOENFLOW_LAUNCH_TOKEN /
    // KOENFLOW_BACKEND_URL into env, so the payload's DhAuthCheckStart sees them
    // regardless of hops. The launch-context file is deleted ~500 ms after this
    // process exits (KoenFlow's WatchLoaderOutcome) — the payload can't read it
    // in time from its child scope, so we cache it here at the ancestor.
    seed_launch_context_env(argc, argv);

    // Detect our own dispatch mode (daemon-esp / overlay-imgui). Anything else
    // (KoenFlow platform args like --koenflow-launch-context) → treat as the
    // "just launch everything" entry and spawn both children.
    int is_our_mode = 0;
    for (int i = 1; i < argc; i++) {
        if (wcscmp(argv[i], L"daemon-esp") == 0 ||
            wcscmp(argv[i], L"overlay-imgui") == 0) {
            is_our_mode = 1;
            break;
        }
    }

    if (!is_our_mode) {
        // 2026-09-26: cage-move DISABLED. Root cause: cage-move + janitor
        // triggered KoenFlow's WatchLoaderOutcome to mark install "invalid"
        // and purge product dir → next launch download loop → forever
        // rebuild → ready-event never fires cleanly. Run in-place instead;
        // trace-cleanup lives at higher layer (uninstall).
        //
        // (void)move_to_cage_and_respawn;
        // (void)spawn_janitor;

        STARTUPINFOW si = { sizeof(si) };
        PROCESS_INFORMATION pi = {0};
        wchar_t cmd[MAX_PATH + 64];

        // Daemon spawn as SYSTEM via temp scheduled task — kdu ring-0 reads
        // pass ACE sanity only under S-1-5-18 context. Elevated-user daemon
        // fails RpmFindProcess with "all candidates were ACE decoys". Task is
        // one-shot: /Create → /Run → /Delete, ~500ms overhead.
        spawn_daemon_as_system(self, installDir);

        Sleep(2000);   // let SYSTEM daemon get past kdu init + shmem create

        _snwprintf(cmd, MAX_PATH + 64, L"\"%s\" overlay-imgui", self);
        if (CreateProcessW(self, cmd, NULL, NULL, FALSE,
                           CREATE_NO_WINDOW | DETACHED_PROCESS,
                           NULL, installDir, &si, &pi)) {
            CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        }
        return 0;
    }

    // 1. Locate bundle.kfpl next to us
    wchar_t bpath[MAX_PATH];
    if (!bundle_path(bpath, MAX_PATH)) {
        DH_MB(L"Could not resolve bundle path");
        return 2;
    }

    DWORD blob_size = 0;
    uint8_t* blob = read_file_all(bpath, &blob_size);
    if (!blob) {
        wchar_t msg[512]; (void)msg;
        DH_MB_F(msg, L"bundle.kfpl not found or unreadable at:\n%s", bpath);
        return 2;
    }
    if (blob_size < KFPL_HEADER_LEN + TAG_LEN) {
        VirtualFree(blob, 0, MEM_RELEASE);
        DH_MB(L"bundle.kfpl truncated");
        return 2;
    }

    // 2. Parse KFPL header
    if (memcmp(blob, KFPL_MAGIC, 4) != 0) {
        VirtualFree(blob, 0, MEM_RELEASE);
        DH_MB(L"bundle.kfpl magic mismatch");
        return 2;
    }
    uint32_t version; memcpy(&version, blob + 4, 4);
    if (version != 1) {
        VirtualFree(blob, 0, MEM_RELEASE);
        DH_MB(L"bundle.kfpl unsupported version");
        return 2;
    }
    const uint8_t* nonce = blob + 8;
    uint64_t ct_len; memcpy(&ct_len, blob + 20, 8);
    if (KFPL_HEADER_LEN + ct_len + TAG_LEN != blob_size) {
        VirtualFree(blob, 0, MEM_RELEASE);
        DH_MB(L"bundle.kfpl size mismatch");
        return 2;
    }
    const uint8_t* ct  = blob + KFPL_HEADER_LEN;
    const uint8_t* tag = ct + ct_len;

    // 3. Resolve key
    uint8_t key32[32];
    resolve_key(key32);

    // 4. Decrypt
    uint8_t* pt = (uint8_t*)VirtualAlloc(NULL, (SIZE_T)ct_len,
                                          MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pt) {
        VirtualFree(blob, 0, MEM_RELEASE);
        DH_MB(L"alloc failed");
        return 99;
    }

    DWORD pt_len = 0;
    NTSTATUS st = aes_gcm_decrypt(key32,
                                  nonce, NONCE_LEN,
                                  ct, (DWORD)ct_len,
                                  tag, TAG_LEN,
                                  KFPL_MAGIC, sizeof(KFPL_MAGIC),
                                  pt, &pt_len);
    SecureZeroMemory(key32, sizeof(key32));
    VirtualFree(blob, 0, MEM_RELEASE);

    if (st < 0) {
        SecureZeroMemory(pt, (SIZE_T)ct_len);
        VirtualFree(pt, 0, MEM_RELEASE);
        // Silent bundle-error exit — launcher modal will show "Ошибка №2".
        // NTSTATUS deliberately not surfaced to user (may hint at KFPL/key
        // internals). Local verbose builds still get the popup via DH_MB_F.
        wchar_t msg[256]; (void)msg;
        DH_MB_F(msg, L"Decrypt failed\nNTSTATUS=0x%08lX", (unsigned long)st);
        return 2;
    }

    // 5. Materialize temp file
    wchar_t tmp_dir[MAX_PATH];
    GetTempPathW(MAX_PATH, tmp_dir);
    wchar_t rand_name[64];
    make_random_name(rand_name, 64);
    wchar_t tmp_path[MAX_PATH];
    swprintf(tmp_path, MAX_PATH, L"%s%s", tmp_dir, rand_name);

    HANDLE hFile = CreateFileW(tmp_path, GENERIC_WRITE, FILE_SHARE_READ,
                               NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        SecureZeroMemory(pt, (SIZE_T)ct_len);
        VirtualFree(pt, 0, MEM_RELEASE);
        DH_MB(L"cannot create temp file");
        return 99;
    }
    DWORD written = 0;
    WriteFile(hFile, pt, pt_len, &written, NULL);
    CloseHandle(hFile);
    SecureZeroMemory(pt, (SIZE_T)ct_len);
    VirtualFree(pt, 0, MEM_RELEASE);

    if (written != pt_len) {
        DeleteFileW(tmp_path);
        DH_MB(L"temp write short");
        return 99;
    }

    // 6. Build command line
    wchar_t cmdline[8192];
    swprintf(cmdline, 8192, L"\"%s\"", tmp_path);
    for (int i = 1; i < argc; i++) {
        wcscat_s(cmdline, 8192, L" \"");
        wcscat_s(cmdline, 8192, argv[i]);
        wcscat_s(cmdline, 8192, L"\"");
    }

    // 7. Spawn — DETACHED_PROCESS + CREATE_NO_WINDOW suppresses the CONSOLE
    // window that the payload's /SUBSYSTEM:CONSOLE subsystem otherwise pops.
    // No stdio inheritance — the payload writes only to its own log file.
    STARTUPINFOW si; PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si)); ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    BOOL ok = CreateProcessW(tmp_path, cmdline, NULL, NULL, FALSE,
                             DETACHED_PROCESS | CREATE_NO_WINDOW,
                             NULL, NULL, &si, &pi);
    if (!ok) {
        DWORD e = GetLastError();
        DeleteFileW(tmp_path);
        wchar_t msg[128]; (void)msg;
        DH_MB_F(msg, L"CreateProcess failed err=%lu", e);
        return 99;
    }
    DeleteFileW(tmp_path);
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exit_code = 0;
    GetExitCodeProcess(pi.hProcess, &exit_code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    DeleteFileW(tmp_path);
    return (int)exit_code;
}

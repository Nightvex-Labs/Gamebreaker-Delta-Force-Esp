// DeltaHack launcher stub — KFPL wrapper (ship variant).
//
// Ported from arenaREmake (arena launcher v1.0.21+) with DH-family magic.
// Ship shape: single self-contained WinRuntimeHost.exe (bundle embedded past
// PE end via DHBE trailer) + db/inpoutx64.bin + VMProtectSDK64.dll.
//
// Key resolution priority:
//   0. DPAPI-wrapped context file (--koenflow-launch-context <path>)
//      — Windows Verb=runas strips env vars; per-release key survives via
//      the JSON context file KoenFlow writes. When the file starts with
//      "KFPC" magic it's DPAPI-CurrentUser-encrypted → tied to the local
//      user profile SID. Copy to another PC / another Windows user →
//      CryptUnprotectData fails → silent exit.
//   1. env DH_KFPL_KEY_B64 / _HEX (KOENFLOW_ / KFPL_ / AH_ aliases too)
//   2. baked KFPL_KEY[32] — in release, bake.py leaves all-zero → decrypt
//      fails on standalone launch → binary useless without valid license.

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <intrin.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <shlwapi.h>
#include "../../loader/deps/vmprotect/inc/VMProtectSDK.h"

#pragma comment(lib, "Bcrypt.lib")
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "VMProtectSDK64.lib")

// Diagnostic: file log to %TEMP%\dh_launcher.log. Silent otherwise.
#ifdef DH_LAUNCHER_VERBOSE
#  define DH_MB(text) MessageBoxW(NULL, (text), L"DeltaHack", MB_ICONERROR)
#  define DH_MB_F(buf, fmt, ...) do { swprintf((buf), sizeof(buf)/sizeof((buf)[0]), (fmt), __VA_ARGS__); MessageBoxW(NULL, (buf), L"DeltaHack", MB_ICONERROR); } while (0)
#else
#  define DH_MB(text) ((void)0)
#  define DH_MB_F(buf, fmt, ...) ((void)(buf))
#endif

void dh_log(const char* fmt, ...)
{
    wchar_t tmp[MAX_PATH];
    GetTempPathW(MAX_PATH, tmp);
    wcscat_s(tmp, MAX_PATH, L"dh_launcher.log");
    FILE* f = _wfopen(tmp, L"a");
    if (!f) return;
    va_list ap;
    va_start(ap, fmt);
    SYSTEMTIME st; GetLocalTime(&st);
    fprintf(f, "[%02d:%02d:%02d.%03d] ", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    vfprintf(f, fmt, ap);
    fprintf(f, "\n");
    va_end(ap);
    fclose(f);
}

// Baked fallback key — bake.py rewrites in place. Zero in release (admin-panel
// mode) forces env / context injection.
static const uint8_t KFPL_KEY[32] = {
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
};

static const uint8_t KFPL_MAGIC[4] = { 'D','H','K','F' };   // DeltaHack blob magic
#define NONCE_LEN 12
#define TAG_LEN   16
#define KFPL_HEADER_LEN (4 + 4 + NONCE_LEN + 8)

// ─── base64 decode ─────────────────────────────────────────────────────────
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

// ─── AES-256-GCM via CNG ───────────────────────────────────────────────────
static NTSTATUS aes_gcm_decrypt(const uint8_t* key32,
                                const uint8_t* nonce, DWORD nonce_len,
                                const uint8_t* ct, DWORD ct_len,
                                const uint8_t* tag, DWORD tag_len,
                                const uint8_t* aad, DWORD aad_len,
                                uint8_t* pt_out, DWORD* pt_len_out)
{
    VMProtectBeginUltra("aes_gcm_decrypt");
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS st = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (st < 0) { VMProtectEnd(); return st; }
    st = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                           (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                           sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (st < 0) goto out;
    st = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, (PUCHAR)key32, 32, 0);
    if (st < 0) goto out;

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = (PUCHAR)nonce; info.cbNonce = nonce_len;
    info.pbAuthData = (PUCHAR)aad; info.cbAuthData = aad_len;
    info.pbTag = (PUCHAR)tag; info.cbTag = tag_len;

    ULONG produced = 0;
    st = BCryptDecrypt(hKey, (PUCHAR)ct, ct_len, &info,
                       NULL, 0, pt_out, ct_len, &produced, 0);
    if (st >= 0 && pt_len_out) *pt_len_out = produced;
out:
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    VMProtectEnd();
    return st;
}

// Context-file key cache.
static uint8_t g_context_key[32];
static int     g_context_key_valid = 0;

// Parse argv for --koenflow-launch-context, DPAPI-unwrap if KFPC-magic'd,
// then pull "kfplKey":"<b64>" out of the JSON.
static void extract_key_from_launch_context(int argc, wchar_t** argv)
{
    VMProtectBeginUltra("extract_key_from_launch_context");
    for (int i = 1; i + 1 < argc; i++) {
        if (_wcsicmp(argv[i], L"--koenflow-launch-context") != 0 &&
            _wcsicmp(argv[i], L"--keonflow-launch-context") != 0) continue;
        const wchar_t* path = argv[i + 1];

        HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                               NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (h == INVALID_HANDLE_VALUE) { VMProtectEnd(); return; }
        LARGE_INTEGER sz;
        if (!GetFileSizeEx(h, &sz) || sz.QuadPart <= 0 || sz.QuadPart > 0x10000) {
            CloseHandle(h); VMProtectEnd(); return;
        }
        char* buf = (char*)VirtualAlloc(NULL, (SIZE_T)sz.QuadPart + 1,
                                        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!buf) { CloseHandle(h); VMProtectEnd(); return; }
        DWORD got = 0;
        BOOL rd = ReadFile(h, buf, (DWORD)sz.QuadPart, &got, NULL);
        CloseHandle(h);
        if (!rd || got == 0) { VirtualFree(buf, 0, MEM_RELEASE); VMProtectEnd(); return; }
        buf[got] = 0;

        char* json_ptr = buf;
        DWORD json_len = got;
        uint8_t* dpapi_pt = NULL;
        if (got >= 4 && memcmp(buf, "KFPC", 4) == 0) {
            DATA_BLOB in_blob  = { got - 4, (BYTE*)(buf + 4) };
            DATA_BLOB out_blob = { 0, NULL };
            if (!CryptUnprotectData(&in_blob, NULL, NULL, NULL, NULL, 0, &out_blob) ||
                out_blob.pbData == NULL || out_blob.cbData == 0) {
                dh_log("context: DPAPI unwrap FAILED gle=%lu (foreign profile? tampered?)",
                       GetLastError());
                SecureZeroMemory(buf, got);
                VirtualFree(buf, 0, MEM_RELEASE);
                VMProtectEnd();
                return;
            }
            dpapi_pt = out_blob.pbData;
            json_ptr = (char*)out_blob.pbData;
            json_len = out_blob.cbData;
            dh_log("context: DPAPI unwrap OK (%u ct -> %u pt bytes)",
                   (unsigned)in_blob.cbData, (unsigned)out_blob.cbData);
        }

        const char needle[] = "\"kfplKey\"";
        const DWORD nlen = sizeof(needle) - 1;
        char* p = NULL;
        for (DWORD j = 0; j + nlen <= json_len; j++) {
            if (memcmp(json_ptr + j, needle, nlen) == 0) { p = json_ptr + j; break; }
        }
        char* end = json_ptr + json_len;
        #define REMAIN() ((DWORD)(end - p))
        if (!p) { dh_log("context: kfplKey field not present"); goto ctx_cleanup; }
        p += nlen;
        while (REMAIN() > 0 && (*p == ' ' || *p == '\t')) p++;
        if (REMAIN() == 0 || *p != ':') goto ctx_cleanup;
        p++;
        while (REMAIN() > 0 && (*p == ' ' || *p == '\t')) p++;
        if (REMAIN() >= 4 && memcmp(p, "null", 4) == 0) {
            dh_log("context: kfplKey=null (backend returned no per-release key)");
            goto ctx_cleanup;
        }
        if (REMAIN() == 0 || *p != '"') goto ctx_cleanup;
        p++;

        char b64buf[80];
        int b64_len = 0;
        while (REMAIN() > 0 && *p != '"' && b64_len < (int)sizeof(b64buf) - 1) {
            b64buf[b64_len++] = *p++;
        }
        b64buf[b64_len] = 0;
        #undef REMAIN

        uint8_t keyout[32];
        if (b64_decode(b64buf, keyout, 32) == 32) {
            memcpy(g_context_key, keyout, 32);
            g_context_key_valid = 1;
            dh_log("context: kfplKey extracted (b64 %d chars, DPAPI=%d)", b64_len, dpapi_pt ? 1 : 0);
        } else {
            dh_log("context: kfplKey b64 decode failed (%d chars)", b64_len);
        }

    ctx_cleanup:
        if (dpapi_pt) { SecureZeroMemory(dpapi_pt, json_len); LocalFree(dpapi_pt); }
        SecureZeroMemory(buf, got);
        VirtualFree(buf, 0, MEM_RELEASE);
        VMProtectEnd();
        return;
    }
    VMProtectEnd();
}

// Env-var + context + baked key fallback chain.
static void resolve_key(uint8_t key32[32])
{
    VMProtectBeginUltra("resolve_key");
    uint8_t out[32]; int ok = 0;

    // Priority 0: context-file key (survives ShellExecute-runas).
    if (g_context_key_valid) {
        memcpy(out, g_context_key, 32);
        ok = 1;
    }

    static const char* B64_NAMES[] = {
        "DH_KFPL_KEY_B64",         // DeltaHack native
        "KFPL_KEY_B64",            // KoenFlow generic
        "AH_KFPL_KEY_B64",         // arenahack alias
        "KOENFLOW_KFPL_KEY_B64",   // KoenFlow prefixed
    };
    for (int i = 0; !ok && i < 4; i++) {
        char env_b64[128];
        DWORD n = GetEnvironmentVariableA(B64_NAMES[i], env_b64, sizeof(env_b64));
        if (n > 0 && n < sizeof(env_b64)) {
            env_b64[n] = 0;
            if (b64_decode(env_b64, out, 32) == 32) ok = 1;
        }
    }
    if (!ok) {
        static const wchar_t* HEX_NAMES[] = {
            L"DH_KFPL_KEY_HEX",
            L"KFPL_KEY_HEX",
            L"AH_KFPL_KEY_HEX",
            L"KOENFLOW_KFPL_KEY_HEX",
        };
        for (int i = 0; !ok && i < 4; i++) {
            wchar_t env_hex[128];
            DWORD nh = GetEnvironmentVariableW(HEX_NAMES[i], env_hex, 128);
            if (nh > 0 && nh < 128) {
                env_hex[nh] = 0;
                if (hex_decode(env_hex, out, 32) == 32) ok = 1;
            }
        }
    }
    if (!ok) memcpy(out, KFPL_KEY, 32);
    memcpy(key32, out, 32);
    VMProtectEnd();
}

// Self-trailer bundle read. Format past PE end:
//   [ bundle bytes (N) ][ u64 LE bundle_size ][ 4-byte magic "DHBE" ]
// Total trailer = 12 bytes. Windows loader ignores bytes past last section.
#define DHBE_MAGIC      "DHBE"
#define DHBE_TRAILER    12

static uint8_t* read_bundle_from_self(DWORD* out_size)
{
    if (out_size) *out_size = 0;

    wchar_t self_path[MAX_PATH];
    DWORD np = GetModuleFileNameW(NULL, self_path, MAX_PATH);
    if (!np || np >= MAX_PATH) return NULL;

    HANDLE h = CreateFileW(self_path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return NULL;

    LARGE_INTEGER sz;
    if (!GetFileSizeEx(h, &sz) || sz.QuadPart <= DHBE_TRAILER || sz.QuadPart > 0x40000000LL) {
        CloseHandle(h); return NULL;
    }

    LARGE_INTEGER off; off.QuadPart = sz.QuadPart - DHBE_TRAILER;
    if (!SetFilePointerEx(h, off, NULL, FILE_BEGIN)) { CloseHandle(h); return NULL; }
    uint8_t trailer[DHBE_TRAILER];
    DWORD rd = 0;
    if (!ReadFile(h, trailer, DHBE_TRAILER, &rd, NULL) || rd != DHBE_TRAILER) {
        CloseHandle(h); return NULL;
    }
    if (memcmp(trailer + 8, DHBE_MAGIC, 4) != 0) {
        CloseHandle(h); return NULL;
    }
    uint64_t bundle_size = 0;
    memcpy(&bundle_size, trailer, 8);
    if (bundle_size == 0 || bundle_size > 0x20000000ULL ||
        bundle_size + DHBE_TRAILER > (uint64_t)sz.QuadPart) {
        CloseHandle(h); return NULL;
    }

    off.QuadPart = sz.QuadPart - DHBE_TRAILER - (LONGLONG)bundle_size;
    if (!SetFilePointerEx(h, off, NULL, FILE_BEGIN)) { CloseHandle(h); return NULL; }

    uint8_t* buf = (uint8_t*)VirtualAlloc(NULL, (SIZE_T)bundle_size,
                                          MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buf) { CloseHandle(h); return NULL; }

    DWORD remaining = (DWORD)bundle_size, got = 0;
    uint8_t* cur = buf;
    while (remaining) {
        DWORD chunk = 0;
        if (!ReadFile(h, cur, remaining, &chunk, NULL) || chunk == 0) {
            VirtualFree(buf, 0, MEM_RELEASE); CloseHandle(h); return NULL;
        }
        cur += chunk; got += chunk; remaining -= chunk;
    }
    CloseHandle(h);
    if (out_size) *out_size = got;
    return buf;
}

// Legacy sidecar path — retained for dev workflow before trailer append.
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

// Anti-theft guard — silent kill on debugger / attach / HWBP / kernel debug port.
// Fires BEFORE any key material touches memory.
static void antitheft_guard(void)
{
    VMProtectBeginUltra("antitheft_guard");

    if (IsDebuggerPresent()) TerminateProcess(GetCurrentProcess(), 0);

    BOOL rdp = FALSE;
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &rdp) && rdp) {
        TerminateProcess(GetCurrentProcess(), 0);
    }

    #ifdef _WIN64
    DWORD peb_ngf = *(DWORD*)(__readgsqword(0x60) + 0xBC);
    #else
    DWORD peb_ngf = *(DWORD*)(__readfsdword(0x30) + 0x68);
    #endif
    if (peb_ngf & 0x70) TerminateProcess(GetCurrentProcess(), 0);

    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(GetCurrentThread(), &ctx)) {
        if (ctx.Dr0 | ctx.Dr1 | ctx.Dr2 | ctx.Dr3) {
            TerminateProcess(GetCurrentProcess(), 0);
        }
    }

    typedef NTSTATUS (WINAPI *NtQIP_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll) {
        NtQIP_t NtQIP = (NtQIP_t)GetProcAddress(ntdll, "NtQueryInformationProcess");
        if (NtQIP) {
            HANDLE dbg_port = (HANDLE)-1;
            ULONG rlen = 0;
            if (NtQIP(GetCurrentProcess(), 7 /*ProcessDebugPort*/,
                      &dbg_port, sizeof(dbg_port), &rlen) == 0 &&
                dbg_port != NULL) {
                TerminateProcess(GetCurrentProcess(), 0);
            }
            HANDLE dbg_obj = NULL;
            if (NtQIP(GetCurrentProcess(), 30 /*ProcessDebugObjectHandle*/,
                      &dbg_obj, sizeof(dbg_obj), &rlen) == 0 &&
                dbg_obj != NULL) {
                TerminateProcess(GetCurrentProcess(), 0);
            }
        }
    }

    VMProtectEnd();
}

int wmain(int argc, wchar_t** argv)
{
    // Anti-debug first — fires before any key-touch. Silent kill.
    antitheft_guard();

    dh_log("--- dh_launcher start argc=%d", argc);

    // Per-release KFPL key from context (before resolve_key hits).
    extract_key_from_launch_context(argc, argv);

    wchar_t self_path[MAX_PATH];
    GetModuleFileNameW(NULL, self_path, MAX_PATH);
    wchar_t self_dir[MAX_PATH];
    wcscpy_s(self_dir, MAX_PATH, self_path);
    PathRemoveFileSpecW(self_dir);
    dh_log("self_dir=%ls", self_dir);

    // Provider chain needs DH_INSTALL_DIR to find db/*.bin.
    SetEnvironmentVariableW(L"DH_INSTALL_DIR", self_dir);

    // Bundle: self-trailer first, sidecar bundle.kfpl fallback for dev.
    DWORD blob_size = 0;
    uint8_t* blob = read_bundle_from_self(&blob_size);
    if (blob) {
        dh_log("bundle: self-trailer size=%lu", blob_size);
    } else {
        wchar_t bpath[MAX_PATH];
        if (!bundle_path(bpath, MAX_PATH)) { dh_log("bundle_path fail"); DH_MB(L"bundle path"); return 2; }
        dh_log("bundle: sidecar path=%ls", bpath);
        blob = read_file_all(bpath, &blob_size);
        if (!blob) { dh_log("bundle read fail"); DH_MB(L"bundle read"); return 2; }
        dh_log("bundle: sidecar size=%lu", blob_size);
    }
    if (blob_size < KFPL_HEADER_LEN + TAG_LEN) {
        dh_log("bundle truncated"); VirtualFree(blob, 0, MEM_RELEASE); DH_MB(L"bundle truncated"); return 2;
    }

    // Parse KFPL header.
    if (memcmp(blob, KFPL_MAGIC, 4) != 0) {
        dh_log("magic mismatch: %02X %02X %02X %02X", blob[0],blob[1],blob[2],blob[3]);
        VirtualFree(blob, 0, MEM_RELEASE); DH_MB(L"magic"); return 2;
    }
    uint32_t version; memcpy(&version, blob + 4, 4);
    if (version != 1) {
        VirtualFree(blob, 0, MEM_RELEASE); DH_MB(L"version"); return 2;
    }
    const uint8_t* nonce = blob + 8;
    uint64_t ct_len; memcpy(&ct_len, blob + 20, 8);
    if (KFPL_HEADER_LEN + ct_len + TAG_LEN != blob_size) {
        VirtualFree(blob, 0, MEM_RELEASE); DH_MB(L"size"); return 2;
    }
    const uint8_t* ct  = blob + KFPL_HEADER_LEN;
    const uint8_t* tag = ct + ct_len;

    // Decrypt.
    uint8_t key32[32]; resolve_key(key32);
    dh_log("key32 first bytes: %02X %02X %02X %02X ...",
           key32[0], key32[1], key32[2], key32[3]);
    uint8_t* pt = (uint8_t*)VirtualAlloc(NULL, (SIZE_T)ct_len,
                                          MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pt) { VirtualFree(blob, 0, MEM_RELEASE); DH_MB(L"alloc"); return 99; }

    DWORD pt_len = 0;
    NTSTATUS st = aes_gcm_decrypt(key32, nonce, NONCE_LEN,
                                  ct, (DWORD)ct_len, tag, TAG_LEN,
                                  KFPL_MAGIC, sizeof(KFPL_MAGIC),
                                  pt, &pt_len);
    SecureZeroMemory(key32, sizeof(key32));
    VirtualFree(blob, 0, MEM_RELEASE);
    if (st < 0) {
        dh_log("aes_gcm_decrypt fail NTSTATUS=0x%08lX", (unsigned long)st);
        SecureZeroMemory(pt, (SIZE_T)ct_len); VirtualFree(pt, 0, MEM_RELEASE);
        wchar_t msg[64]; (void)msg;
        DH_MB_F(msg, L"decrypt %08lX", (unsigned long)st);
        return 2;
    }
    dh_log("decrypt OK pt_len=%lu", pt_len);

    // Materialize temp exe.
    wchar_t tmp_dir[MAX_PATH]; GetTempPathW(MAX_PATH, tmp_dir);
    wchar_t rand_name[64]; make_random_name(rand_name, 64);
    wchar_t tmp_path[MAX_PATH];
    swprintf(tmp_path, MAX_PATH, L"%s%s", tmp_dir, rand_name);

    dh_log("tmp path=%ls", tmp_path);
    HANDLE hFile = CreateFileW(tmp_path, GENERIC_WRITE, FILE_SHARE_READ,
                               NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        dh_log("tmp create fail gle=%lu", GetLastError());
        SecureZeroMemory(pt, (SIZE_T)ct_len); VirtualFree(pt, 0, MEM_RELEASE);
        DH_MB(L"tmp create"); return 99;
    }
    DWORD written = 0;
    WriteFile(hFile, pt, pt_len, &written, NULL);
    CloseHandle(hFile);
    dh_log("tmp write %lu of %lu", written, pt_len);
    SecureZeroMemory(pt, (SIZE_T)ct_len); VirtualFree(pt, 0, MEM_RELEASE);
    if (written != pt_len) { DeleteFileW(tmp_path); DH_MB(L"tmp write"); return 99; }

    // Spawn payload — cwd=self_dir so db/*.bin path resolves.
    wchar_t cmdline[8192];
    swprintf(cmdline, 8192, L"\"%s\"", tmp_path);
    for (int i = 1; i < argc; i++) {
        wcscat_s(cmdline, 8192, L" \"");
        wcscat_s(cmdline, 8192, argv[i]);
        wcscat_s(cmdline, 8192, L"\"");
    }
    dh_log("cmdline=%ls", cmdline);

    STARTUPINFOW si = { sizeof(si) };
    si.dwFlags     = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = {0};
    BOOL ok = CreateProcessW(tmp_path, cmdline, NULL, NULL, FALSE,
                             DETACHED_PROCESS | CREATE_NO_WINDOW,
                             NULL, self_dir, &si, &pi);
    if (!ok) {
        DWORD e = GetLastError(); dh_log("CreateProcess fail gle=%lu", e);
        DeleteFileW(tmp_path);
        wchar_t msg[128]; (void)msg;
        DH_MB_F(msg, L"CreateProcess %lu", e);
        return 99;
    }
    dh_log("child spawned pid=%lu", pi.dwProcessId);
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exit_code = 0; GetExitCodeProcess(pi.hProcess, &exit_code);
    dh_log("child exit_code=%lu (0x%08lX)", exit_code, exit_code);

    // Telemetry — POST log tails + crash artefacts + machine profile to
    // https://koenflow.com/api/telemetry/crash. Silent, 5s per stage, never
    // blocks launcher exit. Server dir key = SHA256(MachineGuid|ComputerName).
    extern void dh_crash_upload_after_child(DWORD child_pid, DWORD exit_code, const char* version);
    dh_crash_upload_after_child(pi.dwProcessId, exit_code, "dh-1.0.0");

    CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    DeleteFileW(tmp_path);
    return (int)exit_code;
}

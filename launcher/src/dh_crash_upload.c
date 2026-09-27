// dh_crash_upload.c — auto-post client log tails to
//   https://koenflow.com/api/telemetry/crash
// after the overlay child exits. Silent on failure — never blocks launcher.
//
// Payload: multipart/form-data, plain-text log bytes (no gzip; server accepts
// up to 8 MB total). Fields:
//   license_hash   64-hex SHA256(MachineGuid + ComputerName)   — server dir key
//   product        "deltahack"
//   version        compile-time string
//   os_build       Windows CurrentBuild (RtlGetVersion)
//   os_product     Windows edition string (SKU)
//   screen_w/h     primary monitor resolution
//   ram_mb         GlobalMemoryStatusEx TotalPhys
//   cpu_brand      CPUID EAX=0x80000002..4 brand string
//   gpu_desc       DXGI IDXGIAdapter1 description (best-effort)
//   exit_code      overlay child exit code, hex
//   parent_pid     launcher PID
//   child_pid      overlay PID
//   dh_launcher    up to 500 KB tail  — KFPL stub log
//   dh_reader      up to 500 KB tail  — reader thread per-tick diag
//   dh_procs       up to 500 KB tail  — periodic tasklist snapshots
//   core_log       up to 500 KB tail  — overlay/daemon WARN/ERROR log
//   crash_meta     up to 16 KB       — VEH exception meta (opt)
//   crash_dump     up to 2 MB        — MiniDump (opt)
//
// Auth: none beyond license_hash. Server has no reply the launcher needs.

#include <windows.h>
#include <winhttp.h>
#include <bcrypt.h>
#include <shlobj.h>
#include <intrin.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Ole32.lib")

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "bcrypt.lib")

#define TELEM_HOST   L"koenflow.com"
#define TELEM_PATH   L"/api/telemetry/crash"
#define TAIL_BYTES   (500 * 1024)
#define BODY_MAX     (8  * 1024 * 1024)

extern void dh_log(const char* fmt, ...);   // provided by dh_launcher.c
// dh_log is currently 'static' in dh_launcher.c — for the extern link to
// resolve, the caller (dh_launcher.c) unstatics it or we log locally.
// Local fallback below in case ext link isn't wired.

// ─── helpers ────────────────────────────────────────────────────────────────

static void get_machine_guid(char out[64]) {
    HKEY hk = NULL;
    out[0] = 0;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SOFTWARE\\Microsoft\\Cryptography", 0,
                      KEY_READ | KEY_WOW64_64KEY, &hk) == ERROR_SUCCESS) {
        wchar_t buf[64] = {0};
        DWORD cb = sizeof(buf);
        DWORD type = 0;
        if (RegQueryValueExW(hk, L"MachineGuid", NULL, &type,
                             (LPBYTE)buf, &cb) == ERROR_SUCCESS && type == REG_SZ) {
            WideCharToMultiByte(CP_UTF8, 0, buf, -1, out, 63, NULL, NULL);
        }
        RegCloseKey(hk);
    }
}

static void compute_license_hash(char hex_out[65]) {
    char guid[64] = {0};
    get_machine_guid(guid);
    char host[64] = {0};
    DWORD hn = sizeof(host);
    GetComputerNameA(host, &hn);

    char blob[192];
    int n = _snprintf_s(blob, sizeof(blob), _TRUNCATE, "%s|%s", guid, host);
    if (n <= 0) { strcpy_s(hex_out, 65, "0"); return; }

    BCRYPT_ALG_HANDLE alg = NULL;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL, 0) < 0) {
        strcpy_s(hex_out, 65, "1"); return;
    }
    BYTE digest[32] = {0};
    NTSTATUS st = BCryptHash(alg, NULL, 0, (PUCHAR)blob, (ULONG)n, digest, sizeof(digest));
    BCryptCloseAlgorithmProvider(alg, 0);
    if (st < 0) { strcpy_s(hex_out, 65, "2"); return; }
    static const char* HEX = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        hex_out[i*2]   = HEX[(digest[i] >> 4) & 0xF];
        hex_out[i*2+1] = HEX[ digest[i]       & 0xF];
    }
    hex_out[64] = 0;
}

static DWORD get_os_build(void) {
    typedef LONG (WINAPI *pfnRtlGetVersion)(POSVERSIONINFOEXW);
    HMODULE nt = GetModuleHandleA("ntdll.dll");
    if (!nt) return 0;
    pfnRtlGetVersion p = (pfnRtlGetVersion)GetProcAddress(nt, "RtlGetVersion");
    if (!p) return 0;
    OSVERSIONINFOEXW v = {0}; v.dwOSVersionInfoSize = sizeof(v);
    if (p(&v) < 0) return 0;
    return v.dwBuildNumber;
}

// Windows edition: Home / Pro / Enterprise / IoT / ProWorkstation ...
static void get_os_product(char* out, size_t cap) {
    out[0] = 0;
    HKEY hk = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0,
                      KEY_READ | KEY_WOW64_64KEY, &hk) == ERROR_SUCCESS) {
        wchar_t buf[128] = {0};
        DWORD cb = sizeof(buf); DWORD type = 0;
        if (RegQueryValueExW(hk, L"ProductName", NULL, &type,
                             (LPBYTE)buf, &cb) == ERROR_SUCCESS && type == REG_SZ) {
            WideCharToMultiByte(CP_UTF8, 0, buf, -1, out, (int)cap - 1, NULL, NULL);
        }
        RegCloseKey(hk);
    }
    if (!out[0]) strcpy_s(out, cap, "unknown");
}

// CPU brand string via CPUID leaves 0x80000002..0x80000004.
static void get_cpu_brand(char* out, size_t cap) {
    out[0] = 0;
    int cpuinfo[4] = {0};
    __cpuid(cpuinfo, 0x80000000);
    if ((unsigned)cpuinfo[0] < 0x80000004) { strcpy_s(out, cap, "unknown"); return; }
    char brand[49] = {0};
    for (unsigned int i = 0; i < 3; i++) {
        __cpuid((int*)(brand + i * 16), 0x80000002 + i);
    }
    brand[48] = 0;
    // strip leading spaces
    const char* p = brand;
    while (*p == ' ') p++;
    strncpy_s(out, cap, p, _TRUNCATE);
}

static void get_ram_mb(char* out, size_t cap) {
    MEMORYSTATUSEX ms = { sizeof(ms) };
    if (GlobalMemoryStatusEx(&ms)) {
        _snprintf_s(out, cap, _TRUNCATE, "%llu",
                    (unsigned long long)(ms.ullTotalPhys / (1024 * 1024)));
    } else {
        strcpy_s(out, cap, "0");
    }
}

static void get_screen_dims(int* w, int* h) {
    *w = GetSystemMetrics(SM_CXSCREEN);
    *h = GetSystemMetrics(SM_CYSCREEN);
}

// Best-effort GPU description via dxgi.dll dynamic load (avoids link-time dep
// if launcher is stripped of D3D imports).
static void get_gpu_desc(char* out, size_t cap) {
    out[0] = 0;
    HMODULE dxgi = LoadLibraryW(L"dxgi.dll");
    if (!dxgi) { strcpy_s(out, cap, "no-dxgi"); return; }
    typedef HRESULT (WINAPI *pfnCreateDXGIFactory1)(REFIID, void**);
    pfnCreateDXGIFactory1 pCreate = (pfnCreateDXGIFactory1)GetProcAddress(dxgi, "CreateDXGIFactory1");
    if (!pCreate) { FreeLibrary(dxgi); strcpy_s(out, cap, "no-factory"); return; }

    // Manually declare IDXGIFactory1::EnumAdapters1 + IDXGIAdapter1::GetDesc1
    // via IID_IDXGIFactory1 = 770aae78-f26f-4dba-a829-253c83d1b387
    static const GUID IID_IDXGIFactory1_local =
        { 0x770aae78, 0xf26f, 0x4dba, { 0xa8, 0x29, 0x25, 0x3c, 0x83, 0xd1, 0xb3, 0x87 } };
    typedef struct { void* lpVtbl; } IUnknownStub;

    void* factory = NULL;
    if (pCreate(&IID_IDXGIFactory1_local, &factory) < 0 || !factory) {
        FreeLibrary(dxgi); strcpy_s(out, cap, "factory-fail"); return;
    }

    // vtable slot 6 = EnumAdapters1(index, IDXGIAdapter1**)
    typedef HRESULT (STDMETHODCALLTYPE *pfnEnumAdapters1)(void*, UINT, void**);
    void** vt = *(void***)factory;
    pfnEnumAdapters1 pEnum = (pfnEnumAdapters1)vt[6];   // Release, AddRef ... slot 6

    void* adapter = NULL;
    if (pEnum(factory, 0, &adapter) < 0 || !adapter) {
        typedef ULONG (STDMETHODCALLTYPE *pfnRelease)(void*);
        pfnRelease pR = (pfnRelease)vt[2];
        pR(factory);
        FreeLibrary(dxgi); strcpy_s(out, cap, "no-adapter"); return;
    }

    // IDXGIAdapter1::GetDesc1 = vtable slot 10.
    struct DXGI_ADAPTER_DESC1_MIN {
        WCHAR   Description[128];
        UINT    VendorId, DeviceId, SubSysId, Revision;
        SIZE_T  DedicatedVideoMemory, DedicatedSystemMemory, SharedSystemMemory;
        LUID    AdapterLuid;
        UINT    Flags;
    } desc = {0};

    typedef HRESULT (STDMETHODCALLTYPE *pfnGetDesc1)(void*, struct DXGI_ADAPTER_DESC1_MIN*);
    void** adv = *(void***)adapter;
    pfnGetDesc1 pDesc = (pfnGetDesc1)adv[10];
    if (pDesc(adapter, &desc) >= 0) {
        WideCharToMultiByte(CP_UTF8, 0, desc.Description, -1, out, (int)cap - 1, NULL, NULL);
    }

    // Release adapter + factory (vtable slot 2 = Release)
    typedef ULONG (STDMETHODCALLTYPE *pfnRel)(void*);
    ((pfnRel)adv[2])(adapter);
    ((pfnRel)vt[2])(factory);
    FreeLibrary(dxgi);
    if (!out[0]) strcpy_s(out, cap, "no-desc");
}

// Read tail up to `max` bytes from a file.
static void read_tail(const wchar_t* path, uint8_t** out_buf, DWORD* out_size) {
    *out_buf = NULL; *out_size = 0;
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    LARGE_INTEGER sz;
    if (!GetFileSizeEx(h, &sz)) { CloseHandle(h); return; }
    DWORD want = (DWORD)((sz.QuadPart > (LONGLONG)TAIL_BYTES) ? TAIL_BYTES : sz.QuadPart);
    if (want == 0) { CloseHandle(h); return; }
    LARGE_INTEGER off; off.QuadPart = sz.QuadPart - (LONGLONG)want;
    SetFilePointerEx(h, off, NULL, FILE_BEGIN);
    uint8_t* buf = (uint8_t*)HeapAlloc(GetProcessHeap(), 0, want);
    if (!buf) { CloseHandle(h); return; }
    DWORD got = 0;
    if (!ReadFile(h, buf, want, &got, NULL) || got == 0) {
        HeapFree(GetProcessHeap(), 0, buf); CloseHandle(h); return;
    }
    CloseHandle(h);
    *out_buf  = buf;
    *out_size = got;
}

// Whole-file read (for binary artefacts: MiniDump).
static void read_whole(const wchar_t* path, DWORD cap,
                       uint8_t** out_buf, DWORD* out_size) {
    *out_buf = NULL; *out_size = 0;
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    LARGE_INTEGER sz;
    if (!GetFileSizeEx(h, &sz) || sz.QuadPart <= 0 || sz.QuadPart > (LONGLONG)cap) {
        CloseHandle(h); return;
    }
    DWORD want = (DWORD)sz.QuadPart;
    uint8_t* buf = (uint8_t*)HeapAlloc(GetProcessHeap(), 0, want);
    if (!buf) { CloseHandle(h); return; }
    DWORD got = 0;
    if (!ReadFile(h, buf, want, &got, NULL) || got != want) {
        HeapFree(GetProcessHeap(), 0, buf); CloseHandle(h); return;
    }
    CloseHandle(h);
    *out_buf  = buf;
    *out_size = got;
}

static int mp_field(uint8_t** body, size_t* len, size_t* cap,
                    const char* boundary,
                    const char* name,
                    const char* filename_or_null,
                    const uint8_t* data, size_t data_len) {
    char header[512];
    int hn;
    if (filename_or_null) {
        hn = _snprintf_s(header, sizeof(header), _TRUNCATE,
            "--%s\r\nContent-Disposition: form-data; name=\"%s\"; filename=\"%s\"\r\n"
            "Content-Type: application/octet-stream\r\n\r\n",
            boundary, name, filename_or_null);
    } else {
        hn = _snprintf_s(header, sizeof(header), _TRUNCATE,
            "--%s\r\nContent-Disposition: form-data; name=\"%s\"\r\n\r\n",
            boundary, name);
    }
    if (hn <= 0) return 0;

    size_t need = *len + (size_t)hn + data_len + 2;
    if (need > BODY_MAX) return 0;
    if (need > *cap) {
        size_t new_cap = *cap ? *cap * 2 : 4096;
        while (new_cap < need) new_cap *= 2;
        uint8_t* nb = *body
            ? (uint8_t*)HeapReAlloc(GetProcessHeap(), 0, *body, new_cap)
            : (uint8_t*)HeapAlloc  (GetProcessHeap(), 0, new_cap);
        if (!nb) return 0;
        *body = nb; *cap = new_cap;
    }
    memcpy(*body + *len, header, (size_t)hn); *len += (size_t)hn;
    memcpy(*body + *len, data, data_len);     *len += data_len;
    memcpy(*body + *len, "\r\n", 2);          *len += 2;
    return 1;
}

// Public entry — called from dh_launcher.c after WaitForSingleObject(child).
void dh_crash_upload_after_child(DWORD child_pid, DWORD exit_code, const char* version)
{
    // 1. Gather metadata.
    char license_hash[65]; compute_license_hash(license_hash);
    DWORD os_build   = get_os_build();
    DWORD parent_pid = GetCurrentProcessId();

    char os_prod[128], cpu_brand[64], ram_mb[24], gpu_desc[160];
    int  scr_w, scr_h;
    get_os_product(os_prod, sizeof(os_prod));
    get_cpu_brand(cpu_brand, sizeof(cpu_brand));
    get_ram_mb(ram_mb, sizeof(ram_mb));
    get_gpu_desc(gpu_desc, sizeof(gpu_desc));
    get_screen_dims(&scr_w, &scr_h);

    // 2. Read log tails.
    uint8_t* launcher_buf = NULL; DWORD launcher_len = 0;
    uint8_t* reader_buf   = NULL; DWORD reader_len   = 0;
    uint8_t* procs_buf    = NULL; DWORD procs_len    = 0;
    uint8_t* core_buf     = NULL; DWORD core_len     = 0;
    uint8_t* crashmeta_buf = NULL; DWORD crashmeta_len = 0;
    uint8_t* dump_buf     = NULL; DWORD dump_len     = 0;

    // launcher stub log
    {
        wchar_t p[MAX_PATH];
        DWORD n = GetTempPathW(MAX_PATH, p);
        if (n > 0 && n < MAX_PATH - 32) {
            wcscat_s(p, MAX_PATH, L"dh_launcher.log");
            read_tail(p, &launcher_buf, &launcher_len);
        }
    }
    // reader diag + procs snapshot logs (written by overlay/daemon into
    // C:\Users\Public\ so both user and SYSTEM daemon can append). Arena's
    // path convention preserved.
    read_tail(L"C:\\Users\\Public\\dh_reader.log", &reader_buf, &reader_len);
    read_tail(L"C:\\Users\\Public\\dh_procs.log",  &procs_buf,  &procs_len);

    // core.log — payload WARN/ERROR sink (dh_log via SHGetFolderPath LocalAppData).
    {
        wchar_t p[MAX_PATH];
        if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, p))) {
            wcscat_s(p, MAX_PATH, L"\\Microsoft\\Windows\\DiagnosticCache\\core.log");
            read_tail(p, &core_buf, &core_len);
        }
    }

    // Crash meta / MiniDump (payload writes on VEH catch).
    {
        wchar_t p[MAX_PATH];
        DWORD n = GetTempPathW(MAX_PATH, p);
        if (n > 0 && n < MAX_PATH - 32) {
            wchar_t base[MAX_PATH]; wcscpy_s(base, MAX_PATH, p);
            wcscat_s(p, MAX_PATH, L".dh_crash_meta");
            read_whole(p, 16 * 1024, &crashmeta_buf, &crashmeta_len);
            if (crashmeta_len) DeleteFileW(p);
            wcscpy_s(p, MAX_PATH, base);
            wcscat_s(p, MAX_PATH, L".dh_crash_dump.dmp");
            read_whole(p, 2 * 1024 * 1024, &dump_buf, &dump_len);
            if (dump_len) DeleteFileW(p);
        }
    }

    dh_log("crash_upload: hash=%.16s... build=%u ec=0x%08lX launcher=%lu reader=%lu procs=%lu core=%lu meta=%lu dump=%lu",
           license_hash, os_build, exit_code,
           launcher_len, reader_len, procs_len, core_len, crashmeta_len, dump_len);

    // 3. Build multipart body.
    char boundary[48];
    ULONGLONG t = GetTickCount64();
    _snprintf_s(boundary, sizeof(boundary), _TRUNCATE,
                "----dhUp%016llX%08X", t, (unsigned)parent_pid);

    uint8_t* body = NULL; size_t body_len = 0, body_cap = 0;
    char meta[192];

    mp_field(&body, &body_len, &body_cap, boundary, "license_hash", NULL,
             (const uint8_t*)license_hash, 64);

    mp_field(&body, &body_len, &body_cap, boundary, "product", NULL,
             (const uint8_t*)"deltahack", 9);

    _snprintf_s(meta, sizeof(meta), _TRUNCATE, "%s", version ? version : "unknown");
    mp_field(&body, &body_len, &body_cap, boundary, "version", NULL,
             (const uint8_t*)meta, strlen(meta));

    _snprintf_s(meta, sizeof(meta), _TRUNCATE, "%u", os_build);
    mp_field(&body, &body_len, &body_cap, boundary, "os_build", NULL,
             (const uint8_t*)meta, strlen(meta));

    mp_field(&body, &body_len, &body_cap, boundary, "os_product", NULL,
             (const uint8_t*)os_prod, strlen(os_prod));

    _snprintf_s(meta, sizeof(meta), _TRUNCATE, "%d", scr_w);
    mp_field(&body, &body_len, &body_cap, boundary, "screen_w", NULL,
             (const uint8_t*)meta, strlen(meta));
    _snprintf_s(meta, sizeof(meta), _TRUNCATE, "%d", scr_h);
    mp_field(&body, &body_len, &body_cap, boundary, "screen_h", NULL,
             (const uint8_t*)meta, strlen(meta));

    mp_field(&body, &body_len, &body_cap, boundary, "ram_mb", NULL,
             (const uint8_t*)ram_mb, strlen(ram_mb));
    mp_field(&body, &body_len, &body_cap, boundary, "cpu_brand", NULL,
             (const uint8_t*)cpu_brand, strlen(cpu_brand));
    mp_field(&body, &body_len, &body_cap, boundary, "gpu_desc", NULL,
             (const uint8_t*)gpu_desc, strlen(gpu_desc));

    _snprintf_s(meta, sizeof(meta), _TRUNCATE, "0x%08lX", exit_code);
    mp_field(&body, &body_len, &body_cap, boundary, "exit_code", NULL,
             (const uint8_t*)meta, strlen(meta));

    _snprintf_s(meta, sizeof(meta), _TRUNCATE, "%lu", parent_pid);
    mp_field(&body, &body_len, &body_cap, boundary, "parent_pid", NULL,
             (const uint8_t*)meta, strlen(meta));

    _snprintf_s(meta, sizeof(meta), _TRUNCATE, "%lu", child_pid);
    mp_field(&body, &body_len, &body_cap, boundary, "child_pid", NULL,
             (const uint8_t*)meta, strlen(meta));

    // NOTE: field names use "ah_" prefix — the koenflow.com telemetry server
    // is shared with arenahack and its parseMultipart hardcodes ah_launcher /
    // ah_reader / ah_procs / ah_crashmeta / ah_dump as the accepted keys.
    // We keep the DH filenames inside the multipart for clarity when server
    // dumps them to disk (server names files after field key, but the client
    // can hint the actual product via the "product" text field).
    if (launcher_buf && launcher_len)
        mp_field(&body, &body_len, &body_cap, boundary, "ah_launcher",
                 "dh_launcher.log", launcher_buf, launcher_len);
    if (reader_buf && reader_len)
        mp_field(&body, &body_len, &body_cap, boundary, "ah_reader",
                 "dh_reader.log", reader_buf, reader_len);
    if (procs_buf && procs_len)
        mp_field(&body, &body_len, &body_cap, boundary, "ah_procs",
                 "dh_procs.log", procs_buf, procs_len);
    // Server accepts only one "ah_crashmeta" — prefer crash_meta.txt (SEH
    // context) over core.log when both present, because dh_reader already
    // carries most of what core.log has (both are per-tick diag streams).
    // If no crash_meta this run, fall back to core.log tail so we still
    // ship the payload's WARN/ERROR history.
    if (crashmeta_buf && crashmeta_len) {
        mp_field(&body, &body_len, &body_cap, boundary, "ah_crashmeta",
                 "crash_meta.txt", crashmeta_buf, crashmeta_len);
    } else if (core_buf && core_len) {
        mp_field(&body, &body_len, &body_cap, boundary, "ah_crashmeta",
                 "core.log", core_buf, core_len);
    }
    if (dump_buf && dump_len)
        mp_field(&body, &body_len, &body_cap, boundary, "ah_dump",
                 "crash_dump.dmp", dump_buf, dump_len);

    // Final boundary.
    {
        char tail[128];
        int tn = _snprintf_s(tail, sizeof(tail), _TRUNCATE, "--%s--\r\n", boundary);
        if (tn > 0 && body_len + (size_t)tn <= BODY_MAX) {
            if (body_len + (size_t)tn > body_cap) {
                size_t nc = body_cap + (size_t)tn + 64;
                uint8_t* nb = (uint8_t*)HeapReAlloc(GetProcessHeap(), 0, body, nc);
                if (nb) { body = nb; body_cap = nc; }
            }
            if (body) {
                memcpy(body + body_len, tail, (size_t)tn);
                body_len += (size_t)tn;
            }
        }
    }

    if (!body || body_len == 0) {
        dh_log("crash_upload: empty body — skipping POST");
        goto cleanup;
    }

    // 4. WinHTTP POST — 5s timeouts, NO_PROXY (WPAD lookup blocks elevated child).
    HINTERNET hSess = WinHttpOpen(L"dhUploader/1.0",
                                  WINHTTP_ACCESS_TYPE_NO_PROXY,
                                  WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSess) { dh_log("crash_upload: WinHttpOpen fail gle=%lu", GetLastError()); goto cleanup; }
    WinHttpSetTimeouts(hSess, 5000, 5000, 5000, 5000);
    DWORD tls = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;
    WinHttpSetOption(hSess, WINHTTP_OPTION_SECURE_PROTOCOLS, &tls, sizeof(tls));

    HINTERNET hConn = WinHttpConnect(hSess, TELEM_HOST, INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConn) { dh_log("crash_upload: WinHttpConnect fail"); WinHttpCloseHandle(hSess); goto cleanup; }

    HINTERNET hReq = WinHttpOpenRequest(hConn, L"POST", TELEM_PATH, NULL,
                                        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                        WINHTTP_FLAG_SECURE);
    if (!hReq) { dh_log("crash_upload: OpenRequest fail"); WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSess); goto cleanup; }

    wchar_t ct_hdr[128];
    _snwprintf_s(ct_hdr, 128, _TRUNCATE, L"Content-Type: multipart/form-data; boundary=%S", boundary);

    BOOL ok = WinHttpSendRequest(hReq, ct_hdr, (DWORD)-1L,
                                 body, (DWORD)body_len, (DWORD)body_len, 0);
    if (ok) ok = WinHttpReceiveResponse(hReq, NULL);
    DWORD status = 0, szsz = sizeof(status);
    if (ok) {
        WinHttpQueryHeaders(hReq,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            NULL, &status, &szsz, WINHTTP_NO_HEADER_INDEX);
    }
    dh_log("crash_upload: POST status=%lu (body=%zu)", status, body_len);

    WinHttpCloseHandle(hReq);
    WinHttpCloseHandle(hConn);
    WinHttpCloseHandle(hSess);

cleanup:
    if (launcher_buf)  HeapFree(GetProcessHeap(), 0, launcher_buf);
    if (reader_buf)    HeapFree(GetProcessHeap(), 0, reader_buf);
    if (procs_buf)     HeapFree(GetProcessHeap(), 0, procs_buf);
    if (core_buf)      HeapFree(GetProcessHeap(), 0, core_buf);
    if (crashmeta_buf) HeapFree(GetProcessHeap(), 0, crashmeta_buf);
    if (dump_buf)      HeapFree(GetProcessHeap(), 0, dump_buf);
    if (body)          HeapFree(GetProcessHeap(), 0, body);
}

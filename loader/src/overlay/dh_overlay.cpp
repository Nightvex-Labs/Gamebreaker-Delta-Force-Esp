// DeltaHack — D3D11 + DirectComposition + Direct2D transparent overlay.
//
// GDI+layered magenta doesn't overlay on modern D3D11 games (Delta is a UE4
// title running D3D11 in borderless/fullscreen mode). The Windows compositor
// bypasses layered redirection surfaces when the target draws through DWM
// composition itself. The correct pattern (used by ABIFINAL prod overlay) is:
//
//   WS_EX_NOREDIRECTIONBITMAP window (no redirection bitmap = no compositor
//     interference) with DirectComposition target + visual bound to a
//     DXGI 1.2 swap chain created with DXGI_ALPHA_MODE_PREMULTIPLIED.
//
// D2D1 renders shapes/text into the swap chain back buffer; DComp commits the
// visual tree; DWM composes it above the game every frame.

#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <d3d11.h>
#include <dxgi1_2.h>
#include <dcomp.h>
#include <d2d1_1.h>
#include <dwrite.h>
#include <math.h>
#include <stdio.h>
#include <string.h>
extern "C" {
#include "../../inc/dh_common.h"
#include "../../inc/dh_shmem.h"
}

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")
#pragma comment(lib, "dcomp.lib")
#pragma comment(lib, "d2d1.lib")
#pragma comment(lib, "dwrite.lib")

typedef DH_SHMEM_PLAYER DH_ESP_ENTRY;

typedef struct {
    // shmem reader
    HANDLE  hMap;
    DH_SHMEM* shmem;

    DH_ESP_ENTRY players[DH_MAX_PLAYERS];
    int   count;
    int   myTeam;
    float myX, myY, myZ;      // camera / player position
    float myYaw, myPitch, myRoll;
    float fov;

    CRITICAL_SECTION lock;
    volatile LONG    running;

    HWND  hwnd;
    int   sw, sh;

    // D3D11
    ID3D11Device*        d3d;
    ID3D11DeviceContext* ctx;
    IDXGISwapChain1*     sc;
    // DComp
    IDCompositionDevice* dcomp;
    IDCompositionTarget* dcompT;
    IDCompositionVisual* dcompV;
    // D2D
    ID2D1Factory1*       d2dFactory;
    ID2D1Device*         d2dDev;
    ID2D1DeviceContext*  d2dCtx;
    ID2D1Bitmap1*        d2dBitmap;
    // DWrite
    IDWriteFactory*      dwrite;
    IDWriteTextFormat*   fmtSmall;
    IDWriteTextFormat*   fmtLarge;
} DH_OVERLAY;

// -----------------------------------------------------------------------------
// shmem poll (from daemon)
// -----------------------------------------------------------------------------

static void poll_once(DH_OVERLAY* ov)
{
    if (!ov->shmem) return;

    // ---- Entity block (seqlock #1: sequence) ----
    // Read count + players[] under the primary entity seqlock. Do NOT read
    // cam fields here — they live under cam_seq (updated ~40x more often).
    u32 count = 0;
    i32 myTeam = 0;
    static DH_SHMEM_PLAYER tmp_players[DH_MAX_PLAYERS];
    for (int retry = 0; retry < 8; retry++) {
        u32 s1 = ov->shmem->sequence;
        if (s1 & 1) { Sleep(0); continue; }
        MemoryBarrier();
        u32 c = ov->shmem->count;
        i32 mt = ov->shmem->myTeam;
        memcpy(tmp_players, (void*)ov->shmem->players, sizeof(tmp_players));
        MemoryBarrier();
        u32 s2 = ov->shmem->sequence;
        if (s1 == s2) { count = c; myTeam = mt; break; }
    }
    if (ov->shmem->magic != DH_SHMEM_MAGIC) return;

    // ---- Camera block (seqlock #2: cam_seq) ----
    // Independent, higher-frequency lock. Cam thread writes here every ~4ms.
    float mx=0, my=0, mz=0, myaw=0, mpitch=0, mroll=0, mfov=90.f;
    for (int retry = 0; retry < 8; retry++) {
        u32 s1 = ov->shmem->cam_seq;
        if (s1 & 1) { Sleep(0); continue; }
        MemoryBarrier();
        float _mx = ov->shmem->myX, _my = ov->shmem->myY, _mz = ov->shmem->myZ;
        float _yaw = ov->shmem->myYaw, _pitch = ov->shmem->myPitch, _roll = ov->shmem->myRoll;
        float _fov = ov->shmem->fov;
        MemoryBarrier();
        u32 s2 = ov->shmem->cam_seq;
        if (s1 == s2) {
            mx=_mx; my=_my; mz=_mz;
            myaw=_yaw; mpitch=_pitch; mroll=_roll;
            mfov = (_fov > 30.f && _fov < 170.f) ? _fov : 90.f;
            break;
        }
    }

    EnterCriticalSection(&ov->lock);
    memcpy(ov->players, tmp_players, sizeof(ov->players));
    ov->count = (int)count;
    ov->myTeam = myTeam;
    ov->myX = mx; ov->myY = my; ov->myZ = mz;
    ov->myYaw = myaw; ov->myPitch = mpitch; ov->myRoll = mroll;
    ov->fov = mfov;
    LeaveCriticalSection(&ov->lock);
}

// The rest of the historic poll_once (with driver RPM) is preserved below in a
// commented-out block since we keep the sig for backward-compat in some builds.
#if 0
static void poll_once_LEGACY(DH_OVERLAY* ov)
{
    HANDLE hDev = ov->hDev;
    u64 procCR3 = ov->procCR3;
    u64 base = ov->base;

    u64 uworld = 0;
    RpmRead64(hDev, procCR3, base + DF_RVA_GWORLD, &uworld);
    if (!uworld) return;

    u64 gsRaw = 0;
    RpmRead64(hDev, procCR3, uworld + DF_WORLD_GAMESTATE, &gsRaw);
    u64 gameState = gsRaw & 0x0000FFFFFFFFFFFFULL;
    if (!gameState || gameState < 0x100000) return;

    u64 psArr = 0; i32 psNum = 0;
    RpmRead64(hDev, procCR3, gameState + DF_GAMESTATE_PLAYERARRAY, &psArr);
    RpmReadVirtual(hDev, procCR3, gameState + DF_GAMESTATE_PLAYERARRAY + 8, &psNum, 4);
    if (psNum > 32) psNum = 32;
    if (psNum <= 0) return;

    DH_ESP_ENTRY tmp[32]; ZeroMemory(tmp, sizeof(tmp));
    int cnt = 0;
    int myTeam = -1;
    float myX = 0, myY = 0, myZ = 0;
    float povX = 0, povY = 0, povZ = 0;
    float yaw = 0, pitch = 0, fov = 90.f;
    int haveMy = 0;

    for (i32 pi = 0; pi < psNum && cnt < 32; pi++) {
        u64 ps = 0;
        RpmRead64(hDev, procCR3, psArr + (u64)pi * 8, &ps);
        if (!ps) continue;

        u64 pawn = 0;
        RpmRead64(hDev, procCR3, ps + DF_PLAYERSTATE_PAWNPRIVATE, &pawn);
        if (!pawn) continue;

        i32 teamID = 0;
        RpmReadVirtual(hDev, procCR3, ps + DF_GPPS_TEAMID, &teamID, 4);

        u64 rootRaw = 0;
        RpmRead64(hDev, procCR3, pawn + DF_ACTOR_ROOTCOMPONENT, &rootRaw);
        u64 root = rootRaw & 0x0000FFFFFFFFFFFFULL;
        if (!root || root < 0x100000) continue;

        u64 nameData = 0; i32 nameLen = 0;
        RpmRead64(hDev, procCR3, ps + DF_PLAYERSTATE_NAMEPRIV, &nameData);
        RpmReadVirtual(hDev, procCR3, ps + DF_PLAYERSTATE_NAMEPRIV + 8, &nameLen, 4);
        wchar_t wname[32] = {0};
        if (nameData && nameLen > 0 && nameLen < 31)
            RpmReadVirtual(hDev, procCR3, nameData, wname, nameLen * 2);

        DH_ENC_VECTOR relEnc = {0};
        if (!RpmReadVirtual(hDev, procCR3, root + 0x168, &relEnc, sizeof(relEnc))) continue;

        float px = 0, py = 0, pz = 0;
        int gotPos = 0;
        int isLocal = 0;
        if (relEnc.EncHandler.Index == 0xFFFF) {
            px = relEnc.X; py = relEnc.Y; pz = relEnc.Z;
            gotPos = 1;
            isLocal = 1;
            if (myTeam < 0) myTeam = teamID;
        } else {
            float x, y, z;
            if (RpmReadVirtual(hDev, procCR3, pawn + 0x1C2C, &x, 4) &&
                RpmReadVirtual(hDev, procCR3, pawn + 0x1C30, &y, 4) &&
                RpmReadVirtual(hDev, procCR3, pawn + 0x1C34, &z, 4) &&
                x == x && y == y && z == z &&
                fabsf(x) > 1000.f && fabsf(y) > 1000.f &&
                fabsf(x) < 100000.f && fabsf(y) < 100000.f &&
                fabsf(z) < 10000.f &&
                fabsf(fabsf(y) - fabsf(z)) > 5.f) {
                px = x; py = y; pz = z; gotPos = 1;
            }
        }
        if (!gotPos) continue;

        wcsncpy(tmp[cnt].name, wname, 31);
        tmp[cnt].team = teamID;
        tmp[cnt].x = px; tmp[cnt].y = py; tmp[cnt].z = pz;
        tmp[cnt].valid = 1;
        tmp[cnt].local = isLocal;
        cnt++;

        if (isLocal && !haveMy) {
            myX = px; myY = py; myZ = pz; haveMy = 1;

            // Read PlayerController for POV + rotation
            u64 ctrlRaw = 0;
            RpmRead64(hDev, procCR3, pawn + 0x3A8, &ctrlRaw);
            u64 ctrl = ctrlRaw & 0x0000FFFFFFFFFFFFULL;
            if (ctrl && ctrl >= 0x100000) {
                float pi_r = 0, yaw_r = 0;
                RpmReadVirtual(hDev, procCR3, ctrl + 0x380, &pi_r, 4);
                RpmReadVirtual(hDev, procCR3, ctrl + 0x384, &yaw_r, 4);
                if (pi_r == pi_r) pitch = pi_r;
                if (yaw_r == yaw_r) yaw = yaw_r;

                u64 pcmRaw = 0;
                RpmRead64(hDev, procCR3, ctrl + 0x408, &pcmRaw);
                u64 pcm = pcmRaw & 0x0000FFFFFFFFFFFFULL;
                if (pcm && pcm >= 0x100000) {
                    DH_ENC_VECTOR pov = {0};
                    if (RpmReadVirtual(hDev, procCR3, pcm + 0x31DB0, &pov, sizeof(pov))) {
                        if (pov.EncHandler.Index == 0xFFFF) {
                            povX = pov.X; povY = pov.Y; povZ = pov.Z;
                            myX = povX; myY = povY; myZ = povZ;
                        }
                    }
                    float f = 0;
                    RpmReadVirtual(hDev, procCR3, pcm + 0x31DC0, &f, 4);
                    if (f > 30.f && f < 170.f) fov = f;
                }
            }
        }
    }

    if (!haveMy && cnt > 0) { myX = tmp[0].x; myY = tmp[0].y; myZ = tmp[0].z; }
    (void)cnt; (void)myTeam; (void)myX; (void)myY; (void)myZ; (void)yaw; (void)pitch;
}
#endif

static DWORD WINAPI poll_thread(LPVOID p)
{
    DH_OVERLAY* ov = (DH_OVERLAY*)p;
    while (InterlockedCompareExchange(&ov->running, 0, 0)) {
        poll_once(ov);
        Sleep(2);   // was 50 — capped overlay at 20Hz while daemon runs 200Hz.
                    // 2ms = 500Hz shmem read, always ahead of any render rate.
    }
    return 0;
}

// -----------------------------------------------------------------------------
// W2S — Hor+ rotation matrix from POV yaw/pitch/roll, matches ABI-verified
// formula that works on live UE4 titles.
// -----------------------------------------------------------------------------
static int W2S(float wx, float wy, float wz,
               float px, float py, float pz,
               float yawDeg, float pitchDeg, float rollDeg,
               float fovDeg, int scrW, int scrH,
               float* outX, float* outY)
{
    const float DEG = 3.14159265358979f / 180.f;
    float y = yawDeg   * DEG;
    float p = pitchDeg * DEG;
    float r = rollDeg  * DEG;
    float cy = cosf(y), sy = sinf(y);
    float cp = cosf(p), sp = sinf(p);
    float cr = cosf(r), sr = sinf(r);
    // Camera basis (rows = forward/right/up in world coords). Verified on ABI.
    float m00 =  cp * cy;
    float m01 =  cp * sy;
    float m02 =  sp;
    float m10 =  sr*sp*cy - cr*sy;
    float m11 =  sr*sp*sy + cr*cy;
    float m12 = -sr * cp;
    float m20 = -(cr*sp*cy + sr*sy);
    float m21 =  cy*sr - cr*sp*sy;
    float m22 =  cr * cp;

    float dx = wx - px, dy = wy - py, dz = wz - pz;
    float fwd   = dx*m00 + dy*m01 + dz*m02;
    if (fwd < 1.0f) return 0;
    float right = dx*m10 + dy*m11 + dz*m12;
    float up    = dx*m20 + dy*m21 + dz*m22;

    float aspect = (float)scrW / (float)scrH;
    // Hor+ correction: game reports horizontal FOV; recalc for our aspect if
    // deviates significantly from 16:9 (ultrawide). For 16:9 no change.
    float effectiveFov = fovDeg;
    if (fabsf(aspect - 16.f/9.f) > 0.08f) {
        float vfov = 2.f * atanf(tanf(effectiveFov * DEG * 0.5f) / (16.f/9.f));
        float nh   = 2.f * atanf(tanf(vfov * 0.5f) * aspect);
        effectiveFov = nh / DEG;
    }
    float focal = (float)scrW / (2.f * tanf(effectiveFov * DEG * 0.5f));
    *outX = (float)scrW * 0.5f + focal * right / fwd;
    *outY = (float)scrH * 0.5f - focal * up    / fwd;
    return 1;
}

// -----------------------------------------------------------------------------
// D3D11 + DComp + D2D init
// -----------------------------------------------------------------------------
static LRESULT CALLBACK dh_wndproc(HWND h, UINT m, WPARAM wp, LPARAM lp)
{
    if (m == WM_DESTROY) { PostQuitMessage(0); return 0; }
    if (m == WM_NCHITTEST) return HTTRANSPARENT;
    return DefWindowProcW(h, m, wp, lp);
}

static BOOL create_gpu(DH_OVERLAY* ov)
{
    D3D_FEATURE_LEVEL fl;
    HRESULT hr = D3D11CreateDevice(NULL, D3D_DRIVER_TYPE_HARDWARE, NULL,
        D3D11_CREATE_DEVICE_BGRA_SUPPORT,
        NULL, 0, D3D11_SDK_VERSION,
        &ov->d3d, &fl, &ov->ctx);
    if (FAILED(hr)) {
        hr = D3D11CreateDevice(NULL, D3D_DRIVER_TYPE_WARP, NULL,
            D3D11_CREATE_DEVICE_BGRA_SUPPORT, NULL, 0, D3D11_SDK_VERSION,
            &ov->d3d, &fl, &ov->ctx);
        if (FAILED(hr)) { DH_ERROR("D3D11CreateDevice hr=0x%lX", hr); return FALSE; }
    }

    IDXGIDevice* dxgi = nullptr;
    ov->d3d->QueryInterface(__uuidof(IDXGIDevice), (void**)&dxgi);
    IDXGIAdapter* adap = nullptr;
    dxgi->GetAdapter(&adap);
    IDXGIFactory2* fac = nullptr;
    adap->GetParent(__uuidof(IDXGIFactory2), (void**)&fac);

    DXGI_SWAP_CHAIN_DESC1 sd = {};
    sd.Width = ov->sw; sd.Height = ov->sh;
    sd.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.BufferCount = 2;
    sd.SampleDesc.Count = 1;
    sd.AlphaMode = DXGI_ALPHA_MODE_PREMULTIPLIED;
    sd.SwapEffect = DXGI_SWAP_EFFECT_FLIP_DISCARD;
    hr = fac->CreateSwapChainForComposition(ov->d3d, &sd, nullptr, &ov->sc);
    fac->Release();
    adap->Release();
    if (FAILED(hr)) { DH_ERROR("CreateSwapChainForComposition hr=0x%lX", hr); dxgi->Release(); return FALSE; }

    hr = DCompositionCreateDevice(dxgi, __uuidof(IDCompositionDevice), (void**)&ov->dcomp);
    dxgi->Release();
    if (FAILED(hr)) { DH_ERROR("DCompositionCreateDevice hr=0x%lX", hr); return FALSE; }
    hr = ov->dcomp->CreateTargetForHwnd(ov->hwnd, TRUE, &ov->dcompT);
    if (FAILED(hr)) return FALSE;
    hr = ov->dcomp->CreateVisual(&ov->dcompV);
    if (FAILED(hr)) return FALSE;
    ov->dcompV->SetContent(ov->sc);
    ov->dcompT->SetRoot(ov->dcompV);
    ov->dcomp->Commit();

    // D2D
    D2D1_FACTORY_OPTIONS opts = {};
    hr = D2D1CreateFactory(D2D1_FACTORY_TYPE_SINGLE_THREADED, __uuidof(ID2D1Factory1), &opts, (void**)&ov->d2dFactory);
    if (FAILED(hr)) return FALSE;
    IDXGIDevice* dxgi2 = nullptr;
    ov->d3d->QueryInterface(__uuidof(IDXGIDevice), (void**)&dxgi2);
    hr = ov->d2dFactory->CreateDevice(dxgi2, &ov->d2dDev);
    dxgi2->Release();
    if (FAILED(hr)) return FALSE;
    hr = ov->d2dDev->CreateDeviceContext(D2D1_DEVICE_CONTEXT_OPTIONS_NONE, &ov->d2dCtx);
    if (FAILED(hr)) return FALSE;

    // Bind back buffer as D2D target
    IDXGISurface* surf = nullptr;
    ov->sc->GetBuffer(0, __uuidof(IDXGISurface), (void**)&surf);
    D2D1_BITMAP_PROPERTIES1 bp = {};
    bp.pixelFormat.format = DXGI_FORMAT_B8G8R8A8_UNORM;
    bp.pixelFormat.alphaMode = D2D1_ALPHA_MODE_PREMULTIPLIED;
    bp.bitmapOptions = D2D1_BITMAP_OPTIONS_TARGET | D2D1_BITMAP_OPTIONS_CANNOT_DRAW;
    bp.dpiX = 96.f; bp.dpiY = 96.f;
    hr = ov->d2dCtx->CreateBitmapFromDxgiSurface(surf, &bp, &ov->d2dBitmap);
    surf->Release();
    if (FAILED(hr)) return FALSE;
    ov->d2dCtx->SetTarget(ov->d2dBitmap);

    // DWrite
    hr = DWriteCreateFactory(DWRITE_FACTORY_TYPE_SHARED, __uuidof(IDWriteFactory), (IUnknown**)&ov->dwrite);
    if (FAILED(hr)) return FALSE;
    ov->dwrite->CreateTextFormat(
        L"Segoe UI", nullptr, DWRITE_FONT_WEIGHT_BOLD, DWRITE_FONT_STYLE_NORMAL,
        DWRITE_FONT_STRETCH_NORMAL, 13.0f, L"", &ov->fmtSmall);
    ov->dwrite->CreateTextFormat(
        L"Segoe UI", nullptr, DWRITE_FONT_WEIGHT_BOLD, DWRITE_FONT_STYLE_NORMAL,
        DWRITE_FONT_STRETCH_NORMAL, 16.0f, L"", &ov->fmtLarge);
    return TRUE;
}

static void destroy_gpu(DH_OVERLAY* ov)
{
    if (ov->fmtLarge)   ov->fmtLarge->Release();
    if (ov->fmtSmall)   ov->fmtSmall->Release();
    if (ov->dwrite)     ov->dwrite->Release();
    if (ov->d2dBitmap)  ov->d2dBitmap->Release();
    if (ov->d2dCtx)     ov->d2dCtx->Release();
    if (ov->d2dDev)     ov->d2dDev->Release();
    if (ov->d2dFactory) ov->d2dFactory->Release();
    if (ov->dcompV)     ov->dcompV->Release();
    if (ov->dcompT)     ov->dcompT->Release();
    if (ov->dcomp)      ov->dcomp->Release();
    if (ov->sc)         ov->sc->Release();
    if (ov->ctx)        ov->ctx->Release();
    if (ov->d3d)        ov->d3d->Release();
}

// -----------------------------------------------------------------------------
// D2D helpers
// -----------------------------------------------------------------------------
static void d2d_line(DH_OVERLAY* ov, float x1, float y1, float x2, float y2,
                     D2D1_COLOR_F c, float w)
{
    ID2D1SolidColorBrush* br = nullptr;
    ov->d2dCtx->CreateSolidColorBrush(c, &br);
    ov->d2dCtx->DrawLine(D2D1::Point2F(x1, y1), D2D1::Point2F(x2, y2), br, w);
    br->Release();
}

static void d2d_rect(DH_OVERLAY* ov, float x1, float y1, float x2, float y2,
                     D2D1_COLOR_F c, float w)
{
    ID2D1SolidColorBrush* br = nullptr;
    ov->d2dCtx->CreateSolidColorBrush(c, &br);
    D2D1_RECT_F r = { x1, y1, x2, y2 };
    ov->d2dCtx->DrawRectangle(&r, br, w);
    br->Release();
}

static void d2d_fill_rect(DH_OVERLAY* ov, float x1, float y1, float x2, float y2, D2D1_COLOR_F c)
{
    ID2D1SolidColorBrush* br = nullptr;
    ov->d2dCtx->CreateSolidColorBrush(c, &br);
    D2D1_RECT_F r = { x1, y1, x2, y2 };
    ov->d2dCtx->FillRectangle(&r, br);
    br->Release();
}

static void d2d_fill_ellipse(DH_OVERLAY* ov, float cx, float cy, float rx, float ry, D2D1_COLOR_F c)
{
    ID2D1SolidColorBrush* br = nullptr;
    ov->d2dCtx->CreateSolidColorBrush(c, &br);
    D2D1_ELLIPSE e = D2D1::Ellipse(D2D1::Point2F(cx, cy), rx, ry);
    ov->d2dCtx->FillEllipse(&e, br);
    br->Release();
}

static void d2d_ellipse(DH_OVERLAY* ov, float cx, float cy, float rx, float ry, D2D1_COLOR_F c, float w)
{
    ID2D1SolidColorBrush* br = nullptr;
    ov->d2dCtx->CreateSolidColorBrush(c, &br);
    D2D1_ELLIPSE e = D2D1::Ellipse(D2D1::Point2F(cx, cy), rx, ry);
    ov->d2dCtx->DrawEllipse(&e, br, w);
    br->Release();
}

static void d2d_text(DH_OVERLAY* ov, const wchar_t* s, float x, float y, float w, float h,
                     IDWriteTextFormat* fmt, D2D1_COLOR_F c)
{
    ID2D1SolidColorBrush* br = nullptr;
    ov->d2dCtx->CreateSolidColorBrush(c, &br);
    D2D1_RECT_F r = { x, y, x + w, y + h };
    ov->d2dCtx->DrawText(s, (UINT32)wcslen(s), fmt, &r, br);
    br->Release();
}

static D2D1_COLOR_F col_rgba(float r, float g, float b, float a) {
    D2D1_COLOR_F c = { r, g, b, a }; return c;
}

// -----------------------------------------------------------------------------
// Frame
// -----------------------------------------------------------------------------
static void render_frame(DH_OVERLAY* ov)
{
    ov->d2dCtx->BeginDraw();
    D2D1_COLOR_F clear = { 0.f, 0.f, 0.f, 0.f };
    ov->d2dCtx->Clear(&clear);

    DH_ESP_ENTRY p[DH_MAX_PLAYERS];
    int cnt, myTeam;
    float myX, myY, myZ, myYaw, myPitch, myRoll, fov;
    EnterCriticalSection(&ov->lock);
    memcpy(p, ov->players, sizeof(p));
    cnt = ov->count;
    myTeam = ov->myTeam;
    myX = ov->myX; myY = ov->myY; myZ = ov->myZ;
    myYaw = ov->myYaw; myPitch = ov->myPitch; myRoll = ov->myRoll;
    fov = ov->fov;
    LeaveCriticalSection(&ov->lock);
    if (fov < 30.f || fov > 170.f) fov = 90.f;

    int sw = ov->sw, sh = ov->sh;

    // ── Toggle state (persistent between frames) ─────────────────────────
    // F1 = toggle Players ESP  •  F2 = toggle Bots ESP
    static bool s_show_players = true;
    static bool s_show_bots    = true;
    static bool s_key_f1_prev  = false;
    static bool s_key_f2_prev  = false;

    bool f1_now = (GetAsyncKeyState(VK_F1) & 0x8000) != 0;
    bool f2_now = (GetAsyncKeyState(VK_F2) & 0x8000) != 0;
    if (f1_now && !s_key_f1_prev) s_show_players = !s_show_players;
    if (f2_now && !s_key_f2_prev) s_show_bots    = !s_show_bots;
    s_key_f1_prev = f1_now;
    s_key_f2_prev = f2_now;

    // Top-left status
    wchar_t buf[256];
    _snwprintf_s(buf, 256, _TRUNCATE,
        L"DeltaHack ESP  players=%d  myT=T%d  fov=%.0f    [F1]Players=%s  [F2]Bots=%s",
        cnt, myTeam, fov,
        s_show_players ? L"ON " : L"OFF",
        s_show_bots    ? L"ON " : L"OFF");
    d2d_fill_rect(ov, 10.f, 10.f, 560.f, 34.f, col_rgba(0.f, 0.f, 0.f, 0.6f));
    d2d_text(ov, buf, 14.f, 12.f, 560.f, 24.f, ov->fmtSmall, col_rgba(0.8f, 0.85f, 1.f, 1.f));

    // Client-side prediction — extrapolate enemy position from last-known
    // sample using velocity. Kills the "jelly" lag caused by daemon → shmem
    // → overlay → VSync pipeline delay (~50ms total).
    // Cap extrapolation at 200ms to avoid runaway if velocity spike is bad.
    u64 render_ms = GetTickCount64();
    for (int i = 0; i < cnt; i++) {
        DH_ESP_ENTRY* e = &p[i];
        if (e->pos_ts_ms == 0) continue;
        u64 age_ms = render_ms - e->pos_ts_ms;
        if (age_ms > 200) age_ms = 200;
        float ext = (float)age_ms / 1000.f;
        e->x += e->vx * ext;
        e->y += e->vy * ext;
        e->z += e->vz * ext;
    }

    // Player list
    float listY = 40.f;
    for (int i = 0; i < cnt; i++) {
        DH_ESP_ENTRY* e = &p[i];
        // Filter by toggle: player entries skipped when Players=OFF,
        // bot entries skipped when Bots=OFF.
        if (e->is_bot && !s_show_bots) continue;
        if (!e->is_bot && !s_show_players) continue;
        int enemy = (e->team != myTeam);
        D2D1_COLOR_F col;
        if (e->is_dead) {
            col = col_rgba(0.5f, 0.5f, 0.5f, 0.7f);  // grey for corpses
        } else if (e->is_bot) {
            col = col_rgba(1.f, 1.f, 1.f, 1.f);      // WHITE for bots (any team)
        } else {
            col = enemy ? col_rgba(1.f, 0.25f, 0.25f, 1.f)
                        : col_rgba(0.25f, 0.9f, 0.4f, 1.f);
        }
        float dx = e->x - myX, dy = e->y - myY;
        float distM = sqrtf(dx*dx + dy*dy) / 100.f;
        _snwprintf_s(buf, 256, _TRUNCATE, L"%s T%d %s %s %s  %.0fm",
            enemy ? L"[E]" : L"[F]", e->team,
            e->is_bot ? L"BOT" : L"PL ",
            e->is_dead ? L"DED" : L"ALV",
            e->name, distM);
        d2d_text(ov, buf, 14.f, listY, 500.f, 18.f, ov->fmtSmall, col);
        listY += 16.f;

        // W2S box + skeleton line
        // Delta pawn location = pelvis (actor center), not feet.
        // Character height ~180u. Center box on sy → feet = sy + bh/2, head = sy - bh/2.
        float sx, sy;
        if (W2S(e->x, e->y, e->z, myX, myY, myZ, myYaw, myPitch, myRoll, fov, sw, sh, &sx, &sy)) {
            int bh = (int)(1800.f / (distM + 1.f));
            if (bh < 20) bh = 20;
            if (bh > 400) bh = 400;
            int bw = bh / 3;
            float feet_y = sy + bh * 0.5f;   // shift down half height
            float head_y = sy - bh * 0.5f;   // shift up half height
            d2d_rect(ov, sx - bw, head_y, sx + bw, feet_y, col, 2.f);
            d2d_line(ov, sx, feet_y, sx, head_y, col, 1.5f);
            _snwprintf_s(buf, 256, _TRUNCATE, L"%s%s %.0fm",
                e->is_bot ? L"[BOT] " : L"",
                e->name, distM);
            d2d_text(ov, buf, sx - bw, head_y - 18.f, (float)(2*bw + 40), 16.f, ov->fmtSmall, col);
        }
    }

    // Radar bottom-right
    float rr = 200.f;
    float rcx = (float)sw - rr/2 - 20.f;
    float rcy = (float)sh - rr/2 - 20.f;
    d2d_fill_ellipse(ov, rcx, rcy, rr/2, rr/2, col_rgba(0.05f, 0.05f, 0.05f, 0.6f));
    d2d_ellipse(ov, rcx, rcy, rr/2, rr/2, col_rgba(0.5f, 0.5f, 0.5f, 0.8f), 1.5f);
    d2d_fill_ellipse(ov, rcx, rcy, 4.f, 4.f, col_rgba(1.f, 1.f, 1.f, 1.f));

    // View direction ray
    {
        float yr = myYaw * 3.14159265358979f / 180.f;
        float lx = rcx + cosf(yr) * (rr/2 * 0.9f);
        float ly = rcy + sinf(yr) * (rr/2 * 0.9f);
        d2d_line(ov, rcx, rcy, lx, ly, col_rgba(0.7f, 0.8f, 1.f, 0.9f), 2.f);
    }
    // Radar scale: 100m per rr/2 pixels; Delta uses cm → 10000 cm = 100m
    float rscale = 10000.f / (rr / 2.f);
    for (int i = 0; i < cnt; i++) {
        DH_ESP_ENTRY* e = &p[i];
        if (e->is_bot && !s_show_bots) continue;
        if (!e->is_bot && !s_show_players) continue;
        int enemy = (e->team != myTeam);
        float dx = (e->x - myX) / rscale;
        float dy = (e->y - myY) / rscale;
        float yr = -myYaw * 3.14159265358979f / 180.f;
        float cr = cosf(yr), sr = sinf(yr);
        float rx = dx * cr - dy * sr;
        float ry = dx * sr + dy * cr;
        float dot_x = rcx + rx;
        float dot_y = rcy - ry;
        float d2 = (dot_x - rcx)*(dot_x - rcx) + (dot_y - rcy)*(dot_y - rcy);
        if (d2 > (rr/2)*(rr/2)) continue;
        D2D1_COLOR_F col;
        if (p[i].is_bot) col = col_rgba(1.f, 1.f, 1.f, 1.f);
        else col = enemy ? col_rgba(1.f, 0.25f, 0.25f, 1.f)
                         : col_rgba(0.25f, 0.9f, 0.4f, 1.f);
        d2d_fill_ellipse(ov, dot_x, dot_y, 4.f, 4.f, col);
    }

    ov->d2dCtx->EndDraw();
    // SyncInterval=1 = VSync (DComp swapchain doesn't support tearing).
    // Soft-cap 120Hz in main loop; VSync gives us monitor refresh rate.
    ov->sc->Present(1, 0);
}

// -----------------------------------------------------------------------------
// Public entry
// -----------------------------------------------------------------------------

extern "C" int OverlayRun(HANDLE hDev, u64 procCR3, u64 base)
{
    (void)hDev; (void)procCR3; (void)base;
    DH_OVERLAY ov; ZeroMemory(&ov, sizeof(ov));
    ov.running = 1; ov.fov = 90.f;
    InitializeCriticalSection(&ov.lock);

    // Open shared mem populated by daemon-esp (Session 0 SYSTEM).
    // Retry with backoff — daemon may launch slightly later.
    for (int attempt = 0; attempt < 30; attempt++) {
        ov.hMap = OpenFileMappingW(FILE_MAP_READ, FALSE, DH_SHMEM_NAME);
        if (ov.hMap) break;
        Sleep(200);
    }
    if (!ov.hMap) {
        DH_ERROR("shmem not found — start daemon first (gle=%lu)", GetLastError());
        return 1;
    }
    ov.shmem = (DH_SHMEM*)MapViewOfFile(ov.hMap, FILE_MAP_READ, 0, 0, sizeof(DH_SHMEM));
    if (!ov.shmem) {
        DH_ERROR("MapViewOfFile err=%lu", GetLastError());
        CloseHandle(ov.hMap);
        return 1;
    }
    DH_INFO("shmem opened @ %p, magic=0x%X", ov.shmem, ov.shmem->magic);

    HINSTANCE hi = GetModuleHandleW(NULL);
    WNDCLASSEXW wc; ZeroMemory(&wc, sizeof(wc));
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = dh_wndproc;
    wc.hInstance = hi;
    wc.lpszClassName = L"DHOverlay_" L"c0mp0s1te";
    wc.hCursor = NULL;
    wc.hbrBackground = NULL;
    RegisterClassExW(&wc);

    ov.sw = GetSystemMetrics(SM_CXSCREEN);
    ov.sh = GetSystemMetrics(SM_CYSCREEN);
    if (ov.sw <= 0 || ov.sh <= 0) {
        HDC dc = GetDC(NULL);
        if (dc) { ov.sw = GetDeviceCaps(dc, HORZRES); ov.sh = GetDeviceCaps(dc, VERTRES); ReleaseDC(NULL, dc); }
    }
    if (ov.sw <= 0 || ov.sh <= 0) { ov.sw = 1920; ov.sh = 1080; }
    DH_INFO("overlay screen: %dx%d", ov.sw, ov.sh);

    DWORD ex = WS_EX_TOPMOST | WS_EX_LAYERED | WS_EX_NOREDIRECTIONBITMAP |
               WS_EX_TRANSPARENT | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE;
    ov.hwnd = CreateWindowExW(ex, wc.lpszClassName, L"DHOverlay",
        WS_POPUP, 0, 0, ov.sw, ov.sh, NULL, NULL, hi, NULL);
    if (!ov.hwnd) { DH_ERROR("CreateWindowEx err=%lu", GetLastError()); return 1; }
    SetLayeredWindowAttributes(ov.hwnd, 0, 255, LWA_ALPHA);
    ShowWindow(ov.hwnd, SW_SHOWNOACTIVATE);
    SetWindowPos(ov.hwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);

    if (!create_gpu(&ov)) {
        DH_ERROR("GPU init failed");
        DestroyWindow(ov.hwnd);
        return 1;
    }

    HANDLE th = CreateThread(NULL, 0, poll_thread, &ov, 0, NULL);

    DH_INFO("overlay running: %dx%d — HWND=%p", ov.sw, ov.sh, ov.hwnd);

    // Boost timer resolution to 1ms so Sleep(1) actually sleeps ~1ms
    // (default Windows tick = 15.6ms which caps our loop at ~64fps min).
    timeBeginPeriod(1);

    MSG msg;
    LARGE_INTEGER freq, last, now;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&last);
    for (;;) {
        while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE)) {
            if (msg.message == WM_QUIT) goto done;
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        QueryPerformanceCounter(&now);
        double dt = (double)(now.QuadPart - last.QuadPart) / (double)freq.QuadPart;
        if (dt >= 1.0 / 240.0) {   // cap higher than any common monitor;
            last = now;             // VSync in Present() is the true limit.
            render_frame(&ov);
        } else {
            Sleep(1);
        }
    }
done:
    timeEndPeriod(1);
    InterlockedExchange(&ov.running, 0);
    WaitForSingleObject(th, 500);
    CloseHandle(th);
    destroy_gpu(&ov);
    DestroyWindow(ov.hwnd);
    if (ov.shmem) UnmapViewOfFile(ov.shmem);
    if (ov.hMap)  CloseHandle(ov.hMap);
    DeleteCriticalSection(&ov.lock);
    return 0;
}

extern "C" int OverlayRunShared(void) { return OverlayRun(NULL, 0, 0); }

// DeltaHack overlay â€” ImGui + D3D11 + DirectComposition port.
//
// Ported from ABI's Nightvex overlay. Reads Global\DeltaHackEsp shmem
// (populated by daemon-esp in Session 0), renders ESP through ImGui's
// draw list on a click-through transparent layered window.
//
// Data source: DH_SHMEM published by daemon (see inc/dh_shmem.h).
// Not the ABI abi::Snapshot â€” different struct.

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <mmsystem.h>
#include <d3d11.h>
#include <dxgi1_3.h>
#include <dcomp.h>
#include <math.h>
#include <stdio.h>
#include <string>

#pragma comment(lib, "winmm.lib")

#include "../../deps/imgui/imgui.h"
#include "../../deps/imgui/backends/imgui_impl_win32.h"
#include "../../deps/imgui/backends/imgui_impl_dx11.h"

// Embed stb_image just here (STB_IMAGE_IMPLEMENTATION only in this TU)
#pragma warning(push)
#pragma warning(disable: 4100 4101 4127 4189 4244 4305 4456 4457 4505 4701 4702 4996 6011 6262 6308 6385 6386 26451 26495 28182)
#define STB_IMAGE_IMPLEMENTATION
#define STBI_NO_STDIO
#define STBI_ONLY_PNG
#include "../../deps/stb/stb_image.h"
#pragma warning(pop)
#include "../../deps/stb/nightvex_logo_png.h"

extern "C" {
#include "../../inc/dh_common.h"
#include "../../inc/dh_shmem.h"
}

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")
#pragma comment(lib, "dxguid.lib")
#pragma comment(lib, "dcomp.lib")
#pragma comment(lib, "dwmapi.lib")

extern IMGUI_IMPL_API LRESULT
ImGui_ImplWin32_WndProcHandler(HWND, UINT, WPARAM, LPARAM);

#ifndef WDA_EXCLUDEFROMCAPTURE
#define WDA_EXCLUDEFROMCAPTURE 0x00000011
#endif

// -----------------------------------------------------------------------------
// State
// -----------------------------------------------------------------------------

struct DH_UI {
    HWND hwnd;
    int  sw, sh;

    // D3D11 chain via DComp
    ID3D11Device*           d3d;
    ID3D11DeviceContext*    ctx;
    IDXGISwapChain1*        swap;
    ID3D11RenderTargetView* rtv;
    IDCompositionDevice*    dcomp;
    IDCompositionTarget*    dcompT;
    IDCompositionVisual*    dcompV;

    // Shmem
    HANDLE   hMap;
    DH_SHMEM* shmem;

    // Local frame data (double-buffered from shmem)
    CRITICAL_SECTION lock;
    DH_SHMEM_PLAYER  players[DH_MAX_PLAYERS];
    DH_SHMEM_LOOT    loot[DH_MAX_LOOT];
    int              loot_count;
    int   count;
    float camX, camY, camZ, camYaw, camPitch, camRoll, fov;
    int   myTeam;

    // Toggles — split per entity type so Players/Bots don't share
    bool  show_players;
    bool  show_player_mates;    // draw same-team players (default off)
    bool  show_player_names;
    bool  show_player_dist;
    bool  show_player_team;     // print numeric team id under distance
    bool  show_player_hp;       // HP line above the nickname
    bool  show_player_corpses;  // draw dead players
    int   box_mode_players;     // 0=Off, 1=2D corner-bracket, 2=3D wireframe
    bool  show_bots;
    bool  show_bot_names;
    bool  show_bot_dist;
    bool  show_bot_hp;          // HP line above the nickname for bots
    bool  show_bot_corpses;
    int   box_mode_bots;        // 0=Off, 1=2D corner-bracket, 2=3D wireframe
    bool  show_hud;
    // Radar (cyan-glow military, ABIFinal port)
    bool  show_radar;
    int   radar_range_m;         // 50..500m visible range
    int   radar_px_radius;       // 60..200 px disc radius
    int   radar_x, radar_y;      // center pixel coords; INT_MIN = uninitialised
    bool  radar_dragging;        // drag state while panel open
    float radar_drag_dx, radar_drag_dy;  // mouse-to-center offset at drag start
    bool  radar_rings;           // dashed concentric range rings
    bool  radar_range_label;     // "250" above outer ring
    bool  radar_show_players;    // enemy human players
    bool  radar_show_bots;
    bool  radar_show_teammates;
    bool  radar_show_corpses_players;   // dead enemy humans
    bool  radar_show_corpses_bots;      // dead AI
    // Loot (English-only labels, per user spec)
    bool  show_loot;
    bool  loot_show_common;      // rarity 0 (grey)
    bool  loot_show_uncommon;    // 1 (green)
    bool  loot_show_rare;        // 2 (blue)
    bool  loot_show_epic;        // 3 (purple)
    bool  loot_show_legendary;   // 4 (gold)
    bool  loot_show_mythic;      // 5 (red)
    bool  loot_show_corpses;     // dropped-loot pile from dead pawn
    bool  loot_show_names;       // draw item name text under dot
    int   loot_max_dist_m;       // 0 = unlimited
    int   loot_min_value;        // hide anything cheaper than this ($)
    bool  show_player_armor_tier;   // H:<tier> / A:<tier>
    bool  show_player_armor_dura;   // (durability) numbers
    bool  show_bot_armor_tier;
    bool  show_bot_armor_dura;

    // Settings (adjustable via panel)
    float box_thickness;
    float ui_scale;              // monitor_h / 1080 (1.0 @1080p, 1.33 @1440p, 2.0 @4K)
    float box_corner_frac;   // 0.10 - 0.30 fraction of height
    int   max_dist_players;  // 0 = unlimited, 1..1000 m
    int   max_dist_bots;     // 0 = unlimited, 1..1000 m
    int   box_dist_players;  // 0 = unlimited, box-only distance
    int   box_dist_bots;
    int   corpse_dist_players;
    int   corpse_dist_bots;
    int   text_size;         // px (approx via font scale)

    // Colors (RGBA, per-entity type — not shared between players/bots)
    ImVec4 col_player_box;
    ImVec4 col_player_name;
    ImVec4 col_player_dist;
    ImVec4 col_player_team;
    ImVec4 col_player_hp;
    ImVec4 col_player_armor_tier;   // H:X A:Y tier text
    ImVec4 col_player_armor_dura;   // (nn) durability numbers
    ImVec4 col_teammate_box;   // used only for same-team players — default blue
    ImVec4 col_player_corpse;  // dead player box override
    ImVec4 col_bot_box;
    ImVec4 col_bot_name;
    ImVec4 col_bot_dist;
    ImVec4 col_bot_hp;
    ImVec4 col_bot_armor_tier;      // bot tier text
    ImVec4 col_bot_armor_dura;      // bot durability numbers
    ImVec4 col_bot_corpse;     // dead bot box override
    // Radar palette
    ImVec4 col_radar_disc;      // filled disc background
    ImVec4 col_radar_ring;      // dashed rings + edge
    ImVec4 col_radar_range;     // "250" range label
    ImVec4 col_radar_self;      // center dot (you)
    ImVec4 col_radar_player;    // enemy human dot
    ImVec4 col_radar_bot;
    ImVec4 col_radar_teammate;
    ImVec4 col_radar_corpse_player;
    ImVec4 col_radar_corpse_bot;
    // Loot palette — rarity colors (matches ABIFinal / most looter shooters)
    ImVec4 col_loot_common;      // grey
    ImVec4 col_loot_uncommon;    // green
    ImVec4 col_loot_rare;        // blue
    ImVec4 col_loot_epic;        // purple
    ImVec4 col_loot_legendary;   // gold
    ImVec4 col_loot_mythic;      // red
    ImVec4 col_loot_corpse;      // corpse-drop marker (black box)

    // Panel state
    bool  panel_open;
    bool  input_capture;
    int   lang;   // 0=EN, 1=RU, 2=CN

    // Fonts
    ImFont* font_big;
    ImFont* font_mid;

    // Textures
    ID3D11ShaderResourceView* logo_srv;

    // Threads
    volatile LONG running;
    HANDLE   poll_th;
};

static DH_UI g_ui = {};

// Two-column layout override for tab bodies. When g_col_w > 0 the row
// helpers use it as their child-width and g_col_x as the X offset from
// the tab-content ChildWindow origin. Reset to {24, 0} after each
// column pair. File-scope so every helper sees them without capturing.
static float g_col_x = 24.0f;
static float g_col_w = 0.0f;

// ------------------------------------------------------------------
// Translation table — three columns per key: EN, RU, CN.
// tr("key") returns the current-language text (UTF-8, ImGui-safe).
// UNKNOWN key returns itself so untranslated strings render fine.
// ------------------------------------------------------------------
struct TrEntry { const char* key; const char* en; const char* ru; const char* cn; };
static const TrEntry TR[] = {
    // Tab labels
    { "tab.players",       "Players",              "Игроки",                "玩家" },
    { "tab.bots",          "Bots",                 "Боты",                  "AI" },
    { "tab.radar",         "Radar",                "Радар",                 "雷达" },
    { "tab.overlay",       "Overlay",              "Оверлей",               "覆盖层" },
    { "tab.lang",          "Language",             "Язык",                  "语言" },
    // Radar tab
    { "rad.show",          "Show radar",           "Показывать радар",      "显示雷达" },
    { "rad.show.hint",     "Cyan-glow military disc","Военный цианный диск",  "军事雷达盘" },
    { "rad.rings",         "Range rings",          "Кольца дистанций",      "距离圈" },
    { "rad.rings.hint",    "Dashed 50m marks",     "Пунктир каждые 50 м",   "每50米虚线" },
    { "rad.label",         "Range label",          "Метка дистанции",       "距离标签" },
    { "rad.label.hint",    "\"250\" above outer ring","\"250\" над кольцом",   "外圈上方\"250\"" },
    { "rad.players",       "Enemies (players)",    "Противники (игроки)",   "敌方玩家" },
    { "rad.players.hint",  "Red dots",             "Красные точки",         "红点" },
    { "rad.bots",          "Bots",                 "Боты",                  "AI" },
    { "rad.bots.hint",     "White dots",           "Белые точки",           "白点" },
    { "rad.mates",         "Teammates",            "Тиммейты",              "队友" },
    { "rad.mates.hint",    "Blue dots",            "Синие точки",           "蓝点" },
    { "rad.corp.pl",       "Corpses (players)",    "Трупы (игроки)",        "尸体 (玩家)" },
    { "rad.corp.pl.hint",  "Dead enemy humans",    "Убитые противники",     "死亡敌人" },
    { "rad.corp.bot",      "Corpses (bots)",       "Трупы (боты)",          "尸体 (AI)" },
    { "rad.corp.bot.hint", "Dead AI",              "Убитые боты",           "死亡AI" },
    { "rad.drag.hint",     "Drag with LMB on the radar to move it (menu must be open)",
                           "Тащи ЛКМ по радару чтобы переместить (меню должно быть открыто)",
                           "菜单打开时按住鼠标左键拖动雷达移动位置" },
    { "rad.range",         "Range (m)",            "Дистанция (м)",         "距离 (米)" },
    { "rad.radius",        "Radius (px)",          "Радиус (px)",           "半径 (像素)" },
    // Language tab
    { "lang.title",        "Interface language",   "Язык интерфейса",       "界面语言" },
    { "lang.en",           "English",              "English",               "English" },
    { "lang.ru",           "Русский",              "Русский",               "Русский" },
    { "lang.cn",           "中文",                 "中文",                  "中文" },
    { "lang.hint",         "Translation covers Radar tab + tab titles. Rest of UI stays English until v2.",
                           "Перевод покрывает вкладку Радар + названия вкладок. Остальное — до v2 английский.",
                           "翻译覆盖雷达标签+标签标题。其余界面在v2之前保持英文。" },
    // Overlay tab
    { "ov.hud",            "HUD chip",             "HUD чип",                "HUD 标签" },
    { "ov.hud.hint",       "Top-left overlay",     "Левый верхний угол",     "左上角覆盖" },
    // Players / Bots common row labels
    { "row.enable",        "Enable",               "Включить",               "启用" },
    { "row.mates",         "Show mates",           "Показ тиммейтов",        "显示队友" },
    { "sec.main",          "Main info",            "Основная информация",     "主要信息" },
    { "sec.extra",         "Extra info",           "Доп информация",          "附加信息" },
    { "sec.main",          "Main info",            "Основная информация",     "主要信息" },
    { "sec.extra",         "Extra info",           "Доп информация",          "附加信息" },
    { "row.box",           "Box",                  "Бокс",                   "方框" },
    { "row.box.style",     "Box style",            "Стиль бокса",             "方框样式" },
    { "box.2d",            "2D",                   "2D",                     "2D" },
    { "box.3d",            "3D",                   "3D",                     "3D" },
    { "row.name",          "Name",                 "Ник",                    "昵称" },
    { "row.hp",            "HP",                   "HP",                     "血量" },
    { "row.armor.tier",    "Armor tier",           "Тир брони",              "护甲等级" },
    { "row.armor.dura",    "Armor durability",     "Прочность брони",        "护甲耐久" },
    { "row.dist",          "Distance",             "Дистанция",              "距离" },
    { "row.dist.player",   "Distance to player",   "Расстояние до игрока",   "到玩家的距离" },
    { "row.dist.bot",      "Distance to bot",      "Расстояние до бота",     "到AI的距离" },
    { "row.team",          "Team ID",              "ID команды",             "队伍 ID" },
    { "row.corpses",       "Corpses",              "Трупы",                  "尸体" },
    // Slider labels (dist/box)
    { "slider.dist",              "Max distance",              "Макс. дистанция",              "最大距离" },
    { "slider.box.dist",          "Box distance",              "Дистанция бокса",              "方框距离" },
    { "slider.corpse.dist",       "Corpse distance",           "Дистанция трупов",             "尸体距离" },
    { "slider.players.render",    "Players render distance",   "Дистанция отрисовки игроков",  "玩家渲染距离" },
    { "slider.bots.render",       "Bots render distance",      "Дистанция отрисовки ботов",    "AI渲染距离" },
    { "slider.player.box",        "Boxes render distance",     "Дистанция боксов",             "方框渲染距离" },
    { "slider.bot.box",           "Boxes render distance",     "Дистанция боксов",             "方框渲染距离" },
    { "slider.player.corpse",     "Corpse render distance",    "Дистанция трупов игроков",     "玩家尸体渲染距离" },
    { "slider.bot.corpse",        "Corpse render distance",    "Дистанция трупов ботов",       "AI尸体渲染距离" },
    { "slider.unlim",      "Unlimited",            "Без лимита",             "无限" },
    { NULL, NULL, NULL, NULL }
};

static const char* tr(const char* key)
{
    for (const TrEntry* e = TR; e->key; e++) {
        if (strcmp(e->key, key) == 0) {
            switch (g_ui.lang) {
                case 1:  return e->ru;
                case 2:  return e->cn;
                default: return e->en;
            }
        }
    }
    return key;   // untranslated — render key itself so it's visible
}

// -----------------------------------------------------------------------------
// Shmem poll thread
// -----------------------------------------------------------------------------

static DWORD WINAPI poll_thread(LPVOID)
{
    while (InterlockedCompareExchange(&g_ui.running, 0, 0)) {
        DH_SHMEM* s = g_ui.shmem;
        if (!s || s->magic != DH_SHMEM_MAGIC) { Sleep(4); continue; }

        // Entity block under primary seqlock
        int cnt = 0;
        int myTeam = 0;
        static DH_SHMEM_PLAYER tmp_players[DH_MAX_PLAYERS];
        for (int retry = 0; retry < 8; retry++) {
            u32 s1 = s->sequence;
            if (s1 & 1) { Sleep(0); continue; }
            MemoryBarrier();
            u32 c = s->count;
            i32 mt = s->myTeam;
            memcpy(tmp_players, (void*)s->players, sizeof(tmp_players));
            MemoryBarrier();
            u32 s2 = s->sequence;
            if (s1 == s2) { cnt = (int)c; myTeam = mt; break; }
        }

        // Cam block under cam_seq
        float mx=0, my=0, mz=0, myaw=0, mpitch=0, mroll=0, mfov=90.f;
        for (int retry = 0; retry < 8; retry++) {
            u32 s1 = s->cam_seq;
            if (s1 & 1) { Sleep(0); continue; }
            MemoryBarrier();
            float _mx = s->myX, _my = s->myY, _mz = s->myZ;
            float _yaw = s->myYaw, _pitch = s->myPitch, _roll = s->myRoll;
            float _fov = s->fov;
            MemoryBarrier();
            u32 s2 = s->cam_seq;
            if (s1 == s2) {
                mx=_mx; my=_my; mz=_mz;
                myaw=_yaw; mpitch=_pitch; mroll=_roll;
                mfov = (_fov > 30.f && _fov < 170.f) ? _fov : 90.f;
                break;
            }
        }

        // pos_seq fast-pos DISABLED — slot indices unstable, needs pawn-key
        // lookup redesign before re-enabling.

        // Loot snapshot ripped per user 2026-09-22.
        EnterCriticalSection(&g_ui.lock);
        memcpy(g_ui.players, tmp_players, sizeof(g_ui.players));
        g_ui.count = cnt;
        g_ui.myTeam = myTeam;
        g_ui.camX = mx; g_ui.camY = my; g_ui.camZ = mz;
        g_ui.camYaw = myaw; g_ui.camPitch = mpitch; g_ui.camRoll = mroll;
        g_ui.fov  = mfov;
        g_ui.loot_count = 0;
        LeaveCriticalSection(&g_ui.lock);

        Sleep(2);   // 500Hz shmem poll â€” always ahead of any render rate
    }
    return 0;
}

// -----------------------------------------------------------------------------
// World-to-screen (ABI Hor+ rotation matrix, verified formula)
// -----------------------------------------------------------------------------

struct Mat3 { float m[3][3]; };
static constexpr float PI = 3.14159265358979323846f;
static inline float deg2rad(float d) { return d * PI / 180.f; }

static Mat3 cam_matrix(float yawDeg, float pitchDeg, float rollDeg)
{
    float y = deg2rad(yawDeg), p = deg2rad(pitchDeg), r = deg2rad(rollDeg);
    float cy = cosf(y), sy = sinf(y);
    float cp = cosf(p), sp = sinf(p);
    float cr = cosf(r), sr = sinf(r);
    Mat3 m;
    m.m[0][0] =  cp * cy;
    m.m[0][1] =  cp * sy;
    m.m[0][2] =  sp;
    m.m[1][0] =  sr*sp*cy - cr*sy;
    m.m[1][1] =  sr*sp*sy + cr*cy;
    m.m[1][2] = -sr * cp;
    m.m[2][0] = -(cr*sp*cy + sr*sy);
    m.m[2][1] =  cy*sr - cr*sp*sy;
    m.m[2][2] =  cr * cp;
    return m;
}

struct ScreenPt { float sx, sy, depth; bool ok; };

static ScreenPt w2s(float wx, float wy, float wz,
                    float cx, float cy_, float cz,
                    const Mat3& mat, float fov,
                    int sw, int sh)
{
    float dx = wx - cx, dy = wy - cy_, dz = wz - cz;
    float fwd = dx*mat.m[0][0] + dy*mat.m[0][1] + dz*mat.m[0][2];
    if (fwd < 1.0f) return {0,0,0,false};
    float right = dx*mat.m[1][0] + dy*mat.m[1][1] + dz*mat.m[1][2];
    float up    = dx*mat.m[2][0] + dy*mat.m[2][1] + dz*mat.m[2][2];
    float thf = tanf(deg2rad(fov > 0.f ? fov : 90.f) * 0.5f);
    float ccx = sw * 0.5f, ccy = sh * 0.5f;
    float scl = ccx / thf;
    return { ccx + (right/fwd)*scl, ccy - (up/fwd)*scl, fwd, true };
}

// -----------------------------------------------------------------------------
// WndProc â€” click-through by default
// -----------------------------------------------------------------------------

// Toggle input capture / window transparency for panel open/close.
static void set_input_capture(bool on)
{
    DH_INFO("[capture] enter on=%d hwnd=%p", on ? 1 : 0, g_ui.hwnd);
    if (!g_ui.hwnd) { DH_WARN("[capture] hwnd null â€” bailing"); return; }
    LONG_PTR ex = GetWindowLongPtrW(g_ui.hwnd, GWL_EXSTYLE);
    DH_INFO("[capture] current ex-style=0x%llX", (long long)ex);
    if (on) ex &= ~(LONG_PTR)WS_EX_TRANSPARENT;
    else    ex |=  (LONG_PTR)WS_EX_TRANSPARENT;
    SetWindowLongPtrW(g_ui.hwnd, GWL_EXSTYLE, ex);
    g_ui.input_capture = on;
    DH_INFO("[capture] new ex-style=0x%llX", (long long)ex);

    ImGuiIO& io = ImGui::GetIO();
    if (on) {
        DH_INFO("[capture] enabling ImGui mouse");
        io.ConfigFlags &= ~ImGuiConfigFlags_NoMouse;
        io.ConfigFlags &= ~ImGuiConfigFlags_NoMouseCursorChange;
        SetForegroundWindow(g_ui.hwnd);
        // Delta clips cursor to game window for FPS controls — release it so
        // the panel can be interacted with anywhere on screen.
        ClipCursor(NULL);
        // Move cursor to center of our panel so user sees it immediately.
        RECT r; GetClientRect(g_ui.hwnd, &r);
        POINT c = { (r.right - r.left) / 2, (r.bottom - r.top) / 2 };
        ClientToScreen(g_ui.hwnd, &c);
        SetCursorPos(c.x, c.y);
        while (ShowCursor(TRUE) < 0) {}
        DH_INFO("[capture] cursor unclipped + centered + visible");
    } else {
        DH_INFO("[capture] disabling ImGui mouse");
        io.ConfigFlags |= ImGuiConfigFlags_NoMouse;
        io.ConfigFlags |= ImGuiConfigFlags_NoMouseCursorChange;
        HWND game = FindWindowW(NULL, L"Delta Force");
        if (!game) game = FindWindowW(L"UnrealWindow", NULL);
        DH_INFO("[capture] game hwnd=%p", game);
        if (game && IsWindow(game)) {
            // Windows blocks SetForegroundWindow() when the calling thread
            // isn't the foreground one. AttachThreadInput to the game's
            // input queue defeats that block: while attached, our thread
            // shares foreground privilege, so SetForegroundWindow +
            // SetFocus actually stick. Detach immediately after.
            DWORD our_tid  = GetCurrentThreadId();
            DWORD game_tid = GetWindowThreadProcessId(game, NULL);
            BOOL attached = FALSE;
            if (game_tid && game_tid != our_tid)
                attached = AttachThreadInput(our_tid, game_tid, TRUE);
            SetForegroundWindow(game);
            SetFocus(game);
            SetActiveWindow(game);
            // Force UE to re-arm its FPS mouse capture (ClipCursor + hide)
            // by nudging the input state so the game's WM_ACTIVATE and
            // WM_SETCURSOR handlers run again.
            SendMessageW(game, WM_ACTIVATEAPP, TRUE, our_tid);
            SendMessageW(game, WM_ACTIVATE, MAKEWPARAM(WA_ACTIVE, 0), 0);
            SendMessageW(game, WM_SETFOCUS, 0, 0);
            if (attached)
                AttachThreadInput(our_tid, game_tid, FALSE);
        }
        while (ShowCursor(FALSE) >= 0) {}
        SetCursor(NULL);
        DH_INFO("[capture] cursor forced hidden");
    }
    SetWindowPos(g_ui.hwnd, HWND_TOPMOST, 0, 0, 0, 0,
                 SWP_NOMOVE | SWP_NOSIZE | SWP_FRAMECHANGED | SWP_NOACTIVATE);
    DH_INFO("[capture] exit ok");
}

static LRESULT CALLBACK dh_wndproc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    // Route input to ImGui ONLY when the panel is open (capture mode)
    if (g_ui.input_capture &&
        ImGui_ImplWin32_WndProcHandler(hwnd, msg, wp, lp))
        return true;

    switch (msg) {
    case WM_NCHITTEST:
        return g_ui.input_capture ? DefWindowProcW(hwnd, msg, wp, lp) : HTTRANSPARENT;
    case WM_SETCURSOR:
        if (!g_ui.input_capture) { SetCursor(nullptr); return TRUE; }
        break;
    case WM_DESTROY: PostQuitMessage(0); return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

// -----------------------------------------------------------------------------
// Init D3D11 + DirectComposition swap chain
// -----------------------------------------------------------------------------

static bool init_d3d()
{
    // Feature levels: 11.0 → 10.1 → 10.0 → 9.3. Reject HARDWARE-only fail
    // path (returns E_OUTOFMEMORY under elevated launcher-spawned child on
    // some Win11 configs — GPU access strip). Fall back to WARP renderer
    // if hardware refuses.
    static const D3D_FEATURE_LEVEL fls[] = {
        D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_1,
        D3D_FEATURE_LEVEL_10_0, D3D_FEATURE_LEVEL_9_3,
    };
    D3D_FEATURE_LEVEL got_fl = (D3D_FEATURE_LEVEL)0;
    HRESULT hr = D3D11CreateDevice(NULL, D3D_DRIVER_TYPE_HARDWARE, NULL,
        D3D11_CREATE_DEVICE_BGRA_SUPPORT, fls, (UINT)(sizeof(fls)/sizeof(fls[0])),
        D3D11_SDK_VERSION, &g_ui.d3d, &got_fl, &g_ui.ctx);
    if (FAILED(hr)) {
        DH_WARN("D3D11CreateDevice HARDWARE hr=0x%08lX — trying WARP", hr);
        hr = D3D11CreateDevice(NULL, D3D_DRIVER_TYPE_WARP, NULL,
            D3D11_CREATE_DEVICE_BGRA_SUPPORT, fls, (UINT)(sizeof(fls)/sizeof(fls[0])),
            D3D11_SDK_VERSION, &g_ui.d3d, &got_fl, &g_ui.ctx);
        if (FAILED(hr)) {
            DH_ERROR("D3D11CreateDevice WARP also failed hr=0x%08lX", hr);
            return false;
        }
        DH_WARN("D3D11 using WARP software renderer (fl=0x%X)", got_fl);
    }

    IDXGIDevice*   dxgiDev = NULL;
    IDXGIAdapter*  adapter = NULL;
    IDXGIFactory2* factory = NULL;
    g_ui.d3d->QueryInterface(__uuidof(IDXGIDevice), (void**)&dxgiDev);
    dxgiDev->GetAdapter(&adapter);
    adapter->GetParent(__uuidof(IDXGIFactory2), (void**)&factory);

    DXGI_SWAP_CHAIN_DESC1 sd = {};
    sd.Width  = g_ui.sw;
    sd.Height = g_ui.sh;
    sd.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
    sd.SampleDesc.Count = 1;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.BufferCount = 2;
    sd.SwapEffect = DXGI_SWAP_EFFECT_FLIP_SEQUENTIAL;
    sd.AlphaMode  = DXGI_ALPHA_MODE_PREMULTIPLIED;

    hr = factory->CreateSwapChainForComposition(g_ui.d3d, &sd, NULL, &g_ui.swap);
    factory->Release(); adapter->Release();
    if (FAILED(hr)) { DH_ERROR("CreateSwapChainForComposition hr=0x%08lX", hr);
                      dxgiDev->Release(); return false; }

    ID3D11Texture2D* back = NULL;
    g_ui.swap->GetBuffer(0, __uuidof(ID3D11Texture2D), (void**)&back);
    g_ui.d3d->CreateRenderTargetView(back, NULL, &g_ui.rtv);
    back->Release();

    hr = DCompositionCreateDevice(dxgiDev, __uuidof(IDCompositionDevice),
                                  (void**)&g_ui.dcomp);
    dxgiDev->Release();
    if (FAILED(hr)) { DH_ERROR("DCompositionCreateDevice hr=0x%08lX", hr); return false; }
    g_ui.dcomp->CreateTargetForHwnd(g_ui.hwnd, TRUE, &g_ui.dcompT);
    g_ui.dcomp->CreateVisual(&g_ui.dcompV);
    g_ui.dcompV->SetContent(g_ui.swap);
    g_ui.dcompT->SetRoot(g_ui.dcompV);
    g_ui.dcomp->Commit();
    return true;
}

// -----------------------------------------------------------------------------
// Render one frame
// -----------------------------------------------------------------------------

// team_color removed — colors now come from user-picked per-entity-type
// palette in DH_UI.col_player_* / col_bot_*.

// Top-level exception filter â€” writes crash context to log before process
// dies so we know what killed us (address, exception code, stage flag).
static volatile const char* g_last_stage = "init";
static LONG WINAPI dh_unhandled_ex_filter(EXCEPTION_POINTERS* ep)
{
    DH_ERROR("[CRASH] code=0x%08lX addr=%p flags=0x%lX stage='%s'",
             ep->ExceptionRecord->ExceptionCode,
             ep->ExceptionRecord->ExceptionAddress,
             ep->ExceptionRecord->ExceptionFlags,
             g_last_stage ? g_last_stage : "?");
    for (DWORD i = 0; i < ep->ExceptionRecord->NumberParameters && i < 4; i++) {
        DH_ERROR("[CRASH]   param[%lu] = 0x%llX",
                 i, (unsigned long long)ep->ExceptionRecord->ExceptionInformation[i]);
    }
    return EXCEPTION_EXECUTE_HANDLER;
}

#define STAGE(s) do { g_last_stage = (s); } while(0)
#define STAGE_LOG(s) STAGE(s)

static void render_frame_inner();

static void render_frame()
{
    __try {
        render_frame_inner();
    } __except (dh_unhandled_ex_filter(GetExceptionInformation())) {
        DH_ERROR("[render_frame] SEH-caught, exiting overlay");
        InterlockedExchange(&g_ui.running, 0);
        PostQuitMessage(0);
    }
}

static void render_frame_inner()
{
    STAGE("frame:enter");
    ImGui_ImplDX11_NewFrame();
    ImGui_ImplWin32_NewFrame();
    ImGui::NewFrame();

    // Snapshot local state under lock
    DH_SHMEM_PLAYER players[DH_MAX_PLAYERS];
    int cnt, myTeam;
    float cx, cy, cz, yaw, pitch, roll, fov;
    EnterCriticalSection(&g_ui.lock);
    memcpy(players, g_ui.players, sizeof(players));
    cnt = g_ui.count;
    myTeam = g_ui.myTeam;
    cx = g_ui.camX; cy = g_ui.camY; cz = g_ui.camZ;
    yaw = g_ui.camYaw; pitch = g_ui.camPitch; roll = g_ui.camRoll;
    fov = g_ui.fov;
    bool sp = g_ui.show_players, sb = g_ui.show_bots;
    bool pn = g_ui.show_player_names, pd = g_ui.show_player_dist;
    int  p_box = g_ui.box_mode_players;      // 0=Off, 1=2D, 2=3D
    bool p2d = (p_box == 1);
    bool p3d = (p_box == 2);
    bool pm  = g_ui.show_player_mates;
    bool pt  = g_ui.show_player_team;
    bool php = g_ui.show_player_hp;
    bool pcp = g_ui.show_player_corpses;
    bool bn = g_ui.show_bot_names,    bd = g_ui.show_bot_dist;
    int  b_box = g_ui.box_mode_bots;
    bool b2d = (b_box == 1);
    bool b3d = (b_box == 2);
    bool bhp = g_ui.show_bot_hp;
    bool bcp = g_ui.show_bot_corpses;
    bool shud = g_ui.show_hud;
    LeaveCriticalSection(&g_ui.lock);

    Mat3 mat = cam_matrix(yaw, pitch, roll);
    int sw = g_ui.sw, sh = g_ui.sh;

    ImDrawList* dl = ImGui::GetBackgroundDrawList();

    // ESP boxes for entities
    int drawn = 0, enemies = 0, mates_seen = 0;
    int locals_seen = 0, mates_all = 0, bots_flagged = 0;
    // Pre-scan for diagnostics (before valid/local skips) — this tells us
    // whether the daemon publishes teammates but flags them wrong.
    for (int i = 0; i < cnt; i++) {
        const DH_SHMEM_PLAYER& e = players[i];
        if (!e.valid) continue;
        if (e.local) locals_seen++;
        if (e.is_bot) bots_flagged++;
        if (myTeam >= 0 && e.team == myTeam) mates_all++;
    }
    for (int i = 0; i < cnt; i++) {
        const DH_SHMEM_PLAYER& e = players[i];
        if (!e.valid || e.local) continue;
        if (!e.is_bot && myTeam >= 0 && e.team == myTeam) mates_seen++;
        if (e.is_bot && !sb)  continue;
        if (!e.is_bot && !sp) continue;
        // Teammate filter — draw same-team players by default. Only skip
        // when "Show mates" is explicitly OFF, and even then keep them if
        // "Team ID" is ON (user is diagnosing).
        if (!e.is_bot && !pm && !pt && myTeam >= 0 && e.team == myTeam)
            continue;
        // Corpse gating — per-team toggle. `is_corpse` = daemon's bDead
        // flag OR replicated live_status==2.
        bool is_corpse = (e.is_dead || e.live_status == 2);
        if (is_corpse) {
            if (e.is_bot ? !bcp : !pcp) continue;
        }

        // ABI-style box math — port of abifinal src/render.cpp:432-462.
        // One anchor at capsule center + per-axis dims via perspective scale.
        //
        // Capsule dims come from shmem per entity (daemon reads
        // UCapsuleComponent+0x5D0/0x5D4 every refresh — shrinks on crouch
        // and prone). Fallback to UE Character defaults if shmem hasn't
        // populated yet (first tick after spawn).
        float CAP_HH = e.cap_hh > 0 ? e.cap_hh : 88.0f;
        float CAP_R  = e.cap_r  > 0 ? e.cap_r  : 34.0f;

        // Velocity extrapolation + snap-detect.
        //
        // Compensates ~35ms position staleness: box drawn where target
        // WILL BE at render time, using daemon's (vx,vy,vz).
        //
        // Trade-off — on abrupt direction change (player pivots right),
        // overlay uses OLD velocity for ~1 daemon tick until new vel
        // propagates → brief overshoot along old vector.
        //
        // Mitigations:
        //   * Extrapolation window capped at 50ms
        //     → max overshoot @sprint (2000 UU/s) = 100 UU = 1m
        //   * Snap-detect: if raw pos jumped >200 UU (2m) between ticks,
        //     zero the extrap this frame (teleport / hard pivot / RPM tear)
        //   * Vel magnitude sanity (>2000 UU/s = 20 m/s = rejected spike)
        static float s_prev_x[DH_MAX_PLAYERS] = {0};
        static float s_prev_y[DH_MAX_PLAYERS] = {0};
        static float s_prev_z[DH_MAX_PLAYERS] = {0};
        static u64   s_prev_ts[DH_MAX_PLAYERS] = {0};
        u64 now_ms = GetTickCount64();
        float dt_s = 0.0f;
        if (i >= 0 && i < DH_MAX_PLAYERS &&
            e.pos_ts_ms != 0 && now_ms > e.pos_ts_ms)
        {
            u64 age_ms = now_ms - e.pos_ts_ms;
            if (age_ms > 30) age_ms = 30;
            dt_s = (float)age_ms / 1000.0f;
            // Snap-detect — if raw pos moved >200 UU in last tick, direction
            // just changed, don't extrapolate this frame.
            float dpx = e.x - s_prev_x[i];
            float dpy = e.y - s_prev_y[i];
            if (s_prev_ts[i] != 0 && (dpx*dpx + dpy*dpy) > 200.0f*200.0f)
                dt_s = 0.0f;
            s_prev_x[i] = e.x; s_prev_y[i] = e.y; s_prev_z[i] = e.z;
            s_prev_ts[i] = now_ms;
        }
        float vlen2 = e.vx*e.vx + e.vy*e.vy + e.vz*e.vz;
        if (vlen2 > 2000.0f * 2000.0f) dt_s = 0.0f;   // vel spike → drop
        float epx = e.x + e.vx * dt_s;
        float epy = e.y + e.vy * dt_s;
        float epz = e.z + e.vz * dt_s;

        // Anchor = capsule center (UE Character.Location IS the capsule
        // midpoint; feet at z-88, head at z+88 for the default 88 hh).
        //
        // Corpse fix: on death actor.Location stays at the STANDING
        // capsule centre (~waist height) while the ragdoll drops to
        // the ground. Shift anchor DOWN by (standing_hh − corpse_hh)
        // so the box wraps the flattened silhouette on the feet plane.
        float ez_anchor = epz;
        if (is_corpse) {
            const float STAND_HH = 88.0f;
            ez_anchor -= (STAND_HH - CAP_HH);
        }
        ScreenPt p = w2s(epx, epy, ez_anchor, cx, cy, cz, mat, fov, sw, sh);
        if (!p.ok) continue;

        // Max distance filter (per-team, 0 = unlimited). 2D ground
        // distance in meters — matches abifinal minimap convention.
        // Corpses use their own distance cap so live entities can be seen
        // farther than looting-priority corpses.
        float dxr = epx - cx, dyr = epy - cy;
        int meters = (int)(sqrtf(dxr*dxr + dyr*dyr) / 100.f);
        int max_m = is_corpse
            ? (e.is_bot ? g_ui.corpse_dist_bots : g_ui.corpse_dist_players)
            : (e.is_bot ? g_ui.max_dist_bots     : g_ui.max_dist_players);
        if (max_m > 0 && meters > max_m) continue;

        // Perspective scale — identical formula to w2s above so the
        // capsule projects to the same pixel dims as any world segment.
        //   pixels_per_uu_at_depth = (screen_w/2 / tan(fov/2)) / depth
        float thf = tanf(deg2rad(fov > 0.f ? fov : 90.f) * 0.5f);
        float scale_factor = sw * 0.5f / thf;
        float box_h = scale_factor * (CAP_HH * 2.0f) / p.depth;
        float box_w = scale_factor * (CAP_R  * 2.0f) / p.depth;
        // No hard pixel cull — users tune visibility with the per-team
        // Max distance sliders. Only guard against degenerate NaN/zero
        // that would blow up bracket geometry.
        if (!(box_h > 0.0f) || !(box_w > 0.0f)) continue;

        float x0 = p.sx - box_w * 0.5f, x1 = p.sx + box_w * 0.5f;
        float y0 = p.sy - box_h * 0.5f, y1 = p.sy + box_h * 0.5f;
        float cxs = p.sx;

        // Teammate = non-bot, same team, not local. Get their own box color
        // and drop distance/team-id text (name-only per user spec).
        bool is_teammate = (!e.is_bot && myTeam >= 0 && e.team == myTeam);

        // User-picked per-entity-type colors — players and bots independent.
        // Corpses override with their own colour (default pure black).
        ImU32 col_box;
        if (is_corpse) {
            col_box = ImGui::ColorConvertFloat4ToU32(
                e.is_bot ? g_ui.col_bot_corpse : g_ui.col_player_corpse);
        } else {
            col_box = ImGui::ColorConvertFloat4ToU32(
                e.is_bot   ? g_ui.col_bot_box
              : is_teammate ? g_ui.col_teammate_box
                            : g_ui.col_player_box);
        }
        ImU32 col_name = ImGui::ColorConvertFloat4ToU32(
            e.is_bot ? g_ui.col_bot_name : g_ui.col_player_name);
        ImU32 col_dist = ImGui::ColorConvertFloat4ToU32(
            e.is_bot ? g_ui.col_bot_dist : g_ui.col_player_dist);
        ImU32 col_team = ImGui::ColorConvertFloat4ToU32(g_ui.col_player_team);

        // 2D box: gated by per-team toggle AND per-team box-distance
        // (0=unlimited). Name/distance text uses the wider max_dist filter.
        int box_max = e.is_bot ? g_ui.box_dist_bots : g_ui.box_dist_players;
        bool show_2d = (e.is_bot ? b2d : p2d) &&
                       (box_max == 0 || meters <= box_max);
        if (show_2d) {
            // ABI-style corner brackets: L-shapes at each corner, length
            // 22% of the corresponding side with a 4px floor so tiny boxes
            // still read. Shadow underlay for legibility on bright bg.
            float bw = box_w * 0.22f;
            float bh = box_h * 0.22f;
            if (bw < 4.0f) bw = 4.0f;
            if (bh < 4.0f) bh = 4.0f;
            float thk = g_ui.box_thickness * g_ui.ui_scale;
            ImU32 shd = IM_COL32(0, 0, 0, 180);
            auto seg = [&](float ax, float ay, float bxp, float byp) {
                dl->AddLine(ImVec2(ax+0.5f, ay+0.5f),
                            ImVec2(bxp+0.5f, byp+0.5f), shd, thk + 0.6f);
                dl->AddLine(ImVec2(ax, ay),
                            ImVec2(bxp, byp), col_box, thk);
            };
            // TL
            seg(x0, y0, x0 + bw, y0);
            seg(x0, y0, x0, y0 + bh);
            // TR
            seg(x1, y0, x1 - bw, y0);
            seg(x1, y0, x1, y0 + bh);
            // BL
            seg(x0, y1, x0 + bw, y1);
            seg(x0, y1, x0, y1 - bh);
            // BR
            seg(x1, y1, x1 - bw, y1);
            seg(x1, y1, x1, y1 - bh);
        }

        // 3D box — capsule wrap rotated by pawn yaw. Port of abifinal
        // render.cpp:538-585. 4 corners at 45°/135°/225°/315° from the
        // pawn's yaw, each at CAP_R distance. 12 edges (4 bot + 4 top +
        // 4 vertical). Shadow underlay + main stroke.
        bool show_3d = (e.is_bot ? b3d : p3d) &&
                       (box_max == 0 || meters <= box_max);
        if (show_3d) {
            float thk3 = g_ui.box_thickness * g_ui.ui_scale;
            ImU32 shd3 = IM_COL32(0, 0, 0, 180);
            float z_bot = -CAP_HH, z_top = +CAP_HH;
            if (is_corpse) {
                const float STAND_HH = 88.0f;
                float shift = -(STAND_HH - CAP_HH);
                z_bot += shift;
                z_top += shift;
            }
            float yaw_pawn = e.yaw;
            const float offs[4] = { 45.0f, 135.0f, 225.0f, 315.0f };
            // 3D wireframe reads visually thin at range because the capsule
            // radius is a tight fit around the silhouette; widen by 10% so
            // it hugs the model without clipping the shoulders/backpack.
            const float R3D = CAP_R * 1.10f;
            auto corner = [&](float ang_off, float zoff) -> ScreenPt {
                float ang = deg2rad(yaw_pawn + ang_off);
                float cxw = epx + cosf(ang) * R3D;
                float cyw = epy + sinf(ang) * R3D;
                return w2s(cxw, cyw, epz + zoff, cx, cy, cz, mat, fov, sw, sh);
            };
            ScreenPt cc[8];
            bool any = false;
            for (int k = 0; k < 4; k++) {
                cc[k]   = corner(offs[k], z_bot);
                cc[k+4] = corner(offs[k], z_top);
                any = any || cc[k].ok || cc[k+4].ok;
            }
            if (any) {
                const int edges[12][2] = {
                    {0,1},{1,2},{2,3},{3,0},   // bottom rect
                    {4,5},{5,6},{6,7},{7,4},   // top rect
                    {0,4},{1,5},{2,6},{3,7}    // verticals
                };
                // Corner-bracket mode (abifinal port): for each edge draw
                // two short stubs (~28% of edge length) growing from the
                // two endpoints. 8 corners × 3 arms = 24 short segments,
                // reads as a hologram-target frame — not a solid cage.
                const float T = 0.28f;
                auto stub = [&](const ScreenPt& a, const ScreenPt& b) {
                    if (!a.ok || !b.ok) return;
                    float ex = a.sx + (b.sx - a.sx) * T;
                    float ey = a.sy + (b.sy - a.sy) * T;
                    dl->AddLine(ImVec2(a.sx + 0.5f, a.sy + 0.5f),
                                ImVec2(ex   + 0.5f, ey   + 0.5f),
                                shd3, thk3 + 0.6f);
                    dl->AddLine(ImVec2(a.sx, a.sy),
                                ImVec2(ex,   ey),
                                col_box, thk3);
                };
                for (int k = 0; k < 12; k++) {
                    const ScreenPt& a = cc[edges[k][0]];
                    const ScreenPt& b = cc[edges[k][1]];
                    stub(a, b);
                    stub(b, a);
                }
            }
        }

        // Teammates: box only. No name, no distance, no team-id — nick
        // duplication with in-game HUD is noisy.
        bool show_name = is_teammate ? false : (e.is_bot ? bn : pn);
        bool show_dist = is_teammate ? false : (e.is_bot ? bd : pd);
        bool show_team_here = is_teammate ? false : pt;
        // Nickname line — always at y0 - 14. Team ID (players only) draws
        // as "T:=N" immediately to the right of the nickname, in its own
        // red color, so nickname stays clean while diagnostics stay visible.
        // If nickname is hidden but Team ID is on, the T:= tag anchors
        // itself at the box center.
        char name_buf[64] = {0};
        ImVec2 name_sz(0, 0);
        if (show_name && e.name[0]) {
            WideCharToMultiByte(CP_UTF8, 0, e.name, -1, name_buf, sizeof(name_buf), 0, 0);
            name_sz = ImGui::CalcTextSize(name_buf);
        }

        // HP line — one line ABOVE the nickname when the per-team HP toggle
        // is ON and the daemon delivered a valid MaxHealth. Teammates skip
        // (they render lean by user spec).
        bool show_hp_here = false;
        if (!is_teammate && e.hp_max > 0.5f) {
            show_hp_here = e.is_bot ? bhp : php;
        }
        char hp_buf[24] = {0};
        ImVec2 hp_sz(0, 0);
        if (show_hp_here) {
            snprintf(hp_buf, sizeof(hp_buf), "HP %d/%d",
                     (int)(e.hp + 0.5f), (int)(e.hp_max + 0.5f));
            hp_sz = ImGui::CalcTextSize(hp_buf);
        }
        char team_buf[24] = {0};
        ImVec2 team_sz(0, 0);
        if (show_team_here && !e.is_bot) {
            snprintf(team_buf, sizeof(team_buf), " T:=%d", e.team);
            team_sz = ImGui::CalcTextSize(team_buf);
        }
        // Header layout — three rows stacked ABOVE the box, top-to-bottom:
        //     Nick + Team ID          (top, closest to sky)
        //     HP                      (middle)
        //     Armor                   (just above the box)
        // Rows only take space if they actually render.

        // 1) Build armor spans up-front (tier + durability as separate
        //    coloured spans). Layout: "H:<tier>" "(<dur>)" " A:<tier>" "(<dur>)".
        //    Each piece independently coloured via g_ui.col_(player|bot)_armor_(tier|dura).
        struct ArSpan { char s[16]; ImU32 col; float w; };
        ArSpan ar_spans[4];
        int ar_span_n = 0;
        float ar_total_w = 0.0f;
        {
            bool sh_tier = e.is_bot ? g_ui.show_bot_armor_tier
                                    : g_ui.show_player_armor_tier;
            bool sh_dura = e.is_bot ? g_ui.show_bot_armor_dura
                                    : g_ui.show_player_armor_dura;
            bool bot_in_range = !e.is_bot || meters <= 500;
            ImU32 col_tier = ImGui::ColorConvertFloat4ToU32(
                e.is_bot ? g_ui.col_bot_armor_tier : g_ui.col_player_armor_tier);
            ImU32 col_dura = ImGui::ColorConvertFloat4ToU32(
                e.is_bot ? g_ui.col_bot_armor_dura : g_ui.col_player_armor_dura);
            auto push = [&](const char* fmt, ImU32 col, int va, int vb, int has_b) {
                if (ar_span_n >= 4) return;
                char buf[16];
                if (has_b) snprintf(buf, sizeof(buf), fmt, va, vb);
                else       snprintf(buf, sizeof(buf), fmt, va);
                size_t bl = strlen(buf);
                if (bl >= sizeof(ar_spans[ar_span_n].s))
                    bl = sizeof(ar_spans[ar_span_n].s) - 1;
                memcpy(ar_spans[ar_span_n].s, buf, bl);
                ar_spans[ar_span_n].s[bl] = 0;
                ar_spans[ar_span_n].col = col;
                ar_spans[ar_span_n].w   = ImGui::CalcTextSize(ar_spans[ar_span_n].s).x;
                ar_total_w += ar_spans[ar_span_n].w;
                ar_span_n++;
            };
            if (!is_teammate && bot_in_range && (sh_tier || sh_dura) &&
                (e.helmet_tier > 0 || e.armor_tier > 0)) {
                if (e.helmet_tier > 0) {
                    if (sh_tier) push("H:%d", col_tier, (int)e.helmet_tier, 0, 0);
                    if (sh_dura && e.helmet_durability > 0.0f)
                        push(sh_tier ? "(%d)" : "H:%d", col_dura,
                             (int)e.helmet_durability, 0, 0);
                }
                if (e.armor_tier > 0) {
                    int had = ar_span_n;
                    if (sh_tier) push(had ? " A:%d" : "A:%d",
                                      col_tier, (int)e.armor_tier, 0, 0);
                    if (sh_dura && e.armor_durability > 0.0f) {
                        if (ar_span_n > had)
                            push("(%d)", col_dura, (int)e.armor_durability, 0, 0);
                        else
                            push(had ? " A:%d" : "A:%d", col_dura,
                                 (int)e.armor_durability, 0, 0);
                    }
                }
            }
        }
        // Keep legacy has_ar_row / ar_buf hooks compatible: presence flag +
        // a joined string used only for row-height computation.
        char ar_buf[64] = {0};
        {
            int off = 0;
            for (int k = 0; k < ar_span_n && off < (int)sizeof(ar_buf) - 1; k++)
                off += snprintf(ar_buf + off, sizeof(ar_buf) - off, "%s",
                                ar_spans[k].s);
        }

        // Weapon display disabled per user 2026-09-22 (not implemented).
        char wp_buf[48] = {0};
        ImVec2 wp_sz = wp_buf[0] ? ImGui::CalcTextSize(wp_buf) : ImVec2(0,0);

        // 2) Compute row Y positions from bottom (just above the box) up.
        const float line_h = 14.f;                    // matches previous "y0 - 14"
        float row_ar_y   = y0 - line_h;                // armor row (or absent)
        bool  has_ar_row = ar_buf[0] != 0;
        float row_wp_y   = has_ar_row ? row_ar_y - line_h : row_ar_y;
        bool  has_wp_row = wp_buf[0] != 0;
        float row_hp_y   = has_wp_row ? row_wp_y - line_h : row_wp_y;
        bool  has_hp_row = hp_buf[0] != 0;
        float row_nick_y = has_hp_row ? row_hp_y - line_h : row_hp_y;

        // 3) Nick + team on the top row.
        float head_line_total = name_sz.x + team_sz.x;
        float head_x_start    = cxs - head_line_total * 0.5f;
        float head_x          = head_x_start;
        float head_y          = row_nick_y;
        if (name_buf[0]) {
            dl->AddText(ImVec2(head_x, head_y), col_name, name_buf);
            head_x += name_sz.x;
        }
        if (team_buf[0]) {
            dl->AddText(ImVec2(head_x, head_y), col_team, team_buf);
        }

        // 4) HP on the middle row.
        float hp_y_used = 0;
        if (has_hp_row) {
            float hp_x = cxs - hp_sz.x * 0.5f;
            ImU32 hp_col = ImGui::ColorConvertFloat4ToU32(
                e.is_bot ? g_ui.col_bot_hp : g_ui.col_player_hp);
            dl->AddText(ImVec2(hp_x, row_hp_y), hp_col, hp_buf);
            hp_y_used = row_hp_y;
        }

        // 5a) Weapon row (between HP and armor). Uses armor tier color
        //     (same "info" text style; no separate settings until user asks).
        if (has_wp_row) {
            float wp_x = cxs - wp_sz.x * 0.5f;
            ImU32 wp_col = ImGui::ColorConvertFloat4ToU32(
                e.is_bot ? g_ui.col_bot_armor_tier : g_ui.col_player_armor_tier);
            dl->AddText(ImVec2(wp_x, row_wp_y), wp_col, wp_buf);
        }

        // 5) Armor on the bottom-of-header row (just above the box).
        //    Each span drawn with its own colour so tier and durability
        //    can be styled independently per user preference.
        if (has_ar_row && ar_span_n > 0) {
            float ar_x = cxs - ar_total_w * 0.5f;
            for (int k = 0; k < ar_span_n; k++) {
                dl->AddText(ImVec2(ar_x, row_ar_y),
                            ar_spans[k].col, ar_spans[k].s);
                ar_x += ar_spans[k].w;
            }
        }

        // SKELETON REMOVED 2026-09-26.

        // Status banner above everything else — KNOCKED! (orange) or
        // DEAD (grey). Live-status is server-replicated on PlayerState.
        //
        // Gating:
        //   KNOCKED  → tied to HP toggle (show_player_hp / show_bot_hp).
        //              User treats KNOCKED as a health-state indicator.
        //   DEAD     → NOT gated here — the corpse toggle earlier (~line 671)
        //              skips the whole entity if show_*_corpses is off, so if
        //              we reach here on a dead entity, corpse rendering is on
        //              and DEAD should show as its label.
        const char* status_txt = NULL;
        ImU32 status_col = IM_COL32(255, 140, 40, 255);
        bool hp_on = e.is_bot ? g_ui.show_bot_hp : g_ui.show_player_hp;
        if (e.live_status == 3 && hp_on) {
            status_txt = "KNOCKED!"; status_col = IM_COL32(255, 140, 40, 255);
        }
        else if (e.live_status == 2 || e.is_dead) {
            status_txt = "DEAD"; status_col = IM_COL32(180, 180, 180, 255);
        }
        if (status_txt) {
            ImVec2 tsz = ImGui::CalcTextSize(status_txt);
            // Status banner sits ABOVE the top-most header row (nick).
            float sy = row_nick_y - tsz.y;
            dl->AddText(ImVec2(cxs - tsz.x * 0.5f, sy), status_col, status_txt);
        }

        // Nick + team + HP + armor are drawn earlier in the header block.
        float text_y = y1 + 2.f;
        if (show_dist) {
            char buf[16]; snprintf(buf, sizeof(buf), "%dm", meters);
            ImVec2 tsz = ImGui::CalcTextSize(buf);
            dl->AddText(ImVec2(cxs - tsz.x * 0.5f, text_y), col_dist, buf);
            text_y += tsz.y;
        }
        (void)text_y;

        drawn++;
        if (!e.is_bot && e.team != myTeam) enemies++;
    }

    // ---- Radar (ABIFinal port, "cyan glow military" style) --------------
    if (g_ui.show_radar) {
        static constexpr float UE_UNITS_PER_M = 100.0f;
        const float rr = (float)g_ui.radar_px_radius;
        // First-frame init — snap to top-right if never positioned.
        if (g_ui.radar_x == INT_MIN || g_ui.radar_y == INT_MIN) {
            g_ui.radar_x = (int)((float)sw - rr - 30.0f);
            g_ui.radar_y = (int)(rr + 30.0f);
        }
        // Clamp to screen (radius margin so disc never overflows).
        const int pad = 4;
        int min_x = (int)rr + pad, max_x = sw - (int)rr - pad;
        int min_y = (int)rr + pad, max_y = sh - (int)rr - pad;
        if (g_ui.radar_x < min_x) g_ui.radar_x = min_x;
        if (g_ui.radar_x > max_x) g_ui.radar_x = max_x;
        if (g_ui.radar_y < min_y) g_ui.radar_y = min_y;
        if (g_ui.radar_y > max_y) g_ui.radar_y = max_y;

        // Drag handling — only when settings panel is open (so gameplay
        // clicks never move the radar). Grab the disc anywhere inside.
        if (g_ui.panel_open) {
            ImGuiIO& rio = ImGui::GetIO();
            float mx = rio.MousePos.x, my = rio.MousePos.y;
            float ddx = mx - (float)g_ui.radar_x;
            float ddy = my - (float)g_ui.radar_y;
            bool inside = (ddx*ddx + ddy*ddy) <= (rr * rr);
            bool lmb_down = ImGui::IsMouseDown(ImGuiMouseButton_Left);
            if (!g_ui.radar_dragging && lmb_down && inside && !rio.WantCaptureMouse) {
                g_ui.radar_dragging = true;
                g_ui.radar_drag_dx  = ddx;
                g_ui.radar_drag_dy  = ddy;
            }
            if (g_ui.radar_dragging) {
                if (!lmb_down) {
                    g_ui.radar_dragging = false;
                } else {
                    g_ui.radar_x = (int)(mx - g_ui.radar_drag_dx);
                    g_ui.radar_y = (int)(my - g_ui.radar_drag_dy);
                    if (g_ui.radar_x < min_x) g_ui.radar_x = min_x;
                    if (g_ui.radar_x > max_x) g_ui.radar_x = max_x;
                    if (g_ui.radar_y < min_y) g_ui.radar_y = min_y;
                    if (g_ui.radar_y > max_y) g_ui.radar_y = max_y;
                }
            }
        } else if (g_ui.radar_dragging) {
            g_ui.radar_dragging = false;
        }

        const float rcx = (float)g_ui.radar_x;
        const float rcy = (float)g_ui.radar_y;
        const ImVec2 C(rcx, rcy);

        ImU32 col_disc  = ImGui::ColorConvertFloat4ToU32(g_ui.col_radar_disc);
        ImU32 col_ring  = ImGui::ColorConvertFloat4ToU32(g_ui.col_radar_ring);
        ImU32 col_self  = ImGui::ColorConvertFloat4ToU32(g_ui.col_radar_self);
        ImU32 col_pl    = ImGui::ColorConvertFloat4ToU32(g_ui.col_radar_player);
        ImU32 col_bot   = ImGui::ColorConvertFloat4ToU32(g_ui.col_radar_bot);
        ImU32 col_mate      = ImGui::ColorConvertFloat4ToU32(g_ui.col_radar_teammate);
        ImU32 col_corp_pl   = ImGui::ColorConvertFloat4ToU32(g_ui.col_radar_corpse_player);
        ImU32 col_corp_bot  = ImGui::ColorConvertFloat4ToU32(g_ui.col_radar_corpse_bot);

        // Filled dark disc.
        dl->AddCircleFilled(C, rr, col_disc, 96);

        // Helper: dashed circle (even segments drawn, odd skipped).
        auto dashed_circle = [&](float r, ImU32 c, float thk, int segments) {
            float step = 2.0f * PI / (float)segments;
            for (int i = 0; i < segments; i += 2) {
                float a0 = i * step, a1 = (i + 1) * step;
                ImVec2 p0(rcx + cosf(a0) * r, rcy + sinf(a0) * r);
                ImVec2 p1(rcx + cosf(a1) * r, rcy + sinf(a1) * r);
                dl->AddLine(p0, p1, c, thk);
            }
        };

        // Concentric rings at 50m step + outer.
        if (g_ui.radar_rings && g_ui.radar_range_m > 5) {
            float step = 50.0f;
            int   n_rings = (int)floorf((float)g_ui.radar_range_m / step + 0.001f);
            if (n_rings > 12) n_rings = 12;
            ImU32 ring_mid = (col_ring & 0x00FFFFFFu) | ((uint32_t)70 << 24);
            for (int i = 1; i <= n_rings; i++) {
                float r = rr * ((float)i * step) / (float)g_ui.radar_range_m;
                if (r > rr - 0.5f) break;
                dashed_circle(r, ring_mid, 1.0f, 56);
            }
        }
        dashed_circle(rr, col_ring, 1.4f, 64);

        // Center dot = user.
        dl->AddCircleFilled(C, 3.0f, col_self, 16);

        // Enemy / bot / teammate dots — heading-up transform via camYaw.
        const float yr    = deg2rad(yaw);
        const float cy_r  = cosf(yr);
        const float sy_r  = sinf(yr);
        const float scale = rr / ((float)g_ui.radar_range_m * UE_UNITS_PER_M);

        for (int i = 0; i < cnt; i++) {
            const auto& e = players[i];
            if (!e.valid || e.local) continue;
            bool is_team = (!e.is_bot && myTeam >= 0 && e.team == myTeam);
            if (e.is_bot     && !g_ui.radar_show_bots)      continue;
            if (!e.is_bot    &&  is_team && !g_ui.radar_show_teammates) continue;
            if (!e.is_bot    && !is_team && !g_ui.radar_show_players)   continue;
            if (e.is_dead && !e.is_bot && !g_ui.radar_show_corpses_players) continue;
            if (e.is_dead &&  e.is_bot && !g_ui.radar_show_corpses_bots)    continue;

            float dx = e.x - cx;
            float dy = e.y - cy;
            float dist_m = sqrtf(dx*dx + dy*dy) / UE_UNITS_PER_M;
            if (dist_m > (float)g_ui.radar_range_m) continue;

            // World → radar-local (heading-up).
            float fwd   =  dx * cy_r + dy * sy_r;
            float right = -dx * sy_r + dy * cy_r;
            float sx    = rcx + right * scale;
            float sy_p  = rcy - fwd   * scale;

            ImU32 c_dot;
            float dot_r;
            if (e.is_dead) {
                c_dot = e.is_bot ? col_corp_bot : col_corp_pl;
                dot_r = 4.0f;
            } else if (e.is_bot)  { c_dot = col_bot;  dot_r = 5.5f; }
            else   if (is_team)   { c_dot = col_mate; dot_r = 6.0f; }
            else                  { c_dot = col_pl;   dot_r = 6.5f; }

            ImU32 c_halo = (c_dot & 0x00FFFFFFu) | ((uint32_t)55 << 24);
            dl->AddCircleFilled(ImVec2(sx, sy_p), dot_r + 3.5f, c_halo, 20);
            dl->AddCircleFilled(ImVec2(sx, sy_p), dot_r,        c_dot,  16);
            dl->AddCircle      (ImVec2(sx, sy_p), dot_r + 0.4f,
                                IM_COL32(0, 0, 0, 150), 12, 0.5f);
        }
    }

    // Loot ESP ripped per user 2026-09-22.

    // HUD chip (top-left)
    if (shud) {
        // Overlay FPS meter — measure via frame-time delta.
        static u64 last_frame_ms = 0;
        static float overlay_fps = 0.f;
        u64 now_frame_ms = GetTickCount64();
        if (last_frame_ms != 0) {
            u64 dt = now_frame_ms - last_frame_ms;
            if (dt > 0) {
                float instant = 1000.f / (float)dt;
                overlay_fps = overlay_fps * 0.9f + instant * 0.1f;  // EMA
            }
        }
        last_frame_ms = now_frame_ms;

        // Read shmem-published Hz + compute avg pos age.
        DH_SHMEM* s2 = g_ui.shmem;
        float main_hz = s2 ? s2->main_hz : 0.f;
        float cam_hz  = s2 ? s2->cam_hz  : 0.f;
        u64 now_ms = GetTickCount64();
        u64 age_sum = 0;
        int age_n = 0;
        for (int i = 0; i < cnt && i < 16; i++) {
            if (!players[i].valid || players[i].local) continue;
            if (players[i].pos_ts_ms > 0 && now_ms > players[i].pos_ts_ms) {
                age_sum += (now_ms - players[i].pos_ts_ms);
                age_n++;
            }
        }
        float avg_age_ms = age_n > 0 ? (float)age_sum / (float)age_n : 0.f;

        char buf[256];
        snprintf(buf, sizeof(buf),
                 "DH | ovl %.0ffps  main %.0fHz  cam %.0fHz  posAge %.0fms  |  pl %d en %d mates %d/%d",
                 overlay_fps, main_hz, cam_hz, avg_age_ms,
                 cnt, enemies, mates_all, mates_seen);
        ImVec2 tsz = ImGui::CalcTextSize(buf);
        dl->AddRectFilled(ImVec2(10, 10),
                          ImVec2(10 + tsz.x + 16, 10 + tsz.y + 8),
                          IM_COL32(0, 0, 0, 160), 4.f);
        dl->AddText(ImVec2(18, 14), IM_COL32(220, 220, 220, 255), buf);
    }

    // Hotkey handling â€” F1/F2/F3/F4
    // ESP layer toggles moved into the panel (see toggle switches). No
    // F-key global hotkeys — they were hijacking the game and are gone.

    // Home = toggle settings panel (opens ImGui window + captures input)
    if ((GetAsyncKeyState(VK_HOME) & 1)) {
        STAGE("home:pressed");
        DH_INFO("[hotkey] Home pressed, panel_open %d -> %d",
                (int)g_ui.panel_open, (int)!g_ui.panel_open);
        g_ui.panel_open = !g_ui.panel_open;
        set_input_capture(g_ui.panel_open);
        STAGE("home:done");
    }
    // Insert hotkey removed per user 2026-09-22 — Home only.

    // ---- Settings panel (ABI Nightvex layout: sidebar + row-cards) --------
    if (g_ui.panel_open) {
        STAGE_LOG("panel:begin");
        // Nightvex palette
        const ImU32 C_WINDOW  = IM_COL32(0x0A,0x0A,0x0C,255);
        const ImU32 C_SIDEBAR = IM_COL32(0x0A,0x0A,0x0C,255);
        const ImU32 C_ROW     = IM_COL32(0x10,0x10,0x14,255);
        const ImU32 C_ROWHV   = IM_COL32(0x14,0x14,0x18,255);
        const ImU32 C_SEGACT  = IM_COL32(0x1A,0x1A,0x1F,255);
        const ImU32 C_LINE    = IM_COL32(255,255,255,20);
        const ImU32 C_TEXT    = IM_COL32(0xF4,0xF4,0xF6,255);
        const ImU32 C_MUTED   = IM_COL32(0x8B,0x8B,0x95,255);
        const ImU32 C_AMBER   = IM_COL32(0xE6,0xA3,0x5A,255);

        ImGui::PushStyleColor(ImGuiCol_WindowBg,      C_WINDOW);
        ImGui::PushStyleColor(ImGuiCol_ChildBg,       C_WINDOW);
        ImGui::PushStyleColor(ImGuiCol_TitleBg,       C_WINDOW);
        ImGui::PushStyleColor(ImGuiCol_TitleBgActive, C_WINDOW);
        ImGui::PushStyleColor(ImGuiCol_Border,        C_LINE);
        // Slider/input track: distinct mid-grey so the track reads against
        // the row background (row is C_ROW ≈ 0x101014, near-black).
        ImGui::PushStyleColor(ImGuiCol_FrameBg,       IM_COL32(0x38,0x38,0x42,255));
        ImGui::PushStyleColor(ImGuiCol_FrameBgHovered,IM_COL32(0x44,0x44,0x50,255));
        ImGui::PushStyleColor(ImGuiCol_FrameBgActive, IM_COL32(0x50,0x50,0x5C,255));
        ImGui::PushStyleColor(ImGuiCol_CheckMark,     C_AMBER);
        // High-contrast slider knob: white against dark track. Active state
        // brightens to amber so the drag is visible.
        ImGui::PushStyleColor(ImGuiCol_SliderGrab,       IM_COL32(0xFF,0xFF,0xFF,255));
        ImGui::PushStyleColor(ImGuiCol_SliderGrabActive, C_AMBER);
        ImGui::PushStyleColor(ImGuiCol_Text,          C_TEXT);
        ImGui::PushStyleColor(ImGuiCol_TextDisabled,  C_MUTED);
        ImGui::PushStyleColor(ImGuiCol_Header,        C_ROW);
        ImGui::PushStyleColor(ImGuiCol_HeaderHovered, C_ROWHV);
        ImGui::PushStyleColor(ImGuiCol_HeaderActive,  C_SEGACT);
        ImGui::PushStyleColor(ImGuiCol_ScrollbarBg,   IM_COL32(0,0,0,0));
        ImGui::PushStyleColor(ImGuiCol_ScrollbarGrab, IM_COL32(60,60,68,180));
        ImGui::PushStyleColor(ImGuiCol_ScrollbarGrabHovered, IM_COL32(80,80,90,220));
        ImGui::PushStyleColor(ImGuiCol_ScrollbarGrabActive,  C_AMBER);

        ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 10.0f);
        ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding,  8.0f);
        ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding,  6.0f);
        ImGui::PushStyleVar(ImGuiStyleVar_GrabRounding,   4.0f);
        ImGui::PushStyleVar(ImGuiStyleVar_GrabMinSize,    14.0f);
        ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding,  ImVec2(0, 0));
        ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing,    ImVec2(0, 8));
        ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 1.0f);

        const float kWinW = 900.0f * g_ui.ui_scale;
        const float kWinH = 620.0f * g_ui.ui_scale;
        ImGui::SetNextWindowSize(ImVec2(kWinW, kWinH), ImGuiCond_Always);
        ImGui::SetNextWindowPos(ImVec2(sw * 0.5f, sh * 0.5f),
                                ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));

        STAGE_LOG("panel:styles-pushed");
        if (ImGui::Begin("##dh_panel", &g_ui.panel_open,
                         ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoSavedSettings
                         | ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize))
        {
            STAGE("panel:body");
            static int s_tab = 0;   // 0=Visuals 1=Radar 2=Overlay 3=Settings
            const float kSidebarW = 200.0f * g_ui.ui_scale;

            // â”€â”€ SIDEBAR â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            ImGui::PushStyleColor(ImGuiCol_ChildBg, C_SIDEBAR);
            ImGui::BeginChild("##sidebar", ImVec2(kSidebarW, kWinH),
                              false, ImGuiWindowFlags_NoScrollbar);

            ImGui::Dummy(ImVec2(0, 18));
            // Logo tile â€” placeholder amber square + product name
            ImVec2 p = ImGui::GetCursorScreenPos();
            ImDrawList* wdl = ImGui::GetWindowDrawList();
            // Nightvex logo — real amber shield PNG rasterized from the
            // Nightvex brand SVG, drawn via ImGui::Image over the sidebar
            // draw list. No tile behind it (logo has transparent bg).
            {
                float x = p.x + 14, y = p.y;
                float sz = 44;
                if (g_ui.logo_srv) {
                    wdl->AddImage((ImTextureID)g_ui.logo_srv,
                                  ImVec2(x, y),
                                  ImVec2(x + sz, y + sz));
                } else {
                    // Fallback: solid amber square if texture missing
                    wdl->AddRectFilled(ImVec2(x, y),
                                       ImVec2(x + sz, y + sz),
                                       C_AMBER, 8.0f);
                }
            }
            // "Nightvex" text next to the logo, vertically centered
            ImFont* fb = g_ui.font_big;
            const char* nvtxt = "Nightvex";
            if (fb) {
                wdl->AddText(fb, 22.0f,
                             ImVec2(p.x + 64, p.y + 9),
                             C_TEXT, nvtxt);
            } else {
                wdl->AddText(ImVec2(p.x + 64, p.y + 11), C_TEXT, nvtxt);
            }
            ImGui::Dummy(ImVec2(0, 56));

            // Tabs — custom-drawn rows with icon + label
            struct Tab { const char* label; const char* icon; };
            const Tab tabs[] = {
                {tr("tab.players"), "player"},
                {tr("tab.bots"),    "bot"},
                {tr("tab.radar"),   "radar"},
#ifdef DH_DEBUG
                {"Loot",            "loot"},      // debug only
                {tr("tab.overlay"), "overlay"},   // debug only
#endif
                {tr("tab.lang"),    "settings"},
            };
            for (int i = 0; i < IM_ARRAYSIZE(tabs); i++) {
                bool sel = (s_tab == i);
                ImGui::SetCursorPosX(12);
                ImVec2 pos = ImGui::GetCursorScreenPos();
                float w = kSidebarW - 24, h = 40;
                ImDrawList* tdl = ImGui::GetWindowDrawList();
                bool hov = ImGui::IsMouseHoveringRect(pos, ImVec2(pos.x+w, pos.y+h));
                ImU32 bg = sel ? C_SEGACT : (hov ? C_ROWHV : IM_COL32(0,0,0,0));
                tdl->AddRectFilled(pos, ImVec2(pos.x+w, pos.y+h), bg, 8.0f);
                // Active-tab amber bar on left edge
                if (sel) {
                    tdl->AddRectFilled(pos,
                                      ImVec2(pos.x + 3, pos.y + h),
                                      C_AMBER, 2.0f);
                }
                // Icon (24x24 area centered vertically, left)
                ImU32 ic = sel ? C_AMBER : C_TEXT;
                float ix = pos.x + 14, iy = pos.y + h * 0.5f;
                if (!strcmp(tabs[i].icon, "player")) {
                    // Person: circle head + trapezoid body
                    tdl->AddCircle(ImVec2(ix + 8, iy - 3), 3.5f, ic, 16, 1.7f);
                    ImVec2 body[4] = {
                        { ix + 2.5f,  iy + 7 },
                        { ix + 13.5f, iy + 7 },
                        { ix + 12,    iy + 2 },
                        { ix + 4,     iy + 2 },
                    };
                    tdl->AddPolyline(body, 4, ic, ImDrawFlags_Closed, 1.7f);
                }
                else if (!strcmp(tabs[i].icon, "bot")) {
                    // Bot: antenna + rounded rect head + eyes
                    tdl->AddLine(ImVec2(ix + 8, iy - 8), ImVec2(ix + 8, iy - 5), ic, 1.5f);
                    tdl->AddCircleFilled(ImVec2(ix + 8, iy - 8), 1.4f, ic, 10);
                    tdl->AddRect(ImVec2(ix + 2, iy - 5), ImVec2(ix + 14, iy + 6),
                                 ic, 3.0f, 0, 1.7f);
                    tdl->AddCircleFilled(ImVec2(ix + 5.5f, iy), 1.3f, ic, 10);
                    tdl->AddCircleFilled(ImVec2(ix + 10.5f, iy), 1.3f, ic, 10);
                }
                else if (!strcmp(tabs[i].icon, "radar")) {
                    tdl->AddCircle(ImVec2(ix + 8, iy), 9.0f, ic, 24, 1.7f);
                    tdl->AddCircle(ImVec2(ix + 8, iy), 4.5f, ic, 20, 1.7f);
                    tdl->AddLine(ImVec2(ix + 8, iy), ImVec2(ix + 14, iy - 6), ic, 1.7f);
                    tdl->AddCircleFilled(ImVec2(ix + 8, iy), 1.5f, ic, 8);
                }
                else if (!strcmp(tabs[i].icon, "overlay")) {
                    // Rounded window with title bar
                    tdl->AddRect(ImVec2(ix, iy - 8), ImVec2(ix + 18, iy + 8),
                                ic, 2.5f, 0, 1.7f);
                    tdl->AddLine(ImVec2(ix + 1, iy - 3), ImVec2(ix + 17, iy - 3),
                                ic, 1.4f);
                    tdl->AddLine(ImVec2(ix + 4, iy + 2), ImVec2(ix + 10, iy + 2),
                                ic, 1.4f);
                }
                else if (!strcmp(tabs[i].icon, "settings")) {
                    // Gear: outer 6-tooth star + inner circle
                    tdl->AddCircle(ImVec2(ix + 8, iy), 3.0f, ic, 16, 1.7f);
                    for (int t = 0; t < 6; t++) {
                        float a = t * 3.14159f / 3.0f;
                        float x1 = ix + 8 + cosf(a) * 5.0f;
                        float y1 = iy     + sinf(a) * 5.0f;
                        float x2 = ix + 8 + cosf(a) * 8.5f;
                        float y2 = iy     + sinf(a) * 8.5f;
                        tdl->AddLine(ImVec2(x1, y1), ImVec2(x2, y2), ic, 2.0f);
                    }
                }
                // Label
                if (g_ui.font_mid) {
                    tdl->AddText(g_ui.font_mid, 17.0f,
                                ImVec2(pos.x + 44, pos.y + 11),
                                sel ? C_AMBER : C_TEXT, tabs[i].label);
                } else {
                    tdl->AddText(ImVec2(pos.x + 44, pos.y + 12),
                                sel ? C_AMBER : C_TEXT, tabs[i].label);
                }
                // Consume the space + handle click
                char id[16]; snprintf(id, sizeof(id), "##tab%d", i);
                if (ImGui::InvisibleButton(id, ImVec2(w, h))) {
                    s_tab = i;
                }
                ImGui::Dummy(ImVec2(0, 4));
            }

            ImGui::EndChild();
            ImGui::PopStyleColor();

            // â”€â”€ MAIN CONTENT â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            ImGui::SameLine(0, 0);
            ImGui::BeginChild("##content", ImVec2(kWinW - kSidebarW, kWinH),
                              false);

            // Breadcrumb — just the tab label (tight to top of content)
            ImGui::PushStyleColor(ImGuiCol_Text, C_TEXT);
            ImGui::SetCursorPosX(g_col_x);
            ImGui::Text("%s", tabs[s_tab].label);
            ImGui::PopStyleColor();

            // ABI-style pill toggle switch — amber when on, dark when off,
            // white knob slides across. Returns true if state changed.
            auto pill_toggle = [](const char* id, bool* v) {
                float w = 40, h = 22;
                ImVec2 pos = ImGui::GetCursorScreenPos();
                ImGui::InvisibleButton(id, ImVec2(w, h));
                bool clicked = ImGui::IsItemClicked();
                if (clicked) *v = !*v;
                ImDrawList* dl = ImGui::GetWindowDrawList();
                ImU32 track_on  = IM_COL32(0xE6,0xA3,0x5A, 255);   // amber
                ImU32 track_off = IM_COL32(0x2A,0x2A,0x30, 255);   // dark grey
                ImU32 knob      = IM_COL32(0xF4,0xF4,0xF6, 255);
                ImU32 knob_off  = IM_COL32(0xB8,0xB8,0xBE, 255);
                float r = h * 0.5f;
                dl->AddRectFilled(pos, ImVec2(pos.x + w, pos.y + h),
                                  *v ? track_on : track_off, r);
                float kx = *v ? (pos.x + w - r) : (pos.x + r);
                dl->AddCircleFilled(ImVec2(kx, pos.y + r), r - 3.0f,
                                     *v ? knob : knob_off, 24);
                return clicked;
            };

            // Round color-picker chip — replaces the default ColorEdit4 square.
            // Click opens a full ColorPicker4 popup at the chip's position.
            auto color_circle = [&](const char* id, ImVec4* color) {
                const float r = 10.0f;
                ImVec2 pos = ImGui::GetCursorScreenPos();
                ImGui::InvisibleButton(id, ImVec2(r * 2.0f, r * 2.0f));
                if (ImGui::IsItemClicked()) ImGui::OpenPopup(id);
                ImDrawList* dl = ImGui::GetWindowDrawList();
                ImU32 fill = ImGui::ColorConvertFloat4ToU32(*color);
                ImU32 border = IM_COL32(255, 255, 255, 80);
                ImVec2 c = ImVec2(pos.x + r, pos.y + r);
                dl->AddCircleFilled(c, r, fill, 32);
                dl->AddCircle(c, r, border, 32, 1.2f);
                if (ImGui::BeginPopup(id)) {
                    ImGui::ColorPicker4("##pk", (float*)color,
                        ImGuiColorEditFlags_NoLabel |
                        ImGuiColorEditFlags_AlphaBar);
                    ImGui::EndPopup();
                }
            };

            // Row helper — draws card: [name/desc][color chip][pill toggle]
            // color_ptr may be NULL to omit the color chip.
            // Compact row: single-line title, no description. Height ~40.
            auto row = [&](const char* name, const char* /*desc*/, bool* toggle, ImVec4* color_ptr) {
                const float row_h = 42.0f;
                const float row_w = g_col_w > 0 ? g_col_w : (kWinW - kSidebarW - 48);
                ImGui::SetCursorPosX(g_col_x);
                ImGui::PushStyleColor(ImGuiCol_ChildBg, C_ROW);
                ImGui::BeginChild(name, ImVec2(row_w, row_h), true,
                                  ImGuiWindowFlags_NoScrollbar);

                float title_h = ImGui::GetFontSize();
                float ty = (row_h - title_h) * 0.5f;

                ImGui::SetCursorPos(ImVec2(18, ty));
                ImGui::PushStyleColor(ImGuiCol_Text, C_TEXT);
                ImGui::Text("%s", name);
                ImGui::PopStyleColor();

                if (color_ptr) {
                    ImGui::SetCursorPos(ImVec2(row_w - 92, (row_h - 20) * 0.5f));
                    char cid[64];
                    snprintf(cid, sizeof(cid), "##col_%s", name);
                    color_circle(cid, color_ptr);
                }
                char pid[64];
                snprintf(pid, sizeof(pid), "##pt_%s", name);
                ImGui::SetCursorPos(ImVec2(row_w - 62, (row_h - 22) * 0.5f));
                pill_toggle(pid, toggle);

                ImGui::EndChild();
                ImGui::PopStyleColor();
            };

            // Box-mode row — title on left, [Off] [2D] [3D] radio triplet on
            // right, color picker. Replaces the two separate 2D/3D toggles.
            // Box control — two-row block:
            //   Row 1: "Box"  — pill-toggle on/off + color picker
            //   Row 2 (only if on): "Style" — [2D] [3D] radio pair
            // mode: 0=Off, 1=2D, 2=3D. Turning off nukes mode→0 but remembers
            // the last non-zero style so re-enabling restores 2D/3D user picked.
            auto box_mode_row = [&](const char* name, int* mode, ImVec4* color_ptr) {
                const float row_h = 42.0f;
                const float row_w = g_col_w > 0 ? g_col_w : (kWinW - kSidebarW - 48);

                // Row 1 — main On/Off toggle with color picker.
                ImGui::SetCursorPosX(g_col_x);
                ImGui::PushStyleColor(ImGuiCol_ChildBg, C_ROW);
                char cid_row1[96]; snprintf(cid_row1, sizeof(cid_row1), "%s##bm_r1", name);
                ImGui::BeginChild(cid_row1, ImVec2(row_w, row_h), true,
                                  ImGuiWindowFlags_NoScrollbar);
                float title_h = ImGui::GetFontSize();
                float ty = (row_h - title_h) * 0.5f;
                ImGui::SetCursorPos(ImVec2(18, ty));
                ImGui::PushStyleColor(ImGuiCol_Text, C_TEXT);
                ImGui::Text("%s", name);
                ImGui::PopStyleColor();

                if (color_ptr) {
                    ImGui::SetCursorPos(ImVec2(row_w - 92, (row_h - 20) * 0.5f));
                    char cid[64];
                    snprintf(cid, sizeof(cid), "##colbm_%s", name);
                    color_circle(cid, color_ptr);
                }
                // Static per-row memory of last non-zero style, so toggling
                // Off → On restores the previously picked 2D/3D. Key by mode*
                // pointer identity so Players and Bots rows keep independent
                // memories.
                static int* last_ptr[8]  = {0};
                static int  last_val[8]  = {1,1,1,1,1,1,1,1};
                int slot = 0;
                for (; slot < 8; slot++) {
                    if (last_ptr[slot] == mode) break;
                    if (last_ptr[slot] == 0)  { last_ptr[slot] = mode; break; }
                }
                if (*mode != 0 && slot < 8) last_val[slot] = *mode;

                bool on = (*mode != 0);
                char pid[64];
                snprintf(pid, sizeof(pid), "##pt_bm_%s", name);
                ImGui::SetCursorPos(ImVec2(row_w - 62, (row_h - 22) * 0.5f));
                pill_toggle(pid, &on);
                if (on && *mode == 0) *mode = (slot < 8 ? last_val[slot] : 1);
                if (!on) *mode = 0;

                ImGui::EndChild();
                ImGui::PopStyleColor();

                // Row 2 — Style picker, only when on.
                if (*mode != 0) {
                    ImGui::SetCursorPosX(g_col_x);
                    ImGui::PushStyleColor(ImGuiCol_ChildBg, C_ROW);
                    char cid_row2[96]; snprintf(cid_row2, sizeof(cid_row2), "%s##bm_r2", name);
                    ImGui::BeginChild(cid_row2, ImVec2(row_w, row_h), true,
                                      ImGuiWindowFlags_NoScrollbar);
                    ImGui::SetCursorPos(ImVec2(18, ty));
                    ImGui::PushStyleColor(ImGuiCol_Text, C_TEXT);
                    ImGui::Text("%s", tr("row.box.style"));
                    ImGui::PopStyleColor();

                    const char* labels[2] = { tr("box.2d"), tr("box.3d") };
                    // Right-align the [2D][3D] radio pair. Measure total width,
                    // then start at (row_w - total - right_margin).
                    float gap = 20.0f, right_margin = 16.0f;
                    float knob_w = ImGui::GetFontSize() + 4.0f;   // radio circle
                    float t0 = ImGui::CalcTextSize(labels[0]).x;
                    float t1 = ImGui::CalcTextSize(labels[1]).x;
                    float total = (knob_w + t0) + gap + (knob_w + t1);
                    float rx = row_w - total - right_margin;
                    float ry = (row_h - 20) * 0.5f;
                    for (int i = 0; i < 2; i++) {
                        ImGui::SetCursorPos(ImVec2(rx, ry));
                        char rid[64]; snprintf(rid, sizeof(rid), "%s##bm_%s_%d",
                                               labels[i], name, i);
                        // radio value = i+1 (1=2D, 2=3D)
                        if (ImGui::RadioButton(rid, *mode == (i + 1))) {
                            *mode = i + 1;
                            if (slot < 8) last_val[slot] = *mode;
                        }
                        rx += knob_w + (i == 0 ? t0 : t1) + gap;
                    }

                    ImGui::EndChild();
                    ImGui::PopStyleColor();
                }
            };

            // Round color-picker chip — replaces the default ColorEdit4 square.
            // Click opens a full ColorPicker4 popup at the chip's position.
            // Section header — amber label with a thin divider line below.
            // Not clickable, not collapsible; purely visual grouping inside a tab.
            auto section_header = [&](const char* label) {
                const float default_w = kWinW - kSidebarW - 48;
                const float row_w = g_col_w > 0 ? g_col_w : default_w;
                ImGui::Dummy(ImVec2(0, 4));
                ImGui::SetCursorPosX(g_col_x);
                ImGui::PushStyleColor(ImGuiCol_Text, C_AMBER);
                ImGui::Text("%s", label);
                ImGui::PopStyleColor();
                ImDrawList* dl2 = ImGui::GetWindowDrawList();
                ImVec2 p = ImGui::GetCursorScreenPos();
                dl2->AddLine(ImVec2(p.x + g_col_x, p.y + 2),
                             ImVec2(p.x + g_col_x + row_w, p.y + 2),
                             IM_COL32(255, 255, 255, 30), 1.0f);
                ImGui::Dummy(ImVec2(0, 6));
            };

            // Compact slider row — title on left, slider on right, no description.
            auto slider_row = [&](const char* name, float* val, float lo, float hi,
                                  const char* fmt)
            {
                const float row_h = 42.0f;
                const float row_w = g_col_w > 0 ? g_col_w : (kWinW - kSidebarW - 48);
                ImGui::SetCursorPosX(g_col_x);
                ImGui::PushStyleColor(ImGuiCol_ChildBg, C_ROW);
                ImGui::BeginChild(name, ImVec2(row_w, row_h), true,
                                  ImGuiWindowFlags_NoScrollbar);
                float title_h = ImGui::GetFontSize();
                float ty = (row_h - title_h) * 0.5f;
                ImGui::SetCursorPos(ImVec2(18, ty));
                ImGui::PushStyleColor(ImGuiCol_Text, C_TEXT);
                ImGui::Text("%s", name);
                ImGui::PopStyleColor();

                ImGui::SetCursorPos(ImVec2(row_w - 120, (row_h - 20) * 0.5f));
                ImGui::PushItemWidth(108);
                char sid[64]; snprintf(sid, sizeof(sid), "##sr_%s", name);
                ImGui::SliderFloat(sid, val, lo, hi, fmt);
                ImGui::PopItemWidth();

                ImGui::EndChild();
                ImGui::PopStyleColor();
            };

            // Distance-slider helper — accepts a translation key for its
            // label so each slider states exactly what it caps. `hi` is the
            // upper slider bound (meters). Value 0 renders as "Unlimited".
            auto dist_slider_max = [&](const char* id, const char* lbl_key,
                                       int* val, int hi) {
                const float row_h = 42.0f;
                const float row_w = g_col_w > 0 ? g_col_w : (kWinW - kSidebarW - 48);
                ImGui::SetCursorPosX(g_col_x);
                ImGui::PushStyleColor(ImGuiCol_ChildBg, C_ROW);
                ImGui::BeginChild(id, ImVec2(row_w, row_h), true,
                                  ImGuiWindowFlags_NoScrollbar);
                float title_h = ImGui::GetFontSize();
                float ty = (row_h - title_h) * 0.5f;
                ImGui::SetCursorPos(ImVec2(18, ty));
                ImGui::PushStyleColor(ImGuiCol_Text, C_TEXT);
                ImGui::Text("%s", tr(lbl_key));
                ImGui::PopStyleColor();

                ImGui::SetCursorPos(ImVec2(row_w - 120, (row_h - 20) * 0.5f));
                ImGui::PushItemWidth(108);
                char pl[24];
                if (*val == 0) snprintf(pl, sizeof(pl), "%s", tr("slider.unlim"));
                else           snprintf(pl, sizeof(pl), "%d m", *val);
                ImGui::SliderInt((std::string("##ds_") + id).c_str(),
                                 val, 0, hi, pl);
                ImGui::PopItemWidth();
                ImGui::EndChild();
                ImGui::PopStyleColor();
            };
            auto dist_slider_label = [&](const char* id, const char* lbl_key, int* val) {
                dist_slider_max(id, lbl_key, val, 1000);
            };
            // Backwards-compat wrappers used by tabs below.
            auto dist_slider = [&](const char* id, int* val) {
                dist_slider_label(id, "row.dist", val);
            };
            auto box_dist_slider = [&](const char* id, int* val) {
                dist_slider_label(id, "slider.box.dist", val);
            };
            (void)dist_slider; (void)box_dist_slider;

            if (s_tab == 0) {   // Players — two-column layout
                const float tab_w   = kWinW - kSidebarW - 48;
                const float col_gap = 16.0f;
                const float col_w   = (tab_w - col_gap) * 0.5f;
                float y_start = ImGui::GetCursorPosY();

                // ---- LEFT column: Main info ----
                g_col_x = 24.0f;
                g_col_w = col_w;
                section_header(tr("sec.main"));
                row(tr("row.enable"),     "", &g_ui.show_players, NULL);
                float y_end_left = ImGui::GetCursorPosY();
                float y_end_right = y_end_left;
                if (g_ui.show_players) {
                    dist_slider_label("dist_p", "slider.players.render", &g_ui.max_dist_players);
                    box_mode_row(tr("row.box"), &g_ui.box_mode_players, &g_ui.col_player_box);
                    if (g_ui.box_mode_players != 0)
                        dist_slider_label("bd_p",  "slider.player.box",     &g_ui.box_dist_players);
                    row(tr("row.dist.player"), "", &g_ui.show_player_dist,   &g_ui.col_player_dist);
                    y_end_left = ImGui::GetCursorPosY();

                    // ---- RIGHT column: Extra info ----
                    ImGui::SetCursorPosY(y_start);
                    g_col_x = 24.0f + col_w + col_gap;
                    g_col_w = col_w;
                    section_header(tr("sec.extra"));
                    row(tr("row.name"),       "", &g_ui.show_player_names,  &g_ui.col_player_name);
                    row(tr("row.hp"),         "", &g_ui.show_player_hp,     &g_ui.col_player_hp);
                    row(tr("row.mates"),      "", &g_ui.show_player_mates, &g_ui.col_teammate_box);
                    row(tr("row.armor.tier"), "", &g_ui.show_player_armor_tier, &g_ui.col_player_armor_tier);
                    row(tr("row.armor.dura"), "", &g_ui.show_player_armor_dura, &g_ui.col_player_armor_dura);
                    row(tr("row.team"),       "", &g_ui.show_player_team,   &g_ui.col_player_team);
                    row(tr("row.corpses"),    "", &g_ui.show_player_corpses,&g_ui.col_player_corpse);
                    if (g_ui.show_player_corpses)
                        dist_slider_label("cdist_p", "slider.player.corpse",  &g_ui.corpse_dist_players);
                    y_end_right = ImGui::GetCursorPosY();
                }

                // Restore single-column defaults for other tabs.
                g_col_x = 24.0f;
                g_col_w = 0.0f;
                ImGui::SetCursorPosY(y_end_left > y_end_right ? y_end_left : y_end_right);
            }
            else if (s_tab == 1) {   // Bots — two-column layout
                const float tab_w   = kWinW - kSidebarW - 48;
                const float col_gap = 16.0f;
                const float col_w   = (tab_w - col_gap) * 0.5f;
                float y_start = ImGui::GetCursorPosY();

                // ---- LEFT column: Main info ----
                g_col_x = 24.0f;
                g_col_w = col_w;
                section_header(tr("sec.main"));
                row(tr("row.enable"),     "", &g_ui.show_bots, NULL);
                float y_end_left = ImGui::GetCursorPosY();
                float y_end_right = y_end_left;
                if (g_ui.show_bots) {
                    dist_slider_max("dist_b", "slider.bots.render",    &g_ui.max_dist_bots, 200);
                    box_mode_row(tr("row.box"), &g_ui.box_mode_bots, &g_ui.col_bot_box);
                    if (g_ui.box_mode_bots != 0)
                        dist_slider_max("bd_b",  "slider.bot.box",     &g_ui.box_dist_bots, 200);
                    row(tr("row.dist.bot"),   "", &g_ui.show_bot_dist,   &g_ui.col_bot_dist);
                    y_end_left = ImGui::GetCursorPosY();

                    // ---- RIGHT column: Extra info ----
                    ImGui::SetCursorPosY(y_start);
                    g_col_x = 24.0f + col_w + col_gap;
                    g_col_w = col_w;
                    section_header(tr("sec.extra"));
                    row(tr("row.name"),       "", &g_ui.show_bot_names,  &g_ui.col_bot_name);
                    row(tr("row.hp"),         "", &g_ui.show_bot_hp,     &g_ui.col_bot_hp);
                    row(tr("row.armor.tier"), "", &g_ui.show_bot_armor_tier, &g_ui.col_bot_armor_tier);
                    row(tr("row.armor.dura"), "", &g_ui.show_bot_armor_dura, &g_ui.col_bot_armor_dura);
                    row(tr("row.corpses"),    "", &g_ui.show_bot_corpses,&g_ui.col_bot_corpse);
                    if (g_ui.show_bot_corpses)
                        dist_slider_max("cdist_b", "slider.bot.corpse", &g_ui.corpse_dist_bots, 200);
                    y_end_right = ImGui::GetCursorPosY();
                }
                g_col_x = 24.0f;
                g_col_w = 0.0f;
                ImGui::SetCursorPosY(y_end_left > y_end_right ? y_end_left : y_end_right);
            }
            else if (s_tab == 2) {   // Radar
                row(tr("rad.show"),      tr("rad.show.hint"),
                    &g_ui.show_radar, NULL);
                row(tr("rad.players"),   tr("rad.players.hint"),
                    &g_ui.radar_show_players, &g_ui.col_radar_player);
                row(tr("rad.bots"),      tr("rad.bots.hint"),
                    &g_ui.radar_show_bots, &g_ui.col_radar_bot);
                row(tr("rad.mates"),     tr("rad.mates.hint"),
                    &g_ui.radar_show_teammates, &g_ui.col_radar_teammate);
                row(tr("rad.corp.pl"),   tr("rad.corp.pl.hint"),
                    &g_ui.radar_show_corpses_players, &g_ui.col_radar_corpse_player);
                row(tr("rad.corp.bot"),  tr("rad.corp.bot.hint"),
                    &g_ui.radar_show_corpses_bots, &g_ui.col_radar_corpse_bot);
                // Range + Radius — each on its own full-width row, matching
                // the visual style of dist_slider_label rows.
                auto radar_int_row = [&](const char* id, const char* lbl,
                                         int* val, int lo, int hi,
                                         const char* unit) {
                    const float row_h = 42.0f;
                    const float row_w = g_col_w > 0 ? g_col_w : (kWinW - kSidebarW - 48);
                    ImGui::SetCursorPosX(g_col_x);
                    ImGui::PushStyleColor(ImGuiCol_ChildBg, C_ROW);
                    ImGui::BeginChild(id, ImVec2(row_w, row_h), true,
                                      ImGuiWindowFlags_NoScrollbar);
                    float title_h = ImGui::GetFontSize();
                    float ty = (row_h - title_h) * 0.5f;
                    ImGui::SetCursorPos(ImVec2(18, ty));
                    ImGui::PushStyleColor(ImGuiCol_Text, C_TEXT);
                    ImGui::Text("%s", lbl);
                    ImGui::PopStyleColor();
                    // Full-width slider: right of label + 12px gap to right margin.
                    float lbl_w   = ImGui::CalcTextSize(lbl).x;
                    float start_x = 18.0f + lbl_w + 16.0f;
                    float sw_     = row_w - start_x - 16.0f;
                    if (sw_ < 100) sw_ = 100;
                    ImGui::SetCursorPos(ImVec2(start_x, (row_h - 20) * 0.5f));
                    ImGui::PushItemWidth(sw_);
                    char pl[32]; snprintf(pl, sizeof(pl), "%d %s", *val, unit);
                    char sid[64]; snprintf(sid, sizeof(sid), "##sr_%s", id);
                    ImGui::SliderInt(sid, val, lo, hi, pl);
                    ImGui::PopItemWidth();
                    ImGui::EndChild();
                    ImGui::PopStyleColor();
                };
                radar_int_row("radar_range",  tr("rad.range"),
                              &g_ui.radar_range_m,   50, 500, "m");
                radar_int_row("radar_radius", tr("rad.radius"),
                              &g_ui.radar_px_radius, 60, 220, "px");
            }
#ifdef DH_DEBUG
            else if (s_tab == 3) {   // Loot — debug builds only
                row("Enable",     "Show loot dots",  &g_ui.show_loot, NULL);
                row("Show names", "Item name text",  &g_ui.loot_show_names, NULL);
                ImGui::SetCursorPosX(g_col_x);
                ImGui::PushItemWidth(108);
                char d_fmt[24];
                if (g_ui.loot_max_dist_m == 0) snprintf(d_fmt, sizeof(d_fmt), "unlimited");
                else                           snprintf(d_fmt, sizeof(d_fmt), "%d m", g_ui.loot_max_dist_m);
                ImGui::SliderInt("Max range##loot_maxd",
                                 &g_ui.loot_max_dist_m, 0, 500, d_fmt);
                ImGui::PopItemWidth();
                ImGui::SetCursorPosX(g_col_x);
                ImGui::PushItemWidth(108);
                char v_fmt[24];
                if (g_ui.loot_min_value == 0) snprintf(v_fmt, sizeof(v_fmt), "all");
                else                          snprintf(v_fmt, sizeof(v_fmt), "$%d", g_ui.loot_min_value);
                ImGui::SliderInt("Min value##loot_minv",
                                 &g_ui.loot_min_value, 0, 100000, v_fmt);
                ImGui::PopItemWidth();
            }
#endif
#ifdef DH_DEBUG
            else if (s_tab == 4) {   // Overlay — debug only
                row(tr("ov.hud"), tr("ov.hud.hint"), &g_ui.show_hud, NULL);
            }
            else if (s_tab == 5) {   // Language — debug index
#else
            else if (s_tab == 3) {   // Language — release index (after tabs collapse)
                // Radio-row: three languages, applies on click, saved
                // to g_ui.lang. tr() reads it live so UI relabels instantly.
                struct L { int id; const char* key; };
                const L langs[] = {
                    { 0, "lang.en" },
                    { 1, "lang.ru" },
                    { 2, "lang.cn" },
                };
                for (int i = 0; i < 3; i++) {
                    ImGui::SetCursorPosX(g_col_x);
                    bool sel = (g_ui.lang == langs[i].id);
                    if (ImGui::RadioButton(tr(langs[i].key), sel)) {
                        g_ui.lang = langs[i].id;
                    }
                }
            }
#endif  // DH_DEBUG language-index switch

            ImGui::EndChild();
        }
        ImGui::End();

        ImGui::PopStyleVar(8);
        ImGui::PopStyleColor(20);   // matches 20 PushStyleColor calls above
    }

    // Auto-hide overlay when Delta is minimized. Polled once per frame here
    // (cheap: 2 HWND lookups + IsIconic call = <10µs). Restore visibility
    // when the game window comes back.
    {
        static bool s_shown = true;
        HWND game = FindWindowW(NULL, L"Delta Force");
        if (!game) game = FindWindowW(L"UnrealWindow", NULL);
        bool should_show = game && IsWindow(game) && !IsIconic(game);
        if (should_show != s_shown) {
            ShowWindow(g_ui.hwnd, should_show ? SW_SHOWNA : SW_HIDE);
            s_shown = should_show;
        }
    }

    ImGui::Render();
    float black[4] = { 0, 0, 0, 0 };
    g_ui.ctx->OMSetRenderTargets(1, &g_ui.rtv, NULL);
    g_ui.ctx->ClearRenderTargetView(g_ui.rtv, black);
    ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
    g_ui.swap->Present(0, 0);   // uncap V-sync — allow tear, minimum latency
}

// -----------------------------------------------------------------------------
// Entry (called from main.c "overlay" command)
// -----------------------------------------------------------------------------

extern "C" int OverlayRunImGui(void)
{
    // Install top-level SEH filter so any uncaught access violation still
    // writes crash details to the persistent log before Windows kills us.
    SetUnhandledExceptionFilter(dh_unhandled_ex_filter);

    InitializeCriticalSection(&g_ui.lock);
    // Ship-hygiene: EVERY visual feature starts OFF. Fresh install =
    // silent overlay. User opts in per feature via settings panel.
    g_ui.show_players      = false;
    g_ui.show_player_mates = false;
    g_ui.show_player_names = false;
    g_ui.show_player_dist  = false;
    g_ui.show_player_team  = false;
    g_ui.show_player_hp    = false;
    g_ui.show_player_corpses = false;
    g_ui.box_mode_players  = 0;   // 0=off, 1=2D, 2=3D
    g_ui.show_bots         = false;
    g_ui.show_bot_names    = false;
    g_ui.show_bot_dist     = false;
    g_ui.show_bot_hp       = false;
    g_ui.show_bot_corpses  = false;
    g_ui.box_mode_bots     = 0;
    g_ui.show_hud          = false;
    g_ui.show_player_armor_tier = false;
    g_ui.show_player_armor_dura = false;
    g_ui.show_bot_armor_tier    = false;
    g_ui.show_bot_armor_dura    = false;
    g_ui.box_thickness    = 1.4f;
    g_ui.box_corner_frac  = 0.18f;
    g_ui.max_dist_players = 0;
    g_ui.max_dist_bots    = 0;
    g_ui.box_dist_players = 0;
    g_ui.box_dist_bots    = 0;
    g_ui.corpse_dist_players = 0;    // 0 = unlimited by default; slider tunes
    g_ui.corpse_dist_bots    = 0;
    g_ui.text_size        = 13;

    // Default colors: players red, bots white
    g_ui.col_player_box  = ImVec4(1.00f, 0.24f, 0.24f, 1.0f);
    g_ui.col_player_name = ImVec4(1.00f, 0.24f, 0.24f, 1.0f);
    g_ui.col_player_dist = ImVec4(1.00f, 0.24f, 0.24f, 1.0f);
    g_ui.col_player_team = ImVec4(1.00f, 0.24f, 0.24f, 1.0f);   // red like name/dist
    g_ui.col_player_hp   = ImVec4(1.00f, 0.85f, 0.24f, 1.0f);   // amber for HP
    g_ui.col_player_armor_tier = ImVec4(0.55f, 0.85f, 1.00f, 1.0f); // light cyan tier
    g_ui.col_player_armor_dura = ImVec4(0.70f, 0.70f, 0.70f, 1.0f); // grey durability
    g_ui.col_player_corpse = ImVec4(0.00f, 0.00f, 0.00f, 1.0f); // pure black
    g_ui.col_teammate_box= ImVec4(0.30f, 0.65f, 1.00f, 1.0f);   // blue box for mates
    g_ui.col_bot_box     = ImVec4(1.00f, 1.00f, 1.00f, 1.0f);
    g_ui.col_bot_name    = ImVec4(1.00f, 1.00f, 1.00f, 1.0f);
    g_ui.col_bot_dist    = ImVec4(1.00f, 1.00f, 1.00f, 1.0f);
    g_ui.col_bot_hp      = ImVec4(1.00f, 0.85f, 0.24f, 1.0f);   // amber for HP
    g_ui.col_bot_armor_tier = ImVec4(0.55f, 0.85f, 1.00f, 1.0f); // same defaults but independently editable
    g_ui.col_bot_armor_dura = ImVec4(0.70f, 0.70f, 0.70f, 1.0f);
    g_ui.col_bot_corpse  = ImVec4(0.00f, 0.00f, 0.00f, 1.0f);   // pure black
    // Radar defaults — all OFF for ship. User enables in settings.
    g_ui.show_radar          = false;
    g_ui.radar_range_m       = 150;
    g_ui.radar_px_radius     = 120;
    g_ui.radar_x             = INT_MIN;   // first frame snaps to top-right
    g_ui.radar_y             = INT_MIN;
    g_ui.radar_dragging      = false;
    g_ui.radar_rings         = false;
    g_ui.radar_range_label   = false;
    g_ui.radar_show_players  = false;
    g_ui.radar_show_bots     = false;
    g_ui.radar_show_teammates      = false;
    g_ui.radar_show_corpses_players= false;
    g_ui.radar_show_corpses_bots   = false;
    g_ui.col_radar_disc      = ImVec4(0.00f, 0.00f, 0.00f, 0.50f);
    g_ui.col_radar_ring      = ImVec4(0.86f, 0.90f, 0.92f, 0.45f);
    g_ui.col_radar_range     = ImVec4(0.78f, 0.82f, 0.86f, 0.90f);
    g_ui.col_radar_self      = ImVec4(1.00f, 1.00f, 1.00f, 1.00f);
    g_ui.col_radar_player    = ImVec4(1.00f, 0.24f, 0.24f, 1.00f);  // red, matches box
    g_ui.col_radar_bot       = ImVec4(1.00f, 1.00f, 1.00f, 1.00f);  // white, matches box
    g_ui.col_radar_teammate     = ImVec4(0.30f, 0.65f, 1.00f, 1.00f);  // blue
    g_ui.col_radar_corpse_player= ImVec4(0.55f, 0.30f, 0.30f, 0.90f);  // muted red
    g_ui.col_radar_corpse_bot   = ImVec4(0.55f, 0.55f, 0.55f, 0.85f);  // muted grey
    // Loot defaults — rarity ramp identical to ABIFinal render_loot()
    g_ui.show_loot          = false;   // loot pipeline ripped 2026-09-22
    g_ui.loot_show_common   = false;   // grey hidden by default (noise)
    g_ui.loot_show_uncommon = true;
    g_ui.loot_show_rare     = true;
    g_ui.loot_show_epic     = true;
    g_ui.loot_show_legendary= true;
    g_ui.loot_show_mythic   = true;
    g_ui.loot_show_corpses  = true;
    g_ui.loot_show_names    = true;
    g_ui.loot_max_dist_m    = 200;
    g_ui.loot_min_value     = 0;      // 0 = show all (until item catalog wired)
    g_ui.col_loot_common    = ImVec4(0.86f, 0.86f, 0.86f, 1.00f);   // grey
    g_ui.col_loot_uncommon  = ImVec4(0.39f, 0.86f, 0.39f, 1.00f);   // green
    g_ui.col_loot_rare      = ImVec4(0.39f, 0.51f, 1.00f, 1.00f);   // blue
    g_ui.col_loot_epic      = ImVec4(0.78f, 0.39f, 1.00f, 1.00f);   // purple
    g_ui.col_loot_legendary = ImVec4(1.00f, 0.68f, 0.24f, 1.00f);   // gold
    g_ui.col_loot_mythic    = ImVec4(1.00f, 0.35f, 0.35f, 1.00f);   // red
    g_ui.col_loot_corpse    = ImVec4(0.15f, 0.15f, 0.15f, 0.90f);   // near-black
    g_ui.panel_open     = false;
    g_ui.input_capture  = false;
    g_ui.lang           = 0;   // EN default (0=EN, 1=RU, 2=CN)

    // Multi-monitor: prefer the monitor the game is on, fall back to primary.
    // Supports 4:3 / 16:9 / 21:9 / vertical / mixed setups because we always
    // grab the ACTUAL rect of that display and size the overlay to match.
    HWND game = FindWindowW(NULL, L"Delta Force");
    if (!game) game = FindWindowW(L"UnrealWindow", NULL);
    HMONITOR mon = game ? MonitorFromWindow(game, MONITOR_DEFAULTTOPRIMARY)
                        : MonitorFromPoint({0,0}, MONITOR_DEFAULTTOPRIMARY);
    MONITORINFO mi = { sizeof(mi) };
    GetMonitorInfoW(mon, &mi);
    int mx = mi.rcMonitor.left;
    int my = mi.rcMonitor.top;
    g_ui.sw = mi.rcMonitor.right  - mi.rcMonitor.left;
    g_ui.sh = mi.rcMonitor.bottom - mi.rcMonitor.top;
    float aspect = (float)g_ui.sw / (float)g_ui.sh;
    const char* ar_name =
        aspect < 1.45f ? "4:3" :
        aspect < 1.90f ? "16:9 / 16:10" :
        aspect < 2.20f ? "2:1 (Steam Deck)" : "21:9 / ultrawide";
    DH_INFO("monitor: %dx%d @ (%d,%d)  aspect=%.3f (%s)",
            g_ui.sw, g_ui.sh, mx, my, aspect, ar_name);
    // UI scale — 1.0 @1080p, 1.33 @1440p, 2.0 @4K. Applied to panel size,
    // font, and ESP line thickness. Clamped so extreme resolutions don't
    // scale bogus vertical monitors.
    g_ui.ui_scale = (float)g_ui.sh / 1080.0f;
    if (g_ui.ui_scale < 0.75f) g_ui.ui_scale = 0.75f;
    if (g_ui.ui_scale > 3.0f)  g_ui.ui_scale = 3.0f;
    DH_INFO("ui_scale = %.3f (1080p ref)", g_ui.ui_scale);

    WNDCLASSEXW wc = { sizeof(wc) };
    wc.lpfnWndProc   = dh_wndproc;
    wc.hInstance     = GetModuleHandleW(NULL);
    wc.lpszClassName = L"DHOverlayImGuiClass";
    RegisterClassExW(&wc);

    g_ui.hwnd = CreateWindowExW(
        WS_EX_TOPMOST | WS_EX_LAYERED | WS_EX_TRANSPARENT
        | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE | WS_EX_NOREDIRECTIONBITMAP,
        wc.lpszClassName, L"DHOverlay",
        WS_POPUP, mx, my, g_ui.sw, g_ui.sh,
        NULL, NULL, wc.hInstance, NULL);
    if (!g_ui.hwnd) { DH_ERROR("CreateWindowEx err=%lu", GetLastError()); return 1; }
    SetLayeredWindowAttributes(g_ui.hwnd, 0, 255, LWA_ALPHA);
    ShowWindow(g_ui.hwnd, SW_SHOWNOACTIVATE);
    SetWindowPos(g_ui.hwnd, HWND_TOPMOST, 0, 0, 0, 0,
                 SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
    // Screen-capture protection ON — overlay invisible in OBS/ShadowPlay/
    // AMD ReLive/Discord screenshare captures. Blocks the #1 external-cheat
    // ban vector: user shares highlight → overlay visible in replay → AC
    // gets report → HWID+account ban.
    SetWindowDisplayAffinity(g_ui.hwnd, WDA_EXCLUDEFROMCAPTURE);

    if (!init_d3d()) { DestroyWindow(g_ui.hwnd); return 1; }

    // shmem
    g_ui.hMap = OpenFileMappingW(FILE_MAP_READ, FALSE, DH_SHMEM_NAME);
    if (!g_ui.hMap) {
        DH_ERROR("shmem not found — start daemon first (gle=%lu)",
                 GetLastError());
        return 2;
    }
    g_ui.shmem = (DH_SHMEM*)MapViewOfFile(g_ui.hMap, FILE_MAP_READ, 0, 0,
                                          sizeof(DH_SHMEM));
    if (!g_ui.shmem) { DH_ERROR("MapViewOfFile"); return 3; }
    DH_INFO("shmem opened @ %p", g_ui.shmem);

    // ImGui
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.IniFilename = NULL;
    io.LogFilename = NULL;
    // Start with panel closed = click-through = NoMouse until Home pressed
    io.ConfigFlags |= ImGuiConfigFlags_NoMouse;
    io.ConfigFlags |= ImGuiConfigFlags_NoMouseCursorChange;

    // Custom fonts — Segoe UI for Latin+Cyrillic, merged with Microsoft YaHei
    // for Simplified Chinese CJK glyphs. Single atlas — one primary font,
    // CJK glyphs pulled from the merged secondary. ImGui falls back to
    // Proggy Clean if all system fonts missing.
    ImFontConfig fcfg;
    fcfg.OversampleH = 2;
    fcfg.OversampleV = 2;
    fcfg.PixelSnapH  = true;
    const char* font_candidates[] = {
        "C:\\Windows\\Fonts\\SegoeUIVariable.ttf",
        "C:\\Windows\\Fonts\\segoeui.ttf",
        "C:\\Windows\\Fonts\\tahoma.ttf",
    };
    // Chinese fallback fonts — first available wins.
    const char* cjk_candidates[] = {
        "C:\\Windows\\Fonts\\msyh.ttc",     // Microsoft YaHei UI (SC + TC + Latin)
        "C:\\Windows\\Fonts\\msyh.ttf",
        "C:\\Windows\\Fonts\\simsun.ttc",   // SimSun fallback
        "C:\\Windows\\Fonts\\simhei.ttf",   // SimHei fallback
    };
    auto find_first_font = [](const char* const* list, int n) -> const char* {
        for (int i = 0; i < n; i++) {
            DWORD a = GetFileAttributesA(list[i]);
            if (a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY))
                return list[i];
        }
        return NULL;
    };
    const char* base_font = find_first_font(font_candidates, IM_ARRAYSIZE(font_candidates));
    const char* cjk_font  = find_first_font(cjk_candidates,  IM_ARRAYSIZE(cjk_candidates));

    auto add_size = [&](float sz) -> ImFont* {
        ImFont* f = io.Fonts->AddFontFromFileTTF(base_font, sz, &fcfg,
                                                 io.Fonts->GetGlyphRangesCyrillic());
        if (cjk_font) {
            // Merge Simplified Chinese glyphs into the same font at same size.
            ImFontConfig mcfg = fcfg;
            mcfg.MergeMode = true;
            io.Fonts->AddFontFromFileTTF(cjk_font, sz, &mcfg,
                io.Fonts->GetGlyphRangesChineseSimplifiedCommon());
        }
        return f;
    };
    ImFont* base = NULL;
    if (base_font) {
        base           = add_size(15.0f);
        g_ui.font_big  = add_size(22.0f);
        g_ui.font_mid  = add_size(17.0f);
        DH_INFO("font loaded: %s (CJK=%s)", base_font, cjk_font ? cjk_font : "none");
    }
    if (!base) io.Fonts->AddFontDefault();

    ImGui::StyleColorsDark();
    // Global UI scale — panel widgets + font. Applied ONCE after style
    // reset. Overlay ESP text uses ImGui font so this scales that too.
    ImGui::GetStyle().ScaleAllSizes(g_ui.ui_scale);
    io.FontGlobalScale = g_ui.ui_scale;
    ImGui_ImplWin32_Init(g_ui.hwnd);
    ImGui_ImplDX11_Init(g_ui.d3d, g_ui.ctx);

    // Decode embedded Nightvex logo PNG and upload to D3D11 texture
    {
        int lw = 0, lh = 0, lch = 0;
        unsigned char* pixels = stbi_load_from_memory(
            g_nightvex_logo_png, (int)g_nightvex_logo_png_len,
            &lw, &lh, &lch, 4);
        if (pixels) {
            D3D11_TEXTURE2D_DESC td = {};
            td.Width  = lw; td.Height = lh;
            td.MipLevels = 1; td.ArraySize = 1;
            td.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
            td.SampleDesc.Count = 1;
            td.Usage = D3D11_USAGE_DEFAULT;
            td.BindFlags = D3D11_BIND_SHADER_RESOURCE;
            D3D11_SUBRESOURCE_DATA sd = {};
            sd.pSysMem = pixels;
            sd.SysMemPitch = lw * 4;
            ID3D11Texture2D* tex = NULL;
            g_ui.d3d->CreateTexture2D(&td, &sd, &tex);
            if (tex) {
                g_ui.d3d->CreateShaderResourceView(tex, NULL, &g_ui.logo_srv);
                tex->Release();
            }
            stbi_image_free(pixels);
            DH_INFO("logo texture: %dx%d srv=%p", lw, lh, g_ui.logo_srv);
        } else {
            DH_WARN("logo PNG decode failed");
        }
    }

    // Poll thread
    g_ui.running = 1;
    g_ui.poll_th = CreateThread(NULL, 0, poll_thread, NULL, 0, NULL);

    DH_INFO("overlay-imgui running: %dx%d â€” HWND=%p", g_ui.sw, g_ui.sh, g_ui.hwnd);
    timeBeginPeriod(1);

    // Watch the daemon's stop event — set by daemon-esp when Delta closes,
    // signals overlay to shut down cleanly (auto-close after game exit).
    HANDLE stop_ev = CreateEventW(NULL, TRUE, FALSE, L"Global\\{7A9F3B22-4E2D-4B12-A5F7-8D6E4C9F1B3A}");

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
        // Stop signaled by daemon on Delta exit → shut down.
        if (stop_ev && WaitForSingleObject(stop_ev, 0) == WAIT_OBJECT_0) {
            DH_INFO("stop event signaled by daemon — overlay exiting");
            goto done;
        }
        QueryPerformanceCounter(&now);
        double dt = (double)(now.QuadPart - last.QuadPart) / (double)freq.QuadPart;
        if (dt >= 1.0 / 240.0) {
            last = now;
            render_frame();
        } else {
            Sleep(1);
        }
    }
done:
    if (stop_ev) CloseHandle(stop_ev);
    timeEndPeriod(1);
    InterlockedExchange(&g_ui.running, 0);
    if (g_ui.poll_th) { WaitForSingleObject(g_ui.poll_th, 500); CloseHandle(g_ui.poll_th); }

    if (g_ui.logo_srv) g_ui.logo_srv->Release();
    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    if (g_ui.rtv) g_ui.rtv->Release();
    if (g_ui.swap) g_ui.swap->Release();
    if (g_ui.dcompV) g_ui.dcompV->Release();
    if (g_ui.dcompT) g_ui.dcompT->Release();
    if (g_ui.dcomp) g_ui.dcomp->Release();
    if (g_ui.ctx) g_ui.ctx->Release();
    if (g_ui.d3d) g_ui.d3d->Release();
    if (g_ui.shmem) UnmapViewOfFile(g_ui.shmem);
    if (g_ui.hMap) CloseHandle(g_ui.hMap);
    DestroyWindow(g_ui.hwnd);
    DeleteCriticalSection(&g_ui.lock);
    return 0;
}

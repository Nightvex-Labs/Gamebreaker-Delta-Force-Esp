// dh_ui_state.hpp — расшаренная UI-стейт DeltaHack.
//
// Раньше struct DH_UI жила inline внутри dh_overlay_imgui.cpp — теперь вытащена
// сюда, чтобы новый Spectra-меню (dh_ui/menu_v3.cpp) мог читать/писать те же
// поля без дубликата. Оригинальный dh_overlay_imgui.cpp продолжает объявлять
// static DH_UI g_ui — теперь через #include этого header'а.

#pragma once

#include <windows.h>
#include <d3d11.h>
#include <dxgi1_3.h>
#include <dcomp.h>
#include <imgui.h>

extern "C" {
#include "dh_common.h"
#include "dh_shmem.h"
}

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
    bool  show_player_mates;
    bool  show_player_names;
    bool  show_player_dist;
    bool  show_player_team;
    bool  show_player_hp;
    bool  show_player_corpses;
    int   box_mode_players;     // 0=Off, 1=2D corner-bracket, 2=3D wireframe
    bool  show_bots;
    bool  show_bot_names;
    bool  show_bot_dist;
    bool  show_bot_hp;
    bool  show_bot_corpses;
    int   box_mode_bots;
    bool  show_hud;
    // Radar
    bool  show_radar;
    int   radar_range_m;
    int   radar_px_radius;
    int   radar_x, radar_y;
    bool  radar_dragging;
    float radar_drag_dx, radar_drag_dy;
    bool  radar_rings;
    bool  radar_range_label;
    bool  radar_show_players;
    bool  radar_show_bots;
    bool  radar_show_teammates;
    bool  radar_show_corpses_players;
    bool  radar_show_corpses_bots;
    // Loot
    bool  show_loot;
    bool  loot_show_common;
    bool  loot_show_uncommon;
    bool  loot_show_rare;
    bool  loot_show_epic;
    bool  loot_show_legendary;
    bool  loot_show_mythic;
    bool  loot_show_corpses;
    bool  loot_show_names;
    int   loot_max_dist_m;
    int   loot_min_value;
    bool  show_player_armor_tier;
    bool  show_player_armor_dura;
    bool  show_bot_armor_tier;
    bool  show_bot_armor_dura;

    // Settings
    float box_thickness;
    float ui_scale;
    float box_corner_frac;
    int   max_dist_players;
    int   max_dist_bots;
    int   box_dist_players;
    int   box_dist_bots;
    int   corpse_dist_players;
    int   corpse_dist_bots;
    int   text_size;

    // Colors
    ImVec4 col_player_box;
    ImVec4 col_player_name;
    ImVec4 col_player_dist;
    ImVec4 col_player_team;
    ImVec4 col_player_hp;
    ImVec4 col_player_armor_tier;
    ImVec4 col_player_armor_dura;
    ImVec4 col_teammate_box;
    ImVec4 col_player_corpse;
    ImVec4 col_bot_box;
    ImVec4 col_bot_name;
    ImVec4 col_bot_dist;
    ImVec4 col_bot_hp;
    ImVec4 col_bot_armor_tier;
    ImVec4 col_bot_armor_dura;
    ImVec4 col_bot_corpse;
    // Radar palette
    ImVec4 col_radar_disc;
    ImVec4 col_radar_ring;
    ImVec4 col_radar_range;
    ImVec4 col_radar_self;
    ImVec4 col_radar_player;
    ImVec4 col_radar_bot;
    ImVec4 col_radar_teammate;
    ImVec4 col_radar_corpse_player;
    ImVec4 col_radar_corpse_bot;
    // Loot palette
    ImVec4 col_loot_common;
    ImVec4 col_loot_uncommon;
    ImVec4 col_loot_rare;
    ImVec4 col_loot_epic;
    ImVec4 col_loot_legendary;
    ImVec4 col_loot_mythic;
    ImVec4 col_loot_corpse;

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

extern DH_UI g_ui;

// menu_v3.cpp — GameBreaker · меню v3 (Dear ImGui + ImDrawList).
// 1:1 с макетом «Spectra v3 Dark»: окно 960×540, рейл иконок 64, настройки группами,
// превью 300 справа (только «Визуал»). Состояние — локальное, без RenderConfig.
// Все координаты — в px макета; перевод в экран — через S (menu_v3_set_scale).
#define IMGUI_DEFINE_MATH_OPERATORS
#include "menu_v3.hpp"
#include "icons.hpp"
#include "palette.hpp"
#include <imgui.h>
#include <imgui_internal.h>
#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstring>

#define U8(s) reinterpret_cast<const char*>(u8##s)

namespace {
namespace P = abi::pal;
namespace G = abi::pal::gb;
namespace V = abi::pal::gb3;

ImTextureID s_op_tex = 0; int s_op_w = 0, s_op_h = 0;
float s_dpi = 1.f;

// ── шрифты ────────────────────────────────────────────────────────────────
struct Font { ImFont* f = nullptr; float css = 14; };
struct Fonts { Font ub700_20, ub700_12, ub700_9, ub500_14, jb500_12; bool ok = false; } F;
Font find_font(const char* name, float css) {
    for (ImFont* f : ImGui::GetIO().Fonts->Fonts)
        if (f && std::strcmp(f->GetDebugName(), name) == 0) return {f, css};
    return {ImGui::GetFont(), css};
}
void load_fonts() {
    if (F.ok) return;
    F.ub700_20 = find_font("gb:ub700:20", 20); F.ub700_12 = find_font("gb:ub700:12", 12);
    F.ub700_9  = find_font("gb:ub700:9", 9);   F.ub500_14 = find_font("gb:ub500:14", 14);
    F.jb500_12 = find_font("gb:jb500:12", 12); F.ok = true;
}

// ── состояние ─────────────────────────────────────────────────────────────
// DeltaHack keys: no Weapon/Ammo (daemon path disabled 2026-09-22), armor is
// split into "tier" (H:x A:y) and "durability" (numbers) — two independent
// toggles per user spec.
enum K { K_enable, K_box, K_corners, K_name, K_team, K_hp, K_armor_tier, K_armor_dura, K_distance, K_corpses, K_teammates, K_N };
struct Item { bool on = true; bool has_c = false; ImU32 c = 0; int style = 0; int dist = 250; int min_val = 50; };
// DH radar has 6 dot classes + rings + range label + drag position.
// menu_v3's `corner` (0=TL,1=TR,2=BL,3=BR) drives radar_x/y in the bridge.
struct Radar { bool show = true, players = true, bots = true, mates = false, corpse_pl = false, corpse_bot = false;
               bool rings = true, label = true; int world = 200, screen = 120; int corner = 1; };
// DH loot — 6 rarity filters + names/corpses + range/min-value.
struct Loot { bool show = true; bool r[6] = {true,true,true,true,true,true};
              bool names = true, corpses = true; int max_dist = 0, min_val = 0; };
struct State {
    int sec = 0, vt = 0;          // sec: 0 визуал, 1 радар, 2 лут; vt: 0 игроки, 1 боты
    int open = -1;                // (vt*16 + key)*2 + (0 цвет | 1 настройки)
    bool ru = true;
    Item esp[2][K_N];
    Radar radar; Loot loot;
    bool  show_hud = false;       // Overlay tab: HUD chip
    float scroll = 0, scroll_t = 0, content_h = 0;
    ImGuiID drag = 0; float drag_off = 0;
    bool inited = false;
} S_;

void init_state() {
    if (S_.inited) return;
    for (int v = 0; v < 2; v++) {
        Item* e = S_.esp[v];
        auto col = [&](int k, ImU32 c) { e[k].has_c = true; e[k].c = c; };
        col(K_box, V::ESP_BOX); col(K_name, v ? V::NAME_BOT : V::NAME_PMC);
        col(K_team, V::TEAM); col(K_hp, V::HP);
        col(K_armor_tier, V::ARMOR_H); col(K_armor_dura, V::ARMOR_V);
        col(K_distance, V::ESP_DIST); col(K_corpses, V::ESP_CORPSE);
        e[K_corpses].on = false; e[K_teammates].on = false;
    }
    // Bots off by default. Armor/team/hp on bots also default off.
    S_.esp[1][K_enable].on      = false;
    S_.esp[1][K_armor_tier].on  = false;
    S_.esp[1][K_armor_dura].on  = false;
    S_.esp[1][K_hp].on          = false;
    S_.esp[1][K_team].on        = false;
    S_.sec = 0; S_.vt = 0;   // start on Visuals/Players
    S_.inited = true;
}

const char* label_of(int k) {
    static const char* ru[K_N] = {U8("Включить"), U8("Рамка"), U8("Уголки вместо рамки"), U8("Ник"),
                                  U8("Команда"), U8("Здоровье"), U8("Тир брони"), U8("Прочность брони"),
                                  U8("Дистанция"), U8("Трупы"), U8("Показывать тиммейтов")};
    static const char* en[K_N] = {"Enable", "Box", "Corner brackets", "Name", "Team", "Health",
                                  "Armor tier", "Armor durability", "Distance", "Corpses", "Show teammates"};
    return S_.ru ? ru[k] : en[k];
}
bool has_set(int k) { return k == K_box || k == K_corpses || k == K_enable; }

// ── кадр / хелперы рисования (координаты макета) ─────────────────────────
struct Frame { ImDrawList* dl; ImVec2 o; float s; bool live; ImVec4 clip; } g;
inline ImVec2 Pt(float x, float y) { return {std::floor(g.o.x + x * g.s + .5f), std::floor(g.o.y + y * g.s + .5f)}; }
inline ImVec2 mouse() { ImVec2 m = ImGui::GetIO().MousePos; return {(m.x - g.o.x) / g.s, (m.y - g.o.y) / g.s}; }
inline bool in_clip(ImVec2 m) { return m.x >= g.clip.x && m.y >= g.clip.y && m.x < g.clip.z && m.y < g.clip.w; }
inline bool hot(float x, float y, float w, float h) { ImVec2 m = mouse(); return g.live && in_clip(m) && m.x >= x && m.y >= y && m.x < x + w && m.y < y + h; }
inline bool click(float x, float y, float w, float h) { return hot(x, y, w, h) && ImGui::IsMouseClicked(0); }
inline ImU32 A(ImU32 c, float a) { return a >= 1.f ? c : P::alpha(c, ((c >> IM_COL32_A_SHIFT) & 0xFF) / 255.f * a); }
inline ImU32 mix(ImU32 a, ImU32 b, float t) {
    ImVec4 x = ImGui::ColorConvertU32ToFloat4(a), y = ImGui::ColorConvertU32ToFloat4(b);
    float k = ImClamp(t, 0.f, 1.f);
    // ImVec4 operator+/- aren't defined without IMGUI_DEFINE_MATH_OPERATORS
    // scoping into imgui_internal — spell the lerp component-wise.
    ImVec4 r(x.x + (y.x - x.x) * k, x.y + (y.y - x.y) * k,
             x.z + (y.z - x.z) * k, x.w + (y.w - x.w) * k);
    return ImGui::ColorConvertFloat4ToU32(r);
}
float anim(ImGuiID id, float target, float speed = 16.f) {
    static ImGuiStorage st;
    float* v = st.GetFloatRef(id, target);
    *v += (target - *v) * ImMin(1.f, ImGui::GetIO().DeltaTime * speed);
    if (std::fabs(*v - target) < .002f) *v = target;
    return *v;
}
ImGuiID hid(const char* s, int a = 0) { return ImHashStr(s) ^ (ImGuiID)(a * 2654435761u); }

void rect(float x, float y, float w, float h, ImU32 c, float r) { g.dl->AddRectFilled(Pt(x, y), Pt(x + w, y + h), c, r * g.s); }
void ring(float x, float y, float w, float h, ImU32 c, float r, float t = 1) {
    float i = t * .5f;
    g.dl->AddRect(Pt(x + i, y + i), Pt(x + w - i, y + h - i), c, r * g.s, 0, t * g.s);
}
void circle(float cx, float cy, float r, ImU32 c) { g.dl->AddCircleFilled(Pt(cx, cy), r * g.s, c, 32); }
void line(float ax, float ay, float bx, float by, ImU32 c, float t) { g.dl->AddLine(Pt(ax, ay), Pt(bx, by), c, t * g.s); }

float tw(const Font& f, float css, const char* s, float tr = 0) {
    float sz = f.f->FontSize * css / f.css;
    float w = f.f->CalcTextSizeA(sz, FLT_MAX, 0, s).x / g.s;
    if (tr != 0) { int n = 0; for (const char* p = s; *p; ++p) if ((*p & 0xC0) != 0x80) n++; w += tr * css * n; }
    return w;
}
// текст по вертикальному центру cy; tr — трекинг в em (для капса)
void text(const Font& f, float css, float x, float cy, ImU32 c, const char* s, float tr = 0) {
    float sz = f.f->FontSize * css / f.css;
    float y = std::floor(g.o.y + cy * g.s - sz * .5f + .5f);
    float px = g.o.x + x * g.s;
    if (tr == 0) { g.dl->AddText(f.f, sz, {std::floor(px + .5f), y}, c, s); return; }
    for (const char* p = s; *p;) {
        const char* q = p + 1; while (*q && (*q & 0xC0) == 0x80) q++;
        g.dl->AddText(f.f, sz, {std::floor(px + .5f), y}, c, p, q);
        px += f.f->CalcTextSizeA(sz, FLT_MAX, 0, p, q).x + tr * css * g.s;
        p = q;
    }
}
void text_c(const Font& f, float css, float cx, float cy, ImU32 c, const char* s, float tr = 0) { text(f, css, cx - tw(f, css, s, tr) * .5f, cy, c, s, tr); }
void text_r(const Font& f, float css, float rx, float cy, ImU32 c, const char* s, float tr = 0) { text(f, css, rx - tw(f, css, s, tr), cy, c, s, tr); }
// многоточие, если не влезает в maxw
void text_fit(const Font& f, float css, float x, float cy, float maxw, ImU32 c, const char* s) {
    if (tw(f, css, s) <= maxw) { text(f, css, x, cy, c, s); return; }
    char buf[128]; std::snprintf(buf, sizeof buf, "%s", s);
    int n = (int)std::strlen(buf);
    while (n > 0) {
        do n--; while (n > 0 && (buf[n] & 0xC0) == 0x80);
        std::snprintf(buf + n, sizeof buf - n, "%s", U8("…"));
        if (tw(f, css, buf) <= maxw) break;
    }
    text(f, css, x, cy, c, buf);
}
void icon(const char* name, float x, float y, float sz, ImU32 tint) {
    if (ImTextureID t = abi::icons::get(name)) g.dl->AddImage(t, Pt(x, y), Pt(x + sz, y + sz), {0, 0}, {1, 1}, tint);
}

// ── контролы ──────────────────────────────────────────────────────────────
// кольцо-индикатор 14px (обводка 4)
void dot(float cx, float cy, bool on, ImGuiID id) {
    float t = anim(id, on ? 1.f : 0.f, 18.f);
    g.dl->AddCircle(Pt(cx, cy), 5.f * g.s, mix(V::OFF_DOT, G::ACCENT, t), 24, 4.f * g.s);
}
// сегмент-переключатель; opts — подписи; icons — опц. имена иконок; возвращает новый индекс
int segmented(float x, float y, float w, float h, const char* const* opts, int n, int cur, bool fill, ImGuiID id) {
    rect(x, y, w, h, G::SEG_BG, 6);
    float iw = (w - 6 - 2 * (n - 1)) / n;
    int res = cur;
    for (int i = 0; i < n; i++) {
        float bx = x + 3 + i * (iw + 2);
        float t = anim(id + i, i == cur ? 1.f : 0.f, 18.f);
        if (t > 0) rect(bx, y + 3, iw, h - 6, A(G::ACCENT, t), 5);
        ImU32 tc = mix(G::TEXT_MUTED, G::ON_ACCENT, t);
        text_c(F.ub700_12, 11, bx + iw * .5f, y + h * .5f, tc, opts[i]);
        if (click(bx, y, iw, h)) res = i;
    }
    (void)fill;
    return res;
}
// ползунок: подпись + значение; возвращает true, если значение менялось
bool slider(float x, float y, float w, const char* label, int& v, int mn, int mx, int step, const char* fmt, ImGuiID id, bool big) {
    char val[48]; std::snprintf(val, sizeof val, fmt, v);
    const Font& lf = big ? F.ub500_14 : F.ub500_14;
    text(lf, big ? 12.5f : 12.f, x, y + 7, big ? G::TEXT : G::TEXT_MUTED, label);
    text_r(F.jb500_12, 12, x + w, y + 7, G::ACCENT, val);
    float ty = y + 14 + 9, th = 16;
    bool changed = false;
    if (click(x - 8, ty, w + 16, th)) S_.drag = id;
    if (S_.drag == id) {
        if (ImGui::IsMouseDown(0)) {
            float t = ImClamp((mouse().x - x) / w, 0.f, 1.f);
            int nv = (int)std::lround((mn + t * (mx - mn)) / step) * step;
            nv = ImClamp(nv, mn, mx);
            if (nv != v) { v = nv; changed = true; }
        } else S_.drag = 0;
    }
    float p = (float)(v - mn) / (mx - mn);
    rect(x, ty + 6, w, 4, G::TRACK, 2);
    rect(x, ty + 6, w * p, 4, G::ACCENT, 2);
    float kx = x + w * p;
    circle(kx, ty + 9, 8, G::KNOB_SHADOW);
    circle(kx, ty + 8, 8, G::KNOB);
    return changed;
}

// ── строки ────────────────────────────────────────────────────────────────
constexpr float ROW_H = 44, ROW_GAP = 5, BTN = 44, GROUP_GAP = 18, CAP_H = 18;

void group_title(float x, float y, const char* t) { text(F.ub700_9, 9, x + 4, y + 5, G::TEXT_FAINT, t, .12f); }

// кнопка 44×44 справа от строки (цвет / настройки)
bool side_btn(float x, float y, bool active, ImGuiID id) {
    bool h = hot(x, y, BTN, ROW_H);
    float t = anim(id, h || active ? 1.f : 0.f, 18.f);
    rect(x, y, BTN, ROW_H, mix(V::GLASS, V::GLASS_HOT, t), 7);
    ring(x, y, BTN, ROW_H, V::GLASS_LINE, 7);
    if (active) ring(x, y, BTN, ROW_H, A(G::ACCENT, .5f), 7);
    return click(x, y, BTN, ROW_H);
}

// ESP-строка + раскрытие (палитра / настройки). Возвращает высоту.
float esp_row(float x, float y, float w, int k) {
    State& s = S_; Item& it = s.esp[s.vt][k];
    const bool master = s.esp[s.vt][K_enable].on;
    const float dim = (k == K_enable || master) ? 1.f : .45f;
    const int idc = (s.vt * 16 + k) * 2, ids = idc + 1;
    const bool oc = s.open == idc, os = s.open == ids;
    float rw = w - (it.has_c ? BTN + ROW_GAP : 0) - (has_set(k) ? BTN + ROW_GAP : 0);

    ImGuiID rid = hid("row", s.vt * 100 + k);
    bool h = hot(x, y, rw, ROW_H);
    float ht = anim(rid, h ? 1.f : 0.f, 18.f);
    rect(x, y, rw, ROW_H, A(mix(V::GLASS, V::GLASS_HOT, ht), dim), 7);
    ring(x, y, rw, ROW_H, V::GLASS_LINE, 7);
    dot(x + 12 + 7, y + ROW_H * .5f, it.on, rid + 1);
    float tt = anim(rid + 2, it.on ? 1.f : 0.f, 18.f);
    text_fit(F.ub500_14, 12.5f, x + 12 + 14 + 11, y + ROW_H * .5f, rw - 12 - 14 - 11 - 12, A(mix(G::TEXT_FAINT, G::TEXT, tt), dim), label_of(k));
    if (click(x, y, rw, ROW_H)) it.on = !it.on;

    float bx = x + rw + ROW_GAP;
    if (it.has_c) {
        if (side_btn(bx, y, oc, rid + 3)) s.open = oc ? -1 : idc;
        {   // квадратный образец 16×16, r=4, обводка 1px
            float sx = bx + BTN * .5f - 8, sy = y + ROW_H * .5f - 8;
            rect(sx - 1, sy - 1, 18, 18, A(G::SWATCH_LINE, dim), 5);
            rect(sx, sy, 16, 16, A(it.c, (it.on ? 1.f : .35f) * dim), 4);
        }
        bx += BTN + ROW_GAP;
    }
    if (has_set(k)) {
        if (side_btn(bx, y, os, rid + 4)) s.open = os ? -1 : ids;
        icon("gear", bx + (BTN - 17) * .5f, y + (ROW_H - 17) * .5f, 17, A(os ? G::TEXT : G::TEXT_MUTED, dim));
    }
    float hgt = ROW_H;

    if (oc) {                                   // палитра 6×2
        float py = y + ROW_H + ROW_GAP, ph = 14 + 12 + 12 + 28 + 8 + 28 + 14;
        float a = anim(rid + 5, 1.f, 20.f);
        rect(x, py, w, ph, A(V::GLASS_HOT, a), 7);
        ring(x, py, w, ph, V::GLASS_LINE, 7);
        char cap[96]; std::snprintf(cap, sizeof cap, S_.ru ? U8("ЦВЕТ · %s") : "COLOR · %s", label_of(k));
        text(F.ub700_9, 9, x + 14, py + 14 + 6, A(G::TEXT_FAINT, a), cap, .12f);
        char hex[12]; std::snprintf(hex, sizeof hex, "#%02X%02X%02X", (it.c >> IM_COL32_R_SHIFT) & 255, (it.c >> IM_COL32_G_SHIFT) & 255, (it.c >> IM_COL32_B_SHIFT) & 255);
        float hw = tw(F.jb500_12, 11, hex);
        text(F.jb500_12, 11, x + w - 14 - hw, py + 20, A(G::TEXT, a), hex);
        rect(x + w - 14 - hw - 7 - 12, py + 14, 12, 12, A(it.c, a), 4);
        float gw = (w - 28 - 5 * 8) / 6;
        for (int i = 0; i < 12; i++) {
            float sx = x + 14 + (i % 6) * (gw + 8), sy = py + 14 + 12 + 12 + (i / 6) * (28 + 8);
            ImU32 c = V::SWATCH[i];
            if (c == it.c) { ring(sx - 4, sy - 4, gw + 8, 36, A(G::TEXT, a), 11, 2); }
            rect(sx, sy, gw, 28, A(c, a), 5);
            if (click(sx, sy, gw, 28)) it.c = c;
        }
        hgt += ROW_GAP + ph;
    }
    if (os) {                                   // стиль/отображение + ползунок
        float py = y + ROW_H + ROW_GAP, cy = py + 12;
        const bool seg = k == K_box;                                    // only Box has 2D/3D picker in DH
        const bool sl  = k == K_box || k == K_corpses || k == K_enable; // Box dist, Corpse dist, Render dist
        float ph = 12 + (seg ? 12 + 9 + 34 : 0) + (seg && sl ? 12 : 0) + (sl ? 14 + 9 + 16 : 0) + 14;
        rect(x, py, w, ph, V::GLASS_HOT, 7);
        ring(x, py, w, ph, V::GLASS_LINE, 7);
        if (seg) {
            text(F.ub500_14, 12, x + 14, cy + 6, G::TEXT_MUTED, S_.ru ? U8("Стиль") : "Style");
            static const char* box_o[2] = {"2D", "3D"};
            it.style = segmented(x + 14, cy + 12 + 9, w - 28, 34, box_o, 2, it.style, true, rid + 10);
            cy += 12 + 9 + 34 + 12;
        }
        if (k == K_box)     slider(x + 14, cy, w - 28, S_.ru ? U8("Дистанция бокса") : "Box distance", it.dist, 0, 1000, 10, "%d m", rid + 20, false);
        if (k == K_corpses) slider(x + 14, cy, w - 28, S_.ru ? U8("Дистанция трупов") : "Corpse distance", it.dist, 0, 1000, 10, "%d m", rid + 20, false);
        if (k == K_enable)  slider(x + 14, cy, w - 28, S_.ru ? U8("Дистанция рендера") : "Render distance", it.dist, 0, 1000, 10, "%d m", rid + 20, false);
        hgt += ROW_GAP + ph;
    }
    return hgt;
}

// простая строка-переключатель (радар / лут)
float toggle_row(float x, float y, float w, const char* label, const char* hint, bool& v, float dim, ImGuiID id) {
    bool h = hot(x, y, w, ROW_H);
    float ht = anim(id, h ? 1.f : 0.f, 18.f);
    rect(x, y, w, ROW_H, A(mix(V::GLASS, V::GLASS_HOT, ht), dim), 7);
    ring(x, y, w, ROW_H, V::GLASS_LINE, 7);
    dot(x + 19, y + ROW_H * .5f, v, id + 1);
    float tt = anim(id + 2, v ? 1.f : 0.f, 18.f);
    ImU32 tc = A(mix(G::TEXT_FAINT, G::TEXT, tt), dim);
    if (hint && *hint) {
        text_fit(F.ub500_14, 12.5f, x + 37, y + 16, w - 49, tc, label);
        text_fit(F.ub500_14, 10, x + 37, y + 31, w - 49, A(G::TEXT_FAINT, dim), hint);
    } else text_fit(F.ub500_14, 12.5f, x + 37, y + ROW_H * .5f, w - 49, tc, label);
    if (click(x, y, w, ROW_H)) v = !v;
    return ROW_H;
}
float slider_row(float x, float y, float w, const char* label, int& v, int mn, int mx, int step, const char* fmt, float dim, ImGuiID id) {
    const float h = 12 + 14 + 10 + 16 + 14;
    rect(x, y, w, h, A(V::GLASS, dim), 7);
    ring(x, y, w, h, V::GLASS_LINE, 7);
    slider(x + 14, y + 12, w - 28, label, v, mn, mx, step, fmt, id, true);
    return h;
}
float seg_row(float x, float y, float w, const char* label, const char* const* opts, int n, int& cur, float dim, ImGuiID id, float seg_w) {
    rect(x, y, w, ROW_H, A(V::GLASS, dim), 7);
    ring(x, y, w, ROW_H, V::GLASS_LINE, 7);
    text(F.ub500_14, 12.5f, x + 14, y + ROW_H * .5f, A(G::TEXT, dim), label);
    cur = segmented(x + w - 6 - seg_w, y + 6, seg_w, 32, opts, n, cur, false, id);
    return ROW_H;
}

// ── превью ESP ────────────────────────────────────────────────────────────
void draw_preview(float x, float y, float w, float h) {
    const State& s = S_; const Item* E = s.esp[s.vt]; const bool bots = s.vt == 1;
    auto on = [&](int k) { return E[K_enable].on && E[k].on; };
    rect(x, y, w, h, V::GLASS, 8);
    ring(x, y, w, h, V::GLASS_LINE, 8);
    text(F.ub500_14, 13, x + 18, y + 24, G::TEXT_MUTED, S_.ru ? U8("Превью") : "Preview");
    text_r(F.ub700_9, 9, x + w - 18, y + 24, G::TEXT_FAINT, bots ? "BOTS" : "PLAYERS", .12f);

    // DH: HP row visible for both players and bots when their HP toggle is on.
    // Armor "bar" side-strips only shown if BOTH tier and durability are on.
    const bool hp  = on(K_hp);
    const bool bar = on(K_armor_tier) && on(K_armor_dura);
    const float gh = 15 + 6 + (hp ? 11 + 6 : 0) + 330 + 6 + 16;
    const float cx = x + w * .5f, top = y + 48 + (h - 48 - gh) * .5f;
    const float op = E[K_enable].on ? 1.f : .35f;
    float cy = top;

    // ник + команда
    {
        const char* nick = bots ? "Scav" : "Nightreaper_07";
        const char* team = "Team 2";
        bool n = on(K_name), t = !bots && on(K_team);
        float nw = n ? tw(F.ub700_12, 12, nick) : 0, tw2 = t ? tw(F.ub700_12, 12, team) : 0, gp = n && t ? 7.f : 0;
        float nx = cx - (nw + gp + tw2) * .5f;
        if (n) { text(F.ub700_12, 12, nx + 1, cy + 8.5f, A(P::blk(.8f), op), nick); text(F.ub700_12, 12, nx, cy + 7.5f, A(E[K_name].c, op), nick); }
        if (t) { float tx = nx + nw + gp; text(F.ub700_12, 12, tx + 1, cy + 8.5f, A(P::blk(.8f), op), team); text(F.ub700_12, 12, tx, cy + 7.5f, A(V::TEAM, op), team); }
        cy += 15 + 6;
    }
    if (hp) { text_c(F.jb500_12, 12, cx, cy + 4, A(V::HP, op), "445/445"); cy += 11 + 6; }

    // фигура 140×330: фото (слой 260×326, −60/+2, contain), рамка, полоса брони
    const float fx = cx - 70, fy = cy;
    if (s_op_tex && s_op_w > 0 && s_op_h > 0) {
        float lw = 260, lh = 326, k = ImMin(lw / s_op_w, lh / s_op_h);
        float iw = s_op_w * k, ih = s_op_h * k, ix = fx - 60 + (lw - iw) * .5f, iy = fy + 2 + (lh - ih) * .5f;
        g.dl->AddImage(s_op_tex, Pt(ix, iy), Pt(ix + iw, iy + ih), {0, 0}, {1, 1}, A(IM_COL32_WHITE, op));
    }
    if (on(K_box)) {
        ImU32 bc = A(E[K_box].c, op), sh = A(P::blk(.55f), op);
        auto seg = [&](float ax, float ay, float bx2, float by2) {
            line(fx + ax, fy + ay, fx + bx2, fy + by2, sh, 3.6f);
            line(fx + ax, fy + ay, fx + bx2, fy + by2, bc, 2.f);
        };
        if (on(K_corners)) {
            seg(0, 40, 0, 0); seg(0, 0, 36, 0); seg(104, 0, 140, 0); seg(140, 0, 140, 40);
            seg(140, 290, 140, 330); seg(140, 330, 104, 330); seg(36, 330, 0, 330); seg(0, 330, 0, 290);
        } else {
            seg(0, 0, 140, 0); seg(140, 0, 140, 330); seg(140, 330, 0, 330); seg(0, 330, 0, 0);
            if (E[K_box].style == 1) { seg(0, 0, 12, -8); seg(12, -8, 152, -8); seg(152, -8, 152, 322); seg(152, 322, 140, 330); seg(140, 0, 152, -8); }
        }
    }
    if (bar) {
        rect(fx + 150, fy, 5, 163, A(V::ARMOR_H, op), 3);
        rect(fx + 150, fy + 167, 5, 163, A(V::ARMOR_V, op), 3);
        text(F.jb500_12, 11, fx + 161, fy + 80, A(V::ARMOR_H, op), "H4");
        text(F.jb500_12, 11, fx + 161, fy + 247, A(V::ARMOR_V, op), "V5");
    }
    cy += 330 + 6;

    // Нижняя строка: тир+прочность брони текстом + дистанция (gap 10).
    // Weapon/Ammo убраны — daemon-path в DH отключён 2026-09-22.
    struct Part { const Font* f; float css; const char* s; ImU32 c; } parts[4]; int np = 0;
    if (on(K_armor_tier)) parts[np++] = {&F.jb500_12, 12.5f, U8("H4 · V5"), E[K_armor_tier].c};
    if (on(K_armor_dura)) parts[np++] = {&F.jb500_12, 12.5f, "(45)/(60)", E[K_armor_dura].c};
    if (on(K_distance))   parts[np++] = {&F.jb500_12, 12.5f, "142 m",     E[K_distance].c};
    float tot = 0; for (int i = 0; i < np; i++) tot += tw(*parts[i].f, parts[i].css, parts[i].s) + (i ? 10 : 0);
    float px = cx - tot * .5f;
    for (int i = 0; i < np; i++) {
        if (i) px += 10;
        text(*parts[i].f, parts[i].css, px, cy + 8, A(parts[i].c, op), parts[i].s);
        px += tw(*parts[i].f, parts[i].css, parts[i].s);
    }
}

// ── рейл ──────────────────────────────────────────────────────────────────
void draw_rail(float x, float y, float h) {
    rect(x, y, 64, h, V::GLASS, 8);
    ring(x, y, 64, h, V::GLASS_LINE, 8);
    rect(x + 12, y + 12, 40, 40, G::LOGO_TILE, 7);
    icon("logo", x + 12 + 9.5f, y + 12 + 9, 21, IM_COL32_WHITE);
    static const char* ic[3] = {"nav_visual", "nav_radar", "nav_loot"};
    for (int i = 0; i < 3; i++) {
        float bx = x + 10, by = y + 12 + 40 + 14 + i * (44 + 8);
        bool hv = hot(bx, by, 44, 44);
        float t = anim(hid("rail", i), S_.sec == i ? 1.f : 0.f, 18.f);
        if (t > 0) rect(bx, by, 44, 44, A(G::ACCENT, t), 8);
        ImU32 tc = mix(hv ? G::TEXT : G::TEXT_MUTED, G::ON_ACCENT, t);
        icon(ic[i], bx + 12, by + 12, 20, tc);
        if (click(bx, by, 44, 44) && S_.sec != i) { S_.sec = i; S_.open = -1; S_.scroll = S_.scroll_t = 0; }
    }
    float lx = x + 12, ly = y + h - 12 - 28;
    bool lh = hot(lx, ly, 40, 28);
    if (lh) rect(lx, ly, 40, 28, V::GLASS_HOT, 5);
    text_c(F.ub700_12, 11, lx + 20, ly + 14, lh ? G::TEXT : G::TEXT_MUTED, S_.ru ? "RU" : "EN");
    if (click(lx, ly, 40, 28)) S_.ru = !S_.ru;
}

// ── контент ───────────────────────────────────────────────────────────────
float column_visual(float x, float y, float w, int col) {
    // группы: [колонка][группа] → ключи; -1 — конец
    // DH: без weapon/ammo, armor разделён на tier/dura, hp на своей строке.
    static const int P_L[][4] = {{K_enable, -1}, {K_box, K_corners, -1}, {K_corpses, K_teammates, -1}};
    static const int P_R[][8] = {{K_name, K_team, K_hp, K_armor_tier, K_armor_dura, K_distance, -1}};
    static const int B_L[][4] = {{K_enable, -1}, {K_box, K_corners, -1}, {K_corpses, -1}};
    static const int B_R[][8] = {{K_name, K_hp, K_armor_tier, K_armor_dura, K_distance, -1}};
    const char* tl_ru[] = {U8("ОСНОВНОЕ"), U8("БОКС"), U8("ПРОЧЕЕ")}, *tl_en[] = {"GENERAL", "BOX", "OTHER"};
    const char* tr_ru[] = {U8("ИНФО"), U8("ПРОЧЕЕ")}, *tr_en[] = {"INFO", "OTHER"};
    float cy = y;
    auto group = [&](const char* title, const int* keys) {
        group_title(x, cy, title); cy += CAP_H;
        for (int i = 0; keys[i] >= 0; i++) { cy += esp_row(x, cy, w, keys[i]); cy += ROW_GAP; }
        cy += GROUP_GAP - ROW_GAP;
    };
    const bool bots = S_.vt == 1;
    if (col == 0) {
        int n = 3;   // (для игроков и ботов — 3 группы)
        for (int i = 0; i < n; i++) group(S_.ru ? tl_ru[i] : tl_en[i], bots ? B_L[i] : P_L[i]);
    } else {
        group(S_.ru ? tr_ru[0] : tr_en[0], bots ? B_R[0] : P_R[0]);
    }
    return cy - GROUP_GAP;
}

float column_radar(float x, float y, float w, int col) {
    Radar& R = S_.radar; const bool ru = S_.ru; float cy = y; const float dim = R.show ? 1.f : .45f;
    if (col == 0) {
        group_title(x, cy, ru ? U8("ОТОБРАЖЕНИЕ") : "DISPLAY"); cy += CAP_H;
        bool* v[8] = {&R.show, &R.players, &R.bots, &R.mates, &R.corpse_pl, &R.corpse_bot, &R.rings, &R.label};
        const char* l_ru[8] = {U8("Показывать радар"), U8("Игроки"), U8("Боты"), U8("Тиммейты"),
                               U8("Трупы (игроки)"), U8("Трупы (боты)"), U8("Кольца дистанций"), U8("Метка дистанции")};
        const char* l_en[8] = {"Show radar", "Players", "Bots", "Teammates",
                               "Corpses (players)", "Corpses (bots)", "Distance rings", "Range label"};
        for (int i = 0; i < 8; i++) { cy += toggle_row(x, cy, w, ru ? l_ru[i] : l_en[i], "", *v[i], i == 0 ? 1.f : dim, hid("rt", i)) + ROW_GAP; }
        return cy - ROW_GAP;
    }
    group_title(x, cy, ru ? U8("РАЗМЕР И ДАЛЬНОСТЬ") : "SIZE & RANGE"); cy += CAP_H;
    cy += slider_row(x, cy, w, ru ? U8("Дистанция (м)") : "Range (m)",     R.world, 50, 500, 10, "%d m",  dim, hid("rs", 0)) + ROW_GAP;
    cy += slider_row(x, cy, w, ru ? U8("Радиус (px)")  : "Radius (px)",    R.screen, 60, 200, 5,  "%d px", dim, hid("rs", 1));
    cy += GROUP_GAP;
    group_title(x, cy, ru ? U8("ПОЛОЖЕНИЕ") : "POSITION"); cy += CAP_H;
    // угол экрана — 4 иконки-квадрата
    rect(x, cy, w, ROW_H, A(V::GLASS, dim), 7);
    ring(x, cy, w, ROW_H, V::GLASS_LINE, 7);
    text(F.ub500_14, 12.5f, x + 14, cy + ROW_H * .5f, A(G::TEXT, dim), ru ? U8("Угол экрана") : "Screen corner");
    float sw = 4 * 36 + 3 * 2 + 6, sx = x + w - 6 - sw, sy = cy + 6;
    rect(sx, sy, sw, 32, G::SEG_BG, 6);
    // 4 SVG-иконки из атласа (corner_tl / corner_tr / corner_bl / corner_br)
    // — те же, что использовал старый control_panel. Растрируются nanosvg'ом
    // (icons.cpp), панель тонирует их через AddImage tint.
    static const char* corner_ic[4] = { "corner_tl", "corner_tr", "corner_bl", "corner_br" };
    for (int i = 0; i < 4; i++) {
        float bx = sx + 3 + i * 38;
        float t = anim(hid("rc", i), R.corner == i ? 1.f : 0.f, 18.f);
        if (t > 0) rect(bx, sy + 3, 36, 26, A(G::ACCENT, t), 5);
        ImU32 c = mix(G::TEXT_MUTED, G::ON_ACCENT, t);
        icon(corner_ic[i], bx + 10, sy + 8, 16, c);
        if (click(bx, sy, 36, 32)) R.corner = i;
    }
    cy += ROW_H;
    return cy;
}

float column_loot(float x, float y, float w, int col) {
    // DH loot — 6 rarity filters + corpses + names + max_dist + min_val.
    Loot& L = S_.loot; const bool ru = S_.ru; float cy = y; const float dim = L.show ? 1.f : .45f;
    if (col == 0) {
        group_title(x, cy, ru ? U8("ОТОБРАЖЕНИЕ") : "DISPLAY"); cy += CAP_H;
        cy += toggle_row(x, cy, w, ru ? U8("Показывать лут") : "Show loot", "", L.show, 1.f, hid("lm", 0)) + ROW_GAP;
        cy += toggle_row(x, cy, w, ru ? U8("Названия предметов") : "Item names", "", L.names, dim, hid("lm", 1)) + ROW_GAP;
        cy += toggle_row(x, cy, w, ru ? U8("Трупы (лут)") : "Corpses (loot)", "", L.corpses, dim, hid("lm", 2));
        cy += GROUP_GAP;
        group_title(x, cy, ru ? U8("ФИЛЬТР") : "FILTER"); cy += CAP_H;
        cy += slider_row(x, cy, w, ru ? U8("Макс. дистанция")  : "Max distance",  L.max_dist, 0, 400,    5,   "%d m", dim, hid("lf", 0)) + ROW_GAP;
        cy += slider_row(x, cy, w, ru ? U8("Мин. ценность")    : "Min value",     L.min_val,  0, 200000, 500, "%d $", dim, hid("lf", 1));
        return cy;
    }
    group_title(x, cy, ru ? U8("РЕДКОСТЬ") : "RARITY"); cy += CAP_H;
    const char* rn_ru[6] = {U8("Обычный"), U8("Необычный"), U8("Редкий"), U8("Эпический"), U8("Легендарный"), U8("Мифический")};
    const char* rn_en[6] = {"Common", "Uncommon", "Rare", "Epic", "Legendary", "Mythic"};
    for (int i = 0; i < 6; i++) {
        cy += toggle_row(x, cy, w, ru ? rn_ru[i] : rn_en[i], "", L.r[i], dim, hid("lr", i)) + ROW_GAP;
    }
    return cy - ROW_GAP;
}

void draw_content(float x, float y, float w, float h) {
    State& s = S_;
    const float px = 12, pr = 10, pt = 16, pb = 16;
    const float cx = x + px, cw = w - px - pr;
    ImVec2 m = mouse();
    if (g.live && m.x >= x && m.x < x + w && m.y >= y && m.y < y + h) s.scroll_t -= ImGui::GetIO().MouseWheel * 48;
    const float max_s = ImMax(0.f, s.content_h - h);
    s.scroll_t = ImClamp(s.scroll_t, 0.f, max_s);
    s.scroll += (s.scroll_t - s.scroll) * ImMin(1.f, ImGui::GetIO().DeltaTime * 18);
    if (std::fabs(s.scroll_t - s.scroll) < .5f) s.scroll = s.scroll_t;

    ImVec4 prev = g.clip; g.clip = {x, y, x + w, y + h};
    g.dl->PushClipRect(Pt(x, y), Pt(x + w, y + h), true);
    float cy = y + pt - s.scroll;

    // заголовок + Игроки/Боты
    const char* title = s.sec == 0 ? (s.ru ? U8("Визуал") : "Visuals") : s.sec == 1 ? (s.ru ? U8("Радар") : "Radar") : (s.ru ? U8("Лут") : "Loot");
    text(F.ub700_20, 21, cx, cy + 17, G::TEXT, title, -.03f);
    if (s.sec == 0) {
        const char* vt[2] = {s.ru ? U8("Игроки") : "Players", s.ru ? U8("Боты") : "Bots"};
        float w0 = tw(F.ub500_14, 12, vt[0]) + 32, w1 = tw(F.ub500_14, 12, vt[1]) + 32, sw = w0 + w1 + 2 + 6;
        float sx = cx + cw - sw;
        rect(sx, cy, sw, 34, V::GLASS, 7);
        ring(sx, cy, sw, 34, V::GLASS_LINE, 7);
        for (int i = 0; i < 2; i++) {
            float bx = sx + 3 + (i ? w0 + 2 : 0), bw = i ? w1 : w0;
            float t = anim(hid("vt", i), s.vt == i ? 1.f : 0.f, 18.f);
            if (t > 0) rect(bx, cy + 3, bw, 28, A(V::GLASS_ON, t), 5);
            text_c(t > .5f ? F.ub700_12 : F.ub500_14, 12, bx + bw * .5f, cy + 17, mix(G::TEXT_MUTED, G::TEXT, t), vt[i]);
            if (click(bx, cy, bw, 34) && s.vt != i) { s.vt = i; s.open = -1; }
        }
    }
    cy += 34 + 18;

    const float colw = (cw - 12) * .5f;
    float bottom = cy;
    for (int c = 0; c < 2; c++) {
        float bx = cx + c * (colw + 12);
        float b = s.sec == 0 ? column_visual(bx, cy, colw, c) : s.sec == 1 ? column_radar(bx, cy, colw, c) : column_loot(bx, cy, colw, c);
        bottom = ImMax(bottom, b);
    }
    s.content_h = bottom + s.scroll - y + pb;
    g.dl->PopClipRect();
    g.clip = prev;

    // тонкий скроллбар, только если есть что прокручивать
    if (max_s > 1) {
        float tx = x + w - 5, t0 = y + 6, tl = h - 12;
        float th = ImMax(28.f, tl * h / s.content_h), ty = t0 + (s.scroll / max_s) * (tl - th);
        ImGuiID sid = hid("sb");
        bool zh = hot(tx - 6, t0, 12, tl) || s.drag == sid;
        if (zh && s.drag != sid && ImGui::IsMouseClicked(0)) { float my = mouse().y; s.drag_off = (my < ty || my > ty + th) ? th * .5f : my - ty; s.drag = sid; }
        if (s.drag == sid) {
            if (ImGui::IsMouseDown(0)) { float q = ImClamp((mouse().y - s.drag_off - t0) / ImMax(tl - th, 1.f), 0.f, 1.f); s.scroll = s.scroll_t = q * max_s; ty = t0 + q * (tl - th); }
            else s.drag = 0;
        }
        float hv = anim(sid + 1, zh ? 1.f : 0.f, 18.f), hw = 2 + hv;
        rect(tx - hw, ty, hw * 2, th, mix(G::SCROLL, G::SCROLL_HOT, hv), hw);
    }
}

}  // namespace

namespace abi {

void menu_v3_set_operator_texture(ImTextureID tex, int wpx, int hpx) { s_op_tex = tex; s_op_w = wpx; s_op_h = hpx; }
void menu_v3_set_scale(float dpi) { s_dpi = dpi > 0 ? dpi : 1.f; }

void render_menu_v3() {
    init_state(); load_fonts();
    constexpr float W = 960, H = 540, PAD = 9, RAIL = 64, PV = 300, GAP = 9;
    static ImVec2 pos(-1, -1);
    ImGuiIO& io = ImGui::GetIO();
    if (pos.x < 0) pos = ImVec2((io.DisplaySize.x - W * s_dpi) * .5f, (io.DisplaySize.y - H * s_dpi) * .5f);

    ImGui::SetNextWindowPos(pos);
    ImGui::SetNextWindowSize(ImVec2(W, H) * s_dpi);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0);
    ImGui::Begin("##gb_menu_v3", nullptr, ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoBackground | ImGuiWindowFlags_NoMove |
                                          ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_NoBringToFrontOnFocus);
    g.dl = ImGui::GetWindowDrawList();
    g.o = ImGui::GetWindowPos();
    g.s = s_dpi;
    g.live = ImGui::IsWindowHovered(ImGuiHoveredFlags_AllowWhenBlockedByActiveItem) || S_.drag != 0;
    g.clip = {0, 0, W, H};

    // тень + окно (окно с лёгкой прозрачностью — игра слегка просвечивает)
    for (int i = 1; i <= 4; i++) rect(-i * 3.f, 12 - i * 3.f + i * 4.f, W + i * 6.f, H + i * 4.f, P::blk(.05f), 16 + i * 3.f);
    rect(0, 0, W, H, V::WINDOW_GLASS, 10);
    ring(0, 0, W, H, P::wht(.04f), 10);

    const float ih = H - PAD * 2;
    draw_rail(PAD, PAD, ih);

    // перетаскивание окна за пустую зону рейла
    ImGuiID wd = hid("win_drag");
    if (click(PAD, PAD + 12 + 40 + 14 + 3 * 52, RAIL, ih - 12 - 40 - 14 - 3 * 52 - 48)) { S_.drag = wd; S_.drag_off = 0; }
    if (S_.drag == wd) { if (ImGui::IsMouseDown(0)) pos += io.MouseDelta; else S_.drag = 0; }

    const bool vis = S_.sec == 0;
    const float cx = PAD + RAIL + GAP, cw = W - cx - PAD - (vis ? PV + GAP : 0);
    draw_content(cx, PAD, cw, ih);
    if (vis) draw_preview(W - PAD - PV, PAD, PV, ih);

    ImGui::End();
    ImGui::PopStyleVar(2);
}

// ── DH_UI bridge ─────────────────────────────────────────────────────────
// Pull runs once (first frame after panel opens); push runs every frame so the
// world ESP/radar/loot renderers pick up toggle changes immediately.

static ImU32 v4u32(const ImVec4& v) { return ImGui::ColorConvertFloat4ToU32(v); }
static ImVec4 u32v4(ImU32 c)         { return ImGui::ColorConvertU32ToFloat4(c); }

void menu_v3_pull(const DH_UI& u) {
    init_state();
    static bool s_pulled = false;
    if (s_pulled) return;
    s_pulled = true;

    S_.ru = (u.lang == 1);   // menu_v3 внутри двуязычный (RU/EN); CN — v2

    // ── Players ────────────────────────────────────────────────────────
    Item* P0 = S_.esp[0];
    P0[K_enable].on      = u.show_players;
    P0[K_enable].dist    = u.max_dist_players;
    P0[K_box].on         = (u.box_mode_players > 0);
    P0[K_box].style      = (u.box_mode_players == 2) ? 1 : 0;   // 2D=0, 3D=1
    P0[K_box].dist       = u.box_dist_players;
    P0[K_box].has_c = true; P0[K_box].c = v4u32(u.col_player_box);
    P0[K_corners].on     = (u.box_mode_players == 1);           // 2D-brackets flag
    P0[K_name].on        = u.show_player_names;
    P0[K_name].has_c = true; P0[K_name].c = v4u32(u.col_player_name);
    P0[K_team].on        = u.show_player_team;
    P0[K_team].has_c = true; P0[K_team].c = v4u32(u.col_player_team);
    P0[K_hp].on          = u.show_player_hp;
    P0[K_hp].has_c   = true; P0[K_hp].c   = v4u32(u.col_player_hp);
    P0[K_armor_tier].on  = u.show_player_armor_tier;
    P0[K_armor_tier].has_c = true; P0[K_armor_tier].c = v4u32(u.col_player_armor_tier);
    P0[K_armor_dura].on  = u.show_player_armor_dura;
    P0[K_armor_dura].has_c = true; P0[K_armor_dura].c = v4u32(u.col_player_armor_dura);
    P0[K_distance].on    = u.show_player_dist;
    P0[K_distance].has_c = true; P0[K_distance].c = v4u32(u.col_player_dist);
    P0[K_corpses].on     = u.show_player_corpses;
    P0[K_corpses].dist   = u.corpse_dist_players;
    P0[K_corpses].has_c = true; P0[K_corpses].c = v4u32(u.col_player_corpse);
    P0[K_teammates].on   = u.show_player_mates;

    // ── Bots ───────────────────────────────────────────────────────────
    Item* B0 = S_.esp[1];
    B0[K_enable].on      = u.show_bots;
    B0[K_enable].dist    = u.max_dist_bots;
    B0[K_box].on         = (u.box_mode_bots > 0);
    B0[K_box].style      = (u.box_mode_bots == 2) ? 1 : 0;
    B0[K_box].dist       = u.box_dist_bots;
    B0[K_box].has_c = true; B0[K_box].c = v4u32(u.col_bot_box);
    B0[K_corners].on     = (u.box_mode_bots == 1);
    B0[K_name].on        = u.show_bot_names;
    B0[K_name].has_c = true; B0[K_name].c = v4u32(u.col_bot_name);
    B0[K_hp].on          = u.show_bot_hp;
    B0[K_hp].has_c   = true; B0[K_hp].c   = v4u32(u.col_bot_hp);
    B0[K_armor_tier].on  = u.show_bot_armor_tier;
    B0[K_armor_tier].has_c = true; B0[K_armor_tier].c = v4u32(u.col_bot_armor_tier);
    B0[K_armor_dura].on  = u.show_bot_armor_dura;
    B0[K_armor_dura].has_c = true; B0[K_armor_dura].c = v4u32(u.col_bot_armor_dura);
    B0[K_distance].on    = u.show_bot_dist;
    B0[K_distance].has_c = true; B0[K_distance].c = v4u32(u.col_bot_dist);
    B0[K_corpses].on     = u.show_bot_corpses;
    B0[K_corpses].dist   = u.corpse_dist_bots;
    B0[K_corpses].has_c = true; B0[K_corpses].c = v4u32(u.col_bot_corpse);

    // ── Radar ──────────────────────────────────────────────────────────
    S_.radar.show      = u.show_radar;
    S_.radar.players   = u.radar_show_players;
    S_.radar.bots      = u.radar_show_bots;
    S_.radar.mates     = u.radar_show_teammates;
    S_.radar.corpse_pl = u.radar_show_corpses_players;
    S_.radar.corpse_bot= u.radar_show_corpses_bots;
    S_.radar.rings     = u.radar_rings;
    S_.radar.label     = u.radar_range_label;
    S_.radar.world     = u.radar_range_m;
    S_.radar.screen    = u.radar_px_radius;
    // corner из radar_x/y не восстанавливаем — DH хранит абсолютные пиксели;
    // corner здесь просто "как выставить x/y" при следующем push'е.

    // ── Loot ───────────────────────────────────────────────────────────
    S_.loot.show     = u.show_loot;
    S_.loot.r[0]     = u.loot_show_common;
    S_.loot.r[1]     = u.loot_show_uncommon;
    S_.loot.r[2]     = u.loot_show_rare;
    S_.loot.r[3]     = u.loot_show_epic;
    S_.loot.r[4]     = u.loot_show_legendary;
    S_.loot.r[5]     = u.loot_show_mythic;
    S_.loot.corpses  = u.loot_show_corpses;
    S_.loot.names    = u.loot_show_names;
    S_.loot.max_dist = u.loot_max_dist_m;
    S_.loot.min_val  = u.loot_min_value;

    // ── Overlay tab ────────────────────────────────────────────────────
    S_.show_hud = u.show_hud;
}

void menu_v3_push(DH_UI& u) {
    init_state();
    u.lang = S_.ru ? 1 : 0;

    // ── Players — effective = master && widget ─────────────────────────
    const Item* P0 = S_.esp[0];
    const bool mp = P0[K_enable].on;
    u.show_players            = mp;
    u.max_dist_players        = P0[K_enable].dist;
    // box_mode: 0=Off, 1=2D corner-bracket, 2=3D wireframe.
    // menu_v3: K_box on/off + K_corners = 2D-brackets vs plain 2D, style bit = 3D.
    if (!mp || !P0[K_box].on)             u.box_mode_players = 0;
    else if (P0[K_box].style == 1)        u.box_mode_players = 2;   // 3D wireframe
    else                                  u.box_mode_players = 1;   // 2D (corner-bracket-ish)
    u.box_dist_players        = P0[K_box].dist;
    u.col_player_box          = u32v4(P0[K_box].c);
    u.show_player_names       = mp && P0[K_name].on;
    u.col_player_name         = u32v4(P0[K_name].c);
    u.show_player_team        = mp && P0[K_team].on;
    u.col_player_team         = u32v4(P0[K_team].c);
    u.show_player_hp          = mp && P0[K_hp].on;
    u.col_player_hp           = u32v4(P0[K_hp].c);
    u.show_player_armor_tier  = mp && P0[K_armor_tier].on;
    u.col_player_armor_tier   = u32v4(P0[K_armor_tier].c);
    u.show_player_armor_dura  = mp && P0[K_armor_dura].on;
    u.col_player_armor_dura   = u32v4(P0[K_armor_dura].c);
    u.show_player_dist        = mp && P0[K_distance].on;
    u.col_player_dist         = u32v4(P0[K_distance].c);
    u.show_player_corpses     = mp && P0[K_corpses].on;
    u.corpse_dist_players     = P0[K_corpses].dist;
    u.col_player_corpse       = u32v4(P0[K_corpses].c);
    u.show_player_mates       = mp && P0[K_teammates].on;

    // ── Bots ───────────────────────────────────────────────────────────
    const Item* B0 = S_.esp[1];
    const bool mb = B0[K_enable].on;
    u.show_bots               = mb;
    u.max_dist_bots           = B0[K_enable].dist;
    if (!mb || !B0[K_box].on)             u.box_mode_bots = 0;
    else if (B0[K_box].style == 1)        u.box_mode_bots = 2;
    else                                  u.box_mode_bots = 1;
    u.box_dist_bots           = B0[K_box].dist;
    u.col_bot_box             = u32v4(B0[K_box].c);
    u.show_bot_names          = mb && B0[K_name].on;
    u.col_bot_name            = u32v4(B0[K_name].c);
    u.show_bot_hp             = mb && B0[K_hp].on;
    u.col_bot_hp              = u32v4(B0[K_hp].c);
    u.show_bot_armor_tier     = mb && B0[K_armor_tier].on;
    u.col_bot_armor_tier      = u32v4(B0[K_armor_tier].c);
    u.show_bot_armor_dura     = mb && B0[K_armor_dura].on;
    u.col_bot_armor_dura      = u32v4(B0[K_armor_dura].c);
    u.show_bot_dist           = mb && B0[K_distance].on;
    u.col_bot_dist            = u32v4(B0[K_distance].c);
    u.show_bot_corpses        = mb && B0[K_corpses].on;
    u.corpse_dist_bots        = B0[K_corpses].dist;
    u.col_bot_corpse          = u32v4(B0[K_corpses].c);

    // ── Radar ──────────────────────────────────────────────────────────
    u.show_radar                   = S_.radar.show;
    u.radar_show_players           = S_.radar.players;
    u.radar_show_bots              = S_.radar.bots;
    u.radar_show_teammates         = S_.radar.mates;
    u.radar_show_corpses_players   = S_.radar.corpse_pl;
    u.radar_show_corpses_bots      = S_.radar.corpse_bot;
    u.radar_rings                  = S_.radar.rings;
    u.radar_range_label            = S_.radar.label;
    u.radar_range_m                = S_.radar.world;
    u.radar_px_radius              = S_.radar.screen;
    // При смене угла — переставляем radar_x/y к соответствующему углу
    // экрана. Пользователь может тянуть радар мышью, но при клике по углу
    // менюшки сбрасывается на выбранный.
    static int last_corner = -1;
    if (last_corner != -1 && last_corner != S_.radar.corner) {
        int R = S_.radar.screen;
        int margin = 40;
        int cx = (S_.radar.corner & 1) ? (u.sw - margin - R) : (margin + R);
        int cy = (S_.radar.corner & 2) ? (u.sh - margin - R) : (margin + R);
        u.radar_x = cx; u.radar_y = cy;
    }
    last_corner = S_.radar.corner;

    // ── Loot ───────────────────────────────────────────────────────────
    u.show_loot          = S_.loot.show;
    u.loot_show_common   = S_.loot.r[0];
    u.loot_show_uncommon = S_.loot.r[1];
    u.loot_show_rare     = S_.loot.r[2];
    u.loot_show_epic     = S_.loot.r[3];
    u.loot_show_legendary= S_.loot.r[4];
    u.loot_show_mythic   = S_.loot.r[5];
    u.loot_show_corpses  = S_.loot.corpses;
    u.loot_show_names    = S_.loot.names;
    u.loot_max_dist_m    = S_.loot.max_dist;
    u.loot_min_value     = S_.loot.min_val;

    // ── Overlay tab ────────────────────────────────────────────────────
    u.show_hud = S_.show_hud;
}

}  // namespace abi

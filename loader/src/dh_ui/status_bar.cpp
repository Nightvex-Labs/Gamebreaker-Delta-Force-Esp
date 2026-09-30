// status_bar.cpp — Gamebreaker-style top-left status pill.
// [logo] GameBreaker | ▂▄▆ PING | ◠ FPS.
// Port of ABIESP src/abi_ui/status_bar.cpp — same design, RenderConfig
// dependency stripped (DH doesn't have one). ui_scale is passed in directly.
#define IMGUI_DEFINE_MATH_OPERATORS
#include "status_bar.hpp"
#include "icons.hpp"
#include "palette.hpp"
#include <imgui.h>
#include <imgui_internal.h>
#include <cmath>
#include <cstdio>
#include <cstring>

namespace abi::hud {
namespace {
namespace P = abi::pal;
namespace G = abi::pal::gb;

ImFont* font(const char* name) {
    ImFontAtlas* at = ImGui::GetIO().Fonts;
    for (ImFont* f : at->Fonts) if (f && std::strcmp(f->GetDebugName(), name) == 0) return f;
    return ImGui::GetFont();
}
float tw(ImFont* f, float sz, const char* s) { return f->CalcTextSizeA(sz, FLT_MAX, 0, s).x; }
void txt(ImDrawList* dl, ImFont* f, float sz, float x, float cy, ImU32 c, const char* s, float tr = 0) {
    float y = std::floor(cy - sz * .5f + .5f);
    if (tr == 0) { dl->AddText(f, sz, ImVec2(std::floor(x + .5f), y), c, s); return; }
    for (const char* p = s; *p; ++p) {       // per-glyph tracking for caps
        dl->AddText(f, sz, ImVec2(std::floor(x + .5f), y), c, p, p + 1);
        x += f->CalcTextSizeA(sz, FLT_MAX, 0, p, p + 1).x + tr * sz;
    }
}
float tw_tr(ImFont* f, float sz, const char* s, float tr) { return tw(f, sz, s) + tr * sz * (float)std::strlen(s); }
}  // namespace

void status_bar(float ui_scale, int ping_ms, float fps, ImVec2 pos) {
    ImDrawList* dl = ImGui::GetForegroundDrawList();
    static ImFont *f_brand = nullptr, *f_label = nullptr, *f_cap = nullptr, *f_mono = nullptr;
    if (!f_brand) {
        f_brand = font("gb:ub700:14"); f_label = font("gb:ub500:14");
        f_cap   = font("gb:ub700:9");  f_mono  = font("gb:jb500:12");
    }
    (void)f_label;
    // 1.35x bump — status bar was too small to read at a glance on desktop res;
    // clamp adjusted to keep max reasonable on hi-DPI monitors.
    const float k = ImClamp(std::sqrt(ui_scale > 0 ? ui_scale : 1.f), .85f, 1.4f) * 1.35f;
    const float H = 38 * k, pad = 6 * k, seg = 10 * k, ic = 14 * k, gap = 7 * k;
    const float s_brand = 13 * k, s_cap = 9 * k, s_mono = 12 * k, trk = .12f;

    char s_ping[12], s_fps[12];
    std::snprintf(s_ping, sizeof s_ping, "%d", ping_ms < 0 ? 0 : ping_ms);
    std::snprintf(s_fps, sizeof s_fps, "%d", (int)(fps + .5f));
    const int q = ping_ms <= 60 ? 3 : ping_ms <= 120 ? 2 : 1;
    const ImU32 pc = q == 3 ? P::POS : q == 2 ? P::AMBER : P::NEG;

    const float w_brand = 26 * k + 8 * k + tw(f_brand, s_brand, "GameBreaker") + seg + 2 * k;
    const float w_ping  = seg + ic + gap + tw(f_mono, s_mono, s_ping) + 5 * k + tw_tr(f_cap, s_cap, "PING", trk) + seg;
    const float w_fps   = seg + ic + gap + tw(f_mono, s_mono, s_fps) + 5 * k + tw_tr(f_cap, s_cap, "FPS", trk) + seg;
    const float W = pad * 2 + w_brand + w_ping + w_fps + 2 * (1 + 2 * pad);

    const ImVec2 a(std::floor(pos.x), std::floor(pos.y)), b(a.x + W, a.y + H);
    const float cy = a.y + H * .5f;
    dl->AddRectFilled(a, b, (G::WINDOW & ~IM_COL32_A_MASK) | (235u << IM_COL32_A_SHIFT), 12 * k);
    dl->AddRect(a + ImVec2(.5f, .5f), b - ImVec2(.5f, .5f), P::wht(.06f), 12 * k, 0, 1);

    float x = a.x + pad;
    auto divider = [&] {
        x += pad;
        dl->AddLine(ImVec2(std::floor(x) + .5f, cy - 9 * k), ImVec2(std::floor(x) + .5f, cy + 9 * k), P::wht(.08f), 1);
        x += 1 + pad;
    };

    // logo + GameBreaker
    {
        const float t = 26 * k; ImVec2 ta(x + 2 * k, cy - t * .5f);
        dl->AddRectFilled(ta, ta + ImVec2(t, t), G::LOGO_TILE, 8 * k);
        if (ImTextureID logo = icons::get("logo")) {
            ImVec2 la(std::floor(ta.x + (t - 15 * k) * .5f), std::floor(ta.y + (t - 16 * k) * .5f));
            dl->AddImage(logo, la, la + ImVec2(15 * k, 16 * k));
        }
        txt(dl, f_brand, s_brand, ta.x + t + 8 * k, cy, G::TEXT, "GameBreaker");
        x += w_brand;
    }
    divider();

    // PING — 3 bars + number + PING caps
    {
        float ix = x + seg; const float u = ic / 16.f;
        const float hs[3] = {4, 7.5f, 11}, xs[3] = {2, 6.7f, 11.4f};
        for (int i = 0; i < 3; i++) {
            ImVec2 p0(ix + xs[i] * u, cy + 6 * u - hs[i] * u), p1(p0.x + 2.6f * u, cy + 6 * u);
            dl->AddRectFilled(p0, p1, i < q ? pc : P::wht(.12f), 1 * u);
        }
        float tx = ix + ic + gap;
        txt(dl, f_mono, s_mono, tx, cy, pc, s_ping);
        tx += tw(f_mono, s_mono, s_ping) + 5 * k;
        txt(dl, f_cap, s_cap, tx, cy + 1 * k, G::TEXT_FAINT, "PING", trk);
        x += w_ping;
    }
    divider();

    // FPS — speedometer arc + number + FPS caps
    {
        float ix = x + seg; const float u = ic / 16.f, lw = 1.6f * k;
        const ImVec2 o(ix + 8 * u, cy + 1.5f * u);
        dl->PathArcTo(o, 5.8f * u, IM_PI * .82f, IM_PI * 2.18f, 20);
        dl->PathStroke(G::TEXT_MUTED, 0, lw);
        dl->AddLine(o, o + ImVec2(2.6f * u, -3 * u), G::TEXT_MUTED, lw);
        float tx = ix + ic + gap;
        txt(dl, f_mono, s_mono, tx, cy, G::TEXT, s_fps);
        tx += tw(f_mono, s_mono, s_fps) + 5 * k;
        txt(dl, f_cap, s_cap, tx, cy + 1 * k, G::TEXT_FAINT, "FPS", trk);
    }
}

}  // namespace abi::hud

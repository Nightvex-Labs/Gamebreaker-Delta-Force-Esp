// status_bar.hpp — Gamebreaker-style top-left status pill.
// [logo] GameBreaker | ▂▄▆ PING | ◠ FPS.
//
// Draw every frame after render_frame() / before the panel. The pill lives on
// ImGui's ForegroundDrawList so it renders on top of everything but the panel.
#pragma once
#include <imgui.h>

namespace abi::hud {

// ui_scale: same as g_ui.ui_scale (monitor_h / 1080, clamped).
// ping_ms:  -1 or 0 renders as "0" with green (unknown = optimistic).
// fps:      ImGui::GetIO().Framerate.
// pos:      top-left corner of the pill (default 18,18 like arena).
void status_bar(float ui_scale, int ping_ms, float fps, ImVec2 pos = ImVec2(18, 18));

}

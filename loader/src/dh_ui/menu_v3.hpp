#pragma once
#include <imgui.h>
#include "../../inc/dh_ui_state.hpp"

namespace abi {

// DeltaHack · меню v3 (Spectra Dark). Self-contained ImGui panel drawn on the
// existing dh_overlay_imgui.cpp swapchain. Bridge pulls state from DH_UI once
// (first frame) and pushes back every frame.
void render_menu_v3();
void menu_v3_set_scale(float dpi);
void menu_v3_set_operator_texture(ImTextureID tex, int wpx, int hpx);

void menu_v3_pull(const DH_UI& u);
void menu_v3_push(DH_UI& u);

}

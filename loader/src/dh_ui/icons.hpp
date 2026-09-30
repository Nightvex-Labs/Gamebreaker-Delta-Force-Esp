// SVG icon → D3D11 texture pipeline.
//
// Rationale: the HTML mock uses Lucide-style SVGs where the exact
// stroke geometry matters (corners of a `box`, angle of a `crosshair`
// centre gap, etc.). Instead of hand-matching those to an icon-font
// codepoint we rasterise the mock's own SVG source at panel init and
// present each glyph as an ImTextureID that ImGui blits with
// per-call colour modulation. Any new icon = one line in
// icons_data.hpp.

#pragma once
#include <imgui.h>

struct ID3D11Device;

namespace abi::icons {

// Rasterise every entry in kSvgTable (icons_data.hpp) at the given
// pixel size (default 32). Textures live for the process lifetime.
// Idempotent — subsequent calls with the same device are no-ops.
bool init(ID3D11Device* device, int pixel_size = 32);

// Release GPU resources. Called from Overlay::shutdown before the
// device is dropped.
void shutdown();

// Look up a rasterised icon by name. Returns 0 if unknown or if
// init hasn't run — callers should tolerate that (a missing icon
// just draws nothing, layout stays intact).
ImTextureID get(const char* name);

// Display size in DIPs (defaults to 15×15 like the mock's <colhead>
// icons). The texture itself is 32×32 for 2× sharpness on retina;
// this is what pill_header / nav / gear-row should render at.
ImVec2 display_size();

}  // namespace abi::icons

// nanosvg-based rasteriser: parses the SVG string, replaces
// `currentColor` with white, rasterises to an RGBA8 buffer, wraps
// it in a D3D11 shader-resource view. The SRV pointer becomes the
// ImTextureID we hand back to ImGui.

#include "icons.hpp"
#include "icons_data.hpp"

#define NANOSVG_IMPLEMENTATION
#define NANOSVG_ALL_COLOR_KEYWORDS
#include "../third_party/nanosvg/nanosvg.h"
#define NANOSVGRAST_IMPLEMENTATION
#include "../third_party/nanosvg/nanosvgrast.h"

#include <d3d11.h>
#include <string>
#include <unordered_map>
#include <vector>

namespace abi::icons {

struct Entry {
    ID3D11ShaderResourceView* srv = nullptr;
    ID3D11Texture2D*          tex = nullptr;
};
static std::unordered_map<std::string, Entry> g_icons;
static int g_pixel_size = 32;
static bool g_ready = false;

static std::string swap_current_color(const char* svg) {
    std::string s = svg;
    static const std::string needle = "currentColor";
    static const std::string repl   = "#ffffff";
    for (size_t p = 0; (p = s.find(needle, p)) != std::string::npos; p += repl.size()) {
        s.replace(p, needle.size(), repl);
    }
    return s;
}

bool init(ID3D11Device* device, int pixel_size) {
    if (g_ready || !device) return g_ready;
    g_pixel_size = pixel_size;
    NSVGrasterizer* rast = nsvgCreateRasterizer();
    if (!rast) return false;

    std::vector<unsigned char> pixels((size_t)pixel_size * pixel_size * 4);
    for (const auto& e : kSvgTable) {
        std::string svg = swap_current_color(e.svg);
        // nsvgParse mutates the buffer — work on a copy.
        std::vector<char> buf(svg.begin(), svg.end());
        buf.push_back('\0');
        NSVGimage* img = nsvgParse(buf.data(), "px", 96.0f);
        if (!img) continue;

        // Fit whatever the SVG's own bounding box says into pixel_size × pixel_size
        // with a tiny inset so strokes don't clip. Earlier this hardcoded 24 for the
        // Lucide-style 24×24 rail icons, which meant any SVG with a different viewBox
        // (e.g. the Nightvex brand logo at 1254×1254) rasterised at the wrong scale
        // and blew past the pixel buffer. Reading img->width/height auto-fits every
        // asset regardless of authored viewBox size.
        const float pad = 1.0f;
        const float span = (img->width > 0.0f && img->height > 0.0f)
            ? (img->width > img->height ? img->width : img->height)
            : 24.0f;
        const float scale = ((float)pixel_size - pad * 2.0f) / span;

        std::fill(pixels.begin(), pixels.end(), 0);
        nsvgRasterize(rast, img, pad, pad, scale,
                      pixels.data(), pixel_size, pixel_size, pixel_size * 4);
        nsvgDelete(img);

        D3D11_TEXTURE2D_DESC td{};
        td.Width          = pixel_size;
        td.Height         = pixel_size;
        td.MipLevels      = 1;
        td.ArraySize      = 1;
        td.Format         = DXGI_FORMAT_R8G8B8A8_UNORM;
        td.SampleDesc.Count = 1;
        td.Usage          = D3D11_USAGE_DEFAULT;
        td.BindFlags      = D3D11_BIND_SHADER_RESOURCE;
        D3D11_SUBRESOURCE_DATA sd{ pixels.data(), (UINT)(pixel_size * 4), 0 };

        Entry ent;
        if (FAILED(device->CreateTexture2D(&td, &sd, &ent.tex))) continue;
        if (FAILED(device->CreateShaderResourceView(ent.tex, nullptr, &ent.srv))) {
            ent.tex->Release();
            continue;
        }
        g_icons.emplace(std::string(e.name), ent);
    }
    nsvgDeleteRasterizer(rast);
    g_ready = true;
    return true;
}

void shutdown() {
    for (auto& kv : g_icons) {
        if (kv.second.srv) kv.second.srv->Release();
        if (kv.second.tex) kv.second.tex->Release();
    }
    g_icons.clear();
    g_ready = false;
}

ImTextureID get(const char* name) {
    auto it = g_icons.find(std::string(name));
    if (it == g_icons.end()) return 0;
    return (ImTextureID)(intptr_t)it->second.srv;
}

ImVec2 display_size() { return ImVec2(15.0f, 15.0f); }

}  // namespace abi::icons

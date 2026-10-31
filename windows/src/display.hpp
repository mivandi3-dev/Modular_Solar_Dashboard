// Skaliranje prikaza: dashboard je složen za 1920 × 1080 CSS piksela, a povećava se izvornim zoomom
// WebView2 (kao Ctrl + u pregledniku). Efektivni devicePixelRatio = DPI Windowsa × ZoomFactor.
#pragma once

#include <algorithm>
#include <cmath>
#include <string>

namespace sm {

inline constexpr int kDesignW = 1920, kDesignH = 1080;
inline constexpr int kSidebarCssW = 340;  // izbornik widgeta desno (web/editor.js)
inline constexpr double kMinZoom = 0.25, kMaxZoom = 4.0;

inline int preset_width(const std::string& scale) {
    return scale == "fhd" ? 1920 : scale == "2k" ? 2560 : scale == "4k" ? 3840 : 0;
}

// auto: raspored stane u prozor (uz eventualnu dodatnu širinu za izbornik); fhd/2k/4k: fiksni omjer.
inline double device_scale(const std::string& scale, int width_px, int height_px, int extra_css_width = 0) {
    if (const int w = preset_width(scale)) return static_cast<double>(w) / kDesignW;
    if (width_px <= 0 || height_px <= 0) return 1.0;
    return std::min(static_cast<double>(width_px) / (kDesignW + extra_css_width), static_cast<double>(height_px) / kDesignH);
}

inline double zoom_factor(const std::string& scale, int width_px, int height_px, double dpi_scale, int extra_css_width = 0) {
    const double z = device_scale(scale, width_px, height_px, extra_css_width) / std::max(dpi_scale, 0.1);
    return std::round(std::clamp(z, kMinZoom, kMaxZoom) * 10000) / 10000;
}

}  // namespace sm

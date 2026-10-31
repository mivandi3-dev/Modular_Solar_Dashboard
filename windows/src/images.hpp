// Zamjenjive slike: fotografija u zaglavlju (6 : 1) i crtež zgrade (16 : 9) – vidi desktop/images.py.
#pragma once

#include <string>

#include "config.hpp"

namespace sm {

fs::path image_path(const std::string& kind);       // vlastita (data/images) ili izvorna (assets)
std::string image_url(const std::string& kind);      // URL za WebView (virtualni host, s oznakom verzije)
json image_info(const std::string& kind);            // naslov, upute, omjer, dimenzije, sličica
json replace_image(const std::string& kind, const fs::path& source);  // baca std::runtime_error s porukom
void reset_image(const std::string& kind);
bool is_image_kind(const std::string& kind);

}  // namespace sm

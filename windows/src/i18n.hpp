// Prijevodi (isti i18n/<jezik>.json kao Python verzija): ključ je hrvatski tekst s {mjestima}.
//   tr("Pogrešan PIN.")
//   tr("Uvezeno {n} očitanja.", {{"n", fmt_num(added, 0)}})
#pragma once

#include <initializer_list>
#include <string>
#include <utility>

#include "config.hpp"

namespace sm {

using TrArgs = std::initializer_list<std::pair<const char*, std::string>>;

void set_language(const std::string& code);  // nepoznat jezik → hrvatski
std::string language();
std::string tr(const std::string& key, TrArgs args = {});
std::string fmt_num(double value, int decimals);  // decimalni znak i tisućice prema jeziku
json i18n_bundle(const std::string& code);         // {lang, meta, strings, languages} za JS
std::string system_language();                    // jezik Windowsa (prijedlog u čarobnjaku)
bool is_language(const std::string& code);

}  // namespace sm

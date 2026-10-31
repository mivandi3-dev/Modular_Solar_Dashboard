// Mjesečni izvještaj (isti JSON kao solar/report.py – iscrtava ga web/settings.js) i CSV za Excel.
#pragma once

#include "config.hpp"
#include "data.hpp"

namespace sm {

// Baca std::runtime_error (poruka za korisnika) za budući mjesec.
json build_report(DataService& data, const Settings& s, int year, unsigned month);
std::string report_csv(const json& report);  // UTF-8 s BOM-om; ";" i decimalni zarez kad ga jezik koristi

}  // namespace sm

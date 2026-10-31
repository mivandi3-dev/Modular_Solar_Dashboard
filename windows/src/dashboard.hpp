// Podaci za dashboard (web/dashboard.js) – zajednički za aplikaciju, pregled iz mreže i API poslužitelja.
#pragma once

#include "config.hpp"
#include "data.hpp"
#include "layout.hpp"
#include "weather.hpp"

namespace sm {

// Postavke koje treba sučelje (bez lozinki i ključeva).
json ui_settings(const Settings& s);

// Proizvodnja, vrijeme, raspored (stranice) i slike s virtualnih hostova aplikacije (https://app.solari/…).
json build_dashboard(DataService& data, WeatherService& weather, const Catalog& catalog, const Settings& s);

// Postavke prikaza koje svako računalo/uređaj ima svoje (tema, jezik, noćni način…) – ostalo dolazi s poslužitelja.
void apply_local_display(json& dashboard_settings, const Settings& local);

}  // namespace sm

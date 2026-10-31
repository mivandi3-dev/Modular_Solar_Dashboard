// Fronius Solar API v1 (lokalni HTTP, bez prijave): GetPowerFlowRealtimeData – Datamanager (Symo, Primo, Galvo…)
// i GEN24/Tauro. Site: P_PV (W), P_Grid (W, + iz mreže / − u mrežu), E_Day i E_Total (Wh, na GEN24 često null –
// tada iz Inverters). Bez E_Day dnevnu energiju računa poller iz ukupne (vidi poll_once).
#pragma once

#include <string>

#include "config.hpp"

namespace sm {

struct PlantReading;

// Odgovor GetPowerFlowRealtimeData.fcgi → očitanje; with_meter: uzmi P_Grid kao mjerač (ako postoji).
PlantReading parse_fronius_powerflow(const json& body, bool with_meter);

PlantReading read_fronius(const Settings& s);

}  // namespace sm

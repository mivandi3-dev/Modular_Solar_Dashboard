// Obavijesti e-poštom o stanju elektrane (isto kao solar/alerts.py i solar/mailer.py): uređaj ne odgovara,
// inverter javi grešku, sumnjivo niska proizvodnja prema prognozi. Šalje ih poller; pošta ide preko
// curl.exe (SMTP sa STARTTLS ili SSL) na mrežnoj kartici prema internetu.
#pragma once

#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "config.hpp"
#include "util.hpp"

namespace sm {

inline constexpr int kMaxAlertsPerDay = 20;
inline constexpr int kLowFromHour = 14, kLowToHour = 17;

struct AlertState {
    bool offline_sent = false;
    bool fault_sent = false;
    std::string low_day;  // datum (ISO) provjere niske proizvodnje
    std::string sent_day;
    int sent_count = 0;
    bool operator==(const AlertState&) const = default;
};

struct Observation {
    std::time_t now = 0;
    bool ok = false;
    std::optional<std::time_t> last_ok;
    std::optional<int> status;
    std::string error;
    std::optional<double> day_kwh;
    std::optional<double> expected_kwh;  // očekivano do sada prema prognozi
};

struct MailMessage {
    std::string subject, body;
};

std::pair<AlertState, std::vector<MailMessage>> evaluate_alerts(const Settings& s, AlertState state, const Observation& obs);
bool wants_forecast(const Settings& s, const AlertState& state, std::time_t now);
MailMessage test_message(const Settings& s, std::time_t now);

// Očekivana energija (kWh) od ponoći do `now` iz satnog zračenja Open-Meteo ([["2026-10-29T10:00", W/m²], ...]).
double expected_until(const json& hourly, std::time_t now, double kwp);

AlertState load_alert_state();
void save_alert_state(const AlertState& state);

class MailError : public std::runtime_error {
    using std::runtime_error::runtime_error;
};
// Pošalji svim primateljima iz postavki; password nullopt = spremljena lozinka. Vraća primatelje.
// Vrijednost u curl -K datoteci (u navodnicima). Kontrolni znak (novi red …) → MailError: inače postaje nova curl opcija.
std::string curl_config_value(const std::string& v);
// Cijela curl -K konfiguracija za slanje; provjerava i naziv poslužitelja
std::string curl_mail_config(const Settings& s, const std::string& password, const std::string& sender,
                             const std::vector<std::string>& recipients);

std::vector<std::string> send_mail(const Settings& s, const std::string& subject, const std::string& body,
                                   const std::optional<std::string>& password = std::nullopt);

}  // namespace sm

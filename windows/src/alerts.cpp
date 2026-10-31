#include "alerts.hpp"

#include <windows.h>

#include <cstdio>
#include <map>

#include "i18n.hpp"
#include "net.hpp"
#include "secret.hpp"
#include "system.hpp"

namespace sm {

namespace {

constexpr double kLowRatio = 0.5;
constexpr double kLowMinExpectedKwpH = 0.5;  // usporedba tek ako je prognoza očekivala bar pola sata pune snage
constexpr double kPerformanceRatio = 0.8;     // isto kao solar/forecast.py
constexpr unsigned kMailTimeoutMs = 45'000;

// Huawei SUN2000 "Device status" (registar 32089): isključenja zbog greške ili zaštite
const std::map<int, const char*> kInverterFaults = {
    {0x0300, "Shutdown: Fault"}, {0x0302, "Shutdown: OVGR"}, {0x0305, "Shutdown: manual startup required"},
    {0x0306, "Shutdown: DC switches disconnected"}, {0x0307, "Shutdown: rapid cutoff"}};

std::string time_text(std::time_t t, const char* format) {
    const std::tm tm = local_tm(t);
    char buf[64];
    std::strftime(buf, sizeof buf, format, &tm);
    return buf;
}

std::string subject(const Settings& s, const std::string& text) {
    return "[" + tr("Solarni monitor") + "] " + s.plant_name + ": " + text;
}

std::string footer(const Settings& s, std::time_t now) {
    return "\n\n— " + tr("Solarni monitor · {plant} · {time}", {{"plant", s.plant_name}, {"time", time_text(now, "%d.%m.%Y. %H:%M")}});
}

// "2026-10-29T10:00" (lokalno vrijeme) → time_t
std::optional<std::time_t> parse_local(const std::string& text) {
    std::tm tm{};
    if (std::sscanf(text.c_str(), "%d-%d-%dT%d:%d", &tm.tm_year, &tm.tm_mon, &tm.tm_mday, &tm.tm_hour, &tm.tm_min) != 5) {
        return std::nullopt;
    }
    tm.tm_year -= 1900;
    tm.tm_mon -= 1;
    tm.tm_isdst = -1;
    const std::time_t t = std::mktime(&tm);
    return t == -1 ? std::nullopt : std::optional(t);
}

std::string quote_config(const std::string& v) {  // vrijednost u curl -K datoteci
    std::string out = "\"";
    for (char c : v) {
        if (c == '"' || c == '\\') out += '\\';
        out += c;
    }
    return out + "\"";
}

std::string header_utf8(const std::string& text) {  // RFC 2047 za naslov s kvačicama
    return "=?UTF-8?B?" + base64(std::vector<uint8_t>(text.begin(), text.end())) + "?=";
}

fs::path temp_file(const wchar_t* ext) {
    wchar_t dir[MAX_PATH], name[MAX_PATH];
    GetTempPathW(MAX_PATH, dir);
    GetTempFileNameW(dir, L"sm2", 0, name);
    fs::path p(name);
    std::error_code ec;
    fs::remove(p, ec);
    return p.replace_extension(ext);
}

struct TempFiles {
    std::vector<fs::path> paths;
    ~TempFiles() {
        std::error_code ec;
        for (const auto& p : paths) fs::remove(p, ec);
    }
};

}  // namespace

bool wants_forecast(const Settings& s, const AlertState& state, std::time_t now) {
    const std::tm tm = local_tm(now);
    return s.alert_low_production && tm.tm_hour >= kLowFromHour && tm.tm_hour < kLowToHour &&
           state.low_day != iso_date(local_date(now));
}

double expected_until(const json& hourly, std::time_t now, double kwp) {
    double total = 0;
    const Date today = local_date(now);
    for (const auto& h : hourly) {
        if (!h.is_array() || h.size() < 2 || !h[0].is_string() || !h[1].is_number()) continue;
        const auto end = parse_local(h[0].get<std::string>());
        if (!end) continue;
        const std::time_t start = *end - 3600;
        if (local_date(start + 1800) != today) continue;  // sredina sata pripada danas
        const double kw = std::max(h[1].get<double>(), 0.0) / 1000 * kwp * kPerformanceRatio;
        const double elapsed = std::clamp(static_cast<double>(std::min(now, *end) - start) / 3600, 0.0, 1.0);
        total += kw * elapsed;
    }
    return total;
}

std::pair<AlertState, std::vector<MailMessage>> evaluate_alerts(const Settings& s, AlertState state, const Observation& obs) {
    const std::string device = s.device_type == "inverter" ? tr("Inverter") : tr("Logger");
    std::vector<MailMessage> messages;
    const std::string day = iso_date(local_date(obs.now));
    const int hour = local_tm(obs.now).tm_hour;

    if (s.alert_offline_min > 0) {
        if (obs.ok && state.offline_sent) {
            messages.push_back({subject(s, tr("{device} ponovno radi", {{"device", device}})),
                                tr("{device} {host} ponovno odgovara i podaci se bilježe.", {{"device", device}, {"host", s.modbus_host}})});
            state.offline_sent = false;
        } else if (!obs.ok && !state.offline_sent && obs.last_ok) {
            const auto minutes = (obs.now - *obs.last_ok) / 60;
            if (minutes >= s.alert_offline_min) {
                std::string text = tr("{device} {host} ne odgovara {n} min (zadnje očitanje {time}).",
                                      {{"device", device}, {"host", s.modbus_host}, {"n", std::to_string(minutes)},
                                       {"time", time_text(*obs.last_ok, "%d.%m. %H:%M")}});
                if (!obs.error.empty()) text += "\n\n" + tr("Zadnja greška: {error}", {{"error", obs.error}});
                messages.push_back({subject(s, tr("{device} nedostupan", {{"device", device}})), text});
                state.offline_sent = true;
            }
        }
    }

    if (s.alert_fault && s.device_type == "inverter" && obs.ok && obs.status) {
        const auto fault = kInverterFaults.find(*obs.status);
        if (fault != kInverterFaults.end() && !state.fault_sent) {
            char code[8];
            std::snprintf(code, sizeof code, "%04X", *obs.status);
            messages.push_back({subject(s, tr("inverter javlja grešku")),
                                tr("Inverter javlja stanje „{status}“ (0x{code:04X}) i ne proizvodi. Provjerite inverter "
                                   "u aplikaciji FusionSolar.", {{"status", fault->second}, {"code:04X", code}})});
            state.fault_sent = true;
        } else if (fault == kInverterFaults.end() && state.fault_sent) {
            messages.push_back({subject(s, tr("inverter ponovno radi")), tr("Inverter više ne javlja grešku.")});
            state.fault_sent = false;
        }
    }

    if (s.alert_low_production && obs.ok && obs.day_kwh && obs.expected_kwh && hour >= kLowFromHour && hour < kLowToHour &&
        state.low_day != day && *obs.expected_kwh >= kLowMinExpectedKwpH * s.peak_power_kwp) {
        if (*obs.day_kwh < kLowRatio * *obs.expected_kwh) {
            messages.push_back({subject(s, tr("niska proizvodnja")),
                                tr("Danas je do {time} proizvedeno {kwh} kWh, a prema prognozi zračenja očekivano je oko "
                                   "{expected} kWh ({pct} %). Mogući uzroci: prljavi paneli, ispao string, isključen "
                                   "inverter ili sjena.",
                                   {{"time", time_text(obs.now, "%H:%M")}, {"kwh", fmt_num(*obs.day_kwh, 0)},
                                    {"expected", fmt_num(*obs.expected_kwh, 0)},
                                    {"pct", fmt_num(*obs.day_kwh / *obs.expected_kwh * 100, 0)}})});
        }
        state.low_day = day;  // provjera jednom dnevno (i kad je sve u redu)
    }

    if (!messages.empty()) {
        const int count = state.sent_day == day ? state.sent_count : 0;
        const size_t allowed = static_cast<size_t>(std::max(0, kMaxAlertsPerDay - count));
        if (messages.size() > allowed) {
            log_warn("Dnevno ograničenje obavijesti – " + std::to_string(messages.size() - allowed) + " poruka nije poslano");
            messages.resize(allowed);
        }
        for (auto& m : messages) m.body += footer(s, obs.now);
        state.sent_day = day;
        state.sent_count = count + static_cast<int>(messages.size());
    }
    return {state, messages};
}

MailMessage test_message(const Settings& s, std::time_t now) {
    return {subject(s, tr("probna poruka")), tr("Ovo je probna poruka. Obavijesti o elektrani stižu na ovu adresu.") + footer(s, now)};
}

AlertState load_alert_state() {
    AlertState st;
    const auto text = read_file(data_dir() / L"alerts.json");
    if (!text) return st;
    try {
        const json j = json::parse(*text);
        st.offline_sent = j.value("offline_sent", false);
        st.fault_sent = j.value("fault_sent", false);
        st.low_day = j.value("low_day", "");
        st.sent_day = j.value("sent_day", "");
        st.sent_count = j.value("sent_count", 0);
    } catch (const json::exception&) {
    }
    return st;
}

void save_alert_state(const AlertState& st) {
    const json j = {{"offline_sent", st.offline_sent}, {"fault_sent", st.fault_sent}, {"low_day", st.low_day},
                    {"sent_day", st.sent_day}, {"sent_count", st.sent_count}};
    write_file_atomic(data_dir() / L"alerts.json", j.dump());
}

std::vector<std::string> send_mail(const Settings& s, const std::string& subj, const std::string& body,
                                   const std::optional<std::string>& password) {
    std::string bad;
    const auto recipients = parse_recipients(s.alert_emails, &bad);
    if (!recipients) throw MailError(tr("Neispravna adresa e-pošte: {address}", {{"address", bad}}));
    if (recipients->empty() || s.smtp_host.empty()) throw MailError(tr("Upišite SMTP poslužitelj i barem jednu adresu primatelja."));
    const std::string sender = !s.smtp_from.empty() ? s.smtp_from : !s.smtp_user.empty() ? s.smtp_user : recipients->front();

    std::string to;
    for (const auto& r : *recipients) to += (to.empty() ? "" : ", ") + r;
    std::string message = "From: " + sender + "\r\nTo: " + to + "\r\nSubject: " + header_utf8(subj) + "\r\n";
    const std::time_t t = now();
    std::tm gm{};
    gmtime_s(&gm, &t);
    char date[64];
    std::strftime(date, sizeof date, "%a, %d %b %Y %H:%M:%S +0000", &gm);
    message += std::string("Date: ") + date + "\r\nMessage-ID: <" + std::to_string(t) + "." + std::to_string(GetTickCount64()) +
               "@solarni-monitor>\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n"
               "Content-Transfer-Encoding: 8bit\r\n\r\n";
    for (char c : body) message += c == '\n' ? std::string("\r\n") : std::string(1, c);
    message += "\r\n";

    TempFiles files;
    const fs::path eml = temp_file(L".eml"), cfg = temp_file(L".cfg");
    files.paths = {eml, cfg};
    write_file_atomic(eml, message);
    const char* scheme = s.smtp_security == "ssl" ? "smtps" : "smtp";
    // Korisnik i lozinka idu u privremenu datoteku (-K), ne u naredbeni redak koji vide drugi procesi.
    std::string config = "url = " + quote_config(std::string(scheme) + "://" + s.smtp_host + ":" + std::to_string(s.smtp_port)) + "\n";
    if (!s.smtp_user.empty()) {
        const std::string pwd = password.value_or(unprotect_secret(s.smtp_password_enc));
        config += "user = " + quote_config(s.smtp_user + ":" + pwd) + "\n";
    }
    config += "mail-from = " + quote_config(sender) + "\n";
    for (const auto& r : *recipients) config += "mail-rcpt = " + quote_config(r) + "\n";
    write_file_atomic(cfg, config);

    std::wstring cmd = curl_command() + L" --silent --show-error --max-time 40 ";
    if (s.smtp_security == "starttls") cmd += L"--ssl-reqd ";
    if (const auto ip = source_ip(s.internet_interface)) cmd += L"--interface " + widen(*ip) + L" ";
    cmd += L"-K \"" + cfg.wstring() + L"\" --upload-file \"" + eml.wstring() + L"\"";
    const ProcessResult r = run_capture(cmd, kMailTimeoutMs);
    const std::string host = s.smtp_host + ":" + std::to_string(s.smtp_port);
    switch (r.exit_code) {
    case 0: break;
    case 67: throw MailError(tr("Poslužitelj e-pošte odbio je korisničko ime ili lozinku."));
    case 6: case 7: throw MailError(tr("Nije moguće spojiti se na {host}:{port} ({error}).",
                                       {{"host", s.smtp_host}, {"port", std::to_string(s.smtp_port)}, {"error", trim(r.output)}}));
    case 28: throw MailError(tr("Poslužitelj e-pošte {host}:{port} ne odgovara.", {{"host", s.smtp_host}, {"port", std::to_string(s.smtp_port)}}));
    case -1: throw MailError(tr("curl.exe nije dostupan ili nije odgovorio"));
    default: throw MailError(tr("Poslužitelj e-pošte javio je grešku: {error}", {{"error", trim(r.output)}}));
    }
    log_info("E-pošta „" + subj + "“ poslana na " + std::to_string(recipients->size()) + " adresa");
    return *recipients;
}

}  // namespace sm

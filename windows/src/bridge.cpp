// Pozivi iz JS-a (web/bridge.js → window.pywebview.api.<metoda>). Nazivi i oblik odgovora isti su kao
// u Python verziji (desktop/launcher.py MainApi i desktop/settings_api.py), pa sučelje radi bez izmjena.
#include <windows.h>

#include <functional>
#include <map>
#include <set>

#include "alerts.hpp"
#include "api.hpp"
#include "crypto.hpp"
#include "secret.hpp"
#include "serial.hpp"
#include "tls.hpp"
#include "app.hpp"
#include "cloud.hpp"
#include "dashboard.hpp"
#include "i18n.hpp"
#include "report.hpp"
#include "smartlogger_export.hpp"
#include "vendors.hpp"
#include "images.hpp"
#include "poller.hpp"
#include "modbus.hpp"
#include "net.hpp"
#include "system.hpp"
#include "util.hpp"

namespace sm {

namespace {

json ok(const std::string& message, json extra = json::object()) {
    extra["ok"] = true;
    extra["message"] = message;
    return extra;
}
json fail(const std::string& message, json extra = json::object()) {
    extra["ok"] = false;
    extra["message"] = message;
    return extra;
}

std::string arg_string(const json& args, size_t i) {
    return i < args.size() && args[i].is_string() ? args[i].get<std::string>() : std::string{};
}

std::vector<std::string> interface_names() {
    std::vector<std::string> names;
    for (const auto& i : list_interfaces()) names.push_back(i.name);
    return names;
}

std::optional<fs::path> legacy_db() {
    const wchar_t* pd = _wgetenv(L"PROGRAMDATA");
    for (const fs::path& p : {fs::path(pd ? pd : L"C:\\ProgramData") / L"SolarniMonitor" / L"data" / L"solar.db",
                              fs::path(L"C:\\solari\\data\\solar.db")}) {
        if (fs::exists(p)) return p;
    }
    return std::nullopt;
}

json remote_urls(const Settings& s) {
    json out = json::array();
    for (const auto& i : list_interfaces()) {
        if (i.is_up && !i.ipv4.empty() && !i.link_local_only) out.push_back("http://" + i.ipv4 + ":" + std::to_string(s.remote_port));
    }
    return out;
}

json screens_json() {
    json out = json::array();
    for (const auto& s : list_screens()) {
        out.push_back({{"index", s.index}, {"width", s.width}, {"height", s.height}, {"primary", s.primary}});
    }
    return out;
}

// ---------------------------------------------------------------- glavni prozor (dashboard i editor)
// Zadnji uspješni podaci s poslužitelja: kad tunel ili internet zakaže, ekran ostaje pun (oznaka "nedostupno").
std::mutex g_cloud_mutex;
json g_cloud_last;
std::time_t g_cloud_warned = 0;

json vendor_profiles_json();

json cloud_or_last(App& app, const Settings& s) {
    try {
        json d = cloud_dashboard(s, app.catalog());
        std::lock_guard lock(g_cloud_mutex);
        g_cloud_last = d;
        return d;
    } catch (const std::exception& e) {
        std::lock_guard lock(g_cloud_mutex);
        if (now() - g_cloud_warned > 300) {
            g_cloud_warned = now();
            log_warn(std::string("Poslužitelj: ") + e.what());
        }
        if (g_cloud_last.is_null()) throw;
        json d = g_cloud_last;
        d["realtime"]["stale"] = true;
        d["realtime"]["running"] = false;
        d.update(pages_json(load_pages(app.catalog(), layout_file())));
        apply_local_display(d["settings"], s);
        return d;
    }
}

json server_state(App& app) {
    const Settings s = app.settings();
    // lokalna mreža samo HTTPS (vlastiti certifikat); http samo za cloudflared na 127.0.0.1
    json urls = json::array({"http://127.0.0.1:" + std::to_string(s.server_port)});
    if (s.server_lan) {
        for (const auto& i : list_interfaces()) {
            if (i.is_up && !i.ipv4.empty() && !i.link_local_only) urls.push_back("https://" + i.ipv4 + ":" + std::to_string(s.server_port));
        }
    }
    std::optional<ServerCert> cert;
    try {
        cert = find_server_certificate();
        if (!cert && s.server_lan) cert = ensure_server_certificate();  // aplikacija bez servisa
    } catch (const std::exception& e) {
        log_warn(std::string("HTTPS: ") + e.what());
    }
    const auto me = app.admin();
    return {{"urls", urls}, {"in_app", app.api_port() != 0}, {"task", poller_task_installed()},
            {"certificate", cert ? json{{"fingerprint", cert->fingerprint}, {"not_after", cert->not_after}} : json(nullptr)},
            {"admin", me ? json{{"id", me->id}, {"name", me->first_name + " " + me->last_name}, {"email", me->email}} : json(nullptr)}};
}

// Prijava na Solarni poslužitelj (3.0): lozinka ide samo poslužitelju i ne sprema se; sprema se oznaka prijave
json cloud_login_call(App& app, const json& form) {
    const auto url = normalize_server_url(form.value("cloud_url", std::string{}));
    if (!url) return fail(tr("Upišite adresu poslužitelja, npr. https://solar.tvrtka.hr"));
    std::string password = form.value("password", std::string{});
    const Settings cur = app.settings();
    try {
        const CloudLogin r = cloud_login(*url, form.value("email", std::string{}), std::move(password),
                                         cur.cloud_url == *url ? cur.cloud_cert_pin : std::string{}, form.value("totp", std::string{}),
                                         form.value("new_password", std::string{}));
        if (cur.cloud_url != *url || !cur.cloud_token_enc.empty()) cloud_logout(cur);  // stara prijava ne ostaje aktivna
        app.update_settings([&](Settings& s) {
            s.cloud_url = *url;
            s.cloud_token_enc = protect_secret(r.token);
            s.cloud_account_enc = protect_secret(r.account.dump());
            s.cloud_cert_pin = r.pin;
        });
        log_info("Prijava na Solarni poslužitelj " + *url + (r.pin.empty() ? "" : " (otisak " + r.pin + ")"));
        return ok(tr("Prijavljeni ste kao {name}.", {{"name", r.account.value("name", "")}}),
                  {{"account", r.account}, {"pin", r.pin}, {"cloud_url", *url}, {"recovery_codes", r.recovery_codes}});
    } catch (const CloudTotpNeeded& e) {
        return fail(e.what(), {{"totp", e.info()}});
    } catch (const CloudPasswordChange& e) {
        return fail(e.what(), {{"password_change", true}});
    } catch (const std::exception& e) {
        return fail(e.what());
    }
}

json cloud_logout_call(App& app) {
    cloud_logout(app.settings());
    app.update_settings([](Settings& s) {
        s.cloud_token_enc.clear();
        s.cloud_account_enc.clear();
    });
    return ok(tr("Odjavljeni ste."));
}

// Izvještaj iz lokalne baze ili s poslužitelja (klijent u načinu Cloudflare)
json report_json(App& app, int year, int month) {
    const Settings s = app.settings();
    if (!app.server_role() && s.data_source == "cloud") {
        return cloud_json(s, "/api/v1/report?year=" + std::to_string(year) + "&month=" + std::to_string(month));
    }
    return build_report(app.data(), s, year, static_cast<unsigned>(month));
}

}  // namespace

json dashboard_json(App& app) {
    const Settings s = app.settings();
    json d = !app.server_role() && s.data_source == "cloud" ? cloud_or_last(app, s)
                                                             : build_dashboard(app.data(), app.weather(), app.catalog(), s);
    d["fullscreen"] = app.fullscreen();
    return d;
}

namespace {

// Mogućnosti uređaja za izbor widgeta: lokalni uređaj, a klijent preko tunela – uređaj poslužitelja.
json editor_capabilities(App& app) {
    const Settings s = app.settings();
    if (s.data_source != "cloud") return device_capabilities(s);
    try {
        return cloud_or_last(app, s).value("capabilities", json::array());
    } catch (const std::exception&) {
        return json::array();
    }
}

json get_editor(App& app) {
    const auto& c = app.catalog();
    json e = {{"catalog", c.raw["widgets"]}, {"categories", c.raw["categories"]},
              {"rotateChoices", kRotateChoices}, {"maxPages", kMaxPages}, {"cols", c.cols}, {"rows", c.rows},
              {"hasMeter", app.settings().meter_unit_id != 0}, {"fullscreen", app.fullscreen()},
              {"capabilities", editor_capabilities(app)},
              {"sidebarOpen", app.sidebar_open()}, {"version", SOLARI_VERSION}};
    e.update(pages_json(load_pages(c, layout_file())));
    return e;
}

json save_layout_call(App& app, const json& items, int page) {
    const auto r = validate_layout(app.catalog(), items);
    if (!r.errors.empty()) return fail(r.errors.front());
    try {
        save_page(app.catalog(), r.items, page, layout_file());
    } catch (const std::exception& e) {
        return fail(e.what());
    }
    log_info("Raspored widgeta spremljen (stranica " + std::to_string(page + 1) + ", " + std::to_string(r.items.size()) + " widgeta)");
    return {{"ok", true}, {"layout", layout_json(r.items)}};
}

json pages_reply(const Pages& pages) {
    json out = pages_json(pages);
    out["ok"] = true;
    return out;
}

int arg_int(const json& args, size_t i, int def = 0) {
    if (i >= args.size()) return def;
    if (args[i].is_number()) return args[i].get<int>();
    try {
        return args[i].is_string() ? std::stoi(args[i].get<std::string>()) : def;
    } catch (const std::exception&) {
        return def;
    }
}

json test_email(App& app, const json& form) {
    const auto v = validate_form(form, app.settings(), interface_names());
    Settings s = app.settings();
    if (!v.settings) {
        for (const char* key : {"alert_emails", "smtp_host", "smtp_port", "smtp_from", "smtp_user"}) {
            if (v.errors.count(key)) {
                json errors = json::object();
                for (const auto& [k, msg] : v.errors) errors[k] = msg;
                return fail(tr("Provjerite označena polja."), {{"errors", errors}});
            }
        }
    } else {
        s = *v.settings;  // ostala polja obrasca (npr. mrežna kartica) ne smiju spriječiti probnu poruku
    }
    const std::string pwd = form.value("smtp_password", std::string{});
    try {
        const auto m = test_message(s, now());
        const auto to = send_mail(s, m.subject, m.body, pwd.empty() ? std::nullopt : std::optional(pwd));
        std::string list;
        for (const auto& r : to) list += (list.empty() ? "" : ", ") + r;
        return ok(tr("Probna poruka poslana na: {to}", {{"to", list}}));
    } catch (const std::exception& e) {
        return fail(e.what());
    }
}

json get_report(App& app, int year, int month) {
    try {
        return ok("", {{"report", report_json(app, year, month)}});
    } catch (const std::exception& e) {
        return fail(e.what());
    }
}

// ---------------------------------------------------------------- postavke i čarobnjak
json get_state(App& app) {
    if (!app.settings_unlocked()) {
        if (!app.server_role()) return {{"locked", true}, {"version", SOLARI_VERSION}};
        json auth = {{"server", true}};
        try {
            auth["setup"] = !app.users().has_admin();
        } catch (const std::exception& e) {
            auth["error"] = tr("Podaci o korisnicima ne mogu se otvoriti na ovom računalu ({e}).", {{"e", e.what()}});
        }
        return {{"locked", true}, {"version", SOLARI_VERSION}, {"auth", auth}, {"language", app.settings().language},
                {"i18n", i18n_bundle(app.settings().language)}};
    }
    Settings s = app.settings();
    if (app.wizard()) {
        if (auto legacy = legacy_settings()) s = *legacy;
        s.language = system_language();  // čarobnjak počinje na jeziku Windowsa
        if (s.logger_interface.empty()) s.logger_interface = interface_for_host(s.modbus_host).value_or("");
        if (s.internet_interface.empty()) s.internet_interface = default_route_interface().value_or("");
    }
    json ifaces = json::array();
    for (const auto& i : list_interfaces()) ifaces.push_back(to_json(i));
    const auto legacy = legacy_db();
    set_language(s.language);
    return {
        {"i18n", i18n_bundle(s.language)},
        {"locked", false}, {"wizard", app.wizard()}, {"version", SOLARI_VERSION}, {"panel", app.settings_panel()},
        {"settings", to_form(s)}, {"interfaces", ifaces},
        {"suggested", {{"logger", interface_for_host(s.modbus_host).value_or("")},
                       {"internet", default_route_interface().value_or("")}}},
        {"screens", screens_json()},
        {"scales", {{"auto", "Automatski – prema veličini prozora"}, {"fhd", "Full HD – 1920 × 1080"},
                    {"2k", "2K (QHD) – 2560 × 1440"}, {"4k", "4K (UHD) – 3840 × 2160"}}},
        {"autostart", app.wizard() ? true : autostart_enabled()},
        {"poller_task", poller_task_installed()},
        {"paths", {{"config", narrow(config_file().wstring())}, {"data", narrow(data_dir().wstring())},
                   {"logs", narrow(logs_dir().wstring())}}},
        {"db", app.data().db_info()},
        {"legacy_db", legacy ? json(narrow(legacy->wstring())) : json(nullptr)},
        {"smartlogger_import", true},
        {"device_types", json::array({"logger", "inverter", "sunspec", "fronius", "vendor", "voltronic", "vedirect"})},
        {"serial_ports", list_serial_ports()},
        {"device_profiles", vendor_profiles_json()},
        {"images", {{"hero", image_info("hero")}, {"drawing", image_info("drawing")}, {"logo", image_info("logo")}}},
        {"remote_urls", remote_urls(s)},
        {"role", app.server_role() ? "server" : "client"},
        {"features", {{"cloud", true}}},
        {"server", app.server_role() ? server_state(app) : json(nullptr)},
    };
}

std::string subnet_hint(const json& form) {
    const std::string iface = form.value("logger_interface", ""), host = form.value("modbus_host", "");
    if (!iface.empty() && reaches(iface, host) == std::optional(false)) {
        return " " + tr("Napomena: {host} nije u mreži kartice „{iface}“ – provjerite IP adresu kartice ili postoji li "
                        "ruta do uređaja.", {{"host", host}, {"iface", iface}});
    }
    return "";
}

json test_logger(App& app, const json& form) {
    NetInit net;
    try {
        auto num = [&](const char* k, int def) {
            const json& v = form.contains(k) ? form[k] : json(def);
            return v.is_number() ? v.get<int>() : std::stoi(v.get<std::string>());
        };
        Settings s = app.settings();
        s.modbus_host = trim(form.value("modbus_host", ""));
        s.modbus_port = num("modbus_port", 502);
        s.modbus_unit_id = num("modbus_unit_id", 0);
        s.meter_unit_id = num("meter_unit_id", 0);
        s.device_type = form.value("device_type", "logger");
        s.inverter_units = form.value("inverter_units", "1");
        s.device_profile = form.value("device_profile", s.device_profile);
        s.logger_serial = trim(form.value("logger_serial", s.logger_serial));
        if (form.contains("meter_invert") && form["meter_invert"].is_boolean()) s.meter_invert = form["meter_invert"].get<bool>();
        if (form.contains("meter_export_positive") && form["meter_export_positive"].is_boolean()) {
            s.meter_export_positive = form["meter_export_positive"].get<bool>();
        }
        s.logger_interface = form.value("logger_interface", "");
        s.serial_port = trim(form.value("serial_port", s.serial_port));
        for (auto& c : s.serial_port) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        s.serial_baud = form.contains("serial_baud") ? num("serial_baud", 0) : s.serial_baud;
        const bool serial = is_serial_device(s.device_type, s.device_profile);
        const auto src = serial ? std::nullopt : source_ip(s.logger_interface);
        const PlantReading p = read_plant(s);
        const std::string today = p.reading.e_daily_kwh < 0 ? "—" : fmt_num(p.reading.e_daily_kwh, 1);
        const std::string total = p.reading.e_total_kwh < 0 ? "—" : fmt_num(p.reading.e_total_kwh, 0);
        std::string meter;
        if (!p.meter_error.empty()) meter = " · " + tr("mjerač nije odgovorio ({error})", {{"error", p.meter_error}});
        else if (p.load_kw) meter = " · " + tr("mjerač {kw} kW", {{"kw", fmt_num(*p.load_kw, 2)}});
        const std::string via = serial ? " " + tr("na {port}", {{"port", s.serial_port.empty() ? "USB" : s.serial_port}})
                                : src ? " " + tr("preko {ip}", {{"ip", *src}}) : "";
        if (p.extra.contains("battery_soc") || p.extra.contains("battery_v")) {  // otočni sustav: baterija
            std::string b;
            if (p.extra.contains("battery_soc")) b += fmt_num(p.extra["battery_soc"].get<double>(), 0) + " %";
            if (p.extra.contains("battery_v")) b += (b.empty() ? "" : " / ") + fmt_num(p.extra["battery_v"].get<double>(), 1) + " V";
            meter += " · " + tr("baterija {b}", {{"b", b}});
        }
        const std::string device = !p.device_name.empty() ? p.device_name
                                   : s.device_type == "logger" ? tr("Logger") : tr("Inverter");
        return ok(tr("{device} odgovara{via}: snaga {kw} kW · danas {today} kWh · ukupno {total} kWh",
                     {{"device", device}, {"via", via},
                      {"kw", fmt_num(p.reading.power_kw, 2)}, {"today", today},
                      {"total", total}}) + meter);
    } catch (const std::exception& e) {
        return fail(e.what() + subnet_hint(form));
    }
}

json test_internet(const json& form) {
    NetInit net;
    try {
        auto num = [&](const char* k, double def) {
            if (!form.contains(k)) return def;
            if (form[k].is_number()) return form[k].get<double>();
            std::string s = form[k].get<std::string>();
            for (auto& c : s) if (c == ',') c = '.';
            return std::stod(s);
        };
        const auto ip = source_ip(form.value("internet_interface", ""));
        const json w = WeatherService::fetch(num("weather_lat", 45.815), num("weather_lon", 15.982), ip.value_or(""));
        return ok(tr("Internet radi – prognoza: {temp} °C, {label}, sunčevo zračenje {rad} W/m²",
                     {{"temp", fmt_num(w["temperature"].get<double>(), 0)}, {"label", tr(weather_label(w["code"].get<int>()))},
                      {"rad", fmt_num(w["radiation_wm2"].get<double>(), 0)}}));
    } catch (const std::exception& e) {
        return fail(tr("Internet nije dostupan: {error}", {{"error", e.what()}}));
    }
}

json save_settings_call(App& app, const json& form) {
    const auto v = validate_form(form, app.settings(), interface_names());
    if (!v.settings) {
        json errors = json::object();
        for (const auto& [k, msg] : v.errors) errors[k] = msg;
        return fail(tr("Provjerite označena polja."), {{"errors", errors}});
    }
    try {
        set_autostart(form.value("autostart", false));
    } catch (const std::exception& e) {
        log_warn(std::string("Pokretanje pri prijavi: ") + e.what());
    }
    try {
        app.apply_settings(*v.settings);
    } catch (const std::exception& e) {
        return fail(tr("Postavke nisu spremljene: {error}", {{"error", e.what()}}));
    }
    return ok(tr("Postavke su spremljene."));
}

// Tablice proizvođača za postavke: naziv, uobičajeni port i adresa, veza, ima li mjerač i energiju.
json vendor_profiles_json() {
    json out = json::array();
    for (const auto& p : vendor_profiles()) {
        out.push_back({{"key", p.key}, {"name", p.name}, {"port", p.port}, {"unit", p.unit},
                       {"link", p.link == VendorLink::Solarman ? "solarman" : p.link == VendorLink::GoodweUdp ? "goodwe"
                                : p.link == VendorLink::Serial ? "serial" : "tcp"},
                       {"meter", !p.meter.empty()}, {"energy", p.total.has_value()}});
    }
    return out;
}

json import_smartlogger(App& app, const fs::path& source) {
    try {
        const auto days = parse_perfmg_day(read_perfmg_day(source));
        if (days.empty()) return fail(tr("U izvozu nema dnevne proizvodnje elektrane."));
        Db db(db_file());
        const ExportImport r = import_perfmg_days(db, days, local_date(now()));
        log_info("Izvoz SmartLoggera " + narrow(source.wstring()) + ": uvezeno " + std::to_string(r.imported) +
                 " dana, preskočeno " + std::to_string(r.skipped));
        std::string msg = r.imported
            ? tr("Uvezeno {n} dana ({from} – {to}, {kwh} kWh).", {{"n", std::to_string(r.imported)},
                  {"from", iso_date(*r.first)}, {"to", iso_date(*r.last)}, {"kwh", fmt_num(r.kwh, 0)}})
            : tr("Nema novih dana za uvoz.");
        if (r.skipped) msg += " " + tr("Preskočeno {n} dana koji već imaju podatke u bazi.", {{"n", std::to_string(r.skipped)}});
        return ok(msg, {{"db", app.data().db_info()}, {"imported", r.imported}, {"skipped", r.skipped}});
    } catch (const std::exception& e) {
        log_warn("Izvoz SmartLoggera " + narrow(source.wstring()) + ": " + e.what());
        return fail(e.what());
    }
}

json import_history(App& app, const fs::path& source) {
    try {
        const int64_t added = Db(db_file()).import_history(source);
        log_info("Uvezeno " + std::to_string(added) + " očitanja iz " + narrow(source.wstring()));
        return ok(tr("Uvezeno {n} očitanja.", {{"n", fmt_num(static_cast<double>(added), 0)}}), {{"db", app.data().db_info()}});
    } catch (const std::exception& e) {
        return fail(e.what());
    }
}

// ---------------------------------------------------------------- korisnici poslužitelja (3.0)
UserInput user_input(const json& f) {
    auto s = [&](const char* k) { return f.contains(k) && f[k].is_string() ? f[k].get<std::string>() : std::string{}; };
    const bool totp = f.contains("totp_required") && f["totp_required"].is_boolean() && f["totp_required"].get<bool>();
    return {s("first_name"), s("last_name"), s("email"), s("password"), parse_role(s("role")).value_or(Role::User), totp};
}

json user_row(App& app, const UserInfo& u) {
    const auto me = app.admin();
    return {{"id", u.id}, {"first_name", u.first_name}, {"last_name", u.last_name}, {"email", u.email},
            {"role", role_name(u.role)}, {"disabled", u.disabled}, {"created", u.created}, {"last_login", u.last_login},
            {"locked", u.locked_until > now()}, {"sessions", app.users().active_sessions(u.id, now())},
            {"me", me && me->id == u.id}, {"totp_required", u.totp_required}, {"totp_enabled", u.totp_enabled},
            {"recovery_left", u.recovery_left}, {"must_change_password", u.must_change_password},
            {"default_expired", u.must_change_password && u.default_password_until < now()}};
}

json users_list(App& app) {
    json rows = json::array();
    for (const auto& u : app.users().list()) rows.push_back(user_row(app, u));
    return {{"ok", true}, {"users", rows}};
}

json user_save(App& app, const json& form) {
    const int64_t id = form.contains("id") && form["id"].is_number_integer() ? form["id"].get<int64_t>() : 0;
    UserInput in = user_input(form);
    const auto me = app.admin();
    if (me && id == me->id && in.role != Role::Admin) {
        return {{"ok", false}, {"errors", {{"role", tr("Ne možete sami sebi oduzeti administratorska prava.")}}},
                {"message", tr("Provjerite označena polja.")}};
    }
    try {
        if (id) app.users().update(id, in, now());
        else app.users().create(in, now());
    } catch (const UserError& e) {
        wipe(in.password);
        return {{"ok", false}, {"errors", e.fields}, {"message", tr("Provjerite označena polja.")}};
    }
    const bool new_password = !in.password.empty();
    wipe(in.password);
    log_info(std::string("Korisnici: ") + (id ? "izmijenjen korisnik #" + std::to_string(id) : "dodan korisnik") +
             (me ? " (administrator #" + std::to_string(me->id) + ")" : ""));
    json r = users_list(app);
    r["message"] = id ? (new_password ? tr("Spremljeno. Nova lozinka vrijedi odmah – korisnik se mora ponovno prijaviti.") : tr("Spremljeno."))
                      : new_password ? tr("Korisnik je dodan.")
                                     : tr("Korisnik je dodan s početnom lozinkom 12345678 – pri prvoj prijavi mora je promijeniti (rok 7 dana).");
    return r;
}

json user_set_disabled(App& app, int64_t id, bool disabled) {
    const auto me = app.admin();
    if (me && me->id == id) return fail(tr("Ne možete blokirati sami sebe."));
    try {
        app.users().set_disabled(id, disabled, now());
    } catch (const UserError& e) {
        return fail(e.what());
    }
    log_info("Korisnici: korisnik #" + std::to_string(id) + (disabled ? " blokiran" : " odblokiran"));
    json r = users_list(app);
    r["message"] = disabled ? tr("Korisnik je blokiran i odjavljen sa svih uređaja.") : tr("Korisnik je odblokiran.");
    return r;
}

json user_reset_password(App& app, int64_t id) {
    const auto me = app.admin();
    if (me && me->id == id) return fail(tr("Svoju lozinku promijenite tako da upišete novu."));
    app.users().reset_to_default_password(id, now());
    log_info("Korisnici: početna lozinka ponovno postavljena korisniku #" + std::to_string(id));
    json r = users_list(app);
    r["message"] = tr("Postavljena je početna lozinka 12345678 (vrijedi 7 dana) – korisnik je mora promijeniti pri prijavi.");
    return r;
}

json user_reset_totp(App& app, int64_t id) {
    app.users().reset_totp(id, now());
    log_info("Korisnici: poništena dvofaktorska prijava korisnika #" + std::to_string(id));
    json r = users_list(app);
    r["message"] = tr("Dvofaktorska prijava je poništena – korisnik je pri sljedećoj prijavi ponovno postavlja (novi QR kod).");
    return r;
}

json user_delete(App& app, int64_t id) {
    const auto me = app.admin();
    if (me && me->id == id) return fail(tr("Ne možete obrisati sami sebe."));
    try {
        app.users().remove(id);
    } catch (const UserError& e) {
        return fail(e.what());
    }
    log_info("Korisnici: obrisan korisnik #" + std::to_string(id));
    json r = users_list(app);
    r["message"] = tr("Korisnik je obrisan.");
    return r;
}

// ---------------------------------------------------------------- raspodjela poziva
constexpr const char* kAsyncError = "__async_error";  // greška iz radne niti → odgovor ok=false
using Reply = std::function<void(json)>;

// Metode koje traju (mreža, baza, slike) idu u radnu nit; one koje diraju prozore ostaju u GUI niti.
void call(App& app, WindowKind kind, const std::string& method, const json& args, const Reply& reply) {
    // greška u radnoj niti mora stići do stranice (inače bi npr. dashboard zauvijek čekao)
    auto async = [&app, reply](std::function<json()> work) {
        app.run_async([reply, work] {
            try {
                reply(work());
            } catch (const std::exception& e) {
                reply(json{{kAsyncError, e.what()}});
            }
        });
    };
    const bool locked = kind == WindowKind::Settings && !app.settings_unlocked();
    const std::set<std::string> kPublic = {"get_state", "unlock", "close", "get_i18n", "admin_login", "setup_admin", "window_control",
                                           "window_state"};
    if (locked && !kPublic.count(method)) throw std::runtime_error(tr("Postavke su zaključane PIN-om."));

    // ---- glavni prozor
    if (method == "get_dashboard") return async([&app] { return dashboard_json(app); });
    if (method == "get_editor") return reply(get_editor(app));
    if (method == "save_layout") return reply(save_layout_call(app, args.empty() ? json::array() : args[0], arg_int(args, 1)));
    if (method == "remove_page") return reply(pages_reply(remove_page(app.catalog(), arg_int(args, 0, -1), layout_file())));
    if (method == "set_rotation") {
        try {
            return reply(pages_reply(set_rotation(app.catalog(), arg_int(args, 0, -1), layout_file())));
        } catch (const std::exception& e) {
            return reply(fail(e.what()));
        }
    }
    if (method == "reset_layout") {
        std::error_code ec;
        fs::remove(layout_file(), ec);
        return reply(pages_reply(load_pages(app.catalog(), layout_file())));
    }
    if (method == "set_display") { app.set_display(!args.empty() && args[0].is_boolean() && args[0].get<bool>()); return reply(nullptr); }
    if (method == "set_sidebar") { app.set_sidebar(!args.empty() && args[0].is_boolean() && args[0].get<bool>()); return reply(nullptr); }
    if (method == "toggle_fullscreen") { app.toggle_fullscreen(); return reply(app.fullscreen()); }
    if (method == "exit_fullscreen") { if (app.fullscreen()) app.toggle_fullscreen(); return reply(false); }
    if (method == "open_settings") { app.open_settings(arg_string(args, 0)); return reply(nullptr); }
    if (method == "reload") { app.reload_dashboard(); return reply(nullptr); }
    if (method == "quit") { app.quit(); return reply(nullptr); }
    if (method == "open_logs") { open_path(logs_dir()); return reply(nullptr); }
    if (method == "window_control") { app.window_control(kind, arg_string(args, 0)); return reply(app.window_state(kind)); }
    if (method == "window_state") return reply(app.window_state(kind));

    // ---- postavke
    if (method == "get_state") return async([&app] { return get_state(app); });
    if (method == "unlock") return reply(app.unlock(arg_string(args, 0)));
    if (method == "admin_login" && app.server_role()) {
        return async([&app, email = arg_string(args, 0), pw = arg_string(args, 1), totp = arg_string(args, 2),
                      npw = arg_string(args, 3)]() mutable {
            json r = app.admin_login(email, std::move(pw), totp, std::move(npw));
            wipe(pw);
            return r;
        });
    }
    if (method == "setup_admin" && app.server_role()) {
        return async([&app, form = args.at(0)] { return app.setup_admin(user_input(form)); });
    }
    if (method == "get_i18n") {
        set_language(arg_string(args, 0));
        return reply(i18n_bundle(language()));
    }
    if (method == "interfaces") {
        json out = json::array();
        for (const auto& i : list_interfaces()) out.push_back(to_json(i));
        return reply(out);
    }
    if (method == "test_logger") return async([&app, form = args.at(0)] { return test_logger(app, form); });
    if (method == "test_internet") return async([form = args.at(0)] { return test_internet(form); });
    if (method == "serial_ports") return reply(list_serial_ports());
    if (method == "geocode") {
        return async([name = arg_string(args, 0), iface = arg_string(args, 1), lang = arg_string(args, 2)] {
            NetInit net;
            try {
                const json places = WeatherService::geocode(name, lang, source_ip(iface).value_or(""));
                if (places.empty()) return fail(tr("Mjesto „{name}” nije pronađeno.", {{"name", name}}));
                return ok("", {{"places", places}});
            } catch (const std::exception& e) {
                return fail(tr("Internet nije dostupan: {error}", {{"error", e.what()}}));
            }
        });
    }
    if (method == "save") return reply(save_settings_call(app, args.at(0)));
    if (method == "test_email") return async([&app, form = args.at(0)] { return test_email(app, form); });
    if (method == "cloud_login") return async([&app, form = args.at(0)] { return cloud_login_call(app, form); });
    if (method == "cloud_logout") return async([&app] { return cloud_logout_call(app); });
    if (app.server_role()) {  // korisnici poslužitelja (samo prijavljeni administrator – vidi provjeru gore)
        if (method == "users_list") return async([&app] { return users_list(app); });
        if (method == "user_save") return async([&app, form = args.at(0)] { return user_save(app, form); });
        if (method == "user_set_disabled") {
            return async([&app, id = arg_int(args, 0), off = args.size() > 1 && args[1].is_boolean() && args[1].get<bool>()] {
                return user_set_disabled(app, id, off);
            });
        }
        if (method == "user_delete") return async([&app, id = arg_int(args, 0)] { return user_delete(app, id); });
        if (method == "user_reset_totp") return async([&app, id = arg_int(args, 0)] { return user_reset_totp(app, id); });
        if (method == "user_reset_password") return async([&app, id = arg_int(args, 0)] { return user_reset_password(app, id); });
        if (method == "admin_logout") { app.admin_logout(); app.close_settings(); return reply(nullptr); }
    }
    if (method == "get_report") {
        return async([&app, y = arg_int(args, 0), m = arg_int(args, 1)] { return get_report(app, y, m); });
    }
    if (method == "save_report_csv") {
        const int y = arg_int(args, 0), m = arg_int(args, 1);
        std::string name = app.settings().plant_name + "-" + std::to_string(y) + "-" + (m < 10 ? "0" : "") + std::to_string(m) + ".csv";
        for (auto& c : name) if (!std::isalnum(static_cast<unsigned char>(c)) && c != '-' && c != '_' && c != '.') c = '_';
        const auto target = pick_save_file(app.settings_hwnd(), widen(tr("Excel (CSV)")), widen(tr("Tablica za Excel")) + L" (*.csv)",
                                           L"*.csv", widen(name));
        if (!target) return reply(fail("", {{"cancelled", true}}));
        return async([&app, y, m, path = *target] {
            try {
                const json r = report_json(app, y, m);
                write_file_atomic(path, report_csv(r));
                return ok(tr("Spremljeno: {path}", {{"path", narrow(path.wstring())}}));
            } catch (const std::exception& e) {
                return fail(e.what());
            }
        });
    }
    if (method == "import_history") {
        std::optional<fs::path> source;
        if (const std::string p = arg_string(args, 0); !p.empty()) source = fs::path(widen(p));
        else source = pick_file(app.settings_hwnd(), widen(tr("Uvezi povijest iz datoteke (solar.db)…")), widen(tr("Baza podataka")) + L" (*.db)", L"*.db");
        if (!source) return reply(fail(tr("Uvoz otkazan."), {{"cancelled", true}}));
        return async([&app, src = *source] { return import_history(app, src); });
    }
    if (method == "import_smartlogger") {
        std::optional<fs::path> source;
        if (const std::string p = arg_string(args, 0); !p.empty()) source = fs::path(widen(p));
        else source = pick_file(app.settings_hwnd(), widen(tr("Uvezi povijest sa SmartLoggera (log.zip)…")),
                                widen(tr("Izvoz SmartLoggera")) + L" (*.zip;*.emap)", L"*.zip;*.emap");
        if (!source) return reply(fail(tr("Uvoz otkazan."), {{"cancelled", true}}));
        return async([&app, src = *source] { return import_smartlogger(app, src); });
    }
    if (method == "choose_image" || method == "reset_image") {
        const std::string kind_name = arg_string(args, 0);
        if (!is_image_kind(kind_name)) return reply(fail(tr("Nepoznata slika.")));
        if (method == "reset_image") {
            reset_image(kind_name);
            app.reload_dashboard();
            return async([kind_name] { return ok(tr("Vraćena je izvorna slika."), {{"image", image_info(kind_name)}}); });
        }
        const auto picked = pick_file(app.settings_hwnd(), widen(tr("Odaberite sliku")), widen(tr("Slike")) + L" (*.jpg;*.jpeg;*.png;*.webp)",
                                      L"*.jpg;*.jpeg;*.png;*.webp");
        if (!picked) return reply(fail("", {{"cancelled", true}}));
        return async([&app, kind_name, src = *picked] {
            try {
                json info = replace_image(kind_name, src);
                app.post_ui([&app] { app.reload_dashboard(); });
                return ok(info["message"], {{"image", info}});
            } catch (const std::exception& e) {
                return fail(e.what());
            }
        });
    }
    if (method == "open_folder") {
        const std::string what = arg_string(args, 0);
        open_path(what == "logs" ? logs_dir() : what == "app" ? exe_dir() : data_dir());
        return reply(nullptr);
    }
    if (method == "close") { app.close_settings(); return reply(nullptr); }
    throw std::runtime_error("Nepoznata metoda: " + method);
}

}  // namespace

void dispatch(App& app, WindowKind kind, const json& msg) {
    const json id = msg.value("id", json(nullptr));
    const std::string method = msg.value("method", "");
    const json args = msg.value("args", json::array());
    auto reply = [&app, kind, id](json result) {
        if (result.is_object() && result.size() == 1 && result.contains(kAsyncError)) {
            app.reply(kind, {{"id", id}, {"ok", false}, {"error", result[kAsyncError]}});
            return;
        }
        app.reply(kind, {{"id", id}, {"ok", true}, {"result", std::move(result)}});
    };
    try {
        call(app, kind, method, args, reply);
    } catch (const std::exception& e) {
        log_warn("Poziv " + method + ": " + e.what());
        app.reply(kind, {{"id", id}, {"ok", false}, {"error", e.what()}});
    }
}

}  // namespace sm

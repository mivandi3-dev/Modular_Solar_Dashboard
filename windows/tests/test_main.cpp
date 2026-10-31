// Testovi jezgre (bez GUI-ja): postavke i obrazac, PIN, raspored, Modbus dekodiranje, dnevni izračun, baza, mreža.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <windows.h>

#include <cstring>
#include <atomic>
#include <functional>
#include <map>
#include <set>
#include <mutex>
#include <thread>

#include <winsock2.h>
#include <sqlite3.h>

#include "alerts.hpp"
#include "api.hpp"
#include "config.hpp"
#include "dashboard.hpp"
#include "data.hpp"
#include "layout.hpp"
#include "modbus.hpp"
#include "net.hpp"
#include "remote.hpp"
#include "secret.hpp"
#include "smartlogger_export.hpp"
#include "sunspec.hpp"
#include "fronius.hpp"
#include "vendors.hpp"
#include "poller.hpp"
#include "i18n.hpp"
#include "storage.hpp"
#include "system.hpp"
#include "util.hpp"
#include "crypto.hpp"
#include "users.hpp"
#include "totp.hpp"
#include "weather.hpp"
#include "offgrid.hpp"
#include "serial.hpp"
#include "tls.hpp"
#include "cloud.hpp"

using namespace sm;

namespace {

const fs::path kSource = SOLARI_SOURCE_DIR;

struct TempDir {
    fs::path path;
    TempDir() {
        path = fs::temp_directory_path() / (L"solari2_test_" + std::to_wstring(GetCurrentProcessId()) + L"_" +
                                            std::to_wstring(GetTickCount64()));
        fs::create_directories(path);
    }
    ~TempDir() {
        std::error_code ec;
        fs::remove_all(path, ec);
    }
};

json valid_form() {
    json f = to_form(Settings{});
    f["logger_interface"] = "Ethernet";
    f["internet_interface"] = "Wi-Fi";
    return f;
}
const std::vector<std::string> kIfaces = {"Ethernet", "Wi-Fi"};

std::time_t utc(int y, int m, int d, int H, int M = 0) {
    std::tm tm{};
    tm.tm_year = y - 1900; tm.tm_mon = m - 1; tm.tm_mday = d; tm.tm_hour = H; tm.tm_min = M;
    return _mkgmtime(&tm);
}

Date date(int y, unsigned m, unsigned d) { return Date{std::chrono::year{y}, std::chrono::month{m}, std::chrono::day{d}}; }

}  // namespace

// ---------------------------------------------------------------- postavke
TEST_CASE("postavke: JSON u oba smjera čuva sve vrijednosti") {
    Settings s;
    s.plant_name = "Elektrana \"Sjever\" – č ć š đ ž";
    s.logger_interface = "Ethernet 2";
    s.display_scale = "4k";
    s.peak_power_kwp = 99.5;
    s.start_fullscreen = false;
    CHECK(settings_from_json(to_json(s)) == s);
}

TEST_CASE("postavke: mjerač na loggeru je zadano uključen (adresa 1)") {
    CHECK(Settings{}.meter_unit_id == 1);
    CHECK(settings_from_json(json::object()).meter_unit_id == 1);
    CHECK(settings_from_json({{"meter_unit_id", 0}}).meter_unit_id == 0);
}

TEST_CASE("postavke: nepoznata tema i razlučivost padaju na zadane") {
    const Settings s = settings_from_json({{"theme", "pink"}, {"display_scale", "8k"}, {"modbus_port", "nije broj"}});
    CHECK(s.theme == "dark");
    CHECK(s.display_scale == "auto");
    CHECK(s.modbus_port == 502);
}

TEST_CASE("obrazac: decimalni zarez i ispravne vrijednosti") {
    json f = valid_form();
    f["peak_power_kwp"] = "80,5";
    f["co2_factor"] = "0,25";
    const auto v = validate_form(f, Settings{}, kIfaces);
    REQUIRE(v.errors.empty());
    CHECK(v.settings->peak_power_kwp == doctest::Approx(80.5));
    CHECK(v.settings->co2_factor == doctest::Approx(0.25));
}

TEST_CASE("obrazac: greške po poljima") {
    const std::vector<std::pair<std::string, json>> cases = {
        {"modbus_host", "192.168.5"}, {"modbus_host", "logger nije"}, {"modbus_port", "0"}, {"modbus_unit_id", "248"},
        {"poll_interval_s", "2"}, {"poll_interval_s", "10,5"}, {"weather_lat", "91"}, {"plant_name", ""},
        {"display_scale", "8k"}, {"theme", "pink"}, {"pin_new", "12a4"}, {"logger_interface", ""},
        {"internet_interface", "VPN"},
    };
    for (const auto& [field, value] : cases) {
        json f = valid_form();
        f[field] = value;
        const auto v = validate_form(f, Settings{}, kIfaces);
        CAPTURE(field);
        CHECK(v.errors.count(field) == 1);
    }
}

TEST_CASE("obrazac: naslov u zaglavlju") {
    json f = valid_form();
    f["headline"] = "Naša elektrana";
    f["headline_running"] = "radi *punom snagom*";
    const auto v = validate_form(f, Settings{}, kIfaces);
    REQUIRE(v.errors.empty());
    CHECK(v.settings->headline == "Naša elektrana");
    CHECK(v.settings->headline_running == "radi *punom snagom*");
    f["headline"] = "";
    CHECK(validate_form(f, Settings{}, kIfaces).errors.count("headline") == 1);
    f["headline"] = "x";
    f["headline_idle"] = std::string(61, 'x');
    CHECK(validate_form(f, Settings{}, kIfaces).errors.count("headline_idle") == 1);
}

TEST_CASE("obrazac: naziv računala kao adresa loggera i automatska kartica za internet") {
    json f = valid_form();
    f["modbus_host"] = "smartlogger.local";
    f["internet_interface"] = "";
    CHECK(validate_form(f, Settings{}, kIfaces).errors.empty());
}

TEST_CASE("PIN: postavljanje, provjera i uklanjanje") {
    json f = valid_form();
    f["pin_new"] = "2468";
    const Settings with_pin = *validate_form(f, Settings{}, kIfaces).settings;
    CHECK(check_pin("2468", with_pin.settings_pin_hash));
    CHECK_FALSE(check_pin("1357", with_pin.settings_pin_hash));
    CHECK_FALSE(check_pin("2468", "neispravno"));
    CHECK_FALSE(to_form(with_pin).contains("settings_pin_hash"));

    json clear = valid_form();
    clear["pin_clear"] = true;
    CHECK(validate_form(clear, with_pin, kIfaces).settings->settings_pin_hash.empty());
}

TEST_CASE("PIN: kompatibilan s Python verzijom (PBKDF2-SHA256, 200.000 iteracija)") {
    // hash iz Python verzije: desktop.forms.hash_pin("1234", bytes(16))
    const std::string python =
        "pbkdf2$00000000000000000000000000000000$d5fd5b66d8f899844a8456f49c33f5a7b78f840ae4a53abfba45a6f047cb6c51";
    CHECK(hash_pin("1234", std::vector<uint8_t>(16, 0)) == python);
    CHECK(check_pin("1234", python));
}

// ---------------------------------------------------------------- raspored
TEST_CASE("raspored: zadani raspored je ispravan i ispunjava ekran") {
    const Catalog c = load_catalog(kSource / L"web" / L"catalog.json");
    const auto r = validate_layout(c, c.default_layout);
    CHECK(r.errors.empty());
    int area = 0;
    for (const auto& p : r.items) area += p.w * p.h;
    CHECK(area == c.cols * c.rows);
}

TEST_CASE("raspored: svaki widget stane u zadanoj i najmanjoj veličini") {
    const Catalog c = load_catalog(kSource / L"web" / L"catalog.json");
    CHECK(c.widgets.size() == 31);  // uključujući Ušteda i Stvarno i prognoza
    for (const auto& w : c.widgets) {
        for (auto [ww, hh] : {std::pair{w.w, w.h}, std::pair{w.min_w, w.min_h}}) {
            const auto r = validate_layout(c, json::array({{{"id", "a"}, {"type", w.key}, {"x", 0}, {"y", 0}, {"w", ww}, {"h", hh}}}));
            CAPTURE(w.key);
            CHECK(r.errors.empty());
        }
    }
}

TEST_CASE("raspored: preklapanje, izlazak iz ekrana, veličina i opcije") {
    const Catalog c = load_catalog(kSource / L"web" / L"catalog.json");
    auto errors = [&](const json& items) { return validate_layout(c, items).errors; };
    CHECK(errors(json::array({{{"id", "a"}, {"type", "clock"}, {"x", 0}, {"y", 0}, {"w", 3}, {"h", 1}},
                              {{"id", "b"}, {"type", "clock"}, {"x", 2}, {"y", 0}, {"w", 3}, {"h", 1}}})).size() == 1);
    CHECK(errors(json::array({{{"id", "a"}, {"type", "clock"}, {"x", 11}, {"y", 0}, {"w", 2}, {"h", 1}}})).size() == 1);
    CHECK(errors(json::array({{{"id", "a"}, {"type", "clock"}, {"x", 0}, {"y", 0}, {"w", 1}, {"h", 1}}})).size() == 1);
    CHECK(errors(json::array({{{"id", "a"}, {"type", "nema"}, {"x", 0}, {"y", 0}, {"w", 1}, {"h", 1}}})).size() == 1);
    const auto r = validate_layout(c, json::array({{{"id", "b"}, {"type", "bars"}, {"x", 0}, {"y", 0}, {"w", 5}, {"h", 2},
                                                    {"options", {{"days", "7"}}}}}));
    REQUIRE(r.errors.empty());
    CHECK(r.items[0].options["days"] == 7);
}

TEST_CASE("raspored: stranice, izmjena, stari format i oštećena datoteka") {
    TempDir dir;
    const Catalog c = load_catalog(kSource / L"web" / L"catalog.json");
    const fs::path file = dir.path / L"layout.json";
    auto items = validate_layout(c, json::array({{{"id", "c1"}, {"type", "clock"}, {"x", 0}, {"y", 0}, {"w", 3}, {"h", 1}}})).items;
    save_page(c, items, 0, file);
    save_page(c, {}, 1, file);  // nova (prazna) stranica
    set_rotation(c, 20, file);
    Pages p = load_pages(c, file);
    CHECK(p.pages.size() == 2);
    CHECK(p.pages[0].size() == 1);
    CHECK(p.rotate_s == 20);
    CHECK_THROWS(save_page(c, items, 1, file));  // "c1" je već na prvoj stranici
    CHECK_THROWS(set_rotation(c, 7, file));
    CHECK(remove_page(c, 1, file).pages.size() == 1);
    CHECK(remove_page(c, 0, file).pages.size() == 1);  // zadnja stranica ostaje
    write_file_atomic(file, R"({"version": 1, "widgets": [{"id": "c", "type": "clock", "x": 0, "y": 0, "w": 3, "h": 1}]})");
    CHECK(load_pages(c, file).pages.at(0).size() == 1);
    write_file_atomic(file, "{ neispravno");
    CHECK(load_pages(c, file).pages.at(0).size() == c.default_layout.size());
}

// ---------------------------------------------------------------- ušteda, obavijesti, izvještaj, pregled iz mreže
TEST_CASE("ušteda: višak po otkupnoj cijeni, bez mjerača sve po cijeni iz mreže") {
    Settings s;
    s.price_kwh = 0.20;
    s.feedin_price_kwh = 0.05;
    CHECK(savings(s, 100, 40.0) == doctest::Approx(60 * 0.20 + 40 * 0.05));
    CHECK(savings(s, 100, std::nullopt) == doctest::Approx(20.0));
}

TEST_CASE("dnevna potrošnja, predaja i mreža iz satnih prosjeka mjerača") {
    TempDir dir;
    Db db(dir.path / L"solar.db");
    const std::time_t t0 = local_midnight(Date{std::chrono::year{2026}, std::chrono::October, std::chrono::day{28}}) + 11 * 3600;
    Reading r;
    r.power_kw = 30; r.e_daily_kwh = 10; r.e_total_kwh = 1010;
    db.insert(t0, r, 20.0);
    r.e_daily_kwh = 25;
    db.insert(t0 + 1800, r, 20.0);
    r.power_kw = 10; r.e_daily_kwh = 30;
    db.insert(t0 + 3600, r, 25.0);
    const Date day{std::chrono::year{2026}, std::chrono::October, std::chrono::day{28}};
    const auto days = days_from_aggregates(db.hourly_aggregates(local_midnight(day), local_midnight(add_days(day, 1))), day, day);
    REQUIRE(days.size() == 1);
    CHECK(*days[0].load == doctest::Approx(45.0));
    CHECK(*days[0].exported == doctest::Approx(10.0));
    CHECK(*days[0].import == doctest::Approx(15.0));
}

TEST_CASE("obavijesti: nedostupan uređaj jednom, pa poruka o oporavku") {
    set_language("hr");
    Settings s;
    s.alert_offline_min = 30;
    const std::time_t t = local_midnight(Date{std::chrono::year{2026}, std::chrono::October, std::chrono::day{28}}) + 15 * 3600;
    Observation down{t, false, t - 40 * 60};
    down.error = "timeout";
    auto [state, msgs] = evaluate_alerts(s, AlertState{}, down);
    REQUIRE(msgs.size() == 1);
    CHECK(msgs[0].body.find("40 min") != std::string::npos);
    CHECK(evaluate_alerts(s, state, down).second.empty());
    auto [back, msgs3] = evaluate_alerts(s, state, Observation{t, true, t});
    CHECK(msgs3.size() == 1);
    CHECK_FALSE(back.offline_sent);
}

TEST_CASE("obavijesti: niska proizvodnja jednom dnevno, greška samo za izravni inverter") {
    set_language("hr");
    Settings s;
    const std::time_t t = local_midnight(Date{std::chrono::year{2026}, std::chrono::October, std::chrono::day{28}}) + 15 * 3600;
    Observation low{t, true, t};
    low.day_kwh = 40;
    low.expected_kwh = 200;
    auto [state, msgs] = evaluate_alerts(s, AlertState{}, low);
    REQUIRE(msgs.size() == 1);
    CHECK(msgs[0].body.find("20 %") != std::string::npos);
    CHECK(evaluate_alerts(s, state, low).second.empty());
    Observation fault{t, true, t};
    fault.status = 0x0300;
    CHECK(evaluate_alerts(s, AlertState{}, fault).second.empty());
    s.device_type = "inverter";
    CHECK(evaluate_alerts(s, AlertState{}, fault).second.size() == 1);
}

TEST_CASE("prognoza: očekivana energija do sada iz satnog zračenja") {
    const std::time_t midnight = local_midnight(Date{std::chrono::year{2026}, std::chrono::June, std::chrono::day{1}});
    json hourly = json::array();
    for (int h = 0; h < 24; ++h) {
        char ts[24];
        std::snprintf(ts, sizeof ts, "2026-06-01T%02d:00", h);
        hourly.push_back({ts, h >= 9 && h <= 16 ? 500.0 : 0.0});
    }
    CHECK(expected_until(hourly, midnight + 10 * 3600 + 1800, 10.0) == doctest::Approx(4.0 * 2.5));
}

TEST_CASE("adrese e-pošte i obrazac obavijesti") {
    set_language("hr");
    CHECK(parse_recipients("a@x.hr, b@y.com\nA@x.hr;")->size() == 2);
    std::string bad;
    CHECK_FALSE(parse_recipients("a@x.hr, nije-adresa", &bad));
    CHECK(bad == "nije-adresa");
    Settings cur;
    cur.logger_interface = "Ethernet";
    json form = to_form(cur);
    form["alert_emails"] = "a@x.hr";
    form["smtp_host"] = "";
    form["night_from"] = "25:00";
    const auto v = validate_form(form, cur, {"Ethernet"});
    CHECK(v.errors.count("smtp_host"));
    CHECK(v.errors.count("night_from"));
    CHECK_FALSE(to_form(cur).contains("smtp_password_enc"));
}

TEST_CASE("DPAPI: lozinka se ne sprema u čistom tekstu") {
    const std::string stored = protect_secret("tajna-lozinka");
    CHECK(stored.rfind("dpapi:", 0) == 0);
    CHECK(stored.find("tajna") == std::string::npos);
    CHECK(unprotect_secret(stored) == "tajna-lozinka");
    CHECK(unprotect_secret("dpapi:AAAA").empty());
}

TEST_CASE("pregled iz mreže: samo datoteke programa i slika, bez izlaska iz mape") {
    CHECK(resolve_remote_path("/web/../config.json") == std::nullopt);
    CHECK(resolve_remote_path("/web/%2e%2e/config.json") == std::nullopt);
    CHECK(resolve_remote_path("/data/../../config.json") == std::nullopt);
    CHECK(resolve_remote_path("C:/Windows/win.ini") == std::nullopt);
    CHECK(resolve_remote_path("/etc/passwd") == std::nullopt);
}

// ---------------------------------------------------------------- Modbus
TEST_CASE("Modbus: dekodiranje riječi s predznakom") {
    CHECK(decode({0xFFFF}, "I16") == -1);
    CHECK(decode({0xFFFF}, "U16") == 65535);
    CHECK(decode({0x0001, 0x86A0}, "U32") == 100000);
    CHECK(decode({0xFFFF, 0xFFFE}, "I32") == -2);
}

// ---------------------------------------------------------------- baza i dnevni izračun
TEST_CASE("baza: upis, zadnje očitanje, agregati, rekord i uvoz") {
    TempDir dir;
    {
        Db db(dir.path / L"a.db");
        db.insert(utc(2026, 10, 28, 9), Reading{20.0, 30.0, 1030.0, 0.99, 1}, 12.5);
        db.insert(utc(2026, 10, 28, 15), Reading{35.0, 55.5, 1055.5, 0.98, 1}, std::nullopt);
        const auto last = db.latest();
        REQUIRE(last);
        CHECK(last->e_total_kwh == doctest::Approx(1055.5));
        CHECK_FALSE(last->load_kw);
        CHECK(db.peak_power()->second == doctest::Approx(35.0));
        CHECK(db.hourly_aggregates(utc(2026, 10, 28, 0), utc(2026, 10, 29, 0)).size() == 2);
        const auto curve = db.power_buckets(utc(2026, 10, 28, 0), utc(2026, 10, 29, 0), 300);
        REQUIRE(curve.size() == 2);
        CHECK(curve[0].load_kw == std::optional(12.5));  // mjerač
        CHECK_FALSE(curve[1].load_kw);
    }
    {
        Db other(dir.path / L"b.db");
        other.insert(utc(2026, 10, 28, 9), Reading{20.0, 30.0, 1030.0, 0.99, 1}, std::nullopt);
        other.insert(utc(2026, 10, 27, 9), Reading{10.0, 10.0, 1000.0, 0.99, 1}, std::nullopt);
    }
    Db db(dir.path / L"a.db");
    CHECK(db.import_history(dir.path / L"b.db") == 1);
    CHECK(db.import_history(dir.path / L"b.db") == 0);
    CHECK_THROWS(db.import_history(dir.path / L"a.db"));
}

TEST_CASE("dnevni izračun: E-daily nakon 01:00 lokalno, inače razlika E-total") {
    const Date d27 = date(2026, 10, 27), d28 = date(2026, 10, 28);
    const std::time_t m28 = local_midnight(d28);
    std::vector<HourAggregate> hours = {
        {m28 - 3600, 2, 120.0, 1000.0, 1000.0, 5.0},  // 23:xx jučer
        {m28 + 600 - 600, 2, 120.0, 1000.0, 1000.0, 0.0},  // 00:xx – logger još javlja jučerašnji iznos
        {m28 + 9 * 3600, 2, 30.0, 1030.0, 1030.0, 20.0},
        {m28 + 15 * 3600, 2, 55.5, 1055.5, 1055.5, 35.0},
    };
    const auto days = days_from_aggregates(hours, d27, d28);
    REQUIRE(days.size() == 2);
    CHECK(days[0].kwh == doctest::Approx(120.0));
    CHECK(days[1].kwh == doctest::Approx(55.5));

    const std::vector<HourAggregate> totals = {{m28 + 8 * 3600, 1, 0.0, 2000.0, 2000.0, 1.0},
                                               {m28 + 14 * 3600, 1, 0.0, 2042.0, 2042.0, 1.0}};
    CHECK(days_from_aggregates(totals, d28, d28)[0].kwh == doctest::Approx(42.0));
    CHECK(days_from_aggregates({}, d27, d28)[1].kwh == 0.0);
}

TEST_CASE("sigurnosna kopija: jedna dnevno, stare se brišu") {
    TempDir dir;
    { Db db(dir.path / L"solar.db"); db.insert(utc(2026, 10, 1, 10), Reading{1, 2, 3, 1, 1}, std::nullopt); }
    fs::create_directories(dir.path / L"b");
    write_file_atomic(dir.path / L"b" / L"solar_2026-09-01.db", "x");
    CHECK(daily_backup(dir.path / L"solar.db", dir.path / L"b", 14, date(2026, 10, 29)));
    CHECK_FALSE(daily_backup(dir.path / L"solar.db", dir.path / L"b", 14, date(2026, 10, 29)));
    CHECK_FALSE(fs::exists(dir.path / L"b" / L"solar_2026-09-01.db"));
    CHECK_FALSE(daily_backup(dir.path / L"solar.db", dir.path / L"b", 0, date(2026, 10, 29)));
}

// ---------------------------------------------------------------- mreža i pomoćno
TEST_CASE("mreža: podmreža i stvarne kartice") {
    CHECK(in_subnet("192.168.5.10", 24, "192.168.5.199"));
    CHECK_FALSE(in_subnet("192.168.3.169", 24, "192.168.5.199"));
    CHECK_FALSE(in_subnet("192.168.3.169", 24, "smartlogger.local"));
    NetInit net;
    for (const auto& i : list_interfaces()) CHECK(i.name.find("Loopback") == std::string::npos);
    CHECK_THROWS_AS(source_ip("Ne postoji"), InterfaceError);
    CHECK_FALSE(source_ip(""));
}

TEST_CASE("pomoćno: UTF-8, base64, vrijeme") {
    CHECK(narrow(widen("čćšđž €")) == "čćšđž €");
    CHECK(base64({'M', 'a', 'n'}) == "TWFu");
    CHECK(base64({'M', 'a'}) == "TWE=");
    CHECK(utc_text(*parse_utc_text("2026-10-29 08:15:00")) == "2026-10-29 08:15:00");
    CHECK(days_between(date(2026, 2, 27), add_days(date(2026, 2, 27), 3)) == 3);
}

// ================================================================ 3.0: kriptografija i korisnici
namespace {
constexpr uint32_t kTestIterations = 1000;  // u testovima brže; poslužitelj koristi 600 000
UserInput person(const std::string& email, Role role = Role::User, const std::string& pw = "Sunce-2026-ploce") {
    return {"Ana", "Horvat", email, pw, role};
}
}  // namespace

// ---------------------------------------------------------------- Solarni poslužitelj i klijent (Cloudflare)
namespace {
// Privremena mapa poslužitelja (SOLARI2_HOME) dok traje test
struct TempHome {
    TempDir dir;
    std::wstring old;
    TempHome() {
        if (const wchar_t* v = _wgetenv(L"SOLARI2_HOME")) old = v;
        _wputenv_s(L"SOLARI2_HOME", dir.path.c_str());
    }
    ~TempHome() { _wputenv_s(L"SOLARI2_HOME", old.c_str()); }
};

HttpRequest api_request(const std::string& path, const std::string& token, const std::string& peer = "127.0.0.1",
                        const std::string& method = "GET", const std::string& body = "") {
    HttpRequest r;
    r.method = method;
    r.target = r.path = path;
    r.peer = peer;
    r.body = body;
    if (!token.empty()) r.headers["authorization"] = "Bearer " + token;
    return r;
}

HttpRequest login_request(const std::string& email, const std::string& password, const std::string& peer) {
    return api_request("/api/v1/login", "", peer, "POST", json{{"email", email}, {"password", password}, {"device", "test"}}.dump());
}
}  // namespace

TEST_CASE("API 3.0: bez prijave nema podataka; prijava e-poštom i lozinkom daje oznaku") {
    TempHome home;
    Catalog catalog = load_catalog(kSource / L"web" / L"catalog.json");
    DataService data(home.dir.path / L"solar.db");
    WeatherService weather;
    UserStore users(home.dir.path / L"users.db", {random_bytes(32), random_bytes(32)}, kTestIterations);
    auto handler = api_handler({&data, &weather, &catalog, &users, [] { return Settings{}; }});

    // poslužitelj bez administratora: nitko se ne može prijaviti
    CHECK(json::parse(handler(api_request("/api/v1/ping", "")).body)["setup"] == false);
    CHECK(handler(login_request("a@b.hr", "Sunce-2026-ploce", "10.0.0.1")).code == 503);

    users.create(person("admin@primjer.hr", Role::Admin), now());
    const json ping = json::parse(handler(api_request("/api/v1/ping", "")).body);
    CHECK(ping["api"] == 3);
    CHECK(ping["setup"] == true);
    CHECK_FALSE(ping.contains("plant"));  // bez prijave ništa o elektrani

    for (const char* path : {"/api/v1/info", "/api/v1/dashboard", "/api/v1/images/logo", "/api/v1/me", "/web/index.html", "/"}) {
        CHECK(handler(api_request(path, "")).code == 401);
        CHECK(handler(api_request(path, std::string(43, 'x'), "10.0.0.2")).code == 401);
    }
    CHECK(handler(login_request("admin@primjer.hr", "krivo", "10.0.0.3")).code == 401);
    CHECK(handler(api_request("/api/v1/login", "", "10.0.0.3", "GET")).code == 405);
    CHECK(handler(api_request("/api/v1/login", "", "10.0.0.3", "POST", "nije json")).code == 400);

    const HttpResponse ok = handler(login_request("admin@primjer.hr", "Sunce-2026-ploce", "10.0.0.3"));
    REQUIRE(ok.code == 200);
    const json body = json::parse(ok.body);
    const std::string token = body["token"];
    CHECK(body["user"]["role"] == "admin");
    CHECK_FALSE(body["user"].contains("id"));
    CHECK(handler(api_request("/api/v1/info", token, "10.0.0.3")).code == 200);
    CHECK(json::parse(handler(api_request("/api/v1/me", token, "10.0.0.3")).body)["email"] == "admin@primjer.hr");
    CHECK(handler(api_request("/api/v1/report", token, "10.0.0.3")).code == 400);  // bez godine i mjeseca
    CHECK(handler(api_request("/api/v1/info", token, "10.0.0.3", "POST", "{}")).code == 405);

    // promjena lozinke: stara oznaka prestaje, ovaj uređaj dobiva novu
    const HttpResponse pw = handler(api_request("/api/v1/password", token, "10.0.0.3", "POST",
                                                json{{"old_password", "Sunce-2026-ploce"}, {"new_password", "Nova-Lozinka-2026"}}.dump()));
    REQUIRE(pw.code == 200);
    const std::string token2 = json::parse(pw.body)["token"];
    CHECK(handler(api_request("/api/v1/info", token, "10.0.0.3")).code == 401);
    CHECK(handler(api_request("/api/v1/info", token2, "10.0.0.3")).code == 200);
    CHECK(handler(api_request("/api/v1/logout", token2, "10.0.0.3", "POST", "{}")).code == 200);
    CHECK(handler(api_request("/api/v1/info", token2, "10.0.0.3")).code == 401);
}

TEST_CASE("API 3.0: 10 neuspjelih prijava ili lažnih oznaka s iste adrese blokira adresu na 10 minuta") {
    TempHome home;
    Catalog catalog = load_catalog(kSource / L"web" / L"catalog.json");
    DataService data(home.dir.path / L"solar.db");
    WeatherService weather;
    UserStore users(home.dir.path / L"users.db", {random_bytes(32), random_bytes(32)}, kTestIterations);
    users.create(person("admin@primjer.hr", Role::Admin), now());
    for (int i = 0; i < 4; ++i) users.create(person("korisnik" + std::to_string(i) + "@primjer.hr"), now());
    auto handler = api_handler({&data, &weather, &catalog, &users, [] { return Settings{}; }});
    // napadač pogađa lozinke različitih računa (zaključavanje računa ne bi pomoglo) – blokira se adresa
    for (int i = 0; i < 10; ++i) handler(login_request("korisnik" + std::to_string(i % 4) + "@primjer.hr", "krivo", "10.0.0.9"));
    CHECK(handler(login_request("admin@primjer.hr", "Sunce-2026-ploce", "10.0.0.9")).code == 429);
    CHECK(handler(login_request("admin@primjer.hr", "Sunce-2026-ploce", "10.0.0.10")).code == 200);
    for (int i = 0; i < 10; ++i) handler(api_request("/api/v1/dashboard", "lazna-oznaka-" + std::string(40, 'z'), "10.0.0.11"));
    CHECK(handler(api_request("/api/v1/ping", "", "10.0.0.11")).code == 200);  // provjera veze i dalje radi
    CHECK(handler(login_request("admin@primjer.hr", "Sunce-2026-ploce", "10.0.0.11")).code == 429);
    // iza tunela: blokira se stvarni klijent (CF-Connecting-IP), ne cloudflared na 127.0.0.1
    HttpRequest via_tunnel = login_request("nema@primjer.hr", "krivo", "127.0.0.1");
    via_tunnel.headers["cf-connecting-ip"] = "203.0.113.5";
    for (int i = 0; i < 10; ++i) handler(via_tunnel);
    CHECK(handler(login_request("admin@primjer.hr", "Sunce-2026-ploce", "127.0.0.1")).code == 200);
}

TEST_CASE("klijent 3.0: adresa poslužitelja, prijava umjesto API ključa") {
    set_language("hr");
    CHECK(normalize_server_url("https://solar.tvrtka.hr/") == std::optional<std::string>("https://solar.tvrtka.hr"));
    CHECK(normalize_server_url(" http://192.168.1.20:8700 ") == std::optional<std::string>("https://192.168.1.20:8700"));  // u mreži samo HTTPS
    CHECK(normalize_server_url("http://127.0.0.1:8700") == std::optional<std::string>("http://127.0.0.1:8700"));
    CHECK_FALSE(normalize_server_url("ftp://x.hr"));
    CHECK_FALSE(normalize_server_url("https://x.hr/a b"));
    CHECK(pinned_host("https://192.168.1.20:8700"));
    CHECK(pinned_host("https://solarni-pc:8700"));
    CHECK(pinned_host("https://server.local"));
    CHECK_FALSE(pinned_host("https://solar.tvrtka.hr"));  // javna adresa: uobičajena provjera izdavača
    CHECK_FALSE(pinned_host("http://127.0.0.1:8700"));

    Settings cur;
    json form = to_form(cur);
    form["data_source"] = "cloud";
    form["cloud_url"] = "https://solar.tvrtka.hr";
    form["logger_interface"] = "";
    auto v = validate_form(form, cur, {});
    CHECK(v.errors.count("cloud_login"));  // bez prijave se ne sprema
    CHECK_FALSE(v.errors.count("logger_interface"));
    cur.cloud_url = "https://solar.tvrtka.hr";
    cur.cloud_token_enc = protect_secret("oznaka");
    cur.cloud_account_enc = protect_secret(R"({"email":"ana@primjer.hr","name":"Ana Horvat","role":"user"})");
    cur.cloud_cert_pin = "AB:CD";
    v = validate_form(form, cur, {});
    REQUIRE(v.settings);
    CHECK(v.settings->cloud_token_enc == cur.cloud_token_enc);
    const json f = to_form(*v.settings);
    CHECK_FALSE(f.contains("cloud_token_enc"));
    CHECK_FALSE(f.contains("cloud_account_enc"));
    CHECK(f["cloud_account"]["name"] == "Ana Horvat");
    form["cloud_url"] = "https://drugi.tvrtka.hr";  // drugi poslužitelj: prijava i otisak se brišu
    v = validate_form(form, cur, {});
    CHECK(v.errors.count("cloud_login"));
    // stara konfiguracija s http adresom u mreži prelazi na https
    json old = to_json(Settings{}, false);
    old["cloud_url"] = "http://192.168.1.20:8700";
    CHECK(settings_from_json(old).cloud_url == "https://192.168.1.20:8700");
}

TEST_CASE("HTTPS 3.0: poslužitelj s vlastitim certifikatom, prijava klijenta i provjera otiska prije slanja tajni") {
    const std::wstring cert_name = L"Solari test " + std::to_wstring(GetCurrentProcessId());
    struct CertCleanup {
        std::wstring name;
        ~CertCleanup() { remove_server_certificate(name); }
    } cleanup{cert_name};
    const ServerCert cert = ensure_server_certificate(cert_name);
    CHECK(cert.fingerprint.size() == 32 * 3 - 1);
    CHECK(ensure_server_certificate(cert_name).fingerprint == cert.fingerprint);  // isti certifikat, ne novi
    CHECK(find_server_certificate(cert_name)->fingerprint == cert.fingerprint);

    TempHome home;
    Catalog catalog = load_catalog(kSource / L"web" / L"catalog.json");
    DataService data(home.dir.path / L"solar.db");
    WeatherService weather;
    UserStore users(home.dir.path / L"users.db", {random_bytes(32), random_bytes(32)}, kTestIterations);
    users.create(person("ana@primjer.hr", Role::Admin), now());
    std::atomic<int> secret_requests{0};
    auto api = api_handler({&data, &weather, &catalog, &users, [] { return Settings{}; }});
    HttpServer server([&](const HttpRequest& r) {
        if (r.path != "/api/v1/ping") ++secret_requests;
        return api(r);
    });
    server.set_tls(std::make_shared<TlsCredentials>(cert_name));
    int port = 0;
    for (int p = 18700; p < 18760 && !port; ++p) if (server.start(p, false)) port = p;
    REQUIRE(port);
    const std::string url = "https://127.0.0.1:" + std::to_string(port);

    CHECK_THROWS_AS(cloud_login(url, "ana@primjer.hr", "krivo", ""), CloudError);
    const CloudLogin login = cloud_login(url, "ana@primjer.hr", "Sunce-2026-ploce", "");
    CHECK(login.pin == cert.fingerprint);
    CHECK(login.account["name"] == "Ana Horvat");
    CHECK(login.token.size() == 43);

    Settings s;
    s.cloud_url = url;
    s.cloud_token_enc = protect_secret(login.token);
    s.cloud_cert_pin = login.pin;
    CHECK(cloud_json(s, "/api/v1/info")["api"] == 3);

    // drugi certifikat (npr. netko u mreži): veza se prekida PRIJE slanja oznake – poslužitelj zahtjev ne vidi
    const int before = secret_requests;
    s.cloud_cert_pin = "00:" + cert.fingerprint.substr(3);
    CHECK_THROWS_WITH_AS(cloud_json(s, "/api/v1/info"), doctest::Contains("Certifikat poslužitelja se promijenio"), CloudError);
    CHECK(secret_requests == before);
    CHECK_THROWS_AS(cloud_login(url, "ana@primjer.hr", "Sunce-2026-ploce", s.cloud_cert_pin), CloudError);
    CHECK(secret_requests == before);

    // obični HTTP s 127.0.0.1 (cloudflared) i dalje radi na istom portu
    Settings plain = s;
    plain.cloud_url = "http://127.0.0.1:" + std::to_string(port);
    plain.cloud_cert_pin.clear();
    CHECK(cloud_json(plain, "/api/v1/info")["api"] == 3);
    server.stop();
}

TEST_CASE("HTTP: parametri zahtjeva") {
    HttpRequest r;
    r.query = "year=2026&month=9&x";
    CHECK(r.param("year") == "2026");
    CHECK(r.param("month") == "9");
    CHECK(r.param("nema").empty());
}

TEST_CASE("curl.exe iz instalacije (Windows Server 2016 ga nema)") {
    const std::wstring cmd = curl_command();
    CHECK(cmd.find(L"curl\\curl.exe") != std::wstring::npos);  // build/curl kao {app}\curl u instalaciji
    const ProcessResult r = run_capture(cmd + L" --version", 10'000);
    CHECK(r.exit_code == 0);
    CHECK(cmd.find(L"--ca-native") != std::wstring::npos);  // certifikati iz spremišta Windowsa
}

// ---------------------------------------------------------------- izvoz SmartLoggera (perfmg_day.emap)
namespace {
// zapis: u16 uređaj, u16 KPI, u32 razdoblje, u32 vrijeme (00:00 UTC dana), i32 vrijednost (0,01 kWh)
void put_record(std::string& b, uint16_t device, uint16_t kpi, Date day, int32_t value) {
    const auto ts = static_cast<uint32_t>(Clock::to_time_t(std::chrono::sys_days{day}));
    const uint32_t period = 86400;
    char rec[16];
    std::memcpy(rec, &device, 2);
    std::memcpy(rec + 2, &kpi, 2);
    std::memcpy(rec + 4, &period, 4);
    std::memcpy(rec + 8, &ts, 4);
    std::memcpy(rec + 12, &value, 4);
    b.append(rec, 16);
}

Date ymd(int y, unsigned m, unsigned d) { return Date{std::chrono::year{y}, std::chrono::month{m}, std::chrono::day{d}}; }

std::string sample_emap() {
    std::string b(8, '\0');                                   // zaglavlje
    put_record(b, 0x0002, 0x3011, ymd(2024, 6, 1), 59929);    // 599,29 kWh
    put_record(b, 0x0002, 0x3011, ymd(2024, 6, 2), 41000);
    put_record(b, 0x1002, 0x3011, ymd(2024, 6, 3), 99999);    // inverter – preskače se
    put_record(b, 0x0002, 0x3012, ymd(2024, 6, 3), 88888);    // drugi KPI – preskače se
    put_record(b, 0x0002, 0x3011, ymd(2024, 6, 4), -1);       // nema podatka
    put_record(b, 0x0002, 0x3011, ymd(2024, 6, 5), 0);
    put_record(b, 0x0002, 0x3011, ymd(2024, 6, 6), 12345);
    put_record(b, 0x0002, 0x3011, ymd(1970, 1, 1), 500);     // prazan zapis (vrijeme 0) – preskače se
    return b;
}
}  // namespace

TEST_CASE("izvoz SmartLoggera: dnevna proizvodnja elektrane iz perfmg_day.emap") {
    const auto days = parse_perfmg_day(sample_emap());
    REQUIRE(days.size() == 4);
    CHECK(days.at(ymd(2024, 6, 1)) == doctest::Approx(599.29));
    CHECK(days.at(ymd(2024, 6, 2)) == doctest::Approx(410.0));
    CHECK(days.at(ymd(2024, 6, 5)) == doctest::Approx(0.0));
    CHECK(days.at(ymd(2024, 6, 6)) == doctest::Approx(123.45));
    CHECK_FALSE(days.count(ymd(2024, 6, 3)));
    CHECK_FALSE(days.count(ymd(2024, 6, 4)));
    CHECK_THROWS(parse_perfmg_day("kratko"));
}

TEST_CASE("izvoz SmartLoggera: uvoz u bazu preskače dane pollera i današnji dan") {
    TempDir tmp;
    Db db(tmp.path / "solar.db");
    // poller je 2. 6. već zabilježio dan – ostaje njegov iznos
    Reading r;
    r.power_kw = 5;
    r.e_daily_kwh = 300;
    r.e_total_kwh = 1000;
    db.insert(local_midnight(ymd(2024, 6, 2)) + 15 * 3600, r, std::nullopt);
    auto days = parse_perfmg_day(sample_emap());
    days[ymd(2024, 6, 7)] = 77;  // "danas" – ne uvozi se
    const ExportImport res = import_perfmg_days(db, days, ymd(2024, 6, 7));
    CHECK(res.imported == 3);
    CHECK(res.skipped == 1);
    CHECK(*res.first == ymd(2024, 6, 1));
    CHECK(*res.last == ymd(2024, 6, 6));
    CHECK(res.kwh == doctest::Approx(599.29 + 0 + 123.45));
    const auto out = days_from_aggregates(db.hourly_aggregates(local_midnight(ymd(2024, 6, 1)), local_midnight(ymd(2024, 6, 8))),
                                          ymd(2024, 6, 1), ymd(2024, 6, 7));
    CHECK(out[0].kwh == doctest::Approx(599.29));
    CHECK(out[1].kwh == doctest::Approx(300.0));  // poller
    CHECK(out[5].kwh == doctest::Approx(123.45));
    CHECK(out[6].kwh == doctest::Approx(0.0));    // danas
    // ponovni uvoz ništa ne udvostručuje
    const ExportImport again = import_perfmg_days(db, days, ymd(2024, 6, 7));
    CHECK(again.imported == 0);
    CHECK(again.skipped == 4);
    // zadnje očitanje i dalje je pollerovo (uvezeni dani nemaju ukupnu energiju)
    CHECK(db.latest()->e_total_kwh == doctest::Approx(1000.0));
}

TEST_CASE("izvoz SmartLoggera: log.zip, mapa i datoteka bez perfmg_day.emap") {
    TempDir tmp;
    const fs::path dir = tmp.path / "log" / "smartlogger" / "perf";
    fs::create_directories(dir);
    write_file_atomic(dir / "perfmg_day.emap", sample_emap());
    write_file_atomic(tmp.path / "log" / "readme.txt", "x");
    CHECK(read_perfmg_day(tmp.path / "log") == sample_emap());
    CHECK(read_perfmg_day(dir / "perfmg_day.emap") == sample_emap());
    // ZIP s mapama i razmakom/apostrofom u imenu
    const fs::path zip = tmp.path / L"log izvoz'1.zip";
    const ProcessResult made = run_capture(L"powershell.exe -NoProfile -NonInteractive -Command \"Compress-Archive -Path '" +
                                               (tmp.path / "log").wstring() + L"' -DestinationPath '" +
                                               tmp.path.wstring() + L"\\log izvoz''1.zip'\"", 60'000);
    REQUIRE(made.exit_code == 0);
    CHECK(read_perfmg_day(zip) == sample_emap());
    // ZIP bez dnevne datoteke
    fs::remove(dir / "perfmg_day.emap");
    const fs::path empty_zip = tmp.path / "prazan.zip";
    REQUIRE(run_capture(L"powershell.exe -NoProfile -NonInteractive -Command \"Compress-Archive -Path '" +
                            (tmp.path / "log").wstring() + L"' -DestinationPath '" + empty_zip.wstring() + L"'\"", 60'000)
                .exit_code == 0);
    CHECK_THROWS_WITH(read_perfmg_day(empty_zip), doctest::Contains("perfmg_day.emap"));
}

// ---------------------------------------------------------------- SunSpec i Fronius
namespace {
// Tablica registara uređaja; adresa koje nema → ModbusError (kao "illegal data address")
struct FakeRegisters {
    std::map<uint16_t, uint16_t> regs;
    std::vector<uint16_t> read(uint16_t a, uint16_t n) const {
        std::vector<uint16_t> out;
        for (uint16_t i = 0; i < n; ++i) {
            const auto it = regs.find(static_cast<uint16_t>(a + i));
            if (it == regs.end()) throw ModbusError("illegal data address");
            out.push_back(it->second);
        }
        return out;
    }
    uint16_t put_model(uint16_t at, uint16_t id, const std::vector<uint16_t>& data) {
        regs[at] = id;
        regs[static_cast<uint16_t>(at + 1)] = static_cast<uint16_t>(data.size());
        for (size_t i = 0; i < data.size(); ++i) regs[static_cast<uint16_t>(at + 2 + i)] = data[i];
        return static_cast<uint16_t>(at + 2 + data.size());
    }
};

void put_text(std::vector<uint16_t>& d, size_t at, const std::string& s) {
    for (size_t i = 0; i < s.size(); i += 2) {
        d[at + i / 2] = static_cast<uint16_t>((s[i] << 8) | (i + 1 < s.size() ? s[i + 1] : 0));
    }
}

void put_f32(std::vector<uint16_t>& d, size_t at, float f) {
    uint32_t bits;
    std::memcpy(&bits, &f, 4);
    d[at] = static_cast<uint16_t>(bits >> 16);
    d[at + 1] = static_cast<uint16_t>(bits);
}

std::vector<uint16_t> model103(int16_t w, int16_t w_sf, uint32_t wh, int16_t wh_sf, int16_t pf, int16_t pf_sf, uint16_t st) {
    std::vector<uint16_t> d(50, 0);
    d[12] = static_cast<uint16_t>(w);
    d[13] = static_cast<uint16_t>(w_sf);
    d[20] = static_cast<uint16_t>(pf);
    d[21] = static_cast<uint16_t>(pf_sf);
    d[22] = static_cast<uint16_t>(wh >> 16);
    d[23] = static_cast<uint16_t>(wh);
    d[24] = static_cast<uint16_t>(wh_sf);
    d[36] = st;
    return d;
}

void end_models(FakeRegisters& dev, uint16_t at) {
    dev.regs[at] = 0xFFFF;
    dev.regs[static_cast<uint16_t>(at + 1)] = 0;
}
}  // namespace

TEST_CASE("SunSpec: pronalazi modele iza oznake SunS i čita inverter (cijeli brojevi + faktori skale)") {
    FakeRegisters dev;
    dev.regs[40000] = 0x5375;
    dev.regs[40001] = 0x6E53;
    std::vector<uint16_t> common(66, 0);
    put_text(common, 0, "Fronius");
    put_text(common, 16, "Symo 10.0-3-M");
    uint16_t at = dev.put_model(40002, 1, common);
    at = dev.put_model(at, 103, model103(30000, -1, 12'345'678, 0, -950, -1, 4));
    at = dev.put_model(at, 120, std::vector<uint16_t>(26, 0));
    end_models(dev, at);
    const auto models = sunspec_discover([&](uint16_t a, uint16_t n) { return dev.read(a, n); });
    REQUIRE(models.size() == 3);
    CHECK(models[0].id == 1);
    CHECK(models[1].id == 103);
    CHECK(models[1].address == 40002 + 2 + 66 + 2);
    const auto inv = sunspec_find(models, 101, 113);
    REQUIRE(inv);
    const Reading r = sunspec_inverter(inv->id, dev.read(inv->address, inv->length));
    CHECK(r.power_kw == doctest::Approx(3.0));
    CHECK(r.e_total_kwh == doctest::Approx(12345.678));
    CHECK(r.pf == doctest::Approx(-0.95));
    CHECK(r.status == 4);
    CHECK(r.e_daily_kwh < 0);  // SunSpec nema dnevnu energiju
    CHECK(sunspec_common_name(dev.read(models[0].address, 32)) == "Fronius Symo 10.0-3-M");
}

TEST_CASE("SunSpec: oznaka na adresi 0, float model 113, neimplementirane točke i mjerači") {
    FakeRegisters dev;  // na 40000 nema registara → traži dalje
    dev.regs[0] = 0x5375;
    dev.regs[1] = 0x6E53;
    std::vector<uint16_t> f(60, 0);
    put_f32(f, 20, 7000.5f);
    put_f32(f, 28, 0.98f);   // neki uređaji cos fi daju kao 0–1
    put_f32(f, 30, 2.5e7f);  // Wh
    f[46] = 4;
    end_models(dev, dev.put_model(2, 113, f));
    const auto models = sunspec_discover([&](uint16_t a, uint16_t n) { return dev.read(a, n); });
    REQUIRE(models.size() == 1);
    const Reading r = sunspec_inverter(113, dev.read(models[0].address, models[0].length));
    CHECK(r.power_kw == doctest::Approx(7.0005));
    CHECK(r.e_total_kwh == doctest::Approx(25000.0));
    CHECK(r.pf == doctest::Approx(0.98));
    // neimplementirana snaga (0x8000) i negativna snaga noću → 0
    CHECK(sunspec_inverter(103, model103(static_cast<int16_t>(0x8000), 0, 1000, 0, 100, 0, 2)).power_kw == 0.0);
    CHECK(sunspec_inverter(103, model103(-12, 0, 1000, 0, 100, 0, 2)).power_kw == 0.0);
    CHECK_THROWS(sunspec_inverter(160, std::vector<uint16_t>(60, 0)));
    // mjerač 203: W(16) s W_SF(20); 213: float W na 26
    std::vector<uint16_t> m203(105, 0);
    m203[16] = static_cast<uint16_t>(-1500);
    m203[20] = 1;
    CHECK(*sunspec_meter_w(203, m203) == doctest::Approx(-15000.0));
    m203[16] = 0x8000;
    CHECK_FALSE(sunspec_meter_w(203, m203));
    std::vector<uint16_t> m213(124, 0);
    put_f32(m213, 26, 2300.0f);
    CHECK(*sunspec_meter_w(213, m213) == doctest::Approx(2300.0));
    // bez oznake nigdje → prazno
    FakeRegisters none;
    CHECK(sunspec_discover([&](uint16_t a, uint16_t n) { return none.read(a, n); }).empty());
}

TEST_CASE("Fronius Solar API: Datamanager i GEN24 (bez dnevne energije), mjerač i greške") {
    const json symo = json::parse(R"({"Head":{"Status":{"Code":0}},"Body":{"Data":{
        "Site":{"P_PV":5234.5,"P_Grid":-1200.0,"P_Load":-4034.5,"E_Day":18345,"E_Total":45678900.5},
        "Inverters":{"1":{"P":5234,"E_Day":18345,"E_Total":45678900}}}}})");
    const PlantReading a = parse_fronius_powerflow(symo, true);
    CHECK(a.reading.power_kw == doctest::Approx(5.2345));
    CHECK(a.reading.e_daily_kwh == doctest::Approx(18.345));
    CHECK(a.reading.e_total_kwh == doctest::Approx(45678.9005));
    CHECK(*a.load_kw == doctest::Approx(-1.2));  // predaja u mrežu
    CHECK_FALSE(parse_fronius_powerflow(symo, false).load_kw);
    // GEN24 noću: P_PV null, Site bez energije – zbroj po inverterima, dnevnu računa poller
    const json gen24 = json::parse(R"({"Head":{"Status":{"Code":0}},"Body":{"Data":{
        "Site":{"P_PV":null,"P_Grid":350.0,"E_Day":null,"E_Total":null},
        "Inverters":{"1":{"P":0,"E_Total":1000000.0},"2":{"P":0,"E_Total":500000.0}}}}})");
    const PlantReading g = parse_fronius_powerflow(gen24, true);
    CHECK(g.reading.power_kw == 0.0);
    CHECK(g.reading.e_total_kwh == doctest::Approx(1500.0));
    CHECK(g.reading.e_daily_kwh < 0);
    CHECK(*g.load_kw == doctest::Approx(0.35));
    const json no_meter = json::parse(R"({"Body":{"Data":{"Site":{"P_PV":10,"P_Grid":null,"E_Total":5}}}})");
    CHECK_FALSE(parse_fronius_powerflow(no_meter, true).meter_error.empty());
    CHECK_THROWS(parse_fronius_powerflow(json::parse(R"({"Head":{"Status":{"Code":8,"Reason":"Busy"}}})"), false));
    CHECK_THROWS(parse_fronius_powerflow(json::parse(R"({"Body":{"Data":{"Site":{"P_PV":10}}}})"), false));
}

TEST_CASE("poller: dnevna energija iz ukupne za uređaje bez E-daily") {
    TempDir tmp;
    Db db(tmp.path / "solar.db");
    const std::time_t day = local_midnight(date(2026, 6, 10));
    CHECK(daily_from_total(db, day + 12 * 3600, 1000) == 0.0);  // prazna baza
    Reading r;
    r.e_total_kwh = 1005;
    db.insert(day + 7 * 3600, r, std::nullopt);  // prvo jutarnje očitanje
    CHECK(daily_from_total(db, day + 12 * 3600, 1012.5) == doctest::Approx(7.5));
    r.e_total_kwh = 1000;
    db.insert(day - 3 * 3600, r, std::nullopt);  // jučer navečer – točniji početak dana
    CHECK(daily_from_total(db, day + 12 * 3600, 1012.5) == doctest::Approx(12.5));
    CHECK(daily_from_total(db, day + 12 * 3600, 990) == 0.0);  // nikad negativno
}

TEST_CASE("postavke: vrste uređaja i adrese invertera za SunSpec") {
    for (const char* type : {"logger", "inverter", "sunspec", "fronius"}) {
        json f = valid_form();
        f["device_type"] = type;
        f["inverter_units"] = "1, 2";
        const auto v = validate_form(f, Settings{}, kIfaces);
        CHECK_MESSAGE(v.errors.empty(), type);
        CHECK(v.settings->device_type == type);
    }
    json f = valid_form();
    f["device_type"] = "nepoznat";
    CHECK(validate_form(f, Settings{}, kIfaces).errors.contains("device_type"));
    f["device_type"] = "sunspec";
    f["inverter_units"] = "a,b";
    CHECK(validate_form(f, Settings{}, kIfaces).errors.contains("inverter_units"));
    f["inverter_units"] = "126";
    f["meter_export_positive"] = false;
    const auto v = validate_form(f, Settings{}, kIfaces);
    CHECK(v.errors.empty());
    CHECK_FALSE(v.settings->meter_export_positive);
    CHECK_FALSE(settings_from_json(to_json(*v.settings)).meter_export_positive);
}

// ---------------------------------------------------------------- SunSpec i Fronius preko mreže (poller)
namespace {
// Jednostavan TCP poslužitelj na 127.0.0.1 (slučajni port) za jednu vezu po zahtjevu; respond(zahtjev) → odgovor.
class LocalServer {
public:
    using Handler = std::function<void(SOCKET)>;
    explicit LocalServer(Handler handler) : handler_(std::move(handler)) {
        listener_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        bind(listener_, reinterpret_cast<sockaddr*>(&a), sizeof a);
        int len = sizeof a;
        getsockname(listener_, reinterpret_cast<sockaddr*>(&a), &len);
        port_ = ntohs(a.sin_port);
        listen(listener_, 8);
        thread_ = std::thread([this] {
            for (;;) {
                SOCKET c = accept(listener_, nullptr, nullptr);
                if (c == INVALID_SOCKET) return;
                handler_(c);
                closesocket(c);
            }
        });
    }
    ~LocalServer() {
        closesocket(listener_);
        thread_.join();
    }
    int port() const { return port_; }

private:
    Handler handler_;
    SOCKET listener_ = INVALID_SOCKET;
    std::thread thread_;
    int port_ = 0;
};

bool recv_n(SOCKET s, char* buf, int n) {
    for (int got = 0; got < n;) {
        const int r = recv(s, buf + got, n - got, 0);
        if (r <= 0) return false;
        got += r;
    }
    return true;
}

// Modbus TCP (FC03) nad tablicama registara po adresi uređaja; nepoznata adresa registra → iznimka 0x02.
void serve_modbus(SOCKET c, const std::map<int, FakeRegisters>& units, uint8_t want_fc = 3) {
    for (;;) {
        unsigned char h[12];
        if (!recv_n(c, reinterpret_cast<char*>(h), 12)) return;
        const int unit = h[6];
        const uint16_t addr = static_cast<uint16_t>((h[8] << 8) | h[9]), count = static_cast<uint16_t>((h[10] << 8) | h[11]);
        std::string pdu;
        try {
            const auto it = units.find(unit);
            if (it == units.end() || h[7] != want_fc) throw ModbusError("unit");
            const auto regs = it->second.read(addr, count);
            pdu = {char(h[7]), char(count * 2)};
            for (uint16_t v : regs) pdu += {char(v >> 8), char(v & 0xFF)};
        } catch (const ModbusError&) {
            pdu = {char(h[7] | 0x80), char(0x02)};
        }
        std::string out = {char(h[0]), char(h[1]), 0, 0, char((pdu.size() + 1) >> 8), char((pdu.size() + 1) & 0xFF), char(unit)};
        out += pdu;
        send(c, out.data(), static_cast<int>(out.size()), 0);
    }
}

FakeRegisters sunspec_inverter_device(uint32_t wh) {
    FakeRegisters dev;
    dev.regs[40000] = 0x5375;
    dev.regs[40001] = 0x6E53;
    std::vector<uint16_t> common(66, 0);
    put_text(common, 0, "SimSolar");
    uint16_t at = dev.put_model(40002, 1, common);
    at = dev.put_model(at, 103, model103(420, 1, wh, 0, 990, -1, 4));  // 4,2 kW
    end_models(dev, at);
    return dev;
}

FakeRegisters sunspec_meter_device() {
    FakeRegisters dev;
    dev.regs[40000] = 0x5375;
    dev.regs[40001] = 0x6E53;
    std::vector<uint16_t> m(105, 0);
    m[16] = static_cast<uint16_t>(-1500);  // W
    end_models(dev, dev.put_model(40002, 203, m));
    return dev;
}
}  // namespace

TEST_CASE("SunSpec preko Modbus TCP: read_plant, mjerač i poller (dnevna energija iz ukupne)") {
    NetInit net;
    std::map<int, FakeRegisters> units = {{1, sunspec_inverter_device(12'345'000)}, {240, sunspec_meter_device()}};
    std::mutex m;
    LocalServer server([&](SOCKET c) {
        std::map<int, FakeRegisters> copy;
        {
            std::lock_guard lock(m);
            copy = units;
        }
        serve_modbus(c, copy);
    });
    Settings s;
    s.device_type = "sunspec";
    s.modbus_host = "127.0.0.1";
    s.modbus_port = server.port();
    s.inverter_units = "1";
    s.meter_unit_id = 240;
    const PlantReading p = read_plant(s);
    CHECK(p.reading.power_kw == doctest::Approx(4.2));
    CHECK(p.reading.e_total_kwh == doctest::Approx(12345.0));
    CHECK(p.device_name == "SimSolar");
    REQUIRE(p.load_kw);
    CHECK(*p.load_kw == doctest::Approx(1.5));  // -1500 W uz "pozitivno = predaja" → uzimanje iz mreže
    s.meter_export_positive = false;
    CHECK(*read_plant(s).load_kw == doctest::Approx(-1.5));

    TempDir tmp;
    Db db(tmp.path / "solar.db");
    REQUIRE(poll_once(s, db));  // prvo očitanje dana → 0
    {
        std::lock_guard lock(m);
        units[1] = sunspec_inverter_device(12'347'500);  // +2,5 kWh
    }
    REQUIRE(poll_once(s, db));
    const auto last = db.latest();
    REQUIRE(last);
    CHECK(last->e_total_kwh == doctest::Approx(12347.5));
    CHECK(last->e_daily_kwh == doctest::Approx(2.5));

    s.inverter_units = "5";  // nema uređaja na toj adresi
    CHECK_THROWS_WITH(read_plant(s), doctest::Contains("SunSpec"));
}

TEST_CASE("Fronius Solar API preko HTTP-a: read_plant i poller") {
    NetInit net;
    std::atomic<double> total_wh{5'000'000};
    LocalServer server([&](SOCKET c) {
        char buf[2048];
        const int n = recv(c, buf, sizeof buf - 1, 0);
        const std::string req(buf, n > 0 ? n : 0);
        std::string body, status = "200 OK";
        if (req.find("GET /solar_api/v1/GetPowerFlowRealtimeData.fcgi") == 0) {
            body = json{{"Head", {{"Status", {{"Code", 0}}}}},
                        {"Body", {{"Data", {{"Site", {{"P_PV", 6100.0}, {"P_Grid", -800.0}, {"E_Day", nullptr}, {"E_Total", total_wh.load()}}}}}}}}
                       .dump();
        } else {
            status = "404 Not Found";
        }
        const std::string resp = "HTTP/1.1 " + status + "\r\nContent-Type: application/json\r\nContent-Length: " +
                                 std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n" + body;
        send(c, resp.data(), static_cast<int>(resp.size()), 0);
    });
    Settings s;
    s.device_type = "fronius";
    s.modbus_host = "127.0.0.1";
    s.modbus_port = server.port();
    s.meter_unit_id = 1;
    const PlantReading p = read_plant(s);
    CHECK(p.reading.power_kw == doctest::Approx(6.1));
    CHECK(p.reading.e_total_kwh == doctest::Approx(5000.0));
    CHECK(p.reading.e_daily_kwh < 0);
    CHECK(*p.load_kw == doctest::Approx(-0.8));
    TempDir tmp;
    Db db(tmp.path / "solar.db");
    REQUIRE(poll_once(s, db));
    total_wh = 5'001'200;
    REQUIRE(poll_once(s, db));
    CHECK(db.latest()->e_daily_kwh == doctest::Approx(1.2));
    s.modbus_port = 1;  // nitko ne sluša
    CHECK_THROWS_WITH(read_plant(s), doctest::Contains("Fronius"));
}

// ---------------------------------------------------------------- ostali proizvođači (vendors.cpp) i okviri
TEST_CASE("Modbus RTU: CRC, zahtjev i odgovor") {
    // primjer iz Modbus specifikacije: 01 03 00 00 00 0A → CRC C5 CD
    CHECK(rtu_read_request(1, 3, 0, 10) == std::vector<uint8_t>{0x01, 0x03, 0x00, 0x00, 0x00, 0x0A, 0xC5, 0xCD});
    std::vector<uint8_t> r = {0xF7, 0x03, 0x04, 0x12, 0x34, 0xAB, 0xCD};
    const uint16_t crc = modbus_crc(r.data(), r.size());
    r.push_back(static_cast<uint8_t>(crc));
    r.push_back(static_cast<uint8_t>(crc >> 8));
    CHECK(parse_rtu_response(r.data(), r.size(), 3, 2) == std::vector<uint16_t>{0x1234, 0xABCD});
    r[3] ^= 1;  // pokvaren bajt → CRC ne odgovara
    CHECK_THROWS(parse_rtu_response(r.data(), r.size(), 3, 2));
    const uint8_t exc[] = {0x01, 0x84, 0x02, 0x00, 0x00};
    CHECK_THROWS_WITH(parse_rtu_response(exc, sizeof exc, 4, 2), doctest::Contains("2"));
}

namespace {
std::vector<uint8_t> solarman_response(uint32_t serial, uint8_t seq, const std::vector<uint8_t>& rtu) {
    const uint16_t length = static_cast<uint16_t>(14 + rtu.size());
    std::vector<uint8_t> f = {0xA5, static_cast<uint8_t>(length), static_cast<uint8_t>(length >> 8), 0x10, 0x15, seq, 0,
                              static_cast<uint8_t>(serial), static_cast<uint8_t>(serial >> 8), static_cast<uint8_t>(serial >> 16),
                              static_cast<uint8_t>(serial >> 24), 0x02, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    f.insert(f.end(), rtu.begin(), rtu.end());
    uint8_t sum = 0;
    for (size_t i = 1; i < f.size(); ++i) sum = static_cast<uint8_t>(sum + f[i]);
    f.push_back(sum);
    f.push_back(0x15);
    return f;
}

std::vector<uint8_t> rtu_answer(int unit, uint8_t fc, const std::vector<uint16_t>& words) {
    std::vector<uint8_t> r = {static_cast<uint8_t>(unit), fc, static_cast<uint8_t>(words.size() * 2)};
    for (uint16_t w : words) {
        r.push_back(static_cast<uint8_t>(w >> 8));
        r.push_back(static_cast<uint8_t>(w));
    }
    const uint16_t crc = modbus_crc(r.data(), r.size());
    r.push_back(static_cast<uint8_t>(crc));
    r.push_back(static_cast<uint8_t>(crc >> 8));
    return r;
}
}  // namespace

TEST_CASE("Solarman V5: okvir zahtjeva i odgovora") {
    const uint32_t sn = 2712345678u;
    const auto rtu = rtu_read_request(1, 3, 0x56, 2);
    const auto req = solarman_request(sn, 7, rtu);
    REQUIRE(req.size() == 11 + 15 + rtu.size() + 2);
    CHECK(req[0] == 0xA5);
    CHECK((req[1] | (req[2] << 8)) == 15 + rtu.size());
    CHECK(req[3] == 0x10);
    CHECK(req[4] == 0x45);
    CHECK(req[5] == 7);
    CHECK((req[7] | (req[8] << 8) | (req[9] << 16) | (static_cast<uint32_t>(req[10]) << 24)) == sn);
    CHECK(std::vector<uint8_t>(req.begin() + 26, req.end() - 2) == rtu);
    uint8_t sum = 0;
    for (size_t i = 1; i + 2 < req.size(); ++i) sum = static_cast<uint8_t>(sum + req[i]);
    CHECK(req[req.size() - 2] == sum);
    CHECK(req.back() == 0x15);
    const auto answer = rtu_answer(1, 3, {0x1234, 0x0001});
    CHECK(solarman_rtu(solarman_response(sn, 7, answer), sn) == answer);
    CHECK_THROWS_WITH(solarman_rtu(solarman_response(sn + 1, 7, answer), sn), doctest::Contains("serijski"));
    auto bad = solarman_response(sn, 7, answer);
    bad[30] ^= 0xFF;
    CHECK_THROWS(solarman_rtu(bad, sn));
}

TEST_CASE("proizvođači: vrijednosti, redoslijed riječi i grupiranje čitanja") {
    const std::vector<std::pair<uint16_t, uint16_t>> regs = {{10, 0x0001}, {11, 0x86A0}, {20, 0xFFFF}, {21, 0xFFFE},
                                                              {30, 0xFF38}, {40, 0x000F}, {90, 0x4240}};
    CHECK(vendor_value({11, 10, true, false, 0.1}, regs) == doctest::Approx(10000.0));   // viša riječ prva (BE)
    CHECK(vendor_value({20, 21, true, true, 1}, regs) == doctest::Approx(-65537.0));     // niža riječ prva, s predznakom
    CHECK(vendor_value({30, 0, false, true, 1}, regs) == doctest::Approx(-200.0));       // S16
    CHECK(vendor_value({90, 40, true, false, 1}, regs) == doctest::Approx(1000000.0));   // razdvojeni registri (Deye P3)
    CHECK_THROWS(vendor_value({99, 0, false, false, 1}, regs));
    const auto ranges = vendor_ranges({5002, 5030, 5031, 5003, 5004, 5215, 5216});
    REQUIRE(ranges.size() == 3);
    CHECK(ranges[0] == std::pair<uint16_t, uint16_t>{5002, 3});
    CHECK(ranges[1] == std::pair<uint16_t, uint16_t>{5030, 2});
    CHECK(ranges[2] == std::pair<uint16_t, uint16_t>{5215, 2});
    const auto gaps = vendor_ranges({808, 809, 810, 816, 850});  // rupa do 8 registara se čita u istom zahtjevu
    REQUIRE(gaps.size() == 2);
    CHECK(gaps[0] == std::pair<uint16_t, uint16_t>{808, 9});
}

TEST_CASE("proizvođači: tablice su potpune i dosljedne") {
    std::set<std::string> keys;
    for (const auto& p : vendor_profiles()) {
        INFO(p.key);
        CHECK(keys.insert(p.key).second);
        CHECK_FALSE(p.power.empty());
        CHECK((p.fc == 3 || p.fc == 4));
        CHECK(p.unit >= 0);
        CHECK(p.unit <= 247);
        CHECK(find_vendor(p.key) == &p);
        std::vector<const VendorPoint*> all;
        for (const auto& x : p.power) all.push_back(&x);
        for (const auto& x : p.meter) all.push_back(&x);
        if (p.today) all.push_back(&*p.today);
        if (p.total) all.push_back(&*p.total);
        for (const auto* x : all) CHECK(x->scale > 0);
    }
    CHECK(keys.size() >= 12);
    CHECK(find_vendor("victron")->unit == 100);
    CHECK_FALSE(find_vendor("victron")->total);  // energiju integrira poller
    CHECK(find_vendor("nepostojeći") == nullptr);
}

namespace {
FakeRegisters regs_of(std::initializer_list<std::pair<uint16_t, uint16_t>> list) {
    FakeRegisters f;
    for (const auto& [a, v] : list) f.regs[a] = v;
    return f;
}
}  // namespace

TEST_CASE("proizvođači preko Modbus TCP-a: Sungrow SG (input registri) i Victron (integracija energije)") {
    NetInit net;
    // Sungrow SG: snaga 5030–5031 = 6.500 W (niža riječ prva), danas 5002 = 23,4 kWh, ukupno 5003–5004 = 70.000 kWh,
    // predaja 5215–5216 = 1.200 W
    const FakeRegisters sg = regs_of({{5002, 234}, {5003, 70000 & 0xFFFF}, {5004, 70000 >> 16}, {5030, 6500}, {5031, 0},
                                      {5215, 1200}, {5216, 0}});
    LocalServer s1([&](SOCKET c) { serve_modbus(c, {{1, sg}}, 4); });
    Settings s;
    s.device_type = "vendor";
    s.device_profile = "sungrow_sg";
    s.modbus_host = "127.0.0.1";
    s.modbus_port = s1.port();
    s.inverter_units = "1";
    s.meter_unit_id = 1;
    const PlantReading p = read_plant(s);
    CHECK(p.reading.power_kw == doctest::Approx(6.5));
    CHECK(p.reading.e_daily_kwh == doctest::Approx(23.4));
    CHECK(p.reading.e_total_kwh == doctest::Approx(70000.0));
    CHECK(*p.load_kw == doctest::Approx(-1.2));  // predaja u mrežu
    s.meter_invert = true;
    CHECK(*read_plant(s).load_kw == doctest::Approx(1.2));

    // Victron GX: PV 808 + 811 + 850 = 2.500 W, mreža 820–822 = +300 W (uzimanje); energije nema → integracija
    std::atomic<uint16_t> pv{1000};
    LocalServer s2([&](SOCKET c) {
        FakeRegisters gx;
        for (uint16_t a = 808; a <= 850; ++a) gx.regs[a] = 0;
        gx.regs[808] = pv.load();
        gx.regs[811] = 500;
        gx.regs[850] = 1000;
        gx.regs[820] = 100;
        gx.regs[821] = 250;
        gx.regs[822] = static_cast<uint16_t>(-50);
        serve_modbus(c, {{100, gx}}, 3);
    });
    Settings v;
    v.device_type = "vendor";
    v.device_profile = "victron";
    v.modbus_host = "127.0.0.1";
    v.modbus_port = s2.port();
    v.inverter_units = "100";
    v.meter_unit_id = 1;
    const PlantReading g = read_plant(v);
    CHECK(g.reading.power_kw == doctest::Approx(2.5));
    CHECK(g.reading.e_total_kwh < 0);
    CHECK(*g.load_kw == doctest::Approx(0.3));
    TempDir tmp;
    Db db(tmp.path / "solar.db");
    const std::time_t t0 = now();
    Reading first;
    first.power_kw = 2.5;
    first.e_total_kwh = integrate_total(db, t0, 2.5);  // prazna baza → 0
    CHECK(first.e_total_kwh == 0.0);
    db.insert(t0, first, std::nullopt);
    // 10 minuta kasnije, 3,5 kW → prosjek 3 kW × 1/6 h = +0,5 kWh (trapez); nakon 20 minuta prekida ništa
    CHECK(integrate_total(db, t0 + 600, 3.5) == doctest::Approx(0.5));
    CHECK(integrate_total(db, t0 + 20 * 60, 3.5) == doctest::Approx(0.0));
    REQUIRE(poll_once(v, db));
    CHECK(db.latest()->e_total_kwh >= 0.0);
}

TEST_CASE("proizvođači preko Solarman V5 (Deye) i GoodWe UDP-a") {
    NetInit net;
    const uint32_t sn = 2712345678u;
    // Deye hibridni jednofazni: PV 0xBA–0xBD, danas 0x6C, ukupno 0x60–0x61 (niža riječ prva), mreža 0xA9
    const FakeRegisters deye = regs_of({{0xBA, 1500}, {0xBB, 1300}, {0xBC, 0}, {0xBD, 0}, {0x6C, 125}, {0x60, 0x86A0},
                                        {0x61, 0x0001}, {0xA9, static_cast<uint16_t>(-400)}});
    LocalServer logger([&](SOCKET c) {
        for (;;) {
            unsigned char head[3];
            if (!recv_n(c, reinterpret_cast<char*>(head), 3)) return;
            std::vector<uint8_t> f(13u + (head[1] | (head[2] << 8)));
            std::memcpy(f.data(), head, 3);
            if (!recv_n(c, reinterpret_cast<char*>(f.data() + 3), static_cast<int>(f.size() - 3))) return;
            const uint32_t got = f[7] | (f[8] << 8) | (f[9] << 16) | (static_cast<uint32_t>(f[10]) << 24);
            const uint8_t* rtu = f.data() + 26;
            const uint16_t addr = static_cast<uint16_t>((rtu[2] << 8) | rtu[3]), count = static_cast<uint16_t>((rtu[4] << 8) | rtu[5]);
            const auto heartbeat = std::vector<uint8_t>{0xA5, 0x01, 0x00, 0x10, 0x47, 0x00, 0x00, f[7], f[8], f[9], f[10], 0x00,
                                                        static_cast<uint8_t>(0x01 + 0x10 + 0x47 + f[7] + f[8] + f[9] + f[10]), 0x15};
            send(c, reinterpret_cast<const char*>(heartbeat.data()), static_cast<int>(heartbeat.size()), 0);  // logger šalje i svoje okvire
            const auto words = deye.read(addr, count);
            const auto resp = solarman_response(got, f[5], rtu_answer(rtu[0], rtu[1], words));
            send(c, reinterpret_cast<const char*>(resp.data()), static_cast<int>(resp.size()), 0);
        }
    });
    Settings d;
    d.device_type = "vendor";
    d.device_profile = "deye_hybrid";
    d.modbus_host = "127.0.0.1";
    d.inverter_units = "1";
    d.meter_unit_id = 1;
    d.modbus_port = 8899;  // Solarman samo na 8899 – ovdje: provjera da bez serijskog broja javlja grešku
    CHECK_THROWS_WITH(read_plant(d), doctest::Contains("serijski"));
    // stvarni test na slučajnom portu: Solarman se bira prema portu 8899, pa se ovdje poziva izravno klijent
    ModbusClient sol("127.0.0.1", logger.port(), 1, "", 3000, "Deye", Framing::Solarman, sn);
    sol.connect();
    const auto w = sol.read_registers(0xBA, 4, 1, 3);
    CHECK(w == std::vector<uint16_t>{1500, 1300, 0, 0});
    CHECK(sol.read_registers(0x60, 2, 1, 3) == std::vector<uint16_t>{0x86A0, 0x0001});

    // GoodWe UDP: odgovor s prefiksom AA 55 + RTU
    SOCKET udp = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bind(udp, reinterpret_cast<sockaddr*>(&a), sizeof a);
    int alen = sizeof a;
    getsockname(udp, reinterpret_cast<sockaddr*>(&a), &alen);
    std::thread goodwe([&] {
        unsigned char buf[64];
        sockaddr_in from{};
        int flen = sizeof from;
        const int n = recvfrom(udp, reinterpret_cast<char*>(buf), sizeof buf, 0, reinterpret_cast<sockaddr*>(&from), &flen);
        if (n < 8 || modbus_crc(buf, 6) != (buf[6] | (buf[7] << 8))) return;
        std::vector<uint8_t> resp = {0xAA, 0x55};
        const auto rtu = rtu_answer(buf[0], buf[1], {0x0000, 0x0BB8});  // 3.000 W
        resp.insert(resp.end(), rtu.begin(), rtu.end());
        sendto(udp, reinterpret_cast<const char*>(resp.data()), static_cast<int>(resp.size()), 0,
               reinterpret_cast<sockaddr*>(&from), flen);
    });
    ModbusClient gw("127.0.0.1", ntohs(a.sin_port), 0xF7, "", 3000, "GoodWe", Framing::GoodweUdp);
    gw.connect();
    CHECK(gw.read_registers(35105, 2, 0xF7, 3) == std::vector<uint16_t>{0x0000, 0x0BB8});
    goodwe.join();
    closesocket(udp);
}

TEST_CASE("postavke: proizvođač, serijski broj loggera i predznak mjerača") {
    CHECK(*parse_logger_serial("2712345678") == 2712345678u);
    CHECK_FALSE(parse_logger_serial(""));
    CHECK_FALSE(parse_logger_serial("27123x5678"));
    CHECK_FALSE(parse_logger_serial("99999999999"));
    CHECK_FALSE(parse_logger_serial("0"));
    json f = valid_form();
    f["device_type"] = "vendor";
    f["device_profile"] = "nepostojeći";
    CHECK(validate_form(f, Settings{}, kIfaces).errors.contains("device_profile"));
    f["device_profile"] = "deye_hybrid";
    f["modbus_port"] = "8899";
    f["logger_serial"] = "";
    CHECK(validate_form(f, Settings{}, kIfaces).errors.contains("logger_serial"));
    f["logger_serial"] = " 2712345678 ";
    f["meter_invert"] = true;
    const auto v = validate_form(f, Settings{}, kIfaces);
    CHECK(v.errors.empty());
    CHECK(v.settings->device_profile == "deye_hybrid");
    CHECK(v.settings->logger_serial == "2712345678");
    CHECK(v.settings->meter_invert);
    f["modbus_port"] = "502";  // Deye preko Modbus TCP pristupnika – bez serijskog broja
    f["logger_serial"] = "";
    CHECK(validate_form(f, Settings{}, kIfaces).errors.empty());
}

TEST_CASE("postavke: palete boja – provjera, spremanje i dashboard") {
    CHECK(is_palette(""));
    CHECK(is_palette("ocean"));
    CHECK_FALSE(is_palette("ljubičasta"));
    json f = valid_form();
    f["palette"] = "ocean";
    f["theme"] = "dark";
    const auto v = validate_form(f, Settings{}, kIfaces);
    REQUIRE(v.errors.empty());
    CHECK(v.settings->palette == "ocean");
    CHECK(settings_from_json(to_json(*v.settings)).palette == "ocean");
    CHECK(ui_settings(*v.settings)["palette"] == "ocean");
    json remote = ui_settings(Settings{});
    apply_local_display(remote, *v.settings);  // klijent preko tunela: paleta je lokalna
    CHECK(remote["palette"] == "ocean");
    f["palette"] = "light";  // boje same teme
    CHECK(validate_form(f, Settings{}, kIfaces).settings->palette.empty());
    f["palette"] = "nepostojeća";
    CHECK(validate_form(f, Settings{}, kIfaces).errors.contains("palette"));
    CHECK(settings_from_json(json{{"palette", "x"}}).palette.empty());  // nepoznata paleta u config.json → boje teme
}

TEST_CASE("widgeti uređaja: baterija, temperatura i mreža preko Modbusa, baza i mogućnosti") {
    NetInit net;
    // Victron GX s baterijom: SOC 843 = 76 %, snaga 842 = +1.250 W (punjenje)
    LocalServer gx([&](SOCKET c) {
        FakeRegisters f;
        for (uint16_t a = 808; a <= 850; ++a) f.regs[a] = 0;
        f.regs[808] = 2000;
        f.regs[842] = 1250;
        f.regs[843] = 76;
        serve_modbus(c, {{100, f}}, 3);
    });
    Settings v;
    v.device_type = "vendor";
    v.device_profile = "victron";
    v.modbus_host = "127.0.0.1";
    v.modbus_port = gx.port();
    v.inverter_units = "100";
    v.meter_unit_id = 0;
    const PlantReading g = read_plant(v);
    CHECK(g.extra["battery_soc"] == doctest::Approx(76));
    CHECK(g.extra["battery_kw"] == doctest::Approx(1.25));
    CHECK(g.extra["battery_dir"] == true);
    // Deye hibridni: temperatura 0x5B = 1385 → 38,5 °C (pomak 1000), napon 0x96 = 2312 → 231,2 V, 50,02 Hz,
    // baterija 0xB8 = 64 %, 0xBE = +800 W (Deye: > 0 pražnjenje → −0,8 kW)
    LocalServer dy([&](SOCKET c) {
        FakeRegisters f;
        for (uint16_t a = 0x3C; a <= 0xC0; ++a) f.regs[a] = 0;
        f.regs[0x5B] = 1385;
        f.regs[0x96] = 2312;
        f.regs[0x4F] = 5002;
        f.regs[0xB8] = 64;
        f.regs[0xBE] = 800;
        f.regs[0xBA] = 1500;
        serve_modbus(c, {{1, f}}, 3);
    });
    Settings d = v;
    d.device_profile = "deye_hybrid";
    d.modbus_port = dy.port();  // Modbus TCP pristupnik (ne 8899)
    d.inverter_units = "1";
    const PlantReading p = read_plant(d);
    CHECK(p.extra["inverter_temp"] == doctest::Approx(38.5));
    CHECK(p.extra["grid_v"] == doctest::Approx(231.2));
    CHECK(p.extra["grid_hz"] == doctest::Approx(50.02));
    CHECK(p.extra["battery_soc"] == doctest::Approx(64));
    CHECK(p.extra["battery_kw"] == doctest::Approx(-0.8));
    // hibrid bez baterije: adrese baterije ne postoje → ostali podaci se čitaju, baterije nema, očitanje uspijeva
    LocalServer nb([&](SOCKET c) {
        FakeRegisters f;
        for (uint16_t a = 0x3C; a <= 0xB7; ++a) f.regs[a] = 0;
        f.regs[0x5B] = 1300;
        f.regs[0xBA] = 900;
        for (uint16_t a = 0xBA; a <= 0xBD; ++a) f.regs[a] = a == 0xBA ? 900 : 0;
        serve_modbus(c, {{1, f}}, 3);
    });
    d.modbus_port = nb.port();
    const PlantReading q = read_plant(d);
    CHECK(q.reading.power_kw == doctest::Approx(0.9));
    CHECK(q.extra["inverter_temp"] == doctest::Approx(30.0));
    CHECK_FALSE(q.extra.contains("battery_soc"));
    CHECK_FALSE(q.extra.contains("battery_kw"));

    // baza: extra se sprema i vraća; stare baze dobiju stupac
    TempDir tmp;
    Db db(tmp.path / "solar.db");
    Reading r;
    r.power_kw = 2;
    r.e_total_kwh = 10;
    db.insert(now(), r, std::nullopt, p.extra);
    CHECK(db.latest()->extra["battery_soc"] == doctest::Approx(64));
    db.insert(now() + 1, r, std::nullopt);  // bez podataka uređaja
    CHECK(db.latest()->extra.empty());

    // mogućnosti uređaja → koji se widgeti nude
    auto caps = [](const char* type, const char* profile) {
        Settings s;
        s.device_type = type;
        s.device_profile = profile;
        return device_capabilities(s);
    };
    using V = std::vector<std::string>;
    CHECK(caps("vendor", "victron") == V{"battery", "offgrid"});  // 3.2: napon baterije i AC potrošnja
    CHECK(caps("vendor", "deye_hybrid") == V{"temperature", "grid", "battery"});
    CHECK(caps("vendor", "foxess").empty());
    CHECK(caps("logger", "").empty());
    CHECK(caps("sunspec", "") == V{"temperature", "grid"});
}

TEST_CASE("widgeti uređaja: SunSpec i Fronius daju temperaturu, mrežu i bateriju") {
    auto d = model103(3000, 0, 1000, 0, 100, 0, 4);
    d[8] = 2304; d[11] = static_cast<uint16_t>(-1);    // 230,4 V
    d[14] = 5001; d[15] = static_cast<uint16_t>(-2);   // 50,01 Hz
    d[31] = 412; d[35] = static_cast<uint16_t>(-1);    // 41,2 °C
    const json x = sunspec_extras(103, d);
    CHECK(x["grid_v"] == doctest::Approx(230.4));
    CHECK(x["grid_hz"] == doctest::Approx(50.01));
    CHECK(x["inverter_temp"] == doctest::Approx(41.2));
    d[31] = 0x8000;  // neimplementirano → izostavlja se
    CHECK_FALSE(sunspec_extras(103, d).contains("inverter_temp"));
    const json gen24 = json::parse(R"({"Body":{"Data":{"Site":{"P_PV":3000,"P_Grid":0,"P_Akku":-1500,"E_Total":5000},
        "Inverters":{"1":{"P":3000,"SOC":82.5}}}}})");
    const PlantReading f = parse_fronius_powerflow(gen24, false);
    CHECK(f.extra["battery_soc"] == doctest::Approx(82.5));
    CHECK(f.extra["battery_kw"] == doctest::Approx(1.5));  // P_Akku < 0 = punjenje
}

TEST_CASE("kriptografija: SHA-256, HMAC i PBKDF2 prema službenim testnim vektorima") {
    CHECK(to_hex(sha256("abc")) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    // RFC 4231, slučaj 2
    CHECK(to_hex(hmac_sha256(Bytes{'J', 'e', 'f', 'e'}, "what do ya want for nothing?")) ==
          "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
    // RFC 7914, poglavlje 11 (PBKDF2-HMAC-SHA256)
    CHECK(to_hex(pbkdf2_sha256("passwd", Bytes{'s', 'a', 'l', 't'}, 1, 64)) ==
          "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783");
    CHECK(random_bytes(32) != random_bytes(32));
}

TEST_CASE("kriptografija: AES-256-GCM – povratak, izmijenjen šifrat, pogrešan ključ i namjena") {
    const Bytes key = random_bytes(kAesKeyBytes);
    const Bytes sealed = aes_gcm_encrypt(key, "ana.horvat@primjer.hr", "user.email");
    CHECK(sealed.size() == kGcmNonceBytes + 21 + kGcmTagBytes);
    CHECK(aes_gcm_decrypt(key, sealed, "user.email") == std::optional<std::string>("ana.horvat@primjer.hr"));
    CHECK(aes_gcm_encrypt(key, "isto", "a") != aes_gcm_encrypt(key, "isto", "a"));  // slučajni nonce
    Bytes bad = sealed;
    bad[kGcmNonceBytes + 3] ^= 1;
    CHECK_FALSE(aes_gcm_decrypt(key, bad, "user.email"));
    CHECK_FALSE(aes_gcm_decrypt(random_bytes(kAesKeyBytes), sealed, "user.email"));
    CHECK_FALSE(aes_gcm_decrypt(key, sealed, "user.first_name"));  // šifrat se ne može podmetnuti u drugo polje
    CHECK(aes_gcm_decrypt(key, aes_gcm_encrypt(key, "", "x"), "x") == std::optional<std::string>(""));
}

TEST_CASE("kriptografija: base64url i usporedba u stalnom vremenu") {
    for (size_t n : {0, 1, 2, 3, 31, 32, 33}) {
        const Bytes b = random_bytes(n);
        const std::string s = base64url(b);
        CHECK(s.find_first_of("+/=") == std::string::npos);
        CHECK(from_base64url(s) == std::optional<Bytes>(b));
    }
    CHECK_FALSE(from_base64url("ab$c"));
    CHECK(equal_ct(Bytes{1, 2}, Bytes{1, 2}));
    CHECK_FALSE(equal_ct(Bytes{1, 2}, Bytes{1, 3}));
    CHECK_FALSE(equal_ct(Bytes{1}, Bytes{1, 2}));
}

TEST_CASE("korisnici: pravila lozinke i e-pošte") {
    CHECK(password_problem("Kratka1!", "a@b.hr"));
    CHECK(password_problem("samomalaslova", "a@b.hr"));               // jedna vrsta, < 16
    CHECK_FALSE(password_problem("Sunce-2026-ploce", "a@b.hr"));
    CHECK_FALSE(password_problem("sunce elektrana krov", "a@b.hr"));  // ≥ 16 znakova
    CHECK(password_problem("Ana.Horvat-2026", "ana.horvat@primjer.hr"));  // sadrži e-poštu
    CHECK(valid_email("ana.horvat@primjer.hr"));
    CHECK_FALSE(valid_email("ana@primjer"));
    CHECK_FALSE(valid_email("ana horvat@primjer.hr"));
    CHECK_FALSE(valid_email("@primjer.hr"));
}

TEST_CASE("korisnici: ključevi u datoteci su zaštićeni DPAPI-jem i ponovno se učitavaju") {
    TempDir dir;
    const UserKeys a = load_or_create_user_keys(dir.path / "users.key");
    const UserKeys b = load_or_create_user_keys(dir.path / "users.key");
    CHECK(a.aes == b.aes);
    CHECK(a.hmac == b.hmac);
    const std::string file = *read_file(dir.path / "users.key");
    CHECK(file.rfind("dpapi:", 0) == 0);
    write_file_atomic(dir.path / "bad.key", "dpapi:AAAA\r\n");
    CHECK_THROWS(load_or_create_user_keys(dir.path / "bad.key"));  // ne smije tiho stvoriti nove ključeve
}

TEST_CASE("korisnici: baza ne sadrži e-poštu, ime ni lozinku u čitljivom obliku") {
    TempDir dir;
    {
        UserStore st(dir.path / "users.db", {random_bytes(32), random_bytes(32)}, kTestIterations);
        st.create({"Marija", "Kovačević", "marija.kovacevic@primjer.hr", "Tajna-Lozinka-77", Role::Admin}, 1000);
    }
    std::string raw;
    for (const auto& e : fs::directory_iterator(dir.path)) raw += read_file(e.path()).value_or("");
    for (const char* s : {"marija", "Marija", "Kova", "primjer.hr", "Tajna-Lozinka-77"}) CHECK(raw.find(s) == std::string::npos);
}

TEST_CASE("korisnici: administrator, prijava, oznaka prijave i odjava") {
    TempDir dir;
    UserStore st(dir.path / "users.db", {random_bytes(32), random_bytes(32)}, kTestIterations);
    CHECK_FALSE(st.has_admin());
    const int64_t admin = st.create(person("admin@primjer.hr", Role::Admin), 1000);
    CHECK(st.has_admin());
    CHECK_THROWS_AS(st.create(person("ADMIN@primjer.hr "), 1000), UserError);  // e-pošta bez obzira na velika slova

    const LoginResult ok = st.login(" Admin@Primjer.hr", "Sunce-2026-ploce", "Pixel 8", 2000);
    REQUIRE(ok.status == LoginResult::Status::Ok);
    CHECK(ok.token.size() == 43);
    CHECK(ok.user->id == admin);
    CHECK(ok.user->role == Role::Admin);
    CHECK(ok.user->first_name == "Ana");
    REQUIRE(st.session_user(ok.token, 2100));
    CHECK(st.session_user(ok.token, 2100)->email == "admin@primjer.hr");
    CHECK_FALSE(st.session_user(ok.token + "x", 2100));
    CHECK_FALSE(st.session_user("", 2100));
    CHECK(st.active_sessions(admin, 2100) == 1);
    st.logout(ok.token);
    CHECK_FALSE(st.session_user(ok.token, 2200));

    CHECK(st.login("admin@primjer.hr", "pogresna-lozinka", "", 3000).status == LoginResult::Status::BadCredentials);
    CHECK(st.login("nema@primjer.hr", "Sunce-2026-ploce", "", 3000).status == LoginResult::Status::BadCredentials);
}

TEST_CASE("korisnici: prijava istječe nakon 30 dana nekorištenja i najkasnije nakon 180 dana") {
    TempDir dir;
    UserStore st(dir.path / "users.db", {random_bytes(32), random_bytes(32)}, kTestIterations);
    st.create(person("ana@primjer.hr"), 0);
    const std::string t = st.login("ana@primjer.hr", "Sunce-2026-ploce", "", 0).token;
    CHECK(st.session_user(t, kSessionIdleSeconds - 10));                        // korištena → produžena
    CHECK(st.session_user(t, 2 * kSessionIdleSeconds - 100));
    CHECK_FALSE(st.session_user(t, 3 * kSessionIdleSeconds + 100));             // 30 dana bez korištenja
    const std::string t2 = st.login("ana@primjer.hr", "Sunce-2026-ploce", "", 0).token;
    std::time_t now = 0;
    for (; now < kSessionMaxSeconds - kSessionIdleSeconds; now += kSessionIdleSeconds / 2) CHECK(st.session_user(t2, now));
    CHECK_FALSE(st.session_user(t2, kSessionMaxSeconds + 1));                   // najdulje 180 dana
}

TEST_CASE("korisnici: 5 pogrešnih lozinaka zaključava račun na 15 minuta") {
    TempDir dir;
    UserStore st(dir.path / "users.db", {random_bytes(32), random_bytes(32)}, kTestIterations);
    st.create(person("ana@primjer.hr"), 0);
    for (int i = 0; i < kMaxFailedLogins - 1; ++i) CHECK(st.login("ana@primjer.hr", "krivo", "", 100).status == LoginResult::Status::BadCredentials);
    const LoginResult locked = st.login("ana@primjer.hr", "krivo", "", 100);
    CHECK(locked.status == LoginResult::Status::Locked);
    CHECK(locked.locked_until == 100 + kLockSeconds);
    CHECK(st.login("ana@primjer.hr", "Sunce-2026-ploce", "", 200).status == LoginResult::Status::Locked);  // ni ispravna
    CHECK(st.login("ana@primjer.hr", "Sunce-2026-ploce", "", 100 + kLockSeconds + 1).status == LoginResult::Status::Ok);
    CHECK(st.login("ana@primjer.hr", "krivo", "", 2000).status == LoginResult::Status::BadCredentials);  // brojač ispočetka
}

TEST_CASE("korisnici: promjena lozinke, blokiranje i brisanje poništavaju prijave; zadnji administrator ostaje") {
    TempDir dir;
    UserStore st(dir.path / "users.db", {random_bytes(32), random_bytes(32)}, kTestIterations);
    const int64_t admin = st.create(person("admin@primjer.hr", Role::Admin), 0);
    const int64_t ana = st.create(person("ana@primjer.hr"), 0);
    std::string t = st.login("ana@primjer.hr", "Sunce-2026-ploce", "", 10).token;

    CHECK_THROWS_AS(st.change_password(ana, "krivo", "Nova-Lozinka-2026", 20), UserError);
    st.change_password(ana, "Sunce-2026-ploce", "Nova-Lozinka-2026", 20);
    CHECK_FALSE(st.session_user(t, 30));
    CHECK(st.login("ana@primjer.hr", "Sunce-2026-ploce", "", 40).status == LoginResult::Status::BadCredentials);
    t = st.login("ana@primjer.hr", "Nova-Lozinka-2026", "", 40).token;

    st.set_disabled(ana, true, 50);
    CHECK_FALSE(st.session_user(t, 60));
    CHECK(st.login("ana@primjer.hr", "Nova-Lozinka-2026", "", 60).status == LoginResult::Status::Disabled);
    st.set_disabled(ana, false, 70);
    CHECK(st.login("ana@primjer.hr", "Nova-Lozinka-2026", "", 80).status == LoginResult::Status::Ok);

    CHECK_THROWS_AS(st.set_disabled(admin, true, 90), UserError);
    CHECK_THROWS_AS(st.remove(admin), UserError);
    CHECK_THROWS_AS(st.update(admin, person("admin@primjer.hr", Role::User, ""), 90), UserError);
    st.update(ana, {"Ana", "Kovač", "ana.kovac@primjer.hr", "", Role::Admin}, 100);  // prazna lozinka = ostaje
    CHECK(st.get(ana)->last_name == "Kovač");
    CHECK(st.get(ana)->role == Role::Admin);
    CHECK(st.login("ana.kovac@primjer.hr", "Nova-Lozinka-2026", "", 110).status == LoginResult::Status::Ok);
    st.remove(admin);  // sada postoji drugi administrator
    CHECK(st.list().size() == 1);

    try {
        st.create({"", "", "nije-email", "kratko", Role::User}, 0);
        FAIL("očekivana greška");
    } catch (const UserError& e) {
        CHECK(e.fields.count("first_name"));
        CHECK(e.fields.count("last_name"));
        CHECK(e.fields.count("email"));
        CHECK(e.fields.count("password"));
    }
}

// ================================================================ 3.1: dvofaktorska prijava (TOTP)
TEST_CASE("TOTP: službeni testni vektori RFC 6238 (SHA1) i Base32") {
    const Bytes secret = {'1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0'};
    CHECK(totp_code(secret, totp_step(59), 8) == "94287082");
    CHECK(totp_code(secret, totp_step(1111111109), 8) == "07081804");
    CHECK(totp_code(secret, totp_step(1234567890), 8) == "89005924");
    CHECK(totp_code(secret, totp_step(2000000000), 8) == "69279037");
    CHECK(totp_code(secret, totp_step(59)) == "287082");
    CHECK(base32(secret) == "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
    CHECK(from_base32("gezd gnbv gy3t qojq gezd gnbv gy3t qojq") == std::optional<Bytes>(secret));
    CHECK_FALSE(from_base32("GEZ1"));
    CHECK(otpauth_uri("Solarni monitor", "ana@primjer.hr", secret) ==
          "otpauth://totp/Solarni%20monitor:ana@primjer.hr?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Solarni%20monitor"
          "&algorithm=SHA1&digits=6&period=30");
}

TEST_CASE("TOTP: provjera koda – ±30 s, isti kod ne vrijedi dvaput") {
    const Bytes secret = random_bytes(kTotpSecretBytes);
    const std::time_t t = 1'800'000'000;
    const std::string now_code = totp_code(secret, totp_step(t));
    CHECK(totp_verify(secret, now_code, t, 0) == std::optional<int64_t>(totp_step(t)));
    CHECK(totp_verify(secret, totp_code(secret, totp_step(t) - 1), t, 0));  // sat mobitela kasni
    CHECK(totp_verify(secret, totp_code(secret, totp_step(t) + 1), t, 0));  // sat mobitela žuri
    CHECK_FALSE(totp_verify(secret, totp_code(secret, totp_step(t) - 3), t, 0));
    CHECK_FALSE(totp_verify(secret, now_code, t, totp_step(t)));  // već iskorišten
    CHECK(totp_verify(secret, now_code.substr(0, 3) + " " + now_code.substr(3), t, 0));  // "123 456"
    CHECK_FALSE(totp_verify(secret, "12345", t, 0));
    const auto codes = make_recovery_codes();
    CHECK(codes.size() == 8);
    CHECK(codes[0].size() == 9);
    CHECK(normalize_recovery_code(" ABCD-efgh ") == "abcdefgh");
}

TEST_CASE("korisnici 3.1: postavljanje dvofaktorske prijave QR kodom, prijava kodom, oporavak i poništavanje") {
    TempDir dir;
    UserStore st(dir.path / "users.db", {random_bytes(32), random_bytes(32)}, kTestIterations);
    UserInput in = person("ana@primjer.hr");
    in.totp_required = true;
    const int64_t ana = st.create(in, 0);
    const std::time_t t = 1'800'000'000;

    // lozinka točna, aplikacija još nije postavljena → QR kod (tajna se ne mijenja do potvrde)
    LoginResult r = st.login("ana@primjer.hr", "Sunce-2026-ploce", "", t);
    REQUIRE(r.status == LoginResult::Status::TotpSetup);
    CHECK(r.token.empty());
    CHECK(r.totp_uri.rfind("otpauth://totp/", 0) == 0);
    CHECK(st.login("ana@primjer.hr", "Sunce-2026-ploce", "", t).totp_secret == r.totp_secret);
    CHECK(st.login("ana@primjer.hr", "krivo", "", t).status == LoginResult::Status::BadCredentials);  // lozinka i dalje prva
    const Bytes secret = *from_base32(r.totp_secret);
    CHECK(st.login("ana@primjer.hr", "Sunce-2026-ploce", "", t, "000000").status == LoginResult::Status::TotpInvalid);
    r = st.login("ana@primjer.hr", "Sunce-2026-ploce", "", t, totp_code(secret, totp_step(t)));
    REQUIRE(r.status == LoginResult::Status::Ok);
    CHECK(r.recovery_codes.size() == 8);
    CHECK(r.totp_secret.empty());
    CHECK(st.get(ana)->totp_enabled);
    CHECK(st.get(ana)->recovery_left == 8);

    // postavljeno: bez koda nema prijave, isti kod ne vrijedi dvaput, novi kod vrijedi
    CHECK(st.login("ana@primjer.hr", "Sunce-2026-ploce", "", t + 5).status == LoginResult::Status::TotpRequired);
    CHECK(st.login("ana@primjer.hr", "Sunce-2026-ploce", "", t + 5).totp_uri.empty());  // QR se više ne prikazuje
    CHECK(st.login("ana@primjer.hr", "Sunce-2026-ploce", "", t + 5, totp_code(secret, totp_step(t))).status == LoginResult::Status::TotpInvalid);
    CHECK(st.login("ana@primjer.hr", "Sunce-2026-ploce", "", t + 30, totp_code(secret, totp_step(t + 30))).status == LoginResult::Status::Ok);

    // kod za oporavak – jednokratan
    CHECK(st.login("ana@primjer.hr", "Sunce-2026-ploce", "", t + 60, r.recovery_codes[3]).status == LoginResult::Status::Ok);
    CHECK(st.get(ana)->recovery_left == 7);
    CHECK(st.login("ana@primjer.hr", "Sunce-2026-ploce", "", t + 60, r.recovery_codes[3]).status == LoginResult::Status::TotpInvalid);

    // pogrešni kodovi broje se u zaključavanje računa
    for (int i = 0; i < kMaxFailedLogins - 2; ++i) st.login("ana@primjer.hr", "Sunce-2026-ploce", "", t + 90, "111111");
    CHECK(st.login("ana@primjer.hr", "Sunce-2026-ploce", "", t + 90, "111111").status == LoginResult::Status::Locked);
    CHECK(st.login("ana@primjer.hr", "Sunce-2026-ploce", "", t + 100, totp_code(secret, totp_step(t + 100))).status == LoginResult::Status::Locked);

    // izgubljen mobitel: administrator poništi → nova tajna i QR pri sljedećoj prijavi, stare prijave prestaju
    const std::time_t later = t + kLockSeconds + 200;
    const std::string token = st.login("ana@primjer.hr", "Sunce-2026-ploce", "", later, totp_code(secret, totp_step(later))).token;
    REQUIRE_FALSE(token.empty());
    st.reset_totp(ana, later);
    CHECK_FALSE(st.session_user(token, later));
    const LoginResult again = st.login("ana@primjer.hr", "Sunce-2026-ploce", "", later + 30);
    CHECK(again.status == LoginResult::Status::TotpSetup);
    CHECK(again.totp_secret != base32(secret));

    // isključivanje: prijava samo lozinkom
    UserInput off = person("ana@primjer.hr");
    st.update(ana, off, later + 40);
    CHECK(st.login("ana@primjer.hr", "Sunce-2026-ploce", "", later + 50).status == LoginResult::Status::Ok);
    CHECK_FALSE(st.get(ana)->totp_required);
}

TEST_CASE("korisnici 3.1: tajna dvofaktorske prijave nije u bazi u čitljivom obliku; baza iz 3.0 se nadogradi") {
    TempDir dir;
    // baza 3.0 (bez stupaca za TOTP)
    {
        sqlite3* db = nullptr;
        sqlite3_open(narrow((dir.path / "users.db").wstring()).c_str(), &db);
        sqlite3_exec(db, "CREATE TABLE users (id INTEGER PRIMARY KEY, role TEXT NOT NULL, email_tag BLOB NOT NULL UNIQUE,"
                         " first_enc BLOB NOT NULL, last_enc BLOB NOT NULL, email_enc BLOB NOT NULL, pw_salt BLOB, pw_hash BLOB,"
                         " pw_iter INTEGER, disabled INTEGER NOT NULL DEFAULT 0, failed INTEGER NOT NULL DEFAULT 0,"
                         " locked_until INTEGER NOT NULL DEFAULT 0, created INTEGER NOT NULL, updated INTEGER NOT NULL,"
                         " last_login INTEGER NOT NULL DEFAULT 0)", nullptr, nullptr, nullptr);
        sqlite3_close(db);
    }
    const UserKeys keys{random_bytes(32), random_bytes(32)};
    std::string b32;
    {
        UserStore st(dir.path / "users.db", keys, kTestIterations);
        UserInput in = person("ana@primjer.hr", Role::Admin);
        in.totp_required = true;
        st.create(in, 0);
        b32 = st.login("ana@primjer.hr", "Sunce-2026-ploce", "", 1000).totp_secret;
        REQUIRE_FALSE(b32.empty());
    }
    std::string raw;
    for (const auto& e : fs::directory_iterator(dir.path)) raw += read_file(e.path()).value_or("");
    CHECK(raw.find(b32) == std::string::npos);
    const Bytes s = *from_base32(b32);
    CHECK(raw.find(std::string(s.begin(), s.end())) == std::string::npos);
}

TEST_CASE("prognoza 3.1: grad iz geokodiranja i broj dana (2, 3 ili 5)") {
    const json raw = json::parse(R"({"results":[
        {"name":"Zagreb","latitude":45.81444,"longitude":15.97798,"country":"Hrvatska","admin1":"Grad Zagreb"},
        {"name":"Zagreb","latitude":44.1,"longitude":20.2,"country":"Srbija"},
        {"name":"bez koordinata"}]})");
    const json places = parse_geocoding(raw);
    REQUIRE(places.size() == 2);
    CHECK(places[0]["label"] == "Zagreb, Grad Zagreb, Hrvatska");
    CHECK(places[0]["lat"].get<double>() == doctest::Approx(45.81444));
    CHECK(places[1]["label"] == "Zagreb, Srbija");
    CHECK(parse_geocoding(json::object()).empty());

    Settings cur;
    CHECK(cur.forecast_days == 5);
    json form = valid_form();
    form["forecast_days"] = 3;
    form["weather_city"] = "Osijek, Osječko-baranjska, Hrvatska";
    auto v = validate_form(form, cur, {"Ethernet", "Wi-Fi"});
    REQUIRE(v.settings);
    CHECK(v.settings->forecast_days == 3);
    CHECK(v.settings->weather_city == "Osijek, Osječko-baranjska, Hrvatska");
    form["forecast_days"] = "4";
    CHECK(validate_form(form, cur, {"Ethernet", "Wi-Fi"}).errors.count("forecast_days"));
    json j = to_json(cur, false);
    j["forecast_days"] = 7;
    CHECK(settings_from_json(j).forecast_days == 5);
    json display = json::object();
    Settings local;
    local.forecast_days = 2;
    apply_local_display(display, local);
    CHECK(display["forecast_days"] == 2);  // svaki zaslon ima svoj broj dana
}

// ================================================================ 3.2: otočni sustavi (Voltronic, VE.Direct, serijski profili)
namespace {
// VE.Direct blok s ispravnim kontrolnim zbrojem (zbroj svih bajtova mod 256 = 0)
std::string ve_block(const std::vector<std::pair<std::string, std::string>>& fields) {
    std::string b;
    for (const auto& [k, v] : fields) b += "\r\n" + k + "\t" + v;
    b += "\r\nChecksum\t";
    unsigned sum = 0;
    for (unsigned char c : b) sum += c;
    b += static_cast<char>((256 - (sum & 0xFF)) & 0xFF);
    return b;
}
}  // namespace

TEST_CASE("Voltronic: CRC prema poznatim okvirima protokola i QPIGS") {
    CHECK(voltronic_frame("QPIGS") == std::string("QPIGS\xB7\xA9\r"));
    CHECK(voltronic_frame("QMOD") == std::string("QMOD\x49\xC1\r"));
    CHECK(voltronic_frame("QPIRI") == std::string("QPIRI\xF8\x54\r"));
    const std::string fields = "000.0 00.0 230.0 49.9 0161 0119 003 460 26.50 012 085 0041 0014 103.8 26.45 00000 00110110 00 00 00856 010";
    const uint16_t crc = voltronic_crc("(" + fields);
    const std::string raw = "(" + fields + static_cast<char>(crc >> 8) + static_cast<char>(crc & 0xFF) + "\r";
    CHECK(voltronic_unwrap(raw) == fields);
    std::string bad = raw;
    bad[5] = '9';
    CHECK_THROWS_AS(voltronic_unwrap(bad), SerialError);
    const auto st = parse_qpigs(fields);
    REQUIRE(st);
    CHECK(st->out_v == doctest::Approx(230.0));
    CHECK(st->out_w == doctest::Approx(119));
    CHECK(st->battery_v == doctest::Approx(26.5));
    CHECK(st->battery_pct == doctest::Approx(85));
    CHECK(st->pv_w == doctest::Approx(856));  // polje 20 (novije verzije)
    CHECK(parse_qpigs("000.0 00.0 230.0 49.9 0161 0119 003 460 26.50 012 085 0041 0014 103.8 26.45 00000")->pv_w == doctest::Approx(14 * 103.8));
    CHECK_FALSE(parse_qpigs("NAK"));
    CHECK(nominal_system_voltage(13.2) == 12);
    CHECK(nominal_system_voltage(26.5) == 24);
    CHECK(nominal_system_voltage(52.1) == 48);
    CHECK(nominal_system_voltage(0) == 0);
}

TEST_CASE("VE.Direct: blokovi s kontrolnim zbrojem, oštećeni i HEX se odbacuju, MPPT + SmartShunt + Phoenix se zbrajaju") {
    const std::string mppt = ve_block({{"PID", "0xA053"}, {"SER#", "HQ1"}, {"V", "26150"}, {"I", "3200"}, {"VPV", "76550"}, {"PPV", "85"},
                                       {"CS", "3"}, {"H19", "1234"}, {"H20", "56"}});
    const std::string shunt = ve_block({{"PID", "0xA389"}, {"SER#", "HQ2"}, {"V", "26100"}, {"I", "-1500"}, {"P", "-39"}, {"SOC", "845"}});
    const std::string phoenix = ve_block({{"PID", "0xA231"}, {"SER#", "HQ3"}, {"V", "26000"}, {"AC_OUT_V", "23000"}, {"AC_OUT_I", "10"},
                                          {"AC_OUT_S", "230"}});
    std::string corrupt = ve_block({{"PID", "0xA053"}, {"SER#", "HQ9"}, {"PPV", "999"}});
    corrupt[10] = 'X';
    const std::string stream = "e\t12" + mppt + ":A0002000148\n" + corrupt + shunt + phoenix;  // početak u pola bloka, HEX poruka
    const auto blocks = parse_vedirect(stream);
    REQUIRE(blocks.size() == 3);
    const VeSummary s = summarize_vedirect(blocks);
    CHECK(s.pv_w == doctest::Approx(85));
    CHECK(s.today_kwh == doctest::Approx(0.56));
    CHECK(s.total_kwh == doctest::Approx(12.34));
    CHECK(s.extra["battery_v"].get<double>() == doctest::Approx(26.1));  // šant ima prednost
    CHECK(s.extra["battery_soc"].get<double>() == doctest::Approx(84.5));
    CHECK(s.extra["battery_kw"].get<double>() == doctest::Approx(-0.039));
    CHECK(s.extra["ac_load_kw"].get<double>() == doctest::Approx(0.23));
    CHECK(s.extra["ac_out_v"].get<double>() == doctest::Approx(230.0));
    // samo MPPT: bez SOC-a nema widgeta baterije, ali napon postoji
    const VeSummary only = summarize_vedirect(parse_vedirect(mppt));
    CHECK_FALSE(only.extra.contains("battery_soc"));
    CHECK(only.extra["battery_v"].get<double>() == doctest::Approx(26.15));
}

TEST_CASE("otočni uređaji: postavke serijskog porta, profili i mogućnosti") {
    CHECK(is_serial_port_name("COM3"));
    CHECK(is_serial_port_name("COM256"));
    CHECK_FALSE(is_serial_port_name("COM0"));
    CHECK_FALSE(is_serial_port_name("LPT1"));
    CHECK_FALSE(is_serial_port_name("COM3; del"));
    for (const char* k : {"growatt_spf", "epever", "srne"}) {
        const VendorProfile* p = find_vendor(k);
        REQUIRE(p);
        CHECK(p->link == VendorLink::Serial);
        CHECK(is_serial_device("vendor", k));
    }
    CHECK(is_serial_device("voltronic", ""));
    CHECK(is_serial_device("vedirect", ""));
    CHECK_FALSE(is_serial_device("vendor", "sungrow_sg"));

    Settings cur;
    json form = valid_form();
    form["device_type"] = "voltronic";
    form["serial_port"] = "usb";
    form["logger_interface"] = "";  // otočni uređaj na USB-u: mrežna kartica nije potrebna
    form["modbus_host"] = "";
    auto v = validate_form(form, cur, {"Ethernet", "Wi-Fi"});
    REQUIRE(v.settings);
    CHECK(v.settings->serial_port == "USB");
    form["device_type"] = "vedirect";
    form["serial_port"] = "com3, COM4";
    v = validate_form(form, cur, {"Ethernet", "Wi-Fi"});
    REQUIRE(v.settings);
    CHECK(v.settings->serial_port == "COM3,COM4");
    form["serial_port"] = "USB";  // VE.Direct nema HID
    CHECK(validate_form(form, cur, {"Ethernet", "Wi-Fi"}).errors.count("serial_port"));
    form["device_type"] = "vendor";
    form["device_profile"] = "epever";
    form["serial_port"] = "COM5";
    form["serial_baud"] = "9600";
    v = validate_form(form, cur, {"Ethernet", "Wi-Fi"});
    REQUIRE(v.settings);
    CHECK(v.settings->serial_baud == 9600);
    form["serial_baud"] = "1234";
    CHECK(validate_form(form, cur, {"Ethernet", "Wi-Fi"}).errors.count("serial_baud"));

    Settings s;
    s.device_type = "voltronic";
    const auto caps = device_capabilities(s);
    CHECK(std::find(caps.begin(), caps.end(), "offgrid") != caps.end());
    s.device_type = "vendor";
    s.device_profile = "victron";
    const auto vic = device_capabilities(s);
    CHECK(std::find(vic.begin(), vic.end(), "offgrid") != vic.end());  // napon baterije i AC potrošnja s GX-a
}

TEST_CASE("korisnici 3.3: početna lozinka 12345678 – obavezna promjena pri prvoj prijavi, rok 7 dana, administrator je vraća") {
    TempDir dir;
    UserStore st(dir.path / "users.db", {random_bytes(32), random_bytes(32)}, kTestIterations);
    UserInput in = person("ana@primjer.hr");
    in.password.clear();  // bez lozinke = početna
    const int64_t ana = st.create(in, 0);
    CHECK(st.get(ana)->must_change_password);
    CHECK(st.get(ana)->default_password_until == kDefaultPasswordSeconds);

    // točna početna lozinka, ali bez nove: nema oznake prijave
    LoginResult r = st.login("ana@primjer.hr", kDefaultPassword, "", 100);
    CHECK(r.status == LoginResult::Status::PasswordChange);
    CHECK(r.token.empty());
    CHECK(st.login("ana@primjer.hr", "krivo", "", 100, "", "Nova-Lozinka-2026").status == LoginResult::Status::BadCredentials);
    r = st.login("ana@primjer.hr", kDefaultPassword, "", 100, "", "kratka");
    CHECK(r.status == LoginResult::Status::PasswordInvalid);
    CHECK_FALSE(r.problem.empty());
    CHECK(st.login("ana@primjer.hr", kDefaultPassword, "", 100, "", kDefaultPassword).status == LoginResult::Status::PasswordInvalid);
    r = st.login("ana@primjer.hr", kDefaultPassword, "", 100, "", "Nova-Lozinka-2026");
    REQUIRE(r.status == LoginResult::Status::Ok);
    CHECK_FALSE(r.token.empty());
    CHECK_FALSE(st.get(ana)->must_change_password);
    CHECK(st.login("ana@primjer.hr", kDefaultPassword, "", 200).status == LoginResult::Status::BadCredentials);  // početna više ne vrijedi
    CHECK(st.login("ana@primjer.hr", "Nova-Lozinka-2026", "", 200).status == LoginResult::Status::Ok);

    // zaboravljena lozinka: administrator vraća početnu – stare prijave prestaju
    st.reset_to_default_password(ana, 1000);
    CHECK_FALSE(st.session_user(r.token, 1001));
    CHECK(st.login("ana@primjer.hr", "Nova-Lozinka-2026", "", 1002).status == LoginResult::Status::BadCredentials);
    CHECK(st.login("ana@primjer.hr", kDefaultPassword, "", 1002).status == LoginResult::Status::PasswordChange);
    // rok od 7 dana
    CHECK(st.login("ana@primjer.hr", kDefaultPassword, "", 1000 + kDefaultPasswordSeconds + 1, "", "Treca-Lozinka-2026").status ==
          LoginResult::Status::PasswordExpired);

    // s dvofaktorskom prijavom: najprije nova lozinka, zatim postavljanje aplikacije (s novom lozinkom)
    UserInput b = person("bruno@primjer.hr");
    b.password.clear();
    b.totp_required = true;
    st.create(b, 5000);
    r = st.login("bruno@primjer.hr", kDefaultPassword, "", 5001, "", "Sunce-Lozinka-77");
    CHECK(r.status == LoginResult::Status::TotpSetup);
    CHECK(st.login("bruno@primjer.hr", "Sunce-Lozinka-77", "", 5002).status == LoginResult::Status::TotpSetup);  // lozinka je već nova
}

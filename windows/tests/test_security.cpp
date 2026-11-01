// Regresijski testovi sigurnosnih popravaka 4.0 (SECURITY_FINDINGS.json: SMA-xx)
#include <doctest/doctest.h>

#include <windows.h>
#include <aclapi.h>

#include "alerts.hpp"
#include "config.hpp"
#include "util.hpp"

using namespace sm;

TEST_CASE("SMA-01: novi red u postavkama e-pošte ne može dodati curl opciju") {
    Settings s;
    s.smtp_host = "smtp.primjer.hr";
    s.smtp_port = 587;
    s.smtp_user = "solari@primjer.hr";
    const std::vector<std::string> to = {"a@primjer.hr"};
    const std::string ok = curl_mail_config(s, R"(Lo"z\inka)", "solari@primjer.hr", to);
    CHECK(ok == "url = \"smtp://smtp.primjer.hr:587\"\n"
                R"(user = "solari@primjer.hr:Lo\"z\\inka")" "\n"
                "mail-from = \"solari@primjer.hr\"\nmail-rcpt = \"a@primjer.hr\"\n");

    CHECK_THROWS_AS(curl_mail_config(s, "x", "a@b.hr\noutput = \"C:/Windows/x.dll\"", to), MailError);
    CHECK_THROWS_AS(curl_mail_config(s, "x", "a@b.hr", {"c@d.hr\rupload-file = C:/x"}), MailError);
    CHECK_THROWS_AS(curl_mail_config(s, "lo\nzinka", "a@b.hr", to), MailError);
    Settings bad_user = s;
    bad_user.smtp_user = "u\x01";
    CHECK_THROWS_AS(curl_mail_config(bad_user, "x", "a@b.hr", to), MailError);
    Settings bad_host = s;
    bad_host.smtp_host = "smtp.primjer.hr:25/\nproxy = http://zlo";
    CHECK_THROWS_AS(curl_mail_config(bad_host, "x", "a@b.hr", to), MailError);
    bad_host.smtp_host = "smtp.primjer.hr\"";
    CHECK_THROWS_AS(curl_mail_config(bad_host, "x", "a@b.hr", to), MailError);
    CHECK(valid_host_name("192.168.1.10"));
    CHECK(valid_host_name("mail.primjer.hr"));
    CHECK_FALSE(valid_host_name("1.2.3"));
    CHECK_FALSE(valid_host_name("a b"));
}

TEST_CASE("SMA-20: privremena datoteka s lozinkom ne nasljeđuje dozvole mape") {
    wchar_t dir[MAX_PATH];
    GetTempPathW(MAX_PATH, dir);
    const fs::path p = fs::path(dir) / L"solari_private_test.cfg";
    std::error_code ec;
    fs::remove(p, ec);
    write_private_file(p, "tajna");
    CHECK(read_file(p).value_or("") == "tajna");
    CHECK_THROWS(write_private_file(p, "drugo"));  // CREATE_NEW: postojeća (podmetnuta) datoteka se ne koristi
    PSECURITY_DESCRIPTOR sd = nullptr;
    PACL dacl = nullptr;
    REQUIRE(GetNamedSecurityInfoW(p.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr, &dacl, nullptr, &sd) ==
            ERROR_SUCCESS);
    SECURITY_DESCRIPTOR_CONTROL control = 0;
    DWORD rev = 0;
    GetSecurityDescriptorControl(sd, &control, &rev);
    CHECK((control & SE_DACL_PROTECTED) != 0);
    CHECK(dacl->AceCount == 3);
    LocalFree(sd);
    fs::remove(p, ec);
}

// ---------------------------------------------------------------- SMA-05, SMA-06, SMA-17 (webguard)
#include <algorithm>
#include <fstream>
#include <regex>
#include <set>
#include <sstream>

#include "webguard.hpp"

TEST_CASE("SMA-06: samo stranice aplikacije smiju biti učitane i slati poruke mostu") {
    CHECK(trusted_app_url(L"https://app.solari/web/index.html"));
    CHECK(trusted_app_url(L"HTTPS://APP.SOLARI/web/settings.html"));
    // NEW-05: ui\images (data.solari) nije pouzdan izvor stranica ni poruka mostu; poslužuje samo slike
    CHECK_FALSE(trusted_app_url(L"https://data.solari/logo.png"));
    CHECK_FALSE(allowed_navigation(L"https://data.solari/zlo.html"));
    CHECK_FALSE(external_browser_url(L"https://data.solari/zlo.html"));
    CHECK(allowed_app_resource(L"https://data.solari/hero_custom.jpg?v=12"));
    CHECK(allowed_app_resource(L"https://data.solari/cloud/logo-ab12.PNG"));
    CHECK(allowed_app_resource(L"https://data.solari/x.webp"));
    CHECK_FALSE(allowed_app_resource(L"https://data.solari/zlo.html"));
    CHECK_FALSE(allowed_app_resource(L"https://data.solari/zlo.svg"));
    CHECK_FALSE(allowed_app_resource(L"https://data.solari/zlo.html?x=.png"));
    CHECK_FALSE(allowed_app_resource(L"https://data.solari/../config.json"));
    CHECK_FALSE(allowed_app_resource(L"https://data.solari/a.jpg/..%2fconfig.json"));
    CHECK_FALSE(trusted_app_url(L"https://app.solari.zlo.hr/web/index.html"));
    CHECK_FALSE(trusted_app_url(L"http://app.solari/web/index.html"));
    CHECK_FALSE(trusted_app_url(L"https://app.solari@zlo.hr/"));
    CHECK_FALSE(trusted_app_url(L"https://zlo.hr/?https://app.solari/"));
    CHECK_FALSE(trusted_app_url(L"about:blank"));
    CHECK(allowed_navigation(L"about:blank"));
    CHECK_FALSE(allowed_navigation(L"file:///C:/Windows/win.ini"));
    CHECK_FALSE(allowed_navigation(L"data:text/html,<script>1</script>"));
    CHECK(external_browser_url(L"https://solar.example/upute"));
    CHECK_FALSE(external_browser_url(L"http://solar.example/"));
    CHECK_FALSE(external_browser_url(L"file:///C:/"));
    CHECK_FALSE(external_browser_url(L"https://x.example/\"a b"));
    CHECK(allowed_app_resource(L"https://app.solari/web/dashboard.js"));
    CHECK(allowed_app_resource(L"https://app.solari/assets/font.woff2"));
    CHECK_FALSE(allowed_app_resource(L"https://app.solari/SolarniMonitor.exe"));
    CHECK_FALSE(allowed_app_resource(L"https://app.solari/curl/curl.exe"));
    CHECK_FALSE(allowed_app_resource(L"https://app.solari/web/../SolarniMonitor.exe"));
    CHECK_FALSE(allowed_app_resource(L"https://app.solari/web/%2e%2e/x"));
}

TEST_CASE("SMA-05: svaka metoda mosta razvrstana je po prozoru (glavni ili samo postavke)") {
    std::ifstream in(std::string(SOLARI_SOURCE_DIR) + "/src/bridge.cpp");
    REQUIRE(in);
    std::stringstream ss;
    ss << in.rdbuf();
    const std::string src = ss.str();
    const std::regex re("method == \"([a-z_]+)\"");
    std::set<std::string> methods;
    for (auto it = std::sregex_iterator(src.begin(), src.end(), re); it != std::sregex_iterator(); ++it) methods.insert((*it)[1]);
    REQUIRE(methods.size() > 30);
    for (const auto& m : methods) {
        INFO(m);
        CHECK(settings_only_method(m) != main_window_method(m));  // točno jedan skup – nova metoda mora biti razvrstana
    }
    for (const char* m : {"save", "user_save", "user_delete", "user_reset_password", "user_logout_all", "import_history",
                          "import_smartlogger", "cloud_login", "test_email", "get_state"}) {
        CHECK(settings_only_method(m));
    }
}

// ---------------------------------------------------------------- SMA-10 (WinHTTP bez preusmjeravanja)
#include <atomic>

#include "cloud.hpp"
#include "remote.hpp"

TEST_CASE("SMA-10: preusmjeravanje se ne slijedi i oznaka prijave ne odlazi drugom poslužitelju") {
    std::atomic<int> target_hits{0};
    HttpServer target([&](const HttpRequest&) {
        ++target_hits;
        return HttpResponse::json_body(200, {{"ok", true}});
    });
    int target_port = 0;
    for (int p = 18800; p < 18860 && !target_port; ++p) if (target.start(p, false)) target_port = p;
    REQUIRE(target_port);
    HttpServer redirector([&](const HttpRequest&) {
        HttpResponse r = HttpResponse::text(302, "");
        r.extra_headers = "Location: http://127.0.0.1:" + std::to_string(target_port) + "/api/v1/me\r\n";
        return r;
    });
    int port = 0;
    for (int p = 18860; p < 18920 && !port; ++p) if (redirector.start(p, false)) port = p;
    REQUIRE(port);
    HttpCall call;
    call.path = "/api/v1/me";
    call.token = "tajna-oznaka-prijave-koja-ne-smije-otici-drugom-posluzitelju";
    CHECK_THROWS_AS(http_call("http://127.0.0.1:" + std::to_string(port), call), CloudError);
    CHECK(target_hits == 0);
}

// ---------------------------------------------------------------- SMA-07, SMA-08, SMA-16, SMA-27 (HTTP i pregled iz mreže)
#include <winsock2.h>
#include <ws2tcpip.h>

#include "net.hpp"

namespace {

int start_on_free_port(HttpServer& s, int from) {
    for (int p = from; p < from + 60; ++p) if (s.start(p, false)) return p;
    return 0;
}

SOCKET connect_local(int port) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = htons(static_cast<u_short>(port));
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(s, reinterpret_cast<sockaddr*>(&a), sizeof a) != 0) {
        closesocket(s);
        return INVALID_SOCKET;
    }
    DWORD tmo = 5000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tmo), sizeof tmo);
    return s;
}

// Pošalje sirovi zahtjev i vrati cijeli odgovor ("" = veza zatvorena bez odgovora)
std::string raw_request(int port, const std::string& request) {
    SOCKET s = connect_local(port);
    if (s == INVALID_SOCKET) return {};
    send(s, request.data(), static_cast<int>(request.size()), 0);
    std::string out;
    char buf[4096];
    for (int n; (n = recv(s, buf, sizeof buf, 0)) > 0;) out.append(buf, static_cast<size_t>(n));
    closesocket(s);
    return out;
}

int status_of(const std::string& response) {
    return response.size() > 12 ? std::atoi(response.substr(9, 3).c_str()) : 0;
}

}  // namespace

TEST_CASE("SMA-27: pregled iz mreže poslužuje samo datoteke s popisa") {
    // dopušteno (datoteke postoje u mapi gradnje: web\ se kopira uz program)
    CHECK(resolve_remote_path("/web/index.html"));
    CHECK(resolve_remote_path("/web/i18n/en.json"));
    CHECK(resolve_remote_path("/web/vendor/plotly-basic.min.js"));
    // sve ostalo nedostupno – i stvarno postojeće datoteke programa
    for (const char* p : {"/web/settings.html", "/web/settings.js", "/web/editor.js", "/web/overlay.js", "/web/vendor/qrcode.js",
                          "/web/../SolarniMonitor.exe", "/web/../solari_tests.exe", "/web/%2e%2e/config.json",
                          "/web/..%5cconfig.json", "/web/i18n\\..\\..\\config.json", "/web/INDEX.HTML", "/web/index.html::$DATA",
                          "/web/INDEX~1.HTM", "/web/index.html.", "/data/logo.png", "/data/../solar.db", "/assets/logo.png",
                          "/web/", "/web", "/config.json", "/data/solar.db", "/data/backups/solar.db", "/data/logs/x.log",
                          "/alerts.json", "C:/Windows/win.ini", "/etc/passwd", "//web/index.html"}) {
        INFO(p);
        CHECK_FALSE(resolve_remote_path(p));
    }
}

TEST_CASE("SMA-08: podaci pregleda iz mreže samo uz ključ u zaglavlju, bez tehničkih postavki") {
    const std::string key = "KLJUCKLJUCKLJUCKLJUCKLJUC2";
    HttpServer view(remote_view_handler(
        [] { return json{{"settings", {{"modbus_host", "192.168.5.199"}, {"meter_unit_id", 3}, {"plant_name", "E"}}},
                         {"images", {{"logo", "https://evil/x"}}}}; },
        [&] { return key; }));
    const int port = start_on_free_port(view, 18920);
    REQUIRE(port);
    const std::string base = "GET /api/dashboard HTTP/1.1\r\nHost: x\r\n";
    CHECK(status_of(raw_request(port, base + "\r\n")) == 401);
    CHECK(status_of(raw_request(port, "GET /api/dashboard?k=" + key + " HTTP/1.1\r\nHost: x\r\n\r\n")) == 401);  // ne u URL-u
    const std::string ok = raw_request(port, base + "X-Solari-View-Key: " + key + "\r\n\r\n");
    CHECK(status_of(ok) == 200);
    CHECK(ok.find("192.168.5.199") == std::string::npos);
    CHECK(ok.find("\"meter_unit_id\":1") != std::string::npos);
    CHECK(status_of(raw_request(port, "GET /api/image/logo HTTP/1.1\r\nHost: x\r\nX-Solari-View-Key: " + key + "\r\n\r\n")) == 404);
    CHECK(status_of(raw_request(port, "GET /api/v1/ping HTTP/1.1\r\nHost: x\r\n\r\n")) == 404);  // API nije na ovom portu
    CHECK(status_of(raw_request(port, "POST /api/dashboard HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n")) == 405);
    for (int i = 0; i < 9; ++i) raw_request(port, base + "X-Solari-View-Key: KRIVO\r\n\r\n");
    CHECK(status_of(raw_request(port, base + "X-Solari-View-Key: " + key + "\r\n\r\n")) == 429);  // 10 pogrešnih → blokada
}

TEST_CASE("SMA-16: zaglavlja bez kraja, previše zaglavlja i dvostruki Content-Length se odbijaju") {
    HttpServer s([](const HttpRequest&) { return HttpResponse::text(200, "ok"); });
    const int port = start_on_free_port(s, 18980);
    REQUIRE(port);
    CHECK(status_of(raw_request(port, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")) == 200);
    {
        // Napomena o okruženju: na ovom računalu filtar na loopbacku zadržava NEDOVRŠENE zahtjeve koji počinju s "GET "
        // (provjereno i s običnim Python poslužiteljem), pa se šalje "XGET" – 431 se provjerava prije metode.
        const auto t431 = std::chrono::steady_clock::now();
        const std::string r431 = raw_request(port, "XGET / HTTP/1.1\r\nX: " + std::string(9000, 'a'));
        const auto ms431 = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t431).count();
        INFO("odgovor: [" << r431.substr(0, 60) << "] duljina " << r431.size() << " ms " << ms431 << " wsa " << WSAGetLastError());
        CHECK(status_of(r431) == 431);
    }
    std::string many = "GET / HTTP/1.1\r\n";
    for (int i = 0; i < 120; ++i) many += "X-" + std::to_string(i) + ": 1\r\n";
    CHECK(status_of(raw_request(port, many + "\r\n")) == 431);
    CHECK(status_of(raw_request(port, "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\nContent-Length: 0\r\n\r\nab")) == 400);
    CHECK(status_of(raw_request(port, "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n")) == 411);
}

TEST_CASE("SMA-07: spori klijenti ne blokiraju poslužitelj; najviše 4 veze po adresi") {
    HttpServer s([](const HttpRequest&) { return HttpResponse::text(200, "ok"); });
    const int port = start_on_free_port(s, 19040);
    REQUIRE(port);
    // 3 spora klijenta (otvorena veza bez zahtjeva) – u 3.3 jedina nit bi čekala na prvog
    std::vector<SOCKET> slow;
    for (int i = 0; i < 3; ++i) slow.push_back(connect_local(port));
    Sleep(300);
    const auto t0 = std::chrono::steady_clock::now();
    CHECK(status_of(raw_request(port, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")) == 200);
    CHECK(std::chrono::steady_clock::now() - t0 < std::chrono::seconds(2));
    // četvrta spora veza: s iste adrese više nema mjesta – peta se odmah zatvara bez obrade
    slow.push_back(connect_local(port));
    Sleep(300);
    CHECK(raw_request(port, "GET / HTTP/1.1\r\nHost: x\r\n\r\n").empty());
    for (SOCKET x : slow) closesocket(x);
    Sleep(500);
    CHECK(status_of(raw_request(port, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")) == 200);  // nakon zatvaranja ponovno radi
}


// ---------------------------------------------------------------- SMA-09 (DPAPI s entropijom aplikacije)
#include <wincrypt.h>

#include "secret.hpp"

TEST_CASE("SMA-09: tajna se ne dešifrira bez entropije aplikacije; stari zapis bez entropije se ne čita") {
    const std::string stored = protect_secret("oznaka-prijave");
    CHECK(stored.rfind("dpapi2:", 0) == 0);
    CHECK(unprotect_secret(stored) == "oznaka-prijave");
    // isti tekst zaštićen DPAPI-jem računala BEZ entropije (kako bi to napravio drugi program ili 3.3)
    const std::string text = "oznaka-prijave";
    DATA_BLOB in{static_cast<DWORD>(text.size()), reinterpret_cast<BYTE*>(const_cast<char*>(text.data()))};
    DATA_BLOB out{};
    REQUIRE(CryptProtectData(&in, nullptr, nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN | CRYPTPROTECT_LOCAL_MACHINE, &out));
    const std::string b64 = base64(std::vector<uint8_t>(out.pbData, out.pbData + out.cbData));
    LocalFree(out.pbData);
    CHECK(unprotect_secret("dpapi2:" + b64).empty());  // bez entropije aplikacije nema dešifriranja
    CHECK(unprotect_secret("dpapi:" + b64).empty());   // format 3.3 se ne čita
    // obrnuto: zapis 4.0 drugi program bez entropije ne može otvoriti
    const auto raw = stored.substr(7);
    DWORD size = 0;
    CryptStringToBinaryA(raw.c_str(), static_cast<DWORD>(raw.size()), CRYPT_STRING_BASE64, nullptr, &size, nullptr, nullptr);
    std::vector<BYTE> bytes(size);
    CryptStringToBinaryA(raw.c_str(), static_cast<DWORD>(raw.size()), CRYPT_STRING_BASE64, bytes.data(), &size, nullptr, nullptr);
    DATA_BLOB sealed{size, bytes.data()};
    DATA_BLOB plain{};
    CHECK_FALSE(CryptUnprotectData(&sealed, nullptr, nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &plain));
}

// ---------------------------------------------------------------- SMA-15 (ključ ograničenja po adresi)
#include "api.hpp"

TEST_CASE("SMA-15: IPv6 se grupira po /64, neispravan zapis ne zaobilazi brojanje") {
    CHECK(rate_limit_key("203.0.113.7") == "203.0.113.7");
    CHECK(rate_limit_key("2001:db8:1:2:aaaa::1") == rate_limit_key("2001:db8:1:2:bbbb:cccc:dddd:eeee"));
    CHECK(rate_limit_key("2001:db8:1:2::1") == "v6:2001:db8:1:2::/64");
    CHECK(rate_limit_key("2001:DB8:1:2::1") == "v6:2001:db8:1:2::/64");
    CHECK(rate_limit_key("2001:db8:1:3::1") != rate_limit_key("2001:db8:1:2::1"));
    CHECK(rate_limit_key("::1") == "v6:0:0:0:0::/64");
    CHECK(rate_limit_key("x' or 1=1") == "invalid");
    CHECK(rate_limit_key("1.2.3.4, 5.6.7.8") == "invalid");
    CHECK(rate_limit_key("") == "invalid");
}

// ---------------------------------------------------------------- SMA-04 (kod za uparivanje)
#include "tls.hpp"

TEST_CASE("SMA-04: kod za uparivanje – 20 znakova (100 bita) iz SHA-256 otiska, tolerantan unos, odbijanje drugog certifikata") {
    const std::string fp = "8D:29:86:91:10:49:64:12:9B:D6:BC:56:6F:F3:F4:D2:2E:6F:28:89:1F:53:8F:AB:B2:EC:DC:0E:2C:1A:79:00";
    const std::string code = pairing_code(fp);
    CHECK(code == "RUUYN-EIQJF-SBFG6-WXRLG");  // base32 prvih 100 bita (8D 29 86 91 10 49 64 12 9B D6 BC 56 6F …)
    CHECK(pairing_code_matches("ruuyneiqjfsbfg6wxrlg", fp));
    CHECK(pairing_code_matches(" RUUYN EIQJF SBFG6 WXRLG ", fp));
    CHECK_FALSE(pairing_code_matches("RUUYN-EIQJF-SBFG6-WXRLH", fp));
    CHECK_FALSE(pairing_code_matches("RUUY-NEIQ-JFSB", fp));  // stari kod od 60 bita više ne vrijedi
    CHECK_FALSE(pairing_code_matches("", fp));
    std::string other = fp;
    other[1] = 'E';  // drugi certifikat (napadač u mreži)
    CHECK_FALSE(pairing_code_matches(code, other));
    CHECK(pairing_code("nije otisak").empty());
    CHECK_FALSE(pairing_code_matches("", "nije otisak"));
}

// ---------------------------------------------------------------- SMA-02 (SYSTEM ne piše kroz spojnice)
TEST_CASE("SMA-02: mape u koje piše SYSTEM odbijaju spojnice; kopije, alerts.json i zapisi servisa u mapi service") {
    wchar_t tmp[MAX_PATH];
    GetTempPathW(MAX_PATH, tmp);
    const fs::path home = fs::path(tmp) / (L"solari_sma02_" + std::to_wstring(GetCurrentProcessId()));
    const fs::path elsewhere = fs::path(tmp) / (L"solari_sma02_cilj_" + std::to_wstring(GetCurrentProcessId()));
    std::error_code ec;
    fs::remove_all(home, ec);
    fs::create_directories(home / L"service");
    fs::create_directories(elsewhere);
    wchar_t old[MAX_PATH * 2] = L"";
    GetEnvironmentVariableW(L"SOLARI2_HOME", old, MAX_PATH * 2);
    SetEnvironmentVariableW(L"SOLARI2_HOME", home.c_str());
    _wputenv_s(L"SOLARI2_HOME", home.c_str());

    CHECK(backups_dir() == home / L"service" / L"backups");
    CHECK(service_logs_dir() == home / L"service" / L"logs");
    CHECK(no_reparse_points(backups_dir()));        // još ne postoji – smije se stvoriti
    CHECK(no_reparse_points(data_dir()));
    CHECK_FALSE(no_reparse_points(elsewhere));      // izvan home_dir()
    // spojnica (može je napraviti i običan korisnik) umjesto mape kopija → upis se odbija
    const std::wstring cmd = L"cmd /c mklink /J \"" + backups_dir().wstring() + L"\" \"" + elsewhere.wstring() + L"\" >nul";
    REQUIRE(_wsystem(cmd.c_str()) == 0);
    CHECK_FALSE(no_reparse_points(backups_dir()));
    CHECK_FALSE(no_reparse_points(backups_dir() / L"x"));
    CHECK(no_reparse_points(service_dir()));

    fs::remove(backups_dir(), ec);  // uklanja samo spojnicu
    fs::remove_all(home, ec);
    fs::remove_all(elsewhere, ec);
    SetEnvironmentVariableW(L"SOLARI2_HOME", old[0] ? old : nullptr);
    _wputenv_s(L"SOLARI2_HOME", old);
}

TEST_CASE("Instalacija: prozor koji traži administratora pokreće se nakon instalacije preko ShellExecute (UAC, ne greška 740)") {
    const auto read_all = [](const std::string& rel) {
        std::ifstream in(std::string(SOLARI_SOURCE_DIR) + rel, std::ios::binary);
        std::stringstream ss;
        ss << in.rdbuf();
        return ss.str();
    };
    REQUIRE(read_all("/res/server.manifest").find("requireAdministrator") != std::string::npos);
    const std::string iss = read_all("/installer/SolarniMonitor2.iss");
    REQUIRE_FALSE(iss.empty());
    // stanje grana #ifdef Server / #else / #endif: postinstall u grani poslužitelja mora imati shellexec
    std::istringstream lines(iss);
    std::vector<int> branch;  // 1 = Server, 0 = klijent, -1 = ostalo
    int server_launches = 0;
    for (std::string line; std::getline(lines, line);) {
        if (line.rfind("#ifdef Server", 0) == 0) branch.push_back(1);
        else if (line.rfind("#ifndef Server", 0) == 0) branch.push_back(0);
        else if (line.rfind("#if", 0) == 0) branch.push_back(-1);
        else if (line.rfind("#else", 0) == 0 && !branch.empty() && branch.back() >= 0) branch.back() = 1 - branch.back();
        else if (line.rfind("#endif", 0) == 0 && !branch.empty()) branch.pop_back();
        else if (line.find("postinstall") != std::string::npos && line.rfind(";", 0) != 0) {
            const bool server = std::find(branch.begin(), branch.end(), 1) != branch.end();
            const bool client = std::find(branch.begin(), branch.end(), 0) != branch.end();
            CAPTURE(line);
            CHECK((server || client));  // pokretanje mora biti u grani poslužitelja ili klijenta, ne zajedničko
            if (server) {
                ++server_launches;
                CHECK(line.find("shellexec") != std::string::npos);
            }
        }
    }
    CHECK(server_launches == 1);
}

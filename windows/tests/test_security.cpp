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
#include <fstream>
#include <regex>
#include <set>
#include <sstream>

#include "webguard.hpp"

TEST_CASE("SMA-06: samo stranice aplikacije smiju biti učitane i slati poruke mostu") {
    CHECK(trusted_app_url(L"https://app.solari/web/index.html"));
    CHECK(trusted_app_url(L"HTTPS://APP.SOLARI/web/settings.html"));
    CHECK(trusted_app_url(L"https://data.solari/logo.png"));
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

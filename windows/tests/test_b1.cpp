// 4.0 – testovi IPC sloja (B1), brokera postavki (SMA-02/W4), API-ja preko kanala, odvojenih tajni i baze
// samo za čitanje. Kanali u testovima rade pod trenutnim korisnikom (vlasnik nije SYSTEM), s jedinstvenim imenom.
#include <doctest/doctest.h>

#include <windows.h>
#include <aclapi.h>
#include <sddl.h>

#include <thread>

#include "api_ipc.hpp"
#include "broker.hpp"
#include "config.hpp"
#include "crypto.hpp"
#include "ipc.hpp"
#include "secret.hpp"
#include "storage.hpp"
#include "util.hpp"

using namespace sm;

namespace {

struct TmpDir {
    fs::path path;
    TmpDir() {
        path = fs::temp_directory_path() / (L"solari_b1_" + std::to_wstring(GetCurrentProcessId()) + L"_" + std::to_wstring(GetTickCount64()));
        fs::create_directories(path);
    }
    ~TmpDir() {
        std::error_code ec;
        fs::remove_all(path, ec);
    }
};

struct TmpHome {
    TmpDir dir;
    std::wstring old;
    TmpHome() {
        if (const wchar_t* v = _wgetenv(L"SOLARI2_HOME")) old = v;
        _wputenv_s(L"SOLARI2_HOME", dir.path.c_str());
    }
    ~TmpHome() { _wputenv_s(L"SOLARI2_HOME", old.c_str()); }
};

std::wstring unique_pipe(const wchar_t* tag) {
    return std::wstring(L"\\\\.\\pipe\\SolariTest.") + tag + L"." + std::to_wstring(GetCurrentProcessId()) + L"." +
           std::to_wstring(GetTickCount64());
}

// DACL za testove: trenutni korisnik čitanje/pisanje (bez stvaranja instance), bez vlasnika SYSTEM
// OW:GA – tvorac smije stvarati instance (u produkciji je tvorac SYSTEM s GA)
std::wstring test_sddl() { return L"D:P(A;;GA;;;SY)(A;;GA;;;OW)(A;;0x12018b;;;" + ipc::current_user_sid() + L")"; }

ipc::PipeServerConfig config_for(const std::wstring& name) {
    ipc::PipeServerConfig c;
    c.name = name;
    c.sddl = test_sddl();
    c.instances = 2;
    c.io_timeout_ms = 3000;
    c.idle_timeout_ms = 3000;
    c.requests_per_connection = 1;
    return c;
}

// Sirovi klijent kanala (za neispravne poruke): spajanje, hello, upis proizvoljnih bajtova, pokušaj čitanja odgovora
std::optional<std::string> raw_exchange(const std::wstring& name, const std::string& bytes) {
    HANDLE h = CreateFileW(name.c_str(), GENERIC_READ | FILE_WRITE_DATA, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return std::nullopt;
    char buf[4096];
    DWORD got = 0;
    ReadFile(h, buf, sizeof buf, &got, nullptr);  // hello
    DWORD written = 0;
    WriteFile(h, bytes.data(), static_cast<DWORD>(bytes.size()), &written, nullptr);
    got = 0;
    const BOOL ok = ReadFile(h, buf, sizeof buf, &got, nullptr);
    CloseHandle(h);
    if (!ok || got == 0) return std::nullopt;  // poslužitelj je prekinuo vezu bez odgovora
    return std::string(buf, got);
}

}  // namespace

// ================================================================ okvir
TEST_CASE("IPC: okvir duljine + JSON – kodiranje, nepotpun, prevelik, neispravan, preduboko ugniježđen") {
    const std::string f = ipc::encode_frame({{"a", 1}});
    CHECK(f.size() == 4 + 7);
    auto d = ipc::decode_frame(f, 1024);
    REQUIRE(d.status == ipc::DecodeStatus::Ok);
    CHECK(d.message["a"] == 1);
    CHECK(d.consumed == f.size());
    CHECK(ipc::decode_frame(f.substr(0, 3), 1024).status == ipc::DecodeStatus::NeedMore);
    CHECK(ipc::decode_frame(f.substr(0, 8), 1024).status == ipc::DecodeStatus::NeedMore);
    CHECK(ipc::decode_frame(f, 6).status == ipc::DecodeStatus::TooLarge);
    std::string huge = "\xFF\xFF\xFF\x7F";
    CHECK(ipc::decode_frame(huge, ipc::kMaxRequestBytes).status == ipc::DecodeStatus::TooLarge);
    const auto frame = [](const std::string& body) {
        const auto n = static_cast<uint32_t>(body.size());
        return std::string{static_cast<char>(n & 0xFF), static_cast<char>((n >> 8) & 0xFF), static_cast<char>((n >> 16) & 0xFF),
                           static_cast<char>(n >> 24)} + body;
    };
    CHECK(ipc::decode_frame(frame("{nije json"), 1024).status == ipc::DecodeStatus::BadJson);
    CHECK(ipc::decode_frame(frame("[1,2]"), 1024).status == ipc::DecodeStatus::NotObject);
    CHECK(ipc::decode_frame(frame("\"\xC3\x28\""), 1024).status != ipc::DecodeStatus::Ok);  // neispravan UTF-8
    std::string deep = "{\"x\":" + std::string(40, '[') + std::string(40, ']') + "}";
    CHECK(ipc::decode_frame(frame(deep), 4096).status == ipc::DecodeStatus::BadJson);
    std::string ok_depth = "{\"x\":" + std::string(20, '[') + std::string(20, ']') + "}";
    CHECK(ipc::decode_frame(frame(ok_depth), 4096).status == ipc::DecodeStatus::Ok);
    std::string brackets_in_string = "{\"x\":\"" + std::string(100, '[') + "\"}";
    CHECK(ipc::decode_frame(frame(brackets_in_string), 4096).status == ipc::DecodeStatus::Ok);
}

TEST_CASE("IPC: SID usluge (NT SERVICE\\<ime>) kao `sc showsid`") {
    // poznati vektor: NT SERVICE\TrustedInstaller
    CHECK(ipc::service_sid(L"TrustedInstaller") == L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464");
    CHECK(ipc::service_sid(L"trustedinstaller") == ipc::service_sid(L"TrustedInstaller"));
    CHECK(ipc::service_sid(L"SolariGateway").rfind(L"S-1-5-80-", 0) == 0);
}

// ================================================================ kanal
TEST_CASE("IPC: kanal – izazov, provjera vlasnika, odbijeni klijent, zauzeto ime") {
    const std::wstring name = unique_pipe(L"ipc");
    const std::wstring me = ipc::current_user_sid();
    std::atomic<int> calls{0};
    ipc::PipeServer server(config_for(name), [&](const json& req, const ipc::Caller& caller) {
        ++calls;
        CHECK(caller.sid == me);
        CHECK(caller.pid == GetCurrentProcessId());
        return json{{"ok", true}, {"echo", req.value("x", 0)}};
    });
    server.start();

    const json r = ipc::pipe_call(name, {{"x", 41}, {"id", 7}}, me, 3000);
    CHECK(r["ok"] == true);
    CHECK(r["echo"] == 41);
    CHECK(r["id"] == 7);
    CHECK(r["v"] == ipc::kProtocolVersion);

    // klijent očekuje vlasnika SYSTEM (lažni kanal) → ne šalje ništa
    const int before = calls;
    CHECK_THROWS_AS(ipc::pipe_call(name, {{"x", 1}}, ipc::kSystemSid, 3000), ipc::PipeError);
    CHECK(calls == before);

    // drugi proces/instanca s istim imenom ne može preuzeti kanal (FILE_FLAG_FIRST_PIPE_INSTANCE)
    ipc::PipeServer squatter(config_for(name), [](const json&, const ipc::Caller&) { return json::object(); });
    CHECK_THROWS(squatter.start());

    // pogrešan izazov (nonce) → veza prekinuta bez odgovora
    const uint64_t rejected = server.rejected();
    CHECK_FALSE(raw_exchange(name, ipc::encode_frame({{"v", 1}, {"nonce", std::string(64, '0')}, {"x", 1}})).has_value());
    // prevelik okvir → prekinuto
    CHECK_FALSE(raw_exchange(name, std::string("\xFF\xFF\x0F\x00", 4)).has_value());
    // neispravan JSON
    CHECK_FALSE(raw_exchange(name, std::string("\x05\x00\x00\x00{{{{{", 9)).has_value());
    for (int i = 0; i < 50 && server.rejected() < rejected + 3; ++i) Sleep(20);
    CHECK(server.rejected() >= rejected + 3);
    server.stop();
    CHECK_FALSE(ipc::pipe_exists(name));
    CHECK_THROWS_AS(ipc::pipe_call(name, {{"x", 1}}, me, 500), ipc::PipeError);
}

TEST_CASE("IPC: klijent kojeg authorize ne dopušta ne dobiva odgovor") {
    const std::wstring name = unique_pipe(L"deny");
    auto cfg = config_for(name);
    cfg.authorize = [](const ipc::Caller& c) { return c.sid == ipc::service_sid(kGatewayService); };  // samo usluga gatewaya
    std::atomic<int> calls{0};
    ipc::PipeServer server(cfg, [&](const json&, const ipc::Caller&) {
        ++calls;
        return json{{"ok", true}};
    });
    server.start();
    CHECK_THROWS_AS(ipc::pipe_call(name, {{"x", 1}}, ipc::current_user_sid(), 2000), ipc::PipeError);
    CHECK(calls == 0);
    CHECK(server.rejected() >= 1);
}

TEST_CASE("IPC: DACL kanala u produkciji – vlasnik SYSTEM, bez FILE_CREATE_PIPE_INSTANCE za klijente") {
    for (const std::wstring& sddl : {std::wstring(kBrokerSddl), api_pipe_sddl(ipc::service_sid(kGatewayService))}) {
        PSECURITY_DESCRIPTOR sd = nullptr;
        REQUIRE(ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &sd, nullptr));
        PSID owner = nullptr;
        BOOL defaulted = FALSE;
        REQUIRE(GetSecurityDescriptorOwner(sd, &owner, &defaulted));
        LPWSTR text = nullptr;
        REQUIRE(ConvertSidToStringSidW(owner, &text));
        CHECK(std::wstring(text) == L"S-1-5-18");
        LocalFree(text);
        PACL dacl = nullptr;
        BOOL present = FALSE;
        REQUIRE(GetSecurityDescriptorDacl(sd, &present, &dacl, &defaulted));
        REQUIRE(dacl);
        int clients = 0;
        for (DWORD i = 0; i < dacl->AceCount; ++i) {
            ACCESS_ALLOWED_ACE* ace = nullptr;
            REQUIRE(GetAce(dacl, i, reinterpret_cast<void**>(&ace)));
            LPWSTR sid = nullptr;
            REQUIRE(ConvertSidToStringSidW(&ace->SidStart, &sid));
            const std::wstring who(sid);
            LocalFree(sid);
            if (who == L"S-1-5-18" || who == L"S-1-5-32-544") continue;
            ++clients;
            CHECK((ace->Mask & FILE_CREATE_PIPE_INSTANCE) == 0);
            CHECK((ace->Mask & (WRITE_DAC | WRITE_OWNER | GENERIC_ALL | GENERIC_WRITE)) == 0);
            CHECK((ace->Mask & FILE_WRITE_DATA) != 0);
        }
        CHECK(clients == 1);
        LocalFree(sd);
    }
}

// ================================================================ tajne
TEST_CASE("SMA-02/09: tajne su u secrets\\secrets.json, config.json i .bak su bez njih; stari config.json se prenosi") {
    TmpHome home;
    // config.json iz 4.0.0 s tajnama
    json old = to_json(Settings{});
    old["smtp_password_enc"] = protect_secret("tajna-lozinka");
    old["cloud_token_enc"] = protect_secret("oznaka");
    old["settings_pin_hash"] = hash_pin("1234");
    write_file_atomic(config_file(), old.dump());
    CHECK(config_has_secrets());
    Settings s = load_settings();
    CHECK(unprotect_secret(s.smtp_password_enc) == "tajna-lozinka");
    save_settings(s);  // prijenos (poller u produkciji)
    CHECK_FALSE(config_has_secrets());
    const json cfg = json::parse(*read_file(config_file()));
    const json bak = json::parse(*read_file(fs::path(config_file()) += L".bak"));
    for (const auto& k : secret_keys()) {
        CHECK_FALSE(cfg.contains(k));
        CHECK_FALSE(bak.contains(k));
    }
    const json sec = json::parse(*read_file(secrets_file()));
    CHECK(unprotect_secret(sec["smtp_password_enc"]) == "tajna-lozinka");
    const Settings again = load_settings();
    CHECK(check_pin("1234", again.settings_pin_hash));
    CHECK(unprotect_secret(again.cloud_token_enc) == "oznaka");
    // mapa tajni ima zaštićeni DACL bez Users / Everyone
    PACL dacl = nullptr;
    PSECURITY_DESCRIPTOR sd = nullptr;
    REQUIRE(GetNamedSecurityInfoW(secrets_dir().c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr, &dacl, nullptr, &sd) ==
            ERROR_SUCCESS);
    for (DWORD i = 0; i < dacl->AceCount; ++i) {
        ACCESS_ALLOWED_ACE* ace = nullptr;
        GetAce(dacl, i, reinterpret_cast<void**>(&ace));
        LPWSTR sid = nullptr;
        ConvertSidToStringSidW(&ace->SidStart, &sid);
        const std::wstring who(sid);
        LocalFree(sid);
        CHECK(who != L"S-1-5-32-545");
        CHECK(who != L"S-1-1-0");
        CHECK(who != L"S-1-5-11");
    }
    LocalFree(sd);
}

// ================================================================ broker
TEST_CASE("SMA-02 broker: PIN obavezan, zaključavanje nakon 5 pogrešnih, validacija obrasca, tajne ostaju u brokeru") {
    TmpHome home;
    std::time_t t = 1'800'000'000;
    BrokerCore broker([] { return std::vector<std::string>{"Ethernet"}; }, [&] { return t; });
    const std::wstring caller = L"S-1-5-21-test";

    json st = broker.handle({{"op", "state"}}, caller);
    CHECK(st["ok"] == true);
    CHECK(st["pin_set"] == false);
    CHECK(st["configured"] == false);
    // bez PIN-a (instalacija ga nije postavila) izmjena nije moguća – fail-closed
    CHECK(broker.handle({{"op", "save_settings"}, {"pin", "1234"}, {"form", json::object()}}, caller)["error"] == "pin_not_set");

    save_secret_field("settings_pin_hash", hash_pin("2468"));  // instalacija (--set-pin-file)
    CHECK_FALSE(is_configured());  // PIN ne stvara config.json – čarobnjak ostaje
    CHECK(broker.handle({{"op", "state"}}, caller)["pin_set"] == true);
    CHECK(broker.handle({{"op", "check_pin"}, {"pin", "2468"}}, caller)["ok"] == true);

    // nepoznata operacija i neispravni tipovi
    CHECK(broker.handle({{"op", "write_file"}, {"path", "C:\\Windows\\x"}}, caller)["error"] == "bad_request");
    CHECK(broker.handle({{"op", 5}}, caller)["error"] == "bad_request");
    CHECK(broker.handle(json::object(), caller)["error"] == "bad_request");

    // obrazac: isti validator kao sučelje; neispravno polje → greške, ništa se ne sprema
    json form = to_form(Settings{});
    form["modbus_host"] = "192.168.5.199\nproxy = zlo";
    json r = broker.handle({{"op", "save_settings"}, {"pin", "2468"}, {"form", form}}, caller);
    CHECK(r["ok"] == false);
    CHECK(r["error"] == "invalid");
    CHECK(r["errors"].contains("modbus_host"));
    CHECK_FALSE(is_configured());
    // PIN se ne može ukloniti
    form = to_form(Settings{});
    form["pin_clear"] = true;
    CHECK(broker.handle({{"op", "save_settings"}, {"pin", "2468"}, {"form", form}}, caller)["error"] == "invalid");
    // ispravan obrazac
    form = to_form(Settings{});
    form["plant_name"] = "Elektrana Test";
    form["logger_interface"] = "Ethernet";
    form["smtp_password"] = "smtp-tajna";
    form["smtp_user"] = "solari@primjer.hr";
    form["smtp_host"] = "smtp.primjer.hr";
    r = broker.handle({{"op", "save_settings"}, {"pin", "2468"}, {"form", form}}, caller);
    INFO(r.dump());
    REQUIRE(r["ok"] == true);
    CHECK(is_configured());
    CHECK(load_settings().plant_name == "Elektrana Test");
    CHECK(r["smtp_password_set"] == true);
    CHECK_FALSE(r["settings"].contains("smtp_password_enc"));        // SMTP lozinka ne izlazi iz brokera
    CHECK_FALSE(r["secrets"].contains("smtp_password_enc"));
    CHECK_FALSE(r["settings"].contains("settings_pin_hash"));
    CHECK(read_file(config_file())->find("smtp_password_enc") == std::string::npos);
    // ključ pregleda iz mreže izrađuje broker (stanje nakon postavljanja)
    st = broker.handle({{"op", "state"}}, caller);
    CHECK_FALSE(st["secrets"]["remote_view_key_enc"].get<std::string>().empty());
    const std::string key1 = st["secrets"]["remote_view_key_enc"];
    CHECK(broker.handle({{"op", "remote_view_new_key"}, {"pin", "2468"}}, caller)["secrets"]["remote_view_key_enc"] != key1);

    // 5 pogrešnih PIN-ova → zaključano 15 min, i za ispravan PIN
    for (int i = 0; i < 4; ++i) CHECK(broker.handle({{"op", "check_pin"}, {"pin", "0000"}}, caller)["error"] == "pin_invalid");
    CHECK(broker.handle({{"op", "check_pin"}, {"pin", "0000"}}, caller)["error"] == "pin_invalid");
    json locked = broker.handle({{"op", "check_pin"}, {"pin", "2468"}}, caller);
    CHECK(locked["error"] == "locked");
    CHECK(broker.handle({{"op", "save_settings"}, {"pin", "2468"}, {"form", form}}, caller)["error"] == "locked");
    t += kBrokerLockoutS + 1;
    CHECK(broker.handle({{"op", "check_pin"}, {"pin", "2468"}}, caller)["ok"] == true);
}

TEST_CASE("SMA-02 broker: prijava na poslužitelj i uvoz – validacija polja i redaka") {
    TmpHome home;
    BrokerCore broker([] { return std::vector<std::string>{}; });
    save_secret_field("settings_pin_hash", hash_pin("1357"));
    const std::wstring c = L"S-1-5-21-test";
    json login = {{"op", "cloud_login"}, {"pin", "1357"}, {"cloud_url", "https://192.168.1.20:8700"}, {"token", std::string(43, 'A')},
                  {"account", {{"email", "a@b.hr"}, {"name", "Ana"}}}, {"cert_pin", "AB:CD"}};
    json r = broker.handle(login, c);
    REQUIRE(r["ok"] == true);
    CHECK(unprotect_secret(load_settings().cloud_token_enc) == std::string(43, 'A'));
    CHECK(unprotect_secret(r["secrets"]["cloud_token_enc"]) == std::string(43, 'A'));
    json bad = login;
    bad["token"] = "ima razmak";
    CHECK(broker.handle(bad, c)["error"] == "bad_request");
    bad = login;
    bad["cloud_url"] = "file:///C:/Windows";
    CHECK(broker.handle(bad, c)["error"] == "bad_request");
    bad = login;
    bad["pin"] = "9999";
    CHECK(broker.handle(bad, c)["error"] == "pin_invalid");
    CHECK(broker.handle({{"op", "cloud_logout"}, {"pin", "1357"}}, c)["ok"] == true);
    CHECK(load_settings().cloud_token_enc.empty());

    // uvoz redaka
    json rows = json::array({json::array({"2026-10-01 10:00:00", 12.5, 30.0, 1000.0, 0.99, 0, nullptr}),
                             json::array({"2026-10-01 10:00:10", 12.6, 30.1, 1000.1, nullptr, nullptr, 3.2})});
    r = broker.handle({{"op", "import_rows"}, {"pin", "1357"}, {"rows", rows}}, c);
    REQUIRE(r["ok"] == true);
    CHECK(r["added"] == 2);
    CHECK(broker.handle({{"op", "import_rows"}, {"pin", "1357"}, {"rows", rows}}, c)["added"] == 0);  // INSERT OR IGNORE
    for (const json& wrong : {json::array({json::array({"2026-10-01", 1, 1, 1, 1, 0, nullptr})}),
                              json::array({json::array({"2026-10-01 10:00:00", "1", 1, 1, 1, 0, nullptr})}),
                              json::array({json::array({"2026-10-01 10:00:00", 1e300, 1, 1, 1, 0, nullptr})}),
                              json::array({json::array({"2026-10-01 10:00:00', 1); DROP TABLE readings; --", 1, 1, 1, 1, 0, nullptr})}),
                              json::array({json::array({"2026-10-01 10:00:00", 1, 1, 1, 1, 0})})}) {
        CHECK(broker.handle({{"op", "import_rows"}, {"pin", "1357"}, {"rows", wrong}}, c)["error"] == "bad_request");
    }
    json too_many = json::array();
    for (size_t i = 0; i <= kBrokerMaxRows; ++i) too_many.push_back(rows[0]);
    CHECK(broker.handle({{"op", "import_rows"}, {"pin", "1357"}, {"rows", too_many}}, c)["error"] == "bad_request");
    CHECK(Db(db_file()).total_readings() == 2);
    // uvoz dana (izvoz SmartLoggera)
    r = broker.handle({{"op", "import_days"}, {"pin", "1357"}, {"days", json::array({json::array({"2025-06-01", 310.5}),
                                                                                     json::array({"2025-06-02", 290.0})})}}, c);
    REQUIRE(r["ok"] == true);
    CHECK(r["imported"] == 2);
    CHECK(broker.handle({{"op", "import_days"}, {"pin", "1357"}, {"days", json::array({json::array({"2025-02-30", 1.0})})}}, c)["error"] ==
          "bad_request");
    CHECK(broker.handle({{"op", "import_days"}, {"pin", "1357"}, {"days", json::array({json::array({"2025-06-03", -5.0})})}}, c)["error"] ==
          "bad_request");
}

TEST_CASE("SMA-02 broker preko kanala: sučelje dobiva stanje i sprema obrazac") {
    TmpHome home;
    save_secret_field("settings_pin_hash", hash_pin("8642"));
    const std::wstring name = unique_pipe(L"broker");
    BrokerServer server([] { return std::vector<std::string>{"Ethernet"}; }, name, test_sddl());
    server.start();
    const std::wstring me = ipc::current_user_sid();
    json st = broker_call({{"op", "state"}}, name, me);
    CHECK(st["ok"] == true);
    CHECK(st["pin_set"] == true);
    json form = to_form(Settings{});
    form["plant_name"] = "Preko kanala";
    form["logger_interface"] = "Ethernet";
    json r = broker_call({{"op", "save_settings"}, {"pin", "8642"}, {"form", form}}, name, me);
    CHECK(r["ok"] == true);
    CHECK(load_settings().plant_name == "Preko kanala");
    // pravi produkcijski klijent očekuje vlasnika SYSTEM – testni kanal (vlasnik je korisnik) odbija
    CHECK_THROWS_AS(broker_call({{"op", "state"}}, name), ipc::PipeError);
    server.stop();
}

TEST_CASE("SMA-02: broker se ne pokreće ako mapa daje svim korisnicima pravo upisa ili je spojnica") {
    TmpHome home;
    fs::create_directories(data_dir());
    // privremena mapa ima nasljeđeni ACL korisničkog profila (bez Users) → u redu
    CHECK(broker_home_problem().empty());
    // dodaj Users: pravo upisa na data\ (kao 4.0.0 / 3.x)
    EXPLICIT_ACCESSW ea{};
    ea.grfAccessPermissions = FILE_GENERIC_WRITE;
    ea.grfAccessMode = GRANT_ACCESS;
    ea.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    PSID users = nullptr;
    REQUIRE(ConvertStringSidToSidW(L"S-1-5-32-545", &users));
    ea.Trustee.ptstrName = static_cast<LPWSTR>(users);
    PACL old_acl = nullptr, new_acl = nullptr;
    PSECURITY_DESCRIPTOR sd = nullptr;
    REQUIRE(GetNamedSecurityInfoW(data_dir().c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr, &old_acl, nullptr, &sd) ==
            ERROR_SUCCESS);
    REQUIRE(SetEntriesInAclW(1, &ea, old_acl, &new_acl) == ERROR_SUCCESS);
    REQUIRE(SetNamedSecurityInfoW(const_cast<LPWSTR>(data_dir().c_str()), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr,
                                  new_acl, nullptr) == ERROR_SUCCESS);
    LocalFree(new_acl);
    LocalFree(sd);
    LocalFree(users);
    CHECK_FALSE(broker_home_problem().empty());
}

TEST_CASE("SMA-02: PIN iz instalacije (--set-pin-file) – samo znamenke, datoteka se briše") {
    TmpHome home;
    const fs::path f = home.dir.path / L"pin.txt";
    write_file_atomic(f, "123\r\n");
    CHECK(set_pin_from_file(f) == 3);
    CHECK_FALSE(fs::exists(f));
    write_file_atomic(f, "12a45\r\n");
    CHECK(set_pin_from_file(f) == 3);
    write_file_atomic(f, "97531\r\n");
    CHECK(set_pin_from_file(f) == 0);
    CHECK_FALSE(fs::exists(f));
    CHECK(check_pin("97531", load_settings().settings_pin_hash));
    CHECK_FALSE(is_configured());
}

// ================================================================ baza samo za čitanje i ui\ mapa
TEST_CASE("SMA-02: sučelje čita bazu bez prava upisa (trajni WAL), poller piše") {
    TmpDir dir;
    const fs::path db = dir.path / L"solar.db";
    {
        Db w(db);
        Reading r;
        r.power_kw = 5;
        r.e_daily_kwh = 10;
        r.e_total_kwh = 100;
        w.insert(1'800'000'000, r, std::nullopt);
    }
    CHECK(fs::exists(fs::path(db) += L"-wal"));  // ostaje i nakon zatvaranja
    CHECK(fs::exists(fs::path(db) += L"-shm"));
    {
        Db ro(db, true);  // i bez zabrane upisa
        CHECK(ro.latest().has_value());
    }
    // ACL kao u produkciji: zaštićena mapa, SYSTEM i administratori F, korisnik samo RX; datoteke nasljeđuju
    const std::wstring d = L"\"" + dir.path.wstring() + L"\"";
    const std::wstring me = ipc::current_user_sid();
    REQUIRE(_wsystem((L"icacls " + d + L" /inheritance:r /grant:r *S-1-5-18:(OI)(CI)F *S-1-5-32-544:(OI)(CI)F *" + me + L":(OI)(CI)RX /Q").c_str()) == 0);
    for (const wchar_t* f : {L"solar.db", L"solar.db-wal", L"solar.db-shm"}) {
        REQUIRE(_wsystem((L"icacls \"" + (dir.path / f).wstring() + L"\" /reset /Q").c_str()) == 0);
    }
    CHECK_FALSE(dir_writable(dir.path));
    {
        Db ro(db, true);
        const auto latest = ro.latest();
        REQUIRE(latest);
        CHECK(latest->power_kw == doctest::Approx(5));
        Reading r;
        CHECK_THROWS(ro.insert(1'800'000'100, r, std::nullopt));
    }
    CHECK_THROWS(Db(dir.path / L"novi.db"));  // ni nova baza se ne može stvoriti
    // vrati prava da se privremena mapa može obrisati
    CHECK(_wsystem((L"icacls " + d + L" /grant *" + me + L":(OI)(CI)F /T /Q").c_str()) == 0);
}

TEST_CASE("SMA-02: raspored i slike sučelja u ui\\ (kopija iz data\\, izvor ostaje)") {
    TmpHome home;
    fs::create_directories(data_dir() / L"images");
    write_file_atomic(data_dir() / L"layout.json", "{\"version\":2}");
    write_file_atomic(data_dir() / L"images" / L"hero_custom.jpg", "JPEG");
    migrate_ui_files();
    CHECK(layout_file() == ui_dir() / L"layout.json");
    CHECK(*read_file(layout_file()) == "{\"version\":2}");
    CHECK(*read_file(images_dir() / L"hero_custom.jpg") == "JPEG");
    CHECK(fs::exists(data_dir() / L"layout.json"));
    write_file_atomic(layout_file(), "{\"version\":2,\"novo\":1}");
    migrate_ui_files();  // postojeći ui\ se ne prepisuje
    CHECK(read_file(layout_file())->find("novo") != std::string::npos);
}

// ================================================================ B1: API preko kanala
TEST_CASE("B1: strukturirani zahtjev gatewaya → interni zahtjev; sve izvan popisa se odbija") {
    std::string why;
    json m = {{"type", "request"}, {"route", "report"}, {"method", "GET"}, {"year", 2026}, {"month", 10}, {"token", "abc_DEF-123"},
              {"client_ip", "192.168.1.5"}};
    auto r = request_from_ipc(m, &why);
    REQUIRE(r);
    CHECK(r->path == "/api/v1/report");
    CHECK(r->param("year") == "2026");
    CHECK(r->param("month") == "10");
    CHECK(r->header("authorization") == "Bearer abc_DEF-123");
    CHECK(r->peer == "192.168.1.5");

    json img = {{"type", "request"}, {"route", "image"}, {"method", "GET"}, {"image", "logo"}, {"client_ip", "::1"}};
    REQUIRE(request_from_ipc(img));
    CHECK(request_from_ipc(img)->path == "/api/v1/images/logo");

    // CF-Connecting-IP samo s loopbacka
    json cf = {{"type", "request"}, {"route", "ping"}, {"method", "GET"}, {"client_ip", "127.0.0.1"}, {"cf_ip", "203.0.113.9"}};
    CHECK(request_from_ipc(cf)->header("cf-connecting-ip") == "203.0.113.9");
    cf["client_ip"] = "192.168.1.5";
    CHECK(request_from_ipc(cf)->header("cf-connecting-ip").empty());

    const auto rejected = [&](json bad, const char* reason) {
        std::string w;
        CHECK_FALSE(request_from_ipc(bad, &w));
        CHECK(w == reason);
    };
    json base = {{"type", "request"}, {"route", "ping"}, {"method", "GET"}, {"client_ip", "10.0.0.1"}};
    json b = base; b["route"] = "../../admin"; rejected(b, "route");
    b = base; b["route"] = "users"; rejected(b, "route");
    b = base; b["method"] = "DELETE"; rejected(b, "method");
    b = base; b["client_ip"] = "1.2.3"; rejected(b, "client_ip");
    b = base; b["client_ip"] = "localhost"; rejected(b, "client_ip");
    b = base; b["path"] = "/api/v1/ping"; rejected(b, "unknown_field");
    b = base; b["token"] = "a b"; rejected(b, "token");
    b = base; b["token"] = 5; rejected(b, "field_type");
    b = base; b["body"] = "{}"; rejected(b, "body");  // tijelo samo uz POST
    b = base; b["body"] = std::string(kApiMaxBody + 1, 'x'); b["method"] = "POST"; rejected(b, "field_type");
    b = base; b["route"] = "image"; b["image"] = "..\\users.db"; rejected(b, "image");
    b = base; b["year"] = 2026; rejected(b, "query");
    b = base; b["route"] = "report"; b["year"] = "2026"; b["month"] = 1; rejected(b, "query");
}

TEST_CASE("B1: obrada poruka gatewaya – hello, config, request, odgovor u base64 s dopuštenim zaglavljima") {
    json hello_seen;
    auto handler = api_ipc_handler(
        [](const HttpRequest& req) {
            HttpResponse r = HttpResponse::json_body(req.path == "/api/v1/me" ? 401 : 200, {{"path", req.path}});
            if (r.code == 401) r.extra_headers = "WWW-Authenticate: Bearer\r\nSet-Cookie: x=1\r\n";
            return r;
        },
        [] { return GatewayConfig{8700, true}; }, [&](const json& h) { hello_seen = h; });
    const ipc::Caller c{1, L"S-1-5-80-1"};
    json r = handler({{"type", "hello"}, {"fingerprint", "AB"}}, c);
    CHECK(r["config"]["port"] == 8700);
    CHECK(r["config"]["lan"] == true);
    CHECK(hello_seen["fingerprint"] == "AB");
    CHECK(handler({{"type", "config"}}, c)["ok"] == true);
    CHECK(handler({{"type", "shell"}}, c)["error"] == "bad_request");
    r = handler({{"type", "request"}, {"route", "me"}, {"method", "GET"}, {"client_ip", "10.0.0.2"}}, c);
    CHECK(r["status"] == 401);
    REQUIRE(r["headers"].size() == 1);  // Set-Cookie se ne prosljeđuje
    CHECK(r["headers"][0][0] == "WWW-Authenticate");
    CHECK(r["content_type"].get<std::string>().rfind("application/json", 0) == 0);
    r = handler({{"type", "request"}, {"route", "nope"}, {"method", "GET"}, {"client_ip", "10.0.0.2"}}, c);
    CHECK(r["error"] == "bad_request");
}

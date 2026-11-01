#include "broker.hpp"

#include <windows.h>
#include <aclapi.h>
#include <sddl.h>

#include <algorithm>
#include <cmath>
#include <regex>

#include "alerts.hpp"
#include "crypto.hpp"
#include "i18n.hpp"
#include "mailer.hpp"
#include "net.hpp"
#include "secret.hpp"
#include "smartlogger_export.hpp"
#include "storage.hpp"

namespace sm {

namespace {

json fail(const std::string& error, const std::string& message, json extra = json::object()) {
    json j = {{"ok", false}, {"error", error}, {"message", message}};
    j.update(extra);
    return j;
}

json bad_request() { return fail("bad_request", tr("Neispravan zahtjev.")); }

std::optional<std::string> str_field(const json& j, const char* key, size_t max_len) {
    const auto it = j.find(key);
    if (it == j.end() || !it->is_string()) return std::nullopt;
    std::string v = it->get<std::string>();
    if (v.size() > max_len) return std::nullopt;
    return v;
}

std::optional<double> opt_number(const json& v, bool* ok) {
    if (v.is_null()) return std::nullopt;
    if (!v.is_number()) {
        *ok = false;
        return std::nullopt;
    }
    return v.get<double>();
}

std::optional<Date> parse_iso_date(const std::string& text) {
    static const std::regex re(R"(^(\d{4})-(\d{2})-(\d{2})$)");
    std::smatch m;
    if (!std::regex_match(text, m, re)) return std::nullopt;
    const Date d{std::chrono::year{std::stoi(m[1])}, std::chrono::month{static_cast<unsigned>(std::stoi(m[2]))},
                 std::chrono::day{static_cast<unsigned>(std::stoi(m[3]))}};
    if (!d.ok() || d.year() < std::chrono::year{2000} || d.year() > std::chrono::year{2100}) return std::nullopt;
    return d;
}

std::optional<std::wstring> sid_text(PSID sid) {
    LPWSTR text = nullptr;
    if (!sid || !ConvertSidToStringSidW(sid, &text)) return std::nullopt;
    std::wstring out(text);
    LocalFree(text);
    return out;
}

// 4.0 (NEW-01): vlasnik i pravo upisa smiju imati samo SYSTEM, administratori i račun ovog procesa (u produkciji SYSTEM).
// Vlasnik može sam sebi vratiti prava (WRITE_DAC), pa i vlasnik mape ili datoteke mora biti na tom popisu.
bool trusted_sid(const std::wstring& sid) {
    static const std::wstring me = [] {
        try {
            return ipc::current_user_sid();
        } catch (...) {
            return std::wstring(L"S-1-5-18");
        }
    }();
    return sid == L"S-1-5-18" || sid == L"S-1-5-32-544" || sid == me ||
           sid == L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";  // TrustedInstaller
}

// ACE koji daje pravo upisa nekome izvan pouzdanih (Users, Everyone, INTERACTIVE, pojedinačni korisnik…)
std::optional<std::wstring> foreign_write_ace(PACL acl) {
    constexpr DWORD kWrite = FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES | DELETE | WRITE_DAC |
                             WRITE_OWNER | GENERIC_WRITE | GENERIC_ALL | FILE_DELETE_CHILD;
    if (!acl) return std::wstring(L"NULL DACL");  // svi sve
    for (DWORD i = 0; i < acl->AceCount; ++i) {
        void* ace = nullptr;
        if (!GetAce(acl, i, &ace)) continue;
        const auto* header = static_cast<ACE_HEADER*>(ace);
        if (header->AceType != ACCESS_ALLOWED_ACE_TYPE) continue;
        const auto* allowed = static_cast<ACCESS_ALLOWED_ACE*>(ace);
        if (!(allowed->Mask & kWrite)) continue;
        const auto sid = sid_text(const_cast<DWORD*>(&allowed->SidStart));
        if (!sid) return std::wstring(L"nepoznat SID");
        if (*sid == L"S-1-3-0" && (header->AceFlags & INHERIT_ONLY_ACE)) continue;  // CREATOR OWNER (samo za nove objekte)
        if (!trusted_sid(*sid)) return sid;
    }
    return std::nullopt;
}

std::string path_problem(const fs::path& p) {
    const DWORD a = GetFileAttributesW(p.c_str());
    if (a == INVALID_FILE_ATTRIBUTES) return {};
    if (a & FILE_ATTRIBUTE_REPARSE_POINT) return narrow(p.wstring()) + " je spojnica ili simbolička veza";
    PACL dacl = nullptr;
    PSID owner = nullptr;
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (GetNamedSecurityInfoW(p.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION, &owner, nullptr, &dacl,
                              nullptr, &sd) != ERROR_SUCCESS) {
        return "ACL za " + narrow(p.wstring()) + " nije čitljiv";
    }
    const auto owner_sid = sid_text(owner);
    const auto foreign = foreign_write_ace(dacl);
    LocalFree(sd);
    if (!owner_sid || !trusted_sid(*owner_sid)) {
        return narrow(p.wstring()) + " ima nepouzdanog vlasnika (" + narrow(owner_sid.value_or(L"?")) + ")";
    }
    return foreign ? narrow(p.wstring()) + " daje pravo upisa " + narrow(*foreign) : std::string();
}

}  // namespace

std::string broker_home_problem() {
    for (const fs::path& p : {home_dir(), data_dir(), config_file(), db_file(), secrets_dir(), secrets_file(), service_dir()}) {
        if (auto problem = path_problem(p); !problem.empty()) return problem;
    }
    return {};
}

// ---------------------------------------------------------------- jezgra
BrokerCore::BrokerCore(Interfaces interfaces, Clock clock)
    : interfaces_(std::move(interfaces)), clock_(clock ? std::move(clock) : Clock([] { return now(); })) {}

void BrokerCore::claim_secrets(Settings& s, const std::wstring& caller) {
    if (!s.secrets_owner_sid.empty() || caller.empty()) return;
    if (s.cloud_token_enc.empty() && s.remote_view_key_enc.empty()) return;
    // nadogradnja s 5.0.1: tajne postoje, a vlasnik još nije zapisan – preuzima ih prvi korisnik koji pokrene sučelje
    // (u pravilu korisnik zaslona, autostart); svaki sljedeći drugi korisnik ih više ne dobiva
    s.secrets_owner_sid = narrow(caller);
    save_settings(s);
    log_warn("Broker: tajne sučelja vezane uz korisnika " + s.secrets_owner_sid + " (nadogradnja)");
}

json BrokerCore::state(const Settings& s, const std::wstring& caller) const {
    const std::time_t t = clock_();
    const bool owner = !s.secrets_owner_sid.empty() && s.secrets_owner_sid == narrow(caller);
    json secrets = json::object();
    if (owner) {
        secrets = {{"cloud_token_enc", s.cloud_token_enc}, {"cloud_account_enc", s.cloud_account_enc},
                   {"remote_view_key_enc", s.remote_view_key_enc}};
    } else {
        secrets = {{"cloud_token_enc", ""}, {"cloud_account_enc", ""}, {"remote_view_key_enc", ""}};
    }
    return {{"ok", true},
            {"pin_set", !s.settings_pin_hash.empty()},
            {"locked_s", locked_until_ > t ? locked_until_ - t : 0},
            {"smtp_password_set", !s.smtp_password_enc.empty()},
            {"resend_api_key_set", !s.resend_api_key_enc.empty()},
            {"configured", is_configured()},
            // tajne koje sučelje treba (DPAPI računala): prijava na poslužitelj i ključ pregleda iz mreže – samo vlasniku
            // (korisnik koji se prijavio uz PIN); SMTP lozinka i ključ Resenda nikad
            {"secrets", secrets},
            {"secrets_owner", owner},
            {"settings", strip_secrets(to_json(s))}};
}

void BrokerCore::load_pin_state() {
    if (pin_state_loaded_) return;
    pin_state_loaded_ = true;
    if (const auto text = read_file(secrets_dir() / L"broker_state.json")) {
        const json j = json::parse(*text, nullptr, false);
        if (j.is_object()) {
            failures_ = std::clamp(j.value("failures", 0), 0, kBrokerMaxPinFailures);
            lockouts_ = std::clamp(j.value("lockouts", 0), 0, 64);
            locked_until_ = std::max<std::time_t>(0, j.value("locked_until", std::time_t{0}));
        }
    }
}

void BrokerCore::save_pin_state() const {
    try {
        create_private_dir(secrets_dir());
        if (!no_reparse_points(secrets_dir())) return;
        write_file_atomic(secrets_dir() / L"broker_state.json",
                          json{{"failures", failures_}, {"lockouts", lockouts_}, {"locked_until", locked_until_}}.dump());
    } catch (const std::exception& e) {
        log_warn(std::string("Broker: stanje PIN-a nije spremljeno: ") + e.what());
    }
}

std::optional<json> BrokerCore::check_pin(const json& request, const Settings& s) {
    const std::time_t t = clock_();
    load_pin_state();
    if (s.settings_pin_hash.empty()) {
        return fail("pin_not_set", tr("PIN postavki nije postavljen. Pokrenite instalaciju Solarnog monitora ponovno (popravak) i upišite PIN."));
    }
    if (t < locked_until_) {
        return fail("locked", tr("Previše pogrešnih pokušaja. Pokušajte za {s} s.", {{"s", std::to_string(locked_until_ - t)}}),
                    {{"retry_s", locked_until_ - t}});
    }
    const auto pin = str_field(request, "pin", 64);
    if (pin && sm::check_pin(*pin, s.settings_pin_hash)) {
        if (failures_ || lockouts_) {
            failures_ = 0;
            lockouts_ = 0;
            save_pin_state();
        }
        return std::nullopt;
    }
    if (++failures_ >= kBrokerMaxPinFailures) {
        // NEW-02: svako sljedeće zaključavanje traje dvostruko (15 min, 30 min, 1 h … najviše 24 h) – pogađanje PIN-a od
        // 4 znamenke tako traje godinama umjesto dana; ispravan PIN poništava brojač
        failures_ = 0;
        const std::time_t span = std::min<std::time_t>(kBrokerLockoutMaxS, static_cast<std::time_t>(kBrokerLockoutS) << std::min(lockouts_, 8));
        ++lockouts_;
        locked_until_ = t + span;
        log_warn("Broker: previše pogrešnih PIN-ova – izmjene zaključane " + std::to_string(span / 60) + " min");
    }
    save_pin_state();
    return fail("pin_invalid", tr("Pogrešan PIN."));
}

json BrokerCore::handle(const json& request, const std::wstring& caller_sid) {
    std::lock_guard lock(mutex_);
    load_pin_state();
    const auto op = str_field(request, "op", 32);
    if (!op) return bad_request();
    Settings s = load_settings();
    if (*op == "state") {
        if (s.remote_view_key_enc.empty() && is_configured()) {  // pregled iz mreže samo uz ključ (SMA-08)
            Bytes raw = random_bytes(16);
            std::string key = base32(raw);
            wipe(raw);
            s.remote_view_key_enc = protect_secret(key);
            wipe(key);
            save_settings(s);
            log_info("Broker: izrađen ključ pregleda iz mreže");
        }
        claim_secrets(s, caller_sid);
        return state(s, caller_sid);
    }
    if (*op == "check_pin") {
        if (auto e = check_pin(request, s)) return *e;
        return {{"ok", true}};
    }
    if (*op == "save_settings") return save_form(request, caller_sid);
    if (*op == "test_email") {
        if (auto e = check_pin(request, s)) return *e;
        const auto form = request.find("form");
        if (form == request.end() || !form->is_object()) return bad_request();
        const auto v = validate_form(*form, s, interfaces_ ? interfaces_() : std::vector<std::string>{});
        const Settings& t = v.settings ? *v.settings : s;  // ostale greške obrasca ne sprječavaju probnu poruku
        for (const char* key : {"alert_emails", "smtp_host", "smtp_port", "smtp_from", "smtp_user", "mail_provider", "resend_api_key"}) {
            if (v.errors.count(key)) {
                json errors = json::object();
                for (const auto& [k, msg] : v.errors) errors[k] = msg;
                return fail("invalid", tr("Provjerite označena polja."), {{"errors", errors}});
            }
        }
        std::string secret = form->value(t.mail_provider == "resend" ? "resend_api_key" : "smtp_password", std::string{});
        try {
            NetInit net;
            const auto m = test_message(t, clock_());
            const auto to = send_mail(t, m.subject, m.body, secret.empty() ? std::nullopt : std::optional(secret));
            wipe(secret);
            std::string list;
            for (const auto& r : to) list += (list.empty() ? "" : ", ") + r;
            log_info("Broker: probna poruka (" + narrow(caller_sid) + ")");
            return {{"ok", true}, {"message", tr("Probna poruka poslana na: {to}", {{"to", list}})}};
        } catch (const std::exception& e) {
            wipe(secret);
            return fail("mail", e.what());
        }
    }
    if (*op == "cloud_login") return store_cloud_login(request, caller_sid);
    if (*op == "import_rows") return import_rows(request);
    if (*op == "import_days") return import_days(request);
    if (*op == "cloud_logout" || *op == "remote_view_new_key") {
        if (auto e = check_pin(request, s)) return *e;
        if (*op == "cloud_logout") {
            s.cloud_token_enc.clear();
            s.cloud_account_enc.clear();
        } else {
            Bytes raw = random_bytes(16);
            std::string key = base32(raw);
            wipe(raw);
            s.remote_view_key_enc = protect_secret(key);
            wipe(key);
        }
        if (*op == "remote_view_new_key") s.secrets_owner_sid = narrow(caller_sid);  // novi ključ uz PIN – vlasnik je pozivatelj
        save_settings(s);
        log_info("Broker: " + *op + " (" + narrow(caller_sid) + ")");
        return state(s, caller_sid);
    }
    return bad_request();
}

json BrokerCore::save_form(const json& request, const std::wstring& caller) {
    const Settings current = load_settings();
    if (auto e = check_pin(request, current)) return *e;
    const auto form = request.find("form");
    if (form == request.end() || !form->is_object()) return bad_request();
    if (form->value("pin_clear", false)) {
        return fail("invalid", tr("Provjerite označena polja."), {{"errors", {{"pin_new", tr("PIN postavki je obavezan i ne može se ukloniti.")}}}});
    }
    const auto v = validate_form(*form, current, interfaces_ ? interfaces_() : std::vector<std::string>{});
    if (!v.settings) {
        json errors = json::object();
        for (const auto& [k, msg] : v.errors) errors[k] = msg;
        return fail("invalid", tr("Provjerite označena polja."), {{"errors", errors}});
    }
    save_settings(*v.settings);
    log_info("Broker: postavke spremljene (" + narrow(caller) + ")");
    return state(*v.settings, caller);
}

json BrokerCore::store_cloud_login(const json& request, const std::wstring& caller) {
    Settings s = load_settings();
    if (auto e = check_pin(request, s)) return *e;
    static const std::regex token_re(R"(^[A-Za-z0-9_\-]{16,512}$)");
    static const std::regex pin_re(R"(^[0-9A-Fa-f:]{0,128}$)");
    const auto url = str_field(request, "cloud_url", 512);
    const auto token = str_field(request, "token", 512);
    const auto cert_pin = str_field(request, "cert_pin", 128);
    const auto account = request.find("account");
    if (!url || !token || !cert_pin || account == request.end() || !account->is_object()) return bad_request();
    const auto normalized = normalize_server_url(*url);
    if (!normalized || !std::regex_match(*token, token_re) || !std::regex_match(*cert_pin, pin_re)) return bad_request();
    const std::string account_text = account->dump();
    if (account_text.size() > 2048) return bad_request();
    s.cloud_url = *normalized;
    s.cloud_token_enc = protect_secret(*token);
    s.cloud_account_enc = protect_secret(account_text);
    s.cloud_cert_pin = *cert_pin;
    s.secrets_owner_sid = narrow(caller);  // 5.0.2 (audit W-08/W-12): oznaku dobiva samo korisnik koji se prijavio uz PIN
    save_settings(s);
    log_info("Broker: prijava na poslužitelj " + *normalized + " spremljena (" + s.secrets_owner_sid + ")");
    return state(s, caller);
}

json BrokerCore::import_rows(const json& request) {
    if (auto e = check_pin(request, load_settings())) return *e;
    const auto rows = request.find("rows");
    if (rows == request.end() || !rows->is_array() || rows->size() > kBrokerMaxRows) return bad_request();
    std::vector<HistoryRow> parsed;
    parsed.reserve(rows->size());
    for (const auto& r : *rows) {
        if (!r.is_array() || r.size() != 7 || !r[0].is_string()) return bad_request();
        bool ok = true;
        HistoryRow h;
        h.ts_utc = r[0].get<std::string>();
        h.power_kw = opt_number(r[1], &ok);
        h.e_daily_kwh = opt_number(r[2], &ok);
        h.e_total_kwh = opt_number(r[3], &ok);
        h.pf = opt_number(r[4], &ok);
        if (!r[5].is_null()) {
            if (!r[5].is_number_integer()) return bad_request();
            h.status = r[5].get<int64_t>();
        }
        h.load_kw = opt_number(r[6], &ok);
        if (!ok || !valid_history_row(h)) return bad_request();
        parsed.push_back(std::move(h));
    }
    if (!no_reparse_points(data_dir())) return fail("unsafe", tr("Mapa podataka je spojnica – uvoz odbijen."));
    const int64_t added = Db(db_file()).insert_history_rows(parsed);
    return {{"ok", true}, {"added", added}};
}

json BrokerCore::import_days(const json& request) {
    if (auto e = check_pin(request, load_settings())) return *e;
    const auto days = request.find("days");
    if (days == request.end() || !days->is_array() || days->size() > 4000) return bad_request();
    std::map<Date, double> parsed;
    for (const auto& d : *days) {
        if (!d.is_array() || d.size() != 2 || !d[0].is_string() || !d[1].is_number()) return bad_request();
        const auto date = parse_iso_date(d[0].get<std::string>());
        const double kwh = d[1].get<double>();
        if (!date || !std::isfinite(kwh) || kwh < 0 || kwh > 1e7) return bad_request();
        parsed[*date] = kwh;
    }
    if (!no_reparse_points(data_dir())) return fail("unsafe", tr("Mapa podataka je spojnica – uvoz odbijen."));
    Db db(db_file());
    const ExportImport r = import_perfmg_days(db, parsed, local_date(clock_()));
    json out = {{"ok", true}, {"imported", r.imported}, {"skipped", r.skipped}, {"kwh", r.kwh}};
    if (r.first) out["first"] = iso_date(*r.first);
    if (r.last) out["last"] = iso_date(*r.last);
    return out;
}

// ---------------------------------------------------------------- kanal
BrokerServer::BrokerServer(BrokerCore::Interfaces interfaces, std::wstring name, std::wstring sddl)
    : core_(std::move(interfaces)),
      server_(ipc::PipeServerConfig{std::move(name), std::move(sddl), 2, 10'000, 10'000, 1, ipc::kMaxRequestBytes, nullptr},
              [this](const json& request, const ipc::Caller& caller) { return core_.handle(request, caller.sid); }) {}

void BrokerServer::start() { server_.start(); }
void BrokerServer::stop() { server_.stop(); }

namespace {
std::wstring dev_broker_pipe() {
#ifdef SOLARI_DEV_BUILD
    if (const wchar_t* p = _wgetenv(L"SOLARI_DEV_BROKER_PIPE"); p && *p) return p;
#endif
    return {};
}
}  // namespace

std::wstring broker_pipe_name() {
    const std::wstring dev = dev_broker_pipe();
    return dev.empty() ? std::wstring(kBrokerPipe) : dev;
}

std::wstring broker_owner_sid() { return dev_broker_pipe().empty() ? std::wstring(ipc::kSystemSid) : ipc::current_user_sid(); }

std::wstring broker_sddl() {
    return dev_broker_pipe().empty() ? std::wstring(kBrokerSddl) : std::wstring(L"D:P(A;;GA;;;SY)(A;;GA;;;OW)(A;;0x12018b;;;IU)");
}

json broker_call(const json& request) { return broker_call(request, broker_pipe_name(), broker_owner_sid()); }

json broker_call(const json& request, const std::wstring& name, const std::wstring& owner_sid) {
    return ipc::pipe_call(name, request, owner_sid, 15'000);
}

int set_pin_from_file(const fs::path& file) {
    auto text = read_file(file);
    std::error_code ec;
    fs::remove(file, ec);
    if (!text) return 2;
    std::string pin = trim(text->substr(0, text->find_first_of("\r\n")));
    wipe(*text);
    if (!std::regex_match(pin, std::regex(R"(^\d{4,8}$)"))) return 3;
    try {
        save_secret_field("settings_pin_hash", hash_pin(pin));
    } catch (const std::exception& e) {
        log_error(std::string("PIN postavki nije spremljen: ") + e.what());
        return 4;
    }
    wipe(pin);
    log_info("PIN postavki postavljen (instalacija)");
    return 0;
}

int set_resend_key_from_file(const fs::path& file) {
    auto text = read_file(file);
    std::error_code ec;
    fs::remove(file, ec);
    if (!text) return 2;
    if (text->rfind("\xEF\xBB\xBF", 0) == 0) text->erase(0, 3);  // UTF-8 BOM (Bilježnica)
    std::string key = trim(text->substr(0, text->find_first_of("\r\n")));
    wipe(*text);
    if (!valid_resend_key(key)) {
        wipe(key);
        return 3;
    }
    try {
        Settings s = load_settings();
        s.resend_api_key_enc = protect_secret(key);
        s.mail_provider = "resend";
        save_settings(s);
    } catch (const std::exception& e) {
        wipe(key);
        log_error(std::string("API ključ servisa Resend nije spremljen: ") + e.what());
        return 4;
    }
    wipe(key);
    log_info("API ključ servisa Resend postavljen (administrator)");
    return 0;
}

}  // namespace sm

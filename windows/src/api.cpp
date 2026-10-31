#include "api.hpp"

#include <cctype>
#include <iterator>
#include <map>
#include <mutex>
#include <vector>

#include "dashboard.hpp"
#include "i18n.hpp"
#include "images.hpp"
#include "report.hpp"

namespace sm {

namespace {

constexpr int kFailWindowS = 600, kMaxFailures = 10, kBlockS = 600;
constexpr size_t kMaxTrackedAddresses = 10'000;
constexpr size_t kMaxDeviceLength = 120;

struct Failures {
    int count = 0;
    std::time_t window_start = 0, blocked_until = 0;
};
std::mutex g_mutex;
std::map<std::string, Failures> g_failures;

}  // namespace

// Ključ za ograničenje po adresi (SMA-15): IPv6 se grupira po /64 (jedan priključak dobiva cijeli /64);
// neispravan zapis → jedan zajednički ključ (ne može se koristiti za zaobilaženje brojanja).
std::string rate_limit_key(const std::string& ip) {
    if (ip.find(':') == std::string::npos) {
        for (char c : ip) if (!std::isdigit(static_cast<unsigned char>(c)) && c != '.') return "invalid";
        return ip.empty() ? "invalid" : ip;
    }
    std::vector<std::string> groups;
    std::string cur;
    size_t gap = std::string::npos;  // položaj "::"
    for (size_t i = 0; i < ip.size(); ++i) {
        const char c = ip[i];
        if (c == ':') {
            if (i + 1 < ip.size() && ip[i + 1] == ':') {
                if (gap != std::string::npos) return "invalid";
                if (!cur.empty() || i > 0) groups.push_back(cur);
                cur.clear();
                gap = groups.size();
                ++i;
                continue;
            }
            groups.push_back(cur);
            cur.clear();
        } else if (std::isxdigit(static_cast<unsigned char>(c))) {
            cur += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            if (cur.size() > 4) return "invalid";
        } else {
            return "invalid";
        }
    }
    if (!cur.empty()) groups.push_back(cur);
    std::vector<std::string> full;
    if (gap != std::string::npos) {
        if (groups.size() > 7) return "invalid";
        full.assign(groups.begin(), groups.begin() + static_cast<std::ptrdiff_t>(gap));
        full.insert(full.end(), 8 - groups.size(), "0");
        full.insert(full.end(), groups.begin() + static_cast<std::ptrdiff_t>(gap), groups.end());
    } else {
        full = groups;
    }
    if (full.size() != 8) return "invalid";
    std::string key = "v6:";
    for (int i = 0; i < 4; ++i) key += (i ? ":" : "") + (full[i].empty() ? std::string("0") : full[i]);
    return key + "::/64";
}

namespace {

std::string client_ip(const HttpRequest& req) {
    // cloudflared na istom računalu: stvarni klijent je u CF-Connecting-IP (samo s loopbacka)
    const std::string cf = trim(req.header("CF-Connecting-IP"));
    return rate_limit_key(req.peer == "127.0.0.1" && !cf.empty() ? cf : req.peer);
}

bool blocked(const std::string& ip, std::time_t t) {
    std::lock_guard lock(g_mutex);
    const auto it = g_failures.find(ip);
    return it != g_failures.end() && it->second.blocked_until > t;
}

void count_failure(const std::string& ip, std::time_t t) {
    std::lock_guard lock(g_mutex);
    Failures& f = g_failures[ip];
    if (t - f.window_start > kFailWindowS) f = Failures{0, t, 0};
    if (++f.count >= kMaxFailures) {
        f.blocked_until = t + kBlockS;
        log_warn("API: previše neuspjelih prijava s adrese " + ip + " – blokirano " + std::to_string(kBlockS / 60) + " min");
    }
    if (g_failures.size() > kMaxTrackedAddresses) {  // zaštita memorije (SMA-15): brišu se samo istekli zapisi
        for (auto it = g_failures.begin(); it != g_failures.end();) {
            const bool expired = it->second.blocked_until <= t && t - it->second.window_start > kFailWindowS;
            it = expired ? g_failures.erase(it) : std::next(it);
        }
        // i dalje previše (napad s mnogo adresa): brišu se najstariji neblokirani, aktivne blokade ostaju
        for (auto it = g_failures.begin(); g_failures.size() > kMaxTrackedAddresses && it != g_failures.end();) {
            it = it->second.blocked_until > t ? std::next(it) : g_failures.erase(it);
        }
    }
}

void clear_failures(const std::string& ip) {
    std::lock_guard lock(g_mutex);
    g_failures.erase(ip);
}

std::string bearer(const HttpRequest& req) {
    const std::string h = req.header("Authorization");
    return h.rfind("Bearer ", 0) == 0 ? trim(h.substr(7)) : std::string{};
}

json user_json(const UserInfo& u) {
    return {{"first_name", u.first_name}, {"last_name", u.last_name}, {"email", u.email}, {"role", role_name(u.role)},
            {"totp", u.totp_enabled}};
}

HttpResponse unauthorized() {
    HttpResponse r = HttpResponse::json_body(401, {{"error", "unauthorized"}});
    r.extra_headers = "WWW-Authenticate: Bearer\r\n";
    return r;
}

std::optional<json> body_json(const HttpRequest& req) {
    if (req.body.empty()) return std::nullopt;
    json j = json::parse(req.body, nullptr, false);
    if (j.is_discarded() || !j.is_object()) return std::nullopt;
    return j;
}

std::string str(const json& j, const char* key) { return j.contains(key) && j[key].is_string() ? j[key].get<std::string>() : ""; }

std::string api_image_url(const std::string& kind) {
    const std::string app_url = image_url(kind);  // https://app.solari/...?v=123
    const auto q = app_url.find("?v=");
    return "/api/v1/images/" + kind + (q == std::string::npos ? "" : app_url.substr(q));
}

HttpResponse login(UserStore& users, const HttpRequest& req, const std::string& ip, std::time_t t) {
    if (req.method != "POST") return HttpResponse::json_body(405, {{"error", "method"}});
    if (!users.has_admin()) return HttpResponse::json_body(503, {{"error", "not_set_up"}});
    const auto body = body_json(req);
    if (!body) return HttpResponse::json_body(400, {{"error", "bad_request"}});
    std::string password = str(*body, "password");
    const LoginResult r = users.login(str(*body, "email"), std::move(password), str(*body, "device").substr(0, kMaxDeviceLength), t,
                                      str(*body, "totp"), str(*body, "new_password"));
    // dvofaktorska prijava: lozinka je točna, treba kod (ili postavljanje – adresa za QR kod samo tada)
    const auto totp_reply = [&](const char* error) {
        json j = {{"error", error}};
        if (!r.totp_uri.empty()) j.update({{"secret", r.totp_secret}, {"uri", r.totp_uri}});
        return HttpResponse::json_body(401, j);
    };
    switch (r.status) {
    case LoginResult::Status::Ok: {
        clear_failures(ip);
        log_info("API: prijava korisnika #" + std::to_string(r.user->id) + " s adrese " + ip);
        json ok = {{"token", r.token}, {"user", user_json(*r.user)}};
        if (!r.recovery_codes.empty()) ok["recovery_codes"] = r.recovery_codes;  // samo jednom, pri postavljanju
        return HttpResponse::json_body(200, ok);
    }
    case LoginResult::Status::ActivationRequired:
        return HttpResponse::json_body(401, {{"error", "activation_required"}, {"message", tr("Aktivacijski kod je točan – postavite svoju lozinku.")}});
    case LoginResult::Status::PasswordInvalid: return HttpResponse::json_body(400, {{"error", "password_invalid"}, {"message", r.problem}});
    case LoginResult::Status::TotpRequired: return totp_reply("totp_required");
    case LoginResult::Status::TotpSetup: return totp_reply("totp_setup");
    case LoginResult::Status::TotpInvalid:
        count_failure(ip, t);
        return totp_reply("totp_invalid");
    case LoginResult::Status::Locked:
        count_failure(ip, t);
        return HttpResponse::json_body(423, {{"error", "locked"}, {"message", tr("Račun je privremeno zaključan zbog previše pogrešnih pokušaja.")}});  // bez vremena (SMA-26)
    case LoginResult::Status::Disabled:
        return HttpResponse::json_body(403, {{"error", "disabled"}, {"message", tr("Račun je blokiran.")}});
    case LoginResult::Status::BadCredentials: break;
    }
    count_failure(ip, t);
    return HttpResponse::json_body(401, {{"error", "bad_credentials"}, {"message", tr("Pogrešna e-pošta ili lozinka.")}});
}

HttpResponse change_password(UserStore& users, const UserInfo& me, const HttpRequest& req, const std::string& ip, std::time_t t) {
    if (req.method != "POST") return HttpResponse::json_body(405, {{"error", "method"}});
    const auto body = body_json(req);
    if (!body) return HttpResponse::json_body(400, {{"error", "bad_request"}});
    const std::string old_pw = str(*body, "old_password"), new_pw = str(*body, "new_password");
    try {
        users.change_password(me.id, old_pw, new_pw, t);
    } catch (const UserError& e) {
        if (e.fields.count("old_password")) count_failure(ip, t);
        return HttpResponse::json_body(400, {{"error", "invalid"}, {"fields", e.fields}});
    }
    // sve prijave su poništene – ovaj uređaj dobiva novu oznaku
    const LoginResult r = users.login(me.email, new_pw, str(*body, "device").substr(0, kMaxDeviceLength), t, str(*body, "totp"));
    if (r.status != LoginResult::Status::Ok) return HttpResponse::json_body(200, {{"token", nullptr}, {"login_again", true}});
    return HttpResponse::json_body(200, {{"token", r.token}});
}

}  // namespace

fs::path users_db_file() { return data_dir() / L"users.db"; }
fs::path users_key_file() { return data_dir() / L"users.key"; }

HttpServer::Handler api_handler(ApiContext ctx) {
    return [ctx](const HttpRequest& req) -> HttpResponse {
        const std::string ip = client_ip(req);
        const std::time_t t = now();
        try {
            if (req.path == "/api/v1/ping") {
                return HttpResponse::json_body(200, {{"app", "Solarni poslužitelj"}, {"api", kApiVersion}, {"setup", ctx.users->has_admin()}});
            }
            if (blocked(ip, t)) return HttpResponse::json_body(429, {{"error", "too_many_attempts"}});
            if (req.path == "/api/v1/login") return login(*ctx.users, req, ip, t);

            const std::string token = bearer(req);
            const auto me = token.empty() ? std::nullopt : ctx.users->session_user(token, t);
            if (!me) {
                if (!token.empty()) count_failure(ip, t);
                return unauthorized();
            }
            if (req.path == "/api/v1/logout") {
                ctx.users->logout(token);
                return HttpResponse::json_body(200, {{"ok", true}});
            }
            if (req.path == "/api/v1/me") return HttpResponse::json_body(200, user_json(*me));
            if (req.path == "/api/v1/password") return change_password(*ctx.users, *me, req, ip, t);
            if (req.method != "GET" && req.method != "HEAD") return HttpResponse::json_body(405, {{"error", "method"}});

            const Settings s = ctx.settings();
            if (req.path == "/api/v1/info") {
                return HttpResponse::json_body(200, {{"app", "Solarni poslužitelj"}, {"version", SOLARI_VERSION}, {"api", kApiVersion},
                                                     {"plant", s.plant_name}, {"location", s.location}});
            }
            if (req.path == "/api/v1/dashboard") {
                json d = public_dashboard(build_dashboard(*ctx.data, *ctx.weather, *ctx.catalog, s));  // SMA-08
                d["images"] = {{"hero", api_image_url("hero")}, {"drawing", api_image_url("drawing")}, {"logo", api_image_url("logo")}};
                d["user"] = user_json(*me);
                return HttpResponse::json_body(200, d);
            }
            if (req.path.rfind("/api/v1/images/", 0) == 0) {
                const std::string kind = req.path.substr(15);
                if (!is_image_kind(kind)) return HttpResponse::json_body(404, {{"error", "not_found"}});
                const fs::path file = image_path(kind);
                const auto body = read_file(file);
                if (!body) return HttpResponse::json_body(404, {{"error", "not_found"}});
                return HttpResponse{200, content_type(file.wstring()), *body};
            }
            if (req.path == "/api/v1/report") {
                const int year = std::atoi(req.param("year").c_str()), month = std::atoi(req.param("month").c_str());
                if (year < 2000 || year > 2100 || month < 1 || month > 12) return HttpResponse::json_body(400, {{"error", "bad_month"}});
                return HttpResponse::json_body(200, build_report(*ctx.data, s, year, static_cast<unsigned>(month)));
            }
            return HttpResponse::json_body(404, {{"error", "not_found"}});
        } catch (const std::exception& e) {
            log_warn(std::string("API ") + req.path + ": " + e.what());
            return HttpResponse::json_body(500, {{"error", "internal"}});  // detalji samo u zapisniku
        }
    };
}

}  // namespace sm

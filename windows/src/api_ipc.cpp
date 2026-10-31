#include "api_ipc.hpp"

#include <winsock2.h>
#include <ws2tcpip.h>

#include <regex>
#include <set>

namespace sm {

namespace {

const std::set<std::string>& allowed_keys() {
    static const std::set<std::string> keys = {"v", "nonce", "id", "type", "route", "method", "image", "year", "month",
                                               "token", "client_ip", "cf_ip", "body"};
    return keys;
}

bool set_error(std::string* error, const char* why) {
    if (error) *error = why;
    return false;
}

std::optional<std::string> opt_string(const json& m, const char* key, size_t max_len, bool* ok) {
    const auto it = m.find(key);
    if (it == m.end()) return std::nullopt;
    if (!it->is_string() || it->get_ref<const std::string&>().size() > max_len) {
        *ok = false;
        return std::nullopt;
    }
    return it->get<std::string>();
}

}  // namespace

std::wstring api_pipe_sddl(const std::wstring& gateway_sid, bool owner_system) {
    // bez vlasnika SYSTEM (samo razvojna gradnja i testovi): OW:GA da tvorac smije stvarati instance kanala
    return std::wstring(owner_system ? L"O:SYD:P" : L"D:P(A;;GA;;;OW)") + L"(A;;GA;;;SY)(A;;0x12018b;;;" + gateway_sid + L")";
}

bool valid_ip_literal(const std::string& ip) {
    if (ip.empty() || ip.size() > 45) return false;
    in6_addr v6{};
    in_addr v4{};
    return inet_pton(AF_INET, ip.c_str(), &v4) == 1 || inet_pton(AF_INET6, ip.c_str(), &v6) == 1;
}

std::optional<HttpRequest> request_from_ipc(const json& m, std::string* error) {
    if (!m.is_object()) return set_error(error, "not_object"), std::nullopt;
    for (const auto& [k, _] : m.items()) {
        if (!allowed_keys().count(k)) return set_error(error, "unknown_field"), std::nullopt;
    }
    bool ok = true;
    const auto route = opt_string(m, "route", 16, &ok);
    const auto method = opt_string(m, "method", 8, &ok);
    const auto image = opt_string(m, "image", 16, &ok);
    const auto token = opt_string(m, "token", 512, &ok);
    const auto client_ip = opt_string(m, "client_ip", 45, &ok);
    const auto cf_ip = opt_string(m, "cf_ip", 45, &ok);
    const auto body = opt_string(m, "body", kApiMaxBody, &ok);
    if (!ok) return set_error(error, "field_type"), std::nullopt;
    static const std::set<std::string> routes = {"ping", "login", "logout", "me", "password", "info", "dashboard", "image", "report"};
    if (!route || !routes.count(*route)) return set_error(error, "route"), std::nullopt;
    if (!method || (*method != "GET" && *method != "HEAD" && *method != "POST")) return set_error(error, "method"), std::nullopt;
    if (!client_ip || !valid_ip_literal(*client_ip)) return set_error(error, "client_ip"), std::nullopt;
    if (cf_ip && !valid_ip_literal(*cf_ip)) return set_error(error, "cf_ip"), std::nullopt;
    static const std::regex token_re(R"(^[A-Za-z0-9_\-]{1,512}$)");
    if (token && !std::regex_match(*token, token_re)) return set_error(error, "token"), std::nullopt;

    HttpRequest r;
    r.method = *method;
    r.peer = *client_ip;
    r.path = "/api/v1/" + *route;
    if (*route == "image") {
        if (!image || (*image != "hero" && *image != "drawing" && *image != "logo")) return set_error(error, "image"), std::nullopt;
        r.path = "/api/v1/images/" + *image;
    } else if (image) {
        return set_error(error, "image"), std::nullopt;
    }
    const bool has_year = m.contains("year"), has_month = m.contains("month");
    if (has_year || has_month) {
        if (*route != "report" || !has_year || !has_month || !m["year"].is_number_integer() || !m["month"].is_number_integer()) {
            return set_error(error, "query"), std::nullopt;
        }
        const auto y = m["year"].get<int64_t>(), mo = m["month"].get<int64_t>();
        if (y < 0 || y > 9999 || mo < 0 || mo > 99) return set_error(error, "query"), std::nullopt;
        r.query = "year=" + std::to_string(y) + "&month=" + std::to_string(mo);  // raspon provjerava api.cpp (400)
    }
    r.target = r.path + (r.query.empty() ? "" : "?" + r.query);
    if (token) r.headers["authorization"] = "Bearer " + *token;
    // CF-Connecting-IP samo s loopbacka (cloudflared na istom računalu) – isto kao api.cpp (SMA-15)
    if (cf_ip && *client_ip == "127.0.0.1") r.headers["cf-connecting-ip"] = *cf_ip;
    if (body) {
        if (*method != "POST") return set_error(error, "body"), std::nullopt;
        r.body = *body;
        r.headers["content-type"] = "application/json";
    }
    return r;
}

json response_to_ipc(const HttpResponse& response) {
    json headers = json::array();
    static const std::set<std::string> passed = {"www-authenticate", "allow", "cache-control", "retry-after"};
    size_t pos = 0;
    while (pos < response.extra_headers.size()) {
        const size_t end = response.extra_headers.find("\r\n", pos);
        const std::string line = response.extra_headers.substr(pos, end == std::string::npos ? std::string::npos : end - pos);
        pos = end == std::string::npos ? response.extra_headers.size() : end + 2;
        const size_t colon = line.find(':');
        if (colon == std::string::npos) continue;
        std::string name = line.substr(0, colon);
        std::string lower = name;
        for (char& c : lower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        if (passed.count(lower)) headers.push_back(json::array({name, trim(line.substr(colon + 1))}));
    }
    return {{"ok", true},
            {"status", response.code},
            {"content_type", response.type},
            {"body_b64", base64(std::vector<uint8_t>(response.body.begin(), response.body.end()))},
            {"headers", headers}};
}

ipc::PipeServer::Handler api_ipc_handler(HttpServer::Handler api, std::function<GatewayConfig()> config,
                                         std::function<void(const json& hello)> on_hello) {
    return [api = std::move(api), config = std::move(config), on_hello = std::move(on_hello)](const json& m, const ipc::Caller&) -> json {
        const auto type = m.find("type");
        if (type == m.end() || !type->is_string()) return {{"ok", false}, {"error", "bad_request"}};
        const auto cfg = [&] {
            const GatewayConfig c = config();
            return json{{"port", c.port}, {"lan", c.lan}};
        };
        if (*type == "hello") {
            if (on_hello) on_hello(m);
            return {{"ok", true}, {"config", cfg()}};
        }
        if (*type == "config") return {{"ok", true}, {"config", cfg()}};
        if (*type != "request") return {{"ok", false}, {"error", "bad_request"}};
        std::string why;
        const auto req = request_from_ipc(m, &why);
        if (!req) {
            log_warn("API (IPC): odbijena poruka gatewaya (" + why + ")");
            return {{"ok", false}, {"error", "bad_request"}, {"reason", why}};
        }
        return response_to_ipc(api(*req));
    };
}

fs::path gateway_info_file() { return service_dir() / L"gateway.json"; }

std::optional<json> gateway_info() {
    const auto text = read_file(gateway_info_file());
    if (!text) return std::nullopt;
    json j = json::parse(*text, nullptr, false);
    if (!j.is_object() || !j.contains("fingerprint") || !j["fingerprint"].is_string()) return std::nullopt;
    return j;
}

}  // namespace sm

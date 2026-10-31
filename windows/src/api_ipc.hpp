// 4.0 (B1, ADR-001): API poslužitelja preko imenovanog kanala. Mrežu prima samo Rust gateway (solari-gateway.exe,
// NT SERVICE\SolariGateway); C++ servis (SYSTEM) nema TCP port za API i ne parsira HTTP – dobiva strukturiranu poruku:
//   {"type":"request","route":"ping|login|logout|me|password|info|dashboard|image|report","method":"GET|HEAD|POST",
//    "image":"hero|drawing|logo","year":2026,"month":10,"token":"<Bearer>","client_ip":"…","cf_ip":"…","body":"<JSON>"}
//   → {"ok":true,"status":200,"content_type":"…","body_b64":"…","headers":[["WWW-Authenticate","Bearer"]]}
//   {"type":"hello","fingerprint":"AB:CD:…","not_after":"…","version":"…"} → {"ok":true,"config":{…}}
//   {"type":"config"} → {"ok":true,"config":{"port":8700,"lan":true}}
// Sve što nije na popisu (nepoznata polja, ruta, metoda, neispravna adresa) odbija se bez obrade.
#pragma once

#include <functional>
#include <optional>
#include <string>

#include "config.hpp"
#include "ipc.hpp"
#include "remote.hpp"
#include "util.hpp"

namespace sm {

inline constexpr wchar_t kApiPipe[] = L"\\\\.\\pipe\\SolarniServer.Api.v1";
inline constexpr wchar_t kGatewayService[] = L"SolariGateway";
inline constexpr size_t kApiMaxBody = 16 * 1024;

// DACL kanala: SYSTEM puno, SID usluge gatewaya čitanje/pisanje podataka (bez stvaranja instance)
std::wstring api_pipe_sddl(const std::wstring& gateway_sid, bool owner_system = true);

// Strukturirana poruka → interni zahtjev za api_handler (nullopt + razlog ako poruka nije dopuštena)
std::optional<HttpRequest> request_from_ipc(const json& message, std::string* error = nullptr);
json response_to_ipc(const HttpResponse& response);

struct GatewayConfig {
    int port = 8700;
    bool lan = false;
};
// Obrada poruka gatewaya; config() daje trenutne postavke porta, on_hello sprema podatke o certifikatu
ipc::PipeServer::Handler api_ipc_handler(HttpServer::Handler api, std::function<GatewayConfig()> config,
                                         std::function<void(const json& hello)> on_hello);

// service\gateway.json – otisak certifikata gatewaya (za kod uparivanja u prozoru poslužitelja)
fs::path gateway_info_file();
std::optional<json> gateway_info();
bool valid_ip_literal(const std::string& ip);

}  // namespace sm

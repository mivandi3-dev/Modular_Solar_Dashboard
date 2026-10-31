// API Solarnog poslužitelja (SolarniServer.exe) za klijente preko Cloudflare tunela ili lokalne mreže (HTTPS).
// Od 3.0 nema API ključa: korisnik se prijavi e-poštom i lozinkom (src/users.cpp), a svaki sljedeći zahtjev nosi
// "Authorization: Bearer <oznaka prijave>" – inače 401 bez ikakvih podataka. Nakon 10 neuspjelih prijava ili
// nevaljanih oznaka u 10 minuta adresa je blokirana 10 minuta (429). Iza tunela adresa klijenta je CF-Connecting-IP.
//
//   GET  /api/v1/ping                     bez prijave: {"app","api":3,"setup"} – provjera veze i je li poslužitelj postavljen
//   POST /api/v1/login                    {"email","password","device","totp","new_password"} → {"token","user"[,"recovery_codes"]}
//                                         401 password_change (početna lozinka – pošalji new_password) | password_expired;
//                                         400 password_invalid (+message)
//                                         401 totp_required | totp_setup (+secret, uri za QR) | totp_invalid
//   POST /api/v1/logout                   poništava oznaku iz zaglavlja
//   GET  /api/v1/me                       prijavljeni korisnik
//   POST /api/v1/password                 {"old_password","new_password"} → nova oznaka (sve ostale prijave prestaju)
//   GET  /api/v1/info                     naziv elektrane i verzija
//   GET  /api/v1/dashboard                isti JSON kao dashboard aplikacije; slike kao /api/v1/images/<vrsta>?v=…
//   GET  /api/v1/images/{hero|drawing|logo}
//   GET  /api/v1/report?year=2026&month=9 mjesečni izvještaj (src/report.cpp)
#pragma once

#include <functional>
#include <string>

#include "config.hpp"
#include "data.hpp"
#include "layout.hpp"
#include "remote.hpp"
#include "users.hpp"
#include "weather.hpp"

namespace sm {

inline constexpr int kApiVersion = 3;
inline constexpr wchar_t kServerServiceMutex[] = L"Global\\SolarniServerService";

int run_server_service();  // src/service.cpp – radi dok se proces ne zaustavi

fs::path users_db_file();   // data\users.db
fs::path users_key_file();  // data\users.key (DPAPI)

struct ApiContext {
    DataService* data = nullptr;
    WeatherService* weather = nullptr;
    const Catalog* catalog = nullptr;
    UserStore* users = nullptr;
    std::function<Settings()> settings;
};
HttpServer::Handler api_handler(ApiContext ctx);

}  // namespace sm

// Zaštita lozinke SMTP poslužitelja u config.json (Windows DPAPI, isti zapis kao solar/secret.py).
// Šifrira se za cijelo računalo, jer lozinku čitaju i aplikacija (korisnik) i poller (zadatak sustava).
#pragma once

#include <string>

namespace sm {

std::string protect_secret(const std::string& text);      // "" → ""; inače "dpapi:<base64>"
std::string unprotect_secret(const std::string& stored);   // neispravan zapis → ""

}  // namespace sm

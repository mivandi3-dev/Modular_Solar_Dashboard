// Kriptografija preko Windows CNG-a (bcrypt.dll) – bez vanjskih biblioteka:
// slučajni bajtovi, SHA-256, HMAC-SHA256, PBKDF2-HMAC-SHA256 (lozinke) i AES-256-GCM (osobni podaci).
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace sm {

using Bytes = std::vector<uint8_t>;

inline constexpr size_t kAesKeyBytes = 32;
inline constexpr size_t kGcmNonceBytes = 12;
inline constexpr size_t kGcmTagBytes = 16;

Bytes random_bytes(size_t n);
Bytes sha256(std::string_view data);
Bytes hmac_sha256(const Bytes& key, std::string_view data);
Bytes hmac_sha1(const Bytes& key, std::string_view data);  // samo TOTP (RFC 6238, kompatibilno s aplikacijama autentifikatorima)
Bytes pbkdf2_sha256(std::string_view password, const Bytes& salt, uint32_t iterations, size_t out_bytes);

// AES-256-GCM: izlaz = nonce (12) | šifrat | oznaka (16). aad veže šifrat uz namjenu (npr. "user.email"),
// pa se šifrat jednog polja ne može podmetnuti u drugo. Neispravan ključ, oznaka ili aad → nullopt.
Bytes aes_gcm_encrypt(const Bytes& key, std::string_view plaintext, std::string_view aad);
std::optional<std::string> aes_gcm_decrypt(const Bytes& key, const Bytes& sealed, std::string_view aad);

bool equal_ct(const Bytes& a, const Bytes& b);  // usporedba u stalnom vremenu (za istu duljinu)

std::string to_hex(const Bytes& b);
std::string base64url(const Bytes& b);                     // bez '=' (oznake prijave)
std::optional<Bytes> from_base64url(std::string_view s);   // neispravan znak → nullopt
std::string base32(const Bytes& b);                         // RFC 4648, bez '=' (tajna za aplikaciju autentifikator)
std::optional<Bytes> from_base32(std::string_view s);      // velika ili mala slova, razmaci se preskaču

// Briše osjetljive podatke iz memorije (lozinke, ključeve) – prevoditelj ga ne smije izostaviti.
void wipe(std::string& s);
void wipe(Bytes& b);

}  // namespace sm

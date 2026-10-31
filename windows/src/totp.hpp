// Dvofaktorska prijava (3.1): TOTP prema RFC 6238 – HMAC-SHA1, 6 znamenki, korak 30 s; radi s Google
// Authenticatorom, Microsoft Authenticatorom, Authyjem i sličnim aplikacijama (QR kod s adresom otpauth://).
#pragma once

#include <ctime>
#include <optional>
#include <string>
#include <vector>

#include "crypto.hpp"

namespace sm {

inline constexpr int kTotpDigits = 6;
inline constexpr int kTotpPeriod = 30;
inline constexpr size_t kTotpSecretBytes = 20;  // 160 bita (preporuka RFC 4226)
inline constexpr int kRecoveryCodes = 8;

std::string totp_code(const Bytes& secret, int64_t step, int digits = kTotpDigits);
int64_t totp_step(std::time_t t);

// Korak koraka kojem kod odgovara (±1 korak zbog razlike satova), samo ako je noviji od last_step –
// isti kod se ne može iskoristiti dvaput. nullopt = kod ne vrijedi.
std::optional<int64_t> totp_verify(const Bytes& secret, const std::string& code, std::time_t now, int64_t last_step);

// otpauth://totp/<izdavač>:<račun>?secret=…&issuer=…&algorithm=SHA1&digits=6&period=30
std::string otpauth_uri(const std::string& issuer, const std::string& account, const Bytes& secret);

// Jednokratni kodovi za oporavak ("abcd-efgh"); spremaju se samo njihovi SHA-256 sažeci
std::vector<std::string> make_recovery_codes(int count = kRecoveryCodes);
std::string normalize_recovery_code(const std::string& code);  // bez razmaka i crtica, mala slova

}  // namespace sm

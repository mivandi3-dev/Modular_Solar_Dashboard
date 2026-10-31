#include "totp.hpp"

#include <cctype>

namespace sm {

namespace {

std::string url_encode(const std::string& s) {
    static constexpr char kHex[] = "0123456789ABCDEF";
    std::string out;
    for (unsigned char c : s) {
        if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~' || c == '@') {
            out += static_cast<char>(c);
        } else {
            out += '%';
            out += kHex[c >> 4];
            out += kHex[c & 15];
        }
    }
    return out;
}

}  // namespace

int64_t totp_step(std::time_t t) { return static_cast<int64_t>(t) / kTotpPeriod; }

std::string totp_code(const Bytes& secret, int64_t step, int digits) {
    std::string msg(8, '\0');
    for (int i = 7; i >= 0; --i) {
        msg[static_cast<size_t>(i)] = static_cast<char>(step & 0xFF);
        step >>= 8;
    }
    const Bytes h = hmac_sha1(secret, msg);
    const int offset = h.back() & 0x0F;  // dinamičko skraćivanje (RFC 4226, 5.3)
    const uint32_t bin = ((h[offset] & 0x7Fu) << 24) | (h[offset + 1] << 16) | (h[offset + 2] << 8) | h[offset + 3];
    uint32_t mod = 1;
    for (int i = 0; i < digits; ++i) mod *= 10;
    std::string code = std::to_string(bin % mod);
    return std::string(static_cast<size_t>(digits) - code.size(), '0') + code;
}

std::optional<int64_t> totp_verify(const Bytes& secret, const std::string& code, std::time_t now, int64_t last_step) {
    std::string digits;
    for (char c : code) if (std::isdigit(static_cast<unsigned char>(c))) digits += c;
    if (digits.size() != static_cast<size_t>(kTotpDigits) || secret.empty()) return std::nullopt;
    const int64_t step = totp_step(now);
    std::optional<int64_t> match;
    for (int64_t s = step - 1; s <= step + 1; ++s) {  // svi koraci se provjere (isto vrijeme bez obzira na pogodak)
        const std::string expected = totp_code(secret, s);
        if (equal_ct(Bytes(expected.begin(), expected.end()), Bytes(digits.begin(), digits.end())) && s > last_step) match = s;
    }
    return match;
}

std::string otpauth_uri(const std::string& issuer, const std::string& account, const Bytes& secret) {
    return "otpauth://totp/" + url_encode(issuer) + ":" + url_encode(account) + "?secret=" + base32(secret) +
           "&issuer=" + url_encode(issuer) + "&algorithm=SHA1&digits=" + std::to_string(kTotpDigits) +
           "&period=" + std::to_string(kTotpPeriod);
}

std::vector<std::string> make_recovery_codes(int count) {
    static constexpr char kAlphabet[] = "abcdefghjkmnpqrstuvwxyz23456789";  // bez 0/o, 1/l/i
    std::vector<std::string> out;
    for (int i = 0; i < count; ++i) {
        const Bytes r = random_bytes(8);
        std::string code;
        for (size_t j = 0; j < r.size(); ++j) {
            if (j == 4) code += '-';
            code += kAlphabet[r[j] % (sizeof kAlphabet - 1)];
        }
        out.push_back(code);
    }
    return out;
}

std::string normalize_recovery_code(const std::string& code) {
    std::string out;
    for (unsigned char c : code) if (std::isalnum(c)) out += static_cast<char>(std::tolower(c));
    return out;
}

}  // namespace sm

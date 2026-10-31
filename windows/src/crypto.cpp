#include "crypto.hpp"

#include <windows.h>
#include <bcrypt.h>

#include <cctype>
#include <stdexcept>

namespace sm {

namespace {

bool ok(NTSTATUS s) { return s >= 0; }

void check(NTSTATUS s, const char* what) {
    if (!ok(s)) throw std::runtime_error(std::string("CNG: ") + what);
}

// Otvoreni pružatelj algoritma (RAII)
class Alg {
public:
    Alg(const wchar_t* id, ULONG flags = 0) { check(BCryptOpenAlgorithmProvider(&h_, id, nullptr, flags), "open"); }
    ~Alg() { if (h_) BCryptCloseAlgorithmProvider(h_, 0); }
    Alg(const Alg&) = delete;
    Alg& operator=(const Alg&) = delete;
    BCRYPT_ALG_HANDLE get() const { return h_; }

private:
    BCRYPT_ALG_HANDLE h_ = nullptr;
};

class Key {
public:
    ~Key() { if (h_) BCryptDestroyKey(h_); }
    BCRYPT_KEY_HANDLE* out() { return &h_; }
    BCRYPT_KEY_HANDLE get() const { return h_; }

private:
    BCRYPT_KEY_HANDLE h_ = nullptr;
};

Bytes hash(const Bytes* hmac_key, std::string_view data, const wchar_t* algorithm = BCRYPT_SHA256_ALGORITHM, size_t size = 32) {
    Alg alg(algorithm, hmac_key ? BCRYPT_ALG_HANDLE_HMAC_FLAG : 0);
    BCRYPT_HASH_HANDLE h = nullptr;
    check(BCryptCreateHash(alg.get(), &h, nullptr, 0, hmac_key ? const_cast<PUCHAR>(hmac_key->data()) : nullptr,
                           hmac_key ? static_cast<ULONG>(hmac_key->size()) : 0, 0), "hash");
    Bytes out(size);
    const NTSTATUS s1 = BCryptHashData(h, reinterpret_cast<PUCHAR>(const_cast<char*>(data.data())), static_cast<ULONG>(data.size()), 0);
    const NTSTATUS s2 = ok(s1) ? BCryptFinishHash(h, out.data(), static_cast<ULONG>(out.size()), 0) : s1;
    BCryptDestroyHash(h);
    check(s2, "hash data");
    return out;
}

void gcm_key(const Alg& aes, const Bytes& key, Key& k) {
    if (key.size() != kAesKeyBytes) throw std::invalid_argument("AES ključ mora imati 32 bajta");
    check(BCryptSetProperty(aes.get(), BCRYPT_CHAINING_MODE, reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)),
                            sizeof(BCRYPT_CHAIN_MODE_GCM), 0), "gcm");
    check(BCryptGenerateSymmetricKey(aes.get(), k.out(), nullptr, 0, const_cast<PUCHAR>(key.data()), static_cast<ULONG>(key.size()), 0),
          "key");
}

}  // namespace

Bytes random_bytes(size_t n) {
    Bytes out(n);
    if (n == 0) return out;
    check(BCryptGenRandom(nullptr, out.data(), static_cast<ULONG>(n), BCRYPT_USE_SYSTEM_PREFERRED_RNG), "random");
    return out;
}

Bytes sha256(std::string_view data) { return hash(nullptr, data); }

Bytes hmac_sha256(const Bytes& key, std::string_view data) { return hash(&key, data); }

Bytes hmac_sha1(const Bytes& key, std::string_view data) { return hash(&key, data, BCRYPT_SHA1_ALGORITHM, 20); }

Bytes pbkdf2_sha256(std::string_view password, const Bytes& salt, uint32_t iterations, size_t out_bytes) {
    Alg alg(BCRYPT_SHA256_ALGORITHM, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    Bytes out(out_bytes);
    check(BCryptDeriveKeyPBKDF2(alg.get(), reinterpret_cast<PUCHAR>(const_cast<char*>(password.data())), static_cast<ULONG>(password.size()),
                                const_cast<PUCHAR>(salt.data()), static_cast<ULONG>(salt.size()), iterations, out.data(),
                                static_cast<ULONG>(out.size()), 0), "pbkdf2");
    return out;
}

Bytes aes_gcm_encrypt(const Bytes& key, std::string_view plaintext, std::string_view aad) {
    Alg aes(BCRYPT_AES_ALGORITHM);
    Key k;
    gcm_key(aes, key, k);
    Bytes nonce = random_bytes(kGcmNonceBytes), tag(kGcmTagBytes), out(plaintext.size());
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = nonce.data();
    info.cbNonce = static_cast<ULONG>(nonce.size());
    info.pbAuthData = reinterpret_cast<PUCHAR>(const_cast<char*>(aad.data()));
    info.cbAuthData = static_cast<ULONG>(aad.size());
    info.pbTag = tag.data();
    info.cbTag = static_cast<ULONG>(tag.size());
    ULONG written = 0;
    uint8_t empty = 0;  // CNG ne prima nullptr ni za prazan unos
    check(BCryptEncrypt(k.get(), plaintext.empty() ? &empty : reinterpret_cast<PUCHAR>(const_cast<char*>(plaintext.data())),
                        static_cast<ULONG>(plaintext.size()), &info, nullptr, 0, out.empty() ? &empty : out.data(),
                        static_cast<ULONG>(out.size()), &written, 0), "encrypt");
    Bytes sealed;
    sealed.reserve(nonce.size() + out.size() + tag.size());
    sealed.insert(sealed.end(), nonce.begin(), nonce.end());
    sealed.insert(sealed.end(), out.begin(), out.end());
    sealed.insert(sealed.end(), tag.begin(), tag.end());
    return sealed;
}

std::optional<std::string> aes_gcm_decrypt(const Bytes& key, const Bytes& sealed, std::string_view aad) {
    if (sealed.size() < kGcmNonceBytes + kGcmTagBytes || key.size() != kAesKeyBytes) return std::nullopt;
    Alg aes(BCRYPT_AES_ALGORITHM);
    Key k;
    gcm_key(aes, key, k);
    Bytes nonce(sealed.begin(), sealed.begin() + kGcmNonceBytes), tag(sealed.end() - kGcmTagBytes, sealed.end());
    Bytes cipher(sealed.begin() + kGcmNonceBytes, sealed.end() - kGcmTagBytes);
    std::string out(cipher.size(), '\0');
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = nonce.data();
    info.cbNonce = static_cast<ULONG>(nonce.size());
    info.pbAuthData = reinterpret_cast<PUCHAR>(const_cast<char*>(aad.data()));
    info.cbAuthData = static_cast<ULONG>(aad.size());
    info.pbTag = tag.data();
    info.cbTag = static_cast<ULONG>(tag.size());
    ULONG written = 0;
    uint8_t empty = 0;
    const NTSTATUS s = BCryptDecrypt(k.get(), cipher.empty() ? &empty : cipher.data(), static_cast<ULONG>(cipher.size()), &info,
                                     nullptr, 0, out.empty() ? &empty : reinterpret_cast<PUCHAR>(out.data()),
                                     static_cast<ULONG>(out.size()), &written, 0);
    if (!ok(s)) return std::nullopt;  // pogrešan ključ, aad ili izmijenjen šifrat
    return out;
}

bool equal_ct(const Bytes& a, const Bytes& b) {
    if (a.size() != b.size()) return false;
    uint8_t diff = 0;
    for (size_t i = 0; i < a.size(); ++i) diff |= static_cast<uint8_t>(a[i] ^ b[i]);
    return diff == 0;
}

std::string to_hex(const Bytes& b) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(b.size() * 2);
    for (uint8_t c : b) {
        out += kHex[c >> 4];
        out += kHex[c & 15];
    }
    return out;
}

std::string base64url(const Bytes& b) {
    static constexpr char kAlphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string out;
    size_t i = 0;
    for (; i + 2 < b.size(); i += 3) {
        const uint32_t v = (b[i] << 16) | (b[i + 1] << 8) | b[i + 2];
        out += kAlphabet[v >> 18];
        out += kAlphabet[(v >> 12) & 63];
        out += kAlphabet[(v >> 6) & 63];
        out += kAlphabet[v & 63];
    }
    if (i + 1 == b.size()) {
        const uint32_t v = b[i] << 16;
        out += kAlphabet[v >> 18];
        out += kAlphabet[(v >> 12) & 63];
    } else if (i + 2 == b.size()) {
        const uint32_t v = (b[i] << 16) | (b[i + 1] << 8);
        out += kAlphabet[v >> 18];
        out += kAlphabet[(v >> 12) & 63];
        out += kAlphabet[(v >> 6) & 63];
    }
    return out;
}

std::optional<Bytes> from_base64url(std::string_view s) {
    auto val = [](char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '-') return 62;
        if (c == '_') return 63;
        return -1;
    };
    if (s.size() % 4 == 1) return std::nullopt;
    Bytes out;
    uint32_t acc = 0;
    int bits = 0;
    for (char c : s) {
        const int v = val(c);
        if (v < 0) return std::nullopt;
        acc = (acc << 6) | static_cast<uint32_t>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<uint8_t>((acc >> bits) & 0xFF));
        }
    }
    return out;
}

std::string base32(const Bytes& b) {
    static constexpr char kAlphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    std::string out;
    uint32_t acc = 0;
    int bits = 0;
    for (uint8_t c : b) {
        acc = (acc << 8) | c;
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            out += kAlphabet[(acc >> bits) & 31];
        }
    }
    if (bits > 0) out += kAlphabet[(acc << (5 - bits)) & 31];
    return out;
}

std::optional<Bytes> from_base32(std::string_view s) {
    Bytes out;
    uint32_t acc = 0;
    int bits = 0;
    for (char ch : s) {
        if (ch == ' ' || ch == '-' || ch == '=') continue;
        const char c = static_cast<char>(std::toupper(static_cast<unsigned char>(ch)));
        int v = -1;
        if (c >= 'A' && c <= 'Z') v = c - 'A';
        else if (c >= '2' && c <= '7') v = c - '2' + 26;
        if (v < 0) return std::nullopt;
        acc = (acc << 5) | static_cast<uint32_t>(v);
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<uint8_t>((acc >> bits) & 0xFF));
        }
    }
    return out;
}

void wipe(std::string& s) {
    if (!s.empty()) SecureZeroMemory(s.data(), s.size());
    s.clear();
}

void wipe(Bytes& b) {
    if (!b.empty()) SecureZeroMemory(b.data(), b.size());
    b.clear();
}

}  // namespace sm

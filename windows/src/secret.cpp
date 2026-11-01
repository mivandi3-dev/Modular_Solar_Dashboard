#include "secret.hpp"

#include <windows.h>
#include <wincrypt.h>

#include <vector>

#include "util.hpp"

namespace sm {

namespace {

// 4.0 (SMA-09): DPAPI računala + entropija aplikacije – drugi programi na računalu ne mogu dešifrirati
// samim pozivom CryptUnprotectData. Stari zapis bez entropije ("dpapi:") se ne čita (nema produkcijskih instalacija).
constexpr char kPrefix[] = "dpapi2:";
constexpr char kEntropy[] = "SolarniMonitor/4.0/secret";

DATA_BLOB entropy_blob() {
    return DATA_BLOB{static_cast<DWORD>(sizeof kEntropy - 1), reinterpret_cast<BYTE*>(const_cast<char*>(kEntropy))};
}

std::vector<uint8_t> from_base64(const std::string& text) {
    DWORD size = 0;
    if (!CryptStringToBinaryA(text.c_str(), static_cast<DWORD>(text.size()), CRYPT_STRING_BASE64, nullptr, &size, nullptr,
                              nullptr)) {
        return {};
    }
    std::vector<uint8_t> out(size);
    if (!CryptStringToBinaryA(text.c_str(), static_cast<DWORD>(text.size()), CRYPT_STRING_BASE64, out.data(), &size,
                              nullptr, nullptr)) {
        return {};
    }
    out.resize(size);
    return out;
}

// LocalFree za izlaz DPAPI-ja
struct LocalBlob {
    DATA_BLOB blob{};
    ~LocalBlob() {
        if (blob.pbData) {
            SecureZeroMemory(blob.pbData, blob.cbData);  // 5.0.2 (audit C-16): tajna ne ostaje u oslobođenoj memoriji
            LocalFree(blob.pbData);
        }
    }
};

}  // namespace

std::string protect_secret(const std::string& text) {
    if (text.empty()) return {};
    DATA_BLOB in{static_cast<DWORD>(text.size()), reinterpret_cast<BYTE*>(const_cast<char*>(text.data()))};
    LocalBlob out;
    DATA_BLOB extra = entropy_blob();
    if (!CryptProtectData(&in, nullptr, &extra, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN | CRYPTPROTECT_LOCAL_MACHINE,
                          &out.blob)) {
        throw std::runtime_error("CryptProtectData");
    }
    return kPrefix + base64(std::vector<uint8_t>(out.blob.pbData, out.blob.pbData + out.blob.cbData));
}

std::string unprotect_secret(const std::string& stored) {
    if (stored.rfind(kPrefix, 0) != 0) return {};
    std::vector<uint8_t> data = from_base64(stored.substr(sizeof kPrefix - 1));
    if (data.empty()) return {};
    DATA_BLOB in{static_cast<DWORD>(data.size()), data.data()};
    LocalBlob out;
    DATA_BLOB extra = entropy_blob();
    if (!CryptUnprotectData(&in, nullptr, &extra, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &out.blob)) return {};
    return std::string(reinterpret_cast<char*>(out.blob.pbData), out.blob.cbData);
}

}  // namespace sm

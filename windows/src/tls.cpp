#include "tls.hpp"

#include <winsock2.h>
#include <windows.h>
#include <wincrypt.h>
#include <ncrypt.h>
#define SECURITY_WIN32
#define SCHANNEL_USE_BLACKLISTS  // SCH_CREDENTIALS i TLS_PARAMETERS (TLS 1.3)
#include <subauth.h>
#include <schannel.h>
#include <security.h>
#include <sspi.h>

#include <stdexcept>
#include <string>
#include <vector>

#include "crypto.hpp"
#include "util.hpp"

namespace sm {

namespace {

constexpr DWORD kRsaBits = 3072;
constexpr int kValidYears = 10;
constexpr size_t kMaxHandshakeBytes = 64 * 1024;

struct Store {
    HCERTSTORE h = nullptr;
    Store(bool machine, bool create) {
        DWORD flags = (machine ? CERT_SYSTEM_STORE_LOCAL_MACHINE : CERT_SYSTEM_STORE_CURRENT_USER) | (create ? 0 : CERT_STORE_OPEN_EXISTING_FLAG);
        if (!create) flags |= CERT_STORE_READONLY_FLAG;
        h = CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0, flags, L"MY");
    }
    ~Store() { if (h) CertCloseStore(h, 0); }
};

std::wstring friendly_name(PCCERT_CONTEXT c) {
    DWORD size = 0;
    if (!CertGetCertificateContextProperty(c, CERT_FRIENDLY_NAME_PROP_ID, nullptr, &size) || size < 2) return {};
    std::wstring name(size / sizeof(wchar_t), L'\0');
    CertGetCertificateContextProperty(c, CERT_FRIENDLY_NAME_PROP_ID, name.data(), &size);
    while (!name.empty() && name.back() == L'\0') name.pop_back();
    return name;
}

bool usable(PCCERT_CONTEXT c) {
    FILETIME now{};
    GetSystemTimeAsFileTime(&now);
    if (CompareFileTime(&now, &c->pCertInfo->NotAfter) >= 0) return false;
    NCRYPT_KEY_HANDLE key = 0;
    DWORD spec = 0;
    BOOL free_key = FALSE;
    if (!CryptAcquireCertificatePrivateKey(c, CRYPT_ACQUIRE_SILENT_FLAG | CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG, nullptr, &key, &spec, &free_key)) {
        return false;
    }
    if (free_key) NCryptFreeObject(key);
    return true;
}

ServerCert describe(PCCERT_CONTEXT c, bool machine) {
    ServerCert out;
    std::string der(reinterpret_cast<const char*>(c->pbCertEncoded), c->cbCertEncoded);
    const Bytes h = sha256(der);
    out.fingerprint = format_fingerprint(std::string(h.begin(), h.end()));
    SYSTEMTIME st{};
    FileTimeToSystemTime(&c->pCertInfo->NotAfter, &st);
    char buf[16];
    std::snprintf(buf, sizeof buf, "%04u-%02u-%02u", st.wYear, st.wMonth, st.wDay);
    out.not_after = buf;
    out.machine = machine;
    return out;
}

// Prvi valjani certifikat s tim imenom i dostupnim privatnim ključem (vlasnik zatvara kontekst)
PCCERT_CONTEXT find(HCERTSTORE store, const std::wstring& name, bool need_key) {
    PCCERT_CONTEXT c = nullptr;
    while ((c = CertEnumCertificatesInStore(store, c)) != nullptr) {
        if (friendly_name(c) == name && (!need_key || usable(c))) return CertDuplicateCertificateContext(c);
    }
    return nullptr;
}

PCCERT_CONTEXT create(bool machine, const std::wstring& name) {
    NCRYPT_PROV_HANDLE prov = 0;
    if (NCryptOpenStorageProvider(&prov, MS_KEY_STORAGE_PROVIDER, 0) != ERROR_SUCCESS) return nullptr;
    const std::wstring container = L"Solari-" + widen(to_hex(random_bytes(8)));
    NCRYPT_KEY_HANDLE key = 0;
    PCCERT_CONTEXT stored = nullptr;
    if (NCryptCreatePersistedKey(prov, &key, BCRYPT_RSA_ALGORITHM, container.c_str(), AT_KEYEXCHANGE,
                                 machine ? NCRYPT_MACHINE_KEY_FLAG : 0) == ERROR_SUCCESS) {
        DWORD bits = kRsaBits, export_policy = 0;  // ključ se ne može izvesti
        NCryptSetProperty(key, NCRYPT_LENGTH_PROPERTY, reinterpret_cast<PBYTE>(&bits), sizeof bits, 0);
        NCryptSetProperty(key, NCRYPT_EXPORT_POLICY_PROPERTY, reinterpret_cast<PBYTE>(&export_policy), sizeof export_policy, 0);
        if (NCryptFinalizeKey(key, 0) == ERROR_SUCCESS) {
            // subjekt CN=Solarni posluzitelj; samo za provjeru poslužitelja (EKU serverAuth)
            BYTE subject[256];
            DWORD subject_size = sizeof subject;
            CertStrToNameW(X509_ASN_ENCODING, L"CN=Solarni posluzitelj, O=Solari", CERT_X500_NAME_STR, nullptr, subject, &subject_size, nullptr);
            CERT_NAME_BLOB name_blob{subject_size, subject};
            CRYPT_KEY_PROV_INFO info{};
            info.pwszContainerName = const_cast<wchar_t*>(container.c_str());
            info.pwszProvName = const_cast<wchar_t*>(MS_KEY_STORAGE_PROVIDER);
            info.dwFlags = machine ? NCRYPT_MACHINE_KEY_FLAG : 0;
            info.dwKeySpec = AT_KEYEXCHANGE;
            CRYPT_ALGORITHM_IDENTIFIER alg{const_cast<char*>(szOID_RSA_SHA256RSA), {}};
            LPSTR usages[] = {const_cast<char*>(szOID_PKIX_KP_SERVER_AUTH)};
            CERT_ENHKEY_USAGE eku{1, usages};
            BYTE eku_der[64];
            DWORD eku_size = sizeof eku_der;
            CryptEncodeObject(X509_ASN_ENCODING, X509_ENHANCED_KEY_USAGE, &eku, eku_der, &eku_size);
            CERT_EXTENSION ext{const_cast<char*>(szOID_ENHANCED_KEY_USAGE), FALSE, {eku_size, eku_der}};
            CERT_EXTENSIONS exts{1, &ext};
            SYSTEMTIME start{}, end{};
            GetSystemTime(&start);
            end = start;
            end.wYear = static_cast<WORD>(end.wYear + kValidYears);
            if (end.wMonth == 2 && end.wDay == 29) end.wDay = 28;
            PCCERT_CONTEXT cert = CertCreateSelfSignCertificate(key, &name_blob, 0, &info, &alg, &start, &end, &exts);
            if (cert) {
                Store store(machine, true);
                CRYPT_DATA_BLOB fn{static_cast<DWORD>((name.size() + 1) * sizeof(wchar_t)), reinterpret_cast<BYTE*>(const_cast<wchar_t*>(name.c_str()))};
                CertSetCertificateContextProperty(cert, CERT_FRIENDLY_NAME_PROP_ID, 0, &fn);
                if (store.h) CertAddCertificateContextToStore(store.h, cert, CERT_STORE_ADD_REPLACE_EXISTING, &stored);
                CertFreeCertificateContext(cert);
            }
        }
        if (!stored) NCryptDeleteKey(key, 0); else NCryptFreeObject(key);
    }
    NCryptFreeObject(prov);
    return stored;
}

// Certifikat s ključem: računalo (servis, administrator) pa korisnik; need_key=false samo za prikaz otiska
PCCERT_CONTEXT locate(const std::wstring& name, bool need_key, bool* machine) {
    for (bool m : {true, false}) {
        Store store(m, false);
        if (!store.h) continue;
        if (PCCERT_CONTEXT c = find(store.h, name, need_key)) {
            *machine = m;
            return c;
        }
    }
    return nullptr;
}

PCCERT_CONTEXT locate_or_create(const std::wstring& name, bool* machine) {
    if (PCCERT_CONTEXT c = locate(name, true, machine)) return c;
    for (bool m : {true, false}) {  // bez administratorskih prava izrada u LocalMachine ne uspije
        if (PCCERT_CONTEXT c = create(m, name)) {
            *machine = m;
            log_info(std::string("HTTPS: izrađen certifikat poslužitelja (") + (m ? "računalo" : "korisnik") + ")");
            return c;
        }
    }
    throw std::runtime_error("certifikat poslužitelja nije izrađen");
}

}  // namespace

std::string format_fingerprint(const std::string& raw) {
    static constexpr char kHex[] = "0123456789ABCDEF";
    std::string out;
    for (size_t i = 0; i < raw.size(); ++i) {
        if (i) out += ':';
        const auto b = static_cast<uint8_t>(raw[i]);
        out += kHex[b >> 4];
        out += kHex[b & 15];
    }
    return out;
}

std::string pairing_code(const std::string& fingerprint) {
    Bytes raw;
    for (size_t i = 0; i + 1 < fingerprint.size(); i += 3) {
        const auto hex = [](char c) { return c >= '0' && c <= '9' ? c - '0' : c >= 'A' && c <= 'F' ? c - 'A' + 10 : c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1; };
        const int hi = hex(fingerprint[i]), lo = hex(fingerprint[i + 1]);
        if (hi < 0 || lo < 0 || (i + 2 < fingerprint.size() && fingerprint[i + 2] != ':')) return {};
        raw.push_back(static_cast<uint8_t>(hi * 16 + lo));
    }
    if (raw.size() != 32) return {};
    // 5.0.2 (audit G-07/A-05): 100 bita otiska (20 znakova base32) umjesto 60 – druga predslika više nije izvediva
    const std::string b32 = base32(Bytes(raw.begin(), raw.begin() + 13)).substr(0, 20);
    return b32.substr(0, 5) + "-" + b32.substr(5, 5) + "-" + b32.substr(10, 5) + "-" + b32.substr(15, 5);
}

bool pairing_code_matches(const std::string& entered, const std::string& fingerprint) {
    std::string a, b;
    for (char c : entered) if (c != '-' && c != ' ') a += static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    for (char c : pairing_code(fingerprint)) if (c != '-') b += c;
    return !b.empty() && equal_ct(Bytes(a.begin(), a.end()), Bytes(b.begin(), b.end()));
}

ServerCert ensure_server_certificate(const std::wstring& name) {
    bool machine = false;
    PCCERT_CONTEXT c = locate_or_create(name, &machine);
    ServerCert out = describe(c, machine);
    CertFreeCertificateContext(c);
    return out;
}

std::optional<ServerCert> find_server_certificate(const std::wstring& name) {
    bool machine = false;
    PCCERT_CONTEXT c = locate(name, false, &machine);
    if (!c) return std::nullopt;
    ServerCert out = describe(c, machine);
    CertFreeCertificateContext(c);
    return out;
}

void remove_server_certificate(const std::wstring& name) {
    for (bool m : {true, false}) {
        Store store(m, true);
        if (!store.h) continue;
        while (PCCERT_CONTEXT c = find(store.h, name, false)) {
            NCRYPT_KEY_HANDLE key = 0;
            DWORD spec = 0;
            BOOL free_key = FALSE;
            if (CryptAcquireCertificatePrivateKey(c, CRYPT_ACQUIRE_SILENT_FLAG | CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG, nullptr, &key, &spec, &free_key)) {
                NCryptDeleteKey(key, 0);  // oslobađa ručku
            }
            CertDeleteCertificateFromStore(c);  // oslobađa kontekst
        }
    }
}

// ---------------------------------------------------------------- vjerodajnice
TlsCredentials::TlsCredentials(const std::wstring& name) : cred_(new uint8_t[sizeof(CredHandle)]()) {
    bool machine = false;
    PCCERT_CONTEXT cert = locate_or_create(name, &machine);
    cert_ = describe(cert, machine);
    TLS_PARAMETERS params{};
    params.grbitDisabledProtocols = static_cast<DWORD>(~(SP_PROT_TLS1_2_SERVER | SP_PROT_TLS1_3_SERVER));  // samo TLS 1.2 i 1.3
    SCH_CREDENTIALS sc{};
    sc.dwVersion = SCH_CREDENTIALS_VERSION;
    sc.cCreds = 1;
    sc.paCred = &cert;
    sc.cTlsParameters = 1;
    sc.pTlsParameters = &params;
    sc.dwFlags = SCH_USE_STRONG_CRYPTO;
    TimeStamp expiry{};
    const SECURITY_STATUS s = AcquireCredentialsHandleW(nullptr, const_cast<wchar_t*>(UNISP_NAME_W), SECPKG_CRED_INBOUND, nullptr, &sc,
                                                        nullptr, nullptr, reinterpret_cast<CredHandle*>(cred_.get()), &expiry);
    CertFreeCertificateContext(cert);
    if (s != SEC_E_OK) throw std::runtime_error("SChannel: vjerodajnice (" + std::to_string(static_cast<long>(s)) + ")");
}

TlsCredentials::~TlsCredentials() { FreeCredentialsHandle(reinterpret_cast<CredHandle*>(cred_.get())); }

// ---------------------------------------------------------------- veza
struct TlsConnection::Impl {
    SOCKET s = INVALID_SOCKET;
    CredHandle* cred = nullptr;
    CtxtHandle ctx{};
    bool have_ctx = false;
    SecPkgContext_StreamSizes sizes{};
    std::string enc;    // primljeno, još nedešifrirano
    std::string plain;  // dešifrirano, još nepročitano

    bool send_raw(const char* p, size_t n) {
        while (n) {
            const int k = ::send(s, p, static_cast<int>(n), 0);
            if (k <= 0) return false;
            p += k;
            n -= static_cast<size_t>(k);
        }
        return true;
    }
    bool read_more() {
        char buf[16384];
        const int n = ::recv(s, buf, sizeof buf, 0);
        if (n <= 0) return false;
        enc.append(buf, static_cast<size_t>(n));
        return true;
    }
};

TlsConnection::TlsConnection(uintptr_t socket, const TlsCredentials& creds) : impl_(std::make_unique<Impl>()) {
    impl_->s = static_cast<SOCKET>(socket);
    impl_->cred = static_cast<CredHandle*>(creds.handle());
}

TlsConnection::~TlsConnection() {
    if (impl_->have_ctx) DeleteSecurityContext(&impl_->ctx);
}

bool TlsConnection::handshake() {
    Impl& d = *impl_;
    const ULONG req = ASC_REQ_SEQUENCE_DETECT | ASC_REQ_REPLAY_DETECT | ASC_REQ_CONFIDENTIALITY | ASC_REQ_STREAM | ASC_REQ_ALLOCATE_MEMORY;
    for (;;) {
        if (d.enc.empty() && !d.read_more()) return false;
        SecBuffer in[2] = {{static_cast<ULONG>(d.enc.size()), SECBUFFER_TOKEN, d.enc.data()}, {0, SECBUFFER_EMPTY, nullptr}};
        SecBufferDesc in_desc{SECBUFFER_VERSION, 2, in};
        SecBuffer out[1] = {{0, SECBUFFER_TOKEN, nullptr}};
        SecBufferDesc out_desc{SECBUFFER_VERSION, 1, out};
        ULONG attrs = 0;
        TimeStamp ts{};
        const SECURITY_STATUS st = AcceptSecurityContext(d.cred, d.have_ctx ? &d.ctx : nullptr, &in_desc, req, 0, &d.ctx, &out_desc, &attrs, &ts);
        if (st == SEC_E_INCOMPLETE_MESSAGE) {
            if (d.enc.size() > kMaxHandshakeBytes || !d.read_more()) return false;
            continue;
        }
        d.have_ctx = d.have_ctx || st == SEC_E_OK || st == SEC_I_CONTINUE_NEEDED;
        if (out[0].cbBuffer && out[0].pvBuffer) {
            const bool sent = d.send_raw(static_cast<const char*>(out[0].pvBuffer), out[0].cbBuffer);
            FreeContextBuffer(out[0].pvBuffer);
            if (!sent) return false;
        }
        if (st != SEC_E_OK && st != SEC_I_CONTINUE_NEEDED) return false;
        // neiskorišteni bajtovi (sljedeća poruka) ostaju za idući krug ili za podatke
        d.enc = in[1].BufferType == SECBUFFER_EXTRA ? d.enc.substr(d.enc.size() - in[1].cbBuffer) : std::string{};
        if (st == SEC_E_OK) {
            return QueryContextAttributesW(&d.ctx, SECPKG_ATTR_STREAM_SIZES, &d.sizes) == SEC_E_OK;
        }
    }
}

int TlsConnection::recv(char* out, int size) {
    Impl& d = *impl_;
    while (d.plain.empty()) {
        if (d.enc.empty() && !d.read_more()) return 0;
        SecBuffer b[4] = {{static_cast<ULONG>(d.enc.size()), SECBUFFER_DATA, d.enc.data()}, {0, SECBUFFER_EMPTY, nullptr},
                          {0, SECBUFFER_EMPTY, nullptr}, {0, SECBUFFER_EMPTY, nullptr}};
        SecBufferDesc desc{SECBUFFER_VERSION, 4, b};
        const SECURITY_STATUS st = DecryptMessage(&d.ctx, &desc, 0, nullptr);
        if (st == SEC_E_INCOMPLETE_MESSAGE) {
            if (!d.read_more()) return -1;
            continue;
        }
        if (st == SEC_I_CONTEXT_EXPIRED) return 0;  // close_notify
        if (st != SEC_E_OK && st != SEC_I_RENEGOTIATE) return -1;
        std::string extra;
        for (const auto& x : b) {
            if (x.BufferType == SECBUFFER_DATA) d.plain.append(static_cast<const char*>(x.pvBuffer), x.cbBuffer);
            if (x.BufferType == SECBUFFER_EXTRA) extra.assign(d.enc.data() + d.enc.size() - x.cbBuffer, x.cbBuffer);
        }
        d.enc = std::move(extra);
        if (st == SEC_I_RENEGOTIATE) return -1;  // TLS 1.3 poruke nakon rukovanja poslužitelj ne očekuje
    }
    const int n = std::min<int>(size, static_cast<int>(d.plain.size()));
    std::memcpy(out, d.plain.data(), static_cast<size_t>(n));
    d.plain.erase(0, static_cast<size_t>(n));
    return n;
}

bool TlsConnection::send(const std::string& data) {
    Impl& d = *impl_;
    size_t pos = 0;
    std::vector<char> buf(d.sizes.cbHeader + d.sizes.cbMaximumMessage + d.sizes.cbTrailer);
    while (pos < data.size()) {
        const size_t n = std::min<size_t>(data.size() - pos, d.sizes.cbMaximumMessage);
        std::memcpy(buf.data() + d.sizes.cbHeader, data.data() + pos, n);
        SecBuffer b[4] = {{d.sizes.cbHeader, SECBUFFER_STREAM_HEADER, buf.data()},
                          {static_cast<ULONG>(n), SECBUFFER_DATA, buf.data() + d.sizes.cbHeader},
                          {d.sizes.cbTrailer, SECBUFFER_STREAM_TRAILER, buf.data() + d.sizes.cbHeader + n},
                          {0, SECBUFFER_EMPTY, nullptr}};
        SecBufferDesc desc{SECBUFFER_VERSION, 4, b};
        if (EncryptMessage(&d.ctx, 0, &desc, 0) != SEC_E_OK) return false;
        if (!d.send_raw(buf.data(), b[0].cbBuffer + b[1].cbBuffer + b[2].cbBuffer)) return false;
        pos += n;
    }
    return true;
}

void TlsConnection::shutdown() {
    Impl& d = *impl_;
    if (!d.have_ctx) return;
    DWORD type = SCHANNEL_SHUTDOWN;
    SecBuffer in{sizeof type, SECBUFFER_TOKEN, &type};
    SecBufferDesc in_desc{SECBUFFER_VERSION, 1, &in};
    if (ApplyControlToken(&d.ctx, &in_desc) != SEC_E_OK) return;
    SecBuffer out{0, SECBUFFER_TOKEN, nullptr};
    SecBufferDesc out_desc{SECBUFFER_VERSION, 1, &out};
    ULONG attrs = 0;
    TimeStamp ts{};
    AcceptSecurityContext(d.cred, &d.ctx, nullptr, ASC_REQ_ALLOCATE_MEMORY | ASC_REQ_STREAM, 0, nullptr, &out_desc, &attrs, &ts);
    if (out.pvBuffer) {
        d.send_raw(static_cast<const char*>(out.pvBuffer), out.cbBuffer);
        FreeContextBuffer(out.pvBuffer);
    }
}

}  // namespace sm

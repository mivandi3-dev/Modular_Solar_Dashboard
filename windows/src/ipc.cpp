#include <windows.h>
#include <aclapi.h>
#include <bcrypt.h>
#include <sddl.h>

#include <chrono>
#include <stdexcept>

#include "crypto.hpp"
#include "ipc.hpp"
#include "util.hpp"

namespace sm::ipc {

namespace {

constexpr size_t kMaxDepth = 32;  // dublje ugniježđen JSON se odbija (rekurzivni dump/usporedbe)
constexpr DWORD kPipeBuffer = 64 * 1024;

struct Handle {
    HANDLE h = nullptr;
    Handle() = default;
    explicit Handle(HANDLE v) : h(v) {}
    ~Handle() { reset(); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    void reset(HANDLE v = nullptr) {
        if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h);
        h = v;
    }
    bool valid() const { return h && h != INVALID_HANDLE_VALUE; }
};

std::optional<std::wstring> sid_string(PSID sid) {
    if (!sid || !IsValidSid(sid)) return std::nullopt;
    LPWSTR text = nullptr;
    if (!ConvertSidToStringSidW(sid, &text)) return std::nullopt;
    std::wstring out(text);
    LocalFree(text);
    return out;
}

// JSON dubine > kMaxDepth se odbija prije raščlambe (zagrade izvan nizova znakova)
bool depth_ok(std::string_view text) {
    size_t depth = 0;
    bool in_string = false, escape = false;
    for (const char c : text) {
        if (in_string) {
            if (escape) escape = false;
            else if (c == '\\') escape = true;
            else if (c == '"') in_string = false;
            continue;
        }
        if (c == '"') in_string = true;
        else if (c == '[' || c == '{') {
            if (++depth > kMaxDepth) return false;
        } else if ((c == ']' || c == '}') && depth) --depth;
    }
    return true;
}

uint32_t read_le32(std::string_view b) {
    return static_cast<uint32_t>(static_cast<uint8_t>(b[0])) | static_cast<uint32_t>(static_cast<uint8_t>(b[1])) << 8 |
           static_cast<uint32_t>(static_cast<uint8_t>(b[2])) << 16 | static_cast<uint32_t>(static_cast<uint8_t>(b[3])) << 24;
}

using SteadyClock = std::chrono::steady_clock;

DWORD remaining_ms(SteadyClock::time_point deadline) {
    const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - SteadyClock::now()).count();
    return left <= 0 ? 0 : static_cast<DWORD>(left);
}

// Čitanje ili upis točno n bajtova (overlapped) do roka; stop (može biti nullptr) prekida čekanje.
bool transfer(HANDLE pipe, HANDLE event, HANDLE stop, bool write, char* buf, DWORD n, std::optional<SteadyClock::time_point> deadline) {
    DWORD total = 0;
    while (total < n) {
        OVERLAPPED ov{};
        ov.hEvent = event;
        ResetEvent(event);
        const BOOL ok = write ? WriteFile(pipe, buf + total, n - total, nullptr, &ov) : ReadFile(pipe, buf + total, n - total, nullptr, &ov);
        if (!ok && GetLastError() != ERROR_IO_PENDING) return false;
        HANDLE waits[2] = {event, stop};
        const DWORD wait = WaitForMultipleObjects(stop ? 2 : 1, waits, FALSE, deadline ? remaining_ms(*deadline) : INFINITE);
        DWORD got = 0;
        if (wait != WAIT_OBJECT_0) {
            CancelIoEx(pipe, &ov);
            GetOverlappedResult(pipe, &ov, &got, TRUE);
            return false;
        }
        if (!GetOverlappedResult(pipe, &ov, &got, FALSE) || got == 0) return false;
        total += got;
    }
    return true;
}

bool write_frame(HANDLE pipe, HANDLE event, HANDLE stop, const json& message, SteadyClock::time_point deadline) {
    std::string frame = encode_frame(message);
    return transfer(pipe, event, stop, true, frame.data(), static_cast<DWORD>(frame.size()), deadline);
}

// Okvir: zaglavlje čeka do idle (nullopt = bez roka), tijelo do io roka od početka okvira.
std::optional<json> read_frame(HANDLE pipe, HANDLE event, HANDLE stop, size_t max_bytes,
                               std::optional<SteadyClock::time_point> idle_deadline, std::chrono::milliseconds io_timeout,
                               DecodeStatus* status = nullptr) {
    std::string buf(4, '\0');
    if (!transfer(pipe, event, stop, false, buf.data(), 4, idle_deadline)) return std::nullopt;
    const uint32_t n = read_le32(buf);
    if (n > max_bytes) {
        if (status) *status = DecodeStatus::TooLarge;
        return std::nullopt;
    }
    buf.resize(4 + static_cast<size_t>(n));
    if (n && !transfer(pipe, event, stop, false, buf.data() + 4, n, SteadyClock::now() + io_timeout)) return std::nullopt;
    Decoded d = decode_frame(buf, max_bytes);
    if (status) *status = d.status;
    if (d.status != DecodeStatus::Ok) return std::nullopt;
    return std::move(d.message);
}

}  // namespace

// ---------------------------------------------------------------- okvir
std::string encode_frame(const json& message) {
    const std::string body = message.dump(-1, ' ', false, json::error_handler_t::replace);
    if (body.size() > kMaxResponseBytes) throw std::length_error("IPC: poruka je prevelika");
    const auto n = static_cast<uint32_t>(body.size());
    std::string out;
    out.reserve(4 + body.size());
    out.push_back(static_cast<char>(n & 0xFF));
    out.push_back(static_cast<char>((n >> 8) & 0xFF));
    out.push_back(static_cast<char>((n >> 16) & 0xFF));
    out.push_back(static_cast<char>((n >> 24) & 0xFF));
    out += body;
    return out;
}

Decoded decode_frame(std::string_view buffer, size_t max_bytes) {
    Decoded d;
    if (buffer.size() < 4) return d;
    const uint32_t n = read_le32(buffer);
    if (n > max_bytes) {
        d.status = DecodeStatus::TooLarge;
        return d;
    }
    if (buffer.size() - 4 < n) return d;
    const std::string_view body = buffer.substr(4, n);
    if (!depth_ok(body)) {
        d.status = DecodeStatus::BadJson;
        return d;
    }
    json j = json::parse(body, nullptr, false);
    if (j.is_discarded()) {
        d.status = DecodeStatus::BadJson;
        return d;
    }
    if (!j.is_object()) {
        d.status = DecodeStatus::NotObject;
        return d;
    }
    d.status = DecodeStatus::Ok;
    d.message = std::move(j);
    d.consumed = 4 + static_cast<size_t>(n);
    return d;
}

// ---------------------------------------------------------------- SID-ovi
std::wstring service_sid(std::wstring_view service_name) {
    // Kao `sc showsid`: S-1-5-80 + SHA-1(UTF-16LE velikim slovima) u 5 riječi (little-endian)
    std::wstring upper(service_name);
    if (!upper.empty()) CharUpperBuffW(upper.data(), static_cast<DWORD>(upper.size()));
    BCRYPT_ALG_HANDLE alg = nullptr;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA1_ALGORITHM, nullptr, 0) != 0) throw std::runtime_error("SHA-1 nije dostupan");
    uint8_t digest[20]{};
    const NTSTATUS st = BCryptHash(alg, nullptr, 0, reinterpret_cast<PUCHAR>(upper.data()), static_cast<ULONG>(upper.size() * sizeof(wchar_t)),
                                   digest, sizeof digest);
    BCryptCloseAlgorithmProvider(alg, 0);
    if (st != 0) throw std::runtime_error("SHA-1 nije uspio");
    std::wstring out = L"S-1-5-80";
    for (int i = 0; i < 5; ++i) {
        const uint32_t v = static_cast<uint32_t>(digest[i * 4]) | static_cast<uint32_t>(digest[i * 4 + 1]) << 8 |
                           static_cast<uint32_t>(digest[i * 4 + 2]) << 16 | static_cast<uint32_t>(digest[i * 4 + 3]) << 24;
        out += L"-" + std::to_wstring(v);
    }
    return out;
}

namespace {
std::optional<std::wstring> token_user_sid(HANDLE token) {
    DWORD size = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &size);
    if (!size) return std::nullopt;
    std::vector<uint8_t> buf(size);
    if (!GetTokenInformation(token, TokenUser, buf.data(), size, &size)) return std::nullopt;
    return sid_string(reinterpret_cast<TOKEN_USER*>(buf.data())->User.Sid);
}
}  // namespace

std::wstring current_user_sid() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) throw std::runtime_error("Oznaka procesa nije dostupna");
    Handle guard(token);
    auto sid = token_user_sid(token);
    if (!sid) throw std::runtime_error("SID korisnika nije dostupan");
    return *sid;
}

std::optional<std::wstring> process_user_sid(uint32_t pid) {
    Handle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
    if (!process.valid()) return std::nullopt;
    HANDLE token = nullptr;
    if (!OpenProcessToken(process.h, TOKEN_QUERY, &token)) return std::nullopt;
    Handle guard(token);
    return token_user_sid(token);
}

std::optional<std::wstring> handle_owner_sid(void* handle) {
    PSID owner = nullptr;
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (GetSecurityInfo(static_cast<HANDLE>(handle), SE_KERNEL_OBJECT, OWNER_SECURITY_INFORMATION, &owner, nullptr, nullptr, nullptr, &sd) !=
        ERROR_SUCCESS) {
        return std::nullopt;
    }
    auto out = sid_string(owner);
    LocalFree(sd);
    return out;
}

// ---------------------------------------------------------------- poslužitelj
PipeServer::PipeServer(PipeServerConfig config, Handler handler) : config_(std::move(config)), handler_(std::move(handler)) {}

PipeServer::~PipeServer() { stop(); }

void* PipeServer::create_instance(bool first) {
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(config_.sddl.c_str(), SDDL_REVISION_1, &sd, nullptr)) {
        throw std::runtime_error("IPC: neispravan sigurnosni opisnik kanala");
    }
    SECURITY_ATTRIBUTES sa{sizeof sa, sd, FALSE};
    const DWORD open = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | (first ? FILE_FLAG_FIRST_PIPE_INSTANCE : 0);
    const DWORD mode = PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS;
    HANDLE pipe = CreateNamedPipeW(config_.name.c_str(), open, mode, static_cast<DWORD>(config_.instances), kPipeBuffer, kPipeBuffer, 0, &sa);
    const DWORD err = GetLastError();
    LocalFree(sd);
    if (pipe == INVALID_HANDLE_VALUE) {
        throw std::runtime_error(err == ERROR_ACCESS_DENIED || err == ERROR_PIPE_BUSY
                                     ? "IPC: kanal " + narrow(config_.name) + " već postoji (drugi proces drži ime) – poslužitelj se ne pokreće"
                                     : "IPC: kanal " + narrow(config_.name) + " se ne može stvoriti (greška " + std::to_string(err) + ")");
    }
    return pipe;
}

void PipeServer::start() {
    if (running_) return;
    if (config_.instances < 1) config_.instances = 1;
    stop_event_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    std::vector<HANDLE> pipes;
    try {
        for (int i = 0; i < config_.instances; ++i) pipes.push_back(static_cast<HANDLE>(create_instance(i == 0)));
    } catch (...) {
        for (HANDLE p : pipes) CloseHandle(p);
        CloseHandle(static_cast<HANDLE>(stop_event_));
        stop_event_ = nullptr;
        throw;
    }
    running_ = true;
    for (HANDLE p : pipes) threads_.emplace_back([this, p] { instance_loop(p); });
}

void PipeServer::stop() {
    if (!running_) return;
    running_ = false;
    SetEvent(static_cast<HANDLE>(stop_event_));
    for (auto& t : threads_) {
        if (t.joinable()) t.join();
    }
    threads_.clear();
    CloseHandle(static_cast<HANDLE>(stop_event_));
    stop_event_ = nullptr;
}

void PipeServer::instance_loop(void* pipe_ptr) {
    const HANDLE pipe = static_cast<HANDLE>(pipe_ptr);
    Handle event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    const HANDLE stop = static_cast<HANDLE>(stop_event_);
    while (running_) {
        OVERLAPPED ov{};
        ov.hEvent = event.h;
        ResetEvent(event.h);
        bool connected = false;
        if (ConnectNamedPipe(pipe, &ov)) {
            connected = true;
        } else {
            const DWORD err = GetLastError();
            if (err == ERROR_PIPE_CONNECTED) {
                connected = true;
            } else if (err == ERROR_IO_PENDING) {
                HANDLE waits[2] = {event.h, stop};
                const DWORD w = WaitForMultipleObjects(2, waits, FALSE, INFINITE);
                DWORD ignored = 0;
                if (w != WAIT_OBJECT_0) {
                    CancelIoEx(pipe, &ov);
                    GetOverlappedResult(pipe, &ov, &ignored, TRUE);
                    break;
                }
                connected = GetOverlappedResult(pipe, &ov, &ignored, FALSE) != FALSE;
            } else {
                Sleep(100);  // npr. klijent se odspojio prije prihvaćanja
            }
        }
        if (connected && running_) {
            try {
                serve(pipe, event.h);
            } catch (const std::exception& e) {
                log_error(std::string("IPC: ") + e.what());
            }
            // DisconnectNamedPipe odbacuje nepročitane podatke: pričekaj da klijent pročita odgovor i zatvori vezu
            // (ograničeno – klijent koji ne zatvara ne drži instancu dulje od io roka; ne FlushFileBuffers bez roka)
            char drain = 0;
            transfer(pipe, event.h, stop, false, &drain, 1, SteadyClock::now() + std::chrono::milliseconds(config_.io_timeout_ms));
        }
        DisconnectNamedPipe(pipe);
    }
    CloseHandle(pipe);
}

void PipeServer::serve(void* pipe_ptr, void* event_ptr) {
    const HANDLE pipe = static_cast<HANDLE>(pipe_ptr);
    const HANDLE event = static_cast<HANDLE>(event_ptr);
    const HANDLE stop = static_cast<HANDLE>(stop_event_);
    Caller caller;
    ULONG pid = 0;
    if (!GetNamedPipeClientProcessId(pipe, &pid)) {
        ++rejected_;
        return;
    }
    caller.pid = pid;
    const auto sid = process_user_sid(pid);
    if (!sid) {
        ++rejected_;
        log_warn("IPC " + narrow(config_.name) + ": identitet klijenta (PID " + std::to_string(pid) + ") nije provjeren – veza odbijena");
        return;
    }
    caller.sid = *sid;
    if (config_.authorize && !config_.authorize(caller)) {
        ++rejected_;
        log_warn("IPC " + narrow(config_.name) + ": klijent " + narrow(caller.sid) + " (PID " + std::to_string(pid) + ") nije dopušten");
        return;
    }
    const std::string nonce = to_hex(random_bytes(32));
    const auto io = std::chrono::milliseconds(config_.io_timeout_ms);
    if (!write_frame(pipe, event, stop, json{{"v", kProtocolVersion}, {"type", "hello"}, {"nonce", nonce}}, SteadyClock::now() + io)) return;
    for (int served = 0; running_ && (config_.requests_per_connection == 0 || served < config_.requests_per_connection); ++served) {
        std::optional<SteadyClock::time_point> idle;
        if (config_.idle_timeout_ms) idle = SteadyClock::now() + std::chrono::milliseconds(config_.idle_timeout_ms);
        DecodeStatus status = DecodeStatus::NeedMore;
        const auto request = read_frame(pipe, event, stop, config_.max_request_bytes, idle, io, &status);
        if (!request) {
            if (status != DecodeStatus::NeedMore) {
                ++rejected_;
                log_warn("IPC " + narrow(config_.name) + ": neispravan okvir – veza prekinuta");
            }
            return;
        }
        const auto v = request->find("v");
        const auto n = request->find("nonce");
        if (v == request->end() || *v != kProtocolVersion || n == request->end() || !n->is_string() || n->get<std::string>() != nonce) {
            ++rejected_;
            log_warn("IPC " + narrow(config_.name) + ": nepoznata verzija ili pogrešan izazov – veza prekinuta");
            return;
        }
        json response;
        try {
            response = handler_(*request, caller);
        } catch (const std::exception& e) {
            log_error("IPC " + narrow(config_.name) + ": " + e.what());
            response = json{{"ok", false}, {"error", "internal"}};
        }
        response["v"] = kProtocolVersion;
        if (const auto id = request->find("id"); id != request->end() && id->is_number_integer()) response["id"] = *id;
        if (!write_frame(pipe, event, stop, response, SteadyClock::now() + io)) return;
    }
}

// ---------------------------------------------------------------- klijent
json pipe_call(const std::wstring& name, json request, const std::wstring& expected_owner_sid, uint32_t timeout_ms, size_t max_response_bytes) {
    const auto deadline = SteadyClock::now() + std::chrono::milliseconds(timeout_ms);
    Handle pipe;
    for (;;) {
        // bez GENERIC_WRITE (FILE_APPEND_DATA = stvaranje instance kanala); poslužitelj ne smije oponašati klijenta
        pipe.reset(CreateFileW(name.c_str(), GENERIC_READ | FILE_WRITE_DATA, 0, nullptr, OPEN_EXISTING,
                               FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, nullptr));
        if (pipe.valid()) break;
        const DWORD err = GetLastError();
        if (err != ERROR_PIPE_BUSY) {
            throw PipeError(err == ERROR_FILE_NOT_FOUND ? "kanal ne postoji (servis ne radi)"
                                                        : err == ERROR_ACCESS_DENIED ? "pristup kanalu nije dopušten"
                                                                                     : "kanal nije dostupan (greška " + std::to_string(err) + ")");
        }
        const DWORD left = remaining_ms(deadline);
        if (!left || !WaitNamedPipeW(name.c_str(), left)) throw PipeError("kanal je zauzet");
    }
    const auto owner = handle_owner_sid(pipe.h);
    if (!owner || *owner != expected_owner_sid) {
        throw PipeError("vlasnik kanala nije očekivani (" + (owner ? narrow(*owner) : std::string("nepoznat")) + ") – ništa nije poslano");
    }
    Handle event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    const auto hello = read_frame(pipe.h, event.h, nullptr, 4096, deadline, std::chrono::milliseconds(remaining_ms(deadline)));
    if (!hello || hello->value("type", "") != "hello" || !hello->contains("nonce") || !(*hello)["nonce"].is_string()) {
        throw PipeError("kanal nije odgovorio");
    }
    request["v"] = kProtocolVersion;
    request["nonce"] = (*hello)["nonce"];
    if (!write_frame(pipe.h, event.h, nullptr, request, deadline)) throw PipeError("zahtjev nije poslan");
    auto response = read_frame(pipe.h, event.h, nullptr, max_response_bytes, deadline, std::chrono::milliseconds(remaining_ms(deadline)));
    if (!response) throw PipeError("odgovor nije primljen");
    return std::move(*response);
}

bool pipe_exists(const std::wstring& name) {
    if (WaitNamedPipeW(name.c_str(), 1)) return true;
    return GetLastError() != ERROR_FILE_NOT_FOUND;
}

}  // namespace sm::ipc

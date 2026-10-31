#include "system.hpp"

#include <windows.h>
#include <shellapi.h>
#include <shobjidl.h>

#include <cstdio>
#include <exception>

#include "util.hpp"

namespace sm {

namespace {
constexpr wchar_t kRunKey[] = L"Software\\Microsoft\\Windows\\CurrentVersion\\Run";
constexpr wchar_t kRunValue[] = L"SolarniMonitor2";
constexpr wchar_t kPollerTask[] = L"Solarni monitor 2 - poller";  // registrira ga instalacija

// RAII za HANDLE
struct Handle {
    HANDLE h = nullptr;
    ~Handle() { if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h); }
};
}  // namespace

ProcessResult run_capture(const std::wstring& command_line, unsigned timeout_ms) {
    SECURITY_ATTRIBUTES sa{sizeof sa, nullptr, TRUE};
    Handle read_end, write_end;
    if (!CreatePipe(&read_end.h, &write_end.h, &sa, 0)) return {};
    SetHandleInformation(read_end.h, HANDLE_FLAG_INHERIT, 0);
    STARTUPINFOW si{};
    si.cb = sizeof si;
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = write_end.h;
    si.hStdError = write_end.h;
    PROCESS_INFORMATION pi{};
    std::wstring cmd = command_line;  // CreateProcessW smije mijenjati međuspremnik
    if (!CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        return {};
    }
    Handle process{pi.hProcess}, thread{pi.hThread};
    CloseHandle(write_end.h);
    write_end.h = nullptr;
    ProcessResult result;
    const ULONGLONG deadline = GetTickCount64() + timeout_ms;
    char buf[4096];
    for (;;) {
        DWORD avail = 0;
        if (PeekNamedPipe(read_end.h, nullptr, 0, nullptr, &avail, nullptr) && avail) {
            DWORD n = 0;
            if (ReadFile(read_end.h, buf, sizeof buf, &n, nullptr) && n) result.output.append(buf, n);
            continue;
        }
        if (WaitForSingleObject(process.h, 50) == WAIT_OBJECT_0) {
            DWORD n = 0;
            while (PeekNamedPipe(read_end.h, nullptr, 0, nullptr, &avail, nullptr) && avail &&
                   ReadFile(read_end.h, buf, sizeof buf, &n, nullptr) && n) {
                result.output.append(buf, n);
            }
            break;
        }
        if (GetTickCount64() > deadline) {
            TerminateProcess(process.h, 1);
            return result;
        }
    }
    DWORD code = 0;
    GetExitCodeProcess(process.h, &code);
    result.exit_code = static_cast<int>(code);
    return result;
}

NamedMutex::NamedMutex(const std::wstring& name) {
    SetLastError(0);
    handle_ = CreateMutexW(nullptr, FALSE, name.c_str());
    const DWORD err = GetLastError();
    // ERROR_ACCESS_DENIED: mutex postoji, ali ga je stvorio drugi korisnik (npr. SYSTEM)
    owned_ = handle_ && err != ERROR_ALREADY_EXISTS && err != ERROR_ACCESS_DENIED;
}

NamedMutex::~NamedMutex() {
    if (handle_) CloseHandle(handle_);
}

bool autostart_enabled() {
    return RegGetValueW(HKEY_CURRENT_USER, kRunKey, kRunValue, RRF_RT_REG_SZ, nullptr, nullptr, nullptr) == ERROR_SUCCESS;
}

void set_autostart(bool enabled) {
    HKEY key = nullptr;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, kRunKey, 0, nullptr, 0, KEY_SET_VALUE, nullptr, &key, nullptr) != ERROR_SUCCESS) {
        throw std::runtime_error("Registar se ne može otvoriti");
    }
    if (enabled) {
        const std::wstring value = L"\"" + (exe_dir() / L"SolarniMonitor.exe").wstring() + L"\"";
        RegSetValueExW(key, kRunValue, 0, REG_SZ, reinterpret_cast<const BYTE*>(value.c_str()),
                       static_cast<DWORD>((value.size() + 1) * sizeof(wchar_t)));
    } else {
        RegDeleteValueW(key, kRunValue);
    }
    RegCloseKey(key);
}

bool poller_task_installed() {
    return run_capture(L"schtasks /Query /TN \"" + std::wstring(kPollerTask) + L"\"", 10'000).exit_code == 0;
}

namespace {
const char* g_crash_process = "proces";

LONG WINAPI log_crash(EXCEPTION_POINTERS* info) {
    const auto* rec = info ? info->ExceptionRecord : nullptr;
    HMODULE module = nullptr;
    const void* address = rec ? rec->ExceptionAddress : nullptr;
    GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                       static_cast<LPCWSTR>(address), &module);
    wchar_t name[MAX_PATH] = L"?";
    if (module) GetModuleFileNameW(module, name, MAX_PATH);
    char text[512];
    std::snprintf(text, sizeof text, "%s se srušio: iznimka 0x%08lX na %s+0x%llX", g_crash_process,
                  rec ? static_cast<unsigned long>(rec->ExceptionCode) : 0UL, narrow(fs::path(name).filename().wstring()).c_str(),
                  static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(address) - reinterpret_cast<uintptr_t>(module)));
    log_error(text);
    return EXCEPTION_CONTINUE_SEARCH;
}
}  // namespace

void install_crash_logging(const char* process_name) {
    g_crash_process = process_name;
    SetUnhandledExceptionFilter(log_crash);
    std::set_terminate([] {
        std::string why = "nepoznata iznimka";
        if (const auto e = std::current_exception()) {
            try {
                std::rethrow_exception(e);
            } catch (const std::exception& ex) {
                why = ex.what();
            } catch (...) {
            }
        }
        log_error(std::string(g_crash_process) + " se srušio (neuhvaćena iznimka): " + why);
        std::abort();
    });
}

std::wstring curl_command() {
    const fs::path bundled = exe_dir() / L"curl" / L"curl.exe";
    std::error_code ec;
    // Ugrađeni curl (LibreSSL) provjerava HTTPS certifikate iz spremišta Windowsa; curl iz Windowsa (Schannel) to radi sam.
    return fs::is_regular_file(bundled, ec) ? L"\"" + bundled.wstring() + L"\" --ca-native" : L"curl.exe";
}

void keep_awake(bool enabled, bool display_on) {
    EXECUTION_STATE flags = ES_CONTINUOUS;
    if (enabled) flags |= ES_SYSTEM_REQUIRED | (display_on ? ES_DISPLAY_REQUIRED : 0);
    SetThreadExecutionState(flags);
}

void monitor_power(bool on) {
    constexpr LPARAM kOff = 2, kOn = -1;
    // PostMessage (ne SendMessage): poruka ide svim prozorima i ne čeka one koji ne odgovaraju.
    PostMessageW(HWND_BROADCAST, WM_SYSCOMMAND, SC_MONITORPOWER, on ? kOn : kOff);
    if (on) {  // neki zasloni se bude tek na ulaz – pomak miša tamo i natrag
        mouse_event(MOUSEEVENTF_MOVE, 0, 1, 0, 0);
        mouse_event(MOUSEEVENTF_MOVE, 0, static_cast<DWORD>(-1), 0, 0);
    }
}

void open_path(const fs::path& path) {
    std::error_code ec;
    if (!path.has_extension()) fs::create_directories(path, ec);
    ShellExecuteW(nullptr, L"open", path.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
}

std::optional<fs::path> pick_file(void* owner, const std::wstring& title, const std::wstring& filter_name,
                                  const std::wstring& filter_spec) {
    IFileOpenDialog* dlg = nullptr;
    if (FAILED(CoCreateInstance(CLSID_FileOpenDialog, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&dlg)))) return std::nullopt;
    const COMDLG_FILTERSPEC filters[] = {{filter_name.c_str(), filter_spec.c_str()}, {L"Sve datoteke", L"*.*"}};
    dlg->SetFileTypes(2, filters);
    dlg->SetTitle(title.c_str());
    std::optional<fs::path> result;
    if (SUCCEEDED(dlg->Show(static_cast<HWND>(owner)))) {
        IShellItem* item = nullptr;
        if (SUCCEEDED(dlg->GetResult(&item))) {
            PWSTR path = nullptr;
            if (SUCCEEDED(item->GetDisplayName(SIGDN_FILESYSPATH, &path))) {
                result = fs::path(path);
                CoTaskMemFree(path);
            }
            item->Release();
        }
    }
    dlg->Release();
    return result;
}

std::optional<fs::path> pick_save_file(void* owner, const std::wstring& title, const std::wstring& filter_name,
                                       const std::wstring& filter_spec, const std::wstring& default_name) {
    IFileSaveDialog* dlg = nullptr;
    if (FAILED(CoCreateInstance(CLSID_FileSaveDialog, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&dlg)))) return std::nullopt;
    const COMDLG_FILTERSPEC filters[] = {{filter_name.c_str(), filter_spec.c_str()}};
    dlg->SetFileTypes(1, filters);
    dlg->SetTitle(title.c_str());
    dlg->SetFileName(default_name.c_str());
    dlg->SetDefaultExtension(fs::path(default_name).extension().wstring().substr(1).c_str());
    std::optional<fs::path> result;
    if (SUCCEEDED(dlg->Show(static_cast<HWND>(owner)))) {
        IShellItem* item = nullptr;
        if (SUCCEEDED(dlg->GetResult(&item))) {
            PWSTR path = nullptr;
            if (SUCCEEDED(item->GetDisplayName(SIGDN_FILESYSPATH, &path))) {
                result = fs::path(path);
                CoTaskMemFree(path);
            }
            item->Release();
        }
    }
    dlg->Release();
    return result;
}

void message_box(const std::wstring& text, bool error) {
    MessageBoxW(nullptr, text.c_str(), L"Solarni monitor", error ? MB_ICONERROR : MB_ICONINFORMATION);
}

std::vector<Screen> list_screens() {
    std::vector<Screen> out;
    EnumDisplayMonitors(nullptr, nullptr, [](HMONITOR mon, HDC, LPRECT, LPARAM data) -> BOOL {
        auto& list = *reinterpret_cast<std::vector<Screen>*>(data);
        MONITORINFO mi{sizeof mi};
        GetMonitorInfoW(mon, &mi);
        const RECT& r = mi.rcMonitor;
        list.push_back({static_cast<int>(list.size()), r.left, r.top, r.right - r.left, r.bottom - r.top,
                        (mi.dwFlags & MONITORINFOF_PRIMARY) != 0});
        return TRUE;
    }, reinterpret_cast<LPARAM>(&out));
    return out;
}

}  // namespace sm

// Solarni poslužitelj (C++) – računalo u lokalnoj mreži s loggerom; klijenti (Solarni monitor 2 na Windowsima,
// Android aplikacija) dobivaju podatke, naslov i slike preko API-ja (Cloudflare tunel ili lokalna mreža).
//   SolarniServer.exe            postavke: logger, elektrana, naslov, logotip i slike, API ključ, Cloudflare
//   SolarniServer.exe --service  bilježenje i API bez prozora (zadatak sustava iz instalacije)
// Podaci su u %ProgramData%\SolarniServer (ili SOLARI2_HOME) – odvojeno od klijenta na istom računalu.
#include <windows.h>
#include <objbase.h>
#include <shellapi.h>
#include <shobjidl.h>

#include <cstdlib>
#include <string>

#include "api.hpp"
#include "app.hpp"
#include "broker.hpp"
#include "i18n.hpp"
#include "poller.hpp"
#include "system.hpp"
#include "util.hpp"

namespace sm {
App& app() {
    static App instance;
    return instance;
}
}  // namespace sm

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR cmdline, int) {
    using namespace sm;
    if (const wchar_t* home = _wgetenv(L"SOLARI2_HOME"); !home || !*home) {
        const wchar_t* pd = _wgetenv(L"PROGRAMDATA");
        const std::wstring dir = (fs::path(pd ? pd : L"C:\\ProgramData") / L"SolarniServer").wstring();
        _wputenv_s(L"SOLARI2_HOME", dir.c_str());
    }
    set_poller_mutex(kServerPollerMutex);
    if (std::wstring(cmdline).find(L"--service") != std::wstring::npos) return run_server_service();
    // 4.0: administrator postavlja API ključ servisa Resend: --set-resend-key-file "<datoteka>" (datoteka se briše)
    if (std::wstring(cmdline).find(L"--set-resend-key-file") != std::wstring::npos) {
        int argc = 0;
        LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
        int code = 2;
        for (int i = 1; argv && i + 1 < argc; ++i) {
            if (std::wstring(argv[i]) == L"--set-resend-key-file") code = set_resend_key_from_file(argv[i + 1]);
        }
        if (argv) LocalFree(argv);
        return code;
    }


    NamedMutex single(L"Local\\SolarniServerApp");
    if (!single.owned()) {
        if (HWND existing = FindWindowW(L"SolarniMonitor2Window", nullptr)) {
            ShowWindow(existing, SW_RESTORE);
            SetForegroundWindow(existing);
        }
        return 0;
    }
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    SetCurrentProcessExplicitAppUserModelID(L"MarkoIvandic.SolarniServer");
    app().set_server_role(true);
    int code = 1;
    try {
        code = app().run();
    } catch (const std::exception& e) {
        log_error(std::string("Aplikacija se srušila: ") + e.what());
        message_box(widen(tr("Aplikacija se srušila: {error}", {{"error", e.what()}})), true);
    }
    CoUninitialize();
    return code;
}

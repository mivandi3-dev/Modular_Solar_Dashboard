// Solarni monitor 2 (C++) – ulazna točka.
//   SolarniMonitor.exe            aplikacija (dashboard, postavke, poller u pozadini)
//   SolarniMonitor.exe --poller   samo bilježenje podataka (zadatak sustava iz instalacije)
#include <windows.h>
#include <shellapi.h>
#include <objbase.h>
#include <shobjidl.h>

#include <string>

#include "app.hpp"
#include "i18n.hpp"
#include "broker.hpp"
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
#ifdef SOLARI_DEV_BUILD
    // samo razvojna gradnja: zaseban mutex pollera za e2e (instalirani zadatak sustava drži Global\SolarniMonitor2Poller)
    static std::wstring dev_mutex;
    if (const wchar_t* m = _wgetenv(L"SOLARI_DEV_POLLER_MUTEX"); m && *m) {
        dev_mutex = m;
        set_poller_mutex(dev_mutex.c_str());
    }
#endif
    if (std::wstring(cmdline).find(L"--poller") != std::wstring::npos) return run_poller_mode();
    // 4.0 (SMA-02): instalacija (administrator) postavlja PIN postavki: --set-pin-file "<datoteka>" (datoteka se briše)
    if (std::wstring(cmdline).find(L"--set-pin-file") != std::wstring::npos) {
        int argc = 0;
        LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
        int code = 2;
        for (int i = 1; argv && i + 1 < argc; ++i) {
            if (std::wstring(argv[i]) == L"--set-pin-file") code = set_pin_from_file(argv[i + 1]);
        }
        if (argv) LocalFree(argv);
        return code;
    }

    NamedMutex single(L"Local\\SolarniMonitor2App");
    if (!single.owned()) {
        // Već radi – prikaži postojeći prozor.
        if (HWND existing = FindWindowW(L"SolarniMonitor2Window", nullptr)) {
            ShowWindow(existing, SW_RESTORE);
            SetForegroundWindow(existing);
        }
        return 0;
    }
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    SetCurrentProcessExplicitAppUserModelID(L"MarkoIvandic.SolarniMonitor2");
    int code = 1;
    try {
        code = app().run();
    } catch (const std::exception& e) {
        log_error(std::string("Aplikacija se srušila: ") + e.what());
        message_box(widen(tr("Aplikacija se srušila: {error}", {{"error", e.what()}}) + "\n\n" + tr("Detalji") + ": ") +
                        (logs_dir() / L"app.log").wstring(), true);
    }
    CoUninitialize();
    return code;
}

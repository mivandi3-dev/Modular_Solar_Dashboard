// Solarni monitor 2 (C++) – ulazna točka.
//   SolarniMonitor.exe            aplikacija (dashboard, postavke, poller u pozadini)
//   SolarniMonitor.exe --poller   samo bilježenje podataka (zadatak sustava iz instalacije)
#include <windows.h>
#include <objbase.h>
#include <shobjidl.h>

#include <string>

#include "app.hpp"
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
    if (std::wstring(cmdline).find(L"--poller") != std::wstring::npos) return run_poller_mode();

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

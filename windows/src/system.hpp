// Integracija s Windowsima: procesi, pokretanje pri prijavi, mutex, zasloni, dijalozi, mirovanje.
#pragma once

#include <optional>
#include <string>
#include <vector>

#include "config.hpp"

namespace sm {

struct ProcessResult {
    int exit_code = -1;
    std::string output;
};
// curl.exe iz mape programa (instalacija ga donosi – Windows Server 2016 / Win10 prije 1803 ga nemaju),
// a ako ga nema, onaj iz Windowsa. Vraća naredbu u navodnicima, spremnu za naredbeni redak.
std::wstring curl_command();
// Puna putanja u mapi sustava (System32) – za pokretanje alata sustava bez redoslijeda traženja (audit C-16)
std::wstring system32_path(const std::wstring& relative);

// Neuhvaćena iznimka ili rušenje (npr. pristup memoriji) upiše se u otvoreni zapisnik prije izlaska –
// za procese bez prozora (poslužitelj, poller), da se uzrok vidi i kad nitko ne gleda.
void install_crash_logging(const char* process_name);

// Pokreni naredbu bez prozora i pročitaj izlaz (timeout u ms).
ProcessResult run_capture(const std::wstring& command_line, unsigned timeout_ms);

// Imenovani mutex; poller koristi Global\ (zadatak sustava i aplikacija u različitim sesijama).
class NamedMutex {
public:
    explicit NamedMutex(const std::wstring& name);
    ~NamedMutex();
    NamedMutex(const NamedMutex&) = delete;
    NamedMutex& operator=(const NamedMutex&) = delete;
    bool owned() const { return owned_; }

private:
    void* handle_ = nullptr;
    bool owned_ = false;
};

bool autostart_enabled();
void set_autostart(bool enabled);
bool poller_task_installed();
// Vrijedi za nit koja poziva (glavna nit GUI-ja). display_on=false (noćni način s ugašenim zaslonom):
// računalo ostaje budno, a zaslon se smije ugasiti.
void keep_awake(bool enabled, bool display_on = true);
void monitor_power(bool on);  // ugasi/upali zaslon; pomak miša ili tipka ga pale i sami
void open_path(const fs::path& path);
std::optional<fs::path> pick_file(void* owner, const std::wstring& title, const std::wstring& filter_name,
                                  const std::wstring& filter_spec);
std::optional<fs::path> pick_save_file(void* owner, const std::wstring& title, const std::wstring& filter_name,
                                       const std::wstring& filter_spec, const std::wstring& default_name);
void message_box(const std::wstring& text, bool error = false);

struct Screen {
    int index = 0;
    int x = 0, y = 0, width = 0, height = 0;  // fizički pikseli
    bool primary = false;
};
std::vector<Screen> list_screens();

}  // namespace sm

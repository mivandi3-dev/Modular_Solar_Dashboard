#include "i18n.hpp"

#include <windows.h>

#include <cmath>
#include <map>
#include <mutex>

#include "util.hpp"

namespace sm {

namespace {

const char* const kLanguages[] = {"hr", "en", "de", "fr", "it", "tr", "zh", "ja", "ko", "es"};

std::mutex g_mutex;
std::string g_lang = "hr";
std::map<std::string, json> g_cache;  // jezik → {"meta", "strings"}

fs::path i18n_dir() {
    // Instalacija i izgradnja: web\i18n pokraj .exe; testovi: SOLARI2_I18N_DIR
    if (const wchar_t* env = _wgetenv(L"SOLARI2_I18N_DIR"); env && *env) return fs::path(env);
    return exe_dir() / L"web" / L"i18n";
}

const json& load(const std::string& code) {
    auto it = g_cache.find(code);
    if (it != g_cache.end()) return it->second;
    json data = {{"meta", json::object()}, {"strings", json::object()}};
    if (const auto text = read_file(i18n_dir() / widen(code + ".json"))) {
        try {
            data = json::parse(*text);
            if (!data.contains("strings")) data["strings"] = json::object();
        } catch (const json::exception&) {
            log_warn("Prijevod " + code + " nije čitljiv");
        }
    }
    return g_cache.emplace(code, std::move(data)).first->second;
}

}  // namespace

bool is_language(const std::string& code) {
    for (const char* l : kLanguages) if (code == l) return true;
    return false;
}

void set_language(const std::string& code) {
    std::lock_guard lock(g_mutex);
    g_lang = is_language(code) ? code : "hr";
}

std::string language() {
    std::lock_guard lock(g_mutex);
    return g_lang;
}

std::string tr(const std::string& key, TrArgs args) {
    std::string text;
    {
        std::lock_guard lock(g_mutex);
        const json& strings = load(g_lang).at("strings");
        auto it = strings.find(key);
        text = it != strings.end() && it->is_string() && !it->get<std::string>().empty() ? it->get<std::string>() : key;
    }
    for (const auto& [name, value] : args) {
        const std::string placeholder = std::string("{") + name + "}";
        for (size_t pos = text.find(placeholder); pos != std::string::npos; pos = text.find(placeholder, pos + value.size())) {
            text.replace(pos, placeholder.size(), value);
        }
    }
    return text;
}

std::string fmt_num(double value, int decimals) {
    std::string decimal = ",", group = ".";
    {
        std::lock_guard lock(g_mutex);
        const json meta = load(g_lang).value("meta", json::object());
        decimal = meta.value("decimal", decimal);
        group = meta.value("group", group);
    }
    char buf[64];
    std::snprintf(buf, sizeof buf, "%.*f", decimals, std::abs(value));
    std::string s = buf, frac;
    if (const auto dot = s.find('.'); dot != std::string::npos) {
        frac = s.substr(dot + 1);
        s.resize(dot);
    }
    std::string grouped;
    for (size_t i = 0; i < s.size(); ++i) {
        if (i && (s.size() - i) % 3 == 0) grouped += group;
        grouped += s[i];
    }
    const bool negative = value < 0 && std::abs(value) >= 0.5 * std::pow(10.0, -decimals);
    return (negative ? "-" : "") + grouped + (frac.empty() ? "" : decimal + frac);
}

json i18n_bundle(const std::string& code) {
    std::lock_guard lock(g_mutex);
    const std::string lang = is_language(code) ? code : "hr";
    json languages = json::object();
    for (const char* l : kLanguages) languages[l] = load(l).value("meta", json::object()).value("name", std::string(l));
    const json& data = load(lang);
    return {{"lang", lang}, {"meta", data.value("meta", json::object())}, {"strings", data.at("strings")},
            {"languages", languages}};
}

std::string system_language() {
    switch (GetUserDefaultUILanguage() & 0x3FF) {
    case 0x1A: return "hr";
    case 0x07: return "de";
    case 0x0C: return "fr";
    case 0x10: return "it";
    case 0x1F: return "tr";
    case 0x04: return "zh";
    case 0x11: return "ja";
    case 0x12: return "ko";
    case 0x0A: return "es";
    default: return "en";
    }
}

}  // namespace sm

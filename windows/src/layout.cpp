#include "layout.hpp"

#include <regex>
#include <set>

#include "i18n.hpp"
#include "util.hpp"

namespace sm {

const WidgetSpec* Catalog::find(const std::string& key) const {
    for (const auto& w : widgets) if (w.key == key) return &w;
    return nullptr;
}

Catalog load_catalog(const fs::path& file) {
    const auto text = read_file(file);
    if (!text) throw std::runtime_error("Katalog widgeta nije pronađen: " + narrow(file.wstring()));
    Catalog c;
    c.raw = json::parse(*text);
    c.cols = c.raw.value("cols", 12);
    c.rows = c.raw.value("rows", 5);
    c.default_layout = c.raw.value("defaultLayout", json::array());
    for (const auto& w : c.raw.at("widgets")) {
        WidgetSpec s;
        s.key = w.at("key");
        s.title = w.at("title");
        s.w = w["size"][0]; s.h = w["size"][1];
        s.min_w = w["minSize"][0]; s.min_h = w["minSize"][1];
        s.max_w = w["maxSize"][0]; s.max_h = w["maxSize"][1];
        for (const auto& o : w.value("options", json::array())) {
            WidgetOption opt{o.at("key"), o.at("kind"), o.value("label", std::string{}), o.at("default"), {},
                              o.value("maxLen", size_t{80})};
            for (const auto& ch : o.value("choices", json::array())) opt.choices.push_back(ch[0]);
            s.options.push_back(std::move(opt));
        }
        c.widgets.push_back(std::move(s));
    }
    return c;
}

json to_json(const Placement& p) {
    return {{"id", p.id}, {"type", p.type}, {"x", p.x}, {"y", p.y}, {"w", p.w}, {"h", p.h}, {"options", p.options}};
}

json layout_json(const std::vector<Placement>& items) {
    json arr = json::array();
    for (const auto& p : items) arr.push_back(to_json(p));
    return arr;
}

namespace {

// UTF-8 skraćivanje na najviše n znakova (ne reže usred znaka)
std::string utf8_truncate(const std::string& s, size_t n) {
    std::wstring w = widen(s);
    if (w.size() > n) w.resize(n);
    return narrow(w);
}

json coerce_options(const WidgetSpec& spec, const json& raw, std::vector<std::string>& errors) {
    json out = json::object();
    for (const auto& opt : spec.options) {
        json value = raw.is_object() && raw.contains(opt.key) ? raw[opt.key] : opt.default_value;
        if (opt.kind == "choice") {
            const json* match = nullptr;
            for (const auto& c : opt.choices) {
                // preglednik može poslati "14" umjesto 14
                const std::string a = c.is_string() ? c.get<std::string>() : c.dump();
                const std::string b = value.is_string() ? value.get<std::string>() : value.dump();
                if (a == b) { match = &c; break; }
            }
            if (!match) {
                errors.push_back(tr("{widget}: neispravna vrijednost za „{option}“.", {{"widget", tr(spec.title)}, {"option", tr(opt.label)}}));
                value = opt.default_value;
            } else {
                value = *match;
            }
        } else {
            value = utf8_truncate(trim(value.is_string() ? value.get<std::string>() : value.dump()), opt.max_len);
        }
        out[opt.key] = value;
    }
    return out;
}

std::string random_suffix() {
    static unsigned counter = 0;
    char buf[12];
    std::snprintf(buf, sizeof buf, "%06x", (static_cast<unsigned>(now()) * 2654435761u + ++counter) & 0xFFFFFF);
    return buf;
}

}  // namespace

LayoutResult validate_layout(const Catalog& catalog, const json& items) {
    static const std::regex kId(R"(^[a-z0-9_-]{1,40}$)");
    LayoutResult r;
    std::set<std::string> seen;
    if (!items.is_array()) return r;
    for (const auto& raw : items) {
        const WidgetSpec* spec = raw.is_object() && raw.contains("type") && raw["type"].is_string()
                                     ? catalog.find(raw["type"].get<std::string>())
                                     : nullptr;
        Placement p;
        try {
            if (!spec) throw std::runtime_error("type");
            p.type = spec->key;
            p.id = raw.contains("id") && raw["id"].is_string() ? raw["id"].get<std::string>() : spec->key + "-" + random_suffix();
            p.x = raw.at("x"); p.y = raw.at("y"); p.w = raw.at("w"); p.h = raw.at("h");
        } catch (const std::exception&) {
            r.errors.push_back(tr("Nepoznat ili oštećen widget."));
            continue;
        }
        std::string problem;
        if (!std::regex_match(p.id, kId) || seen.count(p.id)) {
            problem = tr("neispravna oznaka");
        } else if (p.w < spec->min_w || p.w > spec->max_w || p.h < spec->min_h || p.h > spec->max_h) {
            problem = tr("veličina {size} nije dopuštena (od {min} do {max})",
                         {{"size", std::to_string(p.w) + "×" + std::to_string(p.h)},
                          {"min", std::to_string(spec->min_w) + "×" + std::to_string(spec->min_h)},
                          {"max", std::to_string(spec->max_w) + "×" + std::to_string(spec->max_h)}});
        } else if (p.x < 0 || p.y < 0 || p.x + p.w > catalog.cols || p.y + p.h > catalog.rows) {
            problem = tr("izlazi iz ekrana");
        }
        p.options = coerce_options(*spec, raw.value("options", json::object()), r.errors);
        if (problem.empty()) {
            for (const auto& o : r.items) if (p.overlaps(o)) { problem = tr("preklapa se s drugim widgetom"); break; }
        }
        if (!problem.empty()) {
            r.errors.push_back(tr(spec->title) + ": " + problem + ".");
            continue;
        }
        seen.insert(p.id);
        r.items.push_back(std::move(p));
    }
    return r;
}

Pages load_pages(const Catalog& catalog, const fs::path& file) {
    const Pages fallback{{validate_layout(catalog, catalog.default_layout).items}, 0};
    const auto text = read_file(file);
    if (!text) return fallback;
    json raw_pages = json::array();
    int rotate = 0;
    try {
        const json j = json::parse(*text);
        if (!j.is_object()) return fallback;
        if (j.contains("pages") && j["pages"].is_array()) {
            for (const auto& p : j["pages"]) raw_pages.push_back(p.is_object() ? p.value("widgets", json::array()) : json::array());
        } else {
            raw_pages.push_back(j.value("widgets", json::array()));
        }
        rotate = j.value("rotate_s", 0);
    } catch (const json::exception&) {
        log_warn("Raspored widgeta nije čitljiv – koristim zadani");
        return fallback;
    }
    Pages out;
    for (int choice : kRotateChoices) if (choice == rotate) out.rotate_s = rotate;
    std::set<std::string> seen;  // oznaka widgeta jedinstvena je na svim stranicama
    for (const auto& raw : raw_pages) {
        if (static_cast<int>(out.pages.size()) >= kMaxPages) break;
        std::vector<Placement> items;
        for (auto& p : validate_layout(catalog, raw).items) {
            if (seen.insert(p.id).second) items.push_back(std::move(p));
        }
        out.pages.push_back(std::move(items));
    }
    if (out.pages.empty()) out.pages = fallback.pages;
    return out;
}

void save_pages(const Pages& pages, const fs::path& file) {
    json list = json::array();
    for (const auto& p : pages.pages) list.push_back({{"widgets", layout_json(p)}});
    if (!ui_write_allowed(file.parent_path())) throw std::runtime_error("Mapa rasporeda je spojnica – raspored nije spremljen.");  // NEW-05
    write_file_atomic(file, json{{"version", 2}, {"rotate_s", pages.rotate_s}, {"pages", list}}.dump(2));
}

json pages_json(const Pages& pages) {
    json list = json::array();
    for (const auto& p : pages.pages) list.push_back(layout_json(p));
    return {{"pages", list}, {"rotateS", pages.rotate_s}};
}

void save_page(const Catalog& catalog, const std::vector<Placement>& items, int page, const fs::path& file) {
    Pages pages = load_pages(catalog, file);
    if (page == static_cast<int>(pages.pages.size()) && page < kMaxPages) pages.pages.emplace_back();
    if (page < 0 || page >= static_cast<int>(pages.pages.size())) throw std::runtime_error(tr("Stranica ne postoji."));
    for (int n = 0; n < static_cast<int>(pages.pages.size()); ++n) {
        if (n == page) continue;
        for (const auto& other : pages.pages[n]) {
            for (const auto& it : items) {
                if (it.id == other.id) throw std::runtime_error(tr("Oznaka widgeta već postoji na drugoj stranici."));
            }
        }
    }
    pages.pages[page] = items;
    save_pages(pages, file);
}

Pages remove_page(const Catalog& catalog, int page, const fs::path& file) {
    Pages pages = load_pages(catalog, file);
    if (pages.pages.size() <= 1 || page < 0 || page >= static_cast<int>(pages.pages.size())) return pages;
    pages.pages.erase(pages.pages.begin() + page);
    save_pages(pages, file);
    return pages;
}

Pages set_rotation(const Catalog& catalog, int seconds, const fs::path& file) {
    bool known = false;
    for (int choice : kRotateChoices) known = known || choice == seconds;
    if (!known) throw std::runtime_error(tr("Nepoznat interval izmjene."));
    Pages pages = load_pages(catalog, file);
    pages.rotate_s = seconds;
    save_pages(pages, file);
    return pages;
}

}  // namespace sm

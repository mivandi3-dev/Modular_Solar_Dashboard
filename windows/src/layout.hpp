// Raspored widgeta ispod zaglavlja: mreža 12 × 5, data/layout.json (isti format kao Python verzija).
// Katalog widgeta (veličine, opcije) čita se iz web/catalog.json – isti opis koristi i sučelje.
#pragma once

#include <string>
#include <vector>

#include "config.hpp"

namespace sm {

struct WidgetOption {
    std::string key, kind, label;  // kind: "choice" | "text"
    json default_value;
    std::vector<json> choices;
    size_t max_len = 80;
};

struct WidgetSpec {
    std::string key, title;
    int w = 1, h = 1, min_w = 1, min_h = 1, max_w = 12, max_h = 5;
    std::vector<WidgetOption> options;
};

struct Catalog {
    int cols = 12, rows = 5;
    std::vector<WidgetSpec> widgets;
    json default_layout = json::array();
    json raw;  // cijeli catalog.json za sučelje

    const WidgetSpec* find(const std::string& key) const;
};

Catalog load_catalog(const fs::path& file);

struct Placement {
    std::string id, type;
    int x = 0, y = 0, w = 1, h = 1;
    json options = json::object();

    bool overlaps(const Placement& o) const {
        return !(x + w <= o.x || o.x + o.w <= x || y + h <= o.y || o.y + o.h <= y);
    }
};

json to_json(const Placement& p);

struct LayoutResult {
    std::vector<Placement> items;
    std::vector<std::string> errors;
};

// strict: vrati sve greške; inače preskoči neispravne widgete (učitavanje oštećene datoteke).
LayoutResult validate_layout(const Catalog& catalog, const json& items);
json layout_json(const std::vector<Placement>& items);

// Stranice rasporeda (isto kao solar/layout.py): prikaz ih izmjenjuje svakih rotate_s sekundi (0 = bez izmjene).
//   {"version": 2, "rotate_s": 20, "pages": [{"widgets": [...]}, ...]}   ili stariji {"version": 1, "widgets": [...]}
inline constexpr int kMaxPages = 6;
inline constexpr int kRotateChoices[] = {0, 10, 15, 20, 30, 45, 60, 120, 300};
struct Pages {
    std::vector<std::vector<Placement>> pages;
    int rotate_s = 0;
};
Pages load_pages(const Catalog& catalog, const fs::path& file);  // zadani raspored ako nema/oštećen
void save_pages(const Pages& pages, const fs::path& file);
json pages_json(const Pages& pages);  // {"pages": [[...], ...], "rotateS": N}
// Spremi jednu stranicu; page == broj stranica dodaje novu. Baca std::runtime_error s porukom za korisnika.
void save_page(const Catalog& catalog, const std::vector<Placement>& items, int page, const fs::path& file);
Pages remove_page(const Catalog& catalog, int page, const fs::path& file);
Pages set_rotation(const Catalog& catalog, int seconds, const fs::path& file);  // baca za nepoznat interval

}  // namespace sm

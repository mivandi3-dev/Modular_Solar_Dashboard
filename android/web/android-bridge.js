// Most za Android (umjesto web/bridge.js): isto sučelje window.pywebview.api.* kao na Windowsima, pa dashboard,
// widgeti, editor rasporeda (editor.js), prečaci i noćni način (overlay.js) rade bez izmjena.
//   * podaci: /api/v1/dashboard – Java (MainActivity) ih proslijedi poslužitelju s X-API-Key
//   * raspored widgeta (stranice) i prikaz (tema, jezik, noćni način) su lokalni – svaki uređaj ima svoje
"use strict";

(() => {
  window.SOLARI_ANDROID = true;

  // Mobilni raspored: stranica je široka koliko i ekran (dp), slova i dodirne površine su prirodne veličine.
  // Uspravno su widgeti jedan ispod drugog, položeno (i na tabletu) u stupcima od najmanje 340 dp; svi su iste širine,
  // a visina ostaje iz rasporeda. Zaglavlje je kompaktno; izbornik ☰ gore desno zamjenjuje traku s gumbima.
  const root = document.documentElement;
  const portrait = () => window.innerHeight > window.innerWidth;
  const applyOrientation = () => root.classList.toggle("portrait", portrait());
  root.classList.add("android");
  root.style.setProperty("--dp", String(window.SolariAndroid.cssPerDp() || 1));
  applyOrientation();
  window.addEventListener("resize", applyOrientation);
  const shown = [0, 1, 2, 3, 4, 5].map((n) => `html[data-page="${n}"] .st-key-pages > .st-key-grid-p${n}`).join(", ");
  const css = document.createElement("style");
  css.textContent = `
    html.android, html.android body { overflow-y: auto !important; overflow-x: hidden !important; height: auto !important; }
    html.android { -webkit-text-size-adjust: 100%; }
    html.android .stApp { position: static !important; overflow: visible !important; min-height: 100vh; }
    html.android .block-container { min-height: 0 !important; justify-content: flex-start !important;
      padding: 10px 10px 40px !important; }  /* sadržaj do vrha; ☰ gore desno lebdi nad zaglavljem */
    html.android #solari-bar, html.android #se-side, html.android #se-tab, html.android #se-frames { display: none !important; }
    /* zaglavlje: fotografija kao pozadina, naslov, kartica elektrane i prognoza jedno ispod drugog */
    html.android .hero-wrap { margin-bottom: 12px; }
    html.android .hero { height: auto !important; flex-direction: column; gap: 12px; padding: 14px 14px; border-radius: 20px; }
    html.android .hero-left > :first-child { padding-right: 56px; }  /* pozdrav i naslov ne idu ispod ☰ */
    html.android .hero-bg, html.android .hero-bg-layer > * { border-radius: 20px; }
    html.android .hero-left { gap: 12px; }
    html.android .greet { font-size: .88rem; }
    html.android .hero h1 { font-size: 1.5rem; line-height: 1.22; margin-top: 4px; }
    html.android .site-card, html.android .weather { width: 100% !important; box-sizing: border-box; }
    html.android .site-card { padding: 12px 14px; }
    html.android .site-card .logo { max-height: 52px; }
    html.android .weather { padding: 12px 14px; gap: 8px; }
    html.android .weather .temp { font-size: 1.7rem; }
    html.android .weather .icon { font-size: 2.2rem; }
    html.android:not(.portrait) .hero { flex-direction: row; align-items: stretch; padding-right: 66px; }
    html.android:not(.portrait) .hero-left { flex: 1; }
    html.android:not(.portrait) .weather { width: 300px !important; flex: none; }
    /* stranice rasporeda: vidi se samo trenutna */
    html.android .st-key-pages > * { height: 0; overflow: hidden; }
    html.android:not([data-page]) .st-key-pages > .st-key-grid-p0, ${shown} { height: auto; overflow: visible; }
    /* widgeti: iste širine, uspravno jedan stupac, položeno stupci od 340 dp */
    html.android [class*="st-key-grid-p"] { grid-template-columns: repeat(auto-fill, minmax(340px, 1fr)) !important;
      grid-template-rows: none !important; grid-auto-rows: auto !important; align-items: start; gap: 12px !important; }
    html.portrait [class*="st-key-grid-p"] { grid-template-columns: minmax(0, 1fr) !important; }
    html.android [class*="st-key-w-"] { grid-column: auto !important; grid-row: auto !important; height: auto !important; }
    html.android .card { padding: 14px 16px; border-radius: 18px; }
    html.android .card-title { font-size: 1.05rem; }
    html.android .card-title small { font-size: .8rem; }
    /* traka pokazatelja: jedan pokazatelj po retku, krupan broj */
    html.android .kpis { grid-template-columns: 1fr !important; height: auto !important; row-gap: 4px; padding: 8px 4px; }
    html.android .kpi { border-right: 0 !important; padding: 10px 12px; }
    html.android .kpi .value { font-size: 1.7rem; }
    html.android .kpi .label { font-size: .9rem; }
    /* uspravno: prognoza bez redaka zračenja i vjetra (ima ih widget Vremenska prognoza) */
    html.portrait .weather .row { display: none; }
    html.portrait .weather .now { margin: 0; }
    /* tok energije: crtež zgrade gore, četiri vrijednosti ispod (2 × 2) – na uskom zaslonu se ne preklapaju */
    html.android [class*="st-key-flow-"] .card { height: auto !important; }
    html.android [class*="st-key-flow-"] .flow { height: auto; container-type: normal; }
    /* pozadinska kartica (crtež) prekriva cijelu visinu kartice s vrijednostima */
    html.android [class*="st-key-flow-"] > :first-child .card,
    html.android [class*="st-key-flow-"] > :first-child .flow { height: 100% !important; }
    html.android [class*="st-key-flow-"] .flow svg.lines, html.android [class*="st-key-flow-"] .flow .arrow { display: none; }
    html.android [class*="st-key-flow-"] .flow .building { top: 4px; transform: translateX(-50%); height: 150px; }
    html.android .card.overlay .flow { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; padding-top: 164px; }
    html.android .card.overlay .node { position: static; padding: 10px 12px; gap: 10px; min-width: 0; }
    html.android .card.overlay .node .k { white-space: normal; line-height: 1.2; }
    html.android .card.overlay .node .v { font-size: 1.15rem; }`;
  document.head.appendChild(css);
  const A = window.SolariAndroid;
  const KEY = "solari.pages";
  const store = {
    get() { try { return JSON.parse(localStorage.getItem(KEY)); } catch (e) { return null; } },
    set(v) { try { localStorage.setItem(KEY, JSON.stringify(v)); } catch (e) { /* bez spremanja rasporeda */ } },
    clear() { try { localStorage.removeItem(KEY); } catch (e) { /* ništa */ } },
  };
  const prefs = () => JSON.parse(A.getSettings());
  let server = { pages: [[]], rotateS: 0 }, hasMeter = false, catalog = null, capabilities = [];

  async function getJson(url) {
    const res = await fetch(url, { cache: "no-store" });
    if (!res.ok) {
      let why = "";
      try { why = (await res.json()).error || ""; } catch (e) { /* tijelo nije JSON */ }
      // 3.0: prijava istekla ili poništena (promjena lozinke, blokiranje) i promijenjen certifikat – poruka za korisnika
      if (res.status === 401) throw new Error(T("Prijava je istekla ili je poništena – prijavite se ponovno u postavkama."));
      if (res.status === 495) throw new Error(T(why));
      throw new Error(`HTTP ${res.status}${why ? ` (${why})` : ""}`);
    }
    return res.json();
  }
  const pages = () => store.get() || { pages: server.pages, rotateS: server.rotateS };
  const savePages = (p) => { store.set(p); return { ok: true, pages: p.pages, rotateS: p.rotateS }; };
  const overlaps = (a, b) => !(a.x + a.w <= b.x || b.x + b.w <= a.x || a.y + a.h <= b.y || b.y + b.h <= a.y);

  const api = {
    async get_dashboard() {
      let d = await getJson("/api/v1/dashboard");
      if (d.demo_template && window.SolariDemo) d = window.SolariDemo.dashboard(d);  // demo način (demo.js)
      server = { pages: d.pages || [[]], rotateS: d.rotateS || 0 };
      hasMeter = Boolean(d.settings && d.settings.meter_unit_id);
      capabilities = d.capabilities || [];  // uređaj na poslužitelju (widgeti uređaja)
      const p = prefs(), local = pages();
      Object.assign(d.settings, { theme: p.theme, palette: p.palette || "", language: p.language, hide_idle_cursor: false,
        night_mode: p.night_mode, night_from: p.night_from, night_to: p.night_to, forecast_days: p.forecast_days || 5 });
      d.pages = local.pages;
      d.rotateS = local.rotateS;
      d.fullscreen = A.isFullscreen();
      d.version = p.version;
      return d;
    },
    async get_editor() {
      catalog = catalog || await getJson("catalog.json");
      const p = pages();
      return { catalog: catalog.widgets, categories: catalog.categories, pages: p.pages, rotateS: p.rotateS,
        rotateChoices: [0, 10, 15, 20, 30, 45, 60, 120, 300], maxPages: 6, cols: catalog.cols, rows: catalog.rows,
        hasMeter, capabilities, fullscreen: A.isFullscreen(), sidebarOpen: false, version: prefs().version };
    },
    async save_layout(items, page = 0) {
      const p = pages(), list = p.pages.map((x) => x.slice());
      if (page === list.length && list.length < 6) list.push([]);
      if (page < 0 || page >= list.length) return { ok: false, message: T("Stranica ne postoji.") };
      const others = new Set(list.flatMap((x, n) => (n === page ? [] : x.map((i) => i.id))));
      for (const [i, it] of items.entries()) {
        if (others.has(it.id)) return { ok: false, message: T("Oznaka widgeta već postoji na drugoj stranici.") };
        if (items.some((o, j) => j !== i && overlaps(it, o))) return { ok: false, message: T("Widget se ne smije preklapati s drugim.") };
      }
      list[page] = items;
      savePages({ pages: list, rotateS: p.rotateS });
      return { ok: true, layout: items };
    },
    async remove_page(page) {
      const p = pages();
      if (p.pages.length <= 1 || page < 0 || page >= p.pages.length) return { ok: true, pages: p.pages, rotateS: p.rotateS };
      return savePages({ pages: p.pages.filter((_, n) => n !== page), rotateS: p.rotateS });
    },
    async set_rotation(seconds) {
      if (![0, 10, 15, 20, 30, 45, 60, 120, 300].includes(seconds)) return { ok: false, message: T("Nepoznat interval izmjene.") };
      return savePages({ pages: pages().pages, rotateS: seconds });
    },
    async save_pages(list) {  // popis widgeta (android-menu.js): redoslijed je y, širina se na Androidu ne koristi
      if (!Array.isArray(list) || !list.length || list.length > 6) return { ok: false };
      return savePages({ pages: list, rotateS: pages().rotateS });
    },
    async reset_layout() {
      store.clear();
      return { ok: true, pages: server.pages, rotateS: server.rotateS };
    },
    async toggle_fullscreen() {
      const fs = A.setFullscreen(!A.isFullscreen());
      document.dispatchEvent(new CustomEvent("solari-mode", { detail: { fullscreen: fs } }));
      return fs;
    },
    async exit_fullscreen() { return A.isFullscreen() ? api.toggle_fullscreen() : false; },
    async open_settings() { location.href = "settings-android.html"; },
    async reload() { location.reload(); },
    async quit() { A.exit(); },
    async set_display(on) { A.setDisplay(Boolean(on)); },
  };
  window.pywebview = { api: new Proxy(api, { get: (o, m) => o[m] || (async () => null) }) };
  window.solariReload = () => location.reload();
  document.addEventListener("DOMContentLoaded", () => window.dispatchEvent(new Event("pywebviewready")));
})();

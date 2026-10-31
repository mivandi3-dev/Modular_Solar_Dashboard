// Android: izbornik ☰ gore desno (umjesto trake s gumbima) i popis widgeta umjesto editora rasporeda.
// Na Androidu su svi widgeti iste širine, pa se bira samo koji su na ekranu, njihov redoslijed i visina.
// Raspored se sprema lokalno (android-bridge.js → save_pages); y je redni broj, x i w ostaju za Windows editor.
"use strict";

(() => {
  if (window.__solariMenu) return;
  window.__solariMenu = true;
  const api = () => window.pywebview.api;
  const T = window.T || ((s) => s);
  const esc = (s) => String(s).replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
  const dp = (n) => `calc(var(--dp, 1) * ${n}px)`;

  const css = document.createElement("style");
  css.textContent = `
    #am-burger { position: fixed; top: ${dp(8)}; right: ${dp(8)}; z-index: 999999; width: ${dp(48)}; height: ${dp(48)};
      display: grid; place-items: center; padding: 0; border-radius: ${dp(14)}; cursor: pointer; color: var(--text, #E6EAF2);
      background: var(--card, rgba(22,31,51,.85)); border: 1px solid var(--border, rgba(255,255,255,.1));
      box-shadow: var(--shadow, 0 8px 24px rgba(0,0,0,.35)); backdrop-filter: blur(12px); -webkit-backdrop-filter: blur(12px); }
    #am-burger { transition: transform .25s ease, opacity .25s ease; }
    #am-burger.away { transform: translateY(-140%); opacity: 0; pointer-events: none; }
    #am-burger span, #am-burger span::before, #am-burger span::after { display: block; width: ${dp(22)}; height: ${dp(2.5)};
      border-radius: 2px; background: currentColor; position: relative; content: ""; }
    #am-burger span::before { position: absolute; top: ${dp(-7)}; } #am-burger span::after { position: absolute; top: ${dp(7)}; }
    #am-menu { position: fixed; top: ${dp(62)}; right: ${dp(8)}; z-index: 999999; display: none; min-width: ${dp(220)};
      padding: ${dp(6)}; border-radius: ${dp(16)}; background: var(--card-solid, #1A2540);
      border: 1px solid var(--border, rgba(255,255,255,.1)); box-shadow: 0 16px 48px rgba(0,0,0,.45); }
    #am-menu.show { display: block; }
    #am-menu button { display: flex; align-items: center; gap: ${dp(12)}; width: 100%; padding: ${dp(13)} ${dp(16)};
      font: 600 ${dp(16)} 'Plus Jakarta Sans', 'Segoe UI', sans-serif; color: var(--text, #E6EAF2);
      background: none; border: 0; border-radius: ${dp(11)}; text-align: left; cursor: pointer; }
    #am-menu button:active { background: rgba(113,191,67,.18); }
    #am-panel { position: fixed; inset: 0; z-index: 1000000; display: none; overflow-y: auto; background: var(--bg, #0B1220);
      color: var(--text, #E6EAF2); font: ${dp(15)} 'Plus Jakarta Sans', 'Segoe UI', sans-serif; }
    #am-panel.show { display: block; }
    #am-panel .in { max-width: ${dp(560)}; margin: 0 auto; padding: ${dp(16)} ${dp(14)} ${dp(40)}; }
    #am-panel header { display: flex; align-items: center; justify-content: space-between; gap: ${dp(10)}; margin-bottom: ${dp(12)}; }
    #am-panel h2 { margin: 0; font-size: ${dp(21)}; }
    #am-panel h3 { margin: ${dp(18)} 0 ${dp(8)}; font-size: ${dp(13)}; color: var(--muted, #94A3B8); font-weight: 600; text-transform: uppercase; letter-spacing: .04em; }
    #am-panel button { font: 600 ${dp(14)} 'Plus Jakarta Sans', 'Segoe UI', sans-serif; color: inherit; cursor: pointer;
      background: var(--card, rgba(255,255,255,.04)); border: 1px solid var(--line, rgba(255,255,255,.12));
      border-radius: ${dp(11)}; min-height: ${dp(40)}; padding: 0 ${dp(14)}; }
    #am-panel button.primary { background: #71BF43; border-color: #71BF43; color: #0B1220; }
    #am-panel button:disabled { opacity: .35; }
    #am-panel .tabs { display: flex; flex-wrap: wrap; gap: ${dp(6)}; }
    #am-panel .tabs button[aria-pressed="true"] { border-color: #71BF43; color: #71BF43; }
    #am-panel .item { display: flex; align-items: center; gap: ${dp(10)}; padding: ${dp(10)} ${dp(10)}; margin-bottom: ${dp(8)};
      border-radius: ${dp(14)}; background: var(--card, rgba(255,255,255,.04)); border: 1px solid var(--line, rgba(255,255,255,.08)); }
    #am-panel .item .ic { font-size: ${dp(22)}; width: ${dp(30)}; text-align: center; }
    #am-panel .item .name { flex: 1; min-width: 0; font-weight: 600; line-height: 1.25; }
    #am-panel .item .name small { display: block; font-weight: 400; font-size: ${dp(12.5)}; color: var(--muted, #94A3B8); }
    #am-panel .item .btns { display: flex; gap: ${dp(4)}; flex-wrap: wrap; justify-content: flex-end; }
    #am-panel .item .btns button { min-width: ${dp(40)}; padding: 0 ${dp(8)}; }
    #am-panel .add .item { cursor: pointer; } #am-panel .add .item.off { opacity: .45; cursor: default; }
    #am-panel .foot { display: flex; gap: ${dp(8)}; justify-content: space-between; margin-top: ${dp(20)}; }
    #am-panel .hint { color: var(--muted, #94A3B8); font-size: ${dp(13)}; }`;
  document.head.appendChild(css);

  // ---------------------------------------------------------------- izbornik ☰
  const burger = document.createElement("button");
  burger.id = "am-burger";
  burger.type = "button";
  burger.setAttribute("aria-label", T("Izbornik"));
  burger.innerHTML = "<span></span>";
  const menu = document.createElement("div");
  menu.id = "am-menu";
  menu.setAttribute("role", "menu");
  menu.innerHTML = `<button type="button" role="menuitem" data-go="settings">⚙ ${esc(T("Postavke"))}</button>`
    + `<button type="button" role="menuitem" data-go="widgets">▦ ${esc(T("Widgeti"))}</button>`;
  document.body.append(burger, menu);
  const showMenu = (on) => menu.classList.toggle("show", on);
  burger.addEventListener("click", (e) => { e.stopPropagation(); showMenu(!menu.classList.contains("show")); });
  document.addEventListener("click", () => showMenu(false));
  burger.addEventListener("dblclick", (e) => e.stopPropagation()); // dvoklik na dashboardu je cijeli zaslon
  // pomicanje prema dolje skriva ☰ (ne prekriva naslove kartica), prema gore ga vraća; pri vrhu je uvijek vidljiv
  let lastY = window.scrollY;
  window.addEventListener("scroll", () => {
    const y = window.scrollY;
    if (Math.abs(y - lastY) < 8) return;
    burger.classList.toggle("away", y > lastY && y > 80 && !menu.classList.contains("show"));
    lastY = y;
  }, { passive: true });
  menu.addEventListener("click", (e) => {
    const b = e.target.closest("button");
    if (!b) return;
    e.stopPropagation();
    showMenu(false);
    if (b.dataset.go === "settings") api().open_settings();
    else openPanel();
  });

  // ---------------------------------------------------------------- popis widgeta
  const panel = document.createElement("div");
  panel.id = "am-panel";
  panel.setAttribute("role", "dialog");
  panel.setAttribute("aria-label", T("Widgeti"));
  panel.addEventListener("dblclick", (e) => e.stopPropagation());
  document.body.appendChild(panel);
  let ed = null, page = 0, adding = false;

  const spec = (type) => ed.catalog.find((s) => s.key === type) || { title: type, icon: "▫", size: [3, 1], minSize: [1, 1], maxSize: [12, 5], options: [] };
  const ordered = (items) => items.slice().sort((a, b) => (a.y * 100 + a.x) - (b.y * 100 + b.x));
  const newId = (type) => `${type.replace(/_/g, "-").slice(0, 24)}-${Math.random().toString(16).slice(2, 8)}`;

  async function openPanel() {
    const e = await api().get_editor();
    ed = { catalog: e.catalog, categories: e.categories, hasMeter: e.hasMeter, capabilities: e.capabilities || [], pages: e.pages.map(ordered) };
    page = Math.min((window.SolariPages && window.SolariPages.page) || 0, ed.pages.length - 1);
    adding = false;
    draw();
    panel.classList.add("show");
    panel.scrollTop = 0;
  }

  async function save() {
    const list = ed.pages.map((items) => items.map((it, i) => ({ ...it, x: 0, y: i })));
    await api().save_pages(list);
    if (window.solariRender) window.solariRender();
  }

  function itemRow(it, i, count) {
    const s = spec(it.type), [minH, maxH] = [s.minSize[1], s.maxSize[1]];
    return `<div class="item" data-i="${i}"><div class="ic">${s.icon}</div>`
      + `<div class="name">${esc(T(s.title))}<small>${esc(T("Visina"))}: ${it.h}</small></div><div class="btns">`
      + `<button type="button" data-act="h-" aria-label="${esc(T("Smanji"))}" ${it.h <= minH ? "disabled" : ""}>−</button>`
      + `<button type="button" data-act="h+" aria-label="${esc(T("Povećaj"))}" ${it.h >= maxH ? "disabled" : ""}>+</button>`
      + `<button type="button" data-act="up" aria-label="${esc(T("Pomakni gore"))}" ${i === 0 ? "disabled" : ""}>↑</button>`
      + `<button type="button" data-act="down" aria-label="${esc(T("Pomakni dolje"))}" ${i === count - 1 ? "disabled" : ""}>↓</button>`
      + `<button type="button" data-act="rm" aria-label="${esc(T("Ukloni"))}">✕</button></div></div>`;
  }

  function addList() {
    const used = new Set(ed.pages.flat().map((it) => it.type));
    // widgeti uređaja (baterija, temperatura, mreža) samo kad ih uređaj na poslužitelju podržava
    const free = ed.catalog.filter((s) => !used.has(s.key) && (!s.needs || ed.capabilities.includes(s.needs)));
    if (!free.length) return `<p class="hint">${esc(T("Svi widgeti su već na ekranu."))}</p>`;
    return ed.categories.map((cat) => {
      const rows = free.filter((s) => s.category === cat).map((s) => {
        const off = s.needsMeter && !ed.hasMeter;
        return `<div class="item${off ? " off" : ""}" data-add="${esc(s.key)}"><div class="ic">${s.icon}</div>`
          + `<div class="name">${esc(T(s.title))}<small>${esc(off ? T("potreban mjerač") : T(s.description || ""))}</small></div></div>`;
      }).join("");
      return rows ? `<h3>${esc(T(cat))}</h3>${rows}` : "";
    }).join("");
  }

  function draw() {
    const items = ed.pages[page];
    const tabs = ed.pages.length > 1 ? `<div class="tabs">${ed.pages.map((_, n) => `<button type="button" data-page="${n}" `
      + `aria-pressed="${n === page}">${esc(T("Stranica {n}", { n: n + 1 }))}</button>`).join("")}</div>` : "";
    panel.innerHTML = `<div class="in"><header><h2>▦ ${esc(T("Widgeti"))}</h2>`
      + `<button type="button" class="primary" data-act="close">${esc(T("Gotovo"))}</button></header>${tabs}`
      + `<h3>${esc(T("Widgeti"))}</h3>${items.map((it, i) => itemRow(it, i, items.length)).join("")}`
      + `<button type="button" data-act="add" aria-expanded="${adding}">+ ${esc(T("Dodaj widget"))}</button>`
      + (adding ? `<div class="add">${addList()}</div>` : "")
      + `<div class="foot"><button type="button" data-act="reset">${esc(T("Zadani raspored"))}</button>`
      + `<button type="button" class="primary" data-act="close">${esc(T("Gotovo"))}</button></div></div>`;
  }

  panel.addEventListener("click", async (e) => {
    const add = e.target.closest("[data-add]");
    if (add && !add.classList.contains("off")) {
      const s = spec(add.dataset.add);
      const options = Object.fromEntries((s.options || []).map((o) => [o.key, o.default]));
      ed.pages[page].push({ id: newId(s.key), type: s.key, x: 0, y: 0, w: s.size[0], h: s.size[1], options });
      adding = false;
      await save();
      draw();
      return;
    }
    const b = e.target.closest("button");
    if (!b || b.disabled) return;
    if (b.dataset.page) { page = Number(b.dataset.page); draw(); return; }
    const act = b.dataset.act, row = b.closest("[data-i]"), items = ed.pages[page];
    const i = row ? Number(row.dataset.i) : -1;
    if (act === "close") { panel.classList.remove("show"); return; }
    if (act === "add") { adding = !adding; draw(); return; }
    if (act === "reset") {
      await api().reset_layout();
      if (window.solariRender) window.solariRender();
      return openPanel();
    }
    if (act === "h-" || act === "h+") items[i] = { ...items[i], h: items[i].h + (act === "h+" ? 1 : -1) };
    else if (act === "up" || act === "down") {
      const j = act === "up" ? i - 1 : i + 1;
      [items[i], items[j]] = [items[j], items[i]];
    } else if (act === "rm") items.splice(i, 1);
    else return;
    await save();
    draw();
  });
})();

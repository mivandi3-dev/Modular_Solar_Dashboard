// Most JS ↔ C++ (src/bridge.cpp) preko WebView2 poruka. Izlaže isto sučelje kao pywebview u Python
// verziji – window.pywebview.api.<metoda>(...) vraća Promise – pa settings.js, editor.js i overlay.js
// rade bez izmjena. Događaji iz aplikacije: "mode" (cijeli zaslon) i "reload" (nove postavke/slike).
(() => {
  "use strict";
  const webview = window.chrome && window.chrome.webview;
  const pending = new Map();
  let nextId = 1;

  // Pregled iz mreže (src/remote.cpp): obični preglednik nema WebView2 – podaci dolaze s /api/dashboard,
  // adrese slika s virtualnih hostova aplikacije pretvaraju se u adrese poslužitelja; ostalo nije dostupno.
  if (!webview) {
    const rewrite = (v) => (typeof v === "string" ? v.replace("https://app.solari/", "/").replace("https://data.solari/", "/data/")
      : Array.isArray(v) ? v.map(rewrite) : v && typeof v === "object" ? Object.fromEntries(Object.entries(v).map(([k, x]) => [k, rewrite(x)])) : v);
    const remoteApi = {
      get_dashboard: async () => {
        const res = await fetch("/api/dashboard", { cache: "no-store" });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        return rewrite(await res.json());
      },
    };
    window.pywebview = { api: new Proxy(remoteApi, { get: (o, m) => o[m] || (async () => null) }) };
    document.addEventListener("DOMContentLoaded", () => window.dispatchEvent(new Event("pywebviewready")));
    return;
  }

  webview.addEventListener("message", (e) => {
    const msg = e.data;
    if (msg && msg.id != null && pending.has(msg.id)) {
      const { resolve, reject } = pending.get(msg.id);
      pending.delete(msg.id);
      if (msg.ok) resolve(msg.result); else reject(new Error(msg.error || "Greška"));
      return;
    }
    if (msg && msg.event === "mode") {
      document.dispatchEvent(new CustomEvent("solari-mode", { detail: { fullscreen: Boolean(msg.fullscreen) } }));
    } else if (msg && msg.event === "reload") {
      if (window.solariReload) window.solariReload(); else location.reload();
    }
  });

  const api = new Proxy({}, {
    get: (_, method) => (...args) => new Promise((resolve, reject) => {
      const id = nextId++;
      pending.set(id, { resolve, reject });
      webview.postMessage(JSON.stringify({ id, method: String(method), args }));
    }),
  });
  window.pywebview = { api };
  // isti događaj kao pywebview – tek kad se izvrše sve skripte stranice (DOMContentLoaded),
  // jer se datoteke s virtualnog hosta učitavaju asinkrono
  const ready = () => window.dispatchEvent(new Event("pywebviewready"));
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", ready);
  else setTimeout(ready, 0);
})();

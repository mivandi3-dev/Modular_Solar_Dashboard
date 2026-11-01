// Postavke Android aplikacije: poslužitelj (Cloudflare tunel ili lokalna mreža), API ključ, prikaz i izvještaji.
// Spremanje i provjeru radi Java (MainActivity.Bridge); ključ se ne vraća u JavaScript, samo je li spremljen.
"use strict";

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const A = window.SolariAndroid;
const LANGUAGES = { hr: "Hrvatski", en: "English", de: "Deutsch", fr: "Français", it: "Italiano", es: "Español",
  tr: "Türkçe", zh: "中文（简体）", ja: "日本語", ko: "한국어" };
let settings = null;
let report = null;

// Odgovori Jave na asinkrone pozive (provjera veze, spremanje CSV-a)
const pending = new Map();
let nextId = 1;
window.__solariCallback = (id, result) => { const r = pending.get(id); pending.delete(id); if (r) r(result); };
const callJava = (fn) => new Promise((resolve) => { const id = String(nextId++); pending.set(id, resolve); fn(id); });

function setResult(el, res, busyText) {
  el.className = "result " + (busyText ? "busy" : res.ok ? "ok" : "fail");
  el.textContent = busyText || res.message;
}

async function loadLanguage(code) {
  const bundle = await (await fetch(`i18n/${code}.json`)).json();
  window.SOLARI_I18N = { lang: code, meta: bundle.meta, strings: bundle.strings || {}, languages: LANGUAGES };
  document.documentElement.lang = code;
}

function fill(s) {
  $$("[data-field]").forEach((el) => {
    const v = s[el.dataset.field];
    if (el.type === "checkbox") el.checked = Boolean(v); else el.value = v ?? "";
  });
  $(".language-select").innerHTML = Object.entries(LANGUAGES).map(([c, n]) => `<option value="${c}">${esc(n)}</option>`).join("");
  $(".language-select").value = s.language;
  for (const name of ["mode", "night_mode", "forecast_days"]) $$(`input[name="${name}"]`).forEach((r) => { r.checked = r.value === String(s[name]); });
  renderIconThemes(["neon", "iconset"].includes(s.icon_theme) ? s.icon_theme : "classic", s.theme);
  $("#source").dataset.mode = s.mode;
  document.documentElement.dataset.theme = s.theme;
  window.SolariColors.renderChoices($(".palettes"), window.SolariColors.paletteKey(s.theme, s.palette));
  renderAccount(s);
  $("#version").textContent = T("Verzija {v}", { v: s.version });
  $("#btn-back").hidden = !(s.mode === "demo" || s.account);
  $("#demo-start").hidden = s.mode === "demo";
}

// 3.0: prijavljeni korisnik i otisak certifikata poslužitelja (usporedite s prozorom poslužitelja)
function renderAccount(s) {
  const acc = s.account;
  $("#account").innerHTML = acc
    ? T("Prijavljeni ste kao {name} ({email}).", { name: `<b>${esc(acc.name)}</b>`, email: esc(acc.email) })
    : "";
  $$(".login").forEach((el) => { el.hidden = Boolean(acc); });
  $$(".logout").forEach((el) => { el.hidden = !acc; });
  if (acc) $("#email").value = acc.email;
}

// ---- dvofaktorska prijava (3.1)
let totpUri = "";
function showTotp(info) {
  const box = $("#totp");
  box.hidden = !info;
  if (!info) return;
  const setup = info.step === "setup" && info.uri;
  $(".totp-setup", box).hidden = !setup;
  totpUri = setup ? info.uri : "";
  if (setup) {
    const qr = window.qrcode(0, "M");
    qr.addData(info.uri);
    qr.make();
    $(".qr", box).innerHTML = qr.createSvgTag({ cellSize: 4, margin: 3, scalable: true });
    $(".secret", box).textContent = info.secret.replace(/(.{4})/g, "$1 ").trim();
  }
  $(".totp-code", box).value = "";
  box.scrollIntoView({ block: "center" });
}

function showRecovery(codes) {
  return new Promise((resolve) => {
    if (!codes || !codes.length) return resolve();
    const box = $("#recovery");
    $(".codes", box).textContent = codes.join("\n");
    box.hidden = false;
    box.scrollIntoView({ block: "center" });
    $('[data-action="recovery-done"]', box).onclick = () => { $(".codes", box).textContent = ""; box.hidden = true; resolve(); };
  });
}

// tema ikona (icons.js): odabir s primjerima ikona obje teme
function renderIconThemes(want, uiTheme) {
  $$('input[name="icon_theme"]').forEach((r) => { r.checked = r.value === want; });
  const I = window.Icons;
  if (!I) return;
  const sample = ["sun", "sun_cloud", "rain", "bolt", "battery", "home", "chart", "globe"];
  $$(".icon-preview").forEach((el) => {
    I.setTheme(el.dataset.iconTheme, uiTheme === "light" ? "light" : "dark");
    el.innerHTML = sample.map((k) => `<span>${I.get(k)}</span>`).join("");  // statične ikone iz icons.js
  });
  I.setTheme("classic");
}

function collect() {
  const form = {};
  $$("[data-field]").forEach((el) => { form[el.dataset.field] = el.type === "checkbox" ? el.checked : el.value; });
  for (const name of ["mode", "night_mode", "palette", "forecast_days", "icon_theme"]) form[name] = ($(`input[name="${name}"]:checked`) || {}).value;
  form.palette = form.palette || "dark";
  form.theme = window.SolariColors.themeOf(form.palette);  // tema je osnova palete
  return form;
}

function showErrors(errors) {
  $$("[data-error]").forEach((el) => { el.textContent = errors[el.dataset.error] ? T(errors[el.dataset.error]) : ""; });
}

function renderAll() {
  translateDom(document.body);
  document.title = T("Solarni monitor – postavke");
  fill({ ...settings, ...(settings.form || {}) });
  renderMonths();
  if (report) renderReport(report);
}

// CSV za Excel (isti stupci kao na Windowsima): točka-zarez i decimalni zarez kad ga jezik koristi
function reportCsv(r) {
  const dec = (window.SOLARI_I18N.meta || {}).decimal || ",", sep = dec === "," ? ";" : ",";
  const num = (v) => (v == null ? "" : v.toFixed(2).replace(".", dec));
  const head = [T("Datum"), `${T("Proizvodnja")} (kWh)`, `${T("Potrošnja")} (kWh)`, `${T("Iz mreže")} (kWh)`,
    `${T("Predaja u mrežu")} (kWh)`, `${T("Vlastita potrošnja")} (kWh)`, `${T("Ušteda")} (${r.currency})`];
  const rows = r.days.map((d) => [fmtDate("date", day(d.date)), num(d.kwh), num(d.load), num(d.import), num(d.export), num(d.self), num(d.savings)]);
  const t = r.totals;
  rows.push([T("Ukupno"), num(t.kwh), num(t.load), num(t.import), num(t.export), num(t.self), num(t.savings)]);
  return "﻿" + [head, ...rows].map((row) => row.join(sep)).join("\r\n") + "\r\n";
}

const actions = {
  login: async (btn) => {
    const f = collect();
    const box = $("#newpw");
    let npw = "";
    if (!box.hidden) {  // aktivacija: vlastita lozinka umjesto jednokratnog koda
      npw = $(".np1", box).value;
      if (!npw || npw !== $(".np2", box).value) {
        setResult($("#test-result"), { ok: false, message: npw ? T("Lozinke se ne podudaraju.") : T("Upišite novu lozinku.") });
        return;
      }
    }
    btn.disabled = true;
    setResult($("#test-result"), null, T("Prijavljujem se…"));
    const res = await callJava((id) => A.login(JSON.stringify({ url: f.mode === "local" ? f.local_url : f.cloud_url,
                                                                email: $("#email").value.trim(), password: $("#password").value,
                                                                totp: $("#totp .totp-code").value, new_password: npw,
                                                                pairing_code: ($("#pairing") || { value: "" }).value.trim() }), id));
    btn.disabled = false;
    setResult($("#test-result"), { ok: res.ok, message: T(res.message, { name: res.name, code: res.code }) });
    if (res.pairing && $("#pairing")) { $("#pairing").focus(); return; }  // SMA-04: kod za uparivanje je obavezan
    if (res.password_change) { box.hidden = false; $(".np1", box).focus(); box.scrollIntoView({ block: "center" }); return; }
    if (npw) { $("#password").value = npw; box.hidden = true; $$("input", box).forEach((i) => { i.value = ""; }); }  // dalje s novom
    if (res.totp) { showTotp(res.totp); if (!res.totp.invalid) $("#test-result").className = "result"; return; }  // lozinka ostaje do unosa koda
    $("#password").value = "";  // lozinka ne ostaje ni u obrascu
    showTotp(null);
    if (res.ok) {
      await showRecovery(res.recovery_codes);
      $(`[data-field="${f.mode === "local" ? "local_url" : "cloud_url"}"]`).value = res.url;
      renderAccount({ account: res.account, cert_pin: res.pin });
      showErrors({});
    }
  },
  // zaboravljena lozinka: kod e-poštom, zatim nova lozinka uz kod
  "forgot-send": async (btn) => {
    const f = collect(), out = $("#forgot .fp-result");
    btn.disabled = true;
    setResult(out, null, T("Šaljem…"));
    const res = await callJava((id) => A.forgotPassword(JSON.stringify({ url: f.mode === "local" ? f.local_url : f.cloud_url,
      email: $("#email").value.trim(), pairing_code: ($("#pairing") || { value: "" }).value.trim() }), id));
    btn.disabled = false;
    setResult(out, { ok: res.ok, message: T(res.message) });
    if (res.pairing && $("#pairing")) $("#pairing").focus();
  },
  "forgot-reset": async (btn) => {
    const f = collect(), box = $("#forgot"), out = $(".fp-result", box);
    const code = $(".fp-code", box).value.trim(), np1 = $(".fp-np1", box).value, np2 = $(".fp-np2", box).value;
    if (!code) { setResult(out, { ok: false, message: T("Upišite kod iz e-pošte.") }); return; }
    if (!np1 || np1 !== np2) { setResult(out, { ok: false, message: T("Nove lozinke se ne podudaraju.") }); return; }
    btn.disabled = true;
    setResult(out, null, T("Spremam (sigurno spremanje lozinke traje sekundu)…"));
    const res = await callJava((id) => A.resetPassword(JSON.stringify({ url: f.mode === "local" ? f.local_url : f.cloud_url,
      email: $("#email").value.trim(), code, new_password: np1, pairing_code: ($("#pairing") || { value: "" }).value.trim() }), id));
    btn.disabled = false;
    setResult(out, { ok: res.ok, message: T(res.message) });
    if (res.ok) {
      $$(".fp-code, .fp-np1, .fp-np2", box).forEach((el) => { el.value = ""; });
      box.open = false;
      $("#password").focus();
    }
  },
  "open-auth": () => {
    if (!A.openAuthenticator(totpUri)) setResult($("#test-result"), { ok: false, message: T("Na mobitelu nije instalirana aplikacija autentifikator (npr. Google Authenticator).") });
  },
  logout: async (btn) => {
    btn.disabled = true;
    const res = await callJava((id) => A.logout(id));
    btn.disabled = false;
    setResult($("#test-result"), { ok: res.ok, message: T(res.message) });
    renderAccount({ account: null });
  },
  save: () => {
    const f = collect();
    const res = JSON.parse(A.saveSettings(JSON.stringify(f)));
    showErrors(res.errors || {});
    if (!res.ok) { setResult($("#save-result"), { ok: false, message: T(res.message || "Provjerite označena polja.") }); return; }
    setResult($("#save-result"), { ok: true, message: T("Postavke su spremljene.") });
    setTimeout(() => A.openDashboard(), 400);
  },
  back: () => A.openDashboard(),
  demo: () => {
    // primjer podataka: bez adrese i ključa, odmah na dashboard
    const res = JSON.parse(A.saveSettings(JSON.stringify({ ...collect(), mode: "demo" })));
    if (res.ok) A.openDashboard();
    else showErrors(res.errors || {});
  },
  "report-show": async (btn) => {
    const [year, month] = $("#report-month").value.split("-").map(Number);
    btn.disabled = true;
    setResult($("#report-result"), null, T("Izrađujem izvještaj…"));
    try {
      const res = await fetch(`/api/v1/report?year=${year}&month=${month}`, { cache: "no-store" });
      if (!res.ok) throw new Error(res.status === 401 ? T("Poslužitelj je odbio API ključ.") : T("Poslužitelj je vratio grešku {code}.", { code: res.status }));
      report = await res.json();
      if (report.demo_template && window.SolariDemo) report = window.SolariDemo.report(report, year, month);  // demo način
      renderReport(report);
      $("#report-print").disabled = $("#report-csv").disabled = false;
      setResult($("#report-result"), { ok: true, message: "" });
    } catch (e) {
      setResult($("#report-result"), { ok: false, message: e.message || String(e) });
    } finally {
      btn.disabled = false;
    }
  },
  "report-print": () => A.print(`${report.plant} ${report.year}-${String(report.month).padStart(2, "0")}`),
  "report-csv": async () => {
    const name = `${report.plant}-${report.year}-${String(report.month).padStart(2, "0")}.csv`.replace(/[^\w.-]+/g, "_");
    const res = await callJava((id) => A.saveCsv(name, reportCsv(report), id));
    if (res.message) setResult($("#report-result"), { ok: res.ok, message: T(res.message) });
  },
};

document.addEventListener("click", (e) => {
  const btn = e.target.closest("[data-action]");
  if (btn && actions[btn.dataset.action]) { e.preventDefault(); actions[btn.dataset.action](btn); }
});
document.addEventListener("change", async (e) => {
  if (e.target.name === "mode") $("#source").dataset.mode = e.target.value;
  if (e.target.name === "palette") document.documentElement.dataset.theme = window.SolariColors.themeOf(e.target.value);
  if (e.target.id === "report-month") { report = null; $("#report").hidden = true; $("#report-print").disabled = $("#report-csv").disabled = true; }
  if (e.target.classList.contains("language-select")) {
    settings.form = collect();
    await loadLanguage(e.target.value);
    renderAll();
  }
});

(async function start() {
  settings = JSON.parse(A.getSettings());
  await loadLanguage(settings.language);
  renderAll();
})();

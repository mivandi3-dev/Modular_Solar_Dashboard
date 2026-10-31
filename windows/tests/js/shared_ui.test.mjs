// Testovi zajedničkog JS sučelja (Windows, Android, pregled iz mreže) – Node, bez ovisnosti:
//   node --test windows/tests/js/
// Skripte se učitavaju u izolirani vm kontekst s minimalnim `window` objektom (kao u pregledniku).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const WEB = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "web");

function load() {
  const ctx = { console, setTimeout, Intl, Date, Math, JSON, Number, String, Array, Object, RegExp, Map, Set, Promise };
  ctx.window = ctx;
  ctx.document = { documentElement: {}, addEventListener() {} };
  vm.createContext(ctx);
  for (const f of ["themes.js", "i18n.js", "components.js"]) {
    vm.runInContext(readFileSync(join(WEB, f), "utf8"), ctx, { filename: f });
  }
  // const UI u components.js nije svojstvo globalnog objekta – dohvat izrazom u istom kontekstu
  return { ctx, UI: vm.runInContext("UI", ctx) };
}

test("SMA-18: adresa logotipa s poslužitelja ne može ubaciti atribut ni skriptu", () => {
  const { UI } = load();
  const evil = ['x" onerror="window.pwned=1', "javascript:alert(1)", "data:text/html,<script>alert(1)</script>",
    "https://evil.example/logo.png", "https://app.solari/x\" onload=\"a()", "/api/v1/images/logo?v=1' onerror='x"];
  for (const u of evil) {
    const html = UI.siteCard(u, "Elektrana", "Grad", "Aktivna", "ok");
    assert.ok(!/onerror|onload|javascript:|<script/i.test(html), `ubačeno: ${u} → ${html}`);
    assert.ok(!html.includes("<img"), `slika s nedopuštenom adresom se ne prikazuje: ${u}`);
  }
});

test("SMA-18: dopuštene adrese slika se prikazuju", () => {
  const { UI } = load();
  for (const u of ["https://data.solari/logo.png?v=3", "https://app.solari/web/img/x.png", "/api/v1/images/logo?v=12", "blob:https://app.solari/1234"]) {
    assert.ok(UI.siteCard(u, "E", "G", "S", "ok").includes(`src="${u}"`), u);
  }
  assert.equal(UI.safeImageUrl(undefined), "");
  assert.equal(UI.safeImageUrl("https://data.solari/a b.png"), "");
});

test("SMA-18: pozadinska slika (CSS) ne može izaći iz url()", () => {
  const { UI } = load();
  const html = UI.heroBackground("https://data.solari/x.jpg'); background:url(https://evil.example/");
  assert.ok(!html.includes("evil.example"), html);
  assert.ok(UI.heroBackground("https://data.solari/hero.jpg?v=2").includes("url('https://data.solari/hero.jpg?v=2')"));
});

test("SMA-19: tekst s poslužitelja se escapira (naziv, lokacija, stanje)", () => {
  const { UI } = load();
  const html = UI.siteCard("", "<b>x</b>", "<img src=x onerror=alert(1)>", "<script>", "ok");
  assert.ok(!html.includes("<img src=x"));
  assert.ok(!html.includes("<script>"));
  assert.ok(html.includes("&lt;img src=x onerror=alert(1)&gt;"));
  assert.equal(UI.esc(`"'<>&`), "&quot;&#39;&lt;&gt;&amp;");
});

test("T(): nepoznat ključ ostaje izvorni tekst, varijable se umeću", () => {
  const { ctx } = load();
  assert.equal(ctx.T("Nepoznat tekst {n}", { n: 3 }), "Nepoznat tekst 3");
});

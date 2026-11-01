// Teme ikona (web/icons.js): classic | neon | iconset – Node, bez ovisnosti:
//   node --test windows/tests/js/
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const WEB = join(ROOT, "web");
const require = createRequire(import.meta.url);
const Icons = require(join(WEB, "icons.js"));  // bez document → setTheme samo mijenja temu

test("svaka tema ima ikonu za svaki ključ", () => {
  for (const key of Icons.keys()) {
    assert.ok(key in Icons._emoji, `emoji: ${key}`);
    assert.ok(Icons._neon[key], `neon: ${key}`);
  }
  assert.deepEqual(Icons.THEMES, ["classic", "neon", "iconset"]);
});

test("iconset: svaki ključ kompleta ima PNG, a u mapi nema datoteka izvan kompleta", () => {
  const dir = join(WEB, "icons", "iconset");
  for (const key of Icons._iconset) {
    assert.ok(Icons.keys().includes(key), `nepoznat ključ ${key}`);
    const file = join(dir, `${key}.png`);
    assert.ok(existsSync(file), file);
    assert.deepEqual([...readFileSync(file).subarray(0, 4)], [0x89, 0x50, 0x4e, 0x47], `${key}.png nije PNG`);
  }
  assert.deepEqual(readdirSync(dir).sort(), Icons._iconset.map((k) => `${k}.png`).sort());
});

test("iconset: pregled iz mreže smije poslužiti sve PNG ikone kompleta (remote.cpp popis)", () => {
  const cpp = readFileSync(join(ROOT, "src", "remote.cpp"), "utf8");
  for (const key of Icons._iconset) assert.ok(cpp.includes(`"icons/iconset/${key}.png"`), key);
});

test("get(): classic → emoji, neon → svg, iconset → img ili neon zamjena", () => {
  Icons.setTheme("classic");
  assert.equal(Icons.get("sun"), "☀️");
  Icons.setTheme("neon");
  assert.match(Icons.get("sun"), /^<svg class="nx-ico"/);
  Icons.setTheme("iconset");
  assert.equal(Icons.theme(), "iconset");
  assert.equal(Icons.get("sun"), '<img class="ix-ico" src="icons/iconset/sun.png" alt="" aria-hidden="true" draggable="false">');
  assert.match(Icons.get("moon"), /^<svg class="nx-ico"/, "ključ bez PNG-a → neon SVG");
  assert.match(Icons.svgInner("battery"), /^<image href="icons\/iconset\/battery\.png"/);
  assert.match(Icons.svgInner("moon"), /^<path/);
  Icons.setTheme("nepostojeca");
  assert.equal(Icons.theme(), "classic", "nepoznata tema → classic");
  assert.equal(Icons.get("nepostojeci"), "");
});

test("Android i C++ prihvaćaju iste teme kao icons.js", () => {
  const java = readFileSync(join(ROOT, "..", "android", "app", "src", "main", "java", "hr", "ivandic", "solarnimonitor", "Prefs.java"), "utf8");
  assert.match(java, /ICON_THEMES = \{"classic", "neon", "iconset"\}/);
  const cpp = readFileSync(join(ROOT, "src", "config.cpp"), "utf8");
  assert.match(cpp, /key == "classic" \|\| key == "neon" \|\| key == "iconset"/);
});

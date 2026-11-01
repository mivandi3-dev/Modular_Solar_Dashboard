"""Svi prikazi Android aplikacije: mobitel i tablet × uspravno i položeno, postavke (tunel/lokalno, greške,
spremanje, izvještaj), dashboard sa svih 27 widgeta na dvije stranice, izbornik, popis widgeta; više jezika i tema.
Na svakom prikazu traži tekst koji izlazi preko ruba ekrana ili svoje kartice."""
import asyncio
import json
import os
import re
import subprocess
import time
import urllib.request
from pathlib import Path

import websockets

SP = Path(__file__).parent
OUT = SP / "shots" / "all"
OUT.mkdir(parents=True, exist_ok=True)
ADB = str(Path(os.environ["LOCALAPPDATA"]) / "Android" / "Sdk" / "platform-tools" / "adb.exe")
PKG = "hr.ivandic.solarnimonitor"
APK = r"C:\solari\android\app\build\outputs\apk\debug\app-debug.apk"
CDP, PORT = 9566, 8700
LOCAL = f"http://10.0.2.2:{PORT}"
_ENV = next(p for p in (Path(r"C:\ProgramData\SolarniServer\.env"), SP / "home_server_test" / ".env") if p.exists())
KEY = [l.split("=", 1)[1].strip() for l in _ENV.read_text(encoding="utf-8-sig").splitlines()
       if l.startswith("SOLARI_API_KEY")][0]
TUNNEL = "https://nepostojeci-tunel-za-test-solarnog-monitora.trycloudflare.com"
fails, notes = [], []


def adb(*a, check=True):
    return subprocess.run([ADB, *a], capture_output=True, check=check)


def shot(name):
    (OUT / f"{name}.png").write_bytes(adb("exec-out", "screencap", "-p").stdout)


def connect():
    for _ in range(60):
        m = re.findall(r"@(webview_devtools_remote_\d+)", adb("shell", "cat", "/proc/net/unix").stdout.decode(errors="replace"))
        if m:
            adb("forward", f"tcp:{CDP}", f"localabstract:{m[-1]}")
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{CDP}/json", timeout=3).read()
                return
            except OSError:
                pass
        time.sleep(0.5)
    raise RuntimeError("nema WebView socketa")


async def _js(expr):
    tabs = json.loads(urllib.request.urlopen(f"http://127.0.0.1:{CDP}/json").read())
    page = [t for t in tabs if t["type"] == "page"][0]
    async with websockets.connect(page["webSocketDebuggerUrl"], max_size=50_000_000) as ws:
        await ws.send(json.dumps({"id": 1, "method": "Runtime.evaluate",
                                  "params": {"expression": expr, "returnByValue": True, "awaitPromise": True}}))
        while True:
            m = json.loads(await ws.recv())
            if m.get("id") == 1:
                r = m["result"]
                if "exceptionDetails" in r:
                    raise RuntimeError(r["exceptionDetails"].get("exception", {}).get("description"))
                return r["result"].get("value")


def js(expr):
    for attempt in range(3):
        try:
            return asyncio.run(_js(expr))
        except (OSError, websockets.exceptions.WebSocketException, IndexError):
            time.sleep(2)
            connect()
    return asyncio.run(_js(expr))


def check(ctx, name, ok, detail=""):
    if not ok:
        fails.append(f"{ctx}: {name} {detail}")
    print(("    OK  " if ok else "    NE  ") + name + ("" if ok else f"  {detail}"))


# vidljivi tekst koji izlazi preko ekrana ili svoje kartice (2 px tolerancije)
OVERFLOW = r"""(() => {
  const vw = innerWidth, out = [];
  const box = (el) => el.closest('.card, .glass, fieldset, .item, #am-menu, [class^="st-key-w-"], .bar, .kpi');
  for (const el of document.querySelectorAll('body *')) {
    if (!el.offsetParent && getComputedStyle(el).position !== 'fixed') continue;
    if (el.closest('#am-panel:not(.show), #am-menu:not(.show), #solari-help, #solari-night, .hero-bg-layer, svg, .plot, [hidden]')) continue;
    const own = [...el.childNodes].some(n => n.nodeType === 3 && n.textContent.trim());
    if (!own && !['INPUT', 'SELECT', 'BUTTON'].includes(el.tagName)) continue;
    const r = el.getBoundingClientRect();
    if (!r.width || !r.height) continue;
    const st = getComputedStyle(el);
    if (st.visibility === 'hidden' || +st.opacity === 0) continue;
    let bad = r.right > vw + 2 || r.left < -2 ? 'ekran' : '';
    const b = box(el.parentElement || el);
    if (!bad && b && b !== el) { const q = b.getBoundingClientRect(); if (r.right > q.right + 2 || r.left < q.left - 2) bad = 'kartica'; }
    if (bad) out.push(`${bad}: <${el.tagName.toLowerCase()} ${el.className || el.id || ''}> "${(el.textContent || el.value || '').trim().slice(0, 50)}" ${Math.round(r.left)}–${Math.round(r.right)} / ${vw}`);
  }
  if (document.documentElement.scrollWidth > vw + 2) out.unshift(`stranica šira od ekrana: ${document.documentElement.scrollWidth} > ${vw}`);
  return out.slice(0, 8);
})()"""


def no_overflow(ctx, what):
    o = js(OVERFLOW)
    check(ctx, f"ništa ne izlazi preko ruba – {what}", not o, "; ".join(o))


def wait_result(sel, timeout=30):
    end = time.time() + timeout
    while time.time() < end:
        r = js(f"(() => {{ const e = document.querySelector('{sel}'); return [e.className, e.textContent]; }})()")
        if "busy" not in r[0] and r[1].strip():
            return r
        time.sleep(1)
    return r


def open_settings():
    if "settings-android" not in js("location.href"):
        js("window.pywebview.api.open_settings(); 1")
        time.sleep(4)
        connect()
    for _ in range(20):
        if js("!!(document.querySelector('.language-select') && document.querySelector('.language-select').options.length)"):
            return
        time.sleep(0.5)


def set_form(lang, theme, mode, url, key):
    js(f"""(() => {{
      const ls = document.querySelector('.language-select');
      if (ls.value !== '{lang}') {{ ls.value = '{lang}'; ls.dispatchEvent(new Event('change', {{ bubbles: true }})); }}
      return 1; }})()""")
    time.sleep(1.2)
    js(f"""(() => {{
      document.querySelector('input[name=theme][value={theme}]').click();
      document.querySelector('input[name=mode][value={mode}]').click();
      document.querySelector('[data-field={"cloud_url" if mode == "cloud" else "local_url"}]').value = {json.dumps(url)};
      document.getElementById('api_key').value = {json.dumps(key)};
      return 1; }})()""")


def test_connection(ctx, label, expect_ok):
    js("document.querySelector('[data-action=test]').click(); 1")
    cls, text = wait_result("#test-result")
    print(f"    [{label}] {text}")
    check(ctx, f"provjera veze – {label}", ("ok" in cls) == expect_ok, f"({cls}) {text}")
    js("document.querySelector('.test').scrollIntoView({block: 'center'}); 1")
    time.sleep(0.4)
    no_overflow(ctx, f"poruka provjere ({label})")
    return text


def settings_suite(ctx, lang, theme):
    print(f"  postavke ({lang}, {theme})")
    open_settings()
    set_form(lang, theme, "cloud", TUNNEL, KEY)
    no_overflow(ctx, "postavke")
    shot(f"{ctx}_s0_top")
    test_connection(ctx, "tunel: adresa ne postoji", False)
    shot(f"{ctx}_s1_tunel")
    set_form(lang, theme, "cloud", "http://nije-https.primjer.hr", KEY)
    test_connection(ctx, "tunel: adresa bez https", False)
    set_form(lang, theme, "local", LOCAL, "pogresan-kljuc-0123456789abcdef0123")
    test_connection(ctx, "pogrešan ključ", False)
    set_form(lang, theme, "local", LOCAL, KEY)
    test_connection(ctx, "lokalno: uspjeh", True)
    shot(f"{ctx}_s2_ok")
    set_form(lang, theme, "cloud", "", "")
    js("document.querySelector('[data-action=save]').click(); 1")
    time.sleep(0.8)
    errs = js("[...document.querySelectorAll('[data-error]')].map(e => e.textContent).filter(Boolean)")
    print(f"    [prazna polja] {errs}")
    check(ctx, "spremanje bez adrese tunela javlja grešku adrese", any("https://" in e for e in errs), str(errs))
    check(ctx, "spremanje bez adrese ostaje u postavkama", "settings-android" in js("location.href"))
    no_overflow(ctx, "greške polja i poruka spremanja")
    shot(f"{ctx}_s3_errors")
    set_form(lang, theme, "local", LOCAL, KEY)
    js("document.querySelector('[data-action=save]').click(); 1")
    time.sleep(10)
    connect()


def report_suite(ctx):
    open_settings()
    js("""(() => { const m = document.querySelector('#report-month'); m.value = m.options[1].value;
      m.dispatchEvent(new Event('change', { bubbles: true })); document.querySelector('[data-action="report-show"]').click(); return 1; })()""")
    cls, text = wait_result("#report-result")
    shown = js("!document.getElementById('report').hidden && document.querySelectorAll('#report table tr').length")
    check(ctx, "izvještaj prikazan", bool(shown), f"({cls}) {text}")
    js("document.getElementById('report').scrollIntoView(); 1")
    time.sleep(0.5)
    no_overflow(ctx, "izvještaj")
    shot(f"{ctx}_r_report")
    js("document.querySelector('[data-action=back]').click(); 1")
    time.sleep(8)
    connect()


ALL_WIDGETS = """(async () => {
  const cat = await (await fetch('catalog.json')).json();
  const mk = (s, i) => ({ id: s.key.replace(/_/g, '-') + '-t', type: s.key, x: 0, y: i, w: s.size[0], h: s.size[1],
    options: Object.fromEntries(s.options.map(o => [o.key, o.default])) });
  const half = Math.ceil(cat.widgets.length / 2);
  const pages = [cat.widgets.slice(0, half).map(mk), cat.widgets.slice(half).map(mk)];
  localStorage.setItem('solari.pages', JSON.stringify({ pages, rotateS: 0 }));
  return cat.widgets.length;
})()"""


def dashboard_suite(ctx, portrait):
    print("  dashboard")
    if "index.html" not in js("location.href"):
        js("location.href = 'index.html'; 1")
        time.sleep(8)
        connect()
    n = js(ALL_WIDGETS)
    js("location.reload(); 1")
    time.sleep(10)
    connect()
    time.sleep(3)
    for page in (0, 1):
        js(f"window.SolariPages.edit({page}); 1")
        time.sleep(1.5)
        r = js(f"""(() => {{
          const g = document.querySelector('.st-key-grid-p{page}');
          const ws = [...g.children].filter(e => e.className.startsWith('st-key-w-')).map(e => e.getBoundingClientRect());
          return {{ n: ws.length, widths: [...new Set(ws.map(r => Math.round(r.width)))], cols: new Set(ws.map(r => Math.round(r.left))).size,
            errors: [...g.querySelectorAll('.widget-error')].map(e => e.textContent), vw: innerWidth }}; }})()""")
        print(f"    stranica {page + 1}: {r}")
        check(ctx, f"stranica {page + 1}: svi widgeti iste širine", len(r["widths"]) == 1)
        check(ctx, f"stranica {page + 1}: {'jedan stupac' if portrait else 'više stupaca'}",
              r["cols"] == 1 if portrait else r["cols"] >= 2, str(r["cols"]))
        check(ctx, f"stranica {page + 1}: nijedan widget s greškom", not r["errors"], str(r["errors"]))
        h = js("document.documentElement.scrollHeight")
        for k, y in enumerate(range(0, h, js("innerHeight"))):
            js(f"window.scrollTo(0, {y}); 1")
            time.sleep(0.5)
            no_overflow(ctx, f"stranica {page + 1}, dio {k + 1}")
            if k < 6:
                shot(f"{ctx}_d{page + 1}_{k + 1}")
        js("window.scrollTo(0, 0); 1")
    js("window.SolariPages.stopEdit(); window.SolariPages.edit(0); 1")
    check(ctx, "svih 27 widgeta u katalogu", n == 27, str(n))
    print("  izbornik i popis widgeta")
    js("document.getElementById('am-burger').click(); 1")
    time.sleep(0.4)
    no_overflow(ctx, "izbornik")
    shot(f"{ctx}_m1_menu")
    js("document.querySelector('#am-menu [data-go=widgets]').click(); 1")
    time.sleep(1)
    no_overflow(ctx, "popis widgeta")
    shot(f"{ctx}_m2_panel")
    tabs = js("document.querySelectorAll('#am-panel .tabs button').length")
    check(ctx, "kartice stranica u popisu", tabs == 2, str(tabs))
    js("document.querySelector('#am-panel .tabs button[data-page=\"1\"]').click(); document.querySelector('#am-panel [data-act=add]').click(); 1")
    time.sleep(0.5)
    hint = js("document.querySelector('#am-panel .add').innerText")
    check(ctx, "dodavanje: svi su već na ekranu", "27" not in hint and len(hint) < 80, hint[:80])
    js("document.querySelector('#am-panel .item [data-act=rm]').click(); 1")
    time.sleep(1)
    js("document.querySelector('#am-panel [data-act=add]').click(); 1")
    time.sleep(0.5)
    no_overflow(ctx, "popis za dodavanje")
    shot(f"{ctx}_m3_add")
    js("document.querySelector('#am-panel [data-act=close]').click(); 1")


def run(ctx, size, density, rotation, lang, theme):
    print(f"\n=== {ctx}: {size or 'mobitel'} {'uspravno' if rotation == 0 else 'položeno'}, {lang}, {theme}")
    adb("shell", "wm", "size", size or "reset")
    adb("shell", "wm", "density", density or "reset")
    adb("shell", "settings", "put", "system", "user_rotation", str(rotation))
    adb("shell", "am", "force-stop", PKG)
    adb("shell", "am", "start", "-n", f"{PKG}/.MainActivity")
    time.sleep(9)
    connect()
    vp = js("[innerWidth, innerHeight, document.querySelector('meta[name=viewport]').content, location.pathname]")
    print("    viewport", vp)
    if vp[3].endswith("index.html"):
        check(ctx, "prvo učitavanje: viewport prema položaju", vp[0] == 820 if rotation == 0 else vp[0] >= 1920, str(vp))
    settings_suite(ctx, lang, theme)
    dashboard_suite(ctx, rotation == 0)
    report_suite(ctx)


if __name__ == "__main__":
    adb("shell", "settings", "put", "system", "accelerometer_rotation", "0")
    adb("uninstall", PKG, check=False)
    print("instalacija:", adb("install", "-r", APK).stdout.decode().strip())
    try:
        run("mob-u-de", None, None, 0, "de", "dark")
        run("mob-p-hr", None, None, 1, "hr", "light")
        run("tab-u-en", "1600x2560", "320", 0, "en", "dark")
        run("tab-p-ja", "1600x2560", "320", 1, "ja", "dark")
    finally:
        adb("shell", "wm", "size", "reset")
        adb("shell", "wm", "density", "reset")
        adb("shell", "settings", "put", "system", "user_rotation", "0")
        adb("shell", "settings", "put", "system", "accelerometer_rotation", "1")
    log = adb("logcat", "-d", "-s", "chromium:E", "AndroidRuntime:E").stdout.decode(errors="replace").strip().splitlines()
    log = [l for l in log if "variations_seed" not in l and not l.startswith("-----")]
    print("\nlogcat greške:", log[-8:] if log else "nema")
    print("\nNEUSPJELO (%d):" % len(fails) if fails else "\nSVE PROŠLO")
    for f in fails:
        print("  -", f)

"""Dim-test INSTALIRANOG klijenta (Program Files) kao običnog korisnika: prozor mora iscrtati dashboard (5.0.1: profil
WebView2 u mapi samo za čitanje → prazan prozor), a Alt+Enter mora uključiti i isključiti cijeli zaslon.
Pokretanje bez administratorskih prava, dok aplikacija nije otvorena:  python installed_gui_smoke.py
Rezultat: reports\\installed-gui-smoke.txt (+ snimka reports\\screenshots\\installed-gui.png)."""
import asyncio
import json
import subprocess
import sys
import time
from pathlib import Path

import websockets

SP = Path(__file__).parent
sys.path.insert(0, str(SP))
import cdp  # noqa: E402

APP = Path(r"C:\Program Files\Solarni monitor 2\SolarniMonitor.exe")
OUT = Path(r"C:\Modularnisolarnidashboard40\reports")
results = []


def check(name, ok, detail=""):
    results.append(("PASS " if ok else "FAIL ") + name + ("" if ok else f" -- {detail}"))
    print(results[-1], flush=True)


async def key_alt_enter(ws_url):
    async with websockets.connect(ws_url, max_size=50_000_000) as ws:
        n = 0
        for typ in ("rawKeyDown", "keyUp"):
            n += 1
            await ws.send(json.dumps({"id": n, "method": "Input.dispatchKeyEvent", "params": {
                "type": typ, "modifiers": 1, "key": "Enter", "code": "Enter", "windowsVirtualKeyCode": 13}}))
            while json.loads(await ws.recv()).get("id") != n:
                pass


def main():
    if not APP.exists():
        apps = list(Path(r"C:\Program Files").glob(r"Solarni monitor*\SolarniMonitor.exe"))
        if not apps:
            check("instalirani klijent postoji", False, "nema SolarniMonitor.exe u Program Files")
            return
        app = apps[0]
    else:
        app = APP
    env = {**__import__("os").environ, "WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS": f"--remote-debugging-port={cdp.PORT}"}
    gui = subprocess.Popen([str(app)], env=env)
    try:
        main_t = cdp.wait_target("index.html", timeout=60)
        check("prozor je učitao index.html", True)
        ok = False
        for _ in range(30):
            state = cdp.js(main_t, "JSON.stringify({hero: !!document.querySelector('.hero'), cards: document.querySelectorAll('.card, .glass').length,"
                                   " text: (document.body.innerText || '').length})")
            info = json.loads(state) if isinstance(state, str) else {}
            if info.get("cards", 0) > 0 and info.get("text", 0) > 50:
                ok = True
                break
            time.sleep(1)
        check("dashboard je iscrtan (kartice i tekst, nije prazan prozor)", ok, state)
        (OUT / "screenshots").mkdir(parents=True, exist_ok=True)
        asyncio.run(cdp._capture(main_t["webSocketDebuggerUrl"], OUT / "screenshots" / "installed-gui.png"))
        before = cdp.js(main_t, "window.pywebview.api.window_state().then(s => JSON.stringify(s))")
        asyncio.run(key_alt_enter(main_t["webSocketDebuggerUrl"]))
        time.sleep(1.5)
        after = cdp.js(main_t, "window.pywebview.api.window_state().then(s => JSON.stringify(s))")
        asyncio.run(key_alt_enter(main_t["webSocketDebuggerUrl"]))
        time.sleep(1.5)
        back = cdp.js(main_t, "window.pywebview.api.window_state().then(s => JSON.stringify(s))")
        fs = lambda s: json.loads(s).get("fullscreen") if isinstance(s, str) and s.startswith("{") else None  # noqa: E731
        check("Alt+Enter uključuje cijeli zaslon", fs(before) is False and fs(after) is True, f"{before} → {after}")
        check("Alt+Enter isključuje cijeli zaslon", fs(back) is False, back)
    except Exception as e:  # noqa: BLE001
        check("dim-test bez iznimke", False, repr(e))
    finally:
        gui.terminate()
        try:
            gui.wait(10)
        except subprocess.TimeoutExpired:
            gui.kill()
    (OUT / "installed-gui-smoke.txt").write_text("\n".join(results) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()

"""Mali CDP klijent: pokreće C++ aplikaciju s remote debuggingom, izvršava JS i snima zaslon."""
import asyncio
import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import websockets
from PIL import ImageGrab

SP = Path(__file__).parent
EXE = Path(r"C:\solari\verzija2\build\SolarniMonitor.exe")
PORT = 9333


def launch(home: Path, extra_env=None):
    env = {**os.environ, "SOLARI2_HOME": str(home), "SOLARI2_DEBUG": "1",
           "WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS": f"--remote-debugging-port={PORT}", **(extra_env or {})}
    return subprocess.Popen([str(EXE)], env=env)


def targets():
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{PORT}/json", timeout=2) as r:
            return json.loads(r.read())
    except OSError:
        return []


def wait_target(substr, timeout=40):
    end = time.time() + timeout
    while time.time() < end:
        for t in targets():
            if t.get("type") == "page" and substr in t.get("url", ""):
                return t
        time.sleep(0.5)
    raise TimeoutError(f"nema stranice {substr}: {[t.get('url') for t in targets()]}")


async def _eval(ws_url, expr, await_promise=True):
    async with websockets.connect(ws_url, max_size=50_000_000) as ws:
        await ws.send(json.dumps({"id": 1, "method": "Runtime.evaluate",
                                  "params": {"expression": expr, "awaitPromise": await_promise, "returnByValue": True}}))
        while True:
            msg = json.loads(await ws.recv())
            if msg.get("id") == 1:
                res = msg["result"]
                if "exceptionDetails" in res:
                    return {"EXCEPTION": res["exceptionDetails"].get("exception", {}).get("description")}
                return res["result"].get("value")


def js(target, expr):
    return asyncio.run(_eval(target["webSocketDebuggerUrl"], expr))


def shot(name):
    time.sleep(0.4)
    ImageGrab.grab(all_screens=True).save(SP / "shots" / f"{name}.png")
    print("shot", name, flush=True)


async def _capture(ws_url, path):
    import base64
    async with websockets.connect(ws_url, max_size=100_000_000) as ws:
        await ws.send(json.dumps({"id": 1, "method": "Page.captureScreenshot", "params": {"format": "png"}}))
        while True:
            msg = json.loads(await ws.recv())
            if msg.get("id") == 1:
                Path(path).write_bytes(base64.b64decode(msg["result"]["data"]))
                return


def capture(target, name):
    asyncio.run(_capture(target["webSocketDebuggerUrl"], SP / "shots" / f"{name}.png"))
    print("capture", name, flush=True)

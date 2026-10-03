#!/usr/bin/env python3
"""Drive a Chrome that actually logs WebAuthn/CTAP, and dump what it sends.

The chrome-devtools-mcp browser is launched without --enable-logging (see
chrome://version), so chrome://device-log is always empty and the CTAP
exchange is invisible.  This launches a second Chrome on its own profile and
port with FIDO/WebAuthn logging on, drives the demo.yubico.com registration
with CDP, and leaves the log for inspection.

  chrome --remote-debugging-port=9333 --enable-logging --v=1 \\
         --vmodule=*/device/fido/*=3,*/webauthn*/*=3,*/authenticator*/*=3 \\
         --log-file=/tmp/chrome-wa.log --user-data-dir=/tmp/chrome-wa-profile

Usage: drive_logging_chrome.py [url] [seconds_to_observe]
"""
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.request

import websockets

PORT = 9333
PROFILE = "/tmp/chrome-wa-profile"
LOGFILE = "/tmp/chrome-wa.log"
URL = sys.argv[1] if len(sys.argv) > 1 else \
    "https://demo.yubico.com/webauthn-technical/registration"
OBSERVE = int(sys.argv[2]) if len(sys.argv) > 2 else 60

HOOK = r"""
(function () {
  const log = []; window.__waLog = log;
  function show(o){ try { return JSON.stringify(o); } catch(e){ return String(o); } }
  const orig = navigator.credentials.create.bind(navigator.credentials);
  navigator.credentials.create = function (opts) {
    const a = opts.publicKey.authenticatorSelection || {};
    console.log('[WATRACE] create uv=' + a.userVerification + ' rk=' + a.residentKey
                + ' mediation=' + opts.mediation + ' options=' + show(opts.publicKey.authenticatorAttachment));
    log.push('create');
    return orig(opts).then(function (c) {
      const r = c.response, ad = r.authenticatorData;
      const b = new Uint8Array(ad.buffer, ad.byteOffset, ad.byteLength);
      console.log('[WATRACE] OK flags=0x' + b[32].toString(16)
                  + ' UP=' + !!(b[32] & 1) + ' UV=' + !!(b[32] & 4)
                  + ' aaguid=' + Array.from(b.slice(37,53)).map(x=>x.toString(16).padStart(2,'0')).join(''));
      log.push('ok');
      return c;
    }, function (e) {
      console.log('[WATRACE] FAIL ' + e.name + ': ' + e.message);
      log.push('fail:' + e.name);
      throw e;
    });
  };
})();
"""


def launch():
    if os.path.isdir(PROFILE):
        shutil.rmtree(PROFILE, ignore_errors=True)
    for p in (LOGFILE,):
        if os.path.exists(p):
            os.remove(p)
    args = [
        "/opt/google/chrome/chrome",
        f"--remote-debugging-port={PORT}",
        "--user-data-dir=" + PROFILE,
        "--no-first-run", "--no-default-browser-check",
        "--disable-features=Translate",
        "--enable-logging", "--v=1",
        "--vmodule=*/device/fido/*=3,*/webauthn*/*=3,*/web_auth*/*=3,"
                  "*/authenticator*/*=3,*/content/browser/webauth/*=3,"
                  "*/device_event_log/*=1,",
        "--log-file=" + LOGFILE,
        "--ozone-platform=x11",
        "about:blank",
    ]
    return subprocess.Popen(args, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)


def wait_for_port(timeout=30):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(
                    f"http://127.0.0.1:{PORT}/json/version", timeout=2) as r:
                json.load(r)
                return True
        except Exception:  # noqa: BLE001
            time.sleep(0.5)
    return False


def new_tab(url):
    req = urllib.request.Request(
        f"http://127.0.0.1:{PORT}/json/new?{urllib.parse.quote(url, safe='')}",
        method="PUT")
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.load(r)


async def drive(ws_url):
    async with websockets.connect(ws_url, max_size=2**24) as ws:
        n = 0

        async def send(method, params=None):
            nonlocal n
            n += 1
            await ws.send(json.dumps({"id": n, "method": method,
                                      "params": params or {}}))
            while True:
                msg = json.loads(await ws.recv())
                if msg.get("id") == n:
                    if "error" in msg:
                        raise RuntimeError(msg["error"])
                    return msg.get("result", {})

        await send("Page.enable")
        await send("Runtime.enable")
        await send("Log.enable")
        await send("Page.addScriptToEvaluateOnNewDocument", {"source": HOOK})
        await send("Page.navigate", {"url": URL})
        await asyncio.sleep(12)

        # Click NEXT.
        res = await send("Runtime.evaluate", {
            "expression": """(() => {
                const b = Array.from(document.querySelectorAll('button'))
                    .find(x => /next/i.test(x.textContent));
                if (!b) return 'NO NEXT BUTTON: ' + document.body.innerText.slice(0,200);
                b.click(); return 'clicked';
            })()""",
            "returnByValue": True})
        print("NEXT ->", res.get("result", {}).get("value"))

        print(f"observing for {OBSERVE}s (a PIN dialog is browser UI; watch the "
              f"board LED)...")
        start = time.time()
        while time.time() - start < OBSERVE:
            try:
                raw = await asyncio.wait_for(ws.recv(), timeout=3)
            except asyncio.TimeoutError:
                continue
            msg = json.loads(raw)
            m = msg.get("method")
            if m == "Runtime.consoleAPICalled":
                p = msg["params"]
                txt = " ".join(str(a.get("value", a.get("description", "")))
                               for a in p.get("args", []))
                print(f"  [console.{p.get('type')}] {txt[:300]}")
            elif m == "Runtime.exceptionThrown":
                d = msg["params"]["exceptionDetails"]
                print("  [exception]", d.get("text"), d.get("exception", {})
                      .get("description", "")[:200])
            elif m == "Log.entryAdded":
                e = msg["params"]["entry"]
                print(f"  [log.{e.get('level')}] {e.get('text', '')[:300]}")
            elif m == "Page.frameNavigated":
                print("  [nav]", msg["params"]["frame"].get("url", "")[:120])


if __name__ == "__main__":
    import asyncio
    import urllib.parse

    proc = launch()
    if not wait_for_port():
        print("chrome did not come up on port", PORT)
        sys.exit(1)
    print("chrome up; log ->", LOGFILE)
    tab = new_tab(URL)
    try:
        asyncio.run(drive(tab["webSocketDebuggerUrl"]))
    finally:
        time.sleep(1)
        proc.terminate()
    print("\n--- FIDO / CTAP lines from", LOGFILE)
    try:
        with open(LOGFILE, errors="replace") as fh:
            for line in fh:
                low = line.lower()
                if any(k in low for k in ("fido", "ctap", "webauthn", "web_auth",
                                          "authenticator", "pin_uv", "pinuv",
                                          "credential", "usb", "hid")):
                    print("   ", line.rstrip()[:240])
    except FileNotFoundError:
        print("    (no log file)")
#!/usr/bin/env python3
"""End-to-end test of the app in a real browser, served from localhost.

Suno's license server only allows CORS from suno.com and from
http://localhost:<port>, so the app has to run on the visitor's own machine.
This test serves site/ on localhost and drives Chromium through the whole
flow for every supported link type.
"""
import base64
import http.server
import json
import os
import socketserver
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SITE = os.path.join(ROOT, "site")
CLIP = "985f338b-79b2-47f8-8c5f-34eb864a5d0f"

PORT = 8801

CASES = [
    ("cloudfront", f"https://d2lwuy8qc234o3.cloudfront.net/1/clip/{CLIP}.m4a"),
    ("song page", f"https://suno.com/song/{CLIP}"),
    ("share link", "https://suno.com/s/lN26vGvSMqnWMss5"),
]

CHROME = next(
    (p for p in ("/usr/bin/chromium", "/usr/bin/chromium-browser",
                 "/usr/bin/google-chrome") if os.path.exists(p)),
    None,
)


class Handler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *a):
        pass


def serve():
    os.chdir(SITE)
    socketserver.TCPServer.allow_reuse_address = True
    # threaded: the browser keeps connections alive, a serial server would
    # block the next request behind an idle one.
    httpd = socketserver.ThreadingTCPServer(("127.0.0.1", PORT), Handler)
    httpd.daemon_threads = True
    httpd.serve_forever()


def grab_mp3(page):
    b64 = page.evaluate("""async () => {
        const r = await fetch(document.getElementById('dl').href);
        const b = new Uint8Array(await r.arrayBuffer());
        let s = '';
        for (let i = 0; i < b.length; i += 0x8000)
            s += String.fromCharCode.apply(null, b.subarray(i, i + 0x8000));
        return btoa(s);
    }""")
    return base64.b64decode(b64)


def main() -> int:
    from playwright.sync_api import sync_playwright

    threading.Thread(target=serve, daemon=True).start()
    time.sleep(1)

    failures = []
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(
                executable_path=CHROME,
                args=[
                    "--autoplay-policy=no-user-gesture-required",
                    "--no-sandbox",
                    "--disable-dev-shm-usage",
                ],
            )
            page = browser.new_page()
            console = []
            page.on("console", lambda m: console.append(f"{m.type}: {m.text}"))
            page.on("pageerror", lambda e: console.append(f"pageerror: {e}"))

            for name, link in CASES:
                print(f"\n  --- case: {name} ---")
                page.goto(f"http://localhost:{PORT}/", wait_until="load")

                # the local-run banner must stay hidden on localhost
                if page.is_visible("#banner"):
                    failures.append(f"{name}: banner shown on localhost")

                page.fill("#url", link)
                page.click("#go")

                try:
                    page.wait_for_selector("#result:not(.hidden)", timeout=240_000)
                except Exception:
                    err = page.inner_text("#errmsg") if page.is_visible("#error") else ""
                    failures.append(f"{name}: no result ({err})")
                    print(f"  FAILED: {err}")
                    continue

                print(f"  result       : {page.inner_text('#meta')}")
                mp3 = grab_mp3(page)
                out = f"/tmp/opencode/browser_{name.replace(' ', '_')}.mp3"
                with open(out, "wb") as fh:
                    fh.write(mp3)
                print(f"  blob         : {len(mp3)} bytes -> {out}")

                if b"ID3" not in mp3[:4] and not mp3.startswith(b"\xff\xfb"):
                    failures.append(f"{name}: blob does not look like an MP3")

                p = subprocess.run(
                    ["ffprobe", "-v", "error", "-show_entries",
                     "format=duration", "-show_entries",
                     "stream=codec_name", "-of", "json", out],
                    capture_output=True, text=True,
                )
                if p.returncode != 0:
                    failures.append(f"{name}: ffprobe failed: {p.stderr[:200]}")
                else:
                    info = json.loads(p.stdout)
                    codec = info["streams"][0]["codec_name"]
                    dur = float(info["format"]["duration"])
                    print(f"  verified     : codec={codec} duration={dur:.1f}s")
                    if codec != "mp3":
                        failures.append(f"{name}: codec is {codec}")
                    if dur < 10:
                        failures.append(f"{name}: duration {dur}s too short")

            # 127.0.0.1 is NOT in Suno's CORS allowlist (only "localhost"),
            # so the banner must appear there.
            page.goto(f"http://127.0.0.1:{PORT}/", wait_until="load")
            if page.is_visible("#banner"):
                print("\n  banner shown on a non-localhost origin: ok")
            else:
                failures.append("banner did not appear on a foreign origin")

            browser.close()
    finally:
        pass

    if console:
        print("\n  browser console:")
        for c in console[-12:]:
            print(f"      {c}")

    print()
    if failures:
        print("FAILURES:")
        for f in failures:
            print(f"  - {f}")
        return 1
    print(f"all {len(CASES)} browser cases passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())

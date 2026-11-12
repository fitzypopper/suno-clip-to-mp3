#!/usr/bin/env python3
"""End-to-end test against the LIVE deployed site.

This is the test that matters: it loads the published GitHub Pages URL in a
real browser, exactly like a visitor with nothing installed, and converts a
clip through the Cloudflare Worker relay.
"""
import base64
import json
import os
import subprocess
import sys

LIVE = "https://fitzypopper.dpdns.org/suno-clip-to-mp3/"
CLIP = "985f338b-79b2-47f8-8c5f-34eb864a5d0f"

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


def main() -> int:
    from playwright.sync_api import sync_playwright

    failures = []
    with sync_playwright() as pw:
        browser = pw.chromium.launch(
            executable_path=CHROME,
            args=["--autoplay-policy=no-user-gesture-required",
                  "--no-sandbox", "--disable-dev-shm-usage"],
        )
        page = browser.new_page()
        console = []
        page.on("console", lambda m: console.append(f"{m.type}: {m.text}"))
        page.on("pageerror", lambda e: console.append(f"pageerror: {e}"))

        for name, link in CASES:
            print(f"\n  --- case: {name} ---")
            page.goto(LIVE, wait_until="load")

            status = page.inner_text("#status")
            print(f"  relay status : {status}")
            if "online" not in status:
                failures.append(f"{name}: relay status was {status!r}")

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

            b64 = page.evaluate("""async () => {
                const r = await fetch(document.getElementById('dl').href);
                const b = new Uint8Array(await r.arrayBuffer());
                let s = '';
                for (let i = 0; i < b.length; i += 0x8000)
                    s += String.fromCharCode.apply(null, b.subarray(i, i + 0x8000));
                return btoa(s);
            }""")
            mp3 = base64.b64decode(b64)
            out = f"/tmp/opencode/live_{name.replace(' ', '_')}.mp3"
            with open(out, "wb") as fh:
                fh.write(mp3)
            print(f"  blob         : {len(mp3)} bytes -> {out}")

            p = subprocess.run(
                ["ffprobe", "-v", "error", "-show_entries", "format=duration",
                 "-show_entries", "stream=codec_name", "-of", "json", out],
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

        browser.close()

    if console:
        print("\n  browser console:")
        for c in console[-10:]:
            print(f"      {c}")

    print()
    if failures:
        print("FAILURES:")
        for f in failures:
            print(f"  - {f}")
        return 1
    print(f"all {len(CASES)} live cases passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())

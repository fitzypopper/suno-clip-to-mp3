# Suno Clip → MP3 (GitHub Pages)

A browser app that converts a Suno clip to MP3 **entirely client side**. The
encrypted media is downloaded straight from Suno's CDN into the visitor's
browser, decrypted there, and never touches a server we control.

```
site/
├── index.html     the page
├── style.css      styling
├── app.js         all the logic (crypto, decode, encode)
└── lame.min.js    MP3 encoder (lamejs 1.2.1, vendored)
```

There is no backend, no Cloudflare Worker and no account. GitHub Pages only
*hosts* the files; the client runs them.

## Why the client has to run it locally

Suno's license server sends `Access-Control-Allow-Origin` for a small set of
origins only:

| Origin | Allowed |
|---|---|
| `https://suno.com`, `https://www.suno.com` | yes |
| `http://localhost:<any port>` | yes |
| `https://<user>.github.io` | no |
| `http://127.0.0.1:<port>` | no |

A browser on a `*.github.io` origin therefore cannot call the license
endpoint, and `127.0.0.1` does not work either — it has to be `localhost`.
So the app is served from the visitor's own machine, where the origin is
`http://localhost:8000` and CORS allows everything.

The page detects a foreign origin and shows the command to run it locally.

## How it works

1. **Resolve the link to a clip id.**
   * A CloudFront clip URL (`.../1/clip/<uuid>.m4a`) or a
     `suno.com/song/<uuid>` page → the uuid.
   * A `suno.com/s/<shareId>` link → `GET /api/share/code/{share_id}` returns
     the `content_id`.
2. **Get the media URL** from `GET /api/clip/{clip_id}` → `media_urls[0].url`
   (plus the title, used for the filename).
3. **Fetch the rights** from `POST /api/mango/rights` — the same call the
   suno.com player makes. Anonymous playback returns a guest license token.
4. **Unwrap the content key.** The `key` and `iv` come back AES-GCM sealed
   with the clip id as additional data; the sealing key is `SHA-256(glt)`.
5. **Decrypt** the master with AES-128-CTR (128-bit big-endian counter).
6. **Decode** with the Web Audio API and **encode** to MP3 with lamejs.

## Run it

```bash
git clone https://github.com/<user>/<repo>
cd repo/site
python3 -m http.server 8000
```

Then open **http://localhost:8000** — note `localhost`, not `127.0.0.1`.

## Deploy to GitHub Pages

Push the repository with `site/` and `.github/workflows/deploy.yml` at the
root, then **Settings → Pages → Source → GitHub Actions**. The workflow
deploys on every push to `main` that touches `site/`.

The deployed URL doubles as the "here is the app" landing page: opened on
GitHub Pages it shows the clone-and-serve instructions.

## Tests

```bash
python3 tests/browser_test.py
```

Serves `site/` on `http://localhost:8801`, drives real Chromium through all
three link types (CloudFront URL, song page, share link), pulls the produced
blob back out of the page and verifies it with `ffprobe`. It also checks that
the "run locally" banner appears on a foreign origin.

## Notes

* The guest license token path works for clips Suno serves publicly. A clip
  that only your own account can stream needs a session token, which this
  version deliberately does not send anywhere.
* MP3 encoding is lossy and runs in JavaScript, so it is slower than FFmpeg —
  roughly a few seconds per minute of audio.
* `lame.min.js` is lamejs 1.2.1, MIT licensed.

# Suno Clip -> MP3

A browser app that converts a Suno clip to MP3 **entirely client side**. The
encrypted media is downloaded straight from Suno's CDN into the visitor's
browser, decrypted there with WebCrypto, and never touches a server we control.

**Live:** <https://fitzypopper.dpdns.org/suno-clip-to-mp3/>

Nothing to install: paste a link, get an MP3.

## Why there is a Worker at all

Suno's license server only sends `Access-Control-Allow-Origin` for a small set
of origins:

| Origin | Allowed |
|---|---|
| `https://suno.com`, `https://www.suno.com` | yes |
| `http://localhost:<any port>` | yes |
| `https://<user>.github.io` | no |
| `http://127.0.0.1:<port>` | no |

A page served from GitHub Pages therefore cannot call the license endpoint,
and `suno.com` pages send no CORS headers at all, so link resolution has to
happen server side too. A ~40 line Cloudflare Worker relays the three calls
that need it. It stores nothing and only ever talks to `suno.com` hosts.

The media itself never goes through the Worker: the CDN sends
`access-control-allow-origin: *`, so the browser downloads it directly.

This is the same trick the suno.com player uses, and the same one that keeps
the download quota untouched - the license server issues a *guest* license
token for anonymous playback.

## The three things the Worker relays

| endpoint | upstream |
|---|---|
| `GET /rights?clip_id=<uuid>` | `POST studio-api.prod.suno.com/api/mango/rights` |
| `GET /clip?clip_id=<uuid>` | `GET studio-api.prod.suno.com/api/clip/{id}` |
| `GET /share?share_id=<id>` | `GET studio-api.prod.suno.com/api/share/code/{id}` |

plus `GET /resolve?url=<suno url>` (scrapes the clip URL out of a song page)
and `GET /health`.

## How the conversion works

1. **Resolve the link to a clip id.**
   * CloudFront clip URL (`.../1/clip/<uuid>.m4a`) or `suno.com/song/<uuid>`
     → the uuid.
   * `suno.com/s/<shareId>` → `GET /api/share/code/{share_id}`.
2. **Get the media URL** from `GET /api/clip/{clip_id}` → `media_urls[0].url`
   (plus the title, used for the filename).
3. **Fetch the rights** from `POST /api/mango/rights`. Anonymous playback
   returns a guest license token (`glt`).
4. **Unwrap the content key.** The `key` and `iv` come back AES-GCM sealed,
   laid out as `[12 byte iv][ciphertext][16 byte tag]`, with the **clip id as
   additional data**. The sealing key is `SHA-256(glt)`.
5. **Decrypt** the master with AES-128-CTR (128-bit big-endian counter).
6. **Decode** with the Web Audio API and **encode** to MP3 with lamejs.

## Layout

```
site/
├── index.html     the page
├── style.css      styling
├── app.js         all the logic (crypto, decode, encode)
├── lame.min.js    MP3 encoder (lamejs 1.2.1, vendored)
├── worker.js      Cloudflare Worker - the CORS relay
└── wrangler.toml  Worker deployment config

suno_clip_to_mp3.py   CLI version of the same pipeline
tests/
├── browser_test.py    Chromium, served from localhost
└── live_test.py       Chromium, against the deployed site
```

## Deploy

### The Worker

```bash
cd site
npx wrangler login        # one-time
npx wrangler deploy
```

Then put the resulting `*.workers.dev` URL into `PROXY` at the top of
`app.js` and commit.

### The site

Push to GitHub and the workflow in `.github/workflows/deploy.yml` publishes
`site/` to GitHub Pages. **Settings → Pages → Source → GitHub Actions**.

## Tests

```bash
./run_tests.sh                 # CLI: 12 checks
python3 tests/browser_test.py  # Chromium on localhost
python3 tests/live_test.py     # Chromium against the deployed site
```

`live_test.py` is the one that matters: it loads the published URL exactly
like a visitor with nothing installed and converts a clip end to end.

## Notes

* The guest license token path works for clips Suno serves publicly. A clip
  that only your own account can stream needs a session token, which this
  version deliberately does not send anywhere.
* MP3 encoding is lossy and runs in JavaScript, so it is slower than FFmpeg -
  roughly a few seconds per minute of audio.
* `lame.min.js` is lamejs 1.2.1, MIT licensed.

## The CLI

```bash
./suno_clip_to_mp3.py --url 'https://suno.com/s/lN26vGvSMqnWMss5' -o clip.mp3
```

The CLI does the same thing without a browser, and additionally repairs
genuinely broken containers: a garbage prefix before `ftyp` (rebuilding the
box tree and patching `stco`/`co64`), a missing `moov` (sniffing the
elementary stream out of `mdat`), and raw ADTS/MPEG wearing an `.m4a` name.
See `README.md` for the byte-level analysis of those cases.

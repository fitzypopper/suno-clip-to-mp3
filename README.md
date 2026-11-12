# Suno clip -> MP3

Two front ends for the same job:

| | what it is |
|---|---|
| `suno_clip_to_mp3.py` | CLI. Downloads, does byte-level forensics, repairs broken containers, decrypts the streaming master, converts to MP3. |
| `site/` | Static GitHub Pages app. Same crypto, entirely in the browser, no backend and no Worker - see `site/README.md`. |

## The link under investigation

```
https://d2lwuy8qc234o3.cloudfront.net/1/clip/985f338b-79b2-47f8-8c5f-34eb864a5d0f.m4a
```

Required headers (browser-like): `User-Agent` (Firefox 159), `Referer: https://suno.com/`,
`Origin: https://suno.com`.

## What the file actually is

HTTP 200, `content-type: audio/mp4`, `content-length: 1697008`, ETag
`835bf2993c4025fc8209117179b0e4e4`, served from S3 behind CloudFront.
`/1/clip/<id>.m4a` and `/2/clip/<id>.m4a` return **byte-identical** bodies
(the `2` prefix is only a cache-key variant). A random UUID under the same
path returns 404, so the routing is genuine.

### It is ciphertext, not a broken container

| probe | result |
|---|---|
| `file` | `data` |
| ISO-BMFF atoms (`ftyp`/`moov`/`mdat`/`stco`...) | **0 occurrences** anywhere in 1.7 MB |
| ADTS sync candidates (`0xFFFx`) | 467 raw hits, **0** syntactically valid headers |
| whole-file entropy | **8.0000 bit/byte** |
| chi-square vs uniform (df=255) | **240.1** (expectation 255 +/- 23) -> perfectly uniform |
| autocorrelation at lags 1..16 | ~0.000 |
| longest run of identical bytes | 3 |
| repeated 16-byte blocks (ECB test) | 0 |
| length | 1697008, **16-byte aligned** |
| XOR-key period scan (1..8192, header region) | no period above 2% match rate |
| gzip / zlib / bz2 / xz / zstd / brotli | all fail |
| any 16 KB window entropy | >= 7.987 (no plaintext island) |
| Range requests | consistent with the full body (not a truncation artefact) |
| full browser header set / `Accept-Encoding` | byte-identical body |

A real media file is *never* byte-uniform: containers, zero padding and tags
make chi-square thousands, not ~255. Ciphertext is. Conclusion: the object is
**encrypted**.

The reported FFmpeg errors are the AAC decoder chewing random bytes, not a
signal of a special bitstream:

```
[aac] channel element 3.6 is not allocated
[aac] Reserved bit set.
[aac] Number of scalefactor bands in group (53) exceeds limit (41).
[aac] Error decoding AAC frame header.
```

## How Suno actually plays these clips

Downloaded the 124 JS chunks of `suno.com` and grepped them. The frontend:

* fetches the encrypted clip from the CDN URL,
* asks a **license server** for the content key,
* **decrypts client-side** with WebCrypto `AES-CTR` (128-bit counter, offset
  arithmetic), and unwraps the key with `AES-GCM`.

The license request (module `930323` / `44578` / `2b6b6kacq49tp.js`):

```
POST https://studio-api.prod.suno.com/api/mango/rights
Content-Type: application/json

{"content_params":{"content_id":"<uuid>","content_type":"clip"}}

-> {"key":"<b64>", "iv":"<b64>", "glt":"<guest license token JWT>"}
```

The `key` and `iv` blobs are AES-GCM sealed, laid out as
`[12 byte iv][ciphertext][16 byte tag]`, with the **clip id as additional
data**. The sealing key is:

* `SHA-256(glt)` for anonymous playback, or
* `SHA-256(<Clerk session JWT>)` when signed in.

Unsealing gives a 16-byte AES-128-CTR content key and a 16-byte initial
counter block. The media is then decrypted with AES-128-CTR, the counter
being the 16-byte block incremented as a big-endian 128-bit integer.

**This is the playback path, not the download path** - and it does not touch
the plan's download quota (`current_period_downloads_limit`,
`periodDownloadsRemaining`, `additionalDownloadsRemaining`, `canDownload`
are tracked separately, and only `/api/download/clip/{id}` spends one).

Verified end to end: the anonymous request succeeds, the decryption yields a
valid ISO-BMFF file with `ftyp isom`, duration 106.76 s, and the MP3 decodes
clean with real (non-silent) audio.

## The download API (for reference - this one *does* spend quota)

Suno's web player "Download MP3 / Download M4A" buttons call:

```
GET https://studio-api.prod.suno.com/api/download/clip/{clip_id}?format=mp3|m4a
GET https://studio-api.prod.suno.com/api/studio/clip/{clip_id}/download?format=...
```

Response shape (from the bundle):

```json
{ "ok": true, "status": "ready", "download_url": "https://..." }
```

`status` may be `processing` (poll every ~2 s) or `error`. The `download_url`
is a signed, time-limited link to a **decrypted render** - the download code
parses it for a real ID3/MP3 header, which the encrypted master does not have.

Auth is `Authorization: Bearer <jwt>` (plus optional `Device-Id`), or the
session cookie. Unauthenticated, both endpoints answer `401 Unauthorized`.

This route is kept in the script as a **fallback only**, and the script
prints a warning when it falls back to it, because it spends one of the
plan's downloads.

## CORS: why the browser app has to run on localhost

Suno's license server only allows a handful of origins:

| Origin | Allowed |
|---|---|
| `https://suno.com`, `https://www.suno.com` | yes |
| `http://localhost:<any port>` | yes |
| `https://<user>.github.io` | no |
| `http://127.0.0.1:<port>` | no |

So a page hosted on GitHub Pages cannot call the license endpoint, and
`127.0.0.1` does not work either - it has to be `localhost`. The static app
is therefore served from the visitor's own machine, where the origin is
`http://localhost:8000` and CORS allows everything. GitHub Pages only hosts
the files. This is also why no Cloudflare Worker is needed any more.

The media itself never needed a proxy: the CDN sends
`access-control-allow-origin: *`.

## The script

`suno_clip_to_mp3.py` automates all of it:

1. resolve the link - CloudFront clip URL, `suno.com/song/<uuid>` page or
   `suno.com/s/<shareId>` share link all work;
2. download with the browser headers, verifying `Content-Length`;
3. byte-level forensics: box-tree parse, ADTS sync-chain scan, MPEG frame
   sync scan, entropy + chi-square uniformity test;
4. pick a strategy automatically and *verify* it by decoding:
   * intact MP4 -> remux;
   * MP4 with a garbage prefix -> rebuild the box tree and patch `stco`/`co64`
     (tries "stripped", "stripped + offsets-delta" and "prefixed + offsets+delta"
     and keeps the first variant that actually decodes audio frames);
   * MP4 whose `moov` is gone -> sniff the elementary stream out of `mdat`;
   * raw ADTS / raw MPEG wearing an `.m4a` name -> extract and remux;
   * encrypted payload -> fetch playback rights, unwrap the AES-GCM sealed
     key/iv, AES-128-CTR decrypt, then remux;
5. convert with `libmp3lame`, then verify the result with `ffprobe`
   (codec, duration, size).

## Test suite

`./run_tests.sh` - 12/12 green. Fixtures in `/tmp/opencode/sct`:

| fixture | what it simulates |
|---|---|
| `good.m4a` | healthy MP4 |
| `pfx_stale.m4a` | 1000-byte garbage prefix, index stale |
| `pfx_consistent.m4a` | 1000-byte prefix, index consistent |
| `raw.m4a` | raw ADTS AAC named `.m4a` |
| `rawmp3.m4a` | raw MP3 named `.m4a` |
| `fake_mdat_adts.m4a` | `moov` lost, ADTS still inside `mdat` |
| the real URL | the encrypted master |

`python3 tests/browser_test.py` - 3/3 green. Drives real Chromium through all
three link types (CloudFront URL, song page, share link), pulls the produced
blob back out of the page and verifies it with `ffprobe`.

## Bugs found and fixed while building this

* ADTS `frame_length` **includes** the header - adding `header_len` again
  desynchronised the chain.
* ADTS `profile`/`sample_rate_index` live in byte 2, not byte 1; the
  `sampling_frequency_index` table has no leading zero.
* `stco`/`co64` patching must recurse by index - slicing a `bytearray`
  copies it and silently drops nested writes.
* The `ftyp` four-character code sits 4 bytes *inside* its box.
* `patch_chunk_offsets` semantics: signed shift, not "subtract a prefix".

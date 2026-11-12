#!/usr/bin/env python3
"""
suno_clip_to_mp3.py
===================

Robust Suno/CloudFront clip -> MP3 pipeline.

The pipeline is fully autonomous: it downloads the clip with the required
browser headers, runs a byte-level forensic pass over the payload, and then
picks the correct recovery strategy automatically:

  A. ISO-BMFF / MP4 that is merely *mis-assembled*  -> rebuild the box tree
     (strip a garbage prefix, fix absolute chunk offsets in stco/co64) and remux.
  B. Raw ADTS AAC hiding behind an .m4a name        -> detect the 0xFFF sync
     chain, extract the elementary stream, remux.
  C. Raw MPEG audio (no container at all)            -> detect the 0xFFE frame
     sync chain, extract, remux.
  D. Payload that is cryptographically uniform        -> it is NOT a container
     problem, it is an encrypted streaming master.  The suno.com player asks
     the license server for the content key and decrypts with AES-128-CTR, so
     this script does exactly that: POST /api/mango/rights -> unwrap the
     AES-GCM sealed key/iv with SHA-256(guest license token) -> AES-CTR
     decrypt.  This is the *playback* path and it does not spend any of the
     plan's downloads.  Only if the license server refuses the clip does it
     fall back to Suno's download API, which does count.

Only the standard library is required, plus `cryptography` (AES) and
ffmpeg/ffprobe on PATH.

Usage
-----
  # diagnose only
  ./suno_clip_to_mp3.py --url URL --probe

  # full pipeline - no account needed for public clips
  ./suno_clip_to_mp3.py --url URL --out clip.mp3

  # with your own session (needed for clips your account cannot stream
  # anonymously); SUNO_TOKEN/SUNO_COOKIE are also used to unwrap the key
  export SUNO_TOKEN='eyJhbGciOi...'          # Bearer JWT, or
  export SUNO_COOKIE='__Secure-next-auth.session-token=...'   # session cookie
  ./suno_clip_to_mp3.py --url URL --out clip.mp3

  # non-interactive
  ./suno_clip_to_mp3.py --url URL --token "$JWT" --out clip.mp3
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import math
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Optional

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:  # only needed for the encrypted-streaming route
    Cipher = algorithms = modes = None  # type: ignore[assignment]

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64; rv:159.0) Gecko/20100101 Firefox/159.0"
)
BROWSER_HEADERS = {
    "User-Agent": USER_AGENT,
    "Referer": "https://suno.com/",
    "Origin": "https://suno.com",
    "Accept": "*/*",
    "Accept-Language": "en-US,en;q=0.9",
}

SUNO_API_HOSTS = (
    "https://studio-api.prod.suno.com",
    "https://studio-api-prod.suno.com",
)

CLIP_ID_RE = re.compile(
    r"([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})"
)

AAC_SAMPLE_RATES = [
    96000, 88200, 64000, 48000, 44100, 32000, 24000,
    22050, 16000, 12000, 11025, 8000, 7350,
]

MPEG_BITRATES_V1_L3 = [
    0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 0
]
MPEG_BITRATES_V2_L3 = [
    0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160, 0
]
MPEG_RATES = {0: 44100, 1: 48000, 2: 32000}

# --------------------------------------------------------------------------- #
# Terminal helpers
# --------------------------------------------------------------------------- #

_TTY = sys.stdout.isatty()
if _TTY:
    C_RESET = "\033[0m"
    C_DIM = "\033[2m"
    C_RED = "\033[31m"
    C_GRN = "\033[32m"
    C_YEL = "\033[33m"
    C_BLU = "\033[36m"
    C_BOLD = "\033[1m"
else:
    C_RESET = C_DIM = C_RED = C_GRN = C_YEL = C_BLU = C_BOLD = ""


def ok(msg: str) -> None:
    print(f"{C_GRN}[+]{C_RESET} {msg}", flush=True)


def warn(msg: str) -> None:
    print(f"{C_YEL}[!]{C_RESET} {msg}", flush=True)


def fail(msg: str) -> None:
    print(f"{C_RED}[x]{C_RESET} {msg}", flush=True)


def info(msg: str) -> None:
    print(f"    {C_DIM}{msg}{C_RESET}", flush=True)


def head(msg: str) -> None:
    print(f"\n{C_BOLD}{msg}{C_RESET}", flush=True)


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #


def human(n: float) -> str:
    for unit in ("B", "KiB", "MiB", "GiB"):
        if abs(n) < 1024 or unit == "GiB":
            return f"{n:,.0f} {unit}" if unit == "B" else f"{n:,.1f} {unit}"
        n /= 1024
    return f"{n:.1f} GiB"


def have(binary: str) -> bool:
    return shutil.which(binary) is not None


def extract_clip_id(url: str) -> Optional[str]:
    m = CLIP_ID_RE.search(url)
    return m.group(1) if m else None


CLIP_URL_RE = re.compile(rb"/1/clip/([0-9a-fA-F-]{36})\.m4a")


def resolve_media_url(url: str) -> tuple[str, str]:
    """Return the real media URL for whatever link the user pasted.

    Handles the three shapes Suno hands out:

      * ``https://<cdn>/1/clip/<uuid>.m4a``  - already the media
      * ``https://suno.com/song/<uuid>``      - a song page
      * ``https://suno.com/s/<shareId>``     - a short share link that
        307-redirects to the song page

    The page variants have to be fetched and mined for the clip URL, because
    the song id and the clip id are not always the same thing.
    """
    if re.search(r"/clip/[0-9a-fA-F-]{36}\.m4a", url):
        return url, "link is already the media URL"

    req = urllib.request.Request(url, headers=BROWSER_HEADERS, method="GET")
    with urllib.request.urlopen(req, timeout=60) as resp:
        ctype = resp.headers.get("Content-Type", "")
        body = resp.read()
        final = resp.geturl()

    if "html" not in ctype.lower() and not body.lstrip()[:1] == b"<":
        # it was media after all
        return url, "link served the media directly"

    m = CLIP_URL_RE.search(body)
    if not m:
        raise RuntimeError(
            "that page does not contain a clip URL.\n"
            "      It may be a private song, or the page layout changed.\n"
            f"      (final URL was {final})"
        )
    clip = m.group(1).decode().lower()
    media = f"https://d2lwuy8qc234o3.cloudfront.net/1/clip/{clip}.m4a"
    return media, f"resolved page → clip {clip}"


# --------------------------------------------------------------------------- #
# 1. Download
# --------------------------------------------------------------------------- #


def download(url: str, dest: str, timeout: int = 60) -> dict[str, Any]:
    """Download with browser headers, following redirects, verifying length."""
    req = urllib.request.Request(url, headers=BROWSER_HEADERS, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        declared = resp.headers.get("Content-Length")
        declared_len = int(declared) if declared and declared.isdigit() else None
        got = 0
        with open(dest, "wb") as fh:
            while True:
                chunk = resp.read(262144)
                if not chunk:
                    break
                fh.write(chunk)
                got += len(chunk)
                if declared_len:
                    pct = 100.0 * got / declared_len
                    print(
                        f"\r    {C_DIM}downloading... {pct:5.1f}%  "
                        f"{human(got)} / {human(declared_len)}{C_RESET}",
                        end="",
                        flush=True,
                    )
        if declared_len:
            print()
        ctype = resp.headers.get("Content-Type", "")
        etag = resp.headers.get("ETag", "")
    if declared_len and got != declared_len:
        raise RuntimeError(
            f"truncated download: got {got} bytes, server declared {declared_len}"
        )
    if got == 0:
        raise RuntimeError("server returned an empty body")
    return {"bytes": got, "content_type": ctype, "etag": etag}


# --------------------------------------------------------------------------- #
# 2. Forensics
# --------------------------------------------------------------------------- #


@dataclass
class Findings:
    kind: str = "unknown"
    detail: str = ""
    offset: int = 0
    encrypted: bool = False
    entropy: float = 0.0
    chi2: float = 0.0
    uniform: bool = False
    boxes: list[tuple[str, int, int]] = field(default_factory=list)
    has_moov: bool = False
    has_mdat: bool = False
    adts_chain: Optional[tuple[int, int, int]] = None   # start, end, frames
    mp3_chain: Optional[tuple[int, int, int]] = None    # start, end, frames
    ftyp_offset: int = -1


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def chi_square_uniformity(data: bytes) -> float:
    """Chi-square statistic for the hypothesis 'every byte value equally likely'.

    For a 16-bit-aligned random/encrypted payload this lands near 255
    (df = 255).  For any real media container it is orders of magnitude
    larger, because media is extremely non-uniform (headers, zero padding,
    tags).
    """
    counts = Counter(data)
    expected = len(data) / 256.0
    if expected <= 0:
        return 0.0
    return sum(
        (counts.get(i, 0) - expected) ** 2 / expected for i in range(256)
    )


def iter_boxes(data: bytes, start: int = 0, end: Optional[int] = None):
    """Yield (type, offset, size, header_size) for each top-level box."""
    end = len(data) if end is None else end
    off = start
    while off + 8 <= end:
        size = int.from_bytes(data[off : off + 4], "big")
        btype = data[off + 4 : off + 8]
        hdr = 8
        if size == 1:
            if off + 16 > end:
                break
            size = int.from_bytes(data[off + 8 : off + 16], "big")
            hdr = 16
        elif size == 0:
            size = end - off
        if size < hdr or off + size > end:
            # truncated / bogus box
            yield (btype, off, size, hdr)
            break
        yield (btype, off, size, hdr)
        off += size


def find_all(data: bytes, needle: bytes) -> list[int]:
    out, start = [], 0
    while True:
        i = data.find(needle, start)
        if i < 0:
            return out
        out.append(i)
        start = i + 1


# --- ADTS ---------------------------------------------------------------- #


def adts_header_len_and_frame(data: bytes, pos: int):
    """Return (header_len, frame_total_len, sample_rate, channels) or None.

    ADTS header layout (7 bytes without CRC):
      b0      : syncword high
      b1      : syncword low(4) | MPEG id(1) | layer(2) | prot_absent(1)
      b2      : profile(2) | sampling_frequency_index(4) | private(1) | chan bit0
      b3      : chan bits 2..1(2) | original/home/copyright(4) | len bits 12..11
      b4      : frame length bits 10..3
      b5      : frame length bits 2..0 | buffer fullness high bits
      b6      : buffer fullness low bits | number of raw data blocks
    """
    if pos + 7 > len(data):
        return None
    b0, b1, b2, b3, b4, b5 = data[pos : pos + 6]
    if b0 != 0xFF or (b1 & 0xF6) != 0xF0:
        return None
    layer = (b1 >> 1) & 0x03
    if layer != 0:                      # only AAC-LC/Main/SSR are relevant
        return None
    protection_absent = b1 & 0x01
    profile = (b2 >> 6) & 0x03
    if profile == 3:                    # reserved profile value
        return None
    sri = (b2 >> 2) & 0x0F
    if sri > 12:
        return None
    channel_cfg = (((b3 >> 6) & 0x03) << 1) | (b2 & 0x01)
    if channel_cfg > 7:
        return None
    frame = ((b3 & 0x03) << 11) | (b4 << 3) | ((b5 >> 5) & 0x07)
    header_len = 7 if protection_absent else 9
    # The ADTS frame_length field counts the header itself, so the total
    # frame size *is* that value - it must not be added to header_len again.
    total = frame
    if total < header_len or total > len(data) - pos:
        return None
    return header_len, total, AAC_SAMPLE_RATES[sri], channel_cfg


def scan_adts_chain(data: bytes):
    """Find the longest chain of back-to-back, structurally valid ADTS frames."""
    cands = []
    pos = 0
    limit = len(data) - 7
    while pos <= limit:
        pos = data.find(b"\xff", pos)
        if pos < 0 or pos > limit:
            break
        hdr = adts_header_len_and_frame(data, pos)
        if hdr:
            cands.append((pos, hdr[1]))
        pos += 1
    if not cands:
        return None
    best = None
    for start, _ in cands:
        pos = start
        frames = 0
        while True:
            hdr = adts_header_len_and_frame(data, pos)
            if not hdr:
                break
            pos += hdr[1]
            frames += 1
            if frames > 2_000_000:
                break
        if best is None or frames > best[2]:
            best = (start, pos, frames)
    if best and best[2] >= 3:
        return best
    return None


# --- MPEG audio ----------------------------------------------------------- #


def mpeg_frame_len(data: bytes, pos: int):
    """Return (frame_length, bitrate_kbps, sample_rate, channels) or None."""
    if pos + 4 > len(data):
        return None
    if data[pos] != 0xFF or (data[pos + 1] & 0xE0) != 0xE0:
        return None
    ver_bits = (data[pos + 1] >> 3) & 0x03
    layer_bits = (data[pos + 1] >> 1) & 0x03
    if ver_bits == 1 or layer_bits == 0:   # reserved version / layer
        return None
    br_idx = (data[pos + 2] >> 4) & 0x0F
    sr_idx = (data[pos + 2] >> 2) & 0x03
    pad = (data[pos + 2] >> 1) & 0x01
    if br_idx in (0, 15) or sr_idx == 3:
        return None
    if ver_bits == 3:      # MPEG-1
        layer = 4 - layer_bits
        bitrate = MPEG_BITRATES_V1_L3[br_idx]
        samplerate = MPEG_RATES[sr_idx]
    else:                  # MPEG-2 / 2.5
        layer = 4 - layer_bits
        bitrate = MPEG_BITRATES_V2_L3[br_idx]
        samplerate = MPEG_RATES[sr_idx] // (2 if ver_bits == 2 else 4)
    if layer != 3 or bitrate == 0:
        return None
    spf = 1152 if ver_bits == 3 else 576
    length = (144 * bitrate * 1000) // samplerate + pad
    if length < 24:
        return None
    channels = 1 if ((data[pos + 3] >> 6) & 0x03) == 3 else 2
    return length, bitrate, samplerate, channels


def scan_mpeg_chain(data: bytes):
    cands = []
    pos = 0
    limit = len(data) - 4
    while pos <= limit:
        pos = data.find(b"\xff", pos)
        if pos < 0 or pos > limit:
            break
        hdr = mpeg_frame_len(data, pos)
        if hdr:
            cands.append((pos, hdr[0]))
        pos += 1
    if not cands:
        return None
    best = None
    for start, _ in cands:
        pos, frames = start, 0
        while pos + 4 <= len(data):
            hdr = mpeg_frame_len(data, pos)
            if not hdr:
                break
            pos += hdr[0]
            frames += 1
            if frames > 2_000_000:
                break
        if best is None or frames > best[2]:
            best = (start, pos, frames)
    if best and best[2] >= 3:
        return best
    return None


# --- master sniff --------------------------------------------------------- #


def analyse(data: bytes) -> Findings:
    f = Findings()
    f.entropy = shannon_entropy(data)
    f.chi2 = chi_square_uniformity(data)

    # --- ISO-BMFF ---------------------------------------------------------- #
    # The 'ftyp' four-character code sits *inside* the box: the box starts
    # four bytes earlier (the 32-bit size field precedes it).
    ftyp_hits = [h - 4 for h in find_all(data, b"ftyp") if h >= 4]
    ftyp_hits = [h for h in ftyp_hits if h + 8 <= len(data)]
    if ftyp_hits:
        f.ftyp_offset = ftyp_hits[0]
    moov_hits = find_all(data, b"moov")
    mdat_hits = find_all(data, b"mdat")

    # Parse boxes from the ftyp offset (that is where a valid MP4 starts).
    box_start = ftyp_hits[0] if ftyp_hits else 0
    boxes = []
    for btype, off, size, hdr in iter_boxes(data, box_start):
        boxes.append((btype.decode("latin-1"), off, size))
    f.boxes = boxes
    f.has_moov = any(b[0] == "moov" for b in boxes) or bool(moov_hits)
    f.has_mdat = any(b[0] == "mdat" for b in boxes) or bool(mdat_hits)

    if ftyp_hits and (f.has_moov or f.has_mdat):
        f.kind = "mp4"
        f.offset = ftyp_hits[0]
        f.detail = f"ISO-BMFF: ftyp@{ftyp_hits[0]}, {len(boxes)} top-level boxes"
        if f.offset:
            f.detail += f" (garbage prefix of {f.offset} bytes before ftyp)"
        return f

    # --- MPEG audio that already is a standalone, playable file ------------- #
    if data[:3] == b"ID3":
        f.kind = "mpeg-ready"
        f.detail = "ID3-tagged MPEG audio at offset 0 - already a playable stream"
        return f
    if len(data) >= 4 and data[0] == 0xFF and mpeg_frame_len(data, 0):
        f.kind = "mpeg-ready"
        f.detail = "MPEG audio frame sync at offset 0 - already a playable stream"
        return f

    # --- ADTS -------------------------------------------------------------- #
    chain = scan_adts_chain(data)
    if chain:
        f.adts_chain = chain
        f.kind = "adts"
        f.detail = (
            f"raw ADTS AAC: {chain[2]} frames, "
            f"{chain[0]}..{chain[1]} ({human(chain[1] - chain[0])})"
        )
        return f

    mchain = scan_mpeg_chain(data)
    if mchain:
        f.mp3_chain = mchain
        f.kind = "mpeg"
        f.detail = (
            f"raw MPEG audio: {mchain[2]} frames, "
            f"{mchain[0]}..{mchain[1]}"
        )
        return f

    if data[:4] == b"OggS":
        f.kind = "ogg"
        f.detail = "Ogg container"
        return f
    if data[:4] == b"fLaC":
        f.kind = "flac"
        f.detail = "FLAC container"
        return f
    if data[:4] == b"RIFF":
        f.kind = "wav"
        f.detail = "RIFF container"
        return f

    # --- nothing recognisable: is it encrypted? ---------------------------- #
    # A genuine media file is never byte-uniform.  Ciphertext is.
    f.uniform = 210.0 <= f.chi2 <= 320.0 and f.entropy > 7.90
    longest_run = longest_identical_run(data)
    if f.uniform and longest_run <= 6:
        f.encrypted = True
        f.kind = "encrypted"
        f.detail = (
            f"no container signature; byte distribution uniform "
            f"(chi2={f.chi2:.1f}/255, entropy={f.entropy:.3f} bit/byte) "
            f"-> payload is encrypted, not mis-packaged"
        )
        return f

    f.kind = "unknown"
    f.detail = (
        f"no recognised signature (chi2={f.chi2:.1f}, entropy={f.entropy:.3f}, "
        f"longest identical-byte run={longest_run})"
    )
    return f


def longest_identical_run(data: bytes) -> int:
    best = run = 1
    for i in range(1, len(data)):
        if data[i] == data[i - 1]:
            run += 1
            if run > best:
                best = run
        else:
            run = 1
    return best


# --------------------------------------------------------------------------- #
# 3. MP4 box surgery
# --------------------------------------------------------------------------- #


def patch_chunk_offsets(moov: bytearray, amount: int) -> int:
    """Shift every absolute chunk offset (stco/co64) inside a moov atom.

    `amount` is a *signed* shift added to each offset.  Negative values pull
    the offsets back, positive values push them forward.  Returns the number
    of entries patched.
    """
    patched = 0
    containers = {
        b"moov", b"trak", b"mdia", b"minf", b"stbl", b"edts", b"dinf",
        b"udta", b"mvex", b"moof", b"traf",
    }

    def walk(buf: bytearray, start: int, end: int, depth: int = 0) -> None:
        nonlocal patched
        if depth > 8:
            return
        off = start
        while off + 8 <= end:
            size = int.from_bytes(buf[off : off + 4], "big")
            btype = bytes(buf[off + 4 : off + 8])
            hdr = 8
            if size == 1:
                if off + 16 > end:
                    return
                size = int.from_bytes(buf[off + 8 : off + 16], "big")
                hdr = 16
            elif size == 0:
                size = end - off
            if size < hdr or off + size > end:
                return
            if btype == b"stco":
                count = int.from_bytes(buf[off + 12 : off + 16], "big")
                p = off + 16
                for _ in range(count):
                    if p + 4 > end:
                        break
                    val = int.from_bytes(buf[p : p + 4], "big")
                    buf[p : p + 4] = max(0, val + amount).to_bytes(4, "big")
                    p += 4
                    patched += 1
            elif btype == b"co64":
                count = int.from_bytes(buf[off + 12 : off + 16], "big")
                p = off + 16
                for _ in range(count):
                    if p + 8 > end:
                        break
                    val = int.from_bytes(buf[p : p + 8], "big")
                    buf[p : p + 8] = max(0, val + amount).to_bytes(8, "big")
                    p += 8
                    patched += 1
            elif btype in containers:
                walk(buf, off + hdr, off + size, depth + 1)
            off += size

    walk(moov, 0, len(moov))
    return patched


def patch_moov_in_place(data: bytes, moov_off: int, moov_size: int, amount: int):
    """Return `data` with every stco/co64 entry inside moov shifted by amount."""
    buf = bytearray(data)
    moov = bytearray(buf[moov_off : moov_off + moov_size])
    n = patch_chunk_offsets(moov, amount)
    buf[moov_off : moov_off + moov_size] = moov
    return bytes(buf), n


def mp4_repair_candidates(data: bytes) -> list[tuple[str, bytes]]:
    """Build the plausible repaired forms of a mis-assembled ISO-BMFF file.

    A file can be broken in two different ways and they need opposite fixes:

      (a) the container was *written* with the garbage prefix, so its absolute
          chunk offsets already include it -> strip the prefix and subtract it
          from every offset;
      (b) garbage was prepended to an already finished container, so the index
          is stale and still points at the un-prefixed positions -> strip the
          prefix and leave the offsets alone.

    Rather than guess, both variants (plus a "keep the prefix" variant) are
    produced and each one is verified by actually decoding it.
    """
    ftyp_hits = [h - 4 for h in find_all(data, b"ftyp") if h >= 4]
    ftyp_hits = [h for h in ftyp_hits if h + 8 <= len(data)]
    if not ftyp_hits:
        return []
    start = ftyp_hits[0]
    delta = start
    if delta == 0:
        return [("intact", data)]

    moov_off = moov_size = None
    for btype, off, size, hdr in iter_boxes(data, start):
        if btype == b"moov":
            moov_off, moov_size = off, size
            break
    if moov_off is None:
        # no index at all -> the only hope is the raw payload
        return [("stripped", data[start:])]

    out: list[tuple[str, bytes]] = []
    stripped = data[start:]
    out.append(("stripped", stripped))

    patched, n = patch_moov_in_place(data, moov_off, moov_size, -delta)
    out.append((f"stripped+offsets-{delta}", patched[start:]))
    if n == 0:
        # nothing to adjust -> the plain stripped variant is the right one
        return out[:1]

    patched, n2 = patch_moov_in_place(data, moov_off, moov_size, delta)
    out.append((f"prefixed+offsets+{delta}", patched))
    return out


def mdat_payload(data: bytes, start: int = 0):
    """Return the raw bytes carried by the first mdat box, or None."""
    for btype, off, size, hdr in iter_boxes(data, start):
        if btype == b"mdat":
            return data[off + hdr : off + size]
    return None


# --------------------------------------------------------------------------- #
# 4. FFmpeg
# --------------------------------------------------------------------------- #


def run_ffmpeg(args: list[str]) -> subprocess.CompletedProcess:
    cmd = ["ffmpeg", "-hide_banner", "-nostdin", "-y", *args]
    return subprocess.run(cmd, capture_output=True, text=True)


def ffmpeg_error_tail(proc: subprocess.CompletedProcess, n: int = 12) -> str:
    text = (proc.stderr or "").strip().splitlines()
    return "\n".join(f"      {line}" for line in text[-n:])


def convert_to_mp3(
    src: str,
    dst: str,
    *,
    input_format: Optional[str] = None,
    bitrate: str = "192k",
    title: Optional[str] = None,
    artist: Optional[str] = None,
    extra: Optional[list[str]] = None,
) -> bool:
    args: list[str] = []
    if input_format:
        args += ["-f", input_format]
    args += ["-i", src]
    if title:
        args += ["-metadata", f"title={title}"]
    if artist:
        args += ["-metadata", f"artist={artist}"]
    if extra:
        args += extra
    args += ["-vn", "-map", "0:a:0", "-c:a", "libmp3lame", "-b:a", bitrate, dst]
    proc = run_ffmpeg(args)
    if proc.returncode != 0:
        fail("ffmpeg conversion failed")
        print(ffmpeg_error_tail(proc))
        return False
    return True


def probe(path: str) -> dict[str, Any]:
    proc = subprocess.run(
        [
            "ffprobe", "-v", "error", "-show_format", "-show_streams",
            "-of", "json", path,
        ],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        return {}
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {}


def decodes_to_audio(path: str) -> bool:
    """True if ffprobe can actually decode audio frames out of the file."""
    proc = subprocess.run(
        [
            "ffprobe", "-v", "error", "-select_streams", "a:0",
            "-count_frames", "-show_entries", "stream=nb_read_frames,codec_type",
            "-of", "json", path,
        ],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        return False
    try:
        payload = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        return False
    for stream in payload.get("streams", []):
        try:
            frames = int(stream.get("nb_read_frames", 0) or 0)
        except (TypeError, ValueError):
            frames = 0
        if frames > 0:
            return True
    return False


def verify_mp3(path: str) -> bool:
    data = probe(path)
    if not data:
        fail("ffprobe could not read the produced file")
        return False
    streams = data.get("streams", [])
    fmt = data.get("format", {})
    if not streams:
        fail("produced file contains no streams")
        return False
    codec = streams[0].get("codec_name")
    duration = float(fmt.get("duration", 0) or 0)
    size = os.path.getsize(path)
    ok(f"verified: codec={codec} duration={duration:.1f}s size={human(size)}")
    if codec != "mp3":
        fail(f"expected an mp3 stream, got {codec!r}")
        return False
    if duration <= 0.5:
        fail("duration is suspiciously short - the file may be silent/garbage")
        return False
    return True


# --------------------------------------------------------------------------- #
# 5. Suno playback rights: unwrap the content key and decrypt the media
# --------------------------------------------------------------------------- #
#
# The public clip URL serves an *encrypted* streaming master.  The suno.com
# player does not download a plain file: it asks the license server for the
# content key and decrypts in the browser.
#
#   POST /api/mango/rights
#     body: {"content_params": {"content_id": "<uuid>", "content_type": "clip"}}
#     ->   {"key": <b64>, "iv": <b64>, "glt": "<guest license token>"}
#
# The returned key/iv blobs are AES-GCM sealed with the clip id as additional
# data.  The sealing key is SHA-256 of the guest license token (anonymous) or
# SHA-256 of the session JWT (signed in).  Unsealing yields a 16 byte
# AES-128-CTR content key and the 16 byte initial counter block, and the
# media itself is decrypted with AES-128-CTR.
#
# This is the *playback* path.  It is not the download API and it does not
# touch the plan's download quota.


def fetch_rights(
    clip_id: str,
    token: Optional[str] = None,
    cookie: Optional[str] = None,
    device_id: Optional[str] = None,
    version: Optional[int] = None,
    timeout: int = 30,
) -> dict[str, Any]:
    """Ask Suno's license server for the decryption rights of a clip."""
    body: dict[str, Any] = {
        "content_params": {"content_id": clip_id, "content_type": "clip"}
    }
    if version is not None:
        body["version"] = version
    payload = json.dumps(body).encode()

    last: Any = None
    for host in SUNO_API_HOSTS:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Origin": "https://suno.com",
            "Referer": "https://suno.com/",
            "User-Agent": USER_AGENT,
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"
        if cookie:
            headers["Cookie"] = cookie
        if device_id:
            headers["Device-Id"] = device_id
        req = urllib.request.Request(
            f"{host}/api/mango/rights", data=payload, headers=headers, method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as exc:
            last = (exc.code, exc.read().decode("utf-8", "replace"))
            continue
        except urllib.error.URLError as exc:
            raise RuntimeError(f"network error contacting {host}: {exc.reason}") from exc
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            last = (0, raw[:200].decode("utf-8", "replace"))
            continue
        if isinstance(parsed, dict) and parsed.get("key"):
            return parsed
        last = (200, parsed)
    status, detail = last if last else (0, None)
    raise RuntimeError(f"license server refused the clip ({status}): {detail}")


def unwrap_gcm_blob(blob_b64: str, aad: str, sealing_key: bytes) -> bytes:
    """Open an AES-GCM sealed blob: [12 byte iv][ciphertext][16 byte tag]."""
    blob = base64.b64decode(blob_b64)
    if len(blob) < 12 + 16:
        raise ValueError("sealed blob is too short")
    iv, ct, tag = blob[:12], blob[12:-16], blob[-16:]
    decryptor = Cipher(
        algorithms.AES(sealing_key), modes.GCM(iv, tag)
    ).decryptor()
    decryptor.authenticate_additional_data(aad.encode())
    return decryptor.update(ct) + decryptor.finalize()


def ctr_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    """AES-128-CTR decryption with a full 128-bit big-endian counter block."""
    decryptor = Cipher(algorithms.AES(key), modes.CTR(iv)).decryptor()
    return decryptor.update(data) + decryptor.finalize()


def decrypt_streaming_master(
    data: bytes,
    clip_id: str,
    token: Optional[str] = None,
    cookie: Optional[str] = None,
    device_id: Optional[str] = None,
    version: Optional[int] = None,
) -> bytes:
    """Decrypt an encrypted clip using the playback rights of the session."""
    if Cipher is None:
        raise RuntimeError(
            "the 'cryptography' package is required to decrypt an encrypted "
            "clip (pip install cryptography)"
        )
    rights = fetch_rights(clip_id, token, cookie, device_id, version)
    glt = rights.get("glt") or ""

    # Sealing key: SHA-256 of the session JWT when signed in, otherwise
    # SHA-256 of the guest license token that came back with the rights.
    sealing_candidates: list[tuple[str, bytes]] = []
    if token:
        sealing_candidates.append(
            ("session-jwt", hashlib.sha256(token.encode()).digest())
        )
    if glt:
        sealing_candidates.append(
            ("guest-license-token", hashlib.sha256(glt.encode()).digest())
        )
    if not sealing_candidates:
        raise RuntimeError(
            "the license server did not return a guest token and no session "
            "token was supplied"
        )

    for label, sealing_key in sealing_candidates:
        try:
            key = unwrap_gcm_blob(rights["key"], clip_id, sealing_key)
            iv = unwrap_gcm_blob(rights["iv"], clip_id, sealing_key)
        except Exception as exc:
            info(f"sealing key '{label}' did not open the blob ({exc})")
            continue
        if len(key) != 16 or len(iv) != 16:
            info(f"sealing key '{label}' produced an unexpected key size")
            continue
        info(f"content key unwrapped via {label}")
        return ctr_decrypt(data, key, iv)
    raise RuntimeError("could not unwrap the content key with any sealing key")


# --------------------------------------------------------------------------- #
# 6. Suno official download API (counts against the plan's download quota)
# --------------------------------------------------------------------------- #


def api_get_json(
    url: str,
    token: Optional[str],
    cookie: Optional[str],
    device_id: Optional[str],
    timeout: int = 30,
) -> tuple[int, Any]:
    headers = {"Accept": "application/json", "Referer": "https://suno.com/"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if cookie:
        headers["Cookie"] = cookie
    if device_id:
        headers["Device-Id"] = device_id
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            try:
                return resp.status, json.loads(raw)
            except json.JSONDecodeError:
                return resp.status, raw.decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            return exc.code, json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return exc.code, raw.decode("utf-8", "replace")
    except urllib.error.URLError as exc:
        raise RuntimeError(f"network error calling {url}: {exc.reason}") from exc


def fetch_playable_source(
    clip_id: str,
    fmt: str,
    token: Optional[str],
    cookie: Optional[str],
    device_id: Optional[str],
    wait_s: int = 300,
) -> str:
    """Ask Suno's own download API for a playable (decrypted) file URL.

    This is the exact endpoint the suno.com web player uses for its
    "Download MP3 / M4A" buttons.  It returns a signed, time-limited URL for
    a *decrypted* render, which is what the browser then saves to disk.
    """
    last: Any = None
    deadline = time.time() + wait_s
    attempt = 0
    while time.time() < deadline:
        attempt += 1
        got = False
        for host in SUNO_API_HOSTS:
            url = f"{host}/api/download/clip/{clip_id}?format={fmt}"
            status, payload = api_get_json(url, token, cookie, device_id)
            if status == 401:
                last = (status, payload)
                continue
            if status != 200:
                last = (status, payload)
                continue
            got = True
            if isinstance(payload, dict):
                state = payload.get("status")
                if state == "ready" and payload.get("download_url"):
                    return payload["download_url"]
                if state == "processing":
                    last = (status, payload)
                    break
                if payload.get("error_type") or payload.get("detail"):
                    raise RuntimeError(
                        "Suno refused the download: "
                        f"{payload.get('error_type') or 'error'} - "
                        f"{payload.get('detail') or payload.get('message') or payload}"
                    )
                last = (status, payload)
            else:
                last = (status, payload)
        if got:
            info(f"still processing (attempt {attempt}) ...")
            time.sleep(3)
            continue
        break

    status, payload = last if last else (0, None)
    if status == 401:
        raise RuntimeError(
            "Suno API rejected the credentials (401 Unauthorized).\n"
            "      The clip master is encrypted, so your own session is required."
        )
    if status == 404:
        raise RuntimeError(
            "Suno API returned 404 for this clip id - the clip does not exist\n"
            "      or it is not visible to this account."
        )
    if status == 403:
        raise RuntimeError(
            "Suno API returned 403 - this account is not allowed to download\n"
            "      this clip (subscription / sharing permissions)."
        )
    raise RuntimeError(f"Suno API returned {status}: {payload}")


def download_plain(url: str, dest: str, timeout: int = 120) -> int:
    """Download a signed URL.  These may live on any host, so keep it generic."""
    headers = {"User-Agent": USER_AGENT, "Referer": "https://suno.com/"}
    req = urllib.request.Request(url, headers=headers, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        got = 0
        with open(dest, "wb") as fh:
            while True:
                chunk = resp.read(262144)
                if not chunk:
                    break
                fh.write(chunk)
                got += len(chunk)
    if got == 0:
        raise RuntimeError("empty response from download URL")
    return got


# --------------------------------------------------------------------------- #
# 6. Main
# --------------------------------------------------------------------------- #


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="suno_clip_to_mp3.py",
        description="Download a Suno clip and convert it to a playable MP3, "
                    "repairing broken containers automatically.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--url", required=True, help="clip URL (CloudFront / suno)")
    p.add_argument("-o", "--out", default="clip.mp3", help="output MP3 path")
    p.add_argument("--workdir", default=None, help="where to keep temp files")
    p.add_argument("--bitrate", default="192k", help="MP3 bitrate (default 192k)")
    p.add_argument("--token", default=os.environ.get("SUNO_TOKEN"),
                   help="Suno Bearer JWT (or set SUNO_TOKEN)")
    p.add_argument("--cookie", default=os.environ.get("SUNO_COOKIE"),
                   help="Suno session cookie string (or set SUNO_COOKIE)")
    p.add_argument("--device-id", default=os.environ.get("SUNO_DEVICE_ID"),
                   help="optional Suno Device-Id header value")
    p.add_argument("--title", default=None, help="MP3 title tag")
    p.add_argument("--artist", default=None, help="MP3 artist tag")
    p.add_argument("--probe", action="store_true",
                   help="only run the forensic analysis, do not convert")
    p.add_argument("--keep-temp", action="store_true",
                   help="keep the downloaded artefacts")
    p.add_argument("--no-api", action="store_true",
                   help="never contact the Suno download API (skips the route "
                        "that spends a plan download)")
    p.add_argument("--rights-version", type=int, default=None,
                   help="optional 'version' field for the license request")
    p.add_argument("-v", "--verbose", action="store_true")
    return p


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    if not have("ffmpeg"):
        fail("ffmpeg is not on PATH - install it first")
        return 2

    workdir = args.workdir or os.path.dirname(os.path.abspath(args.out)) or "."
    os.makedirs(workdir, exist_ok=True)
    raw_path = os.path.join(workdir, os.path.basename(args.out) + ".source")
    out_path = os.path.abspath(args.out)

    # ---------------- step 1: resolve + download ---------------- #
    head("Step 1/4  Download")
    info(f"URL: {args.url}")
    try:
        media_url, note = resolve_media_url(args.url)
        if note.startswith("resolved"):
            info(note)
        if media_url != args.url:
            info(f"media URL: {media_url}")
        meta = download(media_url, raw_path)
    except Exception as exc:
        fail(f"download failed: {exc}")
        return 1
    ok(f"downloaded {human(meta['bytes'])}  (content-type: {meta['content_type']})")
    if meta["etag"]:
        info(f"etag: {meta['etag']}")

    with open(raw_path, "rb") as fh:
        data = fh.read()

    # ---------------- step 2: forensics ---------------- #
    head("Step 2/4  Forensic analysis")
    f = analyse(data)
    info(f"entropy           : {f.entropy:.4f} bit/byte")
    info(f"chi-square (df255): {f.chi2:.1f}   (uniform/random => ~255)")
    info(f"detected          : {f.kind.upper()}")
    info(f"detail            : {f.detail}")
    if f.boxes:
        preview = ", ".join(
            f"{t}@{o}({s})" for t, o, s in f.boxes[:10]
        )
        info(f"top-level boxes   : {preview}{' ...' if len(f.boxes) > 10 else ''}")

    if args.probe:
        head("Probe only")
        info(f"encrypted_payload = {f.encrypted}")
        return 0

    # ---------------- step 3: recover ---------------- #
    head("Step 3/4  Recover a playable stream")

    work_path = raw_path
    forced_format: Optional[str] = None
    recovered = False

    if f.kind == "mp4":
        if f.has_moov:
            if f.offset == 0:
                ok("MP4 container is intact - remuxing directly")
                work_path = raw_path
                recovered = True
            else:
                warn(f"{f.offset} bytes of garbage in front of the ftyp box")
                candidates = mp4_repair_candidates(data)
                for label, blob in candidates:
                    cand_path = raw_path + ".cand.m4a"
                    with open(cand_path, "wb") as fh:
                        fh.write(blob)
                    if decodes_to_audio(cand_path):
                        ok(f"repair variant '{label}' decodes correctly")
                        work_path = cand_path
                        recovered = True
                        break
                    info(f"repair variant '{label}' does not decode")
                if not recovered:
                    fail("no repair variant produced decodable audio")
                    info(f"raw file kept at: {raw_path}")
                    return 4
        else:
            # No index (moov) -> the container is unusable, but the elementary
            # stream inside mdat usually still is.  Sniff it out.
            warn("MP4 has no moov atom - the sample index is gone")
            payload = mdat_payload(data, f.offset)
            if payload is None:
                fail("no mdat payload to recover from")
                return 4
            info(f"scanning {human(len(payload))} of mdat for an elementary stream")
            chain = scan_adts_chain(payload)
            if chain:
                start, end, frames = chain
                raw_aac = raw_path + ".aac"
                with open(raw_aac, "wb") as fh:
                    fh.write(payload[start:end])
                ok(f"recovered {frames} raw ADTS AAC frames from mdat")
                work_path = raw_aac
                forced_format = "aac"
                recovered = True
            else:
                chain = scan_mpeg_chain(payload)
                if chain:
                    start, end, frames = chain
                    raw_mp3 = raw_path + ".mp3"
                    with open(raw_mp3, "wb") as fh:
                        fh.write(payload[start:end])
                    ok(f"recovered {frames} raw MPEG frames from mdat")
                    work_path = raw_mp3
                    recovered = True
            if not recovered:
                fail("could not recover an elementary stream from mdat")
                info(f"raw file kept at: {raw_path}")
                return 4

    elif f.kind == "adts":
        start, end, frames = f.adts_chain
        raw_aac = raw_path + ".aac"
        with open(raw_aac, "wb") as fh:
            fh.write(data[start:end])
        ok(f"extracted {frames} raw ADTS AAC frames ({human(end - start)})")
        work_path = raw_aac
        forced_format = "aac"
        recovered = True

    elif f.kind == "mpeg":
        start, end, frames = f.mp3_chain
        raw_mp3 = raw_path + ".mp3"
        with open(raw_mp3, "wb") as fh:
            fh.write(data[start:end])
        ok(f"extracted {frames} raw MPEG audio frames ({human(end - start)})")
        work_path = raw_mp3
        recovered = True

    elif f.kind in ("ogg", "flac", "wav"):
        ok(f"{f.kind} container detected - remuxing directly")
        work_path = raw_path
        recovered = True

    elif f.kind == "mpeg-ready":
        ok("standalone MPEG audio stream - remuxing directly")
        work_path = raw_path
        recovered = True

    elif f.encrypted:
        warn("payload is encrypted - this is NOT a container problem")
        info("The public Suno clip URL serves an encrypted streaming master.")
        info("The suno.com player decrypts it with a key from the license")
        info("server; we can do exactly the same, without spending a download.")
        clip_id = extract_clip_id(media_url) or extract_clip_id(args.url)
        if not clip_id:
            fail("could not derive a clip id from the URL")
            return 3
        info(f"clip id: {clip_id}")

        # --- primary route: playback rights (does not use download quota) --- #
        try:
            plain = decrypt_streaming_master(
                data,
                clip_id,
                token=args.token,
                cookie=args.cookie,
                device_id=args.device_id,
                version=args.rights_version,
            )
        except Exception as exc:
            warn(f"playback rights unavailable: {exc}")
            plain = None

        if plain is not None:
            dec_path = raw_path + ".decrypted"
            with open(dec_path, "wb") as fh:
                fh.write(plain)
            plain_facts = analyse(plain)
            if plain_facts.kind in ("unknown", "encrypted"):
                fail("decrypted payload is still not a recognised container")
                info(f"head: {plain[:32].hex()}")
                plain = None
            else:
                ok(f"decrypted the master -> {plain_facts.kind.upper()}: "
                   f"{plain_facts.detail}")
                work_path = dec_path
                forced_format = None
                recovered = True

        # --- fallback: the official download API (uses plan quota) --------- #
        if not recovered:
            if args.no_api:
                fail("--no-api given and playback rights were refused")
                info(f"raw file kept at: {raw_path}")
                return 3
            if not args.token and not args.cookie:
                fail("no Suno credentials available")
                info("Provide your own session with one of:")
                info("  --token  '<JWT from suno.com DevTools>'   (or SUNO_TOKEN)")
                info("  --cookie '__Secure-next-auth.session-token=...' "
                     "(or SUNO_COOKIE)")
                info(f"The encrypted source is kept at: {raw_path}")
                return 3
            warn("falling back to the download API - this spends one of your "
                 "plan downloads")
            for fmt in ("mp3", "m4a"):
                try:
                    info(f"asking the Suno download API for format={fmt} ...")
                    dl_url = fetch_playable_source(
                        clip_id, fmt, args.token, args.cookie, args.device_id
                    )
                except RuntimeError as exc:
                    info(str(exc))
                    if fmt == "mp3":
                        raise
                    continue
                ok(f"got a signed {fmt} download URL")
                plain_path = raw_path + f".plain.{fmt}"
                n = download_plain(dl_url, plain_path)
                ok(f"downloaded the decrypted master ({human(n)})")
                work_path = plain_path
                forced_format = None
                recovered = True
                break
            if not recovered:
                fail("could not obtain a playable master")
                return 3

    else:
        fail(f"unrecognised payload, cannot auto-recover ({f.detail})")
        info(f"raw file kept at: {raw_path}")
        return 4

    # ---------------- step 4: convert ---------------- #
    head("Step 4/4  Convert to MP3")
    tmp_out = out_path + ".tmp.mp3"
    if not convert_to_mp3(
        work_path,
        tmp_out,
        input_format=forced_format,
        bitrate=args.bitrate,
        title=args.title,
        artist=args.artist,
    ):
        return 5

    if not verify_mp3(tmp_out):
        return 5

    os.replace(tmp_out, out_path)

    if not args.keep_temp:
        for path in (raw_path, raw_path + ".repaired.m4a", raw_path + ".cand.m4a",
                     raw_path + ".aac", raw_path + ".mp3", raw_path + ".decrypted",
                     raw_path + ".plain.mp3", raw_path + ".plain.m4a"):
            try:
                os.remove(path)
            except OSError:
                pass

    head("Done")
    ok(f"playable MP3 written to: {out_path}")
    info(f"{human(os.path.getsize(out_path))}  bitrate={args.bitrate}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        sys.exit(130)

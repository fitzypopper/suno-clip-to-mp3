/* Suno Clip -> MP3. Everything runs client side, in the browser. */
(() => {
  "use strict";

  /*
   * Suno's license server only sends CORS headers to suno.com, www.suno.com
   * and http://localhost:<port>. A page served from GitHub Pages therefore
   * cannot call it directly, so a small Cloudflare Worker relays the two
   * calls that need it. The Worker URL is baked in at deploy time; visitors
   * never have to configure anything.
   *
   * Set PROXY to "" to talk to Suno directly (only works on localhost).
   */
  const PROXY = "https://suno-rights-proxy.siggeemilandersson.workers.dev";

  const SUNO_API = "https://studio-api.prod.suno.com";
  const UUID_RE =
    /[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/;

  const $ = (id) => document.getElementById(id);
  const els = {
    url: $("url"), go: $("go"), status: $("status"),
    progress: $("progress"), stageName: $("stage-name"), stagePct: $("stage-pct"),
    barFill: $("bar-fill"), log: $("log"),
    result: $("result"), player: $("player"), meta: $("meta"), dl: $("dl"),
    error: $("error"), errmsg: $("errmsg"),
  };

  /* ----------------------------------------------------------------- ui -- */

  const logLines = [];
  function log(msg, cls) {
    logLines.push(cls ? `<span class="${cls}">${msg}</span>` : msg);
    els.log.innerHTML = logLines.join("\n");
    els.log.scrollTop = els.log.scrollHeight;
  }
  function stage(name, pct) {
    els.stageName.textContent = name;
    els.stagePct.textContent = pct == null ? "" : pct + "%";
    if (pct != null) els.barFill.style.width = pct + "%";
  }
  function show(el, on) { el.classList.toggle("hidden", !on); }
  function fail(msg) {
    show(els.error, true);
    els.errmsg.textContent = msg;
    show(els.progress, false);
    els.go.disabled = false;
  }
  function human(n) {
    const u = ["B", "KiB", "MiB", "GiB"];
    let i = 0;
    while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
    return (i === 0 ? n.toFixed(0) : n.toFixed(1)) + " " + u[i];
  }

  /* -------------------------------------------------------------- utils -- */

  function b64ToBytes(b64) {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  async function getJson(url) {
    const res = await fetch(url, { credentials: "omit" });
    const body = await res.json().catch(() => null);
    if (!res.ok) {
      throw new Error(
        (body && (body.detail || body.error)) || `HTTP ${res.status}`
      );
    }
    return body;
  }

  /* -------------------------------------------------------- url parsing -- */

  /**
   * Turn whatever the user pasted into { clipId }.
   *
   * - CloudFront clip URL : https://<cdn>/1/clip/<uuid>.m4a
   * - song page            : https://suno.com/song/<uuid>
   * - share link           : https://suno.com/s/<shareId>
   */
  async function resolveClip(input) {
    const url = input.trim();
    if (!url) throw new Error("Paste a Suno link first.");

    let m = url.match(/\/clip\/([0-9a-fA-F-]{36})\.m4a/i);
    if (m) return { clipId: m[1].toLowerCase() };

    m = url.match(/suno\.com\/song\/([0-9a-fA-F-]{36})/i);
    if (m) return { clipId: m[1].toLowerCase() };

    m = url.match(/suno\.com\/s\/([A-Za-z0-9_-]+)/i);
    if (m) {
      stage("Resolving share link…", 3);
      const data = await getJson(
        PROXY
          ? `${PROXY}/share?share_id=${encodeURIComponent(m[1])}`
          : `${SUNO_API}/api/share/code/${encodeURIComponent(m[1])}`
      );
      if (!data.content_id) throw new Error("That share link has no clip.");
      log(`share link → clip ${data.content_id}`, "ok");
      return { clipId: data.content_id.toLowerCase() };
    }

    const bare = url.match(UUID_RE);
    if (bare && !/^https?:/i.test(url)) {
      return { clipId: bare[0].toLowerCase() };
    }

    throw new Error(
      "Could not recognise that link.\n" +
      "Expected a CloudFront clip URL, a suno.com/song/<uuid> page or a " +
      "suno.com/s/<id> share link."
    );
  }

  /** Clip metadata: the authoritative CDN media URL plus the title. */
  async function fetchClipMeta(clipId) {
    const data = await getJson(`${SUNO_API}/api/clip/${clipId}`);
    const url =
      (data.media_urls && data.media_urls[0] && data.media_urls[0].url) ||
      data.audio_url ||
      null;
    if (!url || url.includes("/api/forbidden")) {
      throw new Error("This clip does not expose a media URL.");
    }
    return { mediaUrl: url, title: data.title || "" };
  }

  /* ------------------------------------------------------------- crypto -- */

  /** Fetch the decryption rights for a clip. */
  async function fetchRights(clipId) {
    stage("Requesting content key…", 8);
    let res, rights;
    if (PROXY) {
      res = await fetch(`${PROXY}/rights?clip_id=${encodeURIComponent(clipId)}`, {
        credentials: "omit",
      });
      rights = await res.json().catch(() => null);
    } else {
      // direct call - only reachable from http://localhost
      res = await fetch(`${SUNO_API}/api/mango/rights`, {
        method: "POST",
        credentials: "omit",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          content_params: { content_id: clipId, content_type: "clip" },
        }),
      });
      rights = await res.json().catch(() => null);
    }
    if (!res.ok) {
      throw new Error(
        `License server returned ${res.status}: ` +
        ((rights && (rights.detail || rights.error)) || "unknown error")
      );
    }
    if (!rights || !rights.key || !rights.iv) {
      throw new Error("License server did not grant rights for this clip.");
    }
    return rights;
  }

  /** Open an AES-GCM sealed blob: [12 byte iv][ciphertext][16 byte tag]. */
  async function unwrap(blobB64, aad, sealingKey) {
    const blob = b64ToBytes(blobB64);
    const iv = blob.slice(0, 12);
    const ct = blob.slice(12); // ciphertext || tag
    const key = await crypto.subtle.importKey(
      "raw", sealingKey, { name: "AES-GCM" }, false, ["decrypt"]
    );
    const plain = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv, additionalData: new TextEncoder().encode(aad) },
      key,
      ct
    );
    return new Uint8Array(plain);
  }

  /** AES-128-CTR with a full 128-bit big-endian counter block. */
  async function ctrDecrypt(bytes, keyBytes, ivBytes) {
    const key = await crypto.subtle.importKey(
      "raw", keyBytes, { name: "AES-CTR" }, false, ["decrypt"]
    );
    const plain = await crypto.subtle.decrypt(
      { name: "AES-CTR", counter: ivBytes, length: 128 },
      key,
      bytes
    );
    return new Uint8Array(plain);
  }

  /* -------------------------------------------------------------- fetch -- */

  async function fetchMedia(url, onProgress) {
    const res = await fetch(url, { credentials: "omit" });
    if (!res.ok) throw new Error(`Media request failed: HTTP ${res.status}`);
    const total = Number(res.headers.get("Content-Length")) || 0;
    if (!res.body) return new Uint8Array(await res.arrayBuffer());

    const reader = res.body.getReader();
    const chunks = [];
    let got = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
      got += value.length;
      if (total) onProgress(Math.floor((got / total) * 100), got, total);
    }
    const out = new Uint8Array(got);
    let off = 0;
    for (const c of chunks) { out.set(c, off); off += c.length; }
    return out;
  }

  /* ------------------------------------------------------------- encode -- */

  function floatToInt16(f32) {
    const out = new Int16Array(f32.length);
    for (let i = 0; i < f32.length; i++) {
      const s = f32[i] < 0 ? f32[i] * 0x8000 : f32[i] * 0x7fff;
      out[i] = Math.max(-32768, Math.min(32767, Math.round(s)));
    }
    return out;
  }

  async function encodeMp3(audioBuffer, kbps, onProgress) {
    if (typeof lamejs === "undefined" || !lamejs.Mp3Encoder) {
      throw new Error("MP3 encoder (lame.min.js) did not load.");
    }
    const channels = Math.min(2, audioBuffer.numberOfChannels);
    const sampleRate = audioBuffer.sampleRate;
    const encoder = new lamejs.Mp3Encoder(channels, sampleRate, kbps);

    const left = floatToInt16(audioBuffer.getChannelData(0));
    const right =
      channels > 1 ? floatToInt16(audioBuffer.getChannelData(1)) : null;

    const blockSize = 1152;
    const parts = [];
    for (let i = 0; i < left.length; i += blockSize) {
      const l = left.subarray(i, i + blockSize);
      const r = right ? right.subarray(i, i + blockSize) : null;
      const buf = r ? encoder.encodeBuffer(l, r) : encoder.encodeBuffer(l);
      if (buf.length) parts.push(new Int8Array(buf));
      if ((i / blockSize) % 200 === 0) {
        onProgress(Math.floor((i / left.length) * 100));
        await new Promise((r) => setTimeout(r, 0));
      }
    }
    const tail = encoder.flush();
    if (tail.length) parts.push(new Int8Array(tail));

    let size = 0;
    for (const p of parts) size += p.length;
    const out = new Uint8Array(size);
    let off = 0;
    for (const p of parts) { out.set(p, off); off += p.length; }
    onProgress(100);
    return out;
  }

  /* --------------------------------------------------------------- main -- */

  async function run() {
    logLines.length = 0;
    els.log.innerHTML = "";
    show(els.error, false);
    show(els.result, false);
    show(els.progress, true);
    els.go.disabled = true;

    try {
      const clip = await resolveClip(els.url.value);
      log(`clip id: ${clip.clipId}`);

      const meta = await fetchClipMeta(clip.clipId);
      log(`media url: ${meta.mediaUrl}`);
      if (meta.title) log(`title: ${meta.title}`);

      const rights = await fetchRights(clip.clipId);
      log("license rights granted", "ok");

      stage("Downloading encrypted master…", 12);
      const cipher = await fetchMedia(meta.mediaUrl, (pct, got, total) => {
        stage(`Downloading encrypted master… ${human(got)}`, 12 + pct * 0.28);
      });
      log(`master: ${human(cipher.length)}`);

      stage("Unwrapping content key…", 46);
      const glt = rights.glt || "";
      const sealingKey = await crypto.subtle.digest(
        "SHA-256",
        new TextEncoder().encode(glt)
      );
      const keyBytes = await unwrap(rights.key, clip.clipId, sealingKey);
      const ivBytes = await unwrap(rights.iv, clip.clipId, sealingKey);
      if (keyBytes.length !== 16 || ivBytes.length !== 16) {
        throw new Error("Unexpected content key size.");
      }
      log("content key unwrapped", "ok");

      stage("Decrypting…", 54);
      const plain = await ctrDecrypt(cipher, keyBytes, ivBytes);
      const head = String.fromCharCode(...plain.slice(4, 8));
      if (head !== "ftyp") {
        throw new Error(
          "Decryption did not produce an MP4 container " +
          `(got "${head}"). The clip may use a different delivery.`
        );
      }
      log("decrypted to a valid MP4", "ok");

      stage("Decoding audio…", 60);
      const AudioCtx = window.AudioContext || window.webkitAudioContext;
      const ctx = new AudioCtx();
      const copy = plain.slice().buffer;
      const audioBuffer = await ctx.decodeAudioData(copy);
      const dur = audioBuffer.duration;
      log(
        `decoded ${dur.toFixed(1)}s, ${audioBuffer.numberOfChannels}ch @ ` +
        `${audioBuffer.sampleRate} Hz`,
        "ok"
      );

      stage("Encoding MP3…", 65);
      const mp3 = await encodeMp3(audioBuffer, 192, (pct) => {
        stage(`Encoding MP3… ${pct}%`, 65 + pct * 0.33);
      });

      const blob = new Blob([mp3], { type: "audio/mpeg" });
      const slug = (meta.title || clip.clipId)
        .replace(/[^\w\d -]+/g, "")
        .trim()
        .replace(/\s+/g, "-")
        .slice(0, 60) || clip.clipId;
      const name = `suno-${slug}.mp3`;
      const objectUrl = URL.createObjectURL(blob);

      els.player.src = objectUrl;
      els.dl.href = objectUrl;
      els.dl.setAttribute("download", name);
      els.meta.textContent =
        `${name} · ${human(blob.size)} · ${dur.toFixed(1)}s · ` +
        `${audioBuffer.sampleRate} Hz · ${audioBuffer.numberOfChannels}ch · 192 kbps`;
      log("done", "ok");

      stage("Done", 100);
      show(els.result, true);
      els.go.disabled = false;
    } catch (err) {
      fail((err && err.message) || String(err));
      console.error(err);
    }
  }

  /* --------------------------------------------------------------- init -- */

  async function probe() {
    if (!PROXY) {
      els.status.textContent = "direct (localhost only)";
      els.status.className = "status warn";
      return;
    }
    els.status.textContent = "checking relay…";
    try {
      const res = await fetch(`${PROXY}/health`, { credentials: "omit" });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      els.status.textContent = "relay online";
      els.status.className = "status ok";
    } catch (e) {
      els.status.textContent = "relay unreachable";
      els.status.className = "status bad";
    }
  }

  els.go.addEventListener("click", run);
  els.url.addEventListener("keydown", (e) => {
    if (e.key === "Enter") run();
  });

  probe();
})();

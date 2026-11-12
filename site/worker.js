/**
 * Cloudflare Worker - CORS relay for Suno's license server.
 *
 * Suno's /api/mango/rights endpoint only returns Access-Control-Allow-Origin
 * for suno.com, www.suno.com and http://localhost:<port>. A page served from
 * GitHub Pages therefore cannot call it from the browser, and suno.com pages
 * send no CORS headers either, so link resolution has to happen here too.
 *
 * This Worker does exactly two things and nothing else:
 *   GET /rights?clip_id=<uuid>  ->  POST studio-api.prod.suno.com/api/mango/rights
 *   GET /resolve?url=<suno url>  ->  fetch the page, extract the clip URL
 *
 * It stores nothing, logs nothing beyond Cloudflare's own request logs, and
 * only ever talks to suno.com hosts.
 *
 * Deploy:  npm i -g wrangler && wrangler deploy worker.js
 */

const SUNO_API = "https://studio-api.prod.suno.com";
const SUNO_HOSTS = new Set(["suno.com", "www.suno.com"]);

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
  "Access-Control-Max-Age": "86400",
};

const UUID_RE =
  /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

export default {
  async fetch(request) {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: CORS });
    }

    if (url.pathname === "/health") {
      return json({ ok: true, service: "suno-rights-proxy" });
    }

    if (url.pathname === "/rights") {
      const clipId = (url.searchParams.get("clip_id") || "").trim();
      if (!UUID_RE.test(clipId)) {
        return json({ error: "clip_id must be a uuid" }, 400);
      }

      let upstream;
      try {
        upstream = await fetch(`${SUNO_API}/api/mango/rights`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Accept: "application/json",
            Referer: "https://suno.com/",
            "User-Agent":
              "Mozilla/5.0 (X11; Linux x86_64; rv:159.0) Gecko/20100101 Firefox/159.0",
          },
          body: JSON.stringify({
            content_params: {
              content_id: clipId.toLowerCase(),
              content_type: "clip",
            },
          }),
        });
      } catch (e) {
        return json({ error: `upstream unreachable: ${e.message}` }, 502);
      }

      const body = await upstream.text();
      if (!upstream.ok) {
        return new Response(
          JSON.stringify({
            error: "license server refused the clip",
            status: upstream.status,
            detail: body.slice(0, 400),
          }),
          { status: upstream.status, headers: { ...CORS, "Content-Type": "application/json" } }
        );
      }
      return new Response(body, {
        status: 200,
        headers: { ...CORS, "Content-Type": "application/json", "Cache-Control": "no-store" },
      });
    }

    // Resolve a short share id (suno.com/s/<id>) to its clip id.
    if (url.pathname === "/share") {
      const shareId = (url.searchParams.get("share_id") || "").trim();
      if (!/^[A-Za-z0-9_-]{1,64}$/.test(shareId)) {
        return json({ error: "share_id looks wrong" }, 400);
      }
      let upstream;
      try {
        upstream = await fetch(
          `${SUNO_API}/api/share/code/${encodeURIComponent(shareId)}`,
          { headers: { Accept: "application/json", Referer: "https://suno.com/" } }
        );
      } catch (e) {
        return json({ error: `upstream unreachable: ${e.message}` }, 502);
      }
      const body = await upstream.text();
      return new Response(body, {
        status: upstream.status,
        headers: { ...CORS, "Content-Type": "application/json", "Cache-Control": "no-store" },
      });
    }

    // Resolve a suno.com song page or share link to a clip id.
    if (url.pathname === "/resolve") {
      const target = (url.searchParams.get("url") || "").trim();
      let parsed;
      try {
        parsed = new URL(target);
      } catch {
        return json({ error: "url is not valid" }, 400);
      }
      if (!SUNO_HOSTS.has(parsed.hostname)) {
        return json({ error: "only suno.com links can be resolved" }, 400);
      }

      let html;
      try {
        const res = await fetch(parsed.toString(), {
          redirect: "follow",
          headers: {
            "User-Agent":
              "Mozilla/5.0 (X11; Linux x86_64; rv:159.0) Gecko/20100101 Firefox/159.0",
            Accept: "text/html,application/xhtml+xml",
          },
        });
        if (!res.ok) {
          return json({ error: `page returned ${res.status}` }, 502);
        }
        html = await res.text();
      } catch (e) {
        return json({ error: `could not load page: ${e.message}` }, 502);
      }

      const m =
        html.match(/\/1\/clip\/([0-9a-fA-F-]{36})\.m4a/i) ||
        html.match(/\/clip\/([0-9a-fA-F-]{36})\.m4a/i);
      if (!m) {
        return json({ error: "no clip id found on that page (private song?)" }, 404);
      }
      const clipId = m[1].toLowerCase();
      return json({
        clipId,
        mediaUrl: `https://d2lwuy8qc234o3.cloudfront.net/1/clip/${clipId}.m4a`,
      });
    }

    return json({ error: "not found" }, 404);
  },
};

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { ...CORS, "Content-Type": "application/json" },
  });
}

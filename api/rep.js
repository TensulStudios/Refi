// /api/rep.js
export default async function handler(req, res) {
  const { url } = req.query;
  if (!url) return res.status(400).send("Missing ?url parameter");

  if (!/^https?:\/\//i.test(url)) return res.status(400).send("Invalid URL");

  try {
    // Fetch remote resource and follow redirects
    const response = await fetch(url, { redirect: "follow" });
    const contentType = response.headers.get("content-type") || "application/octet-stream";
    const buffer = await response.arrayBuffer();

    // Set universal CORS headers
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET,OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "*");
    res.setHeader("Cache-Control", "no-store");

    // If HTML, rewrite internal links/images/etc to go through proxy
    if (contentType.includes("text/html")) {
      let html = new TextDecoder().decode(buffer);
      const proxyBase = "https://refl.temporarystudios.org/api/rep?url=";
      const base = new URL(url);

      html = html.replace(
        /(<(a|img|script|link|iframe)[^>]+?(href|src)=["'])([^"']+)(["'])/gi,
        (match, p1, _tag, _attr, target, p5) => {
          try {
            const abs = new URL(target, base).href;
            return `${p1}${proxyBase}${encodeURIComponent(abs)}${p5}`;
          } catch {
            return match; // leave broken URLs untouched
          }
        }
      );

      res.setHeader("Content-Type", "text/html; charset=utf-8");
      res.status(200).send(html);
      return;
    }

    // Otherwise, stream the file as-is
    res.setHeader("Content-Type", contentType);
    res.status(200).send(Buffer.from(buffer));

  } catch (err) {
    console.error("Proxy error:", err);
    res.status(500).send("Fetch failed: " + err.message);
  }
}

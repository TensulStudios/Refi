export default async function handler(req, res) {
  const { url } = req.query;
  if (!url) return res.status(400).send("Missing ?url parameter");
  if (!/^https?:\/\//i.test(url)) return res.status(400).send("Invalid URL");

  const USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.117 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.117 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0"
  ];
  const randomUA = USER_AGENTS[Math.floor(Math.random() * USER_AGENTS.length)];

  try {
    const response = await fetch(url, {
      redirect: "follow",
      headers: { "User-Agent": randomUA }
    });

    const contentType = response.headers.get("content-type") || "application/octet-stream";
    const buffer = await response.arrayBuffer();

    // Universal CORS
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET,OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "*");
    res.setHeader("Cache-Control", "no-store");

    // If HTML, rewrite links and form actions
    if (contentType.includes("text/html")) {
      let html = new TextDecoder().decode(buffer);
      const proxyBase = "https://refl.temporarystudios.org/api/rep?url=";
      const base = new URL(url);

      // Replace href/src/action URLs
      html = html.replace(
        /(<(a|img|script|link|iframe|form)[^>]+?(href|src|action)=["'])([^"']+)(["'])/gi,
        (match, p1, _tag, _attr, target, p5) => {
          try {
            const abs = new URL(target, base).href;
            return `${p1}${proxyBase}${encodeURIComponent(abs)}${p5}`;
          } catch {
            return match;
          }
        }
      );

      // Optionally: rewrite <base href> too
      html = html.replace(
        /<base[^>]+href=["']([^"']+)["'][^>]*>/i,
        `<base href="${proxyBase}${encodeURIComponent(base.href)}">`
      );

      res.setHeader("Content-Type", "text/html; charset=utf-8");
      res.status(200).send(html);
      return;
    }

    // Otherwise, stream as-is
    res.setHeader("Content-Type", contentType);
    res.status(200).send(Buffer.from(buffer));

  } catch (err) {
    console.error("Proxy error:", err);
    res.status(500).send("Fetch failed: " + err.message);
  }
}

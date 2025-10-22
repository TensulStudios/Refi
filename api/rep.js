// /api/rep.js
export default async function handler(req, res) {
  // Only allow GET requests
  if (req.method === 'OPTIONS') {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET,OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "*");
    return res.status(200).end();
  }
  
  if (req.method !== 'GET') {
    return res.status(405).send("Method not allowed");
  }

  let { url } = req.query;
  if (!url) return res.status(400).send("Missing url parameter");

  // Decode URL if it's encoded
  try {
    url = decodeURIComponent(url);
  } catch (e) {
    return res.status(400).send("Invalid URL encoding");
  }

  // Validate URL format
  if (!/^https?:\/\//i.test(url)) {
    return res.status(400).send("Invalid URL protocol - only http/https allowed");
  }

  let parsedUrl;
  try {
    parsedUrl = new URL(url);
  } catch (e) {
    return res.status(400).send("Malformed URL");
  }

  // Security: Block private/internal IP addresses and localhost
  const hostname = parsedUrl.hostname.toLowerCase();
  const blockedPatterns = [
    /^localhost$/i,
    /^127\./,
    /^10\./,
    /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
    /^192\.168\./,
    /^169\.254\./, // Link-local
    /^::1$/, // IPv6 localhost
    /^fe80:/i, // IPv6 link-local
    /^fc00:/i, // IPv6 private
  ];

  if (blockedPatterns.some(pattern => pattern.test(hostname))) {
    return res.status(403).send("Access to private/internal addresses is forbidden");
  }

  // Optional: Whitelist specific domains (uncomment to enable)
  // const allowedDomains = ['example.com', 'wikipedia.org'];
  // if (!allowedDomains.some(domain => hostname.endsWith(domain))) {
  //   return res.status(403).send("Domain not allowed");
  // }

  const USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.117 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.117 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0"
  ];
  const randomUA = USER_AGENTS[Math.floor(Math.random() * USER_AGENTS.length)];

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000); // 10 second timeout

    const response = await fetch(url, {
      redirect: "follow",
      headers: {
        "User-Agent": randomUA,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
      },
      signal: controller.signal,
      // Limit redirects
      follow: 5
    });

    clearTimeout(timeoutId);

    // Check response size (limit to 10MB)
    const contentLength = response.headers.get("content-length");
    if (contentLength && parseInt(contentLength) > 10 * 1024 * 1024) {
      return res.status(413).send("Content too large");
    }

    const contentType = response.headers.get("content-type") || "application/octet-stream";
    
    // Security: Only proxy safe content types
    const allowedTypes = [
      'text/html',
      'text/css',
      'text/javascript',
      'application/javascript',
      'application/json',
      'image/',
      'font/',
      'application/xml',
      'text/xml'
    ];

    const isSafeType = allowedTypes.some(type => contentType.toLowerCase().includes(type));
    if (!isSafeType) {
      return res.status(403).send("Content type not allowed");
    }

    const buffer = await response.arrayBuffer();

    // CORS headers
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET,OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "*");
    res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate");
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "SAMEORIGIN");
    
    // Content Security Policy
    res.setHeader("Content-Security-Policy", "default-src 'self' 'unsafe-inline' 'unsafe-eval' *; frame-ancestors 'self'");

    if (contentType.includes("text/html")) {
      let html = new TextDecoder().decode(buffer);
      const proxyBase = `${req.headers['x-forwarded-proto'] || 'https'}://${req.headers.host}/api/rep?url=`;
      const base = new URL(url);

      // Inject base tag at the top of <head>
      html = html.replace(
        /(<head[^>]*>)/i,
        `$1\n<base href="${proxyBase}${encodeURIComponent(base.href)}">`
      );

      // Rewrite absolute URLs in attributes
      html = html.replace(
        /(<(?:a|img|script|link|iframe|form|source|video|audio)[^>]+?(?:href|src|action|data)=["'])([^"']+)(["'])/gi,
        (match, p1, target, p3) => {
          try {
            // Skip if already proxied or is a data URI
            if (target.startsWith(proxyBase) || target.startsWith('data:') || target.startsWith('javascript:') || target.startsWith('#')) {
              return match;
            }
            const abs = new URL(target, base).href;
            return `${p1}${proxyBase}${encodeURIComponent(abs)}${p3}`;
          } catch {
            return match;
          }
        }
      );

      // Rewrite CSS url() references
      html = html.replace(
        /url\(['"]?([^'")\s]+)['"]?\)/gi,
        (match, cssUrl) => {
          try {
            if (cssUrl.startsWith(proxyBase) || cssUrl.startsWith('data:')) {
              return match;
            }
            const abs = new URL(cssUrl, base).href;
            return `url('${proxyBase}${encodeURIComponent(abs)}')`;
          } catch {
            return match;
          }
        }
      );

      res.setHeader("Content-Type", "text/html; charset=utf-8");
      res.status(200).send(html);
      return;
    }

    // Stream other files as-is
    res.setHeader("Content-Type", contentType);
    res.status(200).send(Buffer.from(buffer));
  } catch (err) {
    console.error("Proxy error:", err);
    if (err.name === 'AbortError') {
      return res.status(504).send("Request timeout");
    }
    res.status(500).send("Fetch failed: " + err.message);
  }
}
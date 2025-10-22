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

  // If URL doesn't start with http/https, assume it's incomplete and reject it
  if (!/^https?:\/\//i.test(url)) {
    return res.status(400).send("Invalid URL protocol - only http/https allowed. Full URL required.");
  }

  let parsedUrl;
  try {
    parsedUrl = new URL(url);
  } catch (e) {
    return res.status(400).send("Malformed URL");
  }

  // Security: Block private/internal IP addresses, localhost, and cloud metadata endpoints
  const hostname = parsedUrl.hostname.toLowerCase();
  const blockedPatterns = [
    /^localhost$/i,
    /^127\./,
    /^10\./,
    /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
    /^192\.168\./,
    /^169\.254\./, // Link-local & AWS/GCP/Azure metadata endpoint
    /^::1$/, // IPv6 localhost
    /^fe80:/i, // IPv6 link-local
    /^fc00:/i, // IPv6 private
    /^fd00:/i, // IPv6 unique local
  ];

  // Block cloud metadata endpoints explicitly
  const blockedHosts = [
    'metadata.google.internal',
    '169.254.169.254', // AWS/GCP/Azure/Oracle metadata
    'metadata.azure.com',
    'metadata.packet.net',
  ];

  if (blockedPatterns.some(pattern => pattern.test(hostname)) || 
      blockedHosts.includes(hostname)) {
    return res.status(403).send("Access to private/internal addresses is forbidden");
  }

  // Additional check: Resolve and validate IP address isn't private
  // Note: This requires DNS resolution which may not be available in all environments
  try {
    const dns = require('dns').promises;
    const addresses = await dns.resolve4(hostname).catch(() => []);
    for (const addr of addresses) {
      if (blockedPatterns.some(pattern => pattern.test(addr))) {
        return res.status(403).send("Domain resolves to private IP address");
      }
    }
  } catch (e) {
    // DNS check failed, continue anyway (serverless may not have DNS access)
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
      redirect: "manual", // Don't follow redirects automatically
      headers: {
        "User-Agent": randomUA,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
      },
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    // Handle redirects manually to avoid loops
    if (response.status >= 300 && response.status < 400) {
      const location = response.headers.get('location');
      if (location) {
        try {
          const redirectUrl = new URL(location, url).href;
          const proxyBase = `${req.headers['x-forwarded-proto'] || 'https'}://${req.headers.host}/api/rep?url=`;
          return res.redirect(302, `${proxyBase}${encodeURIComponent(redirectUrl)}`);
        } catch (e) {
          return res.status(400).send("Invalid redirect location");
        }
      }
    }

    // Check response size (limit to 10MB)
    const contentLength = response.headers.get("content-length");
    if (contentLength && parseInt(contentLength) > 10 * 1024 * 1024) {
      return res.status(413).send("Content too large");
    }

    const contentType = response.headers.get("content-type") || "";
    
    // Security: Only proxy safe content types
    const allowedTypes = [
      'text/',
      'application/javascript',
      'application/x-javascript',
      'application/ecmascript',
      'application/json',
      'application/xml',
      'application/xhtml+xml',
      'image/',
      'video/',
      'audio/',
      'font/',
      'application/font',
      'application/wasm',
      'application/octet-stream', // Allow for JS files without proper content-type
    ];

    // Also check file extension if content-type is missing or generic
    const urlPath = parsedUrl.pathname.toLowerCase();
    const safeExtensions = ['.js', '.css', '.html', '.json', '.xml', '.svg', '.png', '.jpg', '.jpeg', '.gif', '.webp', '.ico', '.woff', '.woff2', '.ttf', '.otf', '.eot', '.mp3', '.mp4', '.webm', '.wav', '.ogg'];
    
    const isSafeType = allowedTypes.some(type => contentType.toLowerCase().includes(type)) ||
                       safeExtensions.some(ext => urlPath.endsWith(ext)) ||
                       contentType === ""; // Allow empty content-type

    if (!isSafeType) {
      return res.status(403).send("Content type not allowed: " + contentType);
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

      // Inject base tag and modify forms to work with proxy
      html = html.replace(
        /(<head[^>]*>)/i,
        `$1\n<base href="${proxyBase}${encodeURIComponent(base.href)}">\n<script>
// Intercept form submissions BEFORE DOMContentLoaded
(function() {
  const proxyBase = '${proxyBase}';
  const currentUrl = '${base.href}';
  
  // Use capture phase to intercept before form submits
  document.addEventListener('submit', function(e) {
    const form = e.target;
    if (form.tagName !== 'FORM') return;
    
    e.preventDefault();
    e.stopPropagation();
    
    const formData = new FormData(form);
    const params = new URLSearchParams(formData);
    
    // Determine the full action URL
    let actionUrl;
    try {
      const action = form.getAttribute('action') || window.location.href;
      actionUrl = new URL(action, currentUrl);
    } catch {
      actionUrl = new URL(currentUrl);
    }
    
    if (form.method.toUpperCase() === 'GET' || !form.method) {
      // For GET forms, append params to URL
      actionUrl.search = params.toString();
      window.location.href = proxyBase + encodeURIComponent(actionUrl.href);
    } else {
      // For POST forms
      form.setAttribute('action', proxyBase + encodeURIComponent(actionUrl.href));
      form.submit();
    }
  }, true); // Use capture phase
})();
</script>`
      );

      // Rewrite absolute URLs in attributes
      html = html.replace(
        /(<(?:a|img|script|link|iframe|form|source|video|audio)[^>]+?(?:href|src|action|data)=["'])([^"']+)(["'])/gi,
        (match, p1, target, p3) => {
          try {
            // Skip if already proxied, is a data URI, javascript, or fragment
            if (target.startsWith(proxyBase) || target.startsWith('data:') || 
                target.startsWith('javascript:') || target.startsWith('blob:') ||
                target.startsWith('#') || target === '') {
              return match;
            }
            
            // Skip relative URLs that are just query strings (like ?q=search)
            if (target.startsWith('?') || target.startsWith('&')) {
              const abs = new URL(target, base).href;
              return `${p1}${proxyBase}${encodeURIComponent(abs)}${p3}`;
            }
            
            const abs = new URL(target, base).href;
            
            // Avoid rewriting if it creates a loop (same URL)
            if (abs === url) {
              return match;
            }
            
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

    // Rewrite CSS files
    if (contentType.includes("text/css")) {
      let css = new TextDecoder().decode(buffer);
      const proxyBase = `${req.headers['x-forwarded-proto'] || 'https'}://${req.headers.host}/api/rep?url=`;
      const base = new URL(url);

      // Rewrite @import statements
      css = css.replace(
        /@import\s+(['"]?)([^'")\s]+)\1/gi,
        (match, quote, importUrl) => {
          try {
            if (importUrl.startsWith(proxyBase) || importUrl.startsWith('data:')) {
              return match;
            }
            const abs = new URL(importUrl, base).href;
            return `@import ${quote}${proxyBase}${encodeURIComponent(abs)}${quote}`;
          } catch {
            return match;
          }
        }
      );

      // Rewrite url() references
      css = css.replace(
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

      res.setHeader("Content-Type", "text/css; charset=utf-8");
      res.status(200).send(css);
      return;
    }

    // Rewrite JavaScript files (limited - mainly for dynamic imports)
    if (contentType.includes("javascript") || contentType.includes("ecmascript") || urlPath.endsWith('.js')) {
      let js = new TextDecoder().decode(buffer);
      const proxyBase = `${req.headers['x-forwarded-proto'] || 'https'}://${req.headers.host}/api/rep?url=`;
      const base = new URL(url);

      // Rewrite dynamic imports - import('...')
      js = js.replace(
        /import\s*\(\s*['"`]([^'"`]+)['"`]\s*\)/gi,
        (match, importUrl) => {
          try {
            if (importUrl.startsWith(proxyBase) || importUrl.startsWith('data:') || importUrl.startsWith('blob:')) {
              return match;
            }
            const abs = new URL(importUrl, base).href;
            return `import('${proxyBase}${encodeURIComponent(abs)}')`;
          } catch {
            return match;
          }
        }
      );

      // Rewrite static imports - import ... from '...'
      js = js.replace(
        /from\s+['"`]([^'"`]+)['"`]/gi,
        (match, importUrl) => {
          try {
            // Skip if it looks like a node module or already proxied
            if (!importUrl.startsWith('.') && !importUrl.startsWith('/') && !importUrl.startsWith('http')) {
              return match;
            }
            if (importUrl.startsWith(proxyBase) || importUrl.startsWith('data:')) {
              return match;
            }
            const abs = new URL(importUrl, base).href;
            return `from '${proxyBase}${encodeURIComponent(abs)}'`;
          } catch {
            return match;
          }
        }
      );

      res.setHeader("Content-Type", "application/javascript; charset=utf-8");
      res.status(200).send(js);
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
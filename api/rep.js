// /api/rep.js
export default async function handler(req, res) {
  if (req.method === 'OPTIONS') {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "*");
    return res.status(200).end();
  }
  
  if (req.method !== 'GET' && req.method !== 'POST') {
    return res.status(405).send("Method not allowed");
  }

  let { url } = req.query;
  
  if (!url) return res.status(400).send("Missing url parameter");

  try {
    url = decodeURIComponent(url);
  } catch (e) {
    return res.status(400).send("Invalid URL encoding");
  }

  if (!/^https?:\/\//i.test(url)) {
    return res.status(400).send("Invalid URL protocol");
  }

  let parsedUrl;
  try {
    parsedUrl = new URL(url);
  } catch (e) {
    return res.status(400).send("Malformed URL");
  }

  // Security checks
  const hostname = parsedUrl.hostname.toLowerCase();
  const blockedPatterns = [
    /^localhost$/i, /^127\./, /^10\./, /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
    /^192\.168\./, /^169\.254\./, /^::1$/, /^fe80:/i, /^fc00:/i, /^fd00:/i,
  ];
  const blockedHosts = ['metadata.google.internal', '169.254.169.254', 'metadata.azure.com'];

  if (blockedPatterns.some(p => p.test(hostname)) || blockedHosts.includes(hostname)) {
    return res.status(403).send("Access to private addresses forbidden");
  }

  const USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/118.0.5993.117 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/605.1.15 Version/17.6 Safari/605.1.15",
  ];
  const randomUA = USER_AGENTS[Math.floor(Math.random() * USER_AGENTS.length)];

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 15000);

    const fetchOptions = {
      redirect: "follow", // Follow redirects automatically
      headers: {
        "User-Agent": randomUA,
        "Accept": req.headers.accept || "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Referer": parsedUrl.origin,
      },
      signal: controller.signal,
    };

    // Handle POST requests
    if (req.method === 'POST') {
      fetchOptions.method = 'POST';
      fetchOptions.body = JSON.stringify(req.body);
      fetchOptions.headers['Content-Type'] = 'application/x-www-form-urlencoded';
    }

    const response = await fetch(url, fetchOptions);
    clearTimeout(timeoutId);

    const contentLength = response.headers.get("content-length");
    if (contentLength && parseInt(contentLength) > 10 * 1024 * 1024) {
      return res.status(413).send("Content too large");
    }

    const contentType = response.headers.get("content-type") || "";
    const finalUrl = response.url; // Get final URL after redirects
    const base = new URL(finalUrl);
    
    // Build proxy base URL
    const protocol = req.headers['x-forwarded-proto'] || 'https';
    const proxyBase = `${protocol}://${req.headers.host}/api/rep?url=`;

    // Set cache headers for static resources
    const isStatic = /\.(js|css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|otf|eot)$/i.test(base.pathname);
    
    // CORS and security headers
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
    res.setHeader("X-Content-Type-Options", "nosniff");
    
    // Cache static resources for 1 hour, HTML for 5 minutes
    if (isStatic) {
      res.setHeader("Cache-Control", "public, max-age=3600, s-maxage=3600");
    } else if (contentType.includes("text/html")) {
      res.setHeader("Cache-Control", "public, max-age=300, s-maxage=300");
    } else {
      res.setHeader("Cache-Control", "public, max-age=1800, s-maxage=1800");
    }

    const buffer = await response.arrayBuffer();

    // Process HTML
    if (contentType.includes("text/html")) {
      let html = new TextDecoder().decode(buffer);

      // Remove existing base tags to avoid conflicts
      html = html.replace(/<base\s+[^>]*>/gi, '');

      // Inject our proxy script early in head
      html = html.replace(
        /(<head[^>]*>)/i,
        `$1
<script>
(function() {
  const PROXY_BASE = '${proxyBase}';
  const ORIGINAL_URL = '${base.href}';
  const ORIGINAL_ORIGIN = '${base.origin}';
  
  // Rewrite URL to use proxy
  function rewriteUrl(urlStr) {
    if (!urlStr || urlStr.startsWith(PROXY_BASE) || urlStr.startsWith('data:') || 
        urlStr.startsWith('javascript:') || urlStr.startsWith('blob:') || urlStr.startsWith('#')) {
      return urlStr;
    }
    
    try {
      const absolute = new URL(urlStr, ORIGINAL_URL).href;
      return PROXY_BASE + encodeURIComponent(absolute);
    } catch {
      return urlStr;
    }
  }
  
  // Override fetch
  const originalFetch = window.fetch;
  window.fetch = function(resource, init) {
    if (typeof resource === 'string') {
      resource = rewriteUrl(resource);
    } else if (resource instanceof Request) {
      resource = new Request(rewriteUrl(resource.url), resource);
    }
    return originalFetch(resource, init);
  };
  
  // Override XMLHttpRequest
  const XHR = XMLHttpRequest.prototype;
  const originalOpen = XHR.open;
  XHR.open = function(method, url, ...args) {
    return originalOpen.call(this, method, rewriteUrl(url), ...args);
  };
  
  // Intercept dynamic script/link creation
  const originalCreateElement = document.createElement;
  document.createElement = function(tagName) {
    const element = originalCreateElement.call(document, tagName);
    
    if (tagName.toLowerCase() === 'script') {
      const srcDescriptor = Object.getOwnPropertyDescriptor(HTMLScriptElement.prototype, 'src');
      Object.defineProperty(element, 'src', {
        get: srcDescriptor.get,
        set: function(value) {
          srcDescriptor.set.call(this, rewriteUrl(value));
        }
      });
    } else if (tagName.toLowerCase() === 'link') {
      const hrefDescriptor = Object.getOwnPropertyDescriptor(HTMLLinkElement.prototype, 'href');
      Object.defineProperty(element, 'href', {
        get: hrefDescriptor.get,
        set: function(value) {
          hrefDescriptor.set.call(this, rewriteUrl(value));
        }
      });
    } else if (tagName.toLowerCase() === 'img') {
      const srcDescriptor = Object.getOwnPropertyDescriptor(HTMLImageElement.prototype, 'src');
      Object.defineProperty(element, 'src', {
        get: srcDescriptor.get,
        set: function(value) {
          srcDescriptor.set.call(this, rewriteUrl(value));
        }
      });
    }
    
    return element;
  };
  
  // Handle form submissions
  document.addEventListener('submit', function(e) {
    const form = e.target;
    if (form.tagName !== 'FORM') return;
    
    e.preventDefault();
    e.stopImmediatePropagation();
    
    const formData = new FormData(form);
    const method = (form.method || 'GET').toUpperCase();
    const action = form.action || window.location.href;
    
    try {
      const actionUrl = new URL(action, ORIGINAL_URL);
      
      if (method === 'GET') {
        const params = new URLSearchParams(formData);
        actionUrl.search = params.toString();
        window.location.href = PROXY_BASE + encodeURIComponent(actionUrl.href);
      } else {
        // For POST, create a temporary form
        const tempForm = document.createElement('form');
        tempForm.method = 'POST';
        tempForm.action = PROXY_BASE + encodeURIComponent(actionUrl.href);
        tempForm.style.display = 'none';
        
        for (const [key, value] of formData.entries()) {
          const input = document.createElement('input');
          input.type = 'hidden';
          input.name = key;
          input.value = value;
          tempForm.appendChild(input);
        }
        
        document.body.appendChild(tempForm);
        tempForm.submit();
      }
    } catch (err) {
      console.error('Form submission error:', err);
      form.submit(); // Fallback to normal submission
    }
  }, true);
  
  // Fix window.location to show original URL
  try {
    Object.defineProperty(window, 'location', {
      get: function() {
        const loc = window.top.location;
        return new Proxy(loc, {
          get: function(target, prop) {
            if (prop === 'href') return ORIGINAL_URL;
            if (prop === 'origin') return ORIGINAL_ORIGIN;
            if (prop === 'host') return new URL(ORIGINAL_URL).host;
            if (prop === 'hostname') return new URL(ORIGINAL_URL).hostname;
            return target[prop];
          }
        });
      }
    });
  } catch (e) {
    // May fail in some contexts
  }
})();
</script>`
      );

      // Rewrite URLs in HTML attributes
      html = html.replace(
        /(<(?:a|img|script|link|iframe|form|source|video|audio|embed|object)[^>]+?)((?:href|src|action|data|poster|srcset)=["'])([^"']+)(["'])/gi,
        (match, tagStart, attrStart, url, attrEnd) => {
          try {
            if (url.startsWith(proxyBase) || url.startsWith('data:') || 
                url.startsWith('javascript:') || url.startsWith('blob:') || url.startsWith('#')) {
              return match;
            }
            
            // Handle srcset specially (contains multiple URLs)
            if (attrStart.includes('srcset')) {
              const rewritten = url.split(',').map(part => {
                const [urlPart, ...rest] = part.trim().split(/\s+/);
                const newUrl = proxyBase + encodeURIComponent(new URL(urlPart, base).href);
                return [newUrl, ...rest].join(' ');
              }).join(', ');
              return `${tagStart}${attrStart}${rewritten}${attrEnd}`;
            }
            
            const absolute = new URL(url, base).href;
            return `${tagStart}${attrStart}${proxyBase}${encodeURIComponent(absolute)}${attrEnd}`;
          } catch {
            return match;
          }
        }
      );

      // Rewrite inline CSS url()
      html = html.replace(
        /url\s*\(\s*['"]?([^'")\s]+)['"]?\s*\)/gi,
        (match, cssUrl) => {
          try {
            if (cssUrl.startsWith(proxyBase) || cssUrl.startsWith('data:')) return match;
            const absolute = new URL(cssUrl, base).href;
            return `url('${proxyBase}${encodeURIComponent(absolute)}')`;
          } catch {
            return match;
          }
        }
      );

      res.setHeader("Content-Type", "text/html; charset=utf-8");
      res.status(200).send(html);
      return;
    }

    // Process CSS
    if (contentType.includes("text/css") || base.pathname.endsWith('.css')) {
      let css = new TextDecoder().decode(buffer);

      // Rewrite @import
      css = css.replace(
        /@import\s+(['"]?)([^'")\s;]+)\1/gi,
        (match, quote, importUrl) => {
          try {
            if (importUrl.startsWith(proxyBase) || importUrl.startsWith('data:')) return match;
            const absolute = new URL(importUrl, base).href;
            return `@import ${quote}${proxyBase}${encodeURIComponent(absolute)}${quote}`;
          } catch {
            return match;
          }
        }
      );

      // Rewrite url()
      css = css.replace(
        /url\s*\(\s*['"]?([^'")\s]+)['"]?\s*\)/gi,
        (match, cssUrl) => {
          try {
            if (cssUrl.startsWith(proxyBase) || cssUrl.startsWith('data:')) return match;
            const absolute = new URL(cssUrl, base).href;
            return `url('${proxyBase}${encodeURIComponent(absolute)}')`;
          } catch {
            return match;
          }
        }
      );

      res.setHeader("Content-Type", "text/css; charset=utf-8");
      res.status(200).send(css);
      return;
    }

    // Process JavaScript
    if (contentType.includes("javascript") || contentType.includes("ecmascript") || 
        base.pathname.endsWith('.js')) {
      let js = new TextDecoder().decode(buffer);

      // Rewrite import() and import ... from
      js = js.replace(
        /\b(import\s*\(|from)\s*['"`]([^'"`]+)['"`]/gi,
        (match, keyword, importUrl) => {
          try {
            if (importUrl.startsWith('http://') || importUrl.startsWith('https://')) {
              const absolute = new URL(importUrl, base).href;
              return match.replace(importUrl, `${proxyBase}${encodeURIComponent(absolute)}`);
            }
            if (importUrl.startsWith('.') || importUrl.startsWith('/')) {
              const absolute = new URL(importUrl, base).href;
              return match.replace(importUrl, `${proxyBase}${encodeURIComponent(absolute)}`);
            }
          } catch {}
          return match;
        }
      );

      res.setHeader("Content-Type", "application/javascript; charset=utf-8");
      res.status(200).send(js);
      return;
    }

    // For other content types, stream as-is
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

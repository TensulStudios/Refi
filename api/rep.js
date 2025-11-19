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

  let { url, ...otherParams } = req.query;
  
  // If URL is missing but we have query params, this is likely a form submission
  if (!url && Object.keys(otherParams).length > 0) {
    const referer = req.headers.referer || req.headers.referrer;
    if (referer) {
      try {
        // Extract the original URL from the referer
        const originalUrlMatch = referer.match(/[?&]url=([^&]+)/);
        if (originalUrlMatch) {
          const baseUrl = decodeURIComponent(originalUrlMatch[1]);
          const baseUrlObj = new URL(baseUrl);
          
          // For Google and similar sites, if we're on the homepage and searching,
          // the form submits to /search
          let targetPath = baseUrlObj.pathname;
          
          // Detect if this is a Google search (has 'q' parameter and we're on google.com)
          if (otherParams.q && baseUrlObj.hostname.includes('google.')) {
            targetPath = '/search';
          }
          // For other sites submitting from homepage
          else if (baseUrlObj.pathname === '/') {
            targetPath = '/search'; // Common pattern
          }
          
          // Build the URL
          const queryString = new URLSearchParams(otherParams).toString();
          url = `${baseUrlObj.origin}${targetPath}?${queryString}`;
          
          console.log(`Reconstructed form submission URL: ${url}`);
        } else {
          return res.status(400).send("Missing url parameter - no base URL in referer");
        }
      } catch (e) {
        console.error("Error reconstructing URL:", e);
        return res.status(400).send("Error: " + e.message);
      }
    } else {
      return res.status(400).send("Missing url parameter (no referer)");
    }
  }
  
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
      redirect: "follow",
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
  const ORIGINAL_PATHNAME = '${base.pathname}';
  
  // Rewrite URL to use proxy
  function rewriteUrl(urlStr) {
    if (!urlStr || urlStr.startsWith(PROXY_BASE) || urlStr.startsWith('data:') || 
        urlStr.startsWith('javascript:') || urlStr.startsWith('blob:') || urlStr.startsWith('#')) {
      return urlStr;
    }
    
    try {
      // Handle relative URLs properly
      let absolute;
      if (urlStr.startsWith('?') || urlStr.startsWith('&')) {
        // Query string only - append to current page
        absolute = ORIGINAL_ORIGIN + ORIGINAL_PATHNAME + urlStr;
      } else {
        absolute = new URL(urlStr, ORIGINAL_URL).href;
      }
      return PROXY_BASE + encodeURIComponent(absolute);
    } catch {
      return urlStr;
    }
  }
  
  // Override window.location to handle navigation properly
  let currentLocation = ORIGINAL_URL;
  const originalLocation = window.location;
  
  // Intercept location changes
  const locationProxy = new Proxy({}, {
    get: function(target, prop) {
      const currentUrl = new URL(currentLocation);
      
      if (prop === 'href') return currentLocation;
      if (prop === 'origin') return currentUrl.origin;
      if (prop === 'protocol') return currentUrl.protocol;
      if (prop === 'host') return currentUrl.host;
      if (prop === 'hostname') return currentUrl.hostname;
      if (prop === 'port') return currentUrl.port;
      if (prop === 'pathname') return currentUrl.pathname;
      if (prop === 'search') return currentUrl.search;
      if (prop === 'hash') return currentUrl.hash;
      
      if (prop === 'assign') {
        return function(url) {
          const newUrl = rewriteUrl(url);
          originalLocation.assign(newUrl);
        };
      }
      if (prop === 'replace') {
        return function(url) {
          const newUrl = rewriteUrl(url);
          originalLocation.replace(newUrl);
        };
      }
      if (prop === 'reload') {
        return function() {
          originalLocation.reload();
        };
      }
      
      return originalLocation[prop];
    },
    set: function(target, prop, value) {
      if (prop === 'href') {
        const newUrl = rewriteUrl(value);
        originalLocation.href = newUrl;
        return true;
      }
      return false;
    }
  });
  
  try {
    Object.defineProperty(window, 'location', {
      get: function() { return locationProxy; },
      set: function(value) { 
        const newUrl = rewriteUrl(value);
        originalLocation.href = newUrl;
      }
    });
  } catch (e) {
    // May fail in strict mode
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
    } else if (tagName.toLowerCase() === 'a') {
      const hrefDescriptor = Object.getOwnPropertyDescriptor(HTMLAnchorElement.prototype, 'href');
      Object.defineProperty(element, 'href', {
        get: hrefDescriptor.get,
        set: function(value) {
          hrefDescriptor.set.call(this, rewriteUrl(value));
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
    
    // Get the form action, handling all cases
    let action = form.getAttribute('action');
    
    // If no action or empty, use current page URL
    if (!action || action === '' || action === window.location.href) {
      action = currentLocation;
    }
    
    try {
      // Resolve the action URL relative to the current page
      let actionUrl;
      if (action.startsWith('?') || action.startsWith('&')) {
        // Query string only
        actionUrl = new URL(ORIGINAL_ORIGIN + ORIGINAL_PATHNAME + action);
      } else if (action.startsWith('/') && !action.startsWith('//')) {
        // Absolute path
        actionUrl = new URL(action, ORIGINAL_ORIGIN);
      } else if (action.startsWith('http://') || action.startsWith('https://')) {
        // Full URL
        actionUrl = new URL(action);
      } else {
        // Relative path
        actionUrl = new URL(action, currentLocation);
      }
      
      if (method === 'GET') {
        const params = new URLSearchParams(formData);
        actionUrl.search = params.toString();
        window.location.href = PROXY_BASE + encodeURIComponent(actionUrl.href);
      } else {
        // For POST, create a temporary form pointing to proxied URL
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
      // Last resort fallback
      form.submit();
    }
  }, true);
  
  // Intercept link clicks to ensure they go through proxy
  document.addEventListener('click', function(e) {
    let target = e.target;
    
    // Find the closest anchor tag
    while (target && target.tagName !== 'A') {
      target = target.parentElement;
    }
    
    if (!target || target.tagName !== 'A') return;
    
    const href = target.getAttribute('href');
    if (!href || href.startsWith('#') || href.startsWith('javascript:') || 
        href.startsWith('mailto:') || href.startsWith('tel:')) {
      return;
    }
    
    // If it's not already proxied, intercept it
    if (!href.includes(PROXY_BASE)) {
      e.preventDefault();
      e.stopPropagation();
      
      try {
        const absolute = new URL(href, currentLocation).href;
        window.location.href = PROXY_BASE + encodeURIComponent(absolute);
      } catch (err) {
        console.error('Link navigation error:', err);
      }
    }
  }, true);
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
            
            // Handle query strings that are relative
            let absolute;
            if (url.startsWith('?') || url.startsWith('&')) {
              absolute = base.origin + base.pathname + url;
            } else if (url.startsWith('/') && !url.startsWith('//')) {
              // Absolute path relative to origin
              absolute = base.origin + url;
            } else {
              absolute = new URL(url, base).href;
            }
            
            return `${tagStart}${attrStart}${proxyBase}${encodeURIComponent(absolute)}${attrEnd}`;
          } catch (e) {
            console.error('Error rewriting URL:', url, e);
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

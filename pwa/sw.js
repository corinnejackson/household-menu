// Offline support for the signed-in planner: the page itself is network-first with a cached
// fallback, and the CDN styles/fonts are served from cache while refreshing in the background.
const PAGE_CACHE = 'planner-page-v1';
const ASSET_CACHE = 'planner-assets-v1';
const CDN_HOSTS = ['cdn.tailwindcss.com', 'cdnjs.cloudflare.com'];

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', event => event.waitUntil(self.clients.claim()));

self.addEventListener('fetch', event => {
  const request = event.request;
  if (request.method !== 'GET') return;
  const url = new URL(request.url);

  if (request.mode === 'navigate' && url.origin === self.location.origin && (url.pathname === '/' || url.pathname === '/index.html')) {
    event.respondWith((async () => {
      try {
        const response = await fetch(request);
        // Redirects (to /login when signed out) are never cached
        if (response.ok && response.type === 'basic' && !response.redirected) {
          const cache = await caches.open(PAGE_CACHE);
          await cache.put('/', response.clone());
        }
        return response;
      } catch (err) {
        return (await caches.match('/')) || Response.error();
      }
    })());
    return;
  }

  if (CDN_HOSTS.includes(url.hostname) || (url.origin === self.location.origin && url.pathname.startsWith('/pwa/'))) {
    event.respondWith((async () => {
      const cache = await caches.open(ASSET_CACHE);
      const cached = await cache.match(request);
      const network = fetch(request)
        .then(response => {
          if (response.ok || response.type === 'opaque') cache.put(request, response.clone());
          return response;
        })
        .catch(() => cached);
      return cached || network;
    })());
  }
});

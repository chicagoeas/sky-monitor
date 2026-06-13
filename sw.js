// ─── Cache names ─────────────────────────────────────────────────────────────
// Bump CACHE_VERSION whenever you deploy a breaking change.
// All three sub-caches share the same version prefix so a single bump clears
// everything consistently.
const CACHE_VERSION = 'skymonitor-v2.0.0';
const STATIC_CACHE  = `${CACHE_VERSION}-static`;   // CDN libs — cache-first
const IMAGE_CACHE   = `${CACHE_VERSION}-images`;   // small images — cache-on-use
const RUNTIME_CACHE = `${CACHE_VERSION}-runtime`;  // HTML + same-origin — network-first

const ALL_CACHES = [STATIC_CACHE, IMAGE_CACHE, RUNTIME_CACHE];

// ─── Config ──────────────────────────────────────────────────────────────────
const BASE_URL = 'https://chicagoeas.github.io/sky-monitor/';

const TAG_PATHS = {
    'nws-alert':   '#severe',
    'nws-warning': '#severe',
    'nws-watch':   '#severe',
    'spc-outlook': '#severe-risks',
    'spc-md':      '#severe-risks',
    'wpc-mcd':     '#severe-risks',
    'wpc-mpd':     '#severe-risks',
    'wpc-outlook': '#severe-risks',
};

// CDN libraries only — versioned URLs that never change.
// The main HTML (./index.html) is intentionally NOT here; it uses network-first
// so GitHub Pages updates always reach users immediately.
const STATIC_URLS = [
    'https://cdn.jsdelivr.net/npm/chart.js@4.4.3/dist/chart.umd.min.js',
    'https://unpkg.com/leaflet@1.9.4/dist/leaflet.css',
    'https://unpkg.com/leaflet@1.9.4/dist/leaflet.js',
    'https://unpkg.com/leaflet.markercluster@1.5.3/dist/MarkerCluster.css',
    'https://unpkg.com/leaflet.markercluster@1.5.3/dist/MarkerCluster.Default.css',
    'https://unpkg.com/leaflet.markercluster@1.5.3/dist/leaflet.markercluster.js',
    'https://cdn-icons-png.flaticon.com/512/1779/1779927.png',
];

// Images matching any of these patterns are skipped entirely — too large or too
// dynamic to be worth caching (radar, satellite, SPC outlooks, weather stories).
const SKIP_IMAGE_PATTERNS = [
    /spc\.noaa\.gov/,
    /ems\.psu\.edu/,
    /radar/i,
    /satellite/i,
    /goes/i,
    /mesonet/i,
    /wpc\.ncep\.noaa\.gov.*image/i,
    /weather\.gov.*image/i,
    /nws\.noaa\.gov.*png/i,
    /api\.weather\.gov.*\.(png|jpg|gif)/i,
    /weather-story/i,
];

// Largest image we're willing to cache (500 KB). Anything bigger is served
// directly from the network without being stored.
const MAX_IMAGE_CACHE_BYTES = 500 * 1024;

// ─── Helpers ─────────────────────────────────────────────────────────────────
function isStaticCDN(url) {
    return STATIC_URLS.some((u) => url === u || url === new URL(u, self.location.href).href);
}

function isImageRequest(request, url) {
    const accept = request.headers.get('Accept') || '';
    return accept.includes('image') || /\.(png|jpg|jpeg|gif|webp|svg|ico)(\?|$)/i.test(url);
}

function shouldSkipImage(url) {
    return SKIP_IMAGE_PATTERNS.some((p) => p.test(url));
}

// ─── Install: pre-cache static CDN assets ────────────────────────────────────
self.addEventListener('install', (e) => {
    e.waitUntil(
        caches.open(STATIC_CACHE).then((cache) =>
            Promise.allSettled(STATIC_URLS.map((url) => cache.add(url).catch(() => {})))
        ).then(() => self.skipWaiting())
    );
});

// ─── Activate: delete old caches, claim clients, signal page to reload ───────
self.addEventListener('activate', (e) => {
    e.waitUntil(
        caches.keys()
            .then((keys) =>
                Promise.all(
                    keys
                        .filter((k) => !ALL_CACHES.includes(k))
                        .map((k) => caches.delete(k))
                )
            )
            .then(() => self.clients.claim())
            .then(() =>
                // Tell every open tab to reload so the fresh HTML and assets are
                // picked up immediately — no manual cache-clear needed.
                self.clients.matchAll({ type: 'window', includeUncontrolled: true })
            )
            .then((clients) => {
                clients.forEach((c) => c.postMessage({ type: 'SW_UPDATED' }));
            })
    );
});

// ─── Fetch: tiered caching strategy ─────────────────────────────────────────
self.addEventListener('fetch', (e) => {
    if (e.request.method !== 'GET') return;
    const url = e.request.url;

    // 1. CDN static libs — cache-first (versioned, immutable)
    if (isStaticCDN(url)) {
        e.respondWith(
            caches.match(e.request).then((cached) =>
                cached || fetch(e.request).then((res) => {
                    caches.open(STATIC_CACHE).then((c) => c.put(e.request, res.clone()));
                    return res;
                })
            )
        );
        return;
    }

    // 2. Large / dynamic weather images — network-only, never cache
    if (isImageRequest(e.request, url) && shouldSkipImage(url)) {
        return; // let the browser handle it normally
    }

    // 3. Other images — cache-on-use with a size gate (≤ 500 KB only)
    if (isImageRequest(e.request, url)) {
        e.respondWith(
            caches.match(e.request).then((cached) => {
                if (cached) return cached;
                return fetch(e.request).then((res) => {
                    if (!res.ok) return res;
                    // Check declared size first (saves cloning if obviously too large)
                    const cl = Number(res.headers.get('content-length') || 0);
                    if (cl > MAX_IMAGE_CACHE_BYTES) return res;
                    // Clone and inspect actual size before deciding to cache
                    return res.clone().blob().then((blob) => {
                        if (blob.size <= MAX_IMAGE_CACHE_BYTES) {
                            caches.open(IMAGE_CACHE).then((c) => c.put(e.request, res.clone()));
                        }
                        return res;
                    });
                }).catch(() => caches.match(e.request));
            })
        );
        return;
    }

    // 4. Main HTML document and all same-origin assets — network-first.
    //    This is the key change: the HTML page always tries the network so
    //    every GitHub Pages deployment reaches users on their next visit.
    //    If offline, the cached version is served as a fallback.
    if (url.startsWith(self.location.origin)) {
        e.respondWith(
            fetch(e.request)
                .then((res) => {
                    if (res.ok) {
                        caches.open(RUNTIME_CACHE).then((c) => c.put(e.request, res.clone()));
                    }
                    return res;
                })
                .catch(() => caches.match(e.request))
        );
        return;
    }

    // 5. External API calls (weather data, etc.) — network-first, cache fallback.
    //    Offline users see the last known data instead of a blank card.
    e.respondWith(
        fetch(e.request)
            .then((res) => {
                if (res.ok) {
                    caches.open(RUNTIME_CACHE).then((c) => c.put(e.request, res.clone()));
                }
                return res;
            })
            .catch(() => caches.match(e.request))
    );
});

// ─── Push notifications ───────────────────────────────────────────────────────
self.addEventListener('push', (e) => {
    let data = {};
    try { data = e.data ? e.data.json() : {}; } catch (_) {}

    const tag = data.tag || 'weather-alert';

    const fragment = TAG_PATHS[tag] || '';
    const targetUrl = data.url || (BASE_URL + fragment);

    const title = data.title || 'SkyMonitor Alert';
    const options = {
        body: data.body || 'New weather alert for your area.',
        icon: data.icon || 'https://cdn-icons-png.flaticon.com/512/1779/1779927.png',
        badge: data.badge || 'https://cdn-icons-png.flaticon.com/512/1779/1779927.png',
        tag,
        renotify: true,
        requireInteraction: true,
        vibrate: [200, 100, 200],
        'interruption-level': 'time-sensitive',   // iOS 16.4+: breaks through Focus / DND
        timestamp: data.timestamp || Date.now(),
        data: { url: targetUrl },
    };
    e.waitUntil(self.registration.showNotification(title, options));
});

// ─── Notification click ───────────────────────────────────────────────────────
self.addEventListener('notificationclick', (e) => {
    e.notification.close();
    const url = (e.notification.data && e.notification.data.url) ? e.notification.data.url : BASE_URL;
    e.waitUntil(
        self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((clientList) => {
            for (const client of clientList) {
                if (client.url.includes(self.location.origin) && 'focus' in client) {
                    const navPromise = ('navigate' in client) ? client.navigate(url) : Promise.resolve(client);
                    return navPromise.then(() => client.focus());
                }
            }
            if (self.clients.openWindow) return self.clients.openWindow(url);
        })
    );
});

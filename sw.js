// ─── Cache names ─────────────────────────────────────────────────────────────
// Bump CACHE_VERSION whenever you deploy a breaking change.
// All three sub-caches share the same version prefix so a single bump clears
// everything consistently.
const CACHE_VERSION = 'skymonitor-v1.1.6';
const STATIC_CACHE  = `${CACHE_VERSION}-static`;   // CDN libs — cache-first
const IMAGE_CACHE   = `${CACHE_VERSION}-images`;   // small icons — cache-on-use
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
// dynamic to be worth caching.
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
    // ── Map tile providers ── each page load fetches 20-100+ tiles; never cache
    /openstreetmap\.org/,
    /tile\.openstreetmap/,
    /arcgisonline\.com/,
    /arcgis\.com/,
    /mapbox\.com/,
    /maptiler\.com/,
    /googleapis\.com\/maps/,
];

// Largest icon we're willing to cache. Weather condition icons are small SVGs
// or PNGs — 100 KB is generous. Bumping this higher causes multi-MB IMAGE_CACHE
// bloat from tilesets and high-res graphics.
const MAX_IMAGE_CACHE_BYTES = 100 * 1024; // 100 KB

// Maximum number of entries to keep in RUNTIME_CACHE (same-origin HTML/assets).
// Prevents slow accumulation if the app URL changes frequently (e.g. query params).
const MAX_RUNTIME_ENTRIES = 30;

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

// Trim a cache to at most `maxEntries` entries (drops oldest first).
async function trimCache(cacheName, maxEntries) {
    const cache = await caches.open(cacheName);
    const keys = await cache.keys();
    if (keys.length > maxEntries) {
        await Promise.all(keys.slice(0, keys.length - maxEntries).map((k) => cache.delete(k)));
    }
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
            .then(() => trimCache(RUNTIME_CACHE, MAX_RUNTIME_ENTRIES))
            .then(() => self.clients.claim())
            .then(() =>
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
                    const toCache = res.clone();
                    caches.open(STATIC_CACHE).then((c) => c.put(e.request, toCache));
                    return res;
                })
            )
        );
        return;
    }

    // 2. Large / dynamic weather images — network-only, never cache
    if (isImageRequest(e.request, url) && shouldSkipImage(url)) {
        return;
    }

    // 3. Other images — cache-on-use with a size gate (≤ 100 KB only).
    //    Opaque cross-origin responses (e.g. TWC/Wunderground icons) are cached
    //    directly — they're always tiny SVG/PNG icons in practice.
    if (isImageRequest(e.request, url)) {
        e.respondWith(
            caches.match(e.request).then((cached) => {
                if (cached) return cached;
                return fetch(e.request).then((res) => {
                    // Never cache opaque (cross-origin) responses. Browsers pad each
                    // opaque cache entry to ~7 MB as a Spectre mitigation — a handful
                    // of weather icons turns into 40+ MB of wasted storage.
                    if (res.type === 'opaque') return res;
                    if (!res.ok) return res;
                    const cl = Number(res.headers.get('content-length') || 0);
                    if (cl > MAX_IMAGE_CACHE_BYTES) return res;
                    return res.clone().blob().then((blob) => {
                        if (blob.size <= MAX_IMAGE_CACHE_BYTES) {
                            const toCache = res.clone();
                            caches.open(IMAGE_CACHE).then((c) => c.put(e.request, toCache));
                        }
                        return res;
                    });
                }).catch(() => caches.match(e.request));
            })
        );
        return;
    }

    // 4. Main HTML and all same-origin assets — network-first so GitHub Pages
    //    deployments reach users immediately. Cached copy is the offline fallback.
    if (url.startsWith(self.location.origin)) {
        e.respondWith(
            fetch(e.request)
                .then((res) => {
                    if (res.ok) {
                        const toCache = res.clone();
                        caches.open(RUNTIME_CACHE).then((c) => {
                            c.put(e.request, toCache);
                            trimCache(RUNTIME_CACHE, MAX_RUNTIME_ENTRIES);
                        });
                    }
                    return res;
                })
                .catch(() => caches.match(e.request))
        );
        return;
    }

    // 5. External API calls (weather data, push workers, etc.) — network-only.
    //
    //    WHY NOT CACHE: Every weather API URL embeds lat/lon or a timestamp as
    //    query parameters, so each call produces a brand-new unique cache key
    //    that is never matched again. Over time this silently fills the
    //    RUNTIME_CACHE with gigabytes of stale JSON that never gets evicted.
    //
    //    OFFLINE FALLBACK: The app already persists critical data in IndexedDB
    //    (current conditions, NWS observations, TWC forecast, last alert state)
    //    and shows that stored data when the network is unavailable. The SW
    //    cache adds no value here and only wastes storage.
    //
    //    Just return — the browser makes a normal network request with no SW
    //    interception, and the app's own offline logic handles failures.
    return;
});

// ─── App icon badge (iOS 16.4+ / installed PWAs only) ────────────────────────
// The Badging API count is not tracked by the browser itself, so we persist
// our own running "unread alert" counter in IndexedDB (localStorage is not
// available inside a service worker). The counter survives SW restarts and
// is reset to 0 whenever the user opens/focuses the app.
const BADGE_DB_NAME = 'skymonitor-badge';
const BADGE_STORE = 'kv';

function _openBadgeDb() {
    return new Promise((resolve, reject) => {
        const req = indexedDB.open(BADGE_DB_NAME, 1);
        req.onupgradeneeded = () => {
            if (!req.result.objectStoreNames.contains(BADGE_STORE)) {
                req.result.createObjectStore(BADGE_STORE);
            }
        };
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
    });
}

async function getBadgeCount() {
    try {
        const db = await _openBadgeDb();
        return await new Promise((resolve) => {
            const tx = db.transaction(BADGE_STORE, 'readonly');
            const getReq = tx.objectStore(BADGE_STORE).get('count');
            getReq.onsuccess = () => resolve(getReq.result || 0);
            getReq.onerror = () => resolve(0);
        });
    } catch (_) {
        return 0;
    }
}

async function setBadgeCount(n) {
    try {
        const db = await _openBadgeDb();
        await new Promise((resolve) => {
            const tx = db.transaction(BADGE_STORE, 'readwrite');
            tx.objectStore(BADGE_STORE).put(n, 'count');
            tx.oncomplete = resolve;
            tx.onerror = resolve;
        });
    } catch (_) {}
}

async function clearAppBadge() {
    await setBadgeCount(0);
    if ('clearAppBadge' in navigator) {
        try { await navigator.clearAppBadge(); } catch (_) {}
    }
}

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
        'interruption-level': 'time-sensitive',
        timestamp: data.timestamp || Date.now(),
        data: { url: targetUrl },
    };
    e.waitUntil(
        (async () => {
            await self.registration.showNotification(title, options);
            if ('setAppBadge' in navigator) {
                const count = (await getBadgeCount()) + 1;
                await setBadgeCount(count);
                try { await navigator.setAppBadge(count); } catch (_) {}
            }
        })()
    );
});

// ─── Notification click ───────────────────────────────────────────────────────
self.addEventListener('notificationclick', (e) => {
    e.notification.close();
    const url = (e.notification.data && e.notification.data.url) ? e.notification.data.url : BASE_URL;
    e.waitUntil(
        (async () => {
            await clearAppBadge();
            const clientList = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
            for (const client of clientList) {
                if (client.url.includes(self.location.origin) && 'focus' in client) {
                    const navPromise = ('navigate' in client) ? client.navigate(url) : Promise.resolve(client);
                    await navPromise;
                    return client.focus();
                }
            }
            if (self.clients.openWindow) return self.clients.openWindow(url);
        })()
    );
});

// ─── Messages from the page (e.g. app opened/focused) ────────────────────────
// The page posts CLEAR_BADGE whenever it becomes visible so the badge doesn't
// linger after the user has already seen the alerts inside the app.
self.addEventListener('message', (e) => {
    if (e.data && e.data.type === 'CLEAR_BADGE') {
        e.waitUntil(clearAppBadge());
    }
});

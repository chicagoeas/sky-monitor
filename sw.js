const CACHE = 'skymonitor-v2.0.0';

// App shell: cached on install so the app loads instantly from disk with no network
const PRECACHE = [
    './',
    'https://cdn.jsdelivr.net/npm/chart.js@4.4.3/dist/chart.umd.min.js',
    'https://unpkg.com/leaflet@1.9.4/dist/leaflet.css',
    'https://unpkg.com/leaflet@1.9.4/dist/leaflet.js',
    'https://unpkg.com/leaflet.markercluster@1.5.3/dist/MarkerCluster.css',
    'https://unpkg.com/leaflet.markercluster@1.5.3/dist/MarkerCluster.Default.css',
    'https://unpkg.com/leaflet.markercluster@1.5.3/dist/leaflet.markercluster.js',
    'https://cdn-icons-png.flaticon.com/512/1779/1779927.png',
];

self.addEventListener('install', (e) => {
    e.waitUntil(
        caches.open(CACHE).then((cache) =>
            // allSettled: a single CDN failure won't abort the whole install
            Promise.allSettled(PRECACHE.map((url) => cache.add(url).catch(() => {})))
        ).then(() => self.skipWaiting())
    );
});

self.addEventListener('activate', (e) => {
    e.waitUntil(
        caches.keys()
            .then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
            .then(() => self.clients.claim())
    );
});

self.addEventListener('fetch', (e) => {
    if (e.request.method !== 'GET') return;
    const url = e.request.url;

    // Cache-first for precached shell assets (CDN libs, icon, app root)
    const isShell = PRECACHE.some((p) =>
        url === new URL(p, self.location.href).href || url === p
    );

    if (isShell) {
        e.respondWith(
            caches.match(e.request).then((cached) => cached || fetch(e.request).then((res) => {
                caches.open(CACHE).then((c) => c.put(e.request, res.clone()));
                return res;
            }))
        );
        return;
    }

    // Same-origin requests: network-first, fall back to cache
    if (url.startsWith(self.location.origin)) {
        e.respondWith(
            fetch(e.request)
                .then((res) => {
                    caches.open(CACHE).then((c) => c.put(e.request, res.clone()));
                    return res;
                })
                .catch(() => caches.match(e.request))
        );
    }
});

self.addEventListener('push', (e) => {
    let data = {};
    try { data = e.data ? e.data.json() : {}; } catch (_) {}
    const title = data.title || 'SkyMonitor Alert';
    const options = {
        body: data.body || 'New weather alert for your area.',
        icon: data.icon || 'https://cdn-icons-png.flaticon.com/512/1779/1779927.png',
        badge: data.badge || 'https://cdn-icons-png.flaticon.com/512/1779/1779927.png',
        tag: data.tag || 'weather-alert',
        renotify: true,
        requireInteraction: true,
        vibrate: [200, 100, 200],
        'interruption-level': 'time-sensitive',   // iOS 16.4+: breaks through Focus / DND
        timestamp: data.timestamp || Date.now(),
        data: { url: data.url || '/' },
    };
    e.waitUntil(self.registration.showNotification(title, options));
});

self.addEventListener('notificationclick', (e) => {
    e.notification.close();
    const url = (e.notification.data && e.notification.data.url) ? e.notification.data.url : '/sky-monitor/';
    e.waitUntil(
        self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((clientList) => {
            for (const client of clientList) {
                if (client.url.includes(self.location.origin) && 'focus' in client) return client.focus();
            }
            if (self.clients.openWindow) return self.clients.openWindow(url);
        })
    );
});

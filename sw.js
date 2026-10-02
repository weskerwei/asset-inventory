// 離線快取：App 本身的檔案全部快取，之後沒有網路也能開啟與盤點
const CACHE = 'asset-inventory-v15';
const FILES = [
  './', './index.html', './manifest.webmanifest',
  './icon-180.png', './icon-192.png', './icon-512.png',
  './vendor/xlsx.full.min.js', './vendor/qrcode.js',
  './vendor/JsBarcode.all.min.js', './vendor/html5-qrcode.min.js',
  './vendor/firebase-app-compat.js', './vendor/firebase-auth-compat.js', './vendor/firebase-firestore-compat.js',
  './firebase-config.js', './cloud.js'
];

self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(FILES)).then(() => self.skipWaiting()));
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys()
      .then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

// 網路優先（拿得到新版就更新快取），離線時改用快取
self.addEventListener('fetch', e => {
  if (e.request.method !== 'GET' || new URL(e.request.url).origin !== location.origin) return;
  e.respondWith(
    fetch(e.request)
      .then(res => {
        const copy = res.clone();
        caches.open(CACHE).then(c => c.put(e.request, copy));
        return res;
      })
      .catch(() => caches.match(e.request, { ignoreSearch: true }))
  );
});

// Based on Mozilla's PWA examples from https://github.com/mdn/pwa-examples/,
// published under CC0

var all_files = [
  './',
  './manifest.json',
  './coap-ace-poc-webapp.js',
  './coap-ace-poc-webapp_bg.wasm',
  './icon.svg',
];

self.addEventListener('install', function(e) {
  e.waitUntil(
    caches.open('coap-ace-poc-webapp-cache').then((cache) => cache.addAll(all_files))
  );
});

self.addEventListener('fetch', (e) => {
  e.respondWith(
    caches.match(e.request)
      // It'd be tempting to leave that out, but if something at installation
    // failed and the scripts are not accessible through the service worker, at least they can be fetched now.
      .then(function (response) { if (response) { return response } else { console.warn("Fetch resulted in cache miss, trying again for", e.request); return fetch(e.request); }})
  );
});

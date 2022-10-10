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
    // Many users add to this a `.then((response) => response ||
    // fetch(e.request))`, but AIU this is just a fallback for files not in
    // all_files, and I rather have things fail hard in a PoC than have errors
    // slip in when all_files is incomplete.
    caches.match(e.request)
  );
});

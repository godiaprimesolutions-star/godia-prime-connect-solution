const CACHE_NAME = 'godia-prime-v1';
const APP_SHELL = ['/', '/index.html', '/offline.html', '/manifest.webmanifest', '/icon.svg'];
self.addEventListener('install', event => { event.waitUntil(caches.open(CACHE_NAME).then(cache => cache.addAll(APP_SHELL))); self.skipWaiting(); });
self.addEventListener('activate', event => { event.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k))))); self.clients.claim(); });
self.addEventListener('fetch', event => {
  const req = event.request; const url = new URL(req.url);
  if (req.method !== 'GET' || url.origin !== self.location.origin) return;
  if (url.pathname.startsWith('/api/')) return; // Never cache private API responses.
  if (req.mode === 'navigate') {
    event.respondWith(fetch(req).then(res => { const copy=res.clone(); caches.open(CACHE_NAME).then(c=>c.put('/index.html',copy)); return res; }).catch(() => caches.match(req).then(hit => hit || caches.match('/index.html').then(app => app || caches.match('/offline.html')))));
    return;
  }
  event.respondWith(caches.match(req).then(hit => hit || fetch(req).then(res => { if(res.ok) { const copy=res.clone(); caches.open(CACHE_NAME).then(c=>c.put(req,copy)); } return res; }).catch(() => hit)));
});

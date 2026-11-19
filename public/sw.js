// Service Worker بسيط (مطلوب لتثبيت التطبيق). مبيخزنش حاجة، كله من الشبكة.
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));
self.addEventListener('fetch', e => { if (e.request.method === 'GET') e.respondWith(fetch(e.request)); });

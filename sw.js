/* CepOS servis çalışanı (service worker)
   - Uygulama kapalıyken gelen telefon bildirimlerini gösterir.
   - Bildirime dokununca CepOS'u ilgili sayfada açar (açıksa o pencereye geçer).
   - Önbellek (cache) tutmaz: index.html her yüklendiğinde herkes hemen yeni sürümü görür. */
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));

self.addEventListener('push', e => {
  let d = {};
  try { d = e.data ? e.data.json() : {}; } catch (x) { d = { body: e.data ? e.data.text() : '' }; }
  const pr = d.priority || 'normal';
  const opt = {
    body: d.body || '',
    icon: 'icon-192.png',
    badge: 'icon-192.png',
    data: { url: d.url || '#panel' },
    tag: d.tag || undefined,
    renotify: !!d.tag,
    silent: pr === 'bilgi',               // bilgi: sessiz (özetler)
    requireInteraction: pr === 'acil'     // acil: siz kapatana kadar ekranda kalır
  };
  if (pr !== 'bilgi') opt.vibrate = pr === 'acil' ? [120, 60, 120, 60, 240] : [80];   // sessizde titreşim verilemez
  e.waitUntil(self.registration.showNotification((pr === 'acil' ? '⚠️ ' : '') + (d.title || 'CepOS'), opt));
});

self.addEventListener('notificationclick', e => {
  e.notification.close();
  const hash = (e.notification.data && e.notification.data.url) || '#panel';
  e.waitUntil((async () => {
    const list = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    for (const c of list) {
      if (new URL(c.url).origin === self.location.origin) {
        c.postMessage({ type: 'goto', hash });
        try { await c.focus(); } catch (x) { /* odaklanma izni yoksa yine de sayfa değişir */ }
        return;
      }
    }
    return self.clients.openWindow(new URL('./' + hash, self.registration.scope).href);
  })());
});

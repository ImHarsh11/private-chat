// Service worker: only shows disguised wake-up notifications. No caching, no fetch handling.
self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (e) => e.waitUntil(self.clients.claim()));

self.addEventListener("push", (event) => {
  let d = {};
  try { d = event.data.json(); } catch {}
  event.waitUntil(
    self.registration.showNotification(d.title || "Order update", {
      body: d.body || "Tap to see the latest status",
      icon: "/n-icon.png",
      badge: "/n-icon.png",
      tag: "u",          // newer alerts replace older ones
      renotify: true
    })
  );
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  event.waitUntil(
    self.clients.matchAll({ type: "window", includeUncontrolled: true }).then((list) =>
      list.length ? list[0].focus() : self.clients.openWindow("/"))
  );
});

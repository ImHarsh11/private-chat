const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const crypto = require("crypto");
const webpush = require("web-push");

const app = express();
app.set("trust proxy", 1);
const server = http.createServer(app);

const MAX_PAYLOAD_BYTES = 2 * 1024 * 1024; // photos / voice notes (encrypted, base64)
const MAX_SIGNAL_BYTES = 16 * 1024;
const MAX_SEATS = 2;
const ROOM_ID_RE = /^[0-9a-f]{64}$/;

// Optional hard lock: comma-separated room ids that are allowed to exist.
// Generate yours with `npm run roomid`. When unset, any room id works (still max 2 people).
const ALLOWED_ROOMS = new Set(
  (process.env.ALLOWED_ROOMS || "").split(",").map((s) => s.trim()).filter(Boolean)
);

if (!ALLOWED_ROOMS.size) {
  console.warn("WARNING: ALLOWED_ROOMS is not set. Anyone who guesses your passphrase can use this server. Run `npm run roomid` and set it.");
}

const io = new Server(server, {
  maxHttpBufferSize: MAX_PAYLOAD_BYTES + 4096,
  serveClient: true,
  cors: { origin: false },
  // Block cross-site WebSocket hijacking: only pages served from this host may connect.
  allowRequest: (req, cb) => {
    const origin = req.headers.origin;
    if (!origin) return cb(null, true);
    try { cb(null, new URL(origin).host === req.headers.host); } catch { cb(null, false); }
  }
});

// ---- security headers -------------------------------------------------------
app.disable("x-powered-by");
app.use((req, res, next) => {
  if (req.headers["x-forwarded-proto"] === "http") {
    return res.redirect(301, "https://" + req.headers.host + req.originalUrl);
  }
  next();
});
app.use((req, res, next) => {
  const host = String(req.headers.host || "").replace(/[^a-zA-Z0-9.:-]/g, "");
  res.set({
    "Content-Security-Policy":
      "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; media-src 'self' blob: data:; " +
      `connect-src 'self' wss://${host} ws://${host}; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'; upgrade-insecure-requests`,
    "Cross-Origin-Resource-Policy": "same-origin",
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(self), microphone=(self), geolocation=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "X-Robots-Tag": "noindex, nofollow",
    "Cache-Control": "no-store"
  });
  next();
});
app.use(express.static("public", { etag: false, lastModified: false }));
app.get("/robots.txt", (_req, res) => res.type("text/plain").send("User-agent: *\nDisallow: /\n"));

// ---- abuse protection -------------------------------------------------------
// Sliding-window counters keyed by IP (and one global bucket for room creation).
const buckets = new Map(); // key -> { count, resetAt }
function over(key, limit, windowMs, add = true) {
  const now = Date.now();
  let b = buckets.get(key);
  if (!b || now > b.resetAt) { b = { count: 0, resetAt: now + windowMs }; buckets.set(key, b); }
  if (add) b.count++;
  return b.count > limit;
}
setInterval(() => {
  const now = Date.now();
  for (const [k, b] of buckets) if (now > b.resetAt) buckets.delete(k);
}, 60 * 1000).unref();

const WINDOW = 10 * 60 * 1000;
const FAIL_LIMIT = 8;        // bad joins per IP per window
const CREATE_LIMIT = 12;     // new rooms per IP per window (caps online passphrase guessing)
const CREATE_LIMIT_GLOBAL = 60; // backstop if an attacker rotates IPs

function clientIp(socket) {
  const h = socket.handshake.headers;
  const cf = h["cf-connecting-ip"]; // set by the CDN in front of Render, not spoofable by the client
  const xff = h["x-forwarded-for"];
  return cf || (xff ? xff.split(",")[0].trim() : socket.handshake.address) || "unknown";
}
const FAIL_LIMIT_GLOBAL = 200; // backstop against an attacker who rotates apparent IPs
const isBlocked = (ip) => over("fail:" + ip, FAIL_LIMIT, WINDOW, false) || over("fail:global", FAIL_LIMIT_GLOBAL, WINDOW, false);
const recordFailure = (ip) => { over("fail:global", FAIL_LIMIT_GLOBAL, WINDOW); return over("fail:" + ip, FAIL_LIMIT, WINDOW); };

// ---- rooms ------------------------------------------------------------------
// The server only ever sees a hash-derived room id and AES-GCM ciphertext.
const rooms = new Map(); // roomId -> Map<socketId, clientId>
const CLIENT_ID_RE = /^[0-9a-f]{32}$/;

function presence(roomId) {
  io.to(roomId).emit("presence", { count: rooms.get(roomId)?.size || 0 });
}

function leave(socket) {
  const roomId = socket.roomId;
  if (!roomId) return;
  socket.roomId = null;
  socket.leave(roomId);
  const set = rooms.get(roomId);
  if (!set) return;
  set.delete(socket.id);
  if (set.size === 0) rooms.delete(roomId);
  else {
    io.to(roomId).emit("stop-typing");
    presence(roomId);
  }
}

// ICE servers for calls. STUN works on most networks; set TURN_URL/TURN_USER/TURN_PASS for reliability on strict mobile/CGNAT networks.
function iceServers() {
  const list = [{ urls: "stun:stun.l.google.com:19302" }];
  if (process.env.TURN_URL) {
    list.push({
      urls: process.env.TURN_URL.split(",").map((s) => s.trim()),
      username: process.env.TURN_USER || "",
      credential: process.env.TURN_PASS || ""
    });
  }
  return list;
}

// ---- disguised wake-up notifications ----------------------------------------
// The server can't read messages, so a push can only say "open the app". The text is chosen here from a
// list of boring shopping-style alerts, never from the client, and never names this app or the sender.
// VAPID keys are derived from a server secret so they survive restarts without extra setup:
// set VAPID_PUBLIC/VAPID_PRIVATE yourself, or it uses PUSH_SEED, or your first ALLOWED_ROOMS entry.
const b64url = (buf) => Buffer.from(buf).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
let vapidPublic = null;
(function setupPush() {
  try {
    let pub = process.env.VAPID_PUBLIC;
    let priv = process.env.VAPID_PRIVATE;
    if (!pub || !priv) {
      const seed = process.env.PUSH_SEED || [...ALLOWED_ROOMS][0];
      if (!seed) return console.warn("Notifications disabled: set ALLOWED_ROOMS (or PUSH_SEED) to enable them.");
      const d = crypto.createHash("sha256").update("private-chat/vapid/v1|" + seed).digest();
      const ecdh = crypto.createECDH("prime256v1");
      ecdh.setPrivateKey(d);
      pub = b64url(ecdh.getPublicKey());
      priv = b64url(d);
    }
    webpush.setVapidDetails(process.env.PUSH_CONTACT || "mailto:admin@example.com", pub, priv);
    vapidPublic = pub;
  } catch (e) {
    console.warn("Notifications disabled:", e.message);
  }
})();

const DISGUISES = [
  { title: "Order update", body: "Your package is out for delivery" },
  { title: "Delivery update", body: "Your order has shipped" },
  { title: "Price drop", body: "An item you viewed is now cheaper" },
  { title: "Cart reminder", body: "You left something in your cart" },
  { title: "Flash sale", body: "Deals end tonight — take a look" },
  { title: "Your order", body: "Tap to see the latest status" }
];
// Only real browser push services; stops the server being used to call arbitrary URLs.
const PUSH_HOST_RE = /(^|\.)(googleapis\.com|push\.services\.mozilla\.com|push\.apple\.com|notify\.windows\.com)$/;
function validSub(sub) {
  if (!sub || typeof sub !== "object" || typeof sub.endpoint !== "string" || sub.endpoint.length > 600) return false;
  const k = sub.keys;
  if (!k || typeof k.p256dh !== "string" || typeof k.auth !== "string" || k.p256dh.length > 200 || k.auth.length > 100) return false;
  try {
    const u = new URL(sub.endpoint);
    return u.protocol === "https:" && PUSH_HOST_RE.test(u.hostname);
  } catch { return false; }
}

io.on("connection", (socket) => {
  const ip = clientIp(socket);
  let lastMsg = 0;
  let burst = 0;
  let sigBurst = 0;
  let lastSig = 0;
  let bytesWindowStart = 0;
  let bytesInWindow = 0;
  let typingCount = 0;
  let typingWindow = 0;

  socket.on("join", (req) => {
    if (socket.roomId) return;
    const roomId = req && req.room;
    const cid = req && req.cid;
    if (isBlocked(ip)) return socket.emit("error-msg", "Too many attempts. Try again later.");
    if (typeof roomId !== "string" || !ROOM_ID_RE.test(roomId)) {
      recordFailure(ip);
      return socket.emit("error-msg", "Access denied");
    }
    if (ALLOWED_ROOMS.size && !ALLOWED_ROOMS.has(roomId)) {
      recordFailure(ip);
      return socket.emit("error-msg", "Access denied");
    }
    if (typeof cid !== "string" || !CLIENT_ID_RE.test(cid)) {
      recordFailure(ip);
      return socket.emit("error-msg", "Access denied");
    }
    let set = rooms.get(roomId);
    if (!set) {
      if (over("create:" + ip, CREATE_LIMIT, WINDOW) || over("create:global", CREATE_LIMIT_GLOBAL, WINDOW)) {
        return socket.emit("error-msg", "Too many attempts. Try again later.");
      }
      set = new Map();
      rooms.set(roomId, set);
    }
    // Same device coming back (phone woke up / network switched): drop its stale connection and reuse the seat.
    for (const [sid, c] of [...set]) {
      if (c === cid && sid !== socket.id) {
        const old = io.sockets.sockets.get(sid);
        if (old) { leave(old); old.disconnect(true); } else set.delete(sid);
      }
    }
    if (!rooms.has(roomId)) rooms.set(roomId, set);
    if (set.size >= MAX_SEATS) {
      recordFailure(ip);
      // Someone who knows the passphrase tried to get a third seat: tell the two people inside.
      if (!over("alert:" + roomId, 1, 30 * 1000)) io.to(roomId).emit("alert", "join-attempt");
      return socket.emit("error-msg", "Access denied");
    }
    set.set(socket.id, cid);
    socket.roomId = roomId;
    socket.join(roomId);
    socket.emit("joined", { ice: iceServers(), push: vapidPublic });
    presence(roomId);
  });

  socket.on("send-message", (payload) => {
    if (!socket.roomId || typeof payload !== "string" || payload.length > MAX_PAYLOAD_BYTES) return;
    const now = Date.now();
    burst = now - lastMsg > 5000 ? 0 : burst + 1;
    lastMsg = now;
    if (burst > 30) return;
    if (now - bytesWindowStart > 10000) { bytesWindowStart = now; bytesInWindow = 0; }
    bytesInWindow += payload.length;
    if (bytesInWindow > 10 * 1024 * 1024) return;
    // Relay to the other person only; sender identity is implied by the connection, never trusted from the client.
    socket.to(socket.roomId).emit("receive-message", payload);
  });

  // WebRTC call signalling (offers/answers/ICE), end-to-end encrypted like messages.
  socket.on("signal", (payload) => {
    if (!socket.roomId || typeof payload !== "string" || payload.length > MAX_SIGNAL_BYTES) return;
    const now = Date.now();
    sigBurst = now - lastSig > 5000 ? 0 : sigBurst + 1;
    lastSig = now;
    if (sigBurst > 150) return;
    socket.to(socket.roomId).emit("signal", payload);
  });

  // "Nudge" the other person's phone with a disguised notification. The subscription comes from the sender's
  // device (she shared it with them over the encrypted channel), so the server stores nothing.
  socket.on("wake", async (sub) => {
    if (!socket.roomId || !vapidPublic || !validSub(sub)) return;
    if (over("wake:" + socket.id, 6, WINDOW) || over("wake-room:" + socket.roomId, 20, 60 * 60 * 1000)) return;
    const d = DISGUISES[crypto.randomInt(DISGUISES.length)];
    try {
      await webpush.sendNotification(sub, JSON.stringify(d), { TTL: 600, urgency: "high" });
    } catch (e) {
      if (e && (e.statusCode === 404 || e.statusCode === 410)) socket.emit("wake-gone");
    }
  });

  socket.on("typing", () => {
    const now = Date.now();
    if (now - typingWindow > 2000) { typingWindow = now; typingCount = 0; }
    if (++typingCount > 10) return;
    socket.roomId && socket.to(socket.roomId).emit("typing");
  });
  socket.on("stop-typing", () => socket.roomId && socket.to(socket.roomId).emit("stop-typing"));
  socket.on("logout", () => leave(socket));
  socket.on("disconnect", () => leave(socket));
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, "0.0.0.0", () => console.log(`Server running on port ${PORT}`));

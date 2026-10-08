const express = require("express");
const http = require("http");
const { Server } = require("socket.io");

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
    socket.emit("joined", { ice: iceServers() });
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

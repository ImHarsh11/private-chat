const express = require("express");
const http = require("http");
const { Server } = require("socket.io");

const app = express();
app.set("trust proxy", 1);
const server = http.createServer(app);

const MAX_PAYLOAD_BYTES = 16 * 1024;
const MAX_SEATS = 2;
const ROOM_ID_RE = /^[0-9a-f]{64}$/;

// Optional hard lock: comma-separated room ids that are allowed to exist.
// Generate yours with `npm run roomid`. When unset, any room id works (still max 2 people).
const ALLOWED_ROOMS = new Set(
  (process.env.ALLOWED_ROOMS || "").split(",").map((s) => s.trim()).filter(Boolean)
);

const io = new Server(server, {
  maxHttpBufferSize: MAX_PAYLOAD_BYTES,
  serveClient: true,
  cors: { origin: false }
});

// ---- security headers -------------------------------------------------------
app.disable("x-powered-by");
app.use((req, res, next) => {
  res.set({
    "Content-Security-Policy":
      "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
      "connect-src 'self' ws: wss:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "X-Robots-Tag": "noindex, nofollow",
    "Cache-Control": "no-store"
  });
  next();
});
app.use(express.static("public", { etag: false, lastModified: false }));
app.get("/robots.txt", (_req, res) => res.type("text/plain").send("User-agent: *\nDisallow: /\n"));

// ---- abuse protection -------------------------------------------------------
const failures = new Map(); // ip -> { count, resetAt }
const FAIL_LIMIT = 8;
const FAIL_WINDOW = 10 * 60 * 1000;

function clientIp(socket) {
  const xff = socket.handshake.headers["x-forwarded-for"];
  return (xff ? xff.split(",")[0].trim() : socket.handshake.address) || "unknown";
}
function isBlocked(ip) {
  const f = failures.get(ip);
  if (!f) return false;
  if (Date.now() > f.resetAt) { failures.delete(ip); return false; }
  return f.count >= FAIL_LIMIT;
}
function recordFailure(ip) {
  const f = failures.get(ip);
  if (!f || Date.now() > f.resetAt) failures.set(ip, { count: 1, resetAt: Date.now() + FAIL_WINDOW });
  else f.count++;
}
setInterval(() => {
  const now = Date.now();
  for (const [ip, f] of failures) if (now > f.resetAt) failures.delete(ip);
}, 60 * 1000).unref();

// ---- rooms ------------------------------------------------------------------
// The server only ever sees a hash-derived room id and AES-GCM ciphertext.
const rooms = new Map(); // roomId -> Set<socketId>

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

io.on("connection", (socket) => {
  const ip = clientIp(socket);
  let lastMsg = 0;
  let burst = 0;

  socket.on("join", (roomId) => {
    if (socket.roomId) return;
    if (isBlocked(ip)) return socket.emit("error-msg", "Too many attempts. Try again later.");
    if (typeof roomId !== "string" || !ROOM_ID_RE.test(roomId)) {
      recordFailure(ip);
      return socket.emit("error-msg", "Access denied");
    }
    if (ALLOWED_ROOMS.size && !ALLOWED_ROOMS.has(roomId)) {
      recordFailure(ip);
      return socket.emit("error-msg", "Access denied");
    }
    let set = rooms.get(roomId);
    if (!set) { set = new Set(); rooms.set(roomId, set); }
    if (set.size >= MAX_SEATS) {
      recordFailure(ip);
      return socket.emit("error-msg", "Access denied");
    }
    set.add(socket.id);
    socket.roomId = roomId;
    socket.join(roomId);
    socket.emit("joined");
    presence(roomId);
  });

  socket.on("send-message", (payload) => {
    if (!socket.roomId || typeof payload !== "string" || payload.length > MAX_PAYLOAD_BYTES) return;
    const now = Date.now();
    burst = now - lastMsg > 5000 ? 0 : burst + 1;
    lastMsg = now;
    if (burst > 20) return;
    // Relay to the other person only; sender identity is implied by the connection, never trusted from the client.
    socket.to(socket.roomId).emit("receive-message", payload);
  });

  socket.on("typing", () => socket.roomId && socket.to(socket.roomId).emit("typing"));
  socket.on("stop-typing", () => socket.roomId && socket.to(socket.roomId).emit("stop-typing"));
  socket.on("logout", () => leave(socket));
  socket.on("disconnect", () => leave(socket));
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, "0.0.0.0", () => console.log(`Server running on port ${PORT}`));

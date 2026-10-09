const $ = (id) => document.getElementById(id);
const socket = io({ transports: ["websocket"] });

const MESSAGE_TTL = 5 * 60 * 1000;
const IDLE_LOCK = 15 * 60 * 1000; // auto-lock after this much inactivity (also checked on return from background)
const MAX_VOICE_MS = 60 * 1000;
const MAX_IMG_DIM = 1280;

let myName = "";
let peerName = "";
let peerOnline = false;
let iceServers = [{ urls: "stun:stun.l.google.com:19302" }];
let typingTimeout;
let idleTimer;
let connecting = false;
let roomId = null;
let wasJoined = false;
let lastActive = Date.now();
let cid = (() => { const a = crypto.getRandomValues(new Uint8Array(16)); return [...a].map((b) => b.toString(16).padStart(2, "0")).join(""); })();
const SESSION_KEY = "pc-session";

const initial = (n) => (n.trim()[0] || "?").toUpperCase();
const inChat = () => !$("chat").classList.contains("hidden");

function toast(msg) {
  const t = $("toast");
  t.textContent = msg;
  t.classList.add("show");
  setTimeout(() => t.classList.remove("show"), 2500);
}

/* ---------------- login ---------------- */
$("showPass").addEventListener("click", () => {
  const show = $("pass").type === "password";
  $("pass").type = show ? "text" : "password";
  $("showPass").textContent = show ? "Hide" : "Show";
});
// ~100 bits of randomness: share it with her once, privately (in person is best).
$("genPass").addEventListener("click", async () => {
  const alphabet = "abcdefghjkmnpqrstuvwxyz23456789";
  const bytes = crypto.getRandomValues(new Uint8Array(20));
  const chars = [...bytes].map((b) => alphabet[b % alphabet.length]);
  const p = [0, 5, 10, 15].map((i) => chars.slice(i, i + 5).join("")).join("-");
  $("pass").value = p;
  $("pass").type = "text";
  $("showPass").textContent = "Hide";
  try { await navigator.clipboard.writeText(p); toast("Copied — send it to her privately"); } catch { toast("Write it down and share it privately"); }
});
$("loginForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  if (connecting) return;
  const name = $("name").value.trim();
  const pass = $("pass").value;
  if (!name || pass.length < 14) {
    $("error").textContent = "Passphrase must be at least 14 characters";
    return;
  }
  connecting = true;
  $("connect").disabled = true;
  $("error").textContent = "";
  $("connect").textContent = "Securing…";
  try {
    roomId = await Crypt.deriveKeys(pass);
    myName = name;
    $("pass").value = "";
    socket.emit("join", { room: roomId, cid });
  } catch (err) {
    fail(err.message);
  }
});

function fail(msg) {
  connecting = false;
  $("connect").disabled = false;
  $("connect").textContent = "Connect";
  $("error").textContent = msg;
}
socket.on("error-msg", (msg) => {
  if (wasJoined && inChat()) return toast(msg);
  wasJoined = false; // a failed restore falls back to the normal login screen
  try { sessionStorage.removeItem(SESSION_KEY); } catch {}
  fail(msg);
});

socket.on("joined", (info) => {
  if (info && Array.isArray(info.ice)) iceServers = info.ice;
  if (info) { pushKey = info.push || null; renderNotif(); }
  $("login").classList.add("hidden");
  $("chat").classList.remove("hidden");
  if (!wasJoined) $("message").focus();
  wasJoined = true;
  touch();
  saveSession();
});

// Phones suspend the connection when you switch apps. Quietly rejoin the room when it comes back.
socket.on("connect", () => {
  if (wasJoined && roomId) socket.emit("join", { room: roomId, cid });
});
socket.on("disconnect", () => {
  if (!wasJoined) return;
  peerOnline = false;
  Crypt.resetSession();
  renderStatus("Reconnecting…");
});

socket.on("presence", async ({ count }) => {
  const was = peerOnline;
  peerOnline = count > 1;
  if (!peerOnline) {
    Crypt.resetSession(); // forget the session keys as soon as she leaves
    renderStatus("Partner offline");
    if (call.state !== "idle" && call.state !== "live") endCall(false, "Partner disconnected");
  } else if (!was) {
    renderStatus("Securing…");
    sendKx(); // fresh keys for every session
  }
});

async function sendKx() {
  try { socket.emit("send-message", await Crypt.kxMessage()); } catch {}
}

// Status line + composer state in one place.
function renderStatus(text) {
  const secure = peerOnline && Crypt.isSecure();
  $("status").classList.toggle("online", secure);
  $("statusText").textContent = secure ? "Online" : text || (peerOnline ? "Securing…" : "Partner offline");
  $("verifyBtn").disabled = !secure;
  $("pinBtn").disabled = !secure;
  $("message").placeholder = secure ? "Message" : peerOnline ? "Securing connection…" : "She's offline — message will wait";
}

// Messages are never stored on the server. If she's offline they wait on THIS phone (marked "waiting"), she gets a
// disguised nudge, and they are delivered the moment she is back and the connection is secure.
const outbox = [];
const OUTBOX_TTL = 10 * 60 * 1000;
const canDeliverNow = () => socket.connected && peerOnline && Crypt.isSecure();

async function deliver(obj, item) {
  const { row } = addRow(item, true);
  if (canDeliverNow()) return send(obj);
  row.classList.add("pending");
  outbox.push({ obj, row, ts: Date.now() });
  wakePartner();
}

async function flushOutbox() {
  for (const o of outbox.splice(0)) {
    if (Date.now() - o.ts > OUTBOX_TTL) { o.row.classList.replace("pending", "failed"); continue; }
    try { await send(o.obj); o.row.classList.remove("pending"); } catch { o.row.classList.replace("pending", "failed"); }
  }
}
setInterval(() => {
  for (let i = outbox.length - 1; i >= 0; i--) {
    if (Date.now() - outbox[i].ts > OUTBOX_TTL) { outbox[i].row.classList.replace("pending", "failed"); outbox.splice(i, 1); }
  }
}, 15000);

socket.on("alert", () => {
  $("alertBar").classList.remove("hidden");
  navigator.vibrate && navigator.vibrate([200, 100, 200]);
});
$("alertClose").addEventListener("click", () => $("alertBar").classList.add("hidden"));

/* ---------------- messaging ---------------- */
const send = async (obj) => socket.emit("send-message", await Crypt.encrypt(obj));
const sendSignal = async (obj) => {
  try { socket.emit("signal", await Crypt.encrypt(obj)); } catch {}
};
const announce = () => send({ k: "hello", n: myName });

$("composer").addEventListener("submit", async (e) => {
  e.preventDefault();
  const text = $("message").value.trim();
  if (!text) return;
  $("message").value = "";
  socket.emit("stop-typing");
  await deliver({ k: "msg", n: myName, t: text }, textBubble(text));
  touch();
});

socket.on("receive-message", async (payload) => {
  if (typeof payload === "string" && payload[0] === "{") {
    // Key exchange message (signed with the passphrase, so the server can't forge it).
    const r = await Crypt.handleKx(payload).catch(() => null);
    if (!r) return;
    if (r.reply) await sendKx();
    if (r.secure) { renderStatus(); announce(); flushOutbox(); syncPush(); }
    return;
  }
  let m;
  try { m = await Crypt.decrypt(payload); } catch { return; } // wrong key / tampered / replayed / reflected: drop
  if (!m || typeof m !== "object") return;
  if (typeof m.n === "string") {
    const n = m.n.slice(0, 24);
    const fresh = peerName !== n;
    peerName = n;
    $("peerName").textContent = n;
    $("peerAvatar").textContent = initial(n);
    if (m.k === "hello" && fresh) announce();
  }
  if (m.k === "msg" && typeof m.t === "string") addRow(textBubble(m.t.slice(0, 2000)), false);
  else if (m.k === "wipe") clearAll();
  else if (m.k === "sub") storePartnerSub(m.sub);
  else if (m.k === "pin-ask") onPinAsk(m);
  else if (m.k === "pin-resp") onPinResp(m);
  else if (m.k === "pin-deny") pinFinish("🚫", `${peerName || "She"} declined to answer.`);
  else if (m.k === "pin-result") onPinResult(m);
  else if (m.k === "img") receiveImage(m);
  else if (m.k === "aud") receiveAudio(m);
});

function textBubble(t) {
  const b = document.createElement("div");
  b.className = "bubble";
  b.textContent = t; // textContent only: no HTML injection
  return { el: b };
}

// Adds a message row that disappears after MESSAGE_TTL. `item` = { el, cleanup? }
function addRow(item, mine) {
  const row = document.createElement("div");
  row.className = "msg " + (mine ? "mine" : "theirs");
  const time = document.createElement("span");
  time.className = "time";
  time.textContent = new Date().toLocaleTimeString([], { hour: "numeric", minute: "2-digit" });
  row.append(item.el, time);
  $("messages").appendChild(row);
  $("messages").scrollTop = $("messages").scrollHeight;
  let done = false;
  const finish = () => {
    if (done) return;
    done = true;
    row.remove();
    item.cleanup && item.cleanup();
    rows.delete(finish);
  };
  rows.add(finish);
  setTimeout(() => {
    row.classList.add("gone");
    setTimeout(finish, 400);
  }, MESSAGE_TTL);
  return { row, finish };
}
const rows = new Set();

// Wipe every message from the screen and memory right now.
function clearAll() {
  [...rows].forEach((f) => f());
  $("messages").textContent = "";
  $("viewer").classList.add("hidden");
  $("viewerImg").removeAttribute("src");
}

// "Clear for both": first tap arms the button, second tap wipes both phones.
let clearArmed = null;
$("clearBtn").addEventListener("click", async () => {
  if (!clearArmed) {
    $("clearBtn").classList.add("armed");
    toast("Tap again to clear this chat on both phones");
    clearArmed = setTimeout(() => { clearArmed = null; $("clearBtn").classList.remove("armed"); }, 3000);
    return;
  }
  clearTimeout(clearArmed); clearArmed = null;
  $("clearBtn").classList.remove("armed");
  clearAll();
  $("menu").classList.add("hidden");
  if (peerOnline && Crypt.isSecure()) await send({ k: "wipe", n: myName });
});

// Security code: if both phones show the same digits, nobody is in the middle.
$("verifyBtn").addEventListener("click", () => {
  const code = Crypt.safetyCode();
  if (!code) return;
  $("codeText").textContent = code;
  $("menu").classList.add("hidden");
  $("codeSheet").classList.remove("hidden");
});
$("codeClose").addEventListener("click", () => $("codeSheet").classList.add("hidden"));

$("message").addEventListener("input", () => {
  socket.emit("typing");
  clearTimeout(typingTimeout);
  typingTimeout = setTimeout(() => socket.emit("stop-typing"), 800);
});
socket.on("typing", () => { $("typing").textContent = `${peerName || "Partner"} is typing…`; });
socket.on("stop-typing", () => { $("typing").textContent = ""; });

/* ---------------- photos ---------------- */
let viewOnce = false;
$("onceBtn").addEventListener("click", () => {
  viewOnce = !viewOnce;
  $("onceBtn").classList.toggle("on", viewOnce);
  toast(viewOnce ? "Next photo: view once" : "Photos stay in the chat");
});
$("attach").addEventListener("click", () => $("file").click());
$("file").addEventListener("change", async () => {
  const f = $("file").files[0];
  $("file").value = "";
  if (!f || !f.type.startsWith("image/")) return;
  try {
    const d = await shrinkImage(f);
    const once = viewOnce;
    viewOnce = false;
    $("onceBtn").classList.remove("on");
    await deliver({ k: "img", n: myName, d, once }, once ? onceBubble(null, true) : photoBubble(d));
    touch();
  } catch {
    toast("Couldn't send photo");
  }
});

// Re-encoding through a canvas downsizes the photo and strips EXIF (GPS location, camera info).
function shrinkImage(file) {
  return new Promise((resolve, reject) => {
    const url = URL.createObjectURL(file);
    const img = new Image();
    img.onload = () => {
      const s = Math.min(1, MAX_IMG_DIM / Math.max(img.width, img.height));
      const c = document.createElement("canvas");
      c.width = Math.round(img.width * s);
      c.height = Math.round(img.height * s);
      c.getContext("2d").drawImage(img, 0, 0, c.width, c.height);
      URL.revokeObjectURL(url);
      resolve(c.toDataURL("image/jpeg", 0.72));
    };
    img.onerror = () => { URL.revokeObjectURL(url); reject(new Error("bad image")); };
    img.src = url;
  });
}

const JPEG_URL = /^data:image\/jpeg;base64,[A-Za-z0-9+/=]+$/;

function photoBubble(d) {
  const b = document.createElement("div");
  b.className = "bubble media";
  const img = document.createElement("img");
  img.className = "photo";
  img.src = d;
  img.addEventListener("click", () => openViewer(d));
  b.appendChild(img);
  return { el: b };
}

function onceBubble(d, mine) {
  const b = document.createElement("div");
  b.className = "bubble once";
  b.textContent = mine ? "🔒 View-once photo sent" : "🔒 Photo · tap to view once";
  const item = { el: b };
  if (!mine) {
    let opened = false;
    b.addEventListener("click", () => {
      if (opened) return;
      opened = true;
      b.classList.add("opened");
      b.textContent = "Opened";
      openViewer(d);
      d = null;
    });
  }
  return item;
}

function receiveImage(m) {
  if (typeof m.d !== "string" || !JPEG_URL.test(m.d)) return;
  addRow(m.once ? onceBubble(m.d, false) : photoBubble(m.d), false);
}

function openViewer(d) {
  $("viewerImg").src = d;
  $("viewer").classList.remove("hidden");
}
$("viewer").addEventListener("click", () => {
  $("viewer").classList.add("hidden");
  $("viewerImg").removeAttribute("src");
});

/* ---------------- voice notes ---------------- */
let rec = null;

$("mic").addEventListener("click", async () => {
  if (rec) return stopRecording(true);
  if (!navigator.mediaDevices || !window.MediaRecorder) return toast("Voice notes not supported here");
  try {
    const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
    const mime = ["audio/mp4", "audio/webm;codecs=opus", "audio/webm"].find((t) => MediaRecorder.isTypeSupported(t));
    const mr = new MediaRecorder(stream, mime ? { mimeType: mime } : undefined);
    const chunks = [];
    mr.ondataavailable = (e) => e.data.size && chunks.push(e.data);
    rec = { mr, stream, chunks, send: false, timer: setTimeout(() => stopRecording(true), MAX_VOICE_MS) };
    mr.onstop = async () => {
      stream.getTracks().forEach((t) => t.stop());
      const r = rec; rec = null;
      $("mic").classList.remove("rec");
      clearTimeout(r.timer);
      if (!r.send || !r.chunks.length) return;
      const blob = new Blob(r.chunks, { type: mr.mimeType });
      const d = await blobToDataUrl(blob);
      await deliver({ k: "aud", n: myName, d, m: mr.mimeType }, audioBubble(blob));
      touch();
    };
    mr.start();
    $("mic").classList.add("rec");
    toast("Recording… tap again to send");
  } catch {
    toast("Microphone permission denied");
  }
});

function stopRecording(sendIt) {
  if (!rec) return;
  rec.send = sendIt;
  if (rec.mr.state !== "inactive") rec.mr.stop();
}

const blobToDataUrl = (blob) => new Promise((res) => {
  const r = new FileReader();
  r.onload = () => res(r.result);
  r.readAsDataURL(blob);
});

function audioBubble(blob) {
  const url = URL.createObjectURL(blob);
  const b = document.createElement("div");
  b.className = "bubble media";
  const a = document.createElement("audio");
  a.controls = true;
  a.preload = "metadata";
  a.src = url;
  b.appendChild(a);
  return { el: b, cleanup: () => URL.revokeObjectURL(url) };
}

function receiveAudio(m) {
  if (typeof m.d !== "string" || typeof m.m !== "string" || !/^audio\/(mp4|webm)/.test(m.m)) return;
  const mm = m.d.match(/^data:[^,]*;base64,([A-Za-z0-9+/=]+)$/);
  if (!mm) return;
  const bin = atob(mm[1]);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  addRow(audioBubble(new Blob([bytes], { type: m.m.split(";")[0] })), false);
}

/* ---------------- voice / video calls (WebRTC, DTLS-SRTP encrypted, signalling E2EE) ---------------- */
const call = { state: "idle", video: false, pc: null, stream: null, queue: [], ringTimer: null, startedAt: 0, tick: null, facing: "user", invite: null };

$("voiceCall").addEventListener("click", () => startCall(false));
$("videoCall").addEventListener("click", () => startCall(true));

async function getMedia(video, facing = "user") {
  return navigator.mediaDevices.getUserMedia({
    audio: { echoCancellation: true, noiseSuppression: true },
    video: video ? { facingMode: facing, width: { ideal: 1280 }, height: { ideal: 720 } } : false
  });
}

async function startCall(video) {
  if (call.state !== "idle") return;
  if (!peerOnline) return toast("She's offline");
  if (!navigator.mediaDevices) return toast("Calls need HTTPS");
  try {
    call.stream = await getMedia(video);
  } catch {
    return toast("Camera / microphone permission denied");
  }
  call.state = "calling";
  call.video = video;
  showCall("Calling…");
  sendSignal({ k: "invite", v: video, n: myName });
  call.ringTimer = setTimeout(() => endCall(true, "No answer"), 45000);
}

socket.on("signal", async (payload) => {
  let s;
  try { s = await Crypt.decrypt(payload); } catch { return; }
  if (!s || typeof s !== "object") return;
  try {
    switch (s.k) {
      case "invite":
        if (call.state !== "idle") return sendSignal({ k: "decline", busy: true });
        call.state = "ringing";
        call.video = !!s.v;
        $("incName").textContent = peerName || "Incoming call";
        $("incAvatar").textContent = initial(peerName || "?");
        $("incKind").textContent = call.video ? "Video call" : "Voice call";
        $("incoming").classList.remove("hidden");
        navigator.vibrate && navigator.vibrate([300, 200, 300]);
        call.ringTimer = setTimeout(() => endCall(false), 45000);
        break;
      case "accept":
        if (call.state !== "calling") return;
        clearTimeout(call.ringTimer);
        $("callState").textContent = "Connecting…";
        await makePeer();
        { const offer = await call.pc.createOffer(); await call.pc.setLocalDescription(offer); sendSignal({ k: "offer", sdp: offer }); }
        break;
      case "offer":
        if (!call.pc) return;
        await call.pc.setRemoteDescription(s.sdp);
        await flushQueue();
        { const ans = await call.pc.createAnswer(); await call.pc.setLocalDescription(ans); sendSignal({ k: "answer", sdp: ans }); }
        break;
      case "answer":
        if (!call.pc) return;
        await call.pc.setRemoteDescription(s.sdp);
        await flushQueue();
        break;
      case "ice":
        if (!call.pc || !s.c) return;
        if (call.pc.remoteDescription) await call.pc.addIceCandidate(s.c).catch(() => {});
        else call.queue.push(s.c);
        break;
      case "decline":
        if (call.state === "calling") endCall(false, s.busy ? "Busy" : "Declined");
        break;
      case "hangup":
        if (call.state !== "idle") endCall(false, "Call ended");
        break;
    }
  } catch (err) {
    endCall(true, "Call failed");
  }
});

$("accept").addEventListener("click", async () => {
  if (call.state !== "ringing") return;
  clearTimeout(call.ringTimer);
  $("incoming").classList.add("hidden");
  try {
    call.stream = await getMedia(call.video);
  } catch {
    sendSignal({ k: "decline" });
    call.state = "idle";
    return toast("Camera / microphone permission denied");
  }
  call.state = "connecting";
  showCall("Connecting…");
  await makePeer();
  sendSignal({ k: "accept" });
});
$("decline").addEventListener("click", () => endCall(true));

async function makePeer() {
  const pc = new RTCPeerConnection({ iceServers });
  call.pc = pc;
  call.stream.getTracks().forEach((t) => pc.addTrack(t, call.stream));
  pc.onicecandidate = (e) => e.candidate && sendSignal({ k: "ice", c: e.candidate });
  pc.ontrack = (e) => {
    $("remoteVideo").srcObject = e.streams[0];
    $("remoteVideo").play().catch(() => {});
  };
  pc.onconnectionstatechange = () => {
    if (pc.connectionState === "connected") onConnected();
    else if (pc.connectionState === "failed") endCall(true, "Connection failed");
    else if (pc.connectionState === "disconnected") setTimeout(() => pc.connectionState === "disconnected" && endCall(true, "Connection lost"), 6000);
  };
}

async function flushQueue() {
  for (const c of call.queue.splice(0)) await call.pc.addIceCandidate(c).catch(() => {});
}

function onConnected() {
  if (call.state === "live") return;
  call.state = "live";
  call.startedAt = Date.now();
  $("callInfo").classList.add("live");
  call.tick = setInterval(() => {
    const s = Math.floor((Date.now() - call.startedAt) / 1000);
    $("callState").textContent = `${String(Math.floor(s / 60)).padStart(2, "0")}:${String(s % 60).padStart(2, "0")}`;
  }, 1000);
}

function showCall(text) {
  $("callName").textContent = peerName || "";
  $("callAvatar").textContent = initial(peerName || "?");
  $("callState").textContent = text;
  $("callInfo").classList.remove("live");
  $("callInfo").classList.toggle("video", call.video);
  $("localVideo").classList.toggle("off", !call.video);
  $("remoteVideo").classList.toggle("off", !call.video);
  $("camBtn").classList.toggle("hidden", !call.video);
  $("flipBtn").classList.toggle("hidden", !call.video);
  $("muteBtn").classList.remove("off");
  $("camBtn").classList.remove("off");
  $("localVideo").srcObject = call.stream;
  $("call").classList.remove("hidden");
}

function endCall(notify, reason) {
  if (call.state === "idle") return;
  if (notify) sendSignal({ k: call.state === "ringing" ? "decline" : "hangup" });
  clearTimeout(call.ringTimer);
  clearInterval(call.tick);
  call.pc && call.pc.close();
  call.stream && call.stream.getTracks().forEach((t) => t.stop());
  Object.assign(call, { state: "idle", pc: null, stream: null, queue: [], tick: null, invite: null });
  $("remoteVideo").srcObject = null;
  $("localVideo").srcObject = null;
  $("call").classList.add("hidden");
  $("incoming").classList.add("hidden");
  if (reason) toast(reason);
}

$("hangup").addEventListener("click", () => endCall(true));
$("muteBtn").addEventListener("click", () => {
  const t = call.stream && call.stream.getAudioTracks()[0];
  if (!t) return;
  t.enabled = !t.enabled;
  $("muteBtn").classList.toggle("off", !t.enabled);
});
$("camBtn").addEventListener("click", () => {
  const t = call.stream && call.stream.getVideoTracks()[0];
  if (!t) return;
  t.enabled = !t.enabled;
  $("camBtn").classList.toggle("off", !t.enabled);
});
$("flipBtn").addEventListener("click", async () => {
  if (!call.pc || !call.video) return;
  try {
    const facing = call.facing === "user" ? "environment" : "user";
    const next = await getMedia(true, facing);
    const track = next.getVideoTracks()[0];
    const sender = call.pc.getSenders().find((s) => s.track && s.track.kind === "video");
    await sender.replaceTrack(track);
    call.stream.getVideoTracks().forEach((t) => { t.stop(); call.stream.removeTrack(t); });
    call.stream.addTrack(track);
    next.getAudioTracks().forEach((t) => t.stop());
    call.facing = facing;
    $("localVideo").srcObject = call.stream;
    $("localVideo").style.transform = facing === "user" ? "scaleX(-1)" : "none";
  } catch { toast("Couldn't switch camera"); }
});

/* ---------------- menu ---------------- */
$("menuBtn").addEventListener("click", () => $("menu").classList.remove("hidden"));
$("menuClose").addEventListener("click", () => $("menu").classList.add("hidden"));
$("menu").addEventListener("click", (e) => { if (e.target === $("menu")) $("menu").classList.add("hidden"); });

/* ---------------- disguised notifications ---------------- */
const PARTNER_SUB_KEY = "pc-partner-sub";
const VAPID_KEY = "pc-vapid";
let pushKey = null;      // server's public key (null = notifications unavailable)
let lastWake = 0;

const pushSupported = () => "serviceWorker" in navigator && "PushManager" in window && "Notification" in window;
const b64urlToBytes = (b) => Uint8Array.from(atob(b.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(b.length / 4) * 4, "=")), (c) => c.charCodeAt(0));

if ("serviceWorker" in navigator) navigator.serviceWorker.register("/sw.js").catch(() => {});

function renderNotif() {
  const visible = pushKey && pushSupported();
  $("notifBtn").classList.toggle("hidden", !visible);
  if (visible) $("notifLabel").textContent = "Notifications: " + (Notification.permission === "granted" && localStorage.getItem("pc-push-on") === "1" ? "on" : "off");
}

async function mySubscription(create) {
  const reg = await navigator.serviceWorker.ready;
  let sub = await reg.pushManager.getSubscription();
  // The key changes if the passphrase (and so the server's room id) changed: start over.
  if (sub && localStorage.getItem(VAPID_KEY) !== pushKey) { await sub.unsubscribe(); sub = null; }
  if (!sub && create) {
    sub = await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: b64urlToBytes(pushKey) });
    localStorage.setItem(VAPID_KEY, pushKey);
  }
  return sub;
}

// Give her phone's address to me (and mine to her) over the encrypted channel, so either of us can nudge the other.
async function syncPush() {
  if (!pushKey || !pushSupported() || localStorage.getItem("pc-push-on") !== "1" || Notification.permission !== "granted") return;
  try {
    const sub = await mySubscription(true);
    if (sub && canDeliverNow()) await send({ k: "sub", n: myName, sub: sub.toJSON() });
  } catch {}
}

function storePartnerSub(sub) {
  try {
    if (!sub) return localStorage.removeItem(PARTNER_SUB_KEY);
    if (typeof sub.endpoint !== "string" || !sub.keys) return;
    localStorage.setItem(PARTNER_SUB_KEY, JSON.stringify({ sub: { endpoint: sub.endpoint, keys: { p256dh: String(sub.keys.p256dh), auth: String(sub.keys.auth) } }, key: pushKey }));
  } catch {}
}

function wakePartner() {
  if (Date.now() - lastWake < 60 * 1000 || !socket.connected) return;
  try {
    const p = JSON.parse(localStorage.getItem(PARTNER_SUB_KEY) || "null");
    if (!p || p.key !== pushKey) return;
    lastWake = Date.now();
    socket.emit("wake", p.sub);
  } catch {}
}
socket.on("wake-gone", () => { try { localStorage.removeItem(PARTNER_SUB_KEY); } catch {} });

$("notifBtn").addEventListener("click", async () => {
  const on = localStorage.getItem("pc-push-on") === "1" && Notification.permission === "granted";
  try {
    if (on) {
      localStorage.setItem("pc-push-on", "0");
      const sub = await mySubscription(false);
      if (sub) await sub.unsubscribe();
      if (canDeliverNow()) await send({ k: "sub", n: myName, sub: null });
      toast("Notifications off");
    } else {
      const isiOS = /iPad|iPhone|iPod/.test(navigator.userAgent);
      if (isiOS && !navigator.standalone) { toast("On iPhone: Share → Add to Home Screen first"); return; }
      const perm = await Notification.requestPermission();
      if (perm !== "granted") { toast("Notifications blocked in settings"); return; }
      localStorage.setItem("pc-push-on", "1");
      await syncPush();
      toast("Notifications on — they look like shop alerts");
    }
  } catch { toast("Couldn't change notifications"); }
  renderNotif();
});

/* ---------------- PIN check ---------------- */
// A PIN you both agreed in person (different from the passphrase). Either of you can ask the other for it
// if you suspect someone else is on the other end. Nothing about the PIN is stored anywhere.
let pin = { mode: null, key: null, nonce: null, timer: null };
let pinAsks = [];
const pinOpen = (title, text) => {
  $("pinTitle").textContent = title;
  $("pinText").textContent = text;
  $("pinInput").value = "";
  $("pinInput").classList.remove("hidden");
  $("pinResult").textContent = "";
  $("pinOk").textContent = "Continue";
  $("pinCancel").classList.remove("hidden");
  $("menu").classList.add("hidden");
  $("pinSheet").classList.remove("hidden");
  setTimeout(() => $("pinInput").focus(), 50);
};
function pinFinish(icon, text) {
  clearTimeout(pin.timer);
  pin = { mode: "result", key: null, nonce: null, timer: null };
  $("pinTitle").textContent = "PIN check";
  $("pinText").textContent = text;
  $("pinResult").textContent = icon;
  $("pinInput").classList.add("hidden");
  $("pinCancel").classList.add("hidden");
  $("pinOk").textContent = "Done";
  $("pinSheet").classList.remove("hidden");
  navigator.vibrate && navigator.vibrate(icon === "✅" ? 80 : [150, 80, 150]);
}

$("pinBtn").addEventListener("click", () => {
  if (!canDeliverNow()) return toast("She needs to be online");
  pin = { mode: "ask", key: null, nonce: null, timer: null };
  pinOpen("Check it's really her", "Enter your PIN. She'll be asked for hers. Only a matching PIN passes. Never type your PIN into the chat.");
});
$("pinCancel").addEventListener("click", async () => {
  const mode = pin.mode;
  $("pinSheet").classList.add("hidden");
  clearTimeout(pin.timer);
  pin = { mode: null, key: null, nonce: null, timer: null };
  if (mode === "answer" && canDeliverNow()) await send({ k: "pin-deny", n: myName });
});
$("pinOk").addEventListener("click", async () => {
  if (pin.mode === "result") { $("pinSheet").classList.add("hidden"); pin.mode = null; return; }
  const v = $("pinInput").value.trim();
  if (!/^\d{4,6}$/.test(v)) return toast("PIN is 4 to 6 digits");
  $("pinOk").disabled = true;
  try {
    const key = await Crypt.pinKey(v);
    $("pinInput").value = "";
    if (pin.mode === "ask") {
      pin.key = key;
      pin.nonce = Crypt.pinNonce();
      $("pinSheet").classList.add("hidden");
      toast("Asking her for the PIN…");
      pin.timer = setTimeout(() => pinFinish("⏱️", "No answer. She may not be at her phone."), 60000);
      await send({ k: "pin-ask", n: myName, nonce: pin.nonce });
    } else if (pin.mode === "answer") {
      const proof = await Crypt.pinProof(key, pin.nonce);
      $("pinSheet").classList.add("hidden");
      pin = { mode: "waiting", key: null, nonce: null, timer: null };
      await send({ k: "pin-resp", n: myName, proof });
    }
  } catch { toast("Couldn't check the PIN"); }
  $("pinOk").disabled = false;
});

function onPinAsk(m) {
  const now = Date.now();
  pinAsks = pinAsks.filter((t) => now - t < 10 * 60 * 1000);
  if (pinAsks.length >= 3 || typeof m.nonce !== "string" || m.nonce.length > 40 || (pin.mode && pin.mode !== "result")) return; // flood / busy
  pinAsks.push(now);
  pin = { mode: "answer", key: null, nonce: m.nonce, timer: null };
  pinOpen(`${peerName || "She"} is checking it's you`, "Enter your PIN to prove it. If you weren't expecting this, tap Cancel.");
  navigator.vibrate && navigator.vibrate([200, 100, 200]);
}

async function onPinResp(m) {
  if (pin.mode !== "ask" || !pin.key || typeof m.proof !== "string") return;
  const ok = await Crypt.pinCheck(pin.key, pin.nonce, m.proof);
  await send({ k: "pin-result", n: myName, ok });
  pinFinish(ok ? "✅" : "❌", ok
    ? `${peerName || "She"} knows the PIN. It's really them.`
    : `The PIN did NOT match. This may not be ${peerName || "her"}. Stop sharing anything private, and change your passphrase.`);
}

function onPinResult(m) {
  if (pin.mode !== "waiting") return;
  pinFinish(m.ok ? "✅" : "❌", m.ok
    ? `${peerName || "She"} confirmed you with the PIN.`
    : `${peerName || "She"} says your PIN did not match.`);
}

/* ---------------- lock / privacy ---------------- */
async function lock() {
  try {
    if (call.state !== "idle") { endCall(true); await new Promise((r) => setTimeout(r, 200)); }
    socket.emit("logout");
  } catch {}
  Crypt.wipe();
  try { sessionStorage.removeItem(SESSION_KEY); } catch {}
  location.reload();
}
$("logout").addEventListener("click", lock);

// Inactivity is measured with the wall clock so it is still correct after the phone suspended our timers.
function touch() { lastActive = Date.now(); }
function checkIdle() {
  if (!inChat() || call.state === "live") return;
  if (Date.now() - lastActive > IDLE_LOCK) lock();
}
setInterval(checkIdle, 30 * 1000);

let lastSave = 0;
function saveSession() {
  try {
    const b = Crypt.exportSession();
    if (b) sessionStorage.setItem(SESSION_KEY, JSON.stringify({ b, n: myName, cid, ts: Date.now() }));
    lastSave = Date.now();
  } catch {}
}
["pointerdown", "keydown", "touchstart"].forEach((ev) => document.addEventListener(ev, () => {
  if (!inChat()) return;
  touch();
  if (Date.now() - lastSave > 10000) saveSession();
}, { passive: true }));

// Hide content in app switcher; don't shield during a call so video keeps showing.
const shield = (on) => document.body.classList.toggle("shielded", on && call.state !== "live");
document.addEventListener("visibilitychange", () => {
  shield(document.hidden);
  if (!document.hidden) checkIdle();
});
window.addEventListener("blur", () => shield(true));
window.addEventListener("focus", () => { shield(false); checkIdle(); });

// If the OS reloaded the page while it was in the background, pick up where we left off (within the idle window).
(async function restore() {
  try {
    const raw = sessionStorage.getItem(SESSION_KEY);
    if (!raw) return;
    const s = JSON.parse(raw);
    if (!s || Date.now() - s.ts > IDLE_LOCK) return sessionStorage.removeItem(SESSION_KEY);
    roomId = await Crypt.restoreSession(s.b);
    myName = s.n;
    cid = s.cid;
    wasJoined = true;
    const go = () => socket.emit("join", { room: roomId, cid });
    socket.connected ? go() : socket.once("connect", go);
  } catch { try { sessionStorage.removeItem(SESSION_KEY); } catch {} }
})();

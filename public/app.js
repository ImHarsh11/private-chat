const $ = (id) => document.getElementById(id);
const socket = io({ transports: ["websocket"] });

const MESSAGE_TTL = 5 * 60 * 1000;
const IDLE_LOCK = 3 * 60 * 1000;
const MAX_VOICE_MS = 60 * 1000;
const MAX_IMG_DIM = 1280;

let myName = "";
let peerName = "";
let peerOnline = false;
let iceServers = [{ urls: "stun:stun.l.google.com:19302" }];
let typingTimeout;
let idleTimer;
let connecting = false;

const initial = (n) => (n.trim()[0] || "?").toUpperCase();
const inChat = () => !$("chat").classList.contains("hidden");

function toast(msg) {
  const t = $("toast");
  t.textContent = msg;
  t.classList.add("show");
  setTimeout(() => t.classList.remove("show"), 2500);
}

/* ---------------- login ---------------- */
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
    const roomId = await Crypt.deriveKeys(pass);
    myName = name;
    $("pass").value = "";
    socket.emit("join", roomId);
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
socket.on("error-msg", fail);

socket.on("joined", (info) => {
  if (info && Array.isArray(info.ice)) iceServers = info.ice;
  $("login").classList.add("hidden");
  $("chat").classList.remove("hidden");
  $("message").focus();
  resetIdle();
});

socket.on("presence", ({ count }) => {
  peerOnline = count > 1;
  $("status").classList.toggle("online", peerOnline);
  $("statusText").textContent = peerOnline ? "Online" : "Partner offline";
  if (peerOnline) announce();
  else if (call.state !== "idle") endCall(false, "Partner disconnected");
});

/* ---------------- messaging ---------------- */
const send = async (obj) => socket.emit("send-message", await Crypt.encrypt(obj));
const sendSignal = async (obj) => socket.emit("signal", await Crypt.encrypt(obj));
const announce = () => send({ k: "hello", n: myName });

$("composer").addEventListener("submit", async (e) => {
  e.preventDefault();
  const text = $("message").value.trim();
  if (!text) return;
  $("message").value = "";
  socket.emit("stop-typing");
  addRow(textBubble(text), true);
  await send({ k: "msg", n: myName, t: text });
  resetIdle();
});

socket.on("receive-message", async (payload) => {
  let m;
  try { m = await Crypt.decrypt(payload); } catch { return; } // wrong key / tampered: drop
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
  const remove = () => {
    row.classList.add("gone");
    setTimeout(() => { row.remove(); item.cleanup && item.cleanup(); }, 400);
  };
  setTimeout(remove, MESSAGE_TTL);
  return { row, remove };
}

$("message").addEventListener("input", () => {
  socket.emit("typing");
  clearTimeout(typingTimeout);
  typingTimeout = setTimeout(() => socket.emit("stop-typing"), 800);
});
socket.on("typing", () => { $("typing").textContent = `${peerName || "Partner"} is typing…`; });
socket.on("stop-typing", () => { $("typing").textContent = ""; });

/* ---------------- photos ---------------- */
$("attach").addEventListener("click", () => $("file").click());
$("file").addEventListener("change", async () => {
  const f = $("file").files[0];
  $("file").value = "";
  if (!f || !f.type.startsWith("image/")) return;
  try {
    const d = await shrinkImage(f);
    const once = confirm("Send as view-once photo?\n\nOK = disappears after she opens it\nCancel = normal photo");
    await send({ k: "img", n: myName, d, once });
    if (once) addRow(onceBubble(null, true), true);
    else addRow(photoBubble(d), true);
    resetIdle();
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
      await send({ k: "aud", n: myName, d, m: mr.mimeType });
      addRow(audioBubble(blob), true);
      resetIdle();
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

/* ---------------- lock / privacy ---------------- */
function lock() {
  try { endCall(true); socket.emit("logout"); } catch {}
  Crypt.wipe();
  location.reload();
}
$("logout").addEventListener("click", lock);

function resetIdle() {
  clearTimeout(idleTimer);
  idleTimer = setTimeout(() => (call.state === "live" ? resetIdle() : lock()), IDLE_LOCK);
}
["pointerdown", "keydown", "touchstart"].forEach((ev) => document.addEventListener(ev, () => inChat() && resetIdle(), { passive: true }));

// Hide content in app switcher; don't shield during a call so video keeps showing.
const shield = (on) => document.body.classList.toggle("shielded", on && call.state !== "live");
document.addEventListener("visibilitychange", () => shield(document.hidden));
window.addEventListener("blur", () => shield(true));
window.addEventListener("focus", () => shield(false));

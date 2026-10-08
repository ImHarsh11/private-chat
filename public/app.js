const $ = (id) => document.getElementById(id);
const socket = io({ transports: ["websocket"] });

const MESSAGE_TTL = 5 * 60 * 1000;
const IDLE_LOCK = 3 * 60 * 1000;
let myName = "";
let peerName = "";
let typingTimeout;
let idleTimer;
let connecting = false;

const initial = (n) => (n.trim()[0] || "?").toUpperCase();

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

socket.on("joined", () => {
  $("login").classList.add("hidden");
  $("chat").classList.remove("hidden");
  $("message").focus();
  resetIdle();
});

socket.on("presence", ({ count }) => {
  const online = count > 1;
  $("status").classList.toggle("online", online);
  $("statusText").textContent = online ? "Online" : "Partner offline";
  // Re-announce our name so a partner who just joined can show it.
  if (online) announce();
});

async function announce() {
  socket.emit("send-message", await Crypt.encrypt({ k: "hello", n: myName }));
}

$("composer").addEventListener("submit", async (e) => {
  e.preventDefault();
  const text = $("message").value.trim();
  if (!text) return;
  $("message").value = "";
  socket.emit("stop-typing");
  addMessage({ t: text, n: myName }, true);
  socket.emit("send-message", await Crypt.encrypt({ k: "msg", n: myName, t: text, ts: Date.now() }));
  resetIdle();
});

socket.on("receive-message", async (payload) => {
  let m;
  try { m = await Crypt.decrypt(payload); } catch { return; } // wrong key / tampered: drop silently
  if (typeof m.n === "string") {
    const fresh = peerName !== m.n.slice(0, 24);
    peerName = m.n.slice(0, 24);
    $("peerName").textContent = peerName;
    $("peerAvatar").textContent = initial(peerName);
    if (m.k === "hello" && fresh) announce();
  }
  if (m.k === "msg" && typeof m.t === "string") addMessage({ t: m.t.slice(0, 2000), n: peerName }, false);
});

function addMessage({ t }, mine) {
  const row = document.createElement("div");
  row.className = "msg " + (mine ? "mine" : "theirs");
  const bubble = document.createElement("div");
  bubble.className = "bubble";
  bubble.textContent = t; // textContent only: no HTML injection
  const time = document.createElement("span");
  time.className = "time";
  time.textContent = new Date().toLocaleTimeString([], { hour: "numeric", minute: "2-digit" });
  row.append(bubble, time);
  $("messages").appendChild(row);
  $("messages").scrollTop = $("messages").scrollHeight;
  setTimeout(() => {
    row.classList.add("gone");
    setTimeout(() => row.remove(), 400);
  }, MESSAGE_TTL);
}

$("message").addEventListener("input", () => {
  socket.emit("typing");
  clearTimeout(typingTimeout);
  typingTimeout = setTimeout(() => socket.emit("stop-typing"), 800);
});
socket.on("typing", () => { $("typing").textContent = `${peerName || "Partner"} is typing…`; });
socket.on("stop-typing", () => { $("typing").textContent = ""; });

// Lock: wipe key + DOM by reloading.
function lock() {
  try { socket.emit("logout"); } catch {}
  Crypt.wipe();
  location.reload();
}
$("logout").addEventListener("click", lock);

function resetIdle() {
  clearTimeout(idleTimer);
  idleTimer = setTimeout(lock, IDLE_LOCK);
}
["pointerdown", "keydown", "touchstart"].forEach((ev) => document.addEventListener(ev, () => {
  if (!$("chat").classList.contains("hidden")) resetIdle();
}, { passive: true }));

// Hide content when app is backgrounded (app switcher previews).
document.addEventListener("visibilitychange", () => {
  document.body.classList.toggle("shielded", document.hidden);
});
window.addEventListener("blur", () => document.body.classList.add("shielded"));
window.addEventListener("focus", () => document.body.classList.remove("shielded"));

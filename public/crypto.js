// End-to-end encryption.
//
// passphrase --PBKDF2--> 512 bits
//   first 256 bits  = room id (the only thing sent to the server)
//   second 256 bits = master secret `ms` (never leaves the device)
//
// Every time both people are online they run an authenticated ECDH handshake:
//   * each side makes a fresh P-256 key pair and sends its public key with an HMAC keyed from `ms`
//     (so the server, which doesn't know the passphrase, can't swap keys)
//   * session key = HKDF(ECDH secret || ms)
// The ephemeral private keys are thrown away when the session ends, so recorded traffic can't be
// decrypted later even if the passphrase leaks (forward secrecy).
// Each message carries a sequence number and a direction bit to stop replay and reflection.
const Crypt = (() => {
  const enc = new TextEncoder();
  const dec = new TextDecoder();
  const subtle = crypto.subtle;

  let rawBits = null;     // 64 bytes, kept so a page the OS reloaded can resume
  let msBytes = null;     // master secret
  let macKey = null;      // HMAC key for the handshake

  // per-session state
  let eph = null;         // { priv, pub (b64), sid }
  let peerSid = null;
  let sessionKey = null;
  let role = 0;
  let sendSeq = 0;
  let seen = new Set();
  let maxSeen = -1;
  let safety = null;

  const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
  const b64 = (buf) => {
    const bytes = new Uint8Array(buf);
    let s = "";
    for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
    return btoa(s);
  };
  const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
  const concat = (...arrs) => {
    const out = new Uint8Array(arrs.reduce((n, a) => n + a.length, 0));
    let o = 0;
    for (const a of arrs) { out.set(a, o); o += a.length; }
    return out;
  };
  const rand = (n) => crypto.getRandomValues(new Uint8Array(n));

  async function deriveKeys(passphrase) {
    if (!subtle) throw new Error("Secure connection (HTTPS) required");
    const base = await subtle.importKey("raw", enc.encode(passphrase.normalize("NFKC")), "PBKDF2", false, ["deriveBits"]);
    const bits = await subtle.deriveBits(
      { name: "PBKDF2", hash: "SHA-256", salt: enc.encode("private-chat/v1"), iterations: 600000 },
      base,
      512
    );
    return useBits(bits);
  }

  async function useBits(bits) {
    rawBits = bits;
    msBytes = new Uint8Array(bits.slice(32));
    const hk = await subtle.importKey("raw", msBytes, "HKDF", false, ["deriveBits"]);
    const macBits = await subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: enc.encode("private-chat/kx-mac/v2") }, hk, 256);
    macKey = await subtle.importKey("raw", macBits, { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
    return hex(bits.slice(0, 32));
  }

  // Lets the app survive the OS reloading the page while backgrounded (kept in sessionStorage, cleared on lock).
  const exportSession = () => (rawBits ? b64(rawBits) : null);
  const restoreSession = (s) => useBits(unb64(s).buffer);

  /* ---------- handshake ---------- */
  const macInput = (sid, pub, ack) => enc.encode(`kx|${sid}|${pub}|${ack || ""}`);

  function resetSession() {
    eph = null; peerSid = null; sessionKey = null; safety = null;
    sendSeq = 0; seen = new Set(); maxSeen = -1;
  }

  async function ensureHandshake() {
    if (eph) return false;
    const kp = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
    const pub = b64(await subtle.exportKey("raw", kp.publicKey));
    eph = { priv: kp.privateKey, pub, sid: hex(rand(16)) };
    return true;
  }

  async function kxMessage() {
    await ensureHandshake();
    const mac = b64(await subtle.sign("HMAC", macKey, macInput(eph.sid, eph.pub, peerSid)));
    return JSON.stringify({ t: "kx", sid: eph.sid, pub: eph.pub, ack: peerSid, mac });
  }

  // Returns { secure: bool, reply: bool } or null if the message is invalid.
  async function handleKx(str) {
    let m;
    try { m = JSON.parse(str); } catch { return null; }
    if (!m || m.t !== "kx" || typeof m.sid !== "string" || typeof m.pub !== "string" || typeof m.mac !== "string") return null;
    if (!/^[0-9a-f]{32}$/.test(m.sid) || m.pub.length > 200 || (m.ack != null && typeof m.ack !== "string")) return null;
    let ok = false;
    try { ok = await subtle.verify("HMAC", macKey, unb64(m.mac), macInput(m.sid, m.pub, m.ack)); } catch {}
    if (!ok) return null;                     // not signed with the shared passphrase
    await ensureHandshake();
    if (m.sid === eph.sid) return null;       // our own message bounced back
    const reply = m.ack !== eph.sid;          // partner hasn't seen our key yet
    if (m.sid === peerSid) return { secure: false, reply };

    const peerPub = await subtle.importKey("raw", unb64(m.pub), { name: "ECDH", namedCurve: "P-256" }, false, []);
    const shared = new Uint8Array(await subtle.deriveBits({ name: "ECDH", public: peerPub }, eph.priv, 256));
    const [lo, hi] = eph.pub < m.pub ? [eph.pub, m.pub] : [m.pub, eph.pub];
    role = eph.pub < m.pub ? 0 : 1;
    const salt = new Uint8Array(await subtle.digest("SHA-256", enc.encode(lo + "|" + hi)));
    const hk = await subtle.importKey("raw", concat(shared, msBytes), "HKDF", false, ["deriveBits"]);
    const out = new Uint8Array(await subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt, info: enc.encode("private-chat/session/v2") }, hk, 512));
    sessionKey = await subtle.importKey("raw", out.slice(0, 32), "AES-GCM", false, ["encrypt", "decrypt"]);
    // Security code both people can compare out loud: 5 groups of 5 digits from the session transcript.
    safety = [0, 1, 2, 3, 4].map((i) => String(((out[32 + i * 3] << 16) | (out[33 + i * 3] << 8) | out[34 + i * 3]) % 100000).padStart(5, "0")).join(" ");
    peerSid = m.sid;
    sendSeq = 0; seen = new Set(); maxSeen = -1;
    return { secure: true, reply };
  }

  /* ---------- messages ---------- */
  async function encrypt(obj) {
    if (!sessionKey) throw new Error("not secure");
    const iv = rand(12);
    const body = { ...obj, q: ++sendSeq, r: role };
    const ct = await subtle.encrypt({ name: "AES-GCM", iv }, sessionKey, enc.encode(JSON.stringify(body)));
    return b64(concat(iv, new Uint8Array(ct)));
  }

  async function decrypt(payload) {
    if (!sessionKey) throw new Error("not secure");
    const raw = unb64(payload);
    const pt = await subtle.decrypt({ name: "AES-GCM", iv: raw.slice(0, 12) }, sessionKey, raw.slice(12));
    const m = JSON.parse(dec.decode(pt));
    if (!m || typeof m.q !== "number" || m.r === role) throw new Error("reflected");   // our own message sent back
    if (seen.has(m.q) || m.q < maxSeen - 5000) throw new Error("replay");               // already seen
    seen.add(m.q);
    if (m.q > maxSeen) maxSeen = m.q;
    return m;
  }

  const wipe = () => { resetSession(); rawBits = null; msBytes = null; macKey = null; };

  return {
    deriveKeys, exportSession, restoreSession,
    ensureHandshake, kxMessage, handleKx, resetSession,
    encrypt, decrypt, wipe,
    isSecure: () => !!sessionKey,
    safetyCode: () => safety
  };
})();

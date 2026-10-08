// End-to-end encryption. The passphrase never leaves the device.
// PBKDF2 -> 512 bits: first half = room id (sent to server), second half = AES-GCM key (never sent).
const Crypt = (() => {
  const enc = new TextEncoder();
  const dec = new TextDecoder();
  let key = null;

  const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
  const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
  const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

  async function deriveKeys(passphrase) {
    if (!crypto.subtle) throw new Error("Secure connection (HTTPS) required");
    const base = await crypto.subtle.importKey("raw", enc.encode(passphrase.normalize("NFKC")), "PBKDF2", false, ["deriveBits"]);
    const bits = await crypto.subtle.deriveBits(
      { name: "PBKDF2", hash: "SHA-256", salt: enc.encode("private-chat/v1"), iterations: 600000 },
      base,
      512
    );
    key = await crypto.subtle.importKey("raw", bits.slice(32), "AES-GCM", false, ["encrypt", "decrypt"]);
    return hex(bits.slice(0, 32));
  }

  async function encrypt(obj) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(JSON.stringify(obj)));
    const out = new Uint8Array(12 + ct.byteLength);
    out.set(iv);
    out.set(new Uint8Array(ct), 12);
    return b64(out);
  }

  async function decrypt(payload) {
    const raw = unb64(payload);
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: raw.slice(0, 12) }, key, raw.slice(12));
    return JSON.parse(dec.decode(pt));
  }

  const wipe = () => { key = null; };

  return { deriveKeys, encrypt, decrypt, wipe };
})();

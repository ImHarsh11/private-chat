// Usage: node roomid.js "your long shared passphrase"
// Prints the room id to put in the ALLOWED_ROOMS env var on your host.
// Must stay in sync with deriveKeys() in public/crypto.js.
const { pbkdf2Sync } = require("crypto");

const pass = process.argv[2];
if (!pass || pass.length < 14) {
  console.error('Usage: node roomid.js "passphrase (14+ chars)"');
  process.exit(1);
}
const bits = pbkdf2Sync(pass.normalize("NFKC"), "private-chat/v1", 600000, 64, "sha256");
console.log(bits.subarray(0, 32).toString("hex"));

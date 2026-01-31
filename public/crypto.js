const SECRET = "static-client-key";

function encrypt(text) {
  return btoa(
    text
      .split("")
      .map((c, i) =>
        String.fromCharCode(c.charCodeAt(0) ^ SECRET.charCodeAt(i % SECRET.length))
      )
      .join("")
  );
}

function decrypt(cipher) {
  const decoded = atob(cipher);
  return decoded
    .split("")
    .map((c, i) =>
      String.fromCharCode(c.charCodeAt(0) ^ SECRET.charCodeAt(i % SECRET.length))
    )
    .join("");
}

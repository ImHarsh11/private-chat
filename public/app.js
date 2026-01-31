const socket = io();
let typingTimeout;

function joinRoom() {
  socket.emit("join-room", {
    username: username.value,
    secretCode: code.value
  });
}

socket.on("joined", () => {
  login.classList.add("hidden");
  chat.classList.remove("hidden");
});

socket.on("error-msg", msg => {
  error.innerText = msg;
});

function sendMessage() {
  const text = message.value.trim();
  if (!text) return;

  const encrypted = encrypt(text);

  socket.emit("send-message", {
    from: username.value,
    payload: encrypted
  });

  message.value = "";
  socket.emit("stop-typing");
}

socket.on("receive-message", ({ from, payload }) => {
  const decrypted = decrypt(payload);

  const p = document.createElement("p");
  p.innerHTML = `<span class="sender">[${from}]</span> ${decrypted}`;

  messages.appendChild(p);
  messages.scrollTop = messages.scrollHeight;
});

message.oninput = () => {
  socket.emit("typing");
  clearTimeout(typingTimeout);
  typingTimeout = setTimeout(() => {
    socket.emit("stop-typing");
  }, 800);
};

socket.on("typing", user => {
  typing.innerText = `${user} is typing...`;
});

socket.on("stop-typing", () => {
  typing.innerText = "";
});

socket.on("active-users", users => {
  status.innerText = `user1: ${users.user1} | user2: ${users.user2}`;
});

socket.on("clear-chat", () => {
  messages.innerHTML = "";
});

function logout() {
  socket.emit("logout");
  location.reload();
}

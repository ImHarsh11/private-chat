const express = require("express");
const http = require("http");
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);
const io = new Server(server);

app.use(express.static("public"));

const rooms = {};
const MESSAGE_TTL = 5 * 60 * 1000;

io.on("connection", (socket) => {

  socket.on("join-room", ({ username, secretCode }) => {

    if (!["user1", "user2"].includes(username)) {
      socket.emit("error-msg", "Invalid username");
      return;
    }

    if (!rooms[secretCode]) {
      rooms[secretCode] = {
        users: { user1: null, user2: null },
        timer: null
      };
    }

    const room = rooms[secretCode];

    // Prevent duplicate active session
    if (room.users[username] && room.users[username] !== socket.id) {
      socket.emit("error-msg", `${username} already connected`);
      return;
    }

    room.users[username] = socket.id;

    socket.username = username;
    socket.secretCode = secretCode;
    socket.join(secretCode);

    startAutoDelete(secretCode);

    io.to(secretCode).emit("active-users", getActiveUsers(room));
    socket.emit("joined");
  });

  socket.on("send-message", ({ from, payload }) => {
    io.to(socket.secretCode).emit("receive-message", {
      from,
      payload
    });
  });

  socket.on("typing", () => {
    socket.to(socket.secretCode).emit("typing", socket.username);
  });

  socket.on("stop-typing", () => {
    socket.to(socket.secretCode).emit("stop-typing");
  });

  socket.on("logout", () => {
    cleanup(socket);
  });

  socket.on("disconnect", () => {
    cleanup(socket);
  });

  function cleanup(socket) {
    const { secretCode, username } = socket;
    if (!rooms[secretCode]) return;

    rooms[secretCode].users[username] = null;

    io.to(secretCode).emit(
      "active-users",
      getActiveUsers(rooms[secretCode])
    );

    const stillActive = Object.values(rooms[secretCode].users).some(Boolean);
    if (!stillActive) {
      clearInterval(rooms[secretCode].timer);
      delete rooms[secretCode];
    }
  }
});

function getActiveUsers(room) {
  return {
    user1: room.users.user1 ? "online" : "offline",
    user2: room.users.user2 ? "online" : "offline"
  };
}

function startAutoDelete(code) {
  const room = rooms[code];
  if (room.timer) return;

  room.timer = setInterval(() => {
    io.to(code).emit("clear-chat");
  }, MESSAGE_TTL);
}

server.listen(3000, "0.0.0.0", () => {
  console.log("Server running on port 3000");
});


const express = require("express");
const http = require("http");
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);
const io = new Server(server);

app.use(express.json());
app.use(express.static("public"));

app.get("/api/health", (req, res) => {
res.json({ ok: true, message: "Snake Rivals server is running" });
});

const rooms = new Map();

function isAdmin(req) {
const password = process.env.ADMIN_PASSWORD;
return password && req.headers["x-admin-password"] === password;
}

app.post("/api/admin/rooms", (req, res) => {
if (!isAdmin(req)) {
return res.status(401).json({ error: "Sai mật khẩu Admin" });
}

const id = Math.random().toString(36).slice(2, 8).toUpperCase();
const room = {
id,
name: String(req.body.name || "Phòng mới").slice(0, 40),
players: 0,
createdAt: Date.now()
};

rooms.set(id, room);
io.emit("rooms:update", [...rooms.values()]);
res.json({ ok: true, room });
});

app.get("/api/rooms", (req, res) => {
res.json([...rooms.values()]);
});

app.delete("/api/admin/rooms/:id", (req, res) => {
if (!isAdmin(req)) {
return res.status(401).json({ error: "Sai mật khẩu Admin" });
}

const id = req.params.id.toUpperCase();
if (!rooms.has(id)) {
return res.status(404).json({ error: "Không tìm thấy phòng" });
}

io.in(id).disconnectSockets(true);
rooms.delete(id);
io.emit("rooms:update", [...rooms.values()]);
res.json({ ok: true });
});

io.on("connection", (socket) => {
socket.on("room:join", (id, callback) => {
id = String(id || "").toUpperCase();
const room = rooms.get(id);

if (!room) {
  if (typeof callback === "function") {
    callback({ ok: false, error: "Phòng không tồn tại" });
  }
  return;
}

for (const oldRoom of socket.rooms) {
  if (oldRoom !== socket.id && rooms.has(oldRoom)) {
    socket.leave(oldRoom);
    updatePlayers(oldRoom);
  }
}

socket.join(id);
updatePlayers(id);

if (typeof callback === "function") {
  callback({ ok: true, room });
}

});

socket.on("game:state", (state) => {
for (const id of socket.rooms) {
if (rooms.has(id)) {
socket.to(id).emit("game:state", {
playerId: socket.id,
state
});
}
}
});

socket.on("disconnect", () => {
for (const id of rooms.keys()) {
updatePlayers(id);
}
});
});

function updatePlayers(id) {
const room = rooms.get(id);
if (!room) return;

room.players = io.sockets.adapter.rooms.get(id)?.size || 0;
io.emit("rooms:update", [...rooms.values()]);
io.to(id).emit("room:players", room.players);
}

const PORT = process.env.PORT || 3000;
server.listen(PORT, "0.0.0.0", () => {
console.log("Server listening on port ${PORT}");
});

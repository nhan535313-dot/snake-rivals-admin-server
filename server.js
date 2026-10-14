"use strict";

const express = require("express");
const session = require("express-session");
const http = require("http");
const { Server } = require("socket.io");
const nodemailer = require("nodemailer");
const helmet = require("helmet");
const crypto = require("crypto");
const path = require("path");

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const PORT = process.env.PORT || 3000;
const IS_PRODUCTION = process.env.NODE_ENV === "production";

app.disable("x-powered-by");
app.use(helmet({
  contentSecurityPolicy: false
}));
app.use(express.json({ limit: "20kb" }));
app.use(express.urlencoded({ extended: false, limit: "20kb" }));

if (IS_PRODUCTION) {
  app.set("trust proxy", 1);
}

const SESSION_SECRET = process.env.SESSION_SECRET;
const ADMIN_USERNAME = process.env.ADMIN_USERNAME;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const ADMIN_EMAIL = process.env.ADMIN_EMAIL;
const GMAIL_USER = process.env.GMAIL_USER;
const GMAIL_APP_PASSWORD = process.env.GMAIL_APP_PASSWORD;

if (!SESSION_SECRET || SESSION_SECRET.length < 32) {
  console.error("ERROR: SESSION_SECRET must contain at least 32 characters.");
}

const sessionMiddleware = session({
  name: "snake_admin_session",
  secret: SESSION_SECRET || crypto.randomBytes(48).toString("hex"),
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: IS_PRODUCTION,
    sameSite: "strict",
    maxAge: 12 * 60 * 60 * 1000
  }
});

app.use(sessionMiddleware);
io.engine.use(sessionMiddleware);

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: GMAIL_USER,
    pass: GMAIL_APP_PASSWORD
  }
});

// Email OTP chỉ được lấy từ biến môi trường.
// Không lấy email nhận mã từ dữ liệu do Admin gửi lên.
function getAdminEmail() {
  if (
    !ADMIN_EMAIL ||
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(ADMIN_EMAIL)
  ) {
    throw new Error("ADMIN_EMAIL is not configured correctly.");
  }

  return ADMIN_EMAIL;
}

function isConfigured() {
  return Boolean(
    SESSION_SECRET &&
    SESSION_SECRET.length >= 32 &&
    ADMIN_USERNAME &&
    ADMIN_PASSWORD &&
    ADMIN_EMAIL &&
    GMAIL_USER &&
    GMAIL_APP_PASSWORD
  );
}

function requireAdmin(req, res, next) {
  if (
    req.session &&
    req.session.adminAuthenticated === true
  ) {
    return next();
  }

  return res.status(401).json({
    success: false,
    message: "Vui lòng đăng nhập Admin."
  });
}

function sameOrigin(req, res, next) {
  const origin = req.get("origin");

  if (origin) {
    try {
      const originUrl = new URL(origin);
      const requestUrl = new URL(
        `${req.protocol}://${req.get("host")}`
      );

      if (originUrl.host !== requestUrl.host) {
        return res.status(403).json({
          success: false,
          message: "Origin không hợp lệ."
        });
      }
    } catch {
      return res.status(403).json({
        success: false,
        message: "Origin không hợp lệ."
      });
    }
  }

  next();
}

app.use("/api/admin", sameOrigin);

// So sánh mật khẩu theo thời gian cố định khi hai chuỗi có cùng độ dài.
function safeCompare(a, b) {
  if (typeof a !== "string" || typeof b !== "string") {
    return false;
  }

  const aa = Buffer.from(a);
  const bb = Buffer.from(b);

  if (aa.length !== bb.length) {
    return false;
  }

  return crypto.timingSafeEqual(aa, bb);
}

function maskEmail(email) {
  const [name, ...domainParts] = email.split("@");
  const domain = domainParts.join("@");

  if (!name || !domain) return "***";

  const visible = name.slice(0, Math.min(2, name.length));
  return visible + "***@" + domain;
}

// Khóa thử OTP trong bộ nhớ.
// Lưu ý: bộ đếm này sẽ mất khi máy chủ khởi động lại.
const otpChallenges = new Map();
const loginLocks = new Map();
const MAX_OTP_ATTEMPTS = 5;
const OTP_LIFETIME = 5 * 60 * 1000;
const LOCK_DURATION = 15 * 60 * 1000;

function getClientKey(req) {
  // Dùng địa chỉ IP do kết nối cung cấp.
  // Khi triển khai sau proxy, cần cấu hình trust proxy đúng.
  return req.ip || req.socket.remoteAddress || "unknown";
}

function isLocked(key) {
  const until = loginLocks.get(key);

  if (!until) return false;

  if (Date.now() >= until) {
    loginLocks.delete(key);
    return false;
  }

  return true;
}

function lockLogin(key) {
  loginLocks.set(key, Date.now() + LOCK_DURATION);
}

function createOtp() {
  return crypto.randomInt(100000, 1000000).toString();
}

function hashOtp(otp) {
  return crypto
    .createHash("sha256")
    .update(otp)
    .digest("hex");
}

function safeHashCompare(a, b) {
  const aa = Buffer.from(a, "hex");
  const bb = Buffer.from(b, "hex");

  return aa.length === bb.length &&
    crypto.timingSafeEqual(aa, bb);
}

// Health check
app.get("/api/health", (req, res) => {
  res.json({
    success: true,
    service: "Snake Rivals 3D",
    status: "online",
    configured: isConfigured(),
    time: new Date().toISOString()
  });
});

// Hiển thị email nhận OTP đã che.
app.get("/api/admin/otp-info", (req, res) => {
  try {
    res.json({
      success: true,
      email: maskEmail(getAdminEmail())
    });
  } catch {
    res.status(503).json({
      success: false,
      message: "Chủ hệ thống chưa cấu hình email OTP."
    });
  }
});

// Bước 1: kiểm tra tên và mật khẩu Admin, sau đó gửi OTP.
app.post("/api/admin/login", async (req, res) => {
  const key = getClientKey(req);

  if (isLocked(key)) {
    return res.status(429).json({
      success: false,
      message: "Đang bị khóa đăng nhập. Vui lòng thử lại sau 15 phút."
    });
  }

  if (!isConfigured()) {
    return res.status(503).json({
      success: false,
      message: "Máy chủ chưa được cấu hình đầy đủ."
    });
  }

  const username = req.body?.username;
  const password = req.body?.password;

  if (
    !safeCompare(username, ADMIN_USERNAME) ||
    !safeCompare(password, ADMIN_PASSWORD)
  ) {
    return res.status(401).json({
      success: false,
      message: "Tên tài khoản hoặc mật khẩu không đúng."
    });
  }

  try {
    const otp = createOtp();
    const challengeId = crypto.randomUUID();

    // Xóa thử thách OTP cũ trong phiên.
    if (req.session.otpChallengeId) {
      otpChallenges.delete(req.session.otpChallengeId);
    }

    otpChallenges.set(challengeId, {
      otpHash: hashOtp(otp),
      expiresAt: Date.now() + OTP_LIFETIME,
      attempts: 0,
      clientKey: key
    });

    req.session.otpChallengeId = challengeId;
    req.session.adminAuthenticated = false;

    await transporter.sendMail({
      from: GMAIL_USER,
      to: getAdminEmail(),
      subject: "Mã xác minh Admin - Snake Rivals 3D",
      text:
        `Mã OTP của bạn là: ${otp}\n\n` +
        "Mã hết hạn sau 5 phút.\n" +
        "Không chia sẻ mã này cho bất kỳ ai."
    });

    res.json({
      success: true,
      message: "Đã gửi OTP đến email quản trị.",
      email: maskEmail(getAdminEmail()),
      expiresInSeconds: 300
    });
  } catch (error) {
    console.error("OTP email error:", error.message);

    if (req.session.otpChallengeId) {
      otpChallenges.delete(req.session.otpChallengeId);
      delete req.session.otpChallengeId;
    }

    res.status(500).json({
      success: false,
      message: "Không gửi được OTP. Hãy kiểm tra cấu hình Gmail."
    });
  }
});

// Bước 2: xác minh OTP.
app.post("/api/admin/verify-otp", async (req, res) => {
  const key = getClientKey(req);

  if (isLocked(key)) {
    return res.status(429).json({
      success: false,
      message: "Đăng nhập đang bị khóa."
    });
  }

  const challengeId = req.session?.otpChallengeId;
  const challenge = challengeId
    ? otpChallenges.get(challengeId)
    : null;

  const otp = req.body?.otp;

  if (!challenge || challenge.clientKey !== key) {
    return res.status(401).json({
      success: false,
      message: "Yêu cầu OTP không hợp lệ. Hãy đăng nhập lại."
    });
  }

  if (Date.now() > challenge.expiresAt) {
    otpChallenges.delete(challengeId);
    delete req.session.otpChallengeId;

    return res.status(401).json({
      success: false,
      message: "OTP đã hết hạn. Hãy đăng nhập lại."
    });
  }

  if (
    typeof otp !== "string" ||
    !/^\d{6}$/.test(otp) ||
    !safeHashCompare(hashOtp(otp), challenge.otpHash)
  ) {
    challenge.attempts += 1;

    if (challenge.attempts >= MAX_OTP_ATTEMPTS) {
      otpChallenges.delete(challengeId);
      delete req.session.otpChallengeId;
      lockLogin(key);

      return res.status(429).json({
        success: false,
        message: "Sai OTP 5 lần. Đăng nhập bị khóa trong 15 phút."
      });
    }

    return res.status(401).json({
      success: false,
      message: `OTP không đúng. Còn ${MAX_OTP_ATTEMPTS - challenge.attempts} lần thử.`
    });
  }

  otpChallenges.delete(challengeId);
  delete req.session.otpChallengeId;

  // Đổi session ID sau khi xác minh để giảm nguy cơ session fixation.
  req.session.regenerate((err) => {
    if (err) {
      console.error("Session regenerate error:", err.message);

      return res.status(500).json({
        success: false,
        message: "Không tạo được phiên đăng nhập."
      });
    }

    req.session.adminAuthenticated = true;
    req.session.adminUsername = ADMIN_USERNAME;

    req.session.save((saveError) => {
      if (saveError) {
        return res.status(500).json({
          success: false,
          message: "Không lưu được phiên đăng nhập."
        });
      }

      res.json({
        success: true,
        message: "Xác minh thành công."
      });
    });
  });
});

// Thông tin phiên Admin.
app.get("/api/admin/me", requireAdmin, (req, res) => {
  res.json({
    success: true,
    username: req.session.adminUsername,
    permissions: [
      "view_rooms",
      "create_rooms",
      "close_rooms"
    ],
    emailManagement: false
  });
});

// Đăng xuất.
app.post("/api/admin/logout", requireAdmin, (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("snake_admin_session");

    res.json({
      success: true,
      message: "Đã đăng xuất."
    });
  });
});

// Phòng chơi: dữ liệu hiện lưu trong bộ nhớ.
const rooms = new Map();

function publicRoom(room) {
  return {
    id: room.id,
    name: room.name,
    maxPlayers: room.maxPlayers,
    players: room.players.size,
    status: room.status,
    createdAt: room.createdAt
  };
}

function broadcastRooms() {
  io.emit(
    "rooms:update",
    Array.from(rooms.values()).map(publicRoom)
  );
}

// Danh sách phòng.
app.get("/api/admin/rooms", requireAdmin, (req, res) => {
  res.json({
    success: true,
    rooms: Array.from(rooms.values()).map(publicRoom)
  });
});

// Tạo phòng.
app.post("/api/admin/rooms", requireAdmin, (req, res) => {
  const name = String(req.body?.name || "").trim();
  const maxPlayers = Number(req.body?.maxPlayers || 8);

  if (!name || name.length > 40) {
    return res.status(400).json({
      success: false,
      message: "Tên phòng phải có từ 1 đến 40 ký tự."
    });
  }

  if (
    !Number.isInteger(maxPlayers) ||
    maxPlayers < 2 ||
    maxPlayers > 100
  ) {
    return res.status(400).json({
      success: false,
      message: "Số người chơi phải từ 2 đến 100."
    });
  }

  const id = crypto.randomUUID().slice(0, 8);

  const room = {
    id,
    name,
    maxPlayers,
    players: new Set(),
    status: "open",
    createdAt: new Date().toISOString()
  };

  rooms.set(id, room);
  broadcastRooms();

  res.status(201).json({
    success: true,
    room: publicRoom(room)
  });
});

// Đóng phòng.
app.delete("/api/admin/rooms/:id", requireAdmin, (req, res) => {
  const room = rooms.get(req.params.id);

  if (!room) {
    return res.status(404).json({
      success: false,
      message: "Không tìm thấy phòng."
    });
  }

  room.status = "closed";

  // Thông báo các client đang ở trong phòng.
  io.to(room.id).emit("room:closed", {
    roomId: room.id,
    message: "Phòng đã được đóng bởi Admin."
  });

  for (const socketId of room.players) {
    const playerSocket = io.sockets.sockets.get(socketId);

    if (playerSocket) {
      playerSocket.leave(room.id);
      playerSocket.data.roomId = null;
    }
  }

  room.players.clear();
  rooms.delete(room.id);
  broadcastRooms();

  res.json({
    success: true,
    message: "Đã đóng phòng."
  });
});

// Socket.IO: nền tảng giao tiếp nhiều người chơi.
io.on("connection", (socket) => {
  socket.emit(
    "rooms:update",
    Array.from(rooms.values()).map(publicRoom)
  );

  socket.on("room:join", (data, callback) => {
    const respond = typeof callback === "function"
      ? callback
      : () => {};

    const roomId = String(data?.roomId || "");
    const playerName = String(data?.playerName || "Player")
      .trim()
      .slice(0, 20);

    const room = rooms.get(roomId);

    if (!room || room.status !== "open") {
      return respond({
        success: false,
        message: "Phòng không tồn tại hoặc đã đóng."
      });
    }

    if (room.players.size >= room.maxPlayers) {
      return respond({
        success: false,
        message: "Phòng đã đầy."
      });
    }

    if (socket.data.roomId) {
      const oldRoom = rooms.get(socket.data.roomId);

      if (oldRoom) {
        oldRoom.players.delete(socket.id);
        socket.leave(oldRoom.id);
      }
    }

    room.players.add(socket.id);
    socket.data.roomId = room.id;
    socket.data.playerName = playerName;

    socket.join(room.id);

    socket.to(room.id).emit("player:joined", {
      id: socket.id,
      name: playerName
    });

    respond({
      success: true,
      room: publicRoom(room),
      playerId: socket.id
    });

    broadcastRooms();
  });

  // Chuyển tiếp trạng thái game cho các người chơi trong cùng phòng.
  // Client game phải tự gửi state hợp lệ và giới hạn tốc độ gửi.
  let lastStateAt = 0;

  socket.on("game:state", (state) => {
    const now = Date.now();

    if (now - lastStateAt < 33) return;
    lastStateAt = now;

    const roomId = socket.data.roomId;

    if (!roomId || !rooms.has(roomId)) return;
    if (!state || typeof state !== "object") return;

    // Không chuyển tiếp payload quá lớn.
    let encoded;

    try {
      encoded = JSON.stringify(state);
    } catch {
      return;
    }

    if (encoded.length > 10000) return;

    socket.to(roomId).emit("game:state", {
      playerId: socket.id,
      playerName: socket.data.playerName || "Player",
      state
    });
  });

  socket.on("disconnect", () => {
    const roomId = socket.data.roomId;
    const room = roomId ? rooms.get(roomId) : null;

    if (room) {
      room.players.delete(socket.id);

      socket.to(room.id).emit("player:left", {
        playerId: socket.id
      });

      broadcastRooms();
    }
  });
});

// Trang Admin.
app.get("/", (req, res) => {
  res.redirect("/admin.html");
});

app.use(express.static(path.join(__dirname, "public")));

server.listen(PORT, "0.0.0.0", () => {
  console.log(`Snake Rivals server listening on port ${PORT}`);

  if (!isConfigured()) {
    console.warn(
      "WARNING: Missing environment variables. Admin login is unavailable."
    );
  }
});

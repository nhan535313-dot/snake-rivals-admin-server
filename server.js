
"use strict";

/*
============================================================
 SNAKE RIVALS 3D — SERVER EDITION
============================================================

Chức năng:
  1. Express HTTP API
  2. Socket.IO multiplayer rooms
  3. MongoDB persistent storage
  4. MongoDB-backed Admin sessions
  5. Admin login with email OTP
  6. Login rate limiting
  7. Room creation, listing, closing and joining
  8. Player profiles
  9. Persistent leaderboard
 10. Game-state validation
 11. Health and storage status
 12. Graceful shutdown

Environment variables:
  PORT
  NODE_ENV
  MONGODB_URI
  DATABASE_NAME
  SESSION_SECRET
  ADMIN_USERNAME
  ADMIN_PASSWORD
  ADMIN_EMAIL
  GMAIL_USER
  GMAIL_APP_PASSWORD

Important:
  - Never commit secrets to GitHub.
  - MongoDB is required for persistent storage.
  - Live socket connections are temporary and must reconnect
    after a server restart.
  - Game scores submitted by clients are not trustworthy.
    Use server-authoritative game simulation for competitive play.
============================================================
*/

const express = require("express");
const session = require("express-session");
const http = require("http");
const { Server } = require("socket.io");
const nodemailer = require("nodemailer");
const helmet = require("helmet");
const crypto = require("crypto");
const path = require("path");
const { MongoClient } = require("mongodb");
const MongoStore = require("connect-mongo");

/* =========================================================
   1. CONFIGURATION
========================================================= */

const app = express();
const server = http.createServer(app);

const PORT = Number(process.env.PORT || 3000);
const IS_PRODUCTION = process.env.NODE_ENV === "production";

const MONGODB_URI = process.env.MONGODB_URI || "";
const DATABASE_NAME =
  process.env.DATABASE_NAME || "snake_rivals";

const SESSION_SECRET = process.env.SESSION_SECRET || "";
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || "";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "";
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || "";
const GMAIL_USER = process.env.GMAIL_USER || "";
const GMAIL_APP_PASSWORD =
  process.env.GMAIL_APP_PASSWORD || "";

const SESSION_COOKIE_NAME = "snake_admin_session";
const SESSION_MAX_AGE = 12 * 60 * 60 * 1000;

const OTP_LIFETIME = 5 * 60 * 1000;
const MAX_OTP_ATTEMPTS = 5;
const LOGIN_LOCK_DURATION = 15 * 60 * 1000;

const MAX_ROOM_NAME_LENGTH = 40;
const MAX_PLAYER_NAME_LENGTH = 20;
const MAX_ROOM_PLAYERS = 100;
const MIN_ROOM_PLAYERS = 2;

const MAX_GAME_STATE_BYTES = 10000;
const GAME_STATE_INTERVAL_MS = 50;
const MAX_LEADERBOARD_SCORE = 100000000;

const SERVER_STARTED_AT = Date.now();

app.disable("x-powered-by");

app.use(helmet({
  contentSecurityPolicy: false
}));

app.use(express.json({
  limit: "20kb",
  strict: true
}));

app.use(express.urlencoded({
  extended: false,
  limit: "20kb"
}));

if (IS_PRODUCTION) {
  app.set("trust proxy", 1);
}

/* =========================================================
   2. RUNTIME STATE
========================================================= */

let mongoClient = null;
let db = null;
let sessionStore = null;
let transporter = null;

let roomCollection = null;
let playerCollection = null;
let leaderboardCollection = null;
let otpCollection = null;
let loginLockCollection = null;

let databaseReady = false;
let shuttingDown = false;

const rooms = new Map();
const socketRateLimits = new Map();

const io = new Server(server, {
  cors: {
    origin: true,
    credentials: true,
    methods: ["GET", "POST"]
  },
  maxHttpBufferSize: 1e6,
  connectTimeout: 20000,
  pingInterval: 25000,
  pingTimeout: 20000
});

/* =========================================================
   3. GENERAL HELPERS
========================================================= */

function nowDate() {
  return new Date();
}

function isoNow() {
  return new Date().toISOString();
}

function isPlainObject(value) {
  if (!value || typeof value !== "object") return false;

  const prototype = Object.getPrototypeOf(value);

  return prototype === Object.prototype ||
    prototype === null;
}

function clampNumber(value, minimum, maximum) {
  return Math.max(minimum, Math.min(maximum, value));
}

function cleanString(value, maximumLength, fallback = "") {
  if (typeof value !== "string") return fallback;

  return value
    .replace(/[\u0000-\u001f\u007f]/g, "")
    .trim()
    .slice(0, maximumLength);
}

function validEmail(value) {
  return typeof value === "string" &&
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function isValidIdentifier(value, maxLength = 100) {
  return typeof value === "string" &&
    value.length >= 1 &&
    value.length <= maxLength &&
    /^[a-zA-Z0-9_-]+$/.test(value);
}

function randomId(length = 12) {
  return crypto.randomBytes(Math.ceil(length / 2))
    .toString("hex")
    .slice(0, length);
}

function hashString(value) {
  return crypto
    .createHash("sha256")
    .update(String(value))
    .digest("hex");
}

function safeCompare(a, b) {
  if (typeof a !== "string" || typeof b !== "string") {
    return false;
  }

  const aa = Buffer.from(a, "utf8");
  const bb = Buffer.from(b, "utf8");

  if (aa.length !== bb.length) {
    return false;
  }

  return crypto.timingSafeEqual(aa, bb);
}

function safeHashCompare(a, b) {
  if (
    typeof a !== "string" ||
    typeof b !== "string" ||
    !/^[a-f0-9]{64}$/i.test(a) ||
    !/^[a-f0-9]{64}$/i.test(b)
  ) {
    return false;
  }

  const aa = Buffer.from(a, "hex");
  const bb = Buffer.from(b, "hex");

  return aa.length === bb.length &&
    crypto.timingSafeEqual(aa, bb);
}

function maskEmail(email) {
  if (!validEmail(email)) return "***";

  const at = email.lastIndexOf("@");
  const name = email.slice(0, at);
  const domain = email.slice(at + 1);

  return name.slice(0, Math.min(2, name.length)) +
    "***@" + domain;
}

function getClientKey(req) {
  /*
   * req.ip relies on Express proxy configuration.
   * Do not blindly trust arbitrary X-Forwarded-For values.
   */
  return String(
    req.ip ||
    req.socket?.remoteAddress ||
    "unknown"
  ).slice(0, 128);
}

function sendError(res, status, message) {
  return res.status(status).json({
    success: false,
    message
  });
}

function requireDatabase(req, res, next) {
  if (!databaseReady || !db) {
    return sendError(
      res,
      503,
      "Cơ sở dữ liệu chưa sẵn sàng."
    );
  }

  next();
}

function asyncRoute(handler) {
  return function wrappedRoute(req, res, next) {
    Promise.resolve(handler(req, res, next))
      .catch(next);
  };
}

/* =========================================================
   4. CONFIGURATION VALIDATION
========================================================= */

function isAdminConfigured() {
  return Boolean(
    SESSION_SECRET &&
    SESSION_SECRET.length >= 32 &&
    ADMIN_USERNAME &&
    ADMIN_PASSWORD &&
    ADMIN_EMAIL &&
    validEmail(ADMIN_EMAIL) &&
    GMAIL_USER &&
    GMAIL_APP_PASSWORD
  );
}

function isDatabaseConfigured() {
  return Boolean(MONGODB_URI);
}

function getAdminEmail() {
  if (!validEmail(ADMIN_EMAIL)) {
    throw new Error(
      "ADMIN_EMAIL is missing or invalid."
    );
  }

  return ADMIN_EMAIL;
}

/* =========================================================
   5. MONGODB CONNECTION AND COLLECTIONS
========================================================= */

async function connectDatabase() {
  if (!isDatabaseConfigured()) {
    throw new Error(
      "Thiếu MONGODB_URI trong biến môi trường."
    );
  }

  mongoClient = new MongoClient(MONGODB_URI, {
    serverSelectionTimeoutMS: 10000,
    connectTimeoutMS: 10000,
    maxPoolSize: 15,
    minPoolSize: 0,
    retryWrites: true
  });

  await mongoClient.connect();

  db = mongoClient.db(DATABASE_NAME);

  roomCollection = db.collection("rooms");
  playerCollection = db.collection("players");
  leaderboardCollection = db.collection("leaderboard");
  otpCollection = db.collection("admin_otp_challenges");
  loginLockCollection = db.collection("login_locks");

  await Promise.all([
    roomCollection.createIndex(
      { id: 1 },
      { unique: true }
    ),

    roomCollection.createIndex({
      status: 1,
      updatedAt: -1
    }),

    playerCollection.createIndex(
      { playerId: 1 },
      { unique: true }
    ),

    playerCollection.createIndex({
      updatedAt: -1
    }),

    leaderboardCollection.createIndex(
      { playerId: 1 },
      { unique: true }
    ),

    leaderboardCollection.createIndex({
      score: -1,
      updatedAt: 1
    }),

    otpCollection.createIndex(
      { challengeId: 1 },
      { unique: true }
    ),

    otpCollection.createIndex(
      { expiresAt: 1 },
      { expireAfterSeconds: 0 }
    ),

    loginLockCollection.createIndex(
      { key: 1 },
      { unique: true }
    ),

    loginLockCollection.createIndex(
      { expiresAt: 1 },
      { expireAfterSeconds: 0 }
    )
  ]);

  databaseReady = true;

  console.log(
    "[Database] MongoDB connected:",
    DATABASE_NAME
  );
}

async function closeDatabase() {
  databaseReady = false;

  if (mongoClient) {
    await mongoClient.close();
    mongoClient = null;
  }

  db = null;
}

/* =========================================================
   6. SESSION STORE
========================================================= */

function configureSessionStore() {
  if (!mongoClient) {
    throw new Error(
      "MongoDB must connect before session store setup."
    );
  }

  sessionStore = MongoStore.create({
    client: mongoClient,
    dbName: DATABASE_NAME,
    collectionName: "admin_sessions",
    ttl: Math.floor(SESSION_MAX_AGE / 1000),
    autoRemove: "native",
    touchAfter: 60
  });

  const sessionMiddleware = session({
    name: SESSION_COOKIE_NAME,
    secret: SESSION_SECRET,
    store: sessionStore,
    resave: false,
    saveUninitialized: false,
    rolling: true,
    cookie: {
      httpOnly: true,
      secure: IS_PRODUCTION,
      sameSite: "lax",
      maxAge: SESSION_MAX_AGE
    }
  });

  app.use(sessionMiddleware);
  io.engine.use(sessionMiddleware);
}

/* =========================================================
   7. EMAIL CONFIGURATION
========================================================= */

function configureMailer() {
  if (!GMAIL_USER || !GMAIL_APP_PASSWORD) {
    console.warn(
      "[Mail] Gmail environment variables are missing."
    );

    transporter = null;
    return;
  }

  transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: GMAIL_USER,
      pass: GMAIL_APP_PASSWORD
    },
    pool: true,
    maxConnections: 2,
    maxMessages: 50
  });
}

async function sendOtpEmail(otp) {
  if (!transporter) {
    throw new Error(
      "Email service is not configured."
    );
  }

  const recipient = getAdminEmail();

  await transporter.sendMail({
    from: GMAIL_USER,
    to: recipient,
    subject: "Mã xác minh Admin - Snake Rivals 3D",
    text:
      `Mã OTP của bạn là: ${otp}\n\n` +
      "Mã hết hạn sau 5 phút.\n" +
      "Không chia sẻ mã này cho bất kỳ ai.",
    html: `
      <div style="font-family:Arial,sans-serif;max-width:480px">
        <h2>Snake Rivals 3D</h2>
        <p>Mã xác minh đăng nhập Admin:</p>
        <div style="font-size:32px;font-weight:bold;letter-spacing:8px">
          ${otp}
        </div>
        <p>Mã hết hạn sau 5 phút.</p>
        <p>Không chia sẻ mã này cho bất kỳ ai.</p>
      </div>
    `
  });
}

/* =========================================================
   8. SECURITY MIDDLEWARE
========================================================= */

function requireAdmin(req, res, next) {
  if (
    req.session &&
    req.session.adminAuthenticated === true
  ) {
    return next();
  }

  return sendError(
    res,
    401,
    "Vui lòng đăng nhập Admin."
  );
}

function sameOrigin(req, res, next) {
  const origin = req.get("origin");

  /*
   * Requests without Origin can be legitimate, for example
   * direct API clients. Admin routes still require a session.
   * Browser requests with Origin must match the request host.
   */
  if (!origin) return next();

  try {
    const originUrl = new URL(origin);
    const requestUrl = new URL(
      `${req.protocol}://${req.get("host")}`
    );

    if (originUrl.host !== requestUrl.host) {
      return sendError(
        res,
        403,
        "Origin không hợp lệ."
      );
    }
  } catch {
    return sendError(
      res,
      403,
      "Origin không hợp lệ."
    );
  }

  next();
}

app.use("/api/admin", sameOrigin);

/* =========================================================
   9. PERSISTENT LOGIN LOCKS
========================================================= */

async function getActiveLoginLock(key) {
  if (!databaseReady) return null;

  const record = await loginLockCollection.findOne({
    key,
    expiresAt: { $gt: nowDate() }
  });

  return record || null;
}

async function clearLoginLock(key) {
  if (!databaseReady) return;

  await loginLockCollection.deleteOne({ key });
}

async function lockLogin(key) {
  if (!databaseReady) return;

  const expiresAt = new Date(
    Date.now() + LOGIN_LOCK_DURATION
  );

  await loginLockCollection.updateOne(
    { key },
    {
      $set: {
        key,
        expiresAt,
        updatedAt: nowDate()
      }
    },
    { upsert: true }
  );
}

async function incrementLoginFailure(key) {
  /*
   * This counter is shared across server restarts because
   * the lock is stored in MongoDB.
   */
  const current = await getActiveLoginLock(key);

  if (current) return current;

  const record = await loginLockCollection.findOneAndUpdate(
    { key },
    {
      $inc: { failures: 1 },
      $set: {
        updatedAt: nowDate()
      },
      $setOnInsert: {
        key,
        createdAt: nowDate(),
        expiresAt: new Date(
          Date.now() + LOGIN_LOCK_DURATION
        )
      }
    },
    {
      upsert: true,
      returnDocument: "after"
    }
  );

  const value = record?.value || record;

  if ((value?.failures || 0) >= 5) {
    await lockLogin(key);
    return getActiveLoginLock(key);
  }

  return null;
}

/* =========================================================
   10. OTP CHALLENGES
========================================================= */

function createOtp() {
  return crypto.randomInt(100000, 1000000).toString();
}

function hashOtp(otp) {
  return hashString(otp);
}

async function deleteOtpChallenge(challengeId) {
  if (!databaseReady || !challengeId) return;

  await otpCollection.deleteOne({ challengeId });
}

async function createOtpChallenge(
  challengeId,
  clientKey,
  otp
) {
  const expiresAt = new Date(
    Date.now() + OTP_LIFETIME
  );

  await otpCollection.insertOne({
    challengeId,
    clientKey,
    otpHash: hashOtp(otp),
    attempts: 0,
    expiresAt,
    createdAt: nowDate()
  });
}

/* =========================================================
   11. HEALTH CHECK
========================================================= */

app.get("/api/health", (req, res) => {
  res.set("Cache-Control", "no-store");

  res.json({
    success: true,
    service: "Snake Rivals 3D",
    status: "online",
    storage: databaseReady
      ? "connected"
      : "disconnected",
    adminConfigured: isAdminConfigured(),
    uptimeSeconds: Math.floor(
      (Date.now() - SERVER_STARTED_AT) / 1000
    ),
    socketIO: {
      enabled: true,
      connectedClients: io.engine.clientsCount
    },
    time: isoNow()
  });
});

/* =========================================================
   12. ADMIN OTP INFORMATION
========================================================= */

app.get("/api/admin/otp-info", (req, res) => {
  try {
    res.json({
      success: true,
      email: maskEmail(getAdminEmail())
    });
  } catch {
    return sendError(
      res,
      503,
      "Chủ hệ thống chưa cấu hình email OTP."
    );
  }
});

/* =========================================================
   13. ADMIN LOGIN — STEP ONE
========================================================= */

app.post(
  "/api/admin/login",
  requireDatabase,
  asyncRoute(async (req, res) => {
    const clientKey = getClientKey(req);

    const lock = await getActiveLoginLock(clientKey);

    if (lock) {
      return sendError(
        res,
        429,
        "Đăng nhập bị khóa. Hãy thử lại sau."
      );
    }

    if (!isAdminConfigured()) {
      return sendError(
        res,
        503,
        "Máy chủ chưa được cấu hình đầy đủ."
      );
    }

    const username = req.body?.username;
    const password = req.body?.password;

    if (
      !safeCompare(username, ADMIN_USERNAME) ||
      !safeCompare(password, ADMIN_PASSWORD)
    ) {
      await incrementLoginFailure(clientKey);

      return sendError(
        res,
        401,
        "Tên tài khoản hoặc mật khẩu không đúng."
      );
    }

    await clearLoginLock(clientKey);

    const otp = createOtp();
    const challengeId = crypto.randomUUID();

    if (req.session.otpChallengeId) {
      await deleteOtpChallenge(
        req.session.otpChallengeId
      );
    }

    await createOtpChallenge(
      challengeId,
      clientKey,
      otp
    );

    req.session.otpChallengeId = challengeId;
    req.session.adminAuthenticated = false;

    /*
     * Save the session before sending the email so the client
     * receives a session cookie that can be reused for OTP.
     */
    await new Promise((resolve, reject) => {
      req.session.save(error => {
        if (error) reject(error);
        else resolve();
      });
    });

    try {
      await sendOtpEmail(otp);
    } catch (error) {
      console.error(
        "[Mail] OTP delivery failed:",
        error.message
      );

      await deleteOtpChallenge(challengeId);

      delete req.session.otpChallengeId;

      await new Promise(resolve => {
        req.session.save(() => resolve());
      });

      return sendError(
        res,
        503,
        "Không gửi được OTP. Hãy kiểm tra cấu hình Gmail."
      );
    }

    res.json({
      success: true,
      message: "Đã gửi OTP đến email quản trị.",
      email: maskEmail(getAdminEmail()),
      expiresInSeconds: 300
    });
  })
);

/* =========================================================
   14. ADMIN LOGIN — STEP TWO
========================================================= */

app.post(
  "/api/admin/verify-otp",
  requireDatabase,
  asyncRoute(async (req, res) => {
    const clientKey = getClientKey(req);
    const lock = await getActiveLoginLock(clientKey);

    if (lock) {
      return sendError(
        res,
        429,
        "Đăng nhập đang bị khóa."
      );
    }

    const challengeId = req.session?.otpChallengeId;

    if (!challengeId) {
      return sendError(
        res,
        401,
        "Yêu cầu OTP không hợp lệ. Hãy đăng nhập lại."
      );
    }

    const challenge = await otpCollection.findOne({
      challengeId
    });

    if (
      !challenge ||
      challenge.clientKey !== clientKey
    ) {
      return sendError(
        res,
        401,
        "Yêu cầu OTP không hợp lệ. Hãy đăng nhập lại."
      );
    }

    if (
      !challenge.expiresAt ||
      challenge.expiresAt.getTime() < Date.now()
    ) {
      await deleteOtpChallenge(challengeId);
      delete req.session.otpChallengeId;

      return sendError(
        res,
        401,
        "OTP đã hết hạn. Hãy đăng nhập lại."
      );
    }

    const otp = req.body?.otp;

    const validOtp =
      typeof otp === "string" &&
      /^\d{6}$/.test(otp) &&
      safeHashCompare(
        hashOtp(otp),
        challenge.otpHash
      );

    if (!validOtp) {
      const nextAttempts = challenge.attempts + 1;

      await otpCollection.updateOne(
        { challengeId },
        { $set: { attempts: nextAttempts } }
      );

      if (nextAttempts >= MAX_OTP_ATTEMPTS) {
        await deleteOtpChallenge(challengeId);
        delete req.session.otpChallengeId;
        await lockLogin(clientKey)

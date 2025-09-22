// server.mjs
import dotenv from "dotenv";
dotenv.config();

import express from "express";
import cors from "cors";
import fs from "fs";
import fsPromises from "fs/promises";
import http from "http";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { Server } from "socket.io";
import helmet from "helmet";
import morgan from "morgan";
import rateLimit from "express-rate-limit";
import crypto from "crypto";

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: process.env.CORS_ORIGIN || "*" } });

// ====== ENV & CONFIG ======
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "change-this-secret";
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || "15m"; // short access token
const REFRESH_EXPIRES_DAYS = parseInt(process.env.REFRESH_EXPIRES_DAYS || "30", 10);
const USERS_FILE = process.env.USERS_FILE || "./users.json";
const TOKENS_FILE = process.env.TOKENS_FILE || "./tokens.json";
const SALT_ROUNDS = parseInt(process.env.SALT_ROUNDS || "12", 10);
const LIVE_LOCATION_TIMEOUT_MS = 2 * 60 * 1000; // 2 minutes stale
const BACKUP_INTERVAL_MS = 60 * 60 * 1000; // 1 hour

// ====== IN-MEM STATE ======
let users = []; // { id, username, password(hashed), role, profile }
let hashedRefreshTokens = {}; // { tokenHash: { userId, expiresAt } }
let liveLocations = {}; // { userId: { lat, lng, lastUpdated } }

// ====== HELPERS: Atomic file read/write ======
async function safeReadJSON(path, fallback) {
  try {
    const txt = await fsPromises.readFile(path, "utf8");
    return JSON.parse(txt);
  } catch (e) {
    return fallback;
  }
}
async function safeWriteJSON(path, data) {
  const tmp = path + ".tmp";
  await fsPromises.writeFile(tmp, JSON.stringify(data, null, 2));
  await fsPromises.rename(tmp, path);
}

// ====== LOAD STATE ======
async function loadState() {
  users = await safeReadJSON(USERS_FILE, []);
  hashedRefreshTokens = await safeReadJSON(TOKENS_FILE, {});
  console.log(`Loaded ${users.length} users, ${Object.keys(hashedRefreshTokens).length} refresh tokens`);
}
async function persistUsers() { await safeWriteJSON(USERS_FILE, users); }
async function persistTokens() { await safeWriteJSON(TOKENS_FILE, hashedRefreshTokens); }

// ====== UTILITIES ======
function genId(prefix = "") {
  return prefix + Date.now().toString(36) + "-" + crypto.randomBytes(3).toString("hex");
}
function generateAccessToken(user) {
  return jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
}
function generateRefreshToken() {
  return crypto.randomBytes(32).toString("hex");
}
function hashToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}
function now() { return Date.now(); }

// ====== MIDDLEWARE ======
app.use(helmet());
app.use(cors({ origin: process.env.CORS_ORIGIN || "*" }));
app.use(express.json());
app.use(morgan("tiny"));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200, // per IP
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

// basic auth middleware for API
function authMiddleware(req, res, next) {
  const header = req.headers.authorization;
  const token = header?.startsWith("Bearer ") ? header.split(" ")[1] : null;
  if (!token) return res.status(401).json({ error: "Authorization token missing" });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    return next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}
function requireRole(role) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: "Unauthorized" });
    if (req.user.role !== role) return res.status(403).json({ error: "Forbidden" });
    next();
  };
}

// ====== ROUTES ======
app.get("/api/health", (req, res) => {
  res.json({
    status: "ok",
    uptime: process.uptime(),
    timestamp: new Date().toISOString(),
    users: users.length,
    liveLocations: Object.keys(liveLocations).length,
    message: "Backend running 🔥",
  });
});

// REGISTER
app.post("/api/register", async (req, res) => {
  try {
    const { username, password, role } = req.body;
    if (!username || !password) return res.status(400).json({ error: "username and password required" });
    if (users.find(u => u.username === username)) return res.status(409).json({ error: "User exists" });

    const hashed = await bcrypt.hash(password, SALT_ROUNDS);
    const user = { id: genId("u_"), username, password: hashed, role: role === "admin" ? "admin" : "user", profile: {} };
    users.push(user);
    await persistUsers();

    // issue tokens
    const access = generateAccessToken(user);
    const refresh = generateRefreshToken();
    const rh = hashToken(refresh);
    hashedRefreshTokens[rh] = { userId: user.id, expiresAt: now() + REFRESH_EXPIRES_DAYS * 24 * 3600 * 1000 };
    await persistTokens();

    res.status(201).json({ message: "registered", accessToken: access, refreshToken: refresh });
  } catch (err) {
    console.error("Registration error", err);
    res.status(500).json({ error: "registration failed" });
  }
});

// LOGIN
app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = users.find(u => u.username === username);
    if (!user) return res.status(401).json({ error: "Invalid credentials" });
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ error: "Invalid credentials" });

    const access = generateAccessToken(user);
    const refresh = generateRefreshToken();
    hashedRefreshTokens[hashToken(refresh)] = { userId: user.id, expiresAt: now() + REFRESH_EXPIRES_DAYS * 24 * 3600 * 1000 };
    await persistTokens();

    res.json({ message: "ok", accessToken: access, refreshToken: refresh });
  } catch (err) {
    console.error("Login error", err);
    res.status(500).json({ error: "login failed" });
  }
});

// REFRESH ACCESS TOKEN
app.post("/api/token/refresh", async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) return res.status(400).json({ error: "refreshToken required" });
    const rh = hashToken(refreshToken);
    const stored = hashedRefreshTokens[rh];
    if (!stored) return res.status(401).json({ error: "Invalid refresh token" });
    if (stored.expiresAt < now()) {
      delete hashedRefreshTokens[rh];
      await persistTokens();
      return res.status(401).json({ error: "Refresh token expired" });
    }
    const user = users.find(u => u.id === stored.userId);
    if (!user) return res.status(404).json({ error: "User not found" });

    const access = generateAccessToken(user);
    res.json({ accessToken: access });
  } catch (err) {
    console.error("Refresh token error", err);
    res.status(500).json({ error: "refresh failed" });
  }
});

// LOGOUT (revoke a refresh token)
app.post("/api/logout", async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) return res.status(400).json({ error: "refreshToken required" });
    const rh = hashToken(refreshToken);
    if (hashedRefreshTokens[rh]) {
      delete hashedRefreshTokens[rh];
      await persistTokens();
    }
    res.json({ message: "logged out" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "logout failed" });
  }
});

// ME
app.get("/api/me", authMiddleware, (req, res) => {
  const user = users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: "User not found" });
  res.json({ id: user.id, username: user.username, role: user.role, profile: user.profile });
});

// UPDATE PROFILE
app.put("/api/me", authMiddleware, async (req, res) => {
  const user = users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: "User not found" });
  const { profile } = req.body;
  user.profile = { ...(user.profile || {}), ...(profile || {}) };
  await persistUsers();
  res.json({ message: "profile updated", profile: user.profile });
});

// PASSWORD RESET (generate token) -- returns token so you can send email externally
app.post("/api/password/reset", async (req, res) => {
  try {
    const { username } = req.body;
    const user = users.find(u => u.username === username);
    if (!user) return res.status(200).json({ message: "If user exists, reset token generated" }); // do not reveal existence
    // For demo: we still generate token when user exists
    if (user) {
      const token = crypto.randomBytes(24).toString("hex");
      const rh = hashToken(token);
      hashedRefreshTokens[rh] = { userId: user.id, expiresAt: now() + 60 * 60 * 1000 }; // 1 hour
      await persistTokens();
      return res.json({ resetToken: token, note: "send this to user via email/SMS" });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "failed" });
  }
});

// ADMIN: list users (paginated)
app.get("/api/admin/users", authMiddleware, requireRole("admin"), (req, res) => {
  const limit = Math.min(parseInt(req.query.limit || "20", 10), 100);
  const page = Math.max(parseInt(req.query.page || "1", 10), 1);
  const start = (page - 1) * limit;
  const slice = users.slice(start, start + limit).map(u => ({ id: u.id, username: u.username, role: u.role, profile: u.profile }));
  res.json({ page, limit, total: users.length, users: slice });
});

// ADMIN: revoke all tokens for a user
app.post("/api/admin/revoke", authMiddleware, requireRole("admin"), async (req, res) => {
  const { userId } = req.body;
  if (!userId) return res.status(400).json({ error: "userId required" });
  for (const k of Object.keys(hashedRefreshTokens)) {
    if (hashedRefreshTokens[k].userId === userId) delete hashedRefreshTokens[k];
  }
  await persistTokens();
  res.json({ message: "revoked" });
});

// ====== SOCKET.IO ======
io.use((socket, next) => {
  // token via query or auth payload
  const token = socket.handshake.auth?.token || socket.handshake.query?.token;
  if (!token) return next(new Error("Auth token required"));
  try {
    const user = jwt.verify(token, JWT_SECRET);
    socket.user = user;
    return next();
  } catch (e) {
    return next(new Error("Invalid token"));
  }
});

io.on("connection", (socket) => {
  const user = socket.user;
  console.log(`Socket connected: ${socket.id} (${user.username})`);
  liveLocations[user.id] = { lat: null, lng: null, lastUpdated: null, username: user.username };

  // broadcast sanitized locations
  io.emit("locations", sanitizeLocations(liveLocations));

  socket.on("locationUpdate", (data) => {
    if (!socket.user) return;
    const { lat, lng } = data || {};
    if (typeof lat !== "number" || typeof lng !== "number") return;
    liveLocations[socket.user.id] = { lat, lng, lastUpdated: now(), username: socket.user.username };
    io.emit("locations", sanitizeLocations(liveLocations));
  });

  socket.on("disconnect", () => {
    if (socket.user) {
      delete liveLocations[socket.user.id];
      io.emit("locations", sanitizeLocations(liveLocations));
      console.log(`Socket disconnected: ${socket.id} (${socket.user.username})`);
    }
  });
});

function sanitizeLocations(locObj) {
  // only send public info (no internal timestamps if you don't want)
  const out = {};
  for (const [uid, v] of Object.entries(locObj)) {
    out[uid] = { lat: v.lat, lng: v.lng, lastUpdated: v.lastUpdated ? new Date(v.lastUpdated).toISOString() : null, username: v.username };
  }
  return out;
}

// ====== BACKGROUND TASKS ======
function cleanupStaleLocations() {
  const cutoff = now() - LIVE_LOCATION_TIMEOUT_MS;
  let removed = 0;
  for (const [k, v] of Object.entries(liveLocations)) {
    if (!v.lastUpdated || v.lastUpdated < cutoff) {
      delete liveLocations[k];
      removed++;
    }
  }
  if (removed) io.emit("locations", sanitizeLocations(liveLocations));
}
setInterval(cleanupStaleLocations, 30 * 1000); // every 30s

async function snapshotBackup() {
  try {
    await safeWriteJSON("./backup.users.json", users);
    await safeWriteJSON("./backup.tokens.json", hashedRefreshTokens);
    console.log("Backup snapshot saved");
  } catch (e) {
    console.error("Backup failed", e);
  }
}
setInterval(snapshotBackup, BACKUP_INTERVAL_MS);

// ====== STARTUP ======
(async () => {
  await loadState();

  // create default admin if none exists (convenience for first deploy)
  if (!users.find(u => u.role === "admin")) {
    const pw = process.env.ADMIN_PW || "admin123";
    const admin = { id: genId("u_"), username: "admin", password: await bcrypt.hash(pw, SALT_ROUNDS), role: "admin", profile: {} };
    users.push(admin);
    await persistUsers();
    console.log(`Created default admin (username=admin, password=${process.env.ADMIN_PW ? "from env" : "admin123"})`);
  }

  server.listen(PORT, () => console.log(`🚀 Server running on ${PORT}`));
})();

// ====== GRACEFUL SHUTDOWN ======
async function shutdown() {
  console.log("Shutdown initiated...");
  server.close(async () => {
    console.log("Server closed, persisting data...");
    try {
      await persistUsers();
      await persistTokens();
      console.log("Data persisted. Exiting.");
      process.exit(0);
    } catch (e) {
      console.error("Error during shutdown", e);
      process.exit(1);
    }
  });
  setTimeout(() => {
    console.warn("Force exit");
    process.exit(1);
  }, 10_000);
}
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);

// ====== ERROR HANDLING ======
app.use((err, req, res, next) => {
  console.error("Unhandled error:", err);
  res.status(500).json({ error: "internal_server_error" });
});
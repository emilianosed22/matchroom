import express from "express";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import http from "http";
import { Server } from "socket.io";
import { initDb, run, get, all } from "./db.js";

const app = express();
initDb();

app.use(cors({ origin: true, credentials: true }));
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || "dev_secret_change_me";

/* ================== AUTH MIDDLEWARE ================== */
function auth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: "No token" });

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload; // { id, email }
    next();
  } catch {
    return res.status(401).json({ error: "Invalid token" });
  }
}

/* ================== AUTH ================== */
app.post("/api/auth/register", async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: "email y password requeridos" });

  const hash = await bcrypt.hash(password, 10);
  try {
    const r = await run("INSERT INTO users(email, password_hash) VALUES(?,?)", [email, hash]);
    await run("INSERT INTO profiles(user_id, verificado) VALUES(?,0)", [r.lastID]);
    res.json({ ok: true });
  } catch {
    res.status(400).json({ error: "Email ya existe" });
  }
});

app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: "email y password requeridos" });

  const user = await get("SELECT * FROM users WHERE email = ?", [email]);
  if (!user) return res.status(401).json({ error: "Credenciales inválidas" });

  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.status(401).json({ error: "Credenciales inválidas" });

  const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: "7d" });
  res.json({ token });
});

/* ================== PROFILE ================== */
app.get("/api/profile/me", auth, async (req, res) => {
  const p = await get("SELECT * FROM profiles WHERE user_id = ?", [req.user.id]);
  res.json(p || {});
});

app.put("/api/profile/me", auth, async (req, res) => {
  const { nombre, pais, ciudad, uni, presupuesto, estilo, hobbies, descripcion, verificado } = req.body || {};

  await run(
    `UPDATE profiles SET
      nombre=?, pais=?, ciudad=?, uni=?,
      presupuesto=?, estilo=?, hobbies=?, descripcion=?,
      verificado=?, updated_at=datetime('now')
     WHERE user_id=?`,
    [
      nombre || null,
      pais || null,
      ciudad || null,
      uni || null,
      presupuesto ? Number(presupuesto) : null,
      estilo || null,
      hobbies || null,
      descripcion || null,
      verificado ? 1 : 0,
      req.user.id
    ]
  );

  res.json({ ok: true });
});

/* ================== ROOMIES ================== */
function compatScore(me, other) {
  let score = 50;
  if (me?.estilo && other?.estilo && me.estilo === other.estilo) score += 25;
  if (me?.presupuesto && other?.presupuesto) {
    const diff = Math.abs(me.presupuesto - other.presupuesto);
    score += Math.max(0, 25 - Math.round(diff / 20));
  }
  return Math.min(100, Math.max(0, score));
}

app.get("/api/roomies", auth, async (req, res) => {
  const { city, maxBudget, style } = req.query;

  const me = await get("SELECT * FROM profiles WHERE user_id = ?", [req.user.id]);

  let sql = `SELECT p.* FROM profiles p WHERE p.user_id != ?`;
  const params = [req.user.id];

  if (city) { sql += " AND p.ciudad = ?"; params.push(city); }
  if (style) { sql += " AND p.estilo = ?"; params.push(style); }
  if (maxBudget) { sql += " AND p.presupuesto <= ?"; params.push(Number(maxBudget)); }

  const rows = await all(sql, params);

  res.json(rows.map(r => ({
    user_id: r.user_id,
    nombre: r.nombre,
    ciudad: r.ciudad,
    uni: r.uni,
    presupuesto: r.presupuesto,
    estilo: r.estilo,
    hobbies: r.hobbies,
    descripcion: r.descripcion,
    compat: compatScore(me, r)
  })));
});

/* ================== FAVORITES ================== */
app.get("/api/favorites", auth, async (req, res) => {
  const rows = await all("SELECT favorite_user_id FROM favorites WHERE user_id=?", [req.user.id]);
  res.json(rows.map(r => r.favorite_user_id));
});

app.post("/api/favorites/:targetId", auth, async (req, res) => {
  const targetId = Number(req.params.targetId);
  await run("INSERT OR IGNORE INTO favorites(user_id,favorite_user_id) VALUES(?,?)", [req.user.id, targetId]);
  res.json({ ok: true });
});

app.delete("/api/favorites/:targetId", auth, async (req, res) => {
  const targetId = Number(req.params.targetId);
  await run("DELETE FROM favorites WHERE user_id=? AND favorite_user_id=?", [req.user.id, targetId]);
  res.json({ ok: true });
});

/* ================== SOCKET.IO ================== */
const server = http.createServer(app);

const io = new Server(server, {
  cors: { origin: true, credentials: true }
});

io.use((socket, next) => {
  try {
    const token = socket.handshake.auth?.token;
    const payload = jwt.verify(token, JWT_SECRET);
    socket.user = payload; // {id, email}
    next();
  } catch {
    next(new Error("Invalid token"));
  }
});

function dmRoom(a, b) {
  return `dm:${Math.min(a, b)}:${Math.max(a, b)}`;
}

io.on("connection", (socket) => {
  const me = socket.user.id;
  console.log("🟢 Socket conectado user:", me);

  socket.on("dm:join", ({ otherUserId }) => {
    socket.join(dmRoom(me, Number(otherUserId)));
  });

  socket.on("dm:send", ({ to, text }) => {
    const msg = { from: me, to: Number(to), text, ts: Date.now() };
    io.to(dmRoom(me, Number(to))).emit("dm:message", msg);
  });
});

/* ✅ IMPORTANTE: ESCUCHA EL server, NO app.listen */
const PORT = process.env.PORT || 3001;
server.listen(PORT, () => {
  console.log("✅ API + Socket en http://localhost:" + PORT);
  console.log("✅ Socket client: http://localhost:" + PORT + "/socket.io/socket.io.js");
});

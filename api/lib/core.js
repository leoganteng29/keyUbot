// =====================================================================
//  CORE C KEY WEB (port dari keybot.js, versi web / Vercel serverless)
//  - Data key/role = key.json di GitHub (SAMA dengan keybot & license.js ubot)
//  - Key hanya disimpan sebagai HASH SHA-256, key asli tampil sekali
//  - Semua rahasia dibaca dari Environment Variables Vercel (TIDAK ada di kode)
// =====================================================================
const crypto = require("crypto");
const env = process.env;

const CFG = {
  repo: env.GITHUB_REPO || "leoganteng29/dbUbot",
  branch: env.GITHUB_BRANCH || "main",
  file: env.GITHUB_FILE || "key.json",
  tokenFile: env.GITHUB_TOKENS_FILE || "tokens.json",
  ghToken: env.GITHUB_TOKEN || "",
  dev: new Set((env.DEVELOPER_IDS || "6146077243").split(/[,\s]+/).filter(Boolean).map(String)),
  prefix: String(env.KEY_PREFIX || "LEOX").toUpperCase(),
  defaultDays: Number(env.DEFAULT_DAYS || 30),
  tz: Number(env.TIMEZONE_OFFSET === undefined ? 7 : env.TIMEZONE_OFFSET),
  tzLabel: env.TIMEZONE_LABEL || "WIB",
  secret: env.SESSION_SECRET || "",
  encKey: env.TOKEN_ENC_KEY || "",
  brand: env.BRAND || "LEOX PREMIUM",
  sessionHours: Number(env.SESSION_HOURS || 12),
};

// ------------------------------------------------------------ role & batas (sama dengan keybot)
const ROLES = ["fullup", "reseller", "pt", "admin", "developer"];
const LABEL = { fullup: "Full Up", reseller: "Reseller", pt: "PT", admin: "Admin", developer: "Developer" };
const DEFAULT_LIMITS = { fullup: 10, reseller: 25, pt: 30, admin: null, developer: null };
const ADMIN_CAN_MANAGE = new Set(["fullup", "reseller", "pt"]);

function parseRole(s) {
  const t = String(s || "").toLowerCase().replace(/[\s_-]+/g, "");
  if (t === "fullup" || t === "fu") return "fullup";
  if (t === "dev" || t === "developer") return "developer";
  return ROLES.includes(t) ? t : null;
}

class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}
class Denied extends HttpError {
  constructor(message) { super(400, message); }
}

// ------------------------------------------------------------ util
const sha = (s) => crypto.createHash("sha256").update(String(s)).digest("hex");
const normKey = (s) => String(s || "").trim().toUpperCase().replace(/\s+/g, ""); // HARUS sama dgn license.js & keybot
const hashKey = (s) => sha(normKey(s));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const fmtTime = (ms) => new Date(Number(ms) + CFG.tz * 3600000).toISOString().replace("T", " ").slice(0, 16) + " " + CFG.tzLabel;

const ALPHA = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // tanpa 0/O/1/I
function newKey() {
  const g = () => Array.from(crypto.randomBytes(5), (b) => ALPHA[b % ALPHA.length]).join("");
  return `${CFG.prefix}-${g()}-${g()}-${g()}-${g()}`;
}

// ------------------------------------------------------------ GitHub
function needGithub() {
  if (!CFG.ghToken) throw new HttpError(500, "Server belum dikonfigurasi: env GITHUB_TOKEN belum diisi di Vercel.");
}
const ghUrl = (file) => `https://api.github.com/repos/${CFG.repo}/contents/${String(file).split("/").map(encodeURIComponent).join("/")}`;
const ghHeaders = (extra) => ({
  Authorization: `Bearer ${CFG.ghToken}`, "User-Agent": "ckey-web", "X-GitHub-Api-Version": "2022-11-28",
  Accept: "application/vnd.github+json", ...extra,
});

async function ghGet(file) {
  needGithub();
  const url = `${ghUrl(file)}?ref=${encodeURIComponent(CFG.branch)}`;
  const res = await fetch(url, { headers: ghHeaders(), signal: AbortSignal.timeout(20000) });
  if (res.status === 404) return null;
  if (!res.ok) throw new HttpError(502, `GitHub ${res.status}: ${(await res.text()).slice(0, 140)}`);
  const j = await res.json();
  let text = j.content ? Buffer.from(j.content, "base64").toString("utf8") : "";
  if (!text || j.encoding === "none") {
    const raw = await fetch(url, { headers: ghHeaders({ Accept: "application/vnd.github.raw+json" }), signal: AbortSignal.timeout(20000) });
    if (!raw.ok) throw new HttpError(502, `GitHub raw ${raw.status}`);
    text = await raw.text();
  }
  return { sha: j.sha, db: JSON.parse(text) };
}

async function ghPut(file, db, sha_, message) {
  const body = { message, content: Buffer.from(JSON.stringify(db, null, 2) + "\n").toString("base64"), branch: CFG.branch };
  if (sha_) body.sha = sha_;
  const res = await fetch(ghUrl(file), { method: "PUT", headers: ghHeaders({ "Content-Type": "application/json" }), body: JSON.stringify(body), signal: AbortSignal.timeout(25000) });
  if (!res.ok) {
    const e = new HttpError(502, `GitHub ${res.status}: ${(await res.text()).slice(0, 140)}`);
    e.ghStatus = res.status;
    throw e;
  }
}

function normalize(db) {
  const d = db && typeof db === "object" ? db : {};
  return {
    version: 1,
    updated_at: d.updated_at || Date.now(),
    limits: { ...DEFAULT_LIMITS, ...(d.limits || {}) },
    roles: d.roles || {},
    keys: d.keys || {},
    webs: d.webs || {}, // akun login web (dibuat lewat /cweb di keybot), terpisah dari key ubot
  };
}
function normalizeTokens(db) {
  const d = db && typeof db === "object" ? db : {};
  return { version: 1, updated_at: d.updated_at || Date.now(), tokens: d.tokens || {} };
}

// baca ulang dari GitHub, ubah, tulis; retry kalau bentrok (409/422)
async function mutateFile(file, norm, fn, message) {
  for (let i = 0; i < 4; i++) {
    const r = await ghGet(file);
    const db = norm(r && r.db);
    const out = fn(db); // boleh throw Denied
    db.updated_at = Date.now();
    try {
      await ghPut(file, db, r && r.sha, message);
      return out;
    } catch (e) {
      if ((e.ghStatus === 409 || e.ghStatus === 422) && i < 3) { await sleep(400); continue; }
      throw e;
    }
  }
}
const readDb = async () => { const r = await ghGet(CFG.file); return normalize(r && r.db); };
const mutate = (fn, message) => mutateFile(CFG.file, normalize, fn, message);
const readTokens = async () => { const r = await ghGet(CFG.tokenFile); return normalizeTokens(r && r.db); };
const mutateTokens = (fn, message) => mutateFile(CFG.tokenFile, normalizeTokens, fn, message);

// ------------------------------------------------------------ aturan role (sama dengan keybot)
function actorOf(db, id) {
  id = String(id);
  if (CFG.dev.has(id)) return { id, role: "developer", extra: 0 };
  const r = db.roles[id];
  const role = r && parseRole(r.role);
  return role ? { id, role, extra: Math.max(0, Number(r.extra_quota) || 0) } : null;
}
function limitOf(db, a) {
  if (a.role === "admin" || a.role === "developer") return Infinity;
  const l = db.limits[a.role];
  if (l === null || l === undefined || l === "unlimited") return Infinity;
  return Math.max(0, Number(l) || 0) + a.extra;
}
const usedOf = (db, id) => Object.values(db.keys).filter((k) => String(k.owner_id) === String(id) && k.status !== "revoked").length;
const normUser = (s) => String(s || "").trim().replace(/^@/, "").toLowerCase();
const keyState = (k) => (k.status === "revoked" ? "revoked" : k.expires_at && Date.now() >= Number(k.expires_at) ? "expired" : "active");
const findId = (db, input) => {
  const t = String(input || "").trim().toUpperCase().replace(/^K-?/, "");
  return Object.keys(db.keys).find((id) => id.toUpperCase().replace(/^K-?/, "") === t) || null;
};
// Infinity tidak bisa di-JSON -> null = bebas
const limJson = (n) => (n === Infinity ? null : n);

function doCreate(db, a, days, note, who) {
  const used = usedOf(db, a.id), l = limitOf(db, a);
  if (used >= l) throw new Denied(`Kuota key habis (${used}/${l}). ${a.role === "fullup" ? "Chat developer untuk tambah kuota." : "Hubungi developer."}`);
  let id;
  do { id = "K-" + crypto.randomBytes(3).toString("hex").toUpperCase(); } while (db.keys[id]);
  const key = newKey();
  const rec = {
    hash: hashKey(key), hint: key.slice(-4), owner_id: a.id, owner_role: a.role,
    owner_name: who.name || "", owner_username: who.username || "",
    created_at: Date.now(), expires_at: days > 0 ? Date.now() + days * 86400000 : null,
    status: "active", note: note || "",
  };
  db.keys[id] = rec;
  return { id, key, rec, used: used + 1, limit: l };
}

const publicKey = (id, k) => ({
  id, hint: k.hint || "", note: k.note || "", state: keyState(k), owner_id: String(k.owner_id), owner_role: k.owner_role || "",
  created_at: k.created_at, expires_at: k.expires_at || null,
  created_label: fmtTime(k.created_at), expires_label: k.expires_at ? fmtTime(k.expires_at) : "Permanen",
});

// Catatan: login web memakai db.webs (username + password WEB-xxxxx). Key ubot (db.keys, LEOX-xxxxx) TIDAK bisa dipakai login.
// ------------------------------------------------------------ sesi (cookie bertanda tangan HMAC)
const b64u = (b) => Buffer.from(b).toString("base64url");
function needSecret() {
  if (!CFG.secret || CFG.secret.length < 16) throw new HttpError(500, "Server belum dikonfigurasi: env SESSION_SECRET (min 16 karakter) belum diisi di Vercel.");
}
function signSession(payload) {
  needSecret();
  const body = b64u(JSON.stringify(payload));
  const mac = crypto.createHmac("sha256", CFG.secret).update(body).digest("base64url");
  return `${body}.${mac}`;
}
function readSession(req) {
  const m = String(req.headers.cookie || "").match(/(?:^|;\s*)ckw_session=([^;]+)/);
  if (!m) return null;
  const [body, mac] = decodeURIComponent(m[1]).split(".");
  if (!body || !mac || !CFG.secret) return null;
  const good = crypto.createHmac("sha256", CFG.secret).update(body).digest("base64url");
  const a = Buffer.from(mac), b = Buffer.from(good);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const p = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
    return p && p.exp > Date.now() ? p : null;
  } catch (_) { return null; }
}
const cookieStr = (val, maxAge) => `ckw_session=${val}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}`;

// Wajib login. Setiap request dicek ulang ke key.json: key di-revoke / expired -> langsung keluar.
async function requireAuth(req) {
  const s = readSession(req);
  if (!s) throw new HttpError(401, "Belum login atau sesi habis.");
  const db = await readDb();
  const k = db.webs[s.k];
  if (!k || keyState(k) !== "active") throw new HttpError(401, "Akun web kamu sudah tidak berlaku. Minta login baru lewat /cweb di bot.");
  const actor = s.o ? actorOf(db, s.o) : null; // akun 'member' tidak punya role (tanpa hak buat C Key)
  return { db, session: s, key: k, actor };
}
function needActor(ctx) {
  if (!ctx.actor) throw new HttpError(403, "Akun ini belum punya role (Full Up / Reseller / PT / Admin / Developer). Minta developer menambahkan role lewat /addrole.");
  return ctx.actor;
}

// ------------------------------------------------------------ enkripsi token (AES-256-GCM)
function encKey() {
  const base = CFG.encKey || CFG.secret;
  if (!base || base.length < 16) throw new HttpError(500, "Server belum dikonfigurasi: env TOKEN_ENC_KEY / SESSION_SECRET belum diisi.");
  return crypto.createHash("sha256").update("ckey-web-token:" + base).digest();
}
function encrypt(text) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv("aes-256-gcm", encKey(), iv);
  const ct = Buffer.concat([c.update(String(text), "utf8"), c.final()]);
  return [iv, c.getAuthTag(), ct].map((b) => b.toString("base64url")).join(".");
}
function decrypt(blob) {
  const [iv, tag, ct] = String(blob).split(".").map((x) => Buffer.from(x, "base64url"));
  const d = crypto.createDecipheriv("aes-256-gcm", encKey(), iv);
  d.setAuthTag(tag);
  return Buffer.concat([d.update(ct), d.final()]).toString("utf8");
}
const maskToken = (t) => { t = String(t); return t.length <= 10 ? "••••" : t.slice(0, 4) + "••••••••" + t.slice(-4); };

// ------------------------------------------------------------ HTTP helper
function wrap(methods) {
  return async (req, res) => {
    res.setHeader("Cache-Control", "no-store");
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    try {
      const fn = methods[req.method];
      if (!fn) throw new HttpError(405, "Method tidak didukung.");
      if (req.method !== "GET") {
        const ct = String(req.headers["content-type"] || "");
        if (!ct.includes("application/json")) throw new HttpError(415, "Content-Type harus application/json.");
      }
      const out = await fn(req, res);
      if (!res.writableEnded) res.status(200).send(JSON.stringify({ ok: true, ...(out || {}) }));
    } catch (e) {
      const status = e instanceof HttpError ? e.status : 500;
      if (!(e instanceof HttpError)) console.error("[api]", e && e.message);
      if (!res.writableEnded) res.status(status).send(JSON.stringify({ ok: false, error: e instanceof HttpError ? e.message : "Terjadi kesalahan server." }));
    }
  };
}
const body = (req) => (req.body && typeof req.body === "object" ? req.body : {});

module.exports = {
  CFG, ROLES, LABEL, ADMIN_CAN_MANAGE, HttpError, Denied, parseRole, sha, hashKey, normKey, sleep, fmtTime,
  readDb, mutate, readTokens, mutateTokens, normalize,
  actorOf, limitOf, usedOf, keyState, normUser, findId, limJson, doCreate, publicKey,
  signSession, readSession, cookieStr, requireAuth, needActor,
  encrypt, decrypt, maskToken, wrap, body,
};

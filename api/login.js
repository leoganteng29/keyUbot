// POST /api/login  { username, password }
// Akun login web dibuat lewat bot tele (keybot) dengan /cweb. Disimpan di key.json bagian "webs" (hash saja).
// Ini BEDA dari key ubot (LEOX-xxxxx dari /ckey) yang hanya untuk userbot Leo Brann.
const C = require("./_lib/core");

const fails = new Map(); // best-effort per instance: ip -> {n, until}
const MAX_FAILS = 8, LOCK_MS = 5 * 60 * 1000;

module.exports = C.wrap({
  POST: async (req, res) => {
    const ip = String(req.headers["x-forwarded-for"] || "").split(",")[0].trim() || "?";
    const f = fails.get(ip);
    if (f && f.until > Date.now()) throw new C.HttpError(429, "Terlalu banyak percobaan salah. Coba lagi beberapa menit lagi.");

    const { username, password } = C.body(req);
    const u = C.normUser(username);
    const fail = async (msg) => {
      const cur = fails.get(ip) || { n: 0, until: 0 };
      cur.n++;
      if (cur.n >= MAX_FAILS) { cur.until = Date.now() + LOCK_MS; cur.n = 0; }
      fails.set(ip, cur);
      await C.sleep(700);
      throw new C.HttpError(401, msg);
    };
    if (!u || !String(password || "").trim()) return fail("Username dan password wajib diisi.");

    const db = await C.readDb();
    const h = C.hashKey(password);
    const id = Object.keys(db.webs).find((i) => db.webs[i].username === u && db.webs[i].hash === h);
    if (!id) return fail("Username atau password salah.");
    const w = db.webs[id];

    const st = C.keyState(w);
    if (st === "revoked") throw new C.HttpError(403, "Akun web ini sudah dicabut.");
    if (st === "expired") throw new C.HttpError(403, "Akun web ini sudah expired.");

    fails.delete(ip);
    const maxAge = C.CFG.sessionHours * 3600;
    // 'o' = ID Telegram pembuat akun; role-nya dipakai kecuali akun bertipe "member"
    const token = C.signSession({ k: id, u: w.username, o: w.level === "member" ? null : String(w.owner_id), exp: Date.now() + maxAge * 1000 });
    res.setHeader("Set-Cookie", C.cookieStr(encodeURIComponent(token), maxAge));
    return {};
  },
});

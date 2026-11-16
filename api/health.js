// GET /api/health  -> diagnosa server. Sengaja TIDAK memakai require di atas file,
// supaya tetap jalan walau _lib/core.js hilang / error. Buka: https://domainmu/api/health
const fs = require("fs");
const path = require("path");

module.exports = async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  const out = { ok: true, node: process.version, files: {}, env: {}, core: "belum dicek", github: "skip" };

  // 1. file penting ada?
  const need = ["_lib/core.js", "login.js", "me.js", "keys.js", "tokens.js", "admin.js", "logout.js"];
  for (const f of need) out.files["api/" + f] = fs.existsSync(path.join(__dirname, f));

  // 2. env terisi? (hanya ya/tidak)
  out.env.GITHUB_TOKEN = !!process.env.GITHUB_TOKEN;
  out.env.SESSION_SECRET = !!process.env.SESSION_SECRET && process.env.SESSION_SECRET.length >= 16;

  // 3. core.js bisa di-load?
  let C = null;
  try { C = require("./_lib/core"); out.core = "OK"; }
  catch (e) { out.ok = false; out.core = "GAGAL: " + String(e && e.message).slice(0, 300); }

  // 4. GitHub bisa dibaca?
  if (C && C.CFG.ghToken) {
    try {
      const db = await C.readDb();
      out.github = "OK";
      out.repo = C.CFG.repo + "@" + C.CFG.branch + "/" + C.CFG.file;
      out.jumlah_akun_web = Object.keys(db.webs).length;
      out.username_web = Object.values(db.webs).map((w) => w.username); // bantu cek username cocok
    } catch (e) {
      out.ok = false;
      out.github = "GAGAL: " + String(e && e.message).slice(0, 200);
    }
  } else if (C) { out.ok = false; out.github = "GITHUB_TOKEN belum diisi"; }

  res.status(200).send(JSON.stringify(out, null, 2));
};

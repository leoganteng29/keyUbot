// GET /api/health  -> cek cepat konfigurasi server (tanpa membuka rahasia). Buka di browser: https://domainmu/api/health
const C = require("./_lib/core");

module.exports = async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  const out = {
    ok: true,
    node: process.version,
    env: {
      GITHUB_TOKEN: !!C.CFG.ghToken,
      SESSION_SECRET: !!C.CFG.secret && C.CFG.secret.length >= 16,
    },
    repo: C.CFG.repo, branch: C.CFG.branch, file: C.CFG.file,
    github: "skip",
  };
  if (C.CFG.ghToken) {
    try {
      const db = await C.readDb();
      out.github = "OK";
      out.webs = Object.keys(db.webs).length; // jumlah akun login web yang terbaca
    } catch (e) {
      out.ok = false;
      out.github = "GAGAL: " + String(e && e.message).slice(0, 160);
    }
  } else out.ok = false;
  res.status(200).send(JSON.stringify(out, null, 2));
};

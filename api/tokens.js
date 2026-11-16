// /api/tokens  — fitur "Add Token"
//   GET                          -> daftar token milik akun (disamarkan)
//   POST {provider,label,token}  -> tambah token (diverifikasi ke provider bila bisa, lalu disimpan TERENKRIPSI AES-256-GCM)
//   DELETE {id}                  -> hapus token
// Provider: vercel (sama seperti .setvtoken di ubot), github, telegram (token bot), other
const C = require("./_lib/core");

const MAX_PER_USER = 20;
const PROVIDERS = { vercel: "Vercel", github: "GitHub", telegram: "Bot Telegram", other: "Lainnya" };

async function getJson(url, headers) {
  let res;
  try { res = await fetch(url, { headers: { "User-Agent": "ckey-web", ...headers }, signal: AbortSignal.timeout(15000) }); }
  catch (_) { throw new C.HttpError(502, "Tidak bisa menghubungi provider untuk verifikasi token. Coba lagi."); }
  let j = null;
  try { j = await res.json(); } catch (_) {}
  return { res, j };
}

// kembalikan nama akun pemilik token, atau throw kalau token ditolak provider
async function verify(provider, token) {
  if (provider === "vercel") {
    const { res, j } = await getJson("https://api.vercel.com/v2/user", { Authorization: `Bearer ${token}` });
    if (!res.ok) throw new C.Denied("Token Vercel ditolak. Buat token baru di vercel.com/account/tokens.");
    const u = (j && (j.user || j)) || {};
    return u.username || u.email || "akun Vercel";
  }
  if (provider === "github") {
    const { res, j } = await getJson("https://api.github.com/user", { Authorization: `Bearer ${token}`, Accept: "application/vnd.github+json" });
    if (res.status === 401 || res.status === 403) throw new C.Denied("Token GitHub ditolak (cek masa berlaku & izin).");
    return (j && j.login) || "akun GitHub";
  }
  if (provider === "telegram") {
    if (!/^\d{6,12}:[\w-]{30,}$/.test(token)) throw new C.Denied("Format token bot salah. Contoh: 123456789:AA...");
    const { j } = await getJson(`https://api.telegram.org/bot${token}/getMe`, {});
    if (!j || !j.ok) throw new C.Denied("Token bot ditolak Telegram.");
    return "@" + j.result.username;
  }
  return "";
}

const view = (id, t) => ({ id, provider: t.provider, provider_label: PROVIDERS[t.provider] || t.provider, label: t.label, hint: t.hint, account: t.account || "", created_label: C.fmtTime(t.created_at) });

module.exports = C.wrap({
  GET: async (req) => {
    const ctx = await C.requireAuth(req);
    const tdb = await C.readTokens();
    const me = ctx.session.k;
    const tokens = Object.entries(tdb.tokens)
      .filter(([, t]) => t.owner_key === me)
      .sort((a, b) => b[1].created_at - a[1].created_at)
      .map(([id, t]) => view(id, t));
    return { tokens, providers: PROVIDERS };
  },

  POST: async (req) => {
    const ctx = await C.requireAuth(req);
    const b = C.body(req);
    const provider = Object.keys(PROVIDERS).includes(b.provider) ? b.provider : "other";
    const token = String(b.token || "").trim();
    const label = String(b.label || "").trim().slice(0, 40) || PROVIDERS[provider];
    if (token.length < 8 || token.length > 400 || /\s/.test(token)) throw new C.Denied("Token tidak valid (minimal 8 karakter, tanpa spasi).");

    const account = await verify(provider, token);
    const enc = C.encrypt(token);
    const me = ctx.session.k;
    const id = "T-" + require("crypto").randomBytes(3).toString("hex").toUpperCase();
    const rec = await C.mutateTokens((d) => {
      const mine = Object.values(d.tokens).filter((t) => t.owner_key === me).length;
      if (mine >= MAX_PER_USER) throw new C.Denied(`Maksimal ${MAX_PER_USER} token per akun. Hapus yang tidak dipakai.`);
      const t = { owner_key: me, owner: ctx.session.u, provider, label, enc, hint: C.maskToken(token), account, created_at: Date.now() };
      d.tokens[id] = t;
      return t;
    }, `token ${provider}`);
    return { token: view(id, rec) };
  },

  DELETE: async (req) => {
    const ctx = await C.requireAuth(req);
    const id = String(C.body(req).id || "").trim().toUpperCase();
    if (!id) throw new C.Denied("ID token wajib diisi.");
    await C.mutateTokens((d) => {
      const t = d.tokens[id];
      if (!t || t.owner_key !== ctx.session.k) throw new C.Denied("Token tidak ditemukan.");
      delete d.tokens[id];
    }, "token hapus");
    return { removed: id };
  },
});

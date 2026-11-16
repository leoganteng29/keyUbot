// /api/keys
//   GET                       -> daftar key milik akun (/mykeys)
//   POST {days, note}         -> buat key baru (/ckey)  — key asli hanya dikembalikan SEKALI
//   POST {action:"check",key} -> cek status key (/cekkey)
//   DELETE {id}               -> cabut key (/revoke)
const C = require("./_lib/core");

const parseDays = (v) => {
  const t = String(v === undefined || v === null ? "" : v).toLowerCase().trim();
  if (/^(0|perm|permanen|selamanya|forever|lifetime)$/.test(t)) return 0;
  const m = t.match(/^(\d{1,4})d?$/);
  return m ? Number(m[1]) : null;
};

module.exports = C.wrap({
  GET: async (req) => {
    const ctx = await C.requireAuth(req);
    if (!ctx.actor) return { keys: [] };
    const keys = Object.entries(ctx.db.keys)
      .filter(([, k]) => String(k.owner_id) === ctx.actor.id)
      .sort((a, b) => b[1].created_at - a[1].created_at)
      .map(([id, k]) => C.publicKey(id, k));
    return { keys };
  },

  POST: async (req) => {
    const ctx = await C.requireAuth(req);
    const b = C.body(req);

    if (b.action === "check") {
      if (!String(b.key || "").trim()) throw new C.Denied("Isi key yang mau dicek.");
      const fresh = await C.readDb();
      const h = C.hashKey(b.key);
      const id = Object.keys(fresh.keys).find((i) => fresh.keys[i].hash === h);
      if (!id) throw new C.Denied("Key tidak ditemukan.");
      return { key: C.publicKey(id, fresh.keys[id]) };
    }

    const a0 = C.needActor(ctx);
    const days = parseDays(b.days === undefined ? C.CFG.defaultDays : b.days);
    if (days === null) throw new C.Denied("Masa aktif tidak valid. Isi jumlah hari (1-9999) atau 0 untuk permanen.");
    const note = String(b.note || "").trim().slice(0, 60);
    const r = await C.mutate((db) => {
      const a = C.actorOf(db, a0.id);
      if (!a) throw new C.Denied("Role kamu sudah tidak aktif.");
      const rr = db.roles[a.id] || {};
      return C.doCreate(db, a, days, note, { name: rr.name || "", username: rr.username || "" });
    }, `key web ${a0.id}`);
    return { created: { key: r.key, ...C.publicKey(r.id, r.rec) }, quota: { used: r.used, limit: C.limJson(r.limit) } };
  },

  DELETE: async (req) => {
    const ctx = await C.requireAuth(req);
    const a0 = C.needActor(ctx);
    const { id: input } = C.body(req);
    if (!String(input || "").trim()) throw new C.Denied("ID key wajib diisi.");
    const r = await C.mutate((d) => {
      const me = C.actorOf(d, a0.id);
      if (!me) throw new C.Denied("Role kamu sudah tidak aktif.");
      const id = C.findId(d, input);
      if (!id) throw new C.Denied("ID key tidak ditemukan.");
      const k = d.keys[id];
      const powerful = me.role === "admin" || me.role === "developer";
      if (String(k.owner_id) !== me.id && !powerful) throw new C.Denied("Itu bukan key buatan kamu.");
      if (k.status === "revoked") throw new C.Denied("Key ini sudah di-revoke.");
      k.status = "revoked"; k.revoked_at = Date.now(); k.revoked_by = me.id;
      return { id };
    }, `revoke web ${a0.id}`);
    return { revoked: r.id };
  },
});

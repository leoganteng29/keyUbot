// /api/admin  (khusus Admin & Developer) — setara /roles /stats /addrole /delrole /addquota
//   GET                                  -> statistik + daftar role
//   POST {action:"addrole", id, role, name}
//   POST {action:"delrole", id, revoke}
//   POST {action:"addquota", id, amount}   (khusus Developer)
const C = require("./_lib/core");

const isId = (s) => /^\d{5,15}$/.test(String(s || "").trim());

function needAdmin(ctx) {
  const a = C.needActor(ctx);
  if (a.role !== "admin" && a.role !== "developer") throw new C.HttpError(403, "Menu ini khusus Admin & Developer.");
  return a;
}

module.exports = C.wrap({
  GET: async (req) => {
    const ctx = await C.requireAuth(req);
    needAdmin(ctx);
    const { db } = ctx;
    const all = Object.values(db.keys);
    const c = { active: 0, expired: 0, revoked: 0 };
    for (const k of all) c[C.keyState(k)]++;
    const webs = Object.values(db.webs).filter((w) => C.keyState(w) === "active").length;
    const roles = Object.entries(db.roles).map(([id, r]) => {
      const ac = C.actorOf(db, id);
      return {
        id, name: r.name || "", username: r.username || "", role: C.parseRole(r.role), role_label: C.LABEL[C.parseRole(r.role)] || r.role,
        extra_quota: Number(r.extra_quota) || 0, used: C.usedOf(db, id), limit: ac ? C.limJson(C.limitOf(db, ac)) : null,
      };
    });
    return { stats: { total: all.length, ...c, roles: roles.length, webs }, roles, developers: [...C.CFG.dev] };
  },

  POST: async (req) => {
    const ctx = await C.requireAuth(req);
    const me = needAdmin(ctx);
    const isDev = me.role === "developer", isAdm = me.role === "admin";
    const b = C.body(req);
    const target = String(b.id || "").trim();
    if (!isId(target)) throw new C.Denied("ID Telegram tidak valid (angka 5-15 digit).");

    if (b.action === "addrole") {
      const role = C.parseRole(b.role);
      if (!role) throw new C.Denied("Role tidak dikenal.");
      if (isAdm && !C.ADMIN_CAN_MANAGE.has(role)) throw new C.Denied("Admin hanya boleh menambah Full Up, Reseller & PT.");
      if (C.CFG.dev.has(target)) throw new C.Denied("User itu developer tetap (env DEVELOPER_IDS).");
      const name = String(b.name || "").trim().slice(0, 40);
      await C.mutate((d) => {
        const cur = d.roles[target];
        if (isAdm && cur && !C.ADMIN_CAN_MANAGE.has(C.parseRole(cur.role))) throw new C.Denied("Admin tidak boleh mengubah role Admin/Developer.");
        d.roles[target] = { ...(cur || {}), role, name: name || (cur && cur.name) || "", username: (cur && cur.username) || "", extra_quota: (cur && cur.extra_quota) || 0, added_by: me.id, added_at: (cur && cur.added_at) || Date.now() };
      }, `role web ${target} ${role}`);
      return { done: `Role ${C.LABEL[role]} diatur untuk ${target}.` };
    }

    if (b.action === "delrole") {
      const n = await C.mutate((d) => {
        const cur = d.roles[target];
        if (!cur) throw new C.Denied("User itu tidak punya role.");
        if (isAdm && !C.ADMIN_CAN_MANAGE.has(C.parseRole(cur.role))) throw new C.Denied("Admin tidak boleh menghapus role Admin/Developer.");
        delete d.roles[target];
        let n = 0;
        if (b.revoke) for (const k of Object.values(d.keys)) if (String(k.owner_id) === target && k.status !== "revoked") { k.status = "revoked"; k.revoked_at = Date.now(); k.revoked_by = me.id; n++; }
        return n;
      }, `delrole web ${target}`);
      return { done: `Role ${target} dihapus.${b.revoke ? ` ${n} key dicabut.` : ""}` };
    }

    if (b.action === "addquota") {
      if (!isDev) throw new C.HttpError(403, "Tambah kuota khusus Developer.");
      const n = Number(b.amount);
      if (!Number.isInteger(n) || n === 0 || Math.abs(n) > 100000) throw new C.Denied("Jumlah kuota harus bilangan bulat bukan 0.");
      const r = await C.mutate((d) => {
        const cur = d.roles[target];
        if (!cur) throw new C.Denied("User itu belum punya role. Tambahkan role dulu.");
        cur.extra_quota = Math.max(0, (Number(cur.extra_quota) || 0) + n);
        return { extra: cur.extra_quota, limit: C.limitOf(d, C.actorOf(d, target)) };
      }, `quota web ${target}`);
      return { done: `Kuota ${target}: tambahan ${r.extra}, batas sekarang ${r.limit === Infinity ? "Bebas" : r.limit}.` };
    }

    throw new C.Denied("Aksi tidak dikenal.");
  },
});

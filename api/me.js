// GET /api/me -> info sesi, role, kuota
const C = require("./_lib/core");

module.exports = C.wrap({
  GET: async (req) => {
    const x = await C.requireAuth(req);
    const { db, actor, key, session } = x;
    let quota = null;
    if (actor) {
      const used = C.usedOf(db, actor.id), lim = C.limitOf(db, actor);
      const mine = Object.values(db.keys).filter((k) => String(k.owner_id) === actor.id);
      quota = {
        used, limit: C.limJson(lim), remaining: lim === Infinity ? null : Math.max(0, lim - used),
        active: mine.filter((k) => C.keyState(k) === "active").length,
      };
    }
    return {
      user: { username: session.u, key_expires: key.expires_at ? C.fmtTime(key.expires_at) : "Permanen", level: key.level || "owner" },
      role: actor ? { id: actor.id, key: actor.role, label: C.LABEL[actor.role] } : null,
      quota,
      config: { brand: C.CFG.brand, prefix: C.CFG.prefix, default_days: C.CFG.defaultDays },
    };
  },
});

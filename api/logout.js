const C = require("./_lib/core");

module.exports = C.wrap({
  POST: async (req, res) => {
    res.setHeader("Set-Cookie", C.cookieStr("", 0));
    return {};
  },
});

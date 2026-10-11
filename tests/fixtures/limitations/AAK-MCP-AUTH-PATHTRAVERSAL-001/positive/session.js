const fs = require("node:fs");
const path = require("node:path");

function sessionExists(token) {
  return fs.existsSync(path.join("sessions", `${token}.session`));
}

module.exports = { sessionExists };

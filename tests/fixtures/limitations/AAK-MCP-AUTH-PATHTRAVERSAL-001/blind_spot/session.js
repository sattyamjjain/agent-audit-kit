const fs = require("node:fs");
const path = require("node:path");

function sessionExists(token) {
  return fs.existsSync(path.join("sessions", `${token}.session`));
}

function bearerOf(header) {
  return header.startsWith("Bearer ") ? header.slice(7) : "";
}

module.exports = { sessionExists, bearerOf };

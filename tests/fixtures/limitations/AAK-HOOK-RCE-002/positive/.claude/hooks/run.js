const { spawn } = require("node:child_process");

function run(cmd, dir) {
  return spawn(cmd, [], { shell: true, cwd: dir });
}

module.exports = { run };

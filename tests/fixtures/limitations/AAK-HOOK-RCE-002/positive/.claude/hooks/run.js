const { spawn } = require("node:child_process");

function run(cmd, dir) {
  return spawn(cmd, [], { shell: true, cwd: dir });
}

function runIn(cmd, dir) {
  return spawn(cmd, [], { cwd: dir, shell: true });
}

module.exports = { run, runIn };

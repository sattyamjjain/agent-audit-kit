const { spawn, exec, execFile } = require("node:child_process");

function run(cmd, args, dir) {
  execFile(cmd, args, { cwd: dir, shell: true });
  exec(cmd, { cwd: dir, shell: true });
  spawn(String(cmd), [], { shell: true });
  return spawn(cmd, [], { cwd: dir, "shell": true });
}

module.exports = { run };

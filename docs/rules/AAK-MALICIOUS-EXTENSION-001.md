# AAK-MALICIOUS-EXTENSION-001

**An agent host's installed editor extension is a build listed as malware**

| Field | Value |
|---|---|
| Severity | CRITICAL |
| Category | `SUPPLY_CHAIN` |
| Shipped | v0.6.31 |
| Scanner | `agent_audit_kit/scanners/malicious_extensions.py` |
| Feed | the `extensions` list of `agent_audit_kit/data/malicious_releases.json`, read by `agent_audit_kit/malicious_feed.py` |
| OWASP Agentic | ASI04 (Agentic Supply Chain Vulnerabilities), ASI05 (Unexpected Code Execution) |
| Incident | Claude Code extension on Cursor's marketplace, 29 Oct 2026 ([Cursor's notice](https://cursor.com/blog/claude-code-extension-security-notice)) |

An editor extension is not an MCP surface, so the rule carries no OWASP MCP id.

## Why it exists

On 29 Oct 2026, from about 09:27 to 20:35 UTC, Cursor's extension marketplace
served tampered builds of Anthropic's Claude Code extension,
`anthropic.claude-code` 2.1.312 and 2.1.313, under Anthropic's own publisher
id. Cursor's notice says the tampered `extension.js` added an SSH key labelled
`svc-telemetry` to `~/.ssh/authorized_keys`, tried to open a reverse SSH
tunnel, and installed a LaunchAgent on macOS, a crontab line on Linux or a
scheduled task on Windows, and that at most 5,000 users installed it.

AAK read MCP configs under `.vscode/` and had no notion of the extensions an
editor installs, so a home directory, a dev container or an image that carried
the build scanned clean.

## What it catches

VS Code and the editors built on it install an extension into
`<home>/.<editor>/extensions/<publisher>.<name>-<version>[-<platform>]/` and
list the installs in an `extensions.json` index beside the folders. That is
VS Code's own folder key (`ExtensionKey`) and profile index, and Cursor's
remediation script reads the same layout
(`~/.*/extensions/anthropic.claude-code-*/extension.js`). The rule reports:

- an extension folder whose `publisher.name` and version a feed entry lists,
  for the editors the entry names. A platform suffix is read as one
  (`anthropic.claude-code-2.1.313-darwin-arm64` is 2.1.313 for darwin-arm64);
- a folder of any version whose file the entry names has a SHA-256 the entry
  lists. A tampered build can carry the number of a real release, and Cursor's
  script says as much: "The tampered bundle keeps the real version number, so
  match on content";
- an `extensions.json` index entry whose id and version an entry lists, when
  its folder is gone, reported once per id and version;
- a workspace's `.vscode/extensions.json` recommending an id an entry lists in
  every version. A recommendation names no version, so an entry that lists
  particular versions is not reported for it.

## Where it looks

| Scan | Homes read |
|---|---|
| any `aak scan PATH` | `PATH` itself (a home directory, a dev container home), `PATH/root/`, and each `PATH/home/*/` and `PATH/Users/*/` (an unpacked image root filesystem) |
| with `--include-user-config` | also this user's own home, so `~/.cursor/extensions` and `~/.vscode/extensions` |

In each home, every dot folder with an `extensions` directory is an editor,
named by its folder: `.cursor` is `cursor`, `.vscode` is `vscode`,
`.vscode-insiders` is `vscode-insiders`, and a remote server's copy
(`.cursor-server`, `.vscode-server`) is the editor's own. A feed entry names
the editors it covers, or every editor with `*`.

## The bundled entry

| Field | Value | Source |
|---|---|---|
| `extension` | `anthropic.claude-code` | Cursor's notice |
| `versions` | `2.1.313` | Cursor's notice; Anthropic never published a 2.1.313 (npm `@anthropic-ai/claude-code`, the VS Code Marketplace and Open VSX all go from 2.1.312 to 2.1.314, read 1 Nov 2026) |
| `hosts` | `*` | no legitimate 2.1.313 exists on any marketplace, so a 2.1.313 in any editor is the tampered build |
| `sha256` | `extension.js`: `ecb58cb29078d9646ad1dcdbe51526f2d9cfea06be5fb2ab183e8ecc3ab6bf15` | Cursor's notice, the tampered `extension.js` of 2.1.312 and 2.1.313 on macOS and Windows |
| `fixed` | `2.1.314` | the next release on the VS Code Marketplace and Open VSX |

2.1.312 is a real release (Anthropic published it on 27 Oct), so it is not
listed by version: a 2.1.312 is reported only when its `extension.js` has the
digest above. The entry's note carries the persistence Cursor names, and every
finding quotes it.

## What it does not see

- A home elsewhere, such as `srv/<user>/`, an extensions folder moved by
  `--extensions-dir` or `VSCODE_EXTENSIONS`, and a portable install.
- A symlinked extension folder, and the index of a profile other than the
  default.
- An uninstalled `.vsix`, a devcontainer.json `extensions` list, and an
  editor's download cache.
- A file over 64 MiB is not hashed, and an index entry whose folder is gone is
  matched on its version alone.
- Whether the build ran or what it left behind: a finding says the build is on
  disk. Check the persistence the finding names.
- Neither OSV nor GitHub lists editor extensions, so `aak update` keeps the
  bundled entry and adds none. An index over 8 MB is not read.

## How to fix

Remove the extension, then install the publisher's fixed release from a
marketplace the advisory clears (for anthropic.claude-code, 2.1.314 or later
from the VS Code Marketplace or Open VSX). Check the machine for the
persistence the advisory names, which removing the extension does not undo: for
the Claude Code builds, a `svc-telemetry` key in `~/.ssh/authorized_keys`,
`~/.config/.smt` and `.smtk`, the LaunchAgent `com.apple.sysmond`, a crontab
`@reboot` line and the scheduled task `SysMon`. Where any is present, isolate
the machine and rotate every credential it could reach.

A finding reads:

```text
`.cursor/extensions/anthropic.claude-code-2.1.313` is an installed anthropic.claude-code
2.1.313 for cursor, and CURSOR-CLAUDE-CODE-2026-10-29 lists anthropic.claude-code 2.1.313
as malicious (https://cursor.com/blog/claude-code-extension-security-notice). Remove the
extension, update to 2.1.314 or later, and check the machine for the persistence the
advisory names; removing the extension may not remove it. Cursor's notice (read 2026-11-01)
names 2.1.312 and 2.1.313 ... An install says the build was on disk, not whether it ran.
Feed: the bundled copy generated ...
```

# Instruction-file slice: proposed verdicts (worksheet)

A reading of the 29 HIGH/CRITICAL findings in [`adjudication.json`](adjudication.json),
one row each, with a **proposed** verdict. The verdicts are the maintainer's to give:
this file sets none of them. `adjudication.json` still holds 29 null verdicts,
[`RESULTS.md`](RESULTS.md) still says the slice is pending, and no rate is stated
anywhere until every verdict is set by hand.

Proposed on 2026-10-21 against `main` at `b071a940` (0.6.23), where
`make fp-instruction-check` confirms all 29 still fire. Rows are in the order
`run.py --sheet` prints them (severity, rule id, repository, path, line), so row
N here is entry N of that sheet. The matched line is the one line the finding
points at, read from the local cache at the commit `slice.json` pins for the
repository; a long line is cut to the matched command and marked with `...`.
Nothing else from those files is committed.

Verdicts follow [`../triage.md`](../triage.md): `true_positive` when the file
really contains what the rule says, `false_positive` when AAK is wrong, and
`ambiguous` when it is defensible either way (denominator only).

## Proposals by rule

| Rule | Rows | Proposed |
|------|-----:|----------|
| `AAK-AGENT-001` | 12 | 11 true_positive, 1 ambiguous |
| `AAK-AGENT-003` | 10 | 2 true_positive, 8 ambiguous |
| `AAK-AGENT-006` | 2 | 2 true_positive |
| `AAK-IPI-WILD-CORPUS-001` | 5 | 5 false_positive |

Three patterns account for every row:

- **`AAK-AGENT-001`: an official installer piped into a shell.** bun, uv (twice,
  in home-assistant and vllm), php.new (six lines across two files) and strix.
  The rule names exactly this shape and its remediation (a package manager, or a
  downloaded file whose checksum is checked) applies, so these read as true
  positives of the rule. Whether an unpinned official installer in a setup section
  of a popular project should be CRITICAL is a rule-design question, not a
  verdict, and belongs in #945. The one `ambiguous` row (tw93/Mole) tells the
  agent to hand a `curl | bash` to a bug reporter rather than run it.
- **`AAK-AGENT-003`: every row is PowerShell's `-ExecutionPolicy Bypass`.** The
  rule text names the flag, so the matcher did what it says. Two rows (laravel)
  put the flag in the same line that downloads and runs the php.new script, and
  read as true positives. The other eight run the repository's own `.ps1` files,
  or open a `-Command` session on the project's dev VM, which is the documented
  way to run an unsigned local script on Windows; Microsoft's own
  `about_Execution_Policies` says the policy is not a security system that
  restricts user actions. Those eight are proposed `ambiguous`: if the rater decides
  the flag on a local script is not an override, the change is in the rule, not
  in a verdict.
- **`AAK-IPI-WILD-CORPUS-001`: one payload regex, no injection.** All five rows
  match `IPI-2026-04-WILD-06` ("delete repository":
  `(?i)(?:delete|wipe|rm\s+-rf|drop)\s+(?:repository|repo|database|table)`)
  on a guardrail ("NEVER DROP LOCAL DATABASES"), a migration rule, a skill table
  row, a skill routing row, and a `gh api -X DELETE repos/...` maintainer
  command. The regex has no notion of who is speaking, so a prohibition matches
  as readily as a payload. Proposed `false_positive`, one root cause.

The two `AAK-AGENT-006` rows are the rule's own examples: an unpinned installer
to download and run, and a remote document declared the authoritative source of
truth before any action.

## Rows

| # | Repository | File:line | Rule | Severity | Matched line (pinned commit) | Proposed | Why |
|--:|------------|-----------|------|----------|------------------------------|----------|-----|
| 1 | `garrytan/gbrain` | `AGENTS.md`:20 | `AAK-AGENT-001` | critical | `curl -fsSL https://bun.sh/install \| bash` | true_positive | Step 1 of the setup list tells the agent to pipe the Bun installer into bash, the shape the rule names; the remediation (a package manager, or a checked local copy) applies. |
| 2 | `home-assistant/core` | `.github/copilot-instructions.md`:157 | `AAK-AGENT-001` | critical | ``...upgrade it with `curl -LsSf https://astral.sh/uv/install.sh \| sh` and run `script/setup` again.`` | true_positive | A conditional setup step tells the agent to pipe the uv installer into sh when uv is outdated; same shape, unpinned. |
| 3 | `home-assistant/core` | `AGENTS.md`:17 | `AAK-AGENT-001` | critical | ``...upgrade it with `curl -LsSf https://astral.sh/uv/install.sh \| sh` and run `script/setup` again.`` | true_positive | Same line as #2, carried in AGENTS.md. |
| 4 | `laravel/laravel` | `AGENTS.md`:20 | `AAK-AGENT-001` | critical | `/bin/bash -c "$(curl -fsSL https://php.new/install/mac/8.5)"` | true_positive | The macOS setup block runs whatever php.new serves through bash -c $(curl ...), one of the rule's own example forms. |
| 5 | `laravel/laravel` | `AGENTS.md`:26 | `AAK-AGENT-001` | critical | `...iex ((New-Object System.Net.WebClient).DownloadString('https://php.new/install/windows/8.5'))` | true_positive | The Windows setup block downloads the php.new script and hands it to iex, one of the rule's own example forms. |
| 6 | `laravel/laravel` | `AGENTS.md`:32 | `AAK-AGENT-001` | critical | `/bin/bash -c "$(curl -fsSL https://php.new/install/linux/8.5)"` | true_positive | The Linux setup block, same form as #4. |
| 7 | `laravel/laravel` | `CLAUDE.md`:20 | `AAK-AGENT-001` | critical | `/bin/bash -c "$(curl -fsSL https://php.new/install/mac/8.5)"` | true_positive | Same line as #4, carried in CLAUDE.md. |
| 8 | `laravel/laravel` | `CLAUDE.md`:26 | `AAK-AGENT-001` | critical | `...iex ((New-Object System.Net.WebClient).DownloadString('https://php.new/install/windows/8.5'))` | true_positive | Same line as #5, carried in CLAUDE.md. |
| 9 | `laravel/laravel` | `CLAUDE.md`:32 | `AAK-AGENT-001` | critical | `/bin/bash -c "$(curl -fsSL https://php.new/install/linux/8.5)"` | true_positive | Same line as #6, carried in CLAUDE.md. |
| 10 | `tw93/Mole` | `AGENTS.md`:218 | `AAK-AGENT-001` | critical | ``...give the reporter exactly one command to paste into Terminal: `curl -fsSL 'https://mole.fit/downloads/Mole-Diagnose.command' \| bash`....`` | ambiguous | The agent is told to hand a curl | bash one-liner to a bug reporter, not to run it; the directive is real but its addressee is a human, which a one-line regex cannot tell. |
| 11 | `usestrix/strix` | `AGENTS.md`:30 | `AAK-AGENT-001` | critical | `curl -sSL https://strix.ai/install \| bash...` | true_positive | The self-hosted setup block pipes the Strix installer into bash; same shape, no version or checksum. |
| 12 | `vllm-project/vllm` | `AGENTS.md`:50 | `AAK-AGENT-001` | critical | `curl -LsSf https://astral.sh/uv/install.sh \| sh` | true_positive | The setup block tells the agent to pipe the uv installer into sh, the line of #2 without the condition. |
| 13 | `colbymchenry/codegraph` | `AGENTS.md`:208 | `AAK-AGENT-003` | high | `...powershell -NoProfile -ExecutionPolicy Bypass -Command -...` | ambiguous | The flag is on a PowerShell session the agent opens over ssh into the project's own Windows VM to pipe commands on stdin; the rule names the flag, but with -Command the policy does not gate the piped commands, and the machine is the author's. |
| 14 | `laravel/laravel` | `AGENTS.md`:26 | `AAK-AGENT-003` | high | `Set-ExecutionPolicy Bypass -Scope Process -Force...` | true_positive | Set-ExecutionPolicy Bypass clears the one check that could stop the php.new script downloaded in the same line (#5) from running what it fetches; an override in service of remote code, which is what the rule describes. |
| 15 | `laravel/laravel` | `CLAUDE.md`:26 | `AAK-AGENT-003` | high | `Set-ExecutionPolicy Bypass -Scope Process -Force...` | true_positive | Same line as #14, carried in CLAUDE.md. |
| 16 | `zhaoxuya520/reverse-skill` | `AGENTS.md`:17 | `AAK-AGENT-003` | high | `...powershell -NoProfile -ExecutionPolicy Bypass -File skills/scripts/master-route.ps1...` | ambiguous | The flag lets the repository's own unsigned master-route.ps1 run on Windows, the documented way to run a local script; the rule names the flag, but nothing here gets past a project control such as hooks, verification or auth. |
| 17 | `zhaoxuya520/reverse-skill` | `AGENTS.md`:36 | `AAK-AGENT-003` | high | `...powershell -NoProfile -ExecutionPolicy Bypass -File skills/scripts/refresh-tool-index.ps1` | ambiguous | Same flag on the repository's own refresh-tool-index.ps1; as #16. |
| 18 | `zhaoxuya520/reverse-skill` | `AGENTS.md`:47 | `AAK-AGENT-003` | high | `powershell -NoProfile -ExecutionPolicy Bypass -File skills/scripts/test-routing.ps1` | ambiguous | Same flag on the repository's own test-routing.ps1; as #16. |
| 19 | `zhaoxuya520/reverse-skill` | `AGENTS.md`:48 | `AAK-AGENT-003` | high | `powershell -NoProfile -ExecutionPolicy Bypass -File skills/scripts/verify-routing-coherence.ps1` | ambiguous | Same flag on the repository's own verify-routing-coherence.ps1; as #16. |
| 20 | `zhaoxuya520/reverse-skill` | `AGENTS.md`:49 | `AAK-AGENT-003` | high | `powershell -NoProfile -ExecutionPolicy Bypass -File skills/scripts/smoke.ps1` | ambiguous | Same flag on the repository's own smoke.ps1; as #16. |
| 21 | `zhaoxuya520/reverse-skill` | `CLAUDE.md`:27 | `AAK-AGENT-003` | high | `powershell -NoProfile -ExecutionPolicy Bypass -File skills/scripts/refresh-tool-index.ps1` | ambiguous | Same line as #17, carried in CLAUDE.md. |
| 22 | `zhaoxuya520/reverse-skill` | `CLAUDE.md`:41 | `AAK-AGENT-003` | high | `powershell -NoProfile -ExecutionPolicy Bypass -File skills/scripts/verify-routing-coherence.ps1` | ambiguous | Same line as #19, carried in CLAUDE.md. |
| 23 | `nvm-sh/nvm` | `AGENTS.md`:417 | `AAK-AGENT-006` | high | `...Download Cygwin from [cygwin.com](https://www.cygwin.com/install.html) and run the installer` | true_positive | An environment note tells the agent to download the Cygwin installer from a URL and run it, with no version or checksum: fetch, then execute what came back, which is what the rule reports. |
| 24 | `pypa/setuptools` | `AGENTS.md`:1 | `AAK-AGENT-006` | high | `...fetch and read the [skeleton](https://blog.jaraco.com/skeleton/) document in its entirety. It is the authoritative source of truth...` | true_positive | The first line makes a remote document the authoritative source of truth and forbids acting before it is read: content the repository does not hold is put in charge, the exact shape the rule describes. |
| 25 | `block/buzz` | `AGENTS.md`:507 | `AAK-IPI-WILD-CORPUS-001` | high | `gh api -X DELETE repos/block/buzz/issues/comments/<stale-comment-id>` | false_positive | A maintainer command that deletes one stale bot comment through the GitHub API; payload regex IPI-2026-04-WILD-06 (delete repository) matched 'DELETE repo' inside 'DELETE repos/', not an injected instruction. |
| 26 | `garrytan/gstack` | `AGENTS.md`:112 | `AAK-IPI-WILD-CORPUS-001` | high | `...Warn before destructive commands (rm -rf, DROP TABLE, force-push)....` | false_positive | A table row describing the /careful guardrail; the same regex matched the 'DROP TABLE' it warns about. |
| 27 | `ghostwright/phantom` | `CLAUDE.md`:292 | `AAK-IPI-WILD-CORPUS-001` | high | ``...Migrations therefore must be **additive** (no `DROP TABLE`, `DROP COLUMN`, `DROP CONSTRAINT`, `DROP INDEX`, no `RENAME`)...`` | false_positive | A migration rule listing the statements that are forbidden; the regex matched 'DROP TABLE' inside the prohibition. |
| 28 | `netalertx/NetAlertX` | `.github/copilot-instructions.md`:33 | `AAK-IPI-WILD-CORPUS-001` | high | ``\| Wipe database, fresh start \| `database-reset` \|`` | false_positive | A routing-table row sending a 'wipe database' request to the project's own reset skill; the regex matched the row label, not a payload. |
| 29 | `superplanehq/superplane` | `AGENTS.md`:171 | `AAK-IPI-WILD-CORPUS-001` | high | `` `make dev.pr.clean.checkout`, `dropdb`, or `DROP DATABASE` unless the user `` | false_positive | The line continues a NEVER guardrail naming the commands the agent must not run; the regex matched the forbidden 'DROP DATABASE'. |

## What this file is not

- Not an adjudication: no verdict in `adjudication.json` is set, `rater` and
  `run_date` stay null, and `make fp-instruction-check` still reports the slice
  as pending.
- Not a rate: none is computed here, and none may be stated on any page until
  every verdict is set by hand.
- Not third-party content: one matched line per row, nothing more, at the
  commits `slice.json` records.

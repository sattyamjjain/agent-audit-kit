# AAK-AGENT-SERVER-NOAUTH-001

**OpenHands sandbox agent server started without a session key**

| Field | Value |
|---|---|
| Severity | HIGH; MEDIUM for a Docker launch on 1.52.0 or later, or on a release AAK cannot read, and for a compose service or `docker run` |
| Category | `AGENT_CONFIG` |
| Shipped | v0.6.29 |
| Scanner | `agent_audit_kit/scanners/agent_server_noauth.py` |
| CVE | CVE-2026-112346 (OpenHands Software Agent SDK before 1.52.0, NVD 9.8) |
| OWASP Agentic | ASI03 (Identity and Privilege Abuse), ASI05 (Unexpected Code Execution) |

## What the SDK does

Read from its source, OpenHands/software-agent-sdk at v1.51.0, v1.52.0 and v1.59.0:

- `DockerWorkspace` (with its subclass `DockerDevWorkspace`) and
  `ApptainerWorkspace`, from `openhands.workspace` in the `openhands-workspace`
  distribution, start the sandbox agent server with `--host 0.0.0.0`.
- They take no key and no bind host as arguments. The server reads its key
  from the `OH_SESSION_API_KEYS_0` environment variable, else
  `SESSION_API_KEY`, and the launchers forward both through `forward_env`.
  With neither set, the server logs a warning and accepts unauthenticated
  HTTP and WebSocket requests that run shell commands in the sandbox as root
  and read its secrets.
- 1.52.0 (PR #5209) changed the Docker launcher only: its port is published
  as `127.0.0.1:{host_port}:8000` instead of `{host_port}:8000`, and its client
  now sends the forwarded key (before, it sent none). Without a key the server
  still starts keyless; from 1.52.0 only the host itself reaches it.
- `ApptainerWorkspace` is unchanged by 1.52.0. In 1.59.0 it still runs the
  server with `--host 0.0.0.0` on the host's own network, and its client sends
  `SESSION_API_KEY` only.

## What it catches

- Python source that constructs one of the launchers, imported from
  `openhands.workspace` or one of its modules (any alias), in a file that sets
  neither variable in `os.environ`, or with a literal `forward_env` that leaves
  both out, so no key can reach the server.
  - A Docker launch is HIGH when the project locks, pins exactly or has
    installed an `openhands-workspace` or `openhands-sdk` release below 1.52.0,
    and MEDIUM from 1.52.0, or when no release can be read.
  - An Apptainer launch is HIGH in every release.
- A compose service whose image is `ghcr.io/openhands/agent-server`, the SDK's
  own image, that publishes its port 8000 (or VS Code's 8001) on every
  interface (`"8000:8000"`, `"0.0.0.0:8000:8000"`, a long-syntax `target: 8000`
  without `host_ip`) and sets neither variable in its environment: MEDIUM.
- A `docker run` or `podman run` of that image in a shell script, read the same
  way from its `-p` and `-e` options: MEDIUM.

`127.0.0.1:8000:8000` or `[::1]:8000:8000` is not reported, nor is a service
or command that sets either variable.

## What it does not see

- A key set outside the Python file: the shell that runs it, a `.env` file, the
  agent-server config file. Such a launch is reported; setting the key in code
  (`os.environ.setdefault("SESSION_API_KEY", ...)`) before the launcher is
  built clears it.
- A call through another name or a factory, `**` arguments, and a
  `forward_env` that is not a literal list: not judged.
- A compose service with an `env_file`, and `docker run --env-file`: counted
  as keyed, since the file may hold the key.
- Other images, Kubernetes manifests and a port given by a variable.

## How to fix

Upgrade `openhands-workspace` to 1.52.0 or later: below it the Docker launcher
publishes the port on every interface and its client sends no key. Then set
`SESSION_API_KEY` in the environment that starts the workspace; both launchers
forward it to the server and send it with every request. For a compose service
or a `docker run`, publish the port on 127.0.0.1 and set the key in its
environment.

## Related advisories

NVIDIA's NeMo Agent Toolkit advisory published the same week (CVE-2026-65145,
"missing authentication", affected 1.0 to 1.8.0, fixed in 1.9.0 per NVIDIA's
bulletin) names no component, so this rule has no shape for it. It is covered
only by AAK-KNOWN-VULN-001's version match, once OSV publishes a record for
`nvidia-nat`; on 29 Oct 2026 it had none.

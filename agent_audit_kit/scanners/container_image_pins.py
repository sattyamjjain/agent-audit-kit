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
Chinese README names. Amazon's MCP Gateway & Registry is on neither registry
(npm's and PyPI's `mcp-gateway-registry` do not exist, and its own pyproject names
`mcp-registry` 0.1.0, which on PyPI is another project); its registry service ships
as `public.ecr.aws/p3v1o3c6/registry` and, up to 1.24.4, as Docker Hub's
`mcpgateway/registry`. Trinity's backend ships as `ghcr.io/abilityai/trinity-backend`;
PyPI's `trinity-cli` is its command-line client on its own 0.2.x line, and PyPI's
`trinity` is an unrelated Ethereum client. Nginx UI is a Go binary on neither
registry, and its README deploys the Docker Hub image `uozi/nginx-ui`. EdgeEver is
on neither registry either; its self-hosted server is `ghcr.io/tianma-if/edgeever`.
NullHub is a Zig binary shipped as release binaries and `ghcr.io/nullclaw/nullhub`,
and npm and PyPI have no `nullhub`. Conductor is a Java server whose README runs
the image `conductoross/conductor`, tagged by release. Nezha's dashboard is a Go
server whose install script runs `ghcr.io/nezhahq/nezha` or unpacks a release zip;
PyPI's `nezha` is an unrelated utility library, and npm's a 2017 0.0.1 by another
author. Apache Answer is a Go server too, whose README runs the Docker Hub image
`apache/answer`, tagged by release; npm's `answer-ui` and PyPI's `answer` are
other projects. NetBox MCP Server is on neither registry either: its README runs
`uv run netbox-mcp-server` from a checkout, or the Docker Hub image
`netboxlabs/netbox-mcp-server`, tagged by release from 1.2.0. SiYuan, a notes
app whose kernel serves MCP, ships as desktop installers and the Docker Hub image
`b3log/siyuan`, tagged `vX.Y.Z` by release; npm's `siyuan` is its plugin API
typings and PyPI's a third-party client, so the image tag is the one place a
deployment states its release. OpenHuman, an agent harness, ships as desktop
installers and the image `ghcr.io/tinyhumansai/openhuman-core`; its Rust crate
is not on crates.io, where `openhuman` is a 2023 crate of OpenHuman-ai's, and
npm's and PyPI's `openhuman` are 2023 packages of other projects as well.
The pgEdge Postgres MCP Server is a Go server on neither registry; it ships as
release binaries and `ghcr.io/pgedge/postgres-mcp`, and its two bundled MCP clients,
an agent CLI and a web client, as `ghcr.io/pgedge/nla-cli` and `ghcr.io/pgedge/nla-web`.
Trawl, a scraping engine with
an MCP endpoint, ships as `ghcr.io/germondai/trawl`; npm's and PyPI's `trawl` are
other projects. Dagu, a workflow engine with a built-in MCP server, ships as
`ghcr.io/dagucloud/dagu` and as the npm launcher `@dagucloud/dagu`, which has a
row in `mcp_cve_pins_2026_07` for the same rule. ezBookkeeping, a personal finance
app that serves MCP, is a Go server whose README runs the Docker Hub image
`mayswind/ezbookkeeping`, tagged by release. Helio, an MCP governance proxy, ships as
`ghcr.io/gethelio/helio` and as the npm package `@gethelio/proxy`, which has a row in
`mcp_cve_pins_2026_07` for the same rule. Apache APISIX, an API gateway whose
`openapi-to-mcp` plugin serves an OpenAPI document's operations as MCP tools, ships as
the Docker Hub image `apache/apisix`, tagged `X.Y.Z-debian`, `-ubuntu` and `-redhat` by
release, and as RPM and DEB packages; npm and PyPI have no `apisix`.
REBUILD, a low-code business platform whose gateway serves MCP, ships as the Docker
Hub image `getrebuild/rebuild` and as a Java archive; npm's and PyPI's `rebuild` are
other projects. GitLab, whose instance serves MCP, ships as the Docker Hub images
`gitlab/gitlab-ce` and `gitlab/gitlab-ee`, tagged `X.Y.Z-ce.0` and `X.Y.Z-ee.0`, and as
Linux packages and a Helm chart, which are not read; npm's `@zereight/mcp-gitlab` is a
third party's server for it. CVE-2026-135221 is in EE alone, so its rows name only
`gitlab/gitlab-ee`.
Flowise, whose chatflows can be served as MCP servers, ships as the Docker Hub image
`flowiseai/flowise`, tagged by release, and as the npm package `flowise`, which has a row
in `mcp_cve_pins_2026_07` for the same rule; `flowiseai/flowise-worker` runs the queue
worker and serves no API.
yt-mcp, an MCP server for YouTrack, is on neither registry (npm's `yt-mcp` is a YouTube
server of another project): it is started from its GitHub repository, which
`mcp_cve_pins_2026_07` reads, or as the Docker Hub image `velesnitski/yt-mcp`.
Tapo's MCP server is a Rust binary on no package registry and ships as
`ghcr.io/mihai-dinculescu/tapo-mcp`; PyPI's and crates.io's `tapo` are the client
library on its own version line. Two Go servers on neither npm nor PyPI ship as images
too: reza-gholizade's k8s-mcp-server as `ginnux/k8s-mcp-server` and StacklokLabs'
sqlite-mcp as `ghcr.io/stackloklabs/sqlite-mcp/server`; the packages of those names on
both registries are other projects.
DBHub, mcp-server-kubernetes and obsidian-sync-mcp (npm) and Jupyter MCP Server
(PyPI) are packages with rows here as well, for `bytebase/dbhub`,
`flux159/mcp-server-kubernetes`, `ghcr.io/es617/obsidian-sync-mcp` and
`datalayer/jupyter-mcp-server`; those rows read a version tag only.
ArcadeDB, a database whose server has an MCP module, ships as the Docker Hub images
`arcadedata/arcadedb` (JVM and `-native` builds), `arcadedata/arcadedb-headless` and
`arcadedata/arcadedb-minimal`. PyPI's `arcadedb-embedded` wheels bundle its server jars
and are not read, since no advisory names that package. SurrealDB, whose server carries
MCP, ships as the Docker Hub image `surrealdb/surrealdb`; npm's and PyPI's `surrealdb` are
client SDKs.
Pomerium, a proxy that authorizes MCP clients, ships as `pomerium/pomerium`, its Cloud
Run build `gcr.io/pomerium-io/pomerium` and, embedded, `pomerium/ingress-controller`;
npm's `pomerium` is another project. LibreChat, a chat app that connects to MCP servers,
ships as `librechat` and `librechat-api` under `ghcr.io/librechat-ai` (and, up to
v0.8.8-rc4, `ghcr.io/danny-avila`), both proxied by `registry.librechat.ai`, and under
Docker Hub's `librechat`; `@librechat/api`, where its MCP client lives, is not on npm.
Sim, an agent workflow platform that serves workflows as MCP tools, ships as
`ghcr.io/simstudioai/simstudio`, which its Helm chart names without the registry.
Sdcb Chats, an AI chat server that connects to MCP servers, ships as the Docker Hub
image `sdcb/chats`. FlowIntel, a case management platform whose chatbot is an MCP
client, ships as `ghcr.io/flowintel/flowintel`. The AutoGPT Platform ships as the
Docker Hub image `significantgravitas/autogpt`; `significantgravitas/auto-gpt` and
PyPI's `agpt` are AutoGPT Classic.
NetLicensing MCP is on PyPI
too, and like obsidian-tc it has rows in both
readers, here for `ghcr.io/labs64/netlicensing-mcp` and `labs64/netlicensing-mcp`.
n8n-mcp (npm), mcp-atlassian (PyPI) and IBM ContextForge (PyPI) have rows here as
well, for `ghcr.io/czlonkowski/n8n-mcp` (and its `-railway` build),
`ghcr.io/sooperset/mcp-atlassian` and `ghcr.io/ibm/mcp-context-forge`, which their
docs run with `docker run`; those rows read a version tag only and never report
`latest` or an untagged reference. Langchain-Chatchat's PyPI package is a
presence-only row in the pin table, and its compose file runs `chatimage/chatchat`,
mirrored at `ccr.ccs.tencentyun.com/langchain-chatchat/chatchat`, so the same rule
reads every tag of both here.
Docker Hub
images are matched by the bare name their docs use, so `docker.io/grafana/mcp-k6`
is not read. Nothing `mcp_cve_pins_2026_07` reads carries their version, and a pin
on a look-alike package name would report somebody else's project. The image tag is
the only place a deployment states which release it runs, so this module reads
image references and nothing else. That also holds for a package that ships an
image beside its npm release: obsidian-tc's npm package is a row in
`mcp_cve_pins_2026_07`, and a deployment that runs `ghcr.io/the-40-thieves/obsidian-tc`
states its release only in the tag, so each of its two rules has a row here too.

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
(`-test`, `-amd64`) is ignored, unless a pin's `suffix` asks for one (ArcadeDB's
`-native` builds, LibreChat's `-rc1` to `-rc4` of the fixed release). A two-part tag such as `2.4` floats to the newest
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

from ._helpers import compose_yaml_all, kept_dirs, make_finding, read_text_capped, strip_jsonc

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
    # A pattern the tag must contain after its version, for a flaw only one kind of tag
    # carries: ArcadeDB's native-image builds (`26.10.2-native`), or pre-releases of the
    # fixed version pushed before the fix (LibreChat's `v0.8.8-rc1`). None: any tag.
    suffix: str | None = None


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
    # heym: CVE-2026-67546 (HIGH), `POST /api/mcp/fetch-tools` starts any logged-in
    # account's stdio MCP command on the backend host. A different flaw at a higher
    # severity than the 0.0.109 row, so its own rule. The labels name each image's
    # commit: 0.0.1 (5df3bea6), the first image, already has the route and the spawn;
    # 0.0.74 (e356609b) still spawns on the host; 0.0.75 (6c6213f8) runs every stdio
    # command in a throwaway container (`mcp_stdio_sandbox.py`). GHCR has no 0.0.70,
    # 0.0.71 or 0.0.73 image. `latest` was 0.0.153 on 2026-11-12.
    _ImagePin(
        "AAK-MCP-HEYM-CVE-2026-67546-001", "heym", "ghcr.io/heymrun/heym",
        (0, 0, 75), "below 0.0.75", "Fixed in 0.0.75.", ("CVE-2026-67546",),
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
    # CVE-2026-71563: the MCP answer tool lists the answers to any question id,
    # hidden, deleted and pending-review questions included. `mcp_controller.go`
    # is absent at 1.7.1 and present from 2.0.0-RC1; the fix, 63a67542 ("fix:
    # constrain MCP content access"), is in 2.0.3 and not 2.0.2. Docker Hub tags
    # every release and release candidate, with no two-part tags, and 2.0.3-RC1 is
    # the 2.0.3 commit, 6744295f. On 2026-10-19 `latest` was a separate build of
    # that commit, labelled 2.0.3, so fixed. The pre-Apache `answerdev/answer`
    # image stops in 2023, before MCP.
    _ImagePin(
        "AAK-MCP-APACHEANSWER-CVE-2026-71563-001", "Apache Answer", "apache/answer",
        (2, 0, 3), "from 2.0.0 up to 2.0.3", "Fixed in 2.0.3.", ("CVE-2026-71563",),
        introduced=(2, 0, 0),
    ),
    # Two servers with package pins elsewhere whose docs also run a GHCR image
    # with `docker run` from an MCP config. These rows read a version tag only:
    # `floating_affected` stays False even where `latest` were affected, because
    # the State of MCP v1.1 corpus runs both images on `:latest` and a report over
    # that corpus must not move with this table. Both release workflows tag the
    # image with the package version, without a `v`, plus two-part tags and
    # `latest`; neither image is on Docker Hub.
    #
    # n8n-mcp (npm), CVE-2026-54052 below 2.56.1 and CVE-2026-55608 below 2.57.4:
    # tenant backups in HTTP multi-tenant mode. `release.yml` builds the image
    # from the commit of the npm release, so the tag is the server's version; the
    # Railway image (Dockerfile.railway) runs the same server on the same tags.
    # On 2026-10-16 `2.57` and `latest` were fixed digests (2.57.4 and later,
    # 2.94.0) and `2.56` an affected one.
    _ImagePin(
        "AAK-MCP-N8NMCP-CVE-2026-54052-001", "n8n-mcp", "ghcr.io/czlonkowski/n8n-mcp",
        (2, 57, 4), "below 2.57.4", "Fixed in 2.57.4.",
        ("CVE-2026-54052", "CVE-2026-55608"),
    ),
    _ImagePin(
        "AAK-MCP-N8NMCP-CVE-2026-54052-001", "n8n-mcp",
        "ghcr.io/czlonkowski/n8n-mcp-railway",
        (2, 57, 4), "below 2.57.4", "Fixed in 2.57.4.",
        ("CVE-2026-54052", "CVE-2026-55608"),
    ),
    # mcp-atlassian (PyPI): CVE-2026-27825 and CVE-2026-27826 below 0.17.0, the
    # `mcp_atlassian` module's pair, and CVE-2026-73498 below 0.22.0, the pin
    # table's row. `docker-publish.yml` tags each `v*.*.*` release as its version,
    # and the image installs that checkout. GHCR carries 0.8.0 to 0.23.1; `latest`
    # was the 0.23.1 digest on 2026-10-16.
    _ImagePin(
        "AAK-MCP-ATLASSIAN-CVE-2026-27825-001", "mcp-atlassian",
        "ghcr.io/sooperset/mcp-atlassian",
        (0, 17, 0), "below 0.17.0", "Fixed in 0.17.0.", ("CVE-2026-27825",),
    ),
    _ImagePin(
        "AAK-MCP-ATLASSIAN-CVE-2026-27826-001", "mcp-atlassian",
        "ghcr.io/sooperset/mcp-atlassian",
        (0, 17, 0), "below 0.17.0", "Fixed in 0.17.0.", ("CVE-2026-27826",),
    ),
    _ImagePin(
        "AAK-MCP-ATLASSIAN-CVE-2026-73498-001", "mcp-atlassian",
        "ghcr.io/sooperset/mcp-atlassian",
        (0, 22, 0), "below 0.22.0", "Fixed in 0.22.0.", ("CVE-2026-73498",),
    ),
    # IBM ContextForge MCP Gateway (PyPI `mcp-contextforge-gateway`): the pin
    # table's row for the same rule reads the package below 1.0.9. Its README and
    # Helm chart run `ghcr.io/ibm/mcp-context-forge`, which the release workflow
    # tags with the release tag (`v1.0.5`; the 0.x releases also without the `v`)
    # and `latest`. The image labels name the release commit: v1.0.5 is af178ee1,
    # v1.0.6 d24df05e. The 1.0.0 betas and release candidates read as 1.0.0 and
    # `v1.0.7-20260921`, a patch on the 1.0.7 support line, as 1.0.7, all below
    # the floor, as the PyPI row reads 1.0.7.post20260921. On 2026-10-20 `latest`
    # was the v1.0.11 digest, fixed, and the chart's default `tag: latest` is not
    # a release.
    _ImagePin(
        "AAK-MCP-CONTEXTFORGE-CVE-2026-77822-001", "IBM ContextForge MCP Gateway",
        "ghcr.io/ibm/mcp-context-forge",
        (1, 0, 9), "below 1.0.9", "Fixed in 1.0.9.",
        ("CVE-2026-77822", "CVE-2026-18905", "CVE-2026-18486", "CVE-2026-18489",
         "CVE-2026-53710", "CVE-2026-78573", "CVE-2026-53709", "CVE-2026-53711",
         "CVE-2026-8355"),
    ),
    # CVE-2026-18484 (MEDIUM): a federated tool whose computed name collides with an
    # existing tool's makes `tools/call` fail for everyone, fixed in 1.1.0 (#6534). The
    # pin table's row reads the package from 0.7.0, where tool names became unique per
    # team and owner only; the image carries 0.7.0 and v0.7.0 tags. On 2026-11-11
    # `latest` was the v1.1.1 digest, fixed. Five MEDIUM records fixed in 1.1.0 joined
    # the rule on 2026-11-14, so the row names them too and its range does not move.
    _ImagePin(
        "AAK-MCP-CONTEXTFORGE-CVE-2026-18484-001", "IBM ContextForge MCP Gateway",
        "ghcr.io/ibm/mcp-context-forge",
        (1, 1, 0), "from 0.7.0 up to 1.1.0", "Fixed in 1.1.0.",
        ("CVE-2026-18484", "CVE-2026-110178", "CVE-2026-110194", "CVE-2026-110195",
         "CVE-2026-110199", "CVE-2026-94407"),
        introduced=(0, 7, 0),
    ),
    # CVE-2026-110279 and CVE-2026-110278 (HIGH) and CVE-2026-110189 (MEDIUM), fixed
    # only in 1.1.1: the pin table's row reads the package from 0.8.0, where the
    # `X-Upstream-Authorization` rename arrives; the image carries 0.8.0 and v0.8.0
    # tags (one digest). On 2026-11-14 `latest` was the v1.1.1 digest, whose label
    # names the v1.1.1 tag's commit (dbc643be), fixed.
    _ImagePin(
        "AAK-MCP-CONTEXTFORGE-CVE-2026-110279-001", "IBM ContextForge MCP Gateway",
        "ghcr.io/ibm/mcp-context-forge",
        (1, 1, 1), "from 0.8.0 up to 1.1.1", "Fixed in 1.1.1.",
        ("CVE-2026-110279", "CVE-2026-110278", "CVE-2026-110189"),
        introduced=(0, 8, 0),
    ),
    # Amazon's MCP Gateway & Registry (agentic-community/mcp-gateway-registry) runs
    # its registry API, and the nginx that proxies MCP traffic, in the `registry`
    # image. Its compose file pulled `mcpgateway/registry` from Docker Hub through
    # 1.25.0 and `public.ecr.aws/p3v1o3c6/registry` from 1.26.0. The labels name each
    # image's commit, the git tag's for ECR Public's 1.0.13, 1.24.7, 1.25.0, 1.34.0
    # and 1.35.0. Docker Hub's tags run v1.0.0 to 1.24.4 and stopped on 2026-06-04,
    # so it has no fixed tag for either flaw and its `latest` is the 1.24.4 build
    # (9fd96af3, three commits short of the tag, with the same import handler).
    # ECR Public's run 1.0.13 to 1.37.0, and its `latest` and `1` were the 1.37.0
    # digest on 2026-11-12; Docker Hub's `1` and `1.0` are v1.0.12's.
    #
    # CVE-2026-100307: `POST /api/servers/groups/import` arrived in v1.0.9 (absent in
    # v1.0.8) with no admin check, and 1.25.0 calls `_require_admin` first (#1333).
    _ImagePin(
        "AAK-MCP-GATEWAY-REGISTRY-CVE-2026-100307-001", "Amazon mcp-gateway-registry",
        "public.ecr.aws/p3v1o3c6/registry",
        (1, 25, 0), "from 1.0.9 below 1.25.0", "Fixed in 1.25.0.",
        ("CVE-2026-100307",), introduced=(1, 0, 9),
    ),
    _ImagePin(
        "AAK-MCP-GATEWAY-REGISTRY-CVE-2026-100307-001", "Amazon mcp-gateway-registry",
        "mcpgateway/registry",
        (1, 25, 0), "from 1.0.9 below 1.25.0",
        "Fixed in 1.25.0, published only as public.ecr.aws/p3v1o3c6/registry.",
        ("CVE-2026-100307",), floating_affected=True, introduced=(1, 0, 9),
    ),
    # CVE-2026-125926: no release up to 1.25.0 checks a registered server's address;
    # 1.26.0 refuses a literal private or metadata address at registration and update
    # but resolves no host name (`validate_proxy_pass_url`, `resolve=False`), the same
    # through 1.35.0. The 1.35.0 change on this path is #1795: a virtual server stops
    # routing to a backend that is disabled or not healthy, so one the health check's
    # address guard refused is no longer reachable through it. The advisory names no
    # fix, so its 1.35.0 is the floor. It starts the range at v1.0.3, the first git
    # tag; Docker Hub's v1.0.0 to v1.0.2 builds predate it and are not claimed.
    _ImagePin(
        "AAK-MCP-GATEWAY-REGISTRY-CVE-2026-125926-001", "Amazon mcp-gateway-registry",
        "public.ecr.aws/p3v1o3c6/registry",
        (1, 35, 0), "from 1.0.3 below 1.35.0", "Fixed in 1.35.0.",
        ("CVE-2026-125926",), introduced=(1, 0, 3),
    ),
    _ImagePin(
        "AAK-MCP-GATEWAY-REGISTRY-CVE-2026-125926-001", "Amazon mcp-gateway-registry",
        "mcpgateway/registry",
        (1, 35, 0), "from 1.0.3 below 1.35.0",
        "Fixed in 1.35.0, published only as public.ecr.aws/p3v1o3c6/registry.",
        ("CVE-2026-125926",), floating_affected=True, introduced=(1, 0, 3),
    ),
    # CVE-2026-75128: Langchain-Chatchat's API runs any registered tool, the
    # always-registered `shell` tool included, for an unauthenticated caller on
    # 0.0.0.0:7861. The pin table's presence-only row reads the PyPI package. The
    # docker build workflow clones `master`, tags `<version>-<commit>-<date>` and
    # pushes to Docker Hub and the Tencent mirror, and the image runs as root.
    # Docker Hub carries 0.3.0-0622 to 0.3.1.3-717e03e-20241109 and the Tencent
    # mirror 0.3.1-4e03ec6-20240726 to the same, both with
    # 0.3.2-dev-d15fcd4-20241014. tool_routes.py serves the route from the 0.3.0
    # wheel to `master` today, so every image built in between has it, and no
    # release fixes it. A tag reads as its first three numbers: the release
    # builds as 0.3.0 or 0.3.1 (0.3.1.3-717e03e-20241109 is 0.3.1), and the dev
    # build as 0.3.2. So the floor is 0.3.3, the first number past the dev tag,
    # and every tag on either registry reads affected. Neither registry has a
    # `latest` tag, so `floating_affected` stays False.
    _ImagePin(
        "AAK-CHATCHAT-CVE-2026-75128-001", "Langchain-Chatchat", "chatimage/chatchat",
        (0, 3, 3), "on every tag through 0.3.2-dev", "No fixed release.",
        ("CVE-2026-75128",),
    ),
    _ImagePin(
        "AAK-CHATCHAT-CVE-2026-75128-001", "Langchain-Chatchat",
        "ccr.ccs.tencentyun.com/langchain-chatchat/chatchat",
        (0, 3, 3), "on every tag through 0.3.2-dev", "No fixed release.",
        ("CVE-2026-75128",),
    ),
    # CVE-2026-115477 and CVE-2026-115478, both fixed in 1.31.4 (#1084, #1085): the
    # image twin of the pin table's second obsidian-tc row. GHCR's tags start at
    # 1.0.1, so no `introduced` is needed, and `latest` (1.33.1 on 2026-10-15) is
    # fixed.
    _ImagePin(
        "AAK-MCP-OBSIDIANTC-CVE-2026-115477-001", "obsidian-tc",
        "ghcr.io/the-40-thieves/obsidian-tc",
        (1, 31, 4), "below 1.31.4", "Fixed in 1.31.4.",
        ("CVE-2026-115477", "CVE-2026-115478"),
    ),
    # CVE-2026-57207 (#1086): before 1.2.1 the NetBox MCP Server's HTTP transport had
    # no authentication. 1.2.1 (17df4653) adds a bearer token, `MCP_AUTH_TOKEN`, and
    # leaves it unset by default. Docker Hub carries 1.2.0 and 1.2.1, the floating
    # `1`, `1.2` and `latest` (all the 1.2.1 digest on 2026-10-24), `main` and a
    # `0.0.0-test` tag; no release before 1.2.0 was pushed as an image.
    _ImagePin(
        "AAK-MCP-NETBOX-CVE-2026-57207-001", "NetBox MCP Server",
        "netboxlabs/netbox-mcp-server",
        (1, 2, 1), "below 1.2.1",
        "Fixed in 1.2.1, which adds an optional bearer token: set MCP_AUTH_TOKEN.",
        ("CVE-2026-57207",),
    ),
    # CVE-2026-116168 (#1096): the MCP asset tool's `upload` copies a local file into
    # the workspace, where `/assets/` serves it back. It arrived in v3.7.0-rc.1
    # (`kernel/mcp/tools/asset.go` is absent through v3.6.5); v3.8.1 added a
    # sensitive-path blacklist that leaves out `.env`, and 9ffcc734 adds it, in
    # v3.8.7 and not v3.8.6. Docker Hub tags releases `vX.Y.Z`; every pre-release tag
    # that reads as 3.8.7 or later was pushed after the fix (the first,
    # v3.8.8-alpha.4, on 2026-10-17), and `latest` was the v3.8.8 digest on
    # 2026-10-26.
    _ImagePin(
        "AAK-MCP-SIYUAN-CVE-2026-116168-001", "SiYuan", "b3log/siyuan",
        (3, 8, 7), "from 3.7.0 below 3.8.7", "Fixed in 3.8.7.",
        ("CVE-2026-116168",), introduced=(3, 7, 0),
    ),
    # CVE-2026-54140 (#1219): OpenHuman's MCP client put the names, descriptions and
    # parameter definitions a configured server returned into the model's context
    # unchecked. The image is the core server; its labels name the commit of each
    # tag. `src/openhuman/mcp_client/` is absent at v0.53.43 (2b64ea8a) and present
    # at v0.54.0 (c25fc8e5), with McpRemoteTool and a tool that hands the model
    # each tool's description. The fix, 00b8a669 (sanitize.rs, `apply_safety_filter`),
    # is not in v0.57.11 (8476248e) and is in v0.57.12 (c903227e), so the range ends
    # there, one release below the advisory's 0.57.13: no git tag or GitHub release
    # names 0.57.12, but the image does. GHCR tags each release as `vX.Y.Z` and
    # `X.Y.Z`, and `latest` was the v0.64.15 digest on 2026-11-11.
    _ImagePin(
        "AAK-MCP-OPENHUMAN-CVE-2026-54140-001", "OpenHuman",
        "ghcr.io/tinyhumansai/openhuman-core",
        (0, 57, 12), "from 0.54.0 below 0.57.12",
        "Fixed in the 0.57.12 image; the advisory names 0.57.13.",
        ("CVE-2026-54140",), introduced=(0, 54, 0),
    ),
    # CVE-2026-77604 (< 0.0.345) and CVE-2026-87008 (0.0.421 to 0.0.588): the GHCR
    # image of Code Graph RAG runs `code-graph-rag mcp-server` by default and labels
    # each tag with its commit. GHCR carries 0.0.88, 0.0.99 and 0.0.100, built from
    # source with the MCP server the matching PyPI wheels lack, and their
    # `read_file` joins the path unchecked; then 0.0.496, 0.0.534 and 0.0.584, whose
    # should_skip_path compares unresolved paths; 0.0.639 resolves first. No tag sits
    # between 0.0.100 and 0.0.496. `latest` was 0.6.30 and the floating `0.0` was
    # 0.0.996 on 2026-11-11. One row per CVE, each the image twin of its pin-table
    # row; the ranges are disjoint, so a tag falls in at most one.
    _ImagePin(
        "AAK-MCP-CODEGRAPHRAG-CVE-2026-77604-001", "Code Graph RAG",
        "ghcr.io/vitali87/code-graph-rag",
        (0, 0, 345), "below 0.0.345",
        "Fixed in 0.0.345, but 0.0.421 to 0.0.584 carry CVE-2026-87008: run 0.0.589 or "
        "later.",
        ("CVE-2026-77604",),
    ),
    _ImagePin(
        "AAK-MCP-CODEGRAPHRAG-CVE-2026-87008-001", "Code Graph RAG",
        "ghcr.io/vitali87/code-graph-rag",
        (0, 0, 589), "from 0.0.421 below 0.0.589", "Fixed in 0.0.589.",
        ("CVE-2026-87008",), introduced=(0, 0, 421),
    ),
    # --- 2026-11-11 wave (apps) ---
    # pgEdge Postgres MCP Server: CVE-2026-125320 (no Origin check on the HTTP
    # transport), CVE-2026-125321 (login rate limiting keyed on X-Forwarded-For) and
    # CVE-2026-125322 (`count_rows` `where` subqueries as an oracle), all fixed in
    # 1.1.0. The labels name each image's commit: 1.0.0-beta2 (6830caeb, the first
    # image) and 1.0.0 (67121476) have all three flaws; 1.1.0-beta1 (b971c413) carries
    # all three fixes (6a19e46a, 933f1b4c, 5571bd49), as rc1 and 1.1.0 (25c2aaed) do.
    # 1.0.0-test1 (cc13a18a, June) predates the fixes and reads as 1.0.0. `1.0` is the
    # 1.0.0 digest; `latest` was the 1.1.0 digest on 2026-11-11 and 2026-11-14.
    # CVE-2026-126196 (GHSA-j7mp-839j-jrm7, read-only bypass through `tx.Exec`) and
    # CVE-2026-126197 (GHSA-r5pp-jx86-r6r9, pl-do dollar-quote injection), HIGH, are
    # fixed in 1.1.0-beta1 too and make the rule HIGH; 1.0.0-beta2 has neither route but
    # reads as 1.0.0. Their CVE ids were published on 2026-11-12, after this row shipped
    # under the GHSA ids, and join it with no range change.
    _ImagePin(
        "AAK-MCP-PGEDGE-CVE-2026-125320-001", "pgEdge Postgres MCP Server",
        "ghcr.io/pgedge/postgres-mcp",
        (1, 1, 0), "below 1.1.0",
        "Fixed in 1.1.0, as are CVE-2026-126196 (GHSA-j7mp-839j-jrm7, read-only bypass) and "
        "CVE-2026-126197 (GHSA-r5pp-jx86-r6r9, SQL injection through pl-do tools).",
        ("CVE-2026-125320", "CVE-2026-125321", "CVE-2026-125322"),
    ),
    # --- 2026-11-14 batch (pgedge) ---
    # pgEdge's two bundled MCP clients: CVE-2026-126199 (the write-confirmation prompt
    # classified a `query_database` statement by its first keyword, so `SELECT ... INTO`,
    # a data-modifying CTE and `EXPLAIN ANALYZE` of a write ran unasked) and
    # CVE-2026-126198 (only `query_database` was ever prompted for, so writing custom
    # tools ran unasked), both fixed in 1.1.0, one rule at the higher record's MEDIUM.
    # The images are built from the same commits as the server's, and their labels name
    # them: the prompt is absent at 1.0.0-beta3a (f1bb9986) and earlier and first ships in
    # 1.0.0 (67121476); 1.0.0-test1 (cc13a18a, June) predates both fixes; 1.1.0-beta1
    # (b971c413) carries both (c86d5cbe, 310c0280). Every tag from 1.0.0-alpha3, the
    # first, reads as 1.0.0. `1.0` is the 1.0.0 digest; `latest` and `1.1` were the
    # 1.1.0 digest of both images on 2026-11-14.
    _ImagePin(
        "AAK-MCP-PGEDGE-CVE-2026-126199-001", "pgEdge NLA CLI client",
        "ghcr.io/pgedge/nla-cli",
        (1, 1, 0), "below 1.1.0", "Fixed in 1.1.0.",
        ("CVE-2026-126199", "CVE-2026-126198"),
    ),
    _ImagePin(
        "AAK-MCP-PGEDGE-CVE-2026-126199-001", "pgEdge NLA web client",
        "ghcr.io/pgedge/nla-web",
        (1, 1, 0), "below 1.1.0", "Fixed in 1.1.0.",
        ("CVE-2026-126199", "CVE-2026-126198"),
    ),
    # pgEdge server: GHSA-jf8q-vh2f-mhq4 (no CVE id), a `plperl` or `plperlu` pl-do tool
    # embeds its JSON arguments in the Perl through Go's `%q`, a double-quoted literal in
    # which Perl interpolates `$` and `@`. The tools first ship in 1.0.0-beta3; 1.0.0
    # (67121476) and 1.1.0 (25c2aaed) still use `%q`; 80d4c02c (`perlSingleQuote`) is in
    # 1.2.0-beta1 (d3030c38) and in no other tag. The advisory names 1.1.1, which has no
    # tag, release or image on 2026-11-14, so the floor is 1.2.0: 1.2.0-beta1 folds into
    # 1.2.0 and is not reported. `latest` and `1.1` were the 1.1.0 digest on 2026-11-14,
    # so `latest` is affected. A different flaw above the 1.1.0 rule's floor, so its own
    # rule.
    _ImagePin(
        "AAK-MCP-PGEDGE-PLPERL-001", "pgEdge Postgres MCP Server",
        "ghcr.io/pgedge/postgres-mcp",
        (1, 2, 0), "below 1.2.0",
        "Fixed only in the 1.2.0-beta1 pre-release; the advisory names 1.1.1, which was not "
        "published, and `latest` is the 1.1.0 image.",
        ("GHSA-jf8q-vh2f-mhq4",), floating_affected=True,
    ),
    # Dagu: CVE-2026-102943, the MCP `dagu_read` dag_spec target reads YAML files
    # outside the DAG directories. `internal/service/mcp/server.go` is absent at
    # v2.6.10 and ships in v2.7.0; v2.11.0 confines `locateDAG`. The images carry no
    # revision label, but each was pushed with its release (2.7.0 on 2026-05-18, 2.11.0
    # on 2026-07-26); `-alpine` and `-dev` builds share the version, and `latest` was
    # the 2.26.0 build on 2026-11-11. The npm launcher is the pin table's row.
    _ImagePin(
        "AAK-MCP-DAGU-CVE-2026-102943-001", "Dagu", "ghcr.io/dagucloud/dagu",
        (2, 11, 0), "from 2.7.0 below 2.11.0", "Fixed in 2.11.0.",
        ("CVE-2026-102943",), introduced=(2, 7, 0),
    ),
    # Trawl: CVE-2026-122140, IPv4-mapped IPv6 addresses in hex form pass the MCP
    # outbound URL policy, and GHSA-7qmf-c45g-5p4q (no CVE id), a name that rebinds
    # between the policy's DNS lookup and the fetch's, on the same releases. The labels name each image's commit: 1.4.2 (7189f101) has
    # no MCP routes and no `outbound-policy.ts`; 1.5.0 (c81d628b) adds both, and the
    # file is unchanged at 1.9.3 (4f3a7cf9); 1.10.0 (fc3f64a7) classifies addresses
    # with `BlockList`. `-baseline` and `-fonts` builds share the version. `latest` was
    # the 1.11.0 digest on 2026-11-11; `latest-fonts` is still the 1.6.0 image and
    # states no version.
    _ImagePin(
        "AAK-MCP-TRAWL-CVE-2026-122140-001", "Trawl", "ghcr.io/germondai/trawl",
        (1, 10, 0), "from 1.5.0 below 1.10.0",
        "Fixed in 1.10.0, as is GHSA-7qmf-c45g-5p4q (DNS rebinding past the same policy).",
        ("CVE-2026-122140",), introduced=(1, 5, 0),
    ),
    # SiYuan: CVE-2026-123492, a `resources/read` of a missing resource panics the
    # kernel in `privateCacheMiddleware`. The middleware is absent at v3.7.3 and
    # arrives in v3.8.0; the fix, a8b6dd77 (2026-10-22), is in v3.8.9 and not v3.8.8.
    # v3.8.9-alpha.1 to alpha.3 were pushed before it and read as 3.8.9, so they go
    # unreported; `latest` was the v3.8.10 digest on 2026-11-11. A different flaw from
    # the 116168 row above, so its own rule.
    _ImagePin(
        "AAK-MCP-SIYUAN-CVE-2026-123492-001", "SiYuan", "b3log/siyuan",
        (3, 8, 9), "from 3.8.0 below 3.8.9", "Fixed in 3.8.9.",
        ("CVE-2026-123492",), introduced=(3, 8, 0),
    ),
    # ezBookkeeping: CVE-2026-86041, Gin trusts every proxy, so a spoofed
    # X-Forwarded-For passes `mcp_allowed_remote_ips`. The labels name each image's
    # commit: 0.9.0 (6222b6ed) has no MCP IP limit; 0.10.0 (06ef2220, OSV's
    # `introduced`) adds `mcp_server_ip_limit.go` matching `c.ClientIP()`; 1.5.1
    # (6fa9816c) still sets no trusted proxies; 1.6.0 (e5c12d37) carries d79a5beb.
    # Docker Hub keeps two-part tags (`0.10`, `1.5`) on the newest patch of each line.
    # `latest` was the 2.1.1 digest on 2026-11-11; `SNAPSHOT-<date>` tags state no
    # version.
    _ImagePin(
        "AAK-MCP-EZBOOKKEEPING-CVE-2026-86041-001", "ezBookkeeping", "mayswind/ezbookkeeping",
        (1, 6, 0), "from 0.10.0 below 1.6.0", "Fixed in 1.6.0.",
        ("CVE-2026-86041",), introduced=(0, 10, 0),
    ),
    # --- 2026-11-12 wave (misc) ---
    # Helio: CVE-2026-65957, the dashboard sideband's CORS check matched a private-network
    # prefix on the hostname, so `192.168.attacker.com` passed. The labels name each
    # image's commit: 0.1.0 (fa50419b) and 0.7.0 (0c5bbcfa) carry the prefix test in
    # packages/proxy/src/dashboard/api.ts; 0.8.0 (6f9d147a) carries 4ca8329c, which
    # validates a private IPv4 literal. The two-part tags `0.1` to `0.7` sit on affected
    # lines; `latest` and `0` were the 0.16.0 digest on 2026-11-12. The npm package is
    # the pin table's row.
    _ImagePin(
        "AAK-MCP-HELIO-CVE-2026-65957-001", "Helio", "ghcr.io/gethelio/helio",
        (0, 8, 0), "below 0.8.0", "Fixed in 0.8.0.",
        ("CVE-2026-65957",),
    ),
    # --- 2026-11-14 wave (misc) ---
    # SiYuan: CVE-2026-126393, the MCP `skill` tool's `install` action downloads a skill
    # with a client that follows redirects and resolves the host again at connect time,
    # after a parse-time hostname check, so a redirect or a rebinding name reaches
    # loopback and metadata addresses. `kernel/mcp/tools/skill.go` (with `install`) and
    # `kernel/util/skill.go` (`fetchBytes` on `httpclient.NewBrowserRequest()`) arrive in
    # v3.7.0-rc.1 (`kernel/mcp` is absent through v3.6.5) and are unchanged in that
    # respect through v3.8.9; 3e1b977e (2026-10-29) moves the download onto
    # `ssrfSafeClient` with a redirect check, in v3.8.10-alpha.1 and later and not v3.8.9.
    # Every v3.8.10 pre-release tag was pushed after the fix; `latest` was the v3.8.10
    # digest on 2026-11-14. A different flaw from the two SiYuan rows above.
    _ImagePin(
        "AAK-MCP-SIYUAN-CVE-2026-126393-001", "SiYuan", "b3log/siyuan",
        (3, 8, 10), "from 3.7.0 below 3.8.10", "Fixed in 3.8.10.",
        ("CVE-2026-126393",), introduced=(3, 7, 0),
    ),
    # Apache APISIX: CVE-2026-124726, the `openapi-to-mcp` plugin fills an OpenAPI path
    # template with the caller's path parameters, and a value of `..` (which
    # `ngx.escape_uri` leaves alone) or a separator the upstream decodes moves the request
    # to a path the document never declared, sent with the Route's own credentials.
    # The plugin is absent at 3.18.0 and ships in 3.19.0; 77055643 (#14154, 2026-11-06)
    # confines each value to one path segment, in 3.20.0 and not 3.19.0. Docker Hub tags
    # releases `X.Y.Z-debian`, `-ubuntu` and `-redhat`, with no two-part tags; the
    # handler in the 3.19.0-debian image is byte-identical to the 3.19.0 tag's, and the
    # 3.20.0-debian image's to the 3.20.0 tag's. `latest` was the 3.20.0-ubuntu build on
    # 2026-11-14.
    _ImagePin(
        "AAK-MCP-APISIX-CVE-2026-124726-001", "Apache APISIX", "apache/apisix",
        (3, 20, 0), "from 3.19.0 below 3.20.0", "Fixed in 3.20.0.",
        ("CVE-2026-124726",), introduced=(3, 19, 0),
    ),
    # REBUILD: CVE-2026-129875, the MCP QueryRecords tool filters on `User.password`
    # and answers with a row count, an oracle for the hash. NVD says 4.5.0 through
    # 4.5.4, the newest release when it was reported. QueryRecords.java is absent at
    # 4.4.11 and one blob from 4.5.0 to 4.5.5; AdvFilterParser.java is one blob from
    # 4.5.3 to 4.5.5, and the 4.5.6 commit (1c2a986d, 2026-11-25) changes only how it
    # parses dates. So no fixed release, and the floor is the number past 4.5.6, which
    # had no image on 2026-11-25. `latest` was the 4.5.5 digest.
    _ImagePin(
        "AAK-MCP-REBUILD-CVE-2026-129875-001", "REBUILD", "getrebuild/rebuild",
        (4, 5, 7), "from 4.5.0, the newest release included", "No fixed release yet.",
        ("CVE-2026-129875",), floating_affected=True, introduced=(4, 5, 0),
    ),
    # GitLab: CVE-2026-123142, an authorization check in the instance's MCP server let a
    # user holding an MCP-scoped OAuth token change the state of issues and merge
    # requests, approving and merging included. The ranges are GitLab's CNA record's and
    # its 19.5.6 patch release's (which names the MCP server); they were not read in the
    # source. One row per fixed line and image, since the three lines are disjoint. On
    # 2026-11-25 `latest` was the 19.6.2 digest on both images, fixed.
    _ImagePin(
        "AAK-MCP-GITLAB-CVE-2026-123142-001", "GitLab CE", "gitlab/gitlab-ce",
        (19, 3, 9), "from 18.4 below 19.3.9", "Fixed in 19.3.9, 19.4.8 and 19.5.6.",
        ("CVE-2026-123142",), introduced=(18, 4, 0),
    ),
    _ImagePin(
        "AAK-MCP-GITLAB-CVE-2026-123142-001", "GitLab CE", "gitlab/gitlab-ce",
        (19, 4, 8), "from 19.4 below 19.4.8", "Fixed in 19.3.9, 19.4.8 and 19.5.6.",
        ("CVE-2026-123142",), introduced=(19, 4, 0),
    ),
    _ImagePin(
        "AAK-MCP-GITLAB-CVE-2026-123142-001", "GitLab CE", "gitlab/gitlab-ce",
        (19, 5, 6), "from 19.5 below 19.5.6", "Fixed in 19.3.9, 19.4.8 and 19.5.6.",
        ("CVE-2026-123142",), introduced=(19, 5, 0),
    ),
    _ImagePin(
        "AAK-MCP-GITLAB-CVE-2026-123142-001", "GitLab EE", "gitlab/gitlab-ee",
        (19, 3, 9), "from 18.4 below 19.3.9", "Fixed in 19.3.9, 19.4.8 and 19.5.6.",
        ("CVE-2026-123142",), introduced=(18, 4, 0),
    ),
    _ImagePin(
        "AAK-MCP-GITLAB-CVE-2026-123142-001", "GitLab EE", "gitlab/gitlab-ee",
        (19, 4, 8), "from 19.4 below 19.4.8", "Fixed in 19.3.9, 19.4.8 and 19.5.6.",
        ("CVE-2026-123142",), introduced=(19, 4, 0),
    ),
    _ImagePin(
        "AAK-MCP-GITLAB-CVE-2026-123142-001", "GitLab EE", "gitlab/gitlab-ee",
        (19, 5, 6), "from 19.5 below 19.5.6", "Fixed in 19.3.9, 19.4.8 and 19.5.6.",
        ("CVE-2026-123142",), introduced=(19, 5, 0),
    ),
    # GitLab EE: CVE-2026-135221, the MCP server's OAuth handling validated a URL too
    # loosely, so an authenticated user could have the instance request internal addresses.
    # GitLab's 19.6.2 patch release and its CNA record name EE only, from 18.10 before
    # 19.4.11, 19.5 before 19.5.9 and 19.6 before 19.6.2; not read in the source. The same
    # release's 19.3.10, 19.2.11, 19.1.11, 19.0.12 and 18.11.15 sit inside the first range
    # as GitLab states it, so they are reported. Docker Hub had every fixed tag on
    # 2026-11-25 and no 19.4.9; `latest` was the 19.6.2 digest, fixed.
    _ImagePin(
        "AAK-MCP-GITLAB-CVE-2026-135221-001", "GitLab EE", "gitlab/gitlab-ee",
        (19, 4, 11), "from 18.10 below 19.4.11", "Fixed in 19.4.11, 19.5.9 and 19.6.2.",
        ("CVE-2026-135221",), introduced=(18, 10, 0),
    ),
    _ImagePin(
        "AAK-MCP-GITLAB-CVE-2026-135221-001", "GitLab EE", "gitlab/gitlab-ee",
        (19, 5, 9), "from 19.5 below 19.5.9", "Fixed in 19.4.11, 19.5.9 and 19.6.2.",
        ("CVE-2026-135221",), introduced=(19, 5, 0),
    ),
    _ImagePin(
        "AAK-MCP-GITLAB-CVE-2026-135221-001", "GitLab EE", "gitlab/gitlab-ee",
        (19, 6, 2), "from 19.6 below 19.6.2", "Fixed in 19.4.11, 19.5.9 and 19.6.2.",
        ("CVE-2026-135221",), introduced=(19, 6, 0),
    ),
    # Flowise: CVE-2026-130796, the public chatflow route answers with the chatflow's MCP
    # server token. The MCP server arrives in 3.1.3 (read in the npm tarballs, which the
    # image installs with `npm install -g flowise`), and 3.1.4 is the last release, so the
    # floor is the number after it. `latest` was built on 2026-07-29 at 16:24 UTC, six hours
    # after npm had 3.1.4, and the 3.1.4 tag sixteen minutes later.
    _ImagePin(
        "AAK-MCP-FLOWISE-CVE-2026-130796-001", "Flowise", "flowiseai/flowise",
        (3, 1, 5), "from 3.1.3, the last release included",
        "No fixed release; FlowiseAI ended the project on 2026-08-31.",
        ("CVE-2026-130796",), floating_affected=True, introduced=(3, 1, 3),
    ),
    # yt-mcp: CVE-2026-75612. Docker Hub has two tags, `1.7.0` and `latest`, both pushed on
    # 2026-04-10, and the yt_mcp package in each is 1.7.0. That release has the record's
    # second flaw, `get_project_health` writing a snapshot outside its directory, and not
    # the first, `add_attachment`, which arrived in 1.16.0. The fix, v1.18.1, has no image.
    _ImagePin(
        "AAK-MCP-YTMCP-CVE-2026-75612-001", "yt-mcp", "velesnitski/yt-mcp",
        (1, 18, 1), "below 1.18.1", "Fixed in v1.18.1, which has no image on Docker Hub.",
        ("CVE-2026-75612",), floating_affected=True,
    ),
    # --- 2026-11-26 batch (servers) ---
    # Tapo MCP server: `new_service` calls disable_allowed_hosts() at tapo-mcp-v0.3.1 and
    # v0.4.0 and nowhere else read (absent at v0.3.0, where rmcp's loopback list applies,
    # and from v0.5.0, which takes a configured list and refuses to start in the container
    # with no key), so a rebinding page calls the tools when no TAPO_MCP_API_KEY is set
    # (CVE-2026-77329). `0.3` and `0.4` were the 0.3.1 and 0.4.0 digests on 2026-11-26, and
    # `latest` the 0.7.0 one, fixed.
    _ImagePin(
        "AAK-MCP-TAPO-CVE-2026-77329-001", "Tapo MCP server", "ghcr.io/mihai-dinculescu/tapo-mcp",
        (0, 5, 0), "from 0.3.1 below 0.5.0", "Fixed in 0.5.0, or set TAPO_MCP_API_KEY.",
        ("CVE-2026-77329",), introduced=(0, 3, 1),
    ),
    # mcp-server-kubernetes's image, for the npm row of the same rule: tagged `vX.Y.Z` (and
    # `X.Y.Z` up to 2.4.3) by release. No v4.1.10 image; `latest` was the v4.2.3 digest.
    _ImagePin(
        "AAK-MCP-K8S-CVE-2026-134817-001", "mcp-server-kubernetes", "flux159/mcp-server-kubernetes",
        (4, 1, 10), "from 0.3.0 up to 4.1.9", "Fixed in 4.2.0.",
        ("CVE-2026-134817",), introduced=(0, 3, 0),
    ),
    # DBHub's image, for the two npm rows: tagged `X.Y.Z` by release (no 1.6.1 or 1.7.0).
    # `latest` was pushed on 2026-11-25, after 2.1.0, fixed for the first.
    _ImagePin(
        "AAK-MCP-DBHUB-CVE-2026-134803-001", "DBHub", "bytebase/dbhub",
        (1, 7, 0), "from 0.18.0 below 1.7.0", "Fixed in 1.7.0 (1.7.1 is the first image).",
        ("CVE-2026-134803",), introduced=(0, 18, 0),
    ),
    _ImagePin(
        "AAK-MCP-DBHUB-CVE-2026-136441-001", "DBHub", "bytebase/dbhub",
        (0, 22, 6), "from 0.5.0 below 0.22.6",
        "The record names no fixed release: run 1.7.1 or later and keep the HTTP port private.",
        ("CVE-2026-136441",), introduced=(0, 5, 0),
    ),
    # obsidian-sync-mcp's image, for the npm row: tagged `vX.Y.Z` from v0.1.1. `latest` was
    # the v0.13.0 digest on 2026-11-26.
    _ImagePin(
        "AAK-MCP-OBSIDIANSYNC-CVE-2026-77283-001", "obsidian-sync-mcp",
        "ghcr.io/es617/obsidian-sync-mcp", (0, 5, 7), "below 0.5.7",
        "Fixed in 0.5.7, or set MCP_AUTH_TOKEN.", ("CVE-2026-77283",),
    ),
    # Jupyter MCP Server's image, for the PyPI row: tagged `X.Y.Z`, 1.0.1 included, which
    # PyPI does not have. `latest` was the 2.2.6 digest on 2026-11-26.
    _ImagePin(
        "AAK-MCP-JUPYTER-CVE-2026-77318-001", "Jupyter MCP Server", "datalayer/jupyter-mcp-server",
        (1, 0, 3), "from 0.5.0 below 1.0.3", "Fixed in 1.0.3.",
        ("CVE-2026-77318",), introduced=(0, 5, 0),
    ),
    # k8s-mcp-server (reza-gholizade, Go): the SSE server, the default mode, listens on
    # every interface with no credential (CVE-2026-130007). Read in main.go: v1.0.4 is
    # stdio only, v1.0.5 adds SSE, v1.0.25 calls `sse.Start(":" + port)` as it is, and
    # v1.1.0 defaults to stdio and refuses HTTP without a 32-character MCP_AUTH_TOKEN.
    # Images start at 1.0.6; `latest` was the 1.1.0 digest on 2026-11-26.
    _ImagePin(
        "AAK-MCP-K8SMCPSERVER-CVE-2026-130007-001", "k8s-mcp-server", "ginnux/k8s-mcp-server",
        (1, 1, 0), "from 1.0.5 below 1.1.0", "Fixed in 1.1.0, with MCP_AUTH_TOKEN set for HTTP.",
        ("CVE-2026-130007",), introduced=(1, 0, 5),
    ),
    # sqlite-mcp (StacklokLabs, Go): read-only mode checks for a leading SELECT while the
    # driver runs every statement, and describe_table interpolates its name into a PRAGMA
    # (CVE-2026-130008). Both are in the source at v0.0.1, v0.1.0 and v0.1.1, every release
    # before v0.1.2. `latest` was the 0.1.2 digest on 2026-11-26.
    _ImagePin(
        "AAK-MCP-STACKLOKSQLITE-CVE-2026-130008-001", "sqlite-mcp",
        "ghcr.io/stackloklabs/sqlite-mcp/server", (0, 1, 2), "below 0.1.2", "Fixed in 0.1.2.",
        ("CVE-2026-130008",),
    ),
    # Obot: four flaws fixed in v0.27.0 (43a95224, 30c09dfd, 900e4f31, 092275d1, all in
    # v0.27.0-rc1 and none in v0.26.3). Each arrives in another release, read in the source:
    # the bare code exchange of mcpgateway/oauth/statemanager.go in v0.8.0 (absent at v0.7.1,
    # CVE-2026-130764), the heredoc in pkg/mcp/docker.go in v0.9.0 (CVE-2026-130767), the
    # registry's icon fetch in v0.14.0 (CVE-2026-130768), and pkg/mcp/oauth.go, which takes
    # the resource the server names, in v0.26.0 (v0.25.6 passed the connection URL,
    # CVE-2026-130766). One row per stretch, so the evidence names only the CVEs a tag has.
    # HIGH throughout: CVE-2026-130764 covers the whole range. `latest` was v0.28.2 on
    # 2026-11-26. The floors of the two older Obot rules are other flaws' fixes.
    _ImagePin(
        "AAK-MCP-OBOT-CVE-2026-130766-001", "Obot", "ghcr.io/obot-platform/obot",
        (0, 9, 0), "from v0.8.0 below v0.27.0", "Fixed in v0.27.0.",
        ("CVE-2026-130764",), introduced=(0, 8, 0),
    ),
    _ImagePin(
        "AAK-MCP-OBOT-CVE-2026-130766-001", "Obot", "ghcr.io/obot-platform/obot",
        (0, 14, 0), "from v0.9.0 below v0.27.0", "Fixed in v0.27.0.",
        ("CVE-2026-130764", "CVE-2026-130767"), introduced=(0, 9, 0),
    ),
    _ImagePin(
        "AAK-MCP-OBOT-CVE-2026-130766-001", "Obot", "ghcr.io/obot-platform/obot",
        (0, 26, 0), "from v0.14.0 below v0.27.0", "Fixed in v0.27.0.",
        ("CVE-2026-130764", "CVE-2026-130767", "CVE-2026-130768"), introduced=(0, 14, 0),
    ),
    _ImagePin(
        "AAK-MCP-OBOT-CVE-2026-130766-001", "Obot", "ghcr.io/obot-platform/obot",
        (0, 27, 0), "from v0.26.0 below v0.27.0", "Fixed in v0.27.0.",
        ("CVE-2026-130766", "CVE-2026-130764", "CVE-2026-130767", "CVE-2026-130768"),
        introduced=(0, 26, 0),
    ),
    # Pomerium: CVE-2026-135300, the MCP token endpoint never compared the secret of a client
    # registered for client_secret_basic, the default method. Read in the source: internal/mcp
    # is absent at v0.29.6, the empty case ships in v0.30.0 and is a log line at v0.33.6, and
    # f86d7c00 (#6787) compares the secret in v0.34.0; v0.33 has no backport. The Cloud Run
    # build carries `vX.Y.Z-cloudrun` tags. Every ingress-controller tag from v0.30.0 to
    # v0.33.6 requires a Pomerium from v0.30.0 to v0.33.5 in its go.mod, and v0.34.0 requires
    # v0.34.0; v0.29.6 requires v0.29.6. `latest` was the v0.34.1 digest of both Docker Hub
    # images on 2026-11-26. Docker Hub floats two-part tags (`v0.33` was v0.33.6).
    _ImagePin(
        "AAK-MCP-POMERIUM-CVE-2026-135300-001", "Pomerium", "pomerium/pomerium",
        (0, 34, 0), "from v0.30.0 below v0.34.0", "Fixed in v0.34.0.",
        ("CVE-2026-135300",), introduced=(0, 30, 0),
    ),
    _ImagePin(
        "AAK-MCP-POMERIUM-CVE-2026-135300-001", "Pomerium", "gcr.io/pomerium-io/pomerium",
        (0, 34, 0), "from v0.30.0 below v0.34.0", "Fixed in v0.34.0.",
        ("CVE-2026-135300",), introduced=(0, 30, 0),
    ),
    _ImagePin(
        "AAK-MCP-POMERIUM-CVE-2026-135300-001", "Pomerium Ingress Controller",
        "pomerium/ingress-controller",
        (0, 34, 0), "from v0.30.0 below v0.34.0", "Fixed in v0.34.0.",
        ("CVE-2026-135300",), introduced=(0, 30, 0),
    ),
    # LibreChat: CVE-2026-54031, the MCP OAuth client checks a URL and then follows redirects
    # (and, to v0.8.8-rc4, connects to a literal address unchecked). Read in the source:
    # packages/api/src/mcp/oauth is absent at v0.7.8 and ships in v0.7.9-rc1; v0.8.5 calls bare
    # fetch; v0.8.6 to v0.8.8-rc4 call hardenedFetch with no `redirect`; 4d33d8c2 (#16514) sets
    # `redirect: 'error'` in v0.8.8. CVE-2026-54032 joins it on v0.7.9 alone: the vendor's
    # range is below v0.8.6, but only v0.7.9-rc1 and v0.7.9 mount a dialog that renders the
    # description raw; from v0.8.0-rc1 to v0.8.5 nothing imports the file the record names,
    # and 619f28d7 (#12927) is in v0.8.6-rc1. The third row per image is rc1 to rc4 of the
    # fixed release, which read as 0.8.8. `ghcr.io/danny-avila/*` stops at v0.8.8-rc4 and its
    # `latest` is the v0.8.7 digest; `ghcr.io/librechat-ai/*` and Docker Hub's are v0.8.9
    # (2026-11-26). `registry.librechat.ai` answers with ghcr.io's token realm for both.
    *(
        _ImagePin(
            "AAK-MCP-LIBRECHAT-CVE-2026-54031-001", "LibreChat", f"{registry}/{name}",
            (0, 8, 0), "v0.7.9", "Fixed in v0.8.8.", ("CVE-2026-54031", "CVE-2026-54032"),
            introduced=(0, 7, 9),
        )
        for registry in (
            "ghcr.io/danny-avila", "registry.librechat.ai/danny-avila", "ghcr.io/librechat-ai",
            "registry.librechat.ai/librechat-ai", "librechat",
        )
        for name in ("librechat", "librechat-api")
    ),
    *(
        _ImagePin(
            "AAK-MCP-LIBRECHAT-CVE-2026-54031-001", "LibreChat", f"{registry}/{name}",
            (0, 8, 8), "from v0.7.9 below v0.8.8", "Fixed in v0.8.8.", ("CVE-2026-54031",),
            floating_affected=registry.endswith("danny-avila"), introduced=(0, 8, 0),
        )
        for registry in (
            "ghcr.io/danny-avila", "registry.librechat.ai/danny-avila", "ghcr.io/librechat-ai",
            "registry.librechat.ai/librechat-ai", "librechat",
        )
        for name in ("librechat", "librechat-api")
    ),
    *(
        _ImagePin(
            "AAK-MCP-LIBRECHAT-CVE-2026-54031-001", "LibreChat", f"{registry}/{name}",
            (0, 8, 9), "from v0.8.8-rc1 to v0.8.8-rc4", "Fixed in v0.8.8.", ("CVE-2026-54031",),
            introduced=(0, 8, 8), suffix=r"^-rc[1-4](?!\d)",
        )
        for registry in (
            "ghcr.io/danny-avila", "registry.librechat.ai/danny-avila", "ghcr.io/librechat-ai",
            "registry.librechat.ai/librechat-ai", "librechat",
        )
        for name in ("librechat", "librechat-api")
    ),
    # ArcadeDB: the MCP module's authorization gaps fixed in 26.11.1 (289ef95608, 2026-11-02,
    # and 100d8a021c, 2026-11-04). Read in the source and the server jars: no MCP classes in
    # 26.2.1 or 26.2.2 (NVD starts CVE-2026-134329 at 26.2.1), MCP in 26.3.1, where get_schema
    # lists every type (CVE-2026-134327) and the query tool's read-only check evaluates Groovy
    # Gremlin (CVE-2026-134324); resolveDatabase, which tests existence before access, arrives
    # in 26.4.2 (CVE-2026-134329). Headless and minimal leave Gremlin out and keep MCP, so
    # CVE-2026-134324 reaches them through the upsert tools only, from 26.8.1. They stop at
    # 26.10.1 and their `latest` is a 26.11.1-SNAPSHOT of 2026-10-05, before the fixes;
    # `arcadedata/arcadedb:latest` was 26.12.1-SNAPSHOT on 2026-11-26, after them.
    _ImagePin(
        "AAK-MCP-ARCADEDB-CVE-2026-134327-001", "ArcadeDB", "arcadedata/arcadedb",
        (26, 4, 2), "from 26.3.1 below 26.11.1", "Fixed in 26.11.1.",
        ("CVE-2026-134327", "CVE-2026-134324"), introduced=(26, 3, 1),
    ),
    _ImagePin(
        "AAK-MCP-ARCADEDB-CVE-2026-134327-001", "ArcadeDB", "arcadedata/arcadedb",
        (26, 11, 1), "from 26.4.2 below 26.11.1", "Fixed in 26.11.1.",
        ("CVE-2026-134327", "CVE-2026-134324", "CVE-2026-134329"), introduced=(26, 4, 2),
    ),
    *(
        _ImagePin(
            "AAK-MCP-ARCADEDB-CVE-2026-134327-001", "ArcadeDB", image, floor, label,
            "Fixed in 26.11.1, which this image does not have; use arcadedata/arcadedb.",
            cves, floating_affected=floor == (26, 11, 1), introduced=introduced,
        )
        for image in ("arcadedata/arcadedb-headless", "arcadedata/arcadedb-minimal")
        for introduced, floor, label, cves in (
            ((26, 3, 1), (26, 4, 2), "from 26.3.1 below 26.11.1", ("CVE-2026-134327",)),
            ((26, 4, 2), (26, 8, 1), "from 26.4.2 below 26.11.1",
             ("CVE-2026-134327", "CVE-2026-134329")),
            ((26, 8, 1), (26, 11, 1), "from 26.8.1 below 26.11.1",
             ("CVE-2026-134327", "CVE-2026-134329", "CVE-2026-134324")),
        )
    ),
    # ArcadeDB native builds: CVE-2026-134337. SqlAstInspector walks the SQL AST by reflection
    # and the native binary has no reflection metadata for it, so a write inside a SELECT
    # passes for a read, the MCP tools' own read-only check included. NVD starts at 26.8.1;
    # the class arrives in 26.10.1, the first release with `-native` tags on Docker Hub
    # (26.10.1 and 26.10.2, each also `-native-amd64` and `-native-arm64`). 4ffa8ca240 adds the
    # metadata (220 sql.parser entries) in 26.11.1. JVM tags are not affected, hence `suffix`.
    _ImagePin(
        "AAK-MCP-ARCADEDB-CVE-2026-134337-001", "ArcadeDB native image", "arcadedata/arcadedb",
        (26, 11, 1), "from 26.10.1 below 26.11.1", "Fixed in 26.11.1.",
        ("CVE-2026-134337",), introduced=(26, 10, 1), suffix=r"-native(?![a-z])",
    ),
    # SurrealDB: CVE-2026-134293, the MCP tools' identifier check ends a backtick-quoted name
    # at the first backtick and the SurrealQL lexer honours a backslash before it. Read in the
    # source: surrealdb/mcp is absent at v3.0.5 and ships in v3.1.0-beta.1 with
    # `.find('`')`, unchanged at v3.3.5; ec41ae8f15 scans as the lexer does, in v4.0.0-beta.1
    # and not v3.3.5 (no 3.x backport). Docker Hub floats `v3.1` to `v3.3`, which are reported;
    # `v3` was v3.3.5 on 2026-11-26 and one number is not read. `latest` was v4.0.1.
    _ImagePin(
        "AAK-MCP-SURREALDB-CVE-2026-134293-001", "SurrealDB", "surrealdb/surrealdb",
        (4, 0, 0), "from v3.1.0 below v4.0.0", "Fixed in v4.0.0.",
        ("CVE-2026-134293",), introduced=(3, 1, 0),
    ),
    # Sim: CVE-2026-135162, the internal routes that create and update a workflow MCP
    # server wrote `isPublic` for any workspace member with `write`, and a public server
    # answers /api/mcp/serve/{serverId} with no credential. Neither route mentions
    # `isPublic` at v0.5.60; both write it under `withMcpAuth('write')` at v0.5.61 and at
    # v0.9.40; v0.9.41 asks for admin (3b6be5cd). GHCR has no v0.5.60. `latest` was the
    # v0.9.66 digest on 2026-11-26. The second row is the name the project's Helm chart
    # gives its values (`repository: simstudioai/simstudio`, the registry set globally);
    # Docker Hub has no such repository.
    _ImagePin(
        "AAK-MCP-SIM-CVE-2026-135162-001", "Sim", "ghcr.io/simstudioai/simstudio",
        (0, 9, 41), "from 0.5.61 below 0.9.41", "Fixed in v0.9.41.",
        ("CVE-2026-135162",), introduced=(0, 5, 61),
    ),
    _ImagePin(
        "AAK-MCP-SIM-CVE-2026-135162-001", "Sim", "simstudioai/simstudio",
        (0, 9, 41), "from 0.5.61 below 0.9.41", "Fixed in v0.9.41.",
        ("CVE-2026-135162",), introduced=(0, 5, 61),
    ),
    # sdcb Chats: CVE-2026-135432, `assigned-user-details` on an MCP server returns every
    # assigned user's `CustomHeaders` to any one of them. NVD starts at 1.10.0; in the
    # source McpController.cs is absent at 1.6.9.30 and has the same endpoint and filter
    # at 1.7.0.154, 1.9.1.416 and 1.17.0.772 (it moved to src/BE/web before 1.10.0), so
    # the start is 1.7.0. 1.17.1.799 asks for the owner or an admin (776a065b). Docker
    # Hub tags `X.Y.Z`, `X.Y.Z.BUILD`, `X.Y` and `r-BUILD`; `1`, `1.17` and `latest` were
    # the 1.17.1 digest on 2026-11-26.
    _ImagePin(
        "AAK-MCP-SDCBCHATS-CVE-2026-135432-001", "sdcb Chats", "sdcb/chats",
        (1, 17, 1), "from 1.7.0 below 1.17.1", "Fixed in 1.17.1.",
        ("CVE-2026-135432",), introduced=(1, 7, 0),
    ),
    # FlowIntel: CVE-2026-133853, its chatbot keeps one MCP session and, from 3.3.0, one
    # process-wide FLOWINTEL_API_KEY for every user. chatbot_core.py is absent at 3.1.0;
    # 3.2.0 opens the session with the first caller's key and keeps it; 3.3.0 and 4.0.0
    # swap it under overlapping requests. The fix (9eec395c, 2026-11-17) is on main and
    # the record names 4.1.0, which had no tag and no image on 2026-11-26. `latest` was
    # the 4.0.0 digest.
    _ImagePin(
        "AAK-MCP-FLOWINTEL-CVE-2026-133853-001", "FlowIntel", "ghcr.io/flowintel/flowintel",
        (4, 1, 0), "from 3.2.0, the newest release included",
        "Fixed in 4.1.0, not published on 2026-11-26.",
        ("CVE-2026-133853",), floating_affected=True, introduced=(3, 2, 0),
    ),
    # AutoGPT Platform: CVE-2026-130178 (the outbound request guard lets `::` and other
    # IPv6 forms of a blocked address through) and CVE-2026-133448 (chat and graph text is
    # pre-processed by the Claude Code CLI, outside the tool allow-list and hooks). One
    # range and one fix release, both HIGH, so one rule. At v0.7.1 and v0.8.4 request.py
    # lists no `::/128` and neither SDK caller passes `verbatim_prompts`; v0.9.0 does both.
    # v0.7.1 is the oldest release tag on Docker Hub, and each image's label names its
    # platform tag's commit. `latest` was the v0.12.0 digest on 2026-11-26.
    _ImagePin(
        "AAK-AUTOGPT-CVE-2026-130178-001", "AutoGPT Platform", "significantgravitas/autogpt",
        (0, 9, 0), "from 0.7.1 below 0.9.0", "Fixed in v0.9.0.",
        ("CVE-2026-130178", "CVE-2026-133448"), introduced=(0, 7, 1),
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


def _needle(image: str) -> str:
    """The text every reference to this image contains: its name without the
    registry, which Helm values may split off (`registry: ghcr.io` beside
    `repository: obot-platform/obot`). The first part is a registry when it has
    a `.` or `:` or is `localhost`, Docker's own rule, so a Docker Hub name is
    kept whole. Its last part alone (`answer`, `conductor`) is an ordinary word,
    and every YAML file containing it would be composed for the Helm reader,
    which takes seconds for a large file."""
    first, _, rest = image.partition("/")
    return rest if "." in first or ":" in first or first == "localhost" else image


_NEEDLES = {pin.image: _needle(pin.image) for pin in _PINS}


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
    if pin.suffix is not None and not re.search(pin.suffix, tag[m.end():]):
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
        dirnames[:] = kept_dirs(dirpath, dirnames, project_root)
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


def _helm_refs(text: str, path: Path) -> Iterator[tuple[str, str, int]]:
    """(repository, tag, line) for every mapping that pairs the two, as Helm
    values do. Composed, not loaded: node values are the strings as written."""
    try:
        roots = compose_yaml_all(text, path)
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
            text = read_text_capped(path, _MAX_FILE_BYTES, errors="replace")
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
        pins = [pin for pin in _PINS if _NEEDLES[pin.image] in lowered]
        if not pins:
            continue
        # The walk pops from the end of the document; sort so a file with two
        # image blocks (a chart's app and its migration job) is reported on
        # the first, as the inline reader reports its first reference.
        helm = sorted(_helm_refs(text, path), key=lambda ref: ref[2]) if kind == "yaml" else []
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

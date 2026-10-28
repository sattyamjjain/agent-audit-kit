# Scan a container image's files

A Python startup hook, or an installed malicious release, lives in the image, not
in the repository it was built from: `pip install` puts it in the image's
site-packages. AAK reads an image as a directory. Unpack the image's root
filesystem and scan that directory; AAK never pulls from a registry and makes no
network request.

```sh
cid=$(docker create IMAGE)
mkdir rootfs
docker export "$cid" | tar -x -C rootfs --exclude='dev/*' --exclude='proc/*' --exclude='sys/*'
docker rm "$cid"
aak scan rootfs \
  --rules AAK-STARTUP-HOOK-PTH-001,AAK-STARTUP-HOOK-SITECUSTOMIZE-001,AAK-MALICIOUS-RELEASE-001
```

`docker create` pulls `IMAGE` when it is not already local; that is the Docker
CLI's request, not AAK's. `podman create` and `podman export` work the same way.
The excludes skip device nodes, which `tar` cannot create without root and
which hold nothing AAK reads.

## What is read

- Every `site-packages` and `dist-packages` directory up to 12 levels below the
  root: `usr/local/lib/python3.12/site-packages` for the official Python images,
  `usr/lib/python3/dist-packages` for Debian and Ubuntu packages, and any
  virtualenv the image carries (`opt/venv`, `app/.venv`).
  - AAK-STARTUP-HOOK-PTH-001: `.pth` lines that run as code, and `.start` entry points.
  - AAK-STARTUP-HOOK-SITECUSTOMIZE-001: `sitecustomize` and `usercustomize`.
  - AAK-MALICIOUS-RELEASE-001: installed `<name>-<version>.dist-info` directories.
- Lockfiles and manifests the image carries (`app/package-lock.json`,
  `app/requirements.txt`), read as in a repository.

`--rules` keeps the report to those rules. Without it every rule runs, and a full
root filesystem gives other rules a great deal to read and report.

## What is not read

- The image config. `ENV PYTHONPATH`, `ENV PYTHONSTARTUP` and the entrypoint are
  not part of the exported files. Read them with
  `docker image inspect --format '{{json .Config}}' IMAGE`.
- The layers as layers. An export is the final filesystem, so a file one layer
  added and a later layer deleted is gone.
- An image's digest. To check an image reference against the malicious-release
  feed, scan the compose file or manifest that names it by digest.

## An MCP server's own environment

An MCP server installed in its own virtualenv under the project (`servers/x/.venv`)
or with a vendored `site-packages` is read by a plain `aak scan .`: those rules look
inside `.venv`, `venv`, `env`, `.tox` and `vendor`, which every other rule skips.

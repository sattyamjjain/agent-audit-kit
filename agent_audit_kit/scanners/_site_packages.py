"""Where the startup-hook and malicious-release scanners find installed packages.

Every other scanner skips `.venv/`, `venv/` and `env/` (`SKIP_DIRS`): a
virtualenv is vendored code, not the project. For these two it is the point.
Python runs the startup files of every site-packages directory on its path at
each interpreter start (`.pth` import lines, PEP 829 `.start` entry points,
`sitecustomize`), and an installed `<name>-<version>.dist-info` says which
release is installed, so a malicious release that sits in a project's `.venv/`,
in an MCP server's own environment under the project, in a vendored
`site-packages`, or in an image's root filesystem unpacked for the scan
(`docker export`) is only seen by looking there.

The walk stays bounded. It looks for directories named `site-packages` or
`dist-packages` (the scan root itself included) at most `MAX_SITE_DEPTH` levels
below the root, follows no symlinked directory, and never descends into a
site-packages directory it found: Python reads startup files only at the top
of one. It still skips the rest of `SKIP_DIRS` (`node_modules/`, `.git/`,
`__pycache__/`, build output), with `.venv`, `venv`, `env`, `.tox` and `vendor`
taken out, since those are where an environment or a vendored site-packages
lives. A site-packages directory deeper than the cap, or reached only through a
symlink, is not read; both scanners say so in their limitations.
"""

from __future__ import annotations

import os
from pathlib import Path

from ._helpers import SKIP_DIRS, in_skip_dir

#: The directory names Python installs packages into: `site-packages` (pip,
#: venvs, `/usr/local`) and `dist-packages` (Debian and Ubuntu system Python).
SITE_DIR_NAMES = frozenset({"site-packages", "dist-packages"})

#: How many directories below the scan root a site-packages directory may sit.
#: An image's `usr/local/lib/python3.12/site-packages` is 5 deep, a conda env's
#: `opt/conda/envs/app/lib/python3.12/site-packages` 7, a pipx venv under a
#: home directory 9, and a monorepo service's `.venv` usually 6 to 8.
MAX_SITE_DEPTH = 12

#: `SKIP_DIRS` without the names an environment or a vendored tree lives under.
WALK_SKIP_DIRS = SKIP_DIRS - {".venv", "venv", "env", ".tox", "vendor"}


def is_site_dir(name: str) -> bool:
    """Is a directory of this name one Python installs packages into?"""
    return name.lower() in SITE_DIR_NAMES


def site_package_dirs(project_root: Path) -> list[Path]:
    """Every site-packages or dist-packages directory the walk reaches, sorted.

    The root itself counts when it is one (`aak scan .venv/lib/python3.12/site-packages`).

    Args:
        project_root: The scan root.

    Returns:
        The directories, as absolute paths under `project_root`, in path order.
    """
    found: list[Path] = []
    if is_site_dir(project_root.name) and project_root.is_dir():
        return [project_root]
    for dirpath, dirnames, _ in os.walk(project_root, followlinks=False):
        here = Path(dirpath)
        depth = len(here.relative_to(project_root).parts)
        kept: list[str] = []
        for name in sorted(dirnames):
            child = here / name
            if os.path.islink(child) or in_skip_dir(child, project_root, WALK_SKIP_DIRS):
                continue
            if is_site_dir(name):
                found.append(child)
                continue  # Python reads startup files at the top of one only
            if depth + 1 < MAX_SITE_DEPTH:
                kept.append(name)
        dirnames[:] = kept
    return sorted(found)


def site_entries(site_dir: Path) -> list[os.DirEntry[str]]:
    """The entries directly inside one site-packages directory, sorted by name.

    An unreadable directory has none; the caller reports nothing from it.
    """
    try:
        with os.scandir(site_dir) as it:
            return sorted(it, key=lambda entry: entry.name)
    except OSError:
        return []

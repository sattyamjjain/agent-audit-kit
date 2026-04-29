"""Mechanical-fix codemods paired with SAST rules.

Each module exposes a `fix(text: str) -> str` entry point that
rewrites known-safe transformations. Run by `aak suggest --apply-trivial`.
"""

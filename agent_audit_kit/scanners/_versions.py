"""What a version specifier allows, as spans of release triples.

The dependency-pin scanners used to read a specifier by taking the first number
after the package name. That is right for `==1.2.3` and `^1.2.3`, and wrong for
every specifier whose first number is an upper bound: `litellm<1.84.0` read as
1.84.0, which is patched, although every version it allows is affected;
`<2.0.0,>=1.0.0` read as 2.0.0 while the same range written `>=1.0.0,<2.0.0` read
as 1.0.0; Flowise's `"<3.1.3"` read as 3.1.3. A Poetry caret or a Pipfile
`"==1.90.0"` was not read at all and was reported as unpinned, so upgrading could
not clear it.

This module turns a specifier into the set of versions it admits, so a pin asks
the one question that does not depend on how the range is written: does the
range admit an affected version?

Versions compare on their first three numbers, as the pin table always has. A
pre-release, a post-release, a fourth component and a local label fold into the
release triple (`16.4.0-canary.12` is 16.4.0, `2.0.0-beta.5` is 2.0.0), and an
epoch is dropped. A set is a sorted tuple of disjoint half-open spans `[lo, hi)`,
and `TOP` stands above every real version.

Three grammars, because the registries disagree about a bare version:

- `npm`, node-semver: `1.2` and `1.x` are ranges (`>=1.2.0 <1.3.0`); `^`, `~`,
  x-ranges and hyphen ranges; a space means "and", `||` means "or".
- `poetry`, Poetry's constraints: `^`, `~`, `~=`, `==`, `!=` and `*` wildcards; a
  bare version is exact; a comma or a space means "and", `||` or `|` means "or".
- `pep440`, for requirements files, PEP 621 and Pipfile: `==1.2` is exactly
  1.2.0, `==1.2.*` is a range, `~=` is the compatible release. A bare version is
  read as `==`, which PEP 440 does not allow but a hand-written Pipfile does.

A parse returns `None` when the text states no version AAK can read: an empty
string, `*`, a dist-tag such as `latest`, a URL, a git or file reference, or
syntax none of the grammars accepts. The caller decides what that means; the pin
table reads it as "unpinned", as it always has.

The version reader is a hand-written scanner rather than a regular expression on
purpose. A version tail (`-beta.1`, `rc1`, `.post2`, `+local`) is "separator,
then letters or digits, repeated", and the natural regex for that nests one
quantifier inside another, which backtracks exponentially on a crafted token.
"""

from __future__ import annotations

import re
import sys

Ver = tuple[int, int, int]
Span = tuple[Ver, Ver]
Spans = tuple[Span, ...]

ZERO: Ver = (0, 0, 0)
TOP: Ver = (sys.maxsize, 0, 0)
ANY: Spans = ((ZERO, TOP),)
NONE: Spans = ()

# No real version is longer than this; a longer token is not one.
_MAX_TOKEN = 128
_WILDCARDS = "xX*"
_TAIL_SEPARATORS = "-+._"
_OPERATORS = ("===", "==", "!=", "~=", "<=", ">=", "<", ">", "=", "^", "~")


def _is_digit(c: str) -> bool:
    return "0" <= c <= "9"


def _is_alnum(c: str) -> bool:
    return _is_digit(c) or "a" <= c <= "z" or "A" <= c <= "Z"


def _valid_tail(tail: str) -> bool:
    """A tail is letters and digits, with single separators between runs."""
    previous_was_separator = False
    for c in tail:
        if c in _TAIL_SEPARATORS:
            if previous_was_separator:
                return False
            previous_was_separator = True
        elif _is_alnum(c):
            previous_was_separator = False
        else:
            return False
    return not previous_was_separator


def _partial(token: str) -> tuple[list[int], bool] | None:
    """(the leading numeric components, whether a wildcard appeared), or None.

    `1.2.3` is ([1, 2, 3], False), `1.2` is ([1, 2], False), `1.x` is ([1], True)
    and `*` is ([], True). A wildcard ends the numeric components, so `1.x.3` is
    `1.x`. A fourth component or a pre-release tail is accepted and ignored.
    """
    text = token
    if not text or len(text) > _MAX_TOKEN:
        return None
    if text[0] in "vV":
        text = text[1:]
    bang = text.find("!")
    if bang > 0 and all(_is_digit(c) for c in text[:bang]):
        text = text[bang + 1:]
    if not text:
        return None
    parts: list[int] = []
    wild = False
    i, n = 0, len(text)
    for index in range(3):
        if index:
            if i + 1 >= n or text[i] != "." or not (_is_digit(text[i + 1]) or text[i + 1] in _WILDCARDS):
                break
            i += 1
        if text[i] in _WILDCARDS:
            wild = True
            i += 1
            break
        start = i
        while i < n and _is_digit(text[i]):
            i += 1
        if i == start:
            return None
        parts.append(int(text[start:i]))
    if not parts and not wild:
        return None
    if not _valid_tail(text[i:]):
        return None
    return parts, wild


def _pad(parts: list[int]) -> Ver:
    padded = (parts + [0, 0, 0])[:3]
    return padded[0], padded[1], padded[2]


def _after(parts: list[int]) -> Ver:
    """The first version past every version whose release starts with `parts`."""
    if not parts:
        return TOP
    head = parts[:3]
    head[-1] += 1
    return _pad(head)


def next_patch(v: Ver) -> Ver:
    return v[0], v[1], v[2] + 1


def _span(lo: Ver, hi: Ver) -> Spans:
    return ((lo, hi),) if lo < hi else NONE


def union(spans: list[Span] | Spans) -> Spans:
    merged: list[Span] = []
    for lo, hi in sorted(spans):
        if merged and lo <= merged[-1][1]:
            if hi > merged[-1][1]:
                merged[-1] = (merged[-1][0], hi)
        else:
            merged.append((lo, hi))
    return tuple(merged)


def intersect(a: Spans, b: Spans) -> Spans:
    out: list[Span] = []
    for a_lo, a_hi in a:
        for b_lo, b_hi in b:
            lo, hi = max(a_lo, b_lo), min(a_hi, b_hi)
            if lo < hi:
                out.append((lo, hi))
    return union(out)


def admits(spans: Spans, lo: Ver, hi: Ver) -> bool:
    """True when some version in `spans` lies in `[lo, hi)`."""
    return any(s_lo < hi and lo < s_hi for s_lo, s_hi in spans)


def exact_version(spans: Spans) -> Ver | None:
    """The one version `spans` admits, when it admits exactly one."""
    if len(spans) == 1 and spans[0][1] == next_patch(spans[0][0]):
        return spans[0][0]
    return None


def _caret(parts: list[int]) -> Spans:
    """`^`: changes that do not modify the left-most non-zero component."""
    if not parts:
        return ANY
    if parts[0] > 0 or len(parts) == 1:
        hi: Ver = (parts[0] + 1, 0, 0)
    elif len(parts) == 2 or parts[1] > 0:
        hi = (0, parts[1] + 1, 0)
    else:
        hi = (0, 0, parts[2] + 1)
    return _span(_pad(parts), hi)


def _tilde(parts: list[int]) -> Spans:
    """`~`: patch changes when a minor is given, minor changes when it is not."""
    if not parts:
        return ANY
    if len(parts) == 1:
        return _span(_pad(parts), (parts[0] + 1, 0, 0))
    return _span(_pad(parts), (parts[0], parts[1] + 1, 0))


def _compatible(parts: list[int]) -> Spans:
    """PEP 440 `~=`: `~=1.2` is `>=1.2, ==1.*`, `~=1.2.3` is `>=1.2.3, ==1.2.*`."""
    if len(parts) < 2:
        return _span(_pad(parts), TOP)
    return _span(_pad(parts), _after(parts[:-1]))


def _equal(parts: list[int], wild: bool, op: str, dialect: str) -> Spans:
    """`==`, `===`, `=` and a bare version."""
    if not parts:
        return ANY
    if wild or (dialect == "npm" and op in ("", "=") and len(parts) < 3):
        return _span(_pad(parts), _after(parts))
    v = _pad(parts)
    return _span(v, next_patch(v))


def _comparator(op: str, token: str, dialect: str) -> Spans | None:
    """The spans one `op version` clause admits, or None when it is unreadable."""
    parsed = _partial(token)
    if parsed is None:
        return None
    parts, wild = parsed
    # npm and a wildcard read a short version as "every version starting so";
    # PEP 440 and Poetry pad it with zeros.
    short = (dialect == "npm" or wild) and len(parts) < 3
    if op in ("", "=", "==", "==="):
        return _equal(parts, wild, op, dialect)
    if op == "!=":
        excluded = _equal(parts, wild, "==", dialect)
        if not excluded:
            return ANY
        ex_lo, ex_hi = excluded[0]
        return union(list(_span(ZERO, ex_lo) + _span(ex_hi, TOP)))
    if op == ">=":
        return _span(_pad(parts), TOP)
    if op == ">":
        if not parts:
            return NONE
        return _span(_after(parts) if short else next_patch(_pad(parts)), TOP)
    if op == "<":
        return _span(ZERO, _pad(parts)) if parts else NONE
    if op == "<=":
        if not parts:
            return ANY
        return _span(ZERO, _after(parts) if short else next_patch(_pad(parts)))
    if op == "^":
        return _caret(parts)
    if op == "~":
        return _tilde(parts)
    if op == "~=":
        return _compatible(parts)
    return None


def _split_operator(clause: str) -> tuple[str, str]:
    for op in _OPERATORS:
        if clause.startswith(op):
            return op, clause[len(op):]
    return "", clause


def _clauses(text: str) -> list[str]:
    """Split one "and" group into `op version` clauses.

    A space may sit between an operator and its version (`>= 1.2.3`), so a token
    that is only an operator is glued to the token after it.
    """
    out: list[str] = []
    pending = ""
    for token in re.split(r"[\s,]+", text):
        if not token:
            continue
        if token in _OPERATORS:
            pending += token
            continue
        out.append(pending + token)
        pending = ""
    if pending:
        out.append(pending)
    return out


def _conjunction(text: str, dialect: str) -> Spans | None:
    """Every clause of one "and" group, intersected."""
    words = text.split()
    if dialect == "npm" and len(words) == 3 and words[1] == "-":
        lo, hi = _partial(words[0]), _partial(words[2])
        if lo is None or hi is None:
            return None
        hi_parts = hi[0]
        upper = next_patch(_pad(hi_parts)) if len(hi_parts) == 3 and not hi[1] else _after(hi_parts)
        return _span(_pad(lo[0]), upper)
    clauses = _clauses(text)
    if not clauses:
        return None
    result: Spans = ANY
    for clause in clauses:
        op, token = _split_operator(clause)
        if dialect == "pep440" and op in ("^", "~"):
            return None
        spans = _comparator(op, token, dialect)
        if spans is None:
            return None
        result = intersect(result, spans)
    return result


def parse_range(spec: str, dialect: str) -> Spans | None:
    """The versions `spec` admits under `dialect`, or None (no readable version).

    Args:
        spec: The specifier as written: `^1.2.3`, `>=1.0,<2`, `1.2.x || 2.x`.
        dialect: "npm", "poetry" or "pep440".

    Returns:
        A sorted tuple of disjoint `[lo, hi)` spans, empty when the specifier
        admits nothing, or None when the text states no version this module can
        read.
    """
    text = spec.strip()
    if not text or text in ("*", "x", "X"):
        return None
    if dialect == "npm":
        alternatives = text.split("||")
    else:
        alternatives = text.replace("||", "|").split("|")
        if dialect == "pep440" and len(alternatives) > 1:
            return None
    out: list[Span] = []
    for alternative in alternatives:
        spans = _conjunction(alternative, dialect)
        if spans is None:
            return None
        out.extend(spans)
    return union(out)


def parse_version(text: str) -> Ver | None:
    """The release triple of one exact version string, or None."""
    parsed = _partial(text.strip())
    if parsed is None or parsed[1] or not parsed[0]:
        return None
    return _pad(parsed[0])


def is_exact_version(text: str) -> bool:
    """True for a full `x.y.z` release, with an optional `v` and tail."""
    parsed = _partial(text.strip())
    return parsed is not None and not parsed[1] and len(parsed[0]) == 3

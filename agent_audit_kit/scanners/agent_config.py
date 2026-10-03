from __future__ import annotations

import ipaddress
import re
import unicodedata
from pathlib import Path
from urllib.parse import urlsplit

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import make_finding

# ---- Target files to scan (relative to project root) ----
_AGENT_CONFIG_FILES: list[str] = [
    "AGENTS.md",
    ".cursorrules",
    "CLAUDE.md",
    ".claude/CLAUDE.md",
    ".github/copilot-instructions.md",
    ".windsurfrules",
    ".roo/rules",
    ".kiro/rules",
]

# AAK-AGENT-001 and -003 are matched further down, after the negation helpers
# they share with -006 ("directives, not mentions").

# ---- AAK-AGENT-002 / -006: links in instruction files ----
#
# AAK-AGENT-002 used to be HIGH for *any* link outside a prefix allowlist, which
# reads the wrong risk in both directions. Reported in #771 against 930 public
# repositories shipping AGENTS.md / CLAUDE.md: it fired on 303 of them, so a
# third of that sample failed `--ci` for carrying a documentation link. A link
# on its own is not an attack, and calling it HIGH trains people to pass
# `--fail-on critical`, which then hides the findings that are.
#
# What is worth HIGH is the directive, not the host: text that tells the agent to
# fetch a URL and follow, execute, obey or load what comes back, or to send data
# to one. AAK-AGENT-006 matches that, deterministically and with no allowlist at
# all — the reporter's own point, that an attacker can host on github.com too.
_URL_RE = re.compile(r"https?://[^\s\)>\]\"']+", re.IGNORECASE)

#: Hosts whose links are ordinary documentation. Compared as HOSTS, never as a
#: prefix of the URL string. The prefix form let `github.com.evil.example` pass
#: as `github.com`, so the one shape an allowlist has to get right — a lookalike
#: registered under somebody else's name — was the shape it waved through.
#: Verified against the published 0.6.7 wheel before this change: a
#: fetch-and-follow directive pointing at that host produced no finding at all.
#:
#: The bare `docs.` and `developer.` arms are gone with it. They matched any host
#: beginning with those labels — `docs.attacker.example` included — which is a
#: statement about a subdomain label, not about who controls the domain.
_SAFE_URL_HOSTS = frozenset({
    "github.com",
    "stackoverflow.com",
    "wikipedia.org",
    "npmjs.com",
    "registry.npmjs.org",
    "pypi.org",
    # `python.org` replaces what the bare `docs.` arm used to cover for
    # `docs.python.org`. Naming the domain is the whole change: it admits any
    # subdomain of python.org and nothing that merely begins with `docs.`. Any
    # other documentation host wanted here has to be named the same way.
    "python.org",
    "crates.io",
    "gitlab.com",
    "bitbucket.org",
    "readthedocs.io",
    "readthedocs.org",
    "shields.io",
    "badge.fury.io",
    "travis-ci.org",
    "circleci.com",
    "codecov.io",
    "coveralls.io",
    "mozilla.org",
    "w3.org",
    "json-schema.org",
    "schema.org",
    "creativecommons.org",
    "opensource.org",
    "spdx.org",
    "example.com",
})


def _is_safe_host(url: str) -> bool:
    """True when `url`'s host is an allowlisted domain or a subdomain of one.

    Dot-bounded suffix match on the parsed hostname: `gist.github.com` is inside
    `github.com`, and `github.com.evil.example` is not, because the allowlisted
    name has to end the host rather than merely start it.
    """
    try:
        host = urlsplit(url).hostname
    except ValueError:  # malformed authority — not something to call safe
        return False
    if not host:
        return False
    host = host.rstrip(".").lower()
    return any(
        host == safe or host.endswith("." + safe) for safe in _SAFE_URL_HOSTS
    )


#: A verb that makes a URL an instruction rather than a reference. Three prose
#: shapes, because lumping them made the rule too loose: an act verb plus any URL
#: later on the line matched "Run the tests, then see <docs link>", which is
#: exactly the false positive this rule exists to avoid becoming. A fourth, the
#: shell-command form (`curl -d @.env <url>`), is `_HTTP_SEND_RE` below.
#:
#: `GET` is the HTTP method and only matches in capitals. Matched case-blind it
#: was also the "get" in "To get started, see <url>, then run make test", one of
#: the lines #771 found still reported HIGH after 0.6.8.
_FETCH_VERB = (
    r"(?:fetch|download|curl|wget|retrieve|read|load|import|pull|(?-i:GET)|"
    r"open|visit|go\s+to)"
)
_ACT_VERB = r"(?:follow|execute|run|obey|apply|comply|eval|source|adhere\s+to)"
_SEND_VERB = r"(?:send|post|upload|exfiltrate|report|submit|transmit|push)"
_URL_FRAG = r"https?://[^\s\)>\]\"']+"

#: Each verb is tried where it stands, not through one regex sweep. A sweep's
#: matches cannot overlap, so a negated verb ("Never read the old docs; download
#: <url> and run it") swallowed the directive that followed it inside its own match.
_FETCH_VERB_RE = re.compile(r"\b" + _FETCH_VERB + r"\b", re.IGNORECASE)
_URL_START_RE = re.compile(r"https?://", re.IGNORECASE)
_ACT_VERB_RE = re.compile(r"\b" + _ACT_VERB + r"\b", re.IGNORECASE)
_SEND_VERB_RE = re.compile(r"\b" + _SEND_VERB + r"\b", re.IGNORECASE)

#: What an act verb's object has to be for the act to be about the fetched
#: content: a pronoun, a noun for content, an adverb ("execute immediately",
#: "obey without question"), or nothing at all ("download <url> and execute.").
#: Without this the fetch arm matched any act verb after the link, so
#: "Read <url>, then run `make test`" came out HIGH for running the test suite.
_FETCHED_REF_RE = re.compile(
    r"\s*(?:$|[.;:!?,)]"
    r"|(?:it|them|this|that|these|those|what(?:ever)?|everything|anything)\b"
    r"|(?:immediately|automatically|unconditionally|directly|verbatim|blindly|"
    r"exactly|now|right\s+away|as[\s-]is|in\s+full|without\s+(?:question|"
    r"review|reviewing|asking|checking|confirmation|delay|hesitation))\b"
    r"|(?:the|its|their|any|all|each|every)\s+(?:[\w-]+\s+){0,2}?"
    r"(?:instructions?|steps?|commands?|scripts?|code|outputs?|results?|response|"
    r"rules?|directions?|guidance|contents?|files?|payload|text|prompts?|"
    r"directives?|polic(?:y|ies)|installer|program|binary|playbook|runbook|"
    r"procedure)\b)",
    re.IGNORECASE,
)

#: Fetched content can be put in charge without an act verb: pypa/setuptools'
#: AGENTS.md says to "fetch and read the [skeleton](<url>) document in its
#: entirety. It is the authoritative source of truth for this project". That is
#: the directive this rule exists for, and 0.6.10 caught it only because it read
#: the noun "source" as the shell verb.
_AUTHORITY_RE = re.compile(
    r"\b(?:authoritative|source\s+of\s+truth|takes?\s+precedence|supersedes?|"
    r"overrides?\s+(?:this|these|the|any|all)\b)",
    re.IGNORECASE,
)

#: Act on what is at it: "follow the instructions at <url>". The preposition is
#: required, and is what keeps the act verb bound to the URL rather than merely
#: sharing a line with it. It cannot follow the verb directly: in "the docs
#: source at <url>" the act verb is a noun, and a verb needs an object first.
_ACT_AT_URL_RE = re.compile(
    r"\b(?P<verb>" + _ACT_VERB + r")\b\s+(?!(?:at|from|in|on|via|per)\b)"
    r"[^\n]{0,100}?\b(?:at|from|in|on|via|per)\s+"
    r"(?:the\s+|this\s+)?(?:\S+\s+){0,3}?(?P<url>" + _URL_FRAG + r")",
    re.IGNORECASE,
)

#: Send something to it: "upload the results to <url>". The destination has to
#: be introduced by "to", "into" or "onto". "Report bugs at <url>" and "Submit a
#: PR at <url>" name a place to go, and the old arm, which took any send verb
#: followed anywhere by a URL, reported both as exfiltration.
_SEND_TO_URL_RE = re.compile(
    r"\b(?P<verb>" + _SEND_VERB + r")\b(?P<obj>[^\n]{0,140}?)\b(?:to|into|onto)\s+"
    r"(?:(?:the|this|that|our|your|their)\s+)?(?:\S+\s+){0,3}?(?P<url>" + _URL_FRAG + r")",
    re.IGNORECASE,
)

#: The command form needs no preposition: `curl -X POST -d @.env <url>`. It has
#: to carry a payload, because sending data is the claim. A bare `POST <url>` in
#: an architecture note, or a `curl -X POST` that triggers a job with only an auth
#: header, sends nothing. Method names match in capitals only, as `GET` does.
_HTTP_SEND_RE = re.compile(
    r"(?:(?-i:\b(?P<method>POST|PUT|PATCH)\b)|\b(?P<client>curl|wget)\b)"
    r"[^\n]{0,140}?(?P<url>" + _URL_FRAG + r")",
    re.IGNORECASE,
)
_PAYLOAD_FLAG_RE = re.compile(
    r"(?<!\S)(?:-d|-F|-T|--data(?:-[a-z]+)?|--form|--json|--upload-file|"
    r"--post-(?:data|file))(?=[\s=@'\"]|$)|(?<!\S)-d@"
)

#: An object that is a contribution, not data: "Report security issues to <url>",
#: "Submit pull requests to <url>". The whole object has to be one of these, so
#: "Report the bug along with ~/.ssh/id_rsa to <url>" is still a directive.
_CONTRIBUTION_NP = (
    r"(?:(?:a|an|the|any|all|your|new|security|bug|feature|pull|merge|potential|"
    r"suspected|possible)\s+){0,3}"
    r"(?:bugs?|bug\s+reports?|issues?|PRs?|pull\s+requests?|merge\s+requests?|"
    r"patch(?:es)?|feedback|vulnerabilit(?:y|ies)|questions?|feature\s+requests?|"
    r"suggestions?|ideas?|contributions?|problems?|tickets?|changes|commits?|"
    r"fix(?:es)?)"
)
_CONTRIBUTION_OBJECT_RE = re.compile(
    _CONTRIBUTION_NP + r"(?:\s*(?:,|\band\b|\bor\b|&|/)\s*" + _CONTRIBUTION_NP + r")*",
    re.IGNORECASE,
)

#: A negation that governs the verb right after it: "never upload", "do not
#: send", "don't ever post", "do not, under any circumstances, upload". A line
#: like "Never upload repository files to <url>" is a guardrail, the opposite of
#: what AAK-AGENT-006 and AAK-AGENT-004 report.
#:
#: It has to sit directly before the verb, never merely somewhere on the line.
#: "Don't use pip, download <url> and run it" negates `use`, and reading any
#: negation as a guardrail would let one leading "don't" switch off every
#: directive after it. "Never forget to upload <data> to <url>" is the same: the
#: negation governs `forget`, and the line still tells the agent to upload.
_NEGATION = r"(?:\bnever|\bnot|\bcannot|n['\u2019]t)\b[\s,]*"
_NEGATION_FILLER = (
    r"(?:(?:ever|even|to|under\s+any\s+circumstances|at\s+any\s+point|at\s+all)\b[\s,]*)*"
)
_NEGATED_BEFORE_VERB_RE = re.compile(_NEGATION + _NEGATION_FILLER + r"$", re.IGNORECASE)

#: "Never upload secrets or send logs to <url>": one negation over two verbs. Only
#: "or" and "nor" carry it; "and" does not reliably. A double negative ("never
#: forget to save or upload ...") is an instruction, so those verbs do not count.
_COORDINATED_RE = re.compile(r"\b(?:or|nor)\s+$", re.IGNORECASE)
_DOUBLE_NEGATIVE = r"(?:forget|hesitate|fail|neglect|skip|omit|miss|stop|refuse|delay)\b"
_GOVERNING_NEGATION_RE = re.compile(
    _NEGATION + _NEGATION_FILLER + r"(?!" + _DOUBLE_NEGATIVE + r")\w",
    re.IGNORECASE,
)
_CLAUSE_BREAK_RE = re.compile(r"[.;:!?](?:\s|$)")
#: A second instruction inside one sentence: "Never commit .env, and set $API_KEY
#: in your shell", "Never delete the backups, but zip the repo or upload ...".
_INSTRUCTION_BREAK_RE = re.compile(
    r",\s*(?:and|but|then|so)\b|\b(?:but|then|instead|however|otherwise)\b",
    re.IGNORECASE,
)

#: Verbs a guardrail forbids for a credential: "never send", "do not print or
#: log", "must not commit". Also the words a negated list of verbs is made of.
_DISCLOSE_VERB = (
    r"(?:send|share|print|echo|log|expose|reveal|output|commit|upload|post|paste|"
    r"include|display|leak|transmit|disclose|email|write|hard-?code|store|copy|"
    r"cat|show|return|embed|put|push|forward|pass|enter|insert|type)"
)
_ANY_VERB_RE = re.compile(
    "(?:" + "|".join((_FETCH_VERB, _ACT_VERB, _SEND_VERB, _DISCLOSE_VERB)) + ")",
    re.IGNORECASE,
)

#: How far before a verb or a credential a negation, a clause break or a command
#: separator is looked for. A governing negation sits beside its verb, so a short
#: window loses nothing. Reading the whole prefix instead, once per verb, made a
#: long crafted line quadratic: 0.6.11 took minutes on 600 KB of "never upload it
#: to <url>", which 0.6.10 scanned in a tenth of a second.
_NEAR = 160


def _negated(line: str, verb_start: int) -> bool:
    """True when a negation governs the verb that starts at ``verb_start``."""
    prefix = line[max(0, verb_start - _NEAR):verb_start]
    if _NEGATED_BEFORE_VERB_RE.search(prefix):
        return True
    if not _COORDINATED_RE.search(prefix):
        return False
    # The "or" carries the negation only inside one instruction ("but", "then"
    # and ", and" end it) and only across a list of verbs: in "Never delete the
    # backups, zip the repo or upload <data> to <url>", "never" governs `delete`.
    clause = _INSTRUCTION_BREAK_RE.split(_CLAUSE_BREAK_RE.split(prefix)[-1])[-1]
    negation = None
    for negation in _GOVERNING_NEGATION_RE.finditer(clause):
        pass
    if negation is None:
        return False
    governed = clause[negation.end() - 1:]
    return all(
        _ANY_VERB_RE.fullmatch(word) for word in re.findall(r",\s*(\w+)", governed)
    )


def _refers_to_fetched(tail: str, url: str) -> re.Match[str] | None:
    """Match when the text after an act verb points back at what was fetched.

    The URL's own file name counts too: "Fetch <url>/setup.sh, then run setup.sh"
    runs what it fetched as surely as "and run it" does.
    """
    ref = _FETCHED_REF_RE.match(tail)
    if ref is not None:
        return ref
    # `_URL_RE` keeps a trailing comma or full stop, so trim it off the name.
    name = urlsplit(url).path.rstrip(".,;:!?").rsplit("/", 1)[-1]
    if len(name) >= 3:
        return re.match(r"\s*\S*" + re.escape(name), tail)
    return None


def _is_loopback(url: str) -> bool:
    """True for a URL on this machine: localhost, 127.0.0.0/8, ::1 or 0.0.0.0.

    Such a URL is not a pointer to content somebody else controls, which is the
    premise of AAK-AGENT-006. On the #771 corpus the commonest HIGH left after
    the contributor-link fix was a dev-server comment, "npm run dev  # Starts at
    http://localhost:3000", read as "run what is at <url>".
    """
    try:
        host = urlsplit(url).hostname
    except ValueError:
        return False
    if not host:
        return False
    host = host.rstrip(".").lower()
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return address.is_loopback or address.is_unspecified


def _fetch_then_act(line: str) -> tuple[str, str] | None:
    """``(evidence, url)`` for "fetch <url> ... act on it", else None."""
    for fetch in _FETCH_VERB_RE.finditer(line):
        if _negated(line, fetch.start()):
            continue
        scheme = _URL_START_RE.search(line, fetch.end(), fetch.end() + 128)
        url = _URL_RE.match(line, scheme.start()) if scheme is not None else None
        if url is None or url.start() - fetch.end() > 120 or _is_loopback(url.group()):
            continue
        window_end = min(len(line), url.end() + 120)
        for act in _ACT_VERB_RE.finditer(line, url.end(), window_end):
            if _negated(line, act.start()):
                continue
            ref = _refers_to_fetched(line[act.end():act.end() + 80], url.group())
            if ref is not None:
                return line[fetch.start():act.end() + ref.end()].strip(), url.group()
        authority = _AUTHORITY_RE.search(line, url.end(), window_end)
        if authority is not None:
            return line[fetch.start():authority.end()].strip(), url.group()
    return None


def _act_at_url(line: str) -> tuple[str, str] | None:
    for act in _ACT_VERB_RE.finditer(line):
        match = _ACT_AT_URL_RE.match(line, act.start())
        if match is None or _negated(line, act.start()) or _is_loopback(match.group("url")):
            continue
        return match.group().strip(), match.group("url")
    return None


def _send_to_url(line: str) -> tuple[str, str] | None:
    for verb in _SEND_VERB_RE.finditer(line):
        match = _SEND_TO_URL_RE.match(line, verb.start())
        if match is None or _negated(line, verb.start()) or _is_loopback(match.group("url")):
            continue
        if _CONTRIBUTION_OBJECT_RE.fullmatch(match.group("obj").strip()):
            continue
        return match.group().strip(), match.group("url")
    return None


def _http_send(command: str) -> tuple[str, str] | None:
    """``(evidence, url)`` for an HTTP client call that carries a payload."""
    for match in _HTTP_SEND_RE.finditer(command):
        if _negated(command, match.start()) or _is_loopback(match.group("url")):
            continue
        if _PAYLOAD_FLAG_RE.search(_command_around(command, match.start(), match.end())):
            return match.group().strip(), match.group("url")
    return None


#: What ends one shell command on a line: a pipe, `;`, `&&`, or the backtick
#: closing an inline code span.
_COMMAND_SPLIT_RE = re.compile(r"\|\|?|;|&&|`")


def _command_around(line: str, start: int, end: int) -> str:
    """The shell command containing ``line[start:end]``. A `-d` belongs to the
    command it is in: `curl <url> | cut -d' ' -f1` sends nothing."""
    floor = max(0, start - _NEAR)
    left = max((m.end() for m in _COMMAND_SPLIT_RE.finditer(line, floor, start)), default=floor)
    ceiling = min(len(line), end + _NEAR)
    right = _COMMAND_SPLIT_RE.search(line, end, ceiling)
    return line[left:right.start() if right else ceiling]


_DIRECTIVE_SHAPES = (_fetch_then_act, _act_at_url, _send_to_url)


def _logical_lines(content: str) -> list[tuple[int, str]]:
    """``(first line number, text)``, with backslash-continued lines joined.

    A shell command split with a trailing backslash is one command, and the
    payload of a `curl -X POST` usually sits on its last line.
    """
    out: list[tuple[int, str]] = []
    lines = content.splitlines()
    index = 0
    while index < len(lines):
        first, text = index + 1, lines[index]
        while text.rstrip().endswith("\\") and index + 1 < len(lines):
            index += 1
            text = text.rstrip()[:-1] + " " + lines[index].strip()
        out.append((first, text))
        index += 1
    return out


def _directive_links(content: str) -> list[tuple[int, str, str]]:
    """``(line, evidence, url)`` for each line whose text acts on a URL.

    Scoped to one line, which is what "the same sentence or list item" means in
    a markdown instruction file: a URL three paragraphs below an unrelated
    "follow" is not a directive about that URL, and matching across the gap is
    how a context rule turns into the blunt one it replaced. The one exception
    is a shell command continued with a trailing backslash, read as one line.
    """
    found_at: dict[int, tuple[str, str]] = {}
    for line_num, line in enumerate(content.splitlines(), 1):
        if "://" not in line:
            continue
        for shape in _DIRECTIVE_SHAPES:
            found = shape(line)
            if found is not None:
                found_at[line_num] = found
                break
    # Only the command form reads across a backslash continuation. Joined prose
    # misreads a program's argument as a directive: `cargo run ... \` followed by
    # `-- "Find top travel books on <url>"` is not "run what is on <url>".
    for line_num, command in _logical_lines(content):
        if line_num not in found_at and "://" in command:
            found = _http_send(command)
            if found is not None:
                found_at[line_num] = found
    return [(line_num, ev, url) for line_num, (ev, url) in sorted(found_at.items())]


# ---- AAK-AGENT-001 / -003: directives, not mentions ----
#
# Both rules used to be bare keyword regexes over the whole file. Re-run on the
# #771 corpus (909 public repositories) for #869, that made 001 (CRITICAL) fire
# on 74 repositories and 003 (HIGH) on 127, and nearly all of it was a mention:
# "Never use `eval()`", a deny-list row of `curl|bash`, `insert.exec();` in a code
# sample, `rm -rf dist`, and the word "bypass" in "never bypass the pre-push
# hooks" or "auth bypass" in a review checklist. 173 of those repositories failed
# `--ci` on these two rules and nothing else.
#
# What they report now is the instruction, the move AAK-AGENT-006 made for links
# in #843. 001: a command that runs code it downloads, or a recursive delete of
# the filesystem root or a home directory. 003: telling the agent to get past a
# named security control, plus the prompt-injection phrases it always matched. A
# guardrail that forbids either is not a finding.

#: What a download can fetch: a URL, a `$VARIABLE` holding one, or a bare host
#: (`get.docker.com`, `example.dev/install`). "`curl ... | bash`" and "`curl|sh`"
#: name nothing, and that is the difference between a deny-list or guardrail
#: quoting the pattern and an installer line running one. On the corpus every
#: pipe-to-shell that named a target was an installer (bun, uv, strix, php.new)
#: and every one that did not was a list of things not to do.
_SHELL_VAR_RE = re.compile(r"\$\{?[A-Za-z_]\w*\}?")
_BARE_HOST_RE = re.compile(r"(?<![\w./-])((?:[A-Za-z0-9-]+\.)+([A-Za-z]{2,24}))(?:(/)|(?=[\s'\")]|$))")
#: A last label that makes `install.sh` a file name rather than a host.
_FILE_SUFFIXES = frozenset({
    "sh", "bash", "zsh", "py", "js", "mjs", "cjs", "ts", "rb", "pl", "php", "ps1",
    "bat", "cmd", "txt", "md", "json", "yaml", "yml", "toml", "lock", "tar", "gz",
    "tgz", "zip", "exe", "deb", "rpm", "conf", "cfg", "ini", "env", "log", "html",
})


def _names_remote(args: str) -> bool:
    """True when a downloader's arguments name something off this machine.

    A loopback URL is a local API, as for AAK-AGENT-006: `curl -s
    http://localhost:8080/props | python3 -m json.tool` reads a dev server.
    """
    if any(not _is_loopback(url.group()) for url in _URL_RE.finditer(args)):
        return True
    if _SHELL_VAR_RE.search(args):
        return True
    return any(
        host.group(3) or host.group(1).count(".") >= 2
        or host.group(2).lower() not in _FILE_SUFFIXES
        for host in _BARE_HOST_RE.finditer(args)
    )


_DOWNLOADER = r"(?:\bcurl|\bwget|\biwr|\birm|\bInvoke-WebRequest|\bInvoke-RestMethod)\b"
_INTERPRETER = (
    r"(?:sudo\s+(?:-\S+\s+)*)?"
    r"(?:(?:ba|z|da|k|fi)?sh|python[0-9.]*|node|perl|ruby|php|iex|"
    r"Invoke-Expression|pwsh|powershell)\b"
)
#: A download piped into an interpreter: `curl -fsSL <url> | bash`,
#: `wget -qO- <url> | sudo sh`, `irm <url> | iex`. The arguments are read up to
#: the first pipe and no further, so `curl <url> | tar xz` is not this, and a line
#: of many `curl`s stays linear (the old `[^\n`]*` read to the end for each one).
_PIPE_TO_SHELL_RE = re.compile(
    _DOWNLOADER + r"(?P<args>[^\n|`]{0,240}?)\|\s*" + _INTERPRETER + r"(?P<after>[^\n|`;&]{0,40})",
    re.IGNORECASE,
)
#: An interpreter given its code on the command line reads the download as data:
#: `| python3 -m json.tool`, `| python -c "import json,sys; ..."`, `| node -e ...`,
#: `| bash -c '...'`. `| sh -s -- --flag` and a bare `| bash` run it.
_STDIN_IS_DATA_RE = re.compile(r"^\s+(?:-[cmerp]\b|--eval\b|--print\b)")
#: A download run through substitution: `/bin/bash -c "$(curl -fsSL <url>)"`
#: (the Homebrew and php.new installers), `eval "$(wget -qO- <url>)"`,
#: `source <(curl -s <url>)`, `bash <(curl -s <url>)`.
_SUBSTITUTED_DOWNLOAD_RE = re.compile(
    r"(?:\b(?:ba|z|da|k)?sh\s+(?:-[A-Za-z]*c\s+)?|\beval\s+|\bsource\s+|(?<![\w./-])\.\s+)"
    r"[\"']?(?:\$\(|<\()\s*" + _DOWNLOADER + r"(?P<args>[^\n)`]{0,240})",
    re.IGNORECASE,
)
#: PowerShell's download-and-run: `iex ((New-Object Net.WebClient).DownloadString(<url>))`,
#: `Invoke-Expression (Invoke-WebRequest <url>)`. `irm <url> | iex` is the pipe form.
_PS_DOWNLOAD_EXEC_RE = re.compile(
    r"\b(?:iex|Invoke-Expression)\b(?P<args>[^\n|;]{0,240}?"
    r"\b(?:DownloadString|iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^\n|;]{0,240})",
    re.IGNORECASE,
)
#: A recursive delete aimed at the filesystem root or a home directory. Build
#: output (`rm -rf dist node_modules`), a temp path or a cache is housekeeping;
#: on the corpus it was 43 of the 173 old findings and none of them was this.
_WIPE_RE = re.compile(
    r"\brm\s+(?P<flags>(?:-{1,2}[\w-]+\s+){1,4})"
    r"(?P<target>[\"']?(?:/\*?|~/?\*?|\$\{?HOME\}?/?\*?)[\"']?)(?=[\s`;&|)]|$)"
)
_RECURSIVE_FLAG_RE = re.compile(r"(?:^|\s)(?:-[A-Za-z]*[rR][A-Za-z]*|--recursive)(?=\s|$)")
#: Where a command starts, so a delete counts only when the text runs it: a shell
#: line or list item (optionally after a `$ ` prompt), after `;`, `&&` or `||`,
#: at a new sentence, or after "run", "then", "with". "...(`rm -rf /` stays
#: hardline-blocked)" describes a test; a deny-list row is a table cell.
_COMMAND_LEAD_RE = re.compile(
    r"(?:^\s*(?:[-*+>]|\d+[.)])?\s*(?:\$\s+)?|(?:;|&&|\|\|)\s*|[.:!?]\s+|"
    r"\b(?:run|execute|exec|type|paste|enter|then|and|try|with)\s+)[`'\"]*$",
    re.IGNORECASE,
)
_TABLE_ROW_RE = re.compile(r"^\s*\|.*\|\s*$")

#: Verbs a guardrail puts between its negation and what it forbids: "never run
#: `curl <url> | sh`", "don't add `-ExecutionPolicy Bypass`", "do not push to
#: `main`, bypass hooks, or skip checks".
_GUARD_VERB = (
    r"(?:run|use|add|pass|call|invoke|execute|exec|type|paste|copy|pipe|set|enable|"
    r"apply|include|try|do|introduce|bypass|skip|disable|ignore|push|commit|merge|"
    r"allow|grant|turn\s+off|switch\s+off)"
)
_NEGATED_COMMAND_RE = re.compile(
    _NEGATION + _NEGATION_FILLER + r"(?:" + _GUARD_VERB + r"\b[\s,]*)?"
    r"(?:(?:the|a|an)\s+)?(?:command\s+)?[`'\"(\s]*$",
    re.IGNORECASE,
)
_NEGATED_GUARD_VERB_RE = re.compile(
    _NEGATION + _NEGATION_FILLER + _GUARD_VERB + r"\b", re.IGNORECASE
)
_LIST_CONTINUATION_RE = re.compile(r"(?:,|\b(?:or|nor))\s*$", re.IGNORECASE)


def _forbidden(line: str, start: int) -> bool:
    """True when a guardrail forbids the command or instruction at ``start``.

    Three shapes: a negation right before it ("never bypass the hooks", "do not
    run `curl <url> | sh`"), the negated verb lists `_negated` already reads for
    AAK-AGENT-006, and one negation over a comma list of instructions ("Do not
    push to `main`, bypass hooks, use `--no-verify`, or skip checks"). The list
    is read back only to the start of its clause, and only while nothing in
    between ends the instruction ("but", "then", ", and ...").
    """
    prefix = line[max(0, start - _NEAR):start]
    if _NEGATED_COMMAND_RE.search(prefix) or _negated(line, start):
        return True
    if not _LIST_CONTINUATION_RE.search(prefix):
        return False
    clause = _CLAUSE_BREAK_RE.split(prefix)[-1]
    head = None
    for head in _NEGATED_GUARD_VERB_RE.finditer(clause):
        pass
    return head is not None and not _INSTRUCTION_BREAK_RE.search(clause, head.end())


def _shell_directives(line: str) -> list[tuple[int, str, str]]:
    """``(offset, kind, command)`` for each command on ``line`` that AAK-AGENT-001 reports."""
    found: list[tuple[int, str, str]] = []
    for pattern in (_PIPE_TO_SHELL_RE, _SUBSTITUTED_DOWNLOAD_RE, _PS_DOWNLOAD_EXEC_RE):
        for match in pattern.finditer(line):
            if not _names_remote(match.group("args")) or _forbidden(line, match.start()):
                continue
            if pattern is _PIPE_TO_SHELL_RE:
                if _STDIN_IS_DATA_RE.match(match.group("after")):
                    continue
                command = line[match.start():match.start("after")]
            else:
                command = match.group()
            found.append((match.start(), "runs downloaded code", command.strip()))
    if not _TABLE_ROW_RE.match(line):
        for match in _WIPE_RE.finditer(line):
            lead = line[max(0, match.start() - _NEAR):match.start()]
            if (
                _RECURSIVE_FLAG_RE.search(match.group("flags"))
                and _COMMAND_LEAD_RE.search(lead)
                and not _forbidden(line, match.start())
            ):
                found.append((match.start(), "recursive delete", match.group().strip()))
    return sorted(found)


#: A named security control. "the pre-push hooks", "CI checks", "authentication".
#: A word like "the type-checker" or "the need for screenshots" is not one.
_SECURITY_CONTROL = (
    r"(?:(?:the|any|all|your|our|these|those|this|that|its|their|every)\s+)?"
    r"(?:[\w-]+\s+){0,2}?"
    r"(?:hooks?|checks?|verification|validation|authentication|authorization|auth|"
    r"sandbox(?:ing)?|permissions?|approvals?|security|safeguards?|guardrails?|guards?|"
    r"protections?|restrictions?|polic(?:y|ies)|firewalls?|signing|signatures?|"
    r"code\s+reviews?|reviews?|ci|2fa|mfa|ssl|tls|certificates?)\b"
)
#: "bypass" as a verb with a control as its object, in the base form an
#: instruction uses. As a noun ("auth bypass", "anti-bot bypass"), with anything
#: else as its object, or describing code ("Pairing bypasses the owner check",
#: "`--no-verify` bypasses hooks") it is not a directive.
_BYPASS_CONTROL_RE = re.compile(r"\bbypass\s+" + _SECURITY_CONTROL, re.IGNORECASE)
#: PowerShell's execution policy switched off for the command the agent runs.
_EXECUTION_POLICY_RE = re.compile(
    r"(?:-ExecutionPolicy|\bSet-ExecutionPolicy)\s+(?:Bypass|Unrestricted)\b", re.IGNORECASE
)
#: "Allow all tools" as an instruction. "Allow all crawlers" (robots.txt) and a
#: UI option quoted in a sentence ("Plugins' Allow all actions") are not.
_ALLOW_ALL_RE = re.compile(
    r"\ballow\s+all\s+(?:the\s+)?(?:tools?|tool\s+calls?|commands?|permissions?|actions?|"
    r"operations?|requests?|network(?:\s+access)?|hosts?|domains?|origins?|file\s+access|"
    r"writes?)\b",
    re.IGNORECASE,
)
_OVERRIDE_PHRASE_RE = re.compile(r"ignore\s+security|skip\s+verification|disable\s+auth", re.IGNORECASE)

#: Where an instruction starts: the start of a line, a new sentence, or after
#: "always", "then", "must" and the like. "Length-1 batches bypass these checks"
#: and "settings can bypass any captcha protection" describe; they do not instruct.
_INSTRUCTION_LEAD_RE = re.compile(
    r"(?:^\s*(?:(?:[-*+>]|\d+[.)])\s+)?|[.;:!?]\s+|\b(?:always|just|please|then|and|or|"
    r"should|must|simply)\s+)[`'\"*_]*$",
    re.IGNORECASE,
)
#: Or the purpose clause of an imperative: "Use `--no-verify` to bypass commit hooks".
_PURPOSE_LEAD_RE = re.compile(
    r"(?:^\s*(?:(?:[-*+>]|\d+[.)])\s+)?|[.;:!?]\s+)(?:use|run|pass|add|set|try|call|"
    r"append|include|enable)\b[^.;:!?\n]{0,120}?\bto\s+$",
    re.IGNORECASE,
)
#: Or permission granted to the reader: "You may bypass the approval prompts",
#: "Feel free to bypass the sandbox". A sentence about something else ("these
#: settings can bypass any captcha protection") grants nothing.
_PERMISSION_LEAD_RE = re.compile(
    r"(?:\byou\s+(?:can|may|could|should|must|need\s+to|are\s+(?:allowed|permitted|free)\s+to)"
    r"|\b(?:free|fine|ok|okay|allowed|permitted|safe)\s+to)\s+(?:always\s+|just\s+|simply\s+)?$",
    re.IGNORECASE,
)
#: Lines that stand alone in markdown, so the line after them starts afresh.
_STRUCTURAL_LINE_RE = re.compile(r"^\s*(?:#|```|~~~|\|)|[.:;!?]['\")*_`]*\s*$")


def _instruction_starts(line: str, start: int, previous: str) -> bool:
    """True when the text at ``start`` opens an instruction rather than continuing one.

    A match that is the first thing on its line opens an instruction only if the
    previous line ended one. Markdown joins wrapped prose, so "npm has been
    restricting tokens that" followed by a line starting "bypass 2FA for writes"
    is one sentence about npm, not an order.
    """
    lead = line[max(0, start - _NEAR):start]
    # A quoted phrase is a name, not an order: a token needs the npm setting
    # **"Bypass 2FA"** enabled.
    if lead.rstrip(" *_").endswith(('"', "\u201c", "'", "\u2018")):
        return False
    if _PURPOSE_LEAD_RE.search(lead) or _PERMISSION_LEAD_RE.search(lead):
        return True
    if not _INSTRUCTION_LEAD_RE.search(lead):
        return False
    if line[:start].strip(" \t`'\"*_"):
        return True
    return not previous.strip() or bool(_STRUCTURAL_LINE_RE.search(previous))


#: A heading or lead-in that turns what follows into prohibitions: "### NEVER",
#: "## Don'ts", "**Forbidden:**", "Never do any of the following:". On the corpus
#: "Use `--no-verify` to bypass commit hooks" read as an order until the heading
#: above it, "### NEVER", was read too.
_PROHIBITION_HEAD_RE = re.compile(
    r"^\s*(?:#{1,6}\s+)?[*_]*\s*(?:never|don['\u2019]?ts?|do\s+not|must\s+not|forbidden|"
    r"prohibited|not\s+allowed|disallowed|banned|avoid|anti-?patterns?|blocked|"
    r"deny(?:-?list)?|denied)\b",
    re.IGNORECASE,
)
_HEADING_RE = re.compile(r"^\s*#{1,6}\s")
_LIST_ITEM_RE = re.compile(r"^\s*(?:[-*+]|\d+[.)])\s+")
_FENCE_RE = re.compile(r"^\s*(?:```|~~~)")


def _prohibited_lines(lines: list[str]) -> set[int]:
    """1-based numbers of the lines a prohibition heading or lead-in governs.

    A heading ("### NEVER") governs everything up to the next heading. A lead-in
    paragraph ending in a colon ("Never do any of the following:") governs the
    list right after it, up to the next paragraph that is not a list item. Inside
    a fenced code block a `#` line is a shell comment, not a heading: "# Don't
    forget to install uv" above `curl ... | sh` does not forbid the install.
    """
    governed: set[int] = set()
    heading_forbids = lead_in_forbids = in_fence = False
    for number, line in enumerate(lines, 1):
        if _FENCE_RE.match(line):
            in_fence = not in_fence
            if heading_forbids:
                governed.add(number)
            continue
        if in_fence:
            if heading_forbids or lead_in_forbids:
                governed.add(number)
            continue
        if _HEADING_RE.match(line):
            heading_forbids = bool(_PROHIBITION_HEAD_RE.match(line))
            lead_in_forbids = False
            continue
        stripped = line.strip()
        if not stripped:
            continue
        if _LIST_ITEM_RE.match(line):
            if heading_forbids or lead_in_forbids:
                governed.add(number)
            continue
        lead_in_forbids = bool(_PROHIBITION_HEAD_RE.match(line)) and stripped.rstrip(" *_").endswith(":")
        if heading_forbids:
            governed.add(number)
    return governed
#: Prompt-injection markers. Reported wherever they appear, and matched over the
#: whole file rather than per line: markdown renders "ignore previous" and
#: "instructions" on two lines as one sentence, so a line break must not hide it.
_PROMPT_INJECTION_RE = re.compile(
    r"ignore\s+previous\s+instructions|you\s+are\s+now|new\s+system\s+prompt",
    re.IGNORECASE,
)


def _security_overrides(line: str, previous: str) -> list[tuple[int, str]]:
    """``(offset, evidence)`` for each instruction on ``line`` that AAK-AGENT-003 reports,
    apart from the prompt-injection phrases, which `_check_content` matches file-wide.

    ``previous`` is the line before, which decides whether a match at the start of
    this line opens an instruction or continues a sentence.
    """
    found: list[tuple[int, str]] = []
    # A flag inside a command the agent runs, wherever it sits on the line.
    for match in _EXECUTION_POLICY_RE.finditer(line):
        if not _forbidden(line, match.start()):
            found.append((match.start(), match.group().strip()))
    for pattern in (_BYPASS_CONTROL_RE, _OVERRIDE_PHRASE_RE, _ALLOW_ALL_RE):
        for match in pattern.finditer(line):
            if _instruction_starts(line, match.start(), previous) and not _forbidden(
                line, match.start()
            ):
                found.append((match.start(), match.group().strip()))
    return sorted(found)

# ---- AAK-AGENT-004: Credential patterns ----
_CREDENTIAL_RE = re.compile(
    r"\$API_KEY|\$SECRET|\$TOKEN|\$PASSWORD|"
    r"\$\{?[A-Z_]*(?:API_KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL)[A-Z_]*\}?|"
    r"\benv\s*\[\s*['\"][A-Z_]*(?:KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL)[A-Z_]*['\"]\s*\]|"
    r"\bos\.environ\s*\[\s*['\"][A-Z_]*(?:KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL)[A-Z_]*['\"]\s*\]|"
    r"\bprocess\.env\.[A-Z_]*(?:KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL)[A-Z_]*\b",
    re.IGNORECASE,
)

# A guardrail names a credential in order to forbid disclosing it: "Never send
# $AWS_SECRET_ACCESS_KEY anywhere", "$GITHUB_TOKEN must never be printed". Raised
# in #771 with the AAK-AGENT-002 severity. Reporting that line as a credential
# reference flags the safety instruction itself, so the negation has to govern a
# disclosure verb in the same sentence. "Never forget to export $API_KEY" negates
# `forget`, not a disclosure, and is still reported.
_FORBIDDEN_DISCLOSURE_RE = re.compile(
    _NEGATION + _NEGATION_FILLER + r"\b" + _DISCLOSE_VERB + r"\b", re.IGNORECASE
)
_FORBIDDEN_PASSIVE_RE = re.compile(
    r"\b(?:(?:must|should|may|can|will|is|are)\s+(?:never|not)|"
    r"(?:mustn|shouldn|can|won|isn|aren)['\u2019]t)\s+(?:ever\s+)?be\s+"
    r"(?:sent|shared|printed|echoed|logged|exposed|revealed|output|committed|"
    r"uploaded|posted|pasted|included|displayed|leaked|transmitted|disclosed|"
    r"emailed|written|hard-?coded|stored|copied|shown|returned|embedded|put|"
    r"pushed|forwarded|passed|entered|inserted|typed)\b",
    re.IGNORECASE,
)
#: More verbs under the same negation: "Do not print, log or send $TOKEN".
_VERB_LIST_RE = re.compile(
    r"(?:\s*,\s*|\s+)(?:(?:or|and|nor)\s+)?" + _DISCLOSE_VERB + r"\b", re.IGNORECASE
)
#: After the negated verb has its object, a comma begins a new instruction unless
#: the list goes on: another credential ("Never print $A, $B or $C"), a
#: conjunction, or an object with a determiner. In "Never print $GITHUB_TOKEN, log
#: $AWS_SECRET_ACCESS_KEY to the console" the second credential is an instruction.
_LIST_CONTINUES_RE = re.compile(
    r",\s*(?:(?:or|and|nor|the|a|an|any|your|our|its|their|even|including|"
    r"especially|like)\b|[$`'\"]|process\.env|os\.environ|env\s*\[)",
    re.IGNORECASE,
)


def _forbids_disclosure(content: str, offset: int) -> bool:
    """True when the credential reference at ``offset`` sits in a guardrail.

    Reads at most `_NEAR` characters either side, like `_negated`: a file with
    thousands of credential references on one line stays linear.
    """
    lo, hi = max(0, offset - _NEAR), min(len(content), offset + _NEAR)
    newline = content.rfind("\n", lo, offset)
    start = newline + 1 if newline != -1 else lo
    newline = content.find("\n", offset, hi)
    line = content[start:newline if newline != -1 else hi]
    col = offset - start
    breaks = [m.end() for m in _CLAUSE_BREAK_RE.finditer(line, 0, col)]
    following = _CLAUSE_BREAK_RE.search(line, col)
    sentence = breaks[-1] if breaks else 0
    before = line[sentence:col]
    after = line[col:following.start() if following else len(line)]
    for verb in _FORBIDDEN_DISCLOSURE_RE.finditer(before):
        gap_start = sentence + verb.end()
        more = _VERB_LIST_RE.match(line, gap_start, col)
        while more is not None:
            gap_start = more.end()
            more = _VERB_LIST_RE.match(line, gap_start, col)
        gap = line[gap_start:col]
        if _INSTRUCTION_BREAK_RE.search(gap):
            continue
        # Each comma is judged by what follows it, which may be this credential.
        if all(_LIST_CONTINUES_RE.match(line, gap_start + c.start()) for c in re.finditer(",", gap)):
            return True
    passive = _FORBIDDEN_PASSIVE_RE.search(after)
    return passive is not None and not _INSTRUCTION_BREAK_RE.search(after[:passive.start()])

# ---- AAK-AGENT-005: Hidden content ----
_HTML_COMMENT_RE = re.compile(r"<!--[\s\S]*?-->")

# Comments that are a tool's own bookkeeping, matched against that tool's whole
# syntax. The Claude Code auto-memory plugin writes sixteen section markers into
# a root CLAUDE.md, and once each comment reached code scanning as its own alert
# they buried the comments this rule exists for.
#
# The exemption is a grammar, not a prefix: fixed keywords, a known section name,
# `MDnnn` rule ids, and nowhere to put a sentence. A keyword followed by free
# text is free text, an unknown section name is a free-form phrase, and
# markdownlint's rule aliases are words rather than ids, so all of those still
# report. Length is no test: a short comment hides a command as well as a long one.
# A link reference definition is never rendered, and one whose destination is `#`
# or `<>` exists only to carry its title: `[//]: # (text)` is how Markdown writes a
# comment, and the HTML-comment pattern never saw it. Up to three spaces of indent
# (four is a code block), one line, a title in (), "" or ''. A definition that
# points somewhere is a link, and one with no title carries no text, so neither is
# reported.
_REFDEF_COMMENT_RE = re.compile(
    r"""^[ ]{0,3}\[[^\]\n]+\]:[ \t]*(?:\#|<>)[ \t]+"""
    r"""(?:\((?P<p>[^)\n]*)\)|"(?P<d>[^"\n]*)"|'(?P<s>[^'\n]*)')[ \t]*$""",
    re.MULTILINE,
)

_AUTO_MEMORY_SECTIONS = (
    "project-description", "build-commands", "architecture", "conventions",
    "patterns", "git-insights", "best-practices", "module-description",
    "dependencies",
)
_TOOL_MARKER_RE = re.compile(
    r"<!--\s*(?:"
    r"AUTO-MANAGED:\s*(?:" + "|".join(_AUTO_MEMORY_SECTIONS) + r")"
    r"|END AUTO-MANAGED|MANUAL|END MANUAL"
    r"|markdownlint-(?:disable|enable)(?:-next-line|-line|-file)?(?:\s+[Mm][Dd]\d{3})*"
    r"|markdownlint-(?:capture|restore)"
    r"|prettier-ignore(?:-start|-end)?"
    r")\s*-->"
)
_ZERO_WIDTH_CHARS = frozenset({
    "\u200b",  # zero-width space
    "\u200c",  # zero-width non-joiner
    "\u200d",  # zero-width joiner
    "\ufeff",  # byte order mark / zero-width no-break space
    "\u2060",  # word joiner
    "\u202e",  # right-to-left override
})

# Three of those characters do ordinary work in ordinary text, and reporting
# them as "hidden content" told writers of several scripts that their language
# is suspicious. Raised in #771 alongside the AAK-AGENT-002 severity: emoji ZWJ
# sequences, a leading BOM, and Hindi and Persian joiners were all reported at
# MEDIUM.
#
# What stays reportable is placement, not identity. U+200C and U+200D between
# letters of one script are spelling, and so are they right after that script's
# virama: Devanagari needs U+200D for a conjunct or a half form and U+200C to
# break one, Persian needs U+200C for a word like "می‌رود". U+200D
# between two emoji is how a single glyph is composed. A BOM at offset 0 is a
# file-encoding marker every editor writes.
#
# The same characters anywhere else still fire, because that is where they hide
# text: a joiner between a letter and a space, between two scripts, or inside a
# run of ASCII is doing nothing a reader can see. U+200B, U+2060 and U+202E are
# never exempt -- none of them is required to spell anything, and U+202E
# reverses display order, which is the trick itself.
_CONTEXTUAL_ZERO_WIDTH = frozenset({"\u200c", "\u200d"})

#: Scripts whose orthography uses U+200C / U+200D between letters. Read off
#: `unicodedata.name`, which prefixes every letter with its script, so this is
#: the script name rather than a hand-kept codepoint range.
_JOINER_SCRIPTS = frozenset({
    "DEVANAGARI", "BENGALI", "GURMUKHI", "GUJARATI", "ORIYA", "TAMIL",
    "TELUGU", "KANNADA", "MALAYALAM", "SINHALA",
    "ARABIC", "SYRIAC", "THAANA", "NKO", "HEBREW",
    "MYANMAR", "KHMER", "TIBETAN", "MONGOLIAN", "JAVANESE", "BALINESE",
})


def _script_of(char: str) -> str | None:
    """The script name `unicodedata` gives a letter or a combining mark, else None.

    Marks count because Indic orthography puts the joiner right after one. The
    Hindi half form of क before ष is written क, virama (DEVANAGARI SIGN
    VIRAMA, a mark, not a letter), U+200D, ष. 0.6.8 compared letters only, so
    it saw a mark on the left and reported the joiner it had claimed to stop
    reporting (#771).
    """
    if not (char.isalpha() or unicodedata.category(char).startswith("M")):
        return None
    try:
        name = unicodedata.name(char)
    except ValueError:
        return None
    return name.split()[0]


def _is_emoji(char: str) -> bool:
    """Close enough for the ZWJ case: a pictographic or regional-indicator code point.

    `unicodedata` exposes no Emoji property, so this is a range test over the
    blocks a ZWJ sequence actually draws from. It decides only whether a joiner
    between two of them is ordinary, never whether anything is a finding.
    """
    cp = ord(char)
    return (
        0x1F300 <= cp <= 0x1FAFF      # pictographs, symbols, emoji extensions
        or 0x1F000 <= cp <= 0x1F0FF   # mahjong/domino/cards
        or 0x2600 <= cp <= 0x27BF     # misc symbols and dingbats
        or 0x1F1E6 <= cp <= 0x1F1FF   # regional indicators (flags)
        or cp in {0x2640, 0x2642, 0x2695, 0x2708, 0x2764, 0xFE0F}
    )


def _zero_width_is_expected(text: str, index: int, at_file_start: bool = False) -> bool:
    """True when the zero-width char at `index` is doing ordinary work.

    Exemptions, and nothing wider:

    * U+FEFF at offset 0 **of the file** — an encoding marker, not content.
      `at_file_start` is passed in rather than derived from `index`, because
      `index` is an offset into one line and a BOM at the start of line five is
      not an encoding marker.
    * U+200C / U+200D between two letters, or a letter and a mark such as a
      virama, of the SAME joiner-using script.
      Requiring one script is what keeps the exemption from covering a joiner
      spliced between two alphabets, which is a way to hide a word boundary.
    * U+200D between two emoji — one composed glyph.
    """
    char = text[index]
    if char == "\ufeff":
        return at_file_start
    if char not in _CONTEXTUAL_ZERO_WIDTH:
        return False
    if index == 0 or index + 1 >= len(text):
        return False
    before, after = text[index - 1], text[index + 1]

    left, right = _script_of(before), _script_of(after)
    if left is not None and left == right and left in _JOINER_SCRIPTS:
        return True

    if char == "\u200d" and _is_emoji(before) and _is_emoji(after):
        return True
    return False


def _find_agent_config_files(project_root: Path) -> list[Path]:
    """Locate agent configuration / instruction files in the project."""
    found: list[Path] = []
    for rel in _AGENT_CONFIG_FILES:
        p = project_root / rel
        if p.is_file():
            found.append(p)
    return found


def _line_at(content: str, offset: int) -> int:
    """1-based line of the character at ``offset``, counted as ``str.splitlines`` counts.

    Findings used to locate their line by searching the file for their own
    evidence, which always lands on the first occurrence: the second copy of a
    repeated URL or directive pointed at the first, an earlier line that merely
    contained the evidence as a substring took the finding, and every HTML
    comment, searched for as the literal "<!--", carried the first comment's
    line. A regex match already knows where it is.

    Counting as ``splitlines`` does keeps these numbers identical to
    ``find_line_number`` and to the zero-width walk wherever the evidence is not
    repeated. ``"a\\n".splitlines()`` is one line although offset 2 opens line 2,
    so a sentinel character keeps that line counted.
    """
    return len((content[:offset] + "\0").splitlines())


def _check_content(
    content: str,
    rel_path: str,
) -> list[Finding]:
    """Run all six rules against the text content of a single file."""
    findings: list[Finding] = []

    lines = content.splitlines()
    prohibited = _prohibited_lines(lines)

    # AAK-AGENT-001: a command that runs downloaded code or wipes a root or home
    # directory, unless a guardrail forbids it
    for line_num, line in enumerate(lines, 1):
        if line_num in prohibited:
            continue
        for _, kind, command in _shell_directives(line):
            findings.append(make_finding(
                "AAK-AGENT-001",
                rel_path,
                f"Shell directive ({kind}): {command[:200]}",
                line_num,
            ))

    # AAK-AGENT-006: a link the text tells the agent to act on. HIGH, and
    # reported before 002 so the directive is what a reader sees first.
    directive_urls: set[str] = set()
    for line_num, evidence, url in _directive_links(content):
        directive_urls.add(url)
        findings.append(make_finding(
            "AAK-AGENT-006",
            rel_path,
            f"Directive on an external URL: {evidence[:200]}",
            line_num,
        ))

    # AAK-AGENT-002: a link to a host outside the documentation allowlist. LOW —
    # it is something to look at, not something that has happened. A URL already
    # reported by 006 is not repeated here: the directive is the finding, and
    # naming the same link twice at two severities reads as two problems.
    for match in _URL_RE.finditer(content):
        url = match.group()
        if url in directive_urls:
            continue
        if not _is_safe_host(url):
            findings.append(make_finding(
                "AAK-AGENT-002",
                rel_path,
                f"External URL: {url[:200]}",
                _line_at(content, match.start()),
            ))

    # AAK-AGENT-003: an instruction to get past a named security control, unless a
    # guardrail forbids it, and the prompt-injection phrases anywhere in the file
    overrides = [
        (_line_at(content, match.start()), match.group().strip())
        for match in _PROMPT_INJECTION_RE.finditer(content)
    ]
    for line_num, line in enumerate(lines, 1):
        if line_num in prohibited:
            continue
        previous = lines[line_num - 2] if line_num > 1 else ""
        overrides.extend(
            (line_num, evidence) for _, evidence in _security_overrides(line, previous)
        )
    for line_num, evidence in sorted(overrides):
        findings.append(make_finding(
            "AAK-AGENT-003",
            rel_path,
            f"Security override: {evidence}",
            line_num,
        ))

    # AAK-AGENT-004: Credential patterns, unless the sentence forbids disclosing it
    for match in _CREDENTIAL_RE.finditer(content):
        if _forbids_disclosure(content, match.start()):
            continue
        evidence = match.group().strip()
        findings.append(make_finding(
            "AAK-AGENT-004",
            rel_path,
            f"Credential reference: {evidence}",
            _line_at(content, match.start()),
        ))

    # AAK-AGENT-005: Hidden content
    # HTML comments
    for match in _HTML_COMMENT_RE.finditer(content):
        comment = match.group()
        if _TOOL_MARKER_RE.fullmatch(comment):
            continue
        findings.append(make_finding(
            "AAK-AGENT-005",
            rel_path,
            f"HTML comment: {comment[:120]}{'...' if len(comment) > 120 else ''}",
            _line_at(content, match.start()),
        ))

    # Link reference definitions used as comments: `[//]: # (text)`.
    for match in _REFDEF_COMMENT_RE.finditer(content):
        title = next(g for g in match.group("p", "d", "s") if g is not None)
        if not title.strip():
            continue
        line = match.group().strip()
        findings.append(make_finding(
            "AAK-AGENT-005",
            rel_path,
            f"Markdown comment: {line[:120]}{'...' if len(line) > 120 else ''}",
            _line_at(content, match.start()),
        ))

    # Zero-width / invisible Unicode characters.
    #
    # Walked per OCCURRENCE rather than per line, because the decision needs the
    # neighbours: the same code point is spelling in one position and concealment
    # in another. The old loop asked only whether the character appeared anywhere
    # on the line, which cannot tell those apart and reported every Devanagari
    # conjunct, every Persian ZWNJ, every emoji ZWJ sequence and every file with
    # a BOM. Still one finding per line, so a paragraph of Hindi with one spliced
    # joiner reports once.
    for line_num, line in enumerate(content.splitlines(), 1):
        for index, char in enumerate(line):
            if char not in _ZERO_WIDTH_CHARS:
                continue
            # Offset 0 of line 1 is the only position that is offset 0 of the file.
            at_file_start = line_num == 1 and index == 0
            if _zero_width_is_expected(line, index, at_file_start):
                continue
            codepoint = f"U+{ord(char):04X}"
            findings.append(make_finding(
                "AAK-AGENT-005",
                rel_path,
                f"Hidden Unicode character {codepoint} found",
                line_num,
            ))
            break  # one finding per line is sufficient

    return findings


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    """Scan agent configuration files for security issues.

    Args:
        project_root: The root directory of the project to scan.

    Returns:
        A tuple of (list of findings, set of scanned file relative paths).
    """
    findings: list[Finding] = []
    scanned_files: set[str] = set()

    for config_path in _find_agent_config_files(project_root):
        try:
            content = config_path.read_text(encoding="utf-8", errors="ignore")
            if len(content) > 1_000_000:
                continue
        except OSError:
            continue

        rel_path = str(config_path.relative_to(project_root))
        scanned_files.add(rel_path)
        findings.extend(_check_content(content, rel_path))

    # AAK-CLAUDE-WIN-001: CVE-2026-35603 Windows ProgramData hijack.
    # Fires when a managed-settings.json lives under a ProgramData path
    # without a sibling setup.ps1 that runs icacls hardening.
    findings.extend(_check_claude_win_programdata(project_root, scanned_files))

    return findings, scanned_files


def _check_claude_win_programdata(
    project_root: Path,
    scanned_files: set[str],
) -> list[Finding]:
    """CVE-2026-35603: managed-settings.json under %ProgramData% needs
    a sibling setup.ps1 that runs `icacls` to harden the ACL. Fires on
    any `managed-settings.json` whose path contains `programdata`
    (case-insensitive) and whose directory lacks the hardening script."""
    import re as _re

    findings: list[Finding] = []
    for candidate in project_root.rglob("managed-settings.json"):
        path_lower = str(candidate).lower()
        if "programdata" not in path_lower:
            continue
        rel = str(candidate.relative_to(project_root))
        scanned_files.add(rel)
        sibling = candidate.parent / "setup.ps1"
        if not sibling.is_file():
            findings.append(make_finding(
                "AAK-CLAUDE-WIN-001",
                rel,
                "managed-settings.json under ProgramData without sibling setup.ps1 ACL hardener",
            ))
            continue
        try:
            ps1_text = sibling.read_text(encoding="utf-8", errors="replace")
        except OSError:
            ps1_text = ""
        if not _re.search(r"\bicacls\b", ps1_text, _re.IGNORECASE):
            findings.append(make_finding(
                "AAK-CLAUDE-WIN-001",
                rel,
                f"setup.ps1 next to {rel} does not run icacls to restrict ACLs",
            ))
    return findings

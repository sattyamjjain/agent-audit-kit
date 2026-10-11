"""The labels of a `Field | Value` table are row headers on the built site (WCAG 1.3.1).

Fifteen docs pages open with a two-column table of facts: the 13 hand-written rule
pages and two preset pages. Markdown has no syntax for a row header, so the labels in
the first column were `<td>`, and a screen reader read "HIGH" without saying it was
the severity. The sources cannot become definition lists, because GitHub renders those
files too and does not render a definition list, so `scripts/mkdocs_hooks.py` fixes the
built HTML instead (`on_page_content`).

These tests hold three things: the rewrite is exact (everything else on the page, and
every other table, comes out as it went in), it reaches every page that has such a
table on the built site, and the sources stay plain Markdown tables.
"""

from __future__ import annotations

import importlib.util
import sys
from html.parser import HTMLParser
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
DOCS = REPO_ROOT / "docs"
FACT_HEADER = "| Field | Value |"


def _hooks():
    pytest.importorskip("mkdocs.structure.files", reason="mkdocs is not installed")
    spec = importlib.util.spec_from_file_location(
        "mkdocs_hooks_row_headers", REPO_ROOT / "scripts" / "mkdocs_hooks.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["mkdocs_hooks_row_headers"] = module  # dataclasses resolve their own module
    spec.loader.exec_module(module)
    return module


hooks = _hooks()

_TABLE = (
    "<table>\n<thead>\n<tr>\n<th>Field</th>\n<th>Value</th>\n</tr>\n</thead>\n<tbody>\n"
    "<tr>\n<td>Severity</td>\n<td>HIGH</td>\n</tr>\n"
    "<tr>\n<td>Scanner</td>\n<td><code>x.py</code></td>\n</tr>\n"
    "</tbody>\n</table>"
)
_CONVERTED = (
    '<table>\n<thead>\n<tr>\n<th scope="col">Field</th>\n<th scope="col">Value</th>\n</tr>\n</thead>\n<tbody>\n'
    '<tr>\n<th scope="row">Severity</th>\n<td>HIGH</td>\n</tr>\n'
    '<tr>\n<th scope="row">Scanner</th>\n<td><code>x.py</code></td>\n</tr>\n'
    "</tbody>\n</table>"
)


def _table(*header: str, rows: tuple[tuple[str, ...], ...] = (("a", "b", "c"),)) -> str:
    head = "".join(f"<th>{name}</th>\n" for name in header)
    body = "".join(
        "<tr>\n" + "".join(f"<td>{cell}</td>\n" for cell in row[: len(header)]) + "</tr>\n" for row in rows
    )
    return f"<table>\n<thead>\n<tr>\n{head}</tr>\n</thead>\n<tbody>\n{body}</tbody>\n</table>"


# --------------------------------------------------------------------------
# The rewrite
# --------------------------------------------------------------------------


def test_the_labels_of_a_field_value_table_become_row_headers() -> None:
    page = f"<h1>AAK-X-001</h1>\n{_TABLE}\n<p>after</p>"
    assert hooks.row_headers(page) == f"<h1>AAK-X-001</h1>\n{_CONVERTED}\n<p>after</p>"


def test_the_hook_is_the_function_mkdocs_calls() -> None:
    assert hooks.on_page_content(_TABLE, page=None, config=None, files=None) == _CONVERTED


def test_everything_else_is_written_back_as_it_was() -> None:
    """Attributes, entities, comments, void tags and code are copied, not re-encoded."""
    page = (
        '<!-- keep me -->\n<p>a &lt; b &amp; c &#61; d &#x27;e&#x27; <a href="x?y=1&amp;z=2" title=\'q\'>l</a></p>\n'
        '<table class="t">\n<thead>\n<tr>\n<th style="text-align: left;">Field</th>\n<th>Value</th>\n</tr>\n</thead>\n'
        '<tbody>\n<tr>\n<td style="text-align: left;">A &amp; B</td>\n<td><code>&lt;x&gt;</code></td>\n</tr>\n'
        "<tr>\n<td><code>c</code></td>\n<td><br />two<br></td>\n</tr>\n</tbody>\n</table>\n"
        '<pre><code class="language-bash"># c &amp;&amp; d\n</code></pre>\n<hr />'
    )
    expected = (
        '<!-- keep me -->\n<p>a &lt; b &amp; c &#61; d &#x27;e&#x27; <a href="x?y=1&amp;z=2" title=\'q\'>l</a></p>\n'
        '<table class="t">\n<thead>\n<tr>\n<th style="text-align: left;" scope="col">Field</th>\n'
        '<th scope="col">Value</th>\n</tr>\n</thead>\n'
        '<tbody>\n<tr>\n<th style="text-align: left;" scope="row">A &amp; B</th>\n<td><code>&lt;x&gt;</code></td>\n</tr>\n'
        '<tr>\n<th scope="row"><code>c</code></th>\n<td><br />two<br></td>\n</tr>\n</tbody>\n</table>\n'
        '<pre><code class="language-bash"># c &amp;&amp; d\n</code></pre>\n<hr />'
    )
    assert hooks.row_headers(page) == expected


def test_the_rewrite_is_idempotent() -> None:
    once = hooks.row_headers(_TABLE)
    assert hooks.row_headers(once) is once


@pytest.mark.parametrize(
    "page",
    [
        pytest.param(_table("Rule", "Severity", "Title"), id="three columns"),
        pytest.param(_table("Rule", "Severity", "Class", "CVE / source"), id="four columns"),
        pytest.param(_table("Name", "Description"), id="two columns, other headings"),
        pytest.param(_table("Field", "Value", "Notes"), id="Field | Value | Notes"),
        pytest.param(_table("Value", "Field"), id="the headings the other way round"),
        pytest.param(_table("Field"), id="one column"),
        pytest.param(
            "<table>\n<tbody>\n<tr>\n<td>Field</td>\n<td>Value</td>\n</tr>\n</tbody>\n</table>",
            id="no header row",
        ),
        pytest.param("<p>No table here.</p>\n<ul>\n<li>Field</li>\n<li>Value</li>\n</ul>", id="no table"),
        pytest.param("", id="empty"),
    ],
)
def test_an_ordinary_table_is_left_exactly_alone(page: str) -> None:
    """The very same string comes back, so nothing about it can have been re-serialised."""
    assert hooks.row_headers(page) is page


def test_only_the_field_value_table_on_a_page_with_several_is_changed() -> None:
    ordinary = _table("Rule", "Severity", "Title", rows=(("AAK-X-001", "HIGH", "A title"),))
    page = f"{ordinary}\n<p>between</p>\n{_TABLE}\n<p>between</p>\n{ordinary}"
    assert hooks.row_headers(page) == f"{ordinary}\n<p>between</p>\n{_CONVERTED}\n<p>between</p>\n{ordinary}"


def test_a_two_column_table_that_only_looks_like_one_is_still_ordinary() -> None:
    page = _table("Field", "Value", rows=(("only", "one"),)).replace("Field", "Name")
    assert hooks.row_headers(page) is page


def test_the_heading_match_ignores_case_and_spacing() -> None:
    page = _TABLE.replace("<th>Field</th>", "<th> field </th>").replace("<th>Value</th>", "<th><strong>VALUE</strong></th>")
    converted = hooks.row_headers(page)
    assert '<th scope="row">Severity</th>' in converted and '<th scope="col"> field </th>' in converted


def test_a_label_cell_with_nothing_in_it_stays_a_td() -> None:
    """An empty header cell is a fault of its own, so it is left as it was."""
    page = _table("Field", "Value", rows=(("", "empty label"), (" \n ", "blank label"), ("<code>x</code>", "kept")))
    converted = hooks.row_headers(page)
    assert converted.count('<th scope="row">') == 1
    assert "<td></td>\n<td>empty label</td>" in converted
    assert '<th scope="row"><code>x</code></th>' in converted


def test_a_cell_that_already_says_what_it_is_is_left_alone() -> None:
    page = _TABLE.replace("<td>Severity</td>", '<td scope="row">Severity</td>')
    converted = hooks.row_headers(page)
    assert '<td scope="row">Severity</td>' in converted  # the author's own attribute is respected
    assert '<th scope="row">Scanner</th>' in converted  # the next row is still converted


def test_a_cell_whose_end_tag_was_left_out_is_left_as_written() -> None:
    """HTML lets `</td>` be omitted. A cell is only rewritten once it is seen to close, so a
    page written that way keeps its tags paired instead of getting a `<th>` closed by `</td>`."""
    page = _TABLE.replace("<td>Severity</td>", "<td>Severity")  # the label cell never closes
    converted = hooks.row_headers(page)
    assert "<tr>\n<td>Severity\n<td>HIGH</td>\n</tr>" in converted  # left as it was written
    assert '<th scope="row">Scanner</th>' in converted  # the well-formed row after it is still converted
    opened = converted.count("<th ") + converted.count("<th>")
    assert opened == converted.count("</th>") == 3  # every <th> opened is closed as a <th>
    # And with the end tag of the *second* cell missing instead, the first still converts.
    later = hooks.row_headers(_TABLE.replace("<td>HIGH</td>", "<td>HIGH"))
    assert '<th scope="row">Severity</th>\n<td>HIGH\n</tr>' in later


def test_a_table_inside_a_cell_is_judged_on_its_own() -> None:
    inner = _table("Rule", "Severity", "Title", rows=(("AAK-X-001", "HIGH", "T"),))
    page = _TABLE.replace("<td>HIGH</td>", f"<td>{inner}</td>")
    converted = hooks.row_headers(page)
    assert inner in converted  # the nested ordinary table is untouched
    assert '<th scope="row">Severity</th>' in converted and '<th scope="row">Scanner</th>' in converted
    inside_field_value = _TABLE.replace("<td>HIGH</td>", f"<td>{_TABLE}</td>")
    nested = hooks.row_headers(inside_field_value)
    assert nested.count('scope="row"') == 4  # two rows in each of the two tables


# --------------------------------------------------------------------------
# What it does to the real pages
# --------------------------------------------------------------------------


class _Events(HTMLParser):
    """The tokens of a page, with text nodes merged, for comparing two serialisations."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=False)
        self.events: list[tuple] = []

    def _add(self, event: tuple) -> None:
        if event[0] == "data" and self.events and self.events[-1][0] == "data":
            self.events[-1] = ("data", self.events[-1][1] + event[1])
        else:
            self.events.append(event)

    def handle_starttag(self, tag: str, attrs: list) -> None:
        self._add(("start", tag, tuple(attrs)))

    def handle_startendtag(self, tag: str, attrs: list) -> None:
        self._add(("startend", tag, tuple(attrs)))

    def handle_endtag(self, tag: str) -> None:
        self._add(("end", tag))

    def handle_data(self, data: str) -> None:
        self._add(("data", data))

    def handle_entityref(self, name: str) -> None:
        self._add(("data", f"&{name};"))

    def handle_charref(self, name: str) -> None:
        self._add(("data", f"&#{name};"))

    def handle_comment(self, data: str) -> None:
        self._add(("comment", data))


def _events(html: str) -> list[tuple]:
    parser = _Events()
    parser.feed(html)
    parser.close()
    return parser.events


def _undo(events: list[tuple]) -> list[tuple]:
    """The events with the intended edits taken back out: `th scope=row` is a `td`, and `scope=col` is gone."""
    restored: list[tuple] = []
    row_cells: list[bool] = []  # per open <th>: was it a converted label cell?
    for event in events:
        if event[0] == "start" and event[1] == "th":
            attrs = dict(event[2])
            scope = attrs.pop("scope", None)
            row_cells.append(scope == "row")
            restored.append(("start", "td" if scope == "row" else "th", tuple(attrs.items())))
        elif event[0] == "end" and event[1] == "th":
            restored.append(("end", "td" if row_cells.pop() else "th"))
        else:
            restored.append(event)
    return restored


def _sources_with_a_fact_table() -> list[Path]:
    return sorted(
        path
        for path in DOCS.rglob("*.md")
        if any(line.strip() == FACT_HEADER for line in path.read_text(encoding="utf-8").splitlines())
    )


def test_the_pages_with_a_fact_table_are_the_fifteen_this_was_written_for() -> None:
    sources = _sources_with_a_fact_table()
    names = {path.relative_to(DOCS).as_posix() for path in sources}
    own = {f"rules/{path.name}" for path in (DOCS / "rules").glob("AAK-*.md")}
    assert own and own <= names, f"hand-written rule pages without a fact table: {sorted(own - names)}"
    assert {"presets/mcp-2026-07-28.md", "presets/mcp-ox-2026-04.md"} <= names
    assert len(sources) >= 15


def test_rewriting_a_real_page_changes_nothing_but_the_row_headers() -> None:
    markdown = pytest.importorskip("markdown")
    for source in _sources_with_a_fact_table():
        text = source.read_text(encoding="utf-8")
        assert "<th" not in text and "<td" not in text, f"{source.name}: the source must stay a Markdown table"
        html = markdown.Markdown(extensions=["tables", "fenced_code", "toc", "def_list", "admonition"]).convert(text)
        rewritten = hooks.row_headers(html)
        assert rewritten != html, f"{source.name}: nothing was changed"
        assert _undo(_events(rewritten)) == _events(html), f"{source.name}: more than the row headers changed"


# --------------------------------------------------------------------------
# What it does to the built site
# --------------------------------------------------------------------------


class _Tables(HTMLParser):
    """Every table on a page: its header rows and body rows, each cell as (tag, scope, text)."""

    def __init__(self) -> None:
        super().__init__()
        self.tables: list[dict] = []
        self._open: list[dict] = []

    def handle_starttag(self, tag: str, attrs: list) -> None:
        if tag == "table":
            table = {"head": [], "rows": [], "in_head": False, "row": None, "cell": None}
            self.tables.append(table)
            self._open.append(table)
        elif self._open:
            table = self._open[-1]
            if tag == "thead":
                table["in_head"] = True
            elif tag == "tr":
                table["row"] = []
            elif tag in {"th", "td"}:
                table["cell"] = [tag, dict(attrs).get("scope"), []]

    def handle_data(self, data: str) -> None:
        if self._open and self._open[-1]["cell"] is not None:
            self._open[-1]["cell"][2].append(data)

    def handle_endtag(self, tag: str) -> None:
        if not self._open:
            return
        table = self._open[-1]
        if tag in {"th", "td"} and table["cell"] is not None and table["row"] is not None:
            tag_name, scope, text = table["cell"]
            table["row"].append((tag_name, scope, "".join(text).strip()))
            table["cell"] = None
        elif tag == "tr" and table["row"] is not None:
            (table["head"] if table["in_head"] else table["rows"]).append(table["row"])
            table["row"] = None
        elif tag == "thead":
            table["in_head"] = False
        elif tag == "table":
            self._open.pop()


def _tables(html: str) -> list[dict]:
    parser = _Tables()
    parser.feed(html)
    parser.close()
    return parser.tables


def _is_fact_table(table: dict) -> bool:
    return [[text for _tag, _scope, text in row] for row in table["head"]] == [["Field", "Value"]]


@pytest.fixture(scope="module")
def site(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """The docs, built by MkDocs from the real mkdocs.yml, so the hook runs as it does on deploy."""
    pytest.importorskip("mkdocs.commands.build")
    from mkdocs.commands import build
    from mkdocs.config import load_config

    site_dir = tmp_path_factory.mktemp("built") / "site"
    config = load_config(
        config_file=str(REPO_ROOT / "mkdocs.yml"),
        site_dir=str(site_dir),
        # The deployed site uses Material; the markup under test does not depend on a theme,
        # and CI installs MkDocs alone, so build with the built-in one.
        theme="mkdocs",
        markdown_extensions=["tables", "admonition", "def_list"],
    )
    build.build(config)
    return site_dir


def _built_path(source: Path) -> Path:
    relative = source.relative_to(DOCS).with_suffix("")
    return relative / "index.html" if relative.name != "index" else relative.with_suffix(".html")


def _source_rows(text: str) -> int:
    """How many body rows the Markdown table headed `Field | Value` has."""
    lines = [line.strip() for line in text.splitlines()]
    start = lines.index(FACT_HEADER) + 2  # past the header and its delimiter row
    count = 0
    while start + count < len(lines) and lines[start + count].startswith("|"):
        count += 1
    return count


def test_every_fact_table_on_the_built_site_has_row_headers(site: Path) -> None:
    sources = _sources_with_a_fact_table()
    assert len(sources) >= 15
    problems: list[str] = []
    for source in sources:
        built = site / _built_path(source)
        assert built.is_file(), f"{source.name} was not built"
        tables = [table for table in _tables(built.read_text(encoding="utf-8")) if _is_fact_table(table)]
        if len(tables) != 1:
            problems.append(f"{source.name}: {len(tables)} fact tables")
            continue
        table = tables[0]
        header = [(tag, scope) for tag, scope, _text in table["head"][0]]
        if header != [("th", "col"), ("th", "col")]:
            problems.append(f"{source.name}: header cells are {header}")
        rows = table["rows"]
        if len(rows) != _source_rows(source.read_text(encoding="utf-8")):
            problems.append(f"{source.name}: {len(rows)} built rows for {_source_rows(source.read_text(encoding='utf-8'))} written")
        for row in rows:
            if [(tag, scope) for tag, scope, _text in row] != [("th", "row"), ("td", None)] or not row[0][2]:
                problems.append(f"{source.name}: row {row}")
    assert not problems, "\n".join(problems[:10])


def test_nothing_else_on_the_built_site_gains_a_row_header(site: Path) -> None:
    """Across every built page: only a `Field | Value` table has them, and every one of its rows does."""
    pages = sorted(site.rglob("*.html"))
    assert len(pages) > 300, f"only {len(pages)} pages built; the site did not build"
    stray: list[str] = []
    fact_tables = 0
    for page in pages:
        for table in _tables(page.read_text(encoding="utf-8")):
            cells = [cell for row in table["head"] + table["rows"] for cell in row]
            if _is_fact_table(table):
                fact_tables += 1
                if not all(row[0][:2] == ("th", "row") for row in table["rows"]):
                    stray.append(f"{page.relative_to(site)}: a fact table row without a row header")
            elif any(scope in {"row", "col"} for _tag, scope, _text in cells):
                stray.append(f"{page.relative_to(site)}: scope on a table that is not a fact table")
    assert not stray, "\n".join(stray[:10])
    assert fact_tables >= 15


def test_the_rules_index_tables_are_untouched_on_the_built_site(site: Path) -> None:
    index = _tables((site / "rules" / "index.html").read_text(encoding="utf-8"))
    assert len(index) > 10
    assert not [table for table in index if _is_fact_table(table)]
    assert all(scope is None for table in index for row in table["head"] + table["rows"] for _t, scope, _x in row)


def test_the_sources_stay_plain_markdown_tables() -> None:
    """GitHub renders these files, and renders a table; the fix lives in the build only."""
    for source in _sources_with_a_fact_table():
        text = source.read_text(encoding="utf-8")
        assert f"\n{FACT_HEADER}\n|---|---|\n" in f"\n{text}", f"{source.name}: the table is no longer a pipe table"


def test_the_label_cells_keep_the_row_separators_materials_td_rule_gave_them(site: Path) -> None:
    """Material draws `border-top` on `td` only, so a `th` row header needs the same line."""
    css = (DOCS / "stylesheets" / "extra.css").read_text(encoding="utf-8")
    assert ".md-typeset table:not([class]) tbody th" in css and "border-top" in css
    built = (site / "stylesheets" / "extra.css")
    assert built.is_file() and built.read_text(encoding="utf-8") == css
    page = (site / "rules" / "AAK-AZURE-MCP-001" / "index.html").read_text(encoding="utf-8")
    assert "stylesheets/extra.css" in page

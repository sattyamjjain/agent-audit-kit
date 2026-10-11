"""Link and header contrast on the published docs site (WCAG 2.2 AA, 1.4.3 and 1.4.1).

Material's `primary: red` is about #ef5552 and its `accent: orange` is #ff9100. Against
the white page those are 3.45:1 and 2.26:1, against the grey behind inline code (where a
link to a file name sits) 3.16:1 and 2.07:1, and white on the red header is 3.45:1; text
this size needs 4.5:1. `docs/stylesheets/extra.css` replaces them with the nearest
compliant shades of the same hues.

The ratios here are worked out, not asserted: they come from the colours in that file and
the WCAG 2.2 relative-luminance formula, against Material's own background colours, for
each palette `mkdocs.yml` declares. So a palette change (a dark scheme, another primary
colour, a different red) fails until its contrast has been checked, and the shipped
palette's numbers are written down below, so any change to them shows up in review.

Everything is offline. A cross-check against the installed Material runs where Material is
installed (the docs deploy installs it; CI's `dev` extra does not).
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
MKDOCS_YML = REPO_ROOT / "mkdocs.yml"
CSS = REPO_ROOT / "docs" / "stylesheets" / "extra.css"

#: WCAG 1.4.3 for normal-size text, and 1.4.1's difference between a link and the text
#: around it (technique G183: 3:1, plus a cue other than colour on hover and focus).
TEXT_MINIMUM = 4.5
LINK_VERSUS_TEXT_MINIMUM = 3.0


# --------------------------------------------------------------------------
# WCAG 2.2 relative luminance and contrast ratio
# --------------------------------------------------------------------------

Color = tuple[float, float, float, float]  # red, green, blue (0-255) and alpha (0-1)


def color(text: str) -> Color:
    """`#rgb`, `#rrggbb`, `#rrggbbaa` or `rgba(r,g,b,a)`."""
    text = text.strip().lower()
    if text.startswith("rgba(") and text.endswith(")"):
        red, green, blue, alpha = (float(part) for part in text[5:-1].split(","))
        return red, green, blue, alpha
    assert text.startswith("#"), f"not a colour: {text!r}"
    digits = text[1:]
    if len(digits) in {3, 4}:
        digits = "".join(char * 2 for char in digits)
    assert len(digits) in {6, 8}, f"not a colour: {text!r}"
    channels = [int(digits[i : i + 2], 16) for i in range(0, len(digits), 2)]
    alpha = channels[3] / 255 if len(channels) == 4 else 1.0
    return float(channels[0]), float(channels[1]), float(channels[2]), alpha


def over(foreground: str, background: str) -> str:
    """The opaque colour a translucent `foreground` makes on an opaque `background`."""
    fr, fg, fb, alpha = color(foreground)
    br, bg, bb, _ = color(background)
    return "#%02x%02x%02x" % tuple(round(alpha * f + (1 - alpha) * b) for f, b in ((fr, br), (fg, bg), (fb, bb)))


def luminance(text: str) -> float:
    """Relative luminance, WCAG 2.2: linearised sRGB weighted 0.2126, 0.7152 and 0.0722."""

    def linear(value: float) -> float:
        value /= 255
        return value / 12.92 if value <= 0.04045 else ((value + 0.055) / 1.055) ** 2.4

    red, green, blue, alpha = color(text)
    assert alpha == 1.0, f"{text} is translucent; composite it with over() first"
    return 0.2126 * linear(red) + 0.7152 * linear(green) + 0.0722 * linear(blue)


def contrast(first: str, second: str) -> float:
    lighter, darker = sorted((luminance(first), luminance(second)), reverse=True)
    return (lighter + 0.05) / (darker + 0.05)


def test_the_contrast_formula_agrees_with_the_published_reference_values() -> None:
    """Black on white is 21:1 by definition, and #767676 is the well-known grey that just
    passes on white (4.54:1) next to #777777 that just fails (4.48:1)."""
    assert contrast("#000000", "#ffffff") == pytest.approx(21.0)
    assert contrast("#767676", "#ffffff") == pytest.approx(4.54, abs=0.005)
    assert contrast("#777777", "#ffffff") == pytest.approx(4.48, abs=0.005)
    assert over("#00000080", "#ffffff") == "#7f7f7f"
    assert over("#000000de", "#ffffff") == "#212121"  # Material's body text over its page
    assert color("#abc") == color("#aabbcc") and color("rgba(0,0,0,.5)") == (0.0, 0.0, 0.0, 0.5)


# --------------------------------------------------------------------------
# Material's colours, for the pairs this site's text is made of
# --------------------------------------------------------------------------

#: `--md-default-bg-color` and `--md-code-bg-color` of the default scheme; `--md-default-fg-color`
#: (#000000de) laid over the page, which is the body text; and the row that `tbody tr:hover`
#: paints (`rgba(0,0,0,.035)`). `test_materials_own_colours_are_the_ones_used_here` checks all
#: of them against the installed theme.
SCHEMES = {
    "default": {
        "page": "#ffffff",
        "code": "#f5f5f5",
        "text": over("#000000de", "#ffffff"),
        "row_hover": over("rgba(0,0,0,.035)", "#ffffff"),
    },
}

#: `--md-primary-bg-color`, the colour of text on the primary colour (the header title).
TEXT_ON_PRIMARY = {"red": "#ffffff"}

#: `--md-accent-fg-color--transparent`, the tint a hovered or focused link's code is given.
HOVER_TINT = {"orange": "#ff91001a"}

#: The colours Material itself gives `red` and `orange`, which the stylesheet replaces.
MATERIAL_OWN = {"primary": "#ef5552", "primary_dark": "#e53734", "accent": "#ff9100"}

#: The syntax-highlighting variables Material sets to its secondary text colour,
#: `--md-default-fg-color--light` (#0000008a), and the stylesheet therefore replaces.
TOKEN_VARIABLES = (
    "--md-code-hl-operator-color",
    "--md-code-hl-punctuation-color",
    "--md-code-hl-comment-color",
    "--md-code-hl-generic-color",
    "--md-code-hl-variable-color",
)


def test_the_figures_quoted_for_materials_own_colours_are_right() -> None:
    """The stylesheet's comment says why it exists in numbers; they are checked here."""
    page, code = SCHEMES["default"]["page"], SCHEMES["default"]["code"]
    assert contrast(MATERIAL_OWN["primary"], page) == pytest.approx(3.45, abs=0.005)
    assert contrast(MATERIAL_OWN["primary"], code) == pytest.approx(3.16, abs=0.005)
    assert contrast(MATERIAL_OWN["accent"], page) == pytest.approx(2.26, abs=0.005)
    assert contrast(MATERIAL_OWN["accent"], code) == pytest.approx(2.07, abs=0.005)
    assert contrast("#ffffff", MATERIAL_OWN["primary"]) == pytest.approx(3.45, abs=0.005)
    assert contrast("#ffffff", MATERIAL_OWN["primary_dark"]) == pytest.approx(4.26, abs=0.005)
    # Browsers report the secondary text colour as rgba(0, 0, 0, 0.54), and that rounded value
    # is what a contrast checker computes from; the exact 0x8a / 255 is a hair kinder (4.54).
    assert contrast(over("rgba(0,0,0,.54)", code), code) == pytest.approx(4.48, abs=0.005)
    assert contrast(over("#0000008a", code), code) == pytest.approx(4.54, abs=0.005)


# --------------------------------------------------------------------------
# What mkdocs.yml ships, and what the stylesheet says about it
# --------------------------------------------------------------------------


class _Loader(yaml.SafeLoader):
    """mkdocs.yml may name Python objects (`!!python/name:` for Material's emoji); ignore them."""


_Loader.add_multi_constructor("tag:yaml.org,2002:python/", lambda loader, suffix, node: None)


def mkdocs_config() -> dict:
    return yaml.load(MKDOCS_YML.read_text(encoding="utf-8"), Loader=_Loader)


def palettes() -> list[dict[str, str]]:
    """Every palette `theme.palette` declares, with Material's defaults filled in."""
    declared = (mkdocs_config().get("theme") or {}).get("palette", {})
    entries = declared if isinstance(declared, list) else [declared]
    return [
        {
            "scheme": entry.get("scheme", "default"),
            "primary": entry.get("primary", "indigo"),
            "accent": entry.get("accent", "indigo"),
        }
        for entry in entries
    ]


def _strip_comments(css: str) -> str:
    out: list[str] = []
    position = 0
    while True:
        start = css.find("/*", position)
        if start == -1:
            out.append(css[position:])
            return "".join(out)
        out.append(css[position:start])
        end = css.find("*/", start + 2)
        if end == -1:
            return "".join(out)
        position = end + 2


def rules(css: str) -> list[tuple[str, dict[str, str]]]:
    """(selector, declarations) for each rule of a stylesheet that has no nested blocks."""
    parsed: list[tuple[str, dict[str, str]]] = []
    for chunk in _strip_comments(css).split("}"):
        if "{" not in chunk:
            continue
        selector, _, body = chunk.partition("{")
        declarations: dict[str, str] = {}
        for declaration in body.split(";"):
            name, _, value = declaration.partition(":")
            if name.strip() and value.strip():
                declarations[name.strip()] = value.strip()
        parsed.append((" ".join(selector.split()), declarations))
    return parsed


def declared(
    scheme: str, prop: str, attribute: str | None = None, value: str | None = None
) -> str | None:
    """What the stylesheet sets `prop` to for `<body>` in `scheme`, and with `data-md-color-<attribute>=<value>` if given."""
    found = None
    for selector, declarations in rules(CSS.read_text(encoding="utf-8")):
        if (
            f'[data-md-color-scheme="{scheme}"]' in selector
            and (attribute is None or f'[data-md-color-{attribute}="{value}"]' in selector)
            and prop in declarations
        ):
            found = declarations[prop]
    return found


def ratios(palette: dict[str, str]) -> dict[str, float]:
    """Every contrast this palette's link, header, hover and code-token colours make, from the stylesheet."""
    scheme, primary, accent = palette["scheme"], palette["primary"], palette["accent"]
    colours = SCHEMES[scheme]
    link = declared(scheme, "--md-primary-fg-color", "primary", primary)
    dark = declared(scheme, "--md-primary-fg-color--dark", "primary", primary)
    hover = declared(scheme, "--md-accent-fg-color", "accent", accent)
    tokens = [declared(scheme, prop) for prop in TOKEN_VARIABLES]
    assert link and dark and hover and all(tokens), (
        f"{palette}: docs/stylesheets/extra.css does not set all of its colours"
    )
    tinted = over(HOVER_TINT[accent], colours["page"])
    tinted_in_row = over(HOVER_TINT[accent], colours["row_hover"])
    on_primary = TEXT_ON_PRIMARY[primary]
    return {
        "link on the page": contrast(link, colours["page"]),
        "link on code": contrast(link, colours["code"]),
        "link on a hovered table row": contrast(link, colours["row_hover"]),
        "link against body text": contrast(link, colours["text"]),
        "header title on the header": contrast(on_primary, link),
        "repository link on the mobile menu": contrast(on_primary, dark),
        "hovered link on the page": contrast(hover, colours["page"]),
        "hovered link on code": contrast(hover, colours["code"]),
        "hovered link in code": contrast(hover, tinted),
        "hovered link in code, in a hovered row": contrast(hover, tinted_in_row),
        "operator, punctuation and comment tokens on code": min(
            contrast(token, colours["code"]) for token in tokens if token
        ),
    }


#: The shipped palette's numbers. They are here so that a change to the colours is visible in
#: review: a new compliant red passes the minimums above and still has to update this table.
SHIPPED = {
    "link on the page": 4.98,
    "link on code": 4.57,
    "link on a hovered table row": 4.61,
    "link against body text": 3.23,
    "header title on the header": 4.98,
    "repository link on the mobile menu": 6.57,
    "hovered link on the page": 5.39,
    "hovered link on code": 4.95,
    "hovered link in code": 4.96,
    "hovered link in code, in a hovered row": 4.62,
    "operator, punctuation and comment tokens on code": 5.27,
}


def test_the_site_ships_the_palettes_this_file_has_data_for() -> None:
    """A dark scheme, or another primary or accent, has to be given its backgrounds and its
    checked colours before it can ship; this is the test that says so."""
    shipped = palettes()
    assert shipped, "mkdocs.yml declares no palette"
    for palette in shipped:
        assert palette["scheme"] in SCHEMES, (
            f"{palette}: this scheme's background colours are not in SCHEMES, so its contrast "
            f"is unchecked. Add them (and overrides to docs/stylesheets/extra.css), then re-run."
        )
        assert palette["primary"] in TEXT_ON_PRIMARY and palette["accent"] in HOVER_TINT, (
            f"{palette}: the colour of text on this primary and the hover tint of this accent "
            f"are not known to this file"
        )


def test_every_palette_the_site_ships_has_a_checked_link_header_and_hover_colour() -> None:
    failures: list[str] = []
    for palette in palettes():
        for name, value in ratios(palette).items():
            minimum = LINK_VERSUS_TEXT_MINIMUM if name == "link against body text" else TEXT_MINIMUM
            if value < minimum:
                label = "/".join(palette.values())
                failures.append(f"{label}: {name} is {value:.2f}:1, needs {minimum}:1")
    assert not failures, "\n".join(failures)


def test_the_shipped_numbers_are_the_ones_written_down() -> None:
    (palette,) = palettes()  # one palette ships; a second one needs a table of its own
    actual = ratios(palette)
    assert actual.keys() == SHIPPED.keys()
    changed = {
        name: (round(actual[name], 2), SHIPPED[name]) for name in SHIPPED if abs(actual[name] - SHIPPED[name]) > 0.006
    }
    assert not changed, f"the colours in extra.css changed; update SHIPPED (now, was): {changed}"


def test_a_link_is_still_told_from_the_text_around_it_by_more_than_colour_alone() -> None:
    """Making the link colour darker for 1.4.3 narrows its difference from the dark body text;
    1.4.1 then needs a cue besides colour on hover and focus, which is the underline."""
    cue = [
        declarations
        for selector, declarations in rules(CSS.read_text(encoding="utf-8"))
        if ".md-typeset a:hover" in selector and ".md-typeset a:focus" in selector
    ]
    assert cue and cue[0].get("text-decoration") == "underline"


def test_the_overrides_outrank_materials_own_palette_rules() -> None:
    """Material sets these on `[data-md-color-primary=red]` or `[data-md-color-scheme=default]`
    (one attribute); naming a second attribute, or `body` as well, makes ours more specific, so
    the order the stylesheets load in does not matter."""
    overridden = {"--md-primary-fg-color", "--md-primary-fg-color--dark", "--md-accent-fg-color", *TOKEN_VARIABLES}
    checked = 0
    for selector, declarations in rules(CSS.read_text(encoding="utf-8")):
        if overridden & declarations.keys():
            checked += 1
            specific = selector.count("[data-md-color-") >= 2 or (
                selector.startswith("body[") and selector.count("[data-md-color-") >= 1
            )
            assert specific, f"{selector!r} is no more specific than Material's own rule"
    assert checked >= 3


def test_the_stylesheet_is_wired_into_the_site() -> None:
    config = mkdocs_config()
    assert "stylesheets/extra.css" in config.get("extra_css", [])
    assert CSS.is_file()
    assert (config.get("theme") or {}).get("name") == "material", "the overrides are written for Material's variables"


# --------------------------------------------------------------------------
# Against the installed Material
# --------------------------------------------------------------------------


def _material_css() -> tuple[str, str]:
    material = pytest.importorskip("material", reason="Material is not installed")
    sheets = Path(material.__file__).resolve().parent / "templates" / "assets" / "stylesheets"
    main = next(sheets.glob("main.*.min.css"), None)
    palette = next(sheets.glob("palette.*.min.css"), None)
    assert main and palette, f"no Material stylesheets under {sheets}"
    return main.read_text(encoding="utf-8"), palette.read_text(encoding="utf-8")


def _rules_named(css: str, selector: str) -> list[dict[str, str]]:
    """Every rule of a minified stylesheet written exactly `selector{...}`, as property dictionaries."""
    found: list[dict[str, str]] = []
    needle = selector + "{"
    position = 0
    while True:
        start = css.find(needle, position)
        if start == -1:
            return found
        body_start = start + len(needle)
        position = body_start
        if start and css[start - 1] not in "}{;":
            continue  # the selector is the tail of a longer one
        body = css[body_start : css.index("}", body_start)]
        found.append(
            {name.strip(): value.strip() for name, _, value in (part.partition(":") for part in body.split(";")) if name.strip()}
        )


def _material(css: str, selector: str, prop: str) -> str:
    values = [rule[prop] for rule in _rules_named(css, selector) if prop in rule]
    assert values, (
        f"Material's stylesheet no longer has `{selector}` setting {prop}; "
        f"re-check the assumptions behind docs/stylesheets/extra.css"
    )
    return values[0]


def _same(first: str, second: str) -> bool:
    a, b = color(first), color(second)
    return all(abs(x - y) <= 1 for x, y in zip(a[:3], b[:3])) and abs(a[3] - b[3]) <= 0.01


def test_materials_own_colours_are_the_ones_used_here() -> None:
    """The backgrounds in SCHEMES are read off Material's stylesheet, not remembered.

    It also holds the structure the override relies on: the link colour is derived from the
    primary colour, a hovered link takes the accent, the header is painted with the primary
    colour, and the mobile menu's repository link with its dark shade.
    """
    main, palette = _material_css()
    scheme = ":root,[data-md-color-scheme=default]"
    page = _material(main, scheme, "--md-default-bg-color")
    assert _same(page, SCHEMES["default"]["page"])
    assert _same(_material(main, scheme, "--md-code-bg-color"), SCHEMES["default"]["code"])
    assert _same(over(_material(main, scheme, "--md-default-fg-color"), page), SCHEMES["default"]["text"])
    assert _same(over(_material(main, scheme, "--md-typeset-table-color--light"), page), SCHEMES["default"]["row_hover"])
    assert _material(main, scheme, "--md-typeset-a-color") == "var(--md-primary-fg-color)"
    assert _material(main, ".md-typeset a", "color") == "var(--md-typeset-a-color)"
    assert _material(main, ".md-typeset a:focus,.md-typeset a:hover", "color") == "var(--md-accent-fg-color)"
    assert _material(main, ".md-typeset table:not([class]) tbody tr:hover", "background-color") == (
        "var(--md-typeset-table-color--light)"
    )
    assert _material(main, ".md-header", "background-color") == "var(--md-primary-fg-color)"
    assert _material(main, ".md-header", "color") == "var(--md-primary-bg-color)"
    assert _material(main, ".md-nav__source", "background-color") == "var(--md-primary-fg-color--dark)"
    assert _same(_material(main, scheme, "--md-default-fg-color--light"), "#0000008a")
    on_secondary = {
        name
        for rule in _rules_named(main, scheme)
        for name, value in rule.items()
        if name.startswith("--md-code-hl-") and value == "var(--md-default-fg-color--light)"
    }
    assert on_secondary == set(TOKEN_VARIABLES), (
        f"the syntax tokens on Material's secondary colour are now {sorted(on_secondary)}; "
        f"update TOKEN_VARIABLES and the rule in docs/stylesheets/extra.css"
    )
    assert _same(_material(palette, "[data-md-color-primary=red]", "--md-primary-bg-color"), TEXT_ON_PRIMARY["red"])
    assert _same(
        _material(palette, "[data-md-color-accent=orange]", "--md-accent-fg-color--transparent"), HOVER_TINT["orange"]
    )

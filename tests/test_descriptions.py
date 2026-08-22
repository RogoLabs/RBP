"""
Published descriptions (review item 18).

The load-bearing case: Debian's security tracker appends annotations like

    NOTE: Introduced with: https://gitlab.com/.../commit/90ca4e03

An "Introduced with" pointer is not a description of a flaw, it is a pointer to
the vulnerable code, republished inside a curated list of CVE IDs chosen precisely
because no record has been published. That Debian publishes it first is true, and
is exactly the "aggregation of public facts creates new exposure" argument the
whole site rests on.

Four of these were live on rbptracker.org, two of them "Introduced with".
"""
from __future__ import annotations

import pytest

from rbp import report, site
from rbp.classify import MAX_DESCRIPTION, display_description as clean


# Verbatim shapes taken from the live snapshot, truncated only in the hash.
LIVE = [
    "hcd-ohci: infinite loop  NOTE: Fixed by: "
    "https://gitlab.com/qemu-project/qemu/-/commit/129922c2bc398b656a9180150e",
    "hw/uefi: heap overflow  NOTE: Introduced with: "
    "https://gitlab.com/qemu-project/qemu/-/commit/90ca4e03c27dc8ac821a2e1686",
    "virtio-scsi request size mismatch  NOTE: Fixed by: "
    "https://gitlab.com/qemu-project/qemu/-/commit/799713029354722",
]


@pytest.mark.parametrize("raw", LIVE)
def test_no_commit_pointer_survives(raw):
    out = clean(raw)
    assert "http" not in out
    assert "commit" not in out
    assert "NOTE" not in out
    assert out, "the useful half of the description must survive"


def test_the_useful_half_is_kept_not_the_whole_row_dropped():
    """The field stays. 52 of 96 named rows carried an empty package and CSAF rows
    carry none at all, so the description is the only identifier a defender has.
    Deleting it makes the site less useful without making anyone safer."""
    assert clean(LIVE[1]) == "hw/uefi: heap overflow"


def test_annotations_are_stripped_from_the_marker_onward():
    """These arrive as a trailing block; what follows a marker is never prose."""
    for marker in ("NOTE:", "note:", "DEBIANBUG", "Fixed by:", "Introduced with:",
                   "Introduced in:", "Bug:", "References:"):
        assert clean(f"Real description here {marker} junk junk") == \
            "Real description here", marker


def test_sanitising_happens_before_the_length_cut():
    """The old code sliced the raw feed string at 180 characters, so several rows
    ended in half a commit URL: the annotation was out of view and the pointer was
    still in the data. Cleaning after cutting cannot fix that, because the URL is
    then a fragment that no longer matches a URL pattern."""
    filler = "A" * 170
    raw = f"{filler} NOTE: Fixed by: https://example.invalid/commit/deadbeef"
    out = clean(raw)
    assert out == filler
    assert "http" not in out and "example" not in out
    # And the naive order would have left a fragment. Proving the trap is real:
    naive = raw[:180]
    assert "NOTE" in naive, "the 180-char slice keeps part of the annotation"


def test_cut_falls_on_a_sentence_boundary():
    assert clean("A flaw was found. Then more text follows here.") == \
        "A flaw was found."


def test_version_numbers_and_abbreviations_are_not_sentence_boundaries():
    """"foo v1.2. Attackers" must not cut at the version dot."""
    assert clean("Buffer overflow in foo v1.2. Attackers may crash it.") == \
        "Buffer overflow in foo v1.2. Attackers may crash it."


def test_a_title_with_no_terminal_punctuation_survives_whole():
    t = "Use after free in the network stack of some product"
    assert clean(t) == t


def test_a_long_run_on_is_cut_on_a_word_boundary():
    raw = "word " * 200
    out = clean(raw)
    assert len(out) <= MAX_DESCRIPTION
    assert not out.endswith("wor"), "cut mid-word"
    assert out.endswith("word")


def test_a_url_only_description_yields_nothing_rather_than_a_stub():
    """Stripping the URL out of "See <url> for details" leaves "See for details",
    which reads like prose and says nothing. Returning empty lets the caller fall
    back to the package name, which a defender can actually use."""
    assert clean("See https://example.invalid/adv for details") == ""
    assert clean("https://example.invalid/adv") == ""


def test_bookkeeping_only_descriptions_fall_back_to_the_package():
    """Cleaning, not asserting: a useless description is bad display text, not a
    false statement, so it must never stop a publication (PLAN 8b class 2)."""
    row = {"description": "NOTE: only bookkeeping", "package": "libfoo"}
    assert report._clean_description(row["description"], row["package"]) == "libfoo"
    assert report._clean_description("security update", "libbar") == "libbar"
    assert report._clean_description("[unknown]", "libbaz") == "libbaz"


def test_the_sanitiser_is_idempotent():
    """report._clean_description runs it a second time on purpose, so a row that
    reached that function by a path skipping classify still cannot publish a URL."""
    for raw in LIVE:
        once = clean(raw)
        assert clean(once) == once


def test_the_markdown_report_uses_the_same_sanitiser():
    """_summary was a third independent copy of these rules and had already
    drifted: it omitted "security fix" from its useless-value list."""
    assert report._summary({"description": LIVE[1], "package": "qemu"}) == \
        "hw/uefi: heap overflow"
    assert report._summary({"description": "security fix", "package": "qemu"}) == "qemu"


# --------------------------------------------------------------------------
# the publish-time backstop
# --------------------------------------------------------------------------

def _row(desc):
    return {"cve_id": "CVE-2026-1", "owner": None, "owner_nameable": False,
            "counted": True, "description": desc}


def test_assert_artefact_refuses_a_url_in_a_published_description():
    """A backstop, not a policy gate. It can only fire if the sanitiser has a bug
    or a new feed bypasses it, and when it fires the failure is a disclosure harm
    rather than an ugly string, so blocking is the right direction."""
    with pytest.raises(SystemExit) as e:
        site.assert_artefact([_row("Flaw. See https://x.invalid/commit/ab")], "rbp.json")
    assert "publishes a URL" in str(e.value)


def test_assert_artefact_refuses_a_tracker_annotation():
    with pytest.raises(SystemExit) as e:
        site.assert_artefact([_row("Flaw NOTE: Fixed by: something")], "rbp.json")
    assert "tracker annotation" in str(e.value)


def test_assert_artefact_accepts_a_cleaned_description():
    site.assert_artefact([_row(clean(LIVE[0]))], "rbp.json")
    site.assert_artefact([_row("")], "rbp.json")


def test_the_backstop_would_have_caught_every_live_row():
    """All four live rows, through the real assertion, before and after cleaning."""
    for raw in LIVE:
        with pytest.raises(SystemExit):
            site.assert_artefact([_row(raw)], "rbp.json")
        site.assert_artefact([_row(clean(raw))], "rbp.json")


def test_the_url_assertion_matches_a_scheme_not_the_substring_http():
    """First version was `"http" in desc.lower()`, which flagged 16 live rows on
    software identifiers (NIOHTTPRequestDecompressor, HTTPDecoder) and prose about
    the protocol, against 7 genuine URLs, and blocked the build on all 23.

    A guard that CAN stop a publication has to be precise about what it matches.
    Imprecision in a blocking guard is the class-1-on-class-2 mistake the NOTE:
    guard already made once."""
    legitimate = [
        "NIOExtras: NIOHTTPRequestDecompressor ratio limit bypass via Content-Length",
        "SwiftNIO NIOHTTP1: HTTPDecoder accepts unbounded HTTP/1 header blocks",
        "npm PraisonAI MCPServer exposes unauthenticated HTTP tools/call",
        "CRLF Injection in outbound HTTP request URI",
    ]
    for desc in legitimate:
        site.assert_artefact([_row(desc)], "rbp.json")   # must not raise

    for desc in ("see https://x.invalid/a", "at http://x.invalid", "via www.x.invalid",
                 "git://x.invalid/repo"):
        with pytest.raises(SystemExit):
            site.assert_artefact([_row(desc)], "rbp.json")


def test_a_url_removed_from_mid_prose_leaves_no_wreckage():
    """Three separate rough edges found on live rows once the URL came out.

    `\\S+` swallowed the closing paren of a markdown link, leaving an unclosed
    `[PhotoSwipe](` on the page; a leading "From <url>, The server..." left a
    stranded "From"; and the comma before the removed URL was left dangling."""
    assert clean("The module uses [PhotoSwipe](https://photoswipe.com/) library. More.") \
        == "The module uses PhotoSwipe library."
    assert clean("From https://netatalk.io/security/CVE-1, The server option is unchecked.") \
        == "The server option is unchecked."
    assert clean("A flaw exists. See https://x.invalid for more.") == "A flaw exists."


def test_a_bracketed_reference_that_empties_out_is_removed_entirely():
    assert "(" not in clean("Affected (https://x.invalid/a) component here now")
    assert "[]" not in clean("Affected [https://x.invalid/a] component here now")

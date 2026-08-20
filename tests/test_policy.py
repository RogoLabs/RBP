"""
Guard the site's citations against drift.

Every rule the site quotes is pinned to a fixture captured from the canonical
source. The frozen tests assert we still say what the document says. The live
tests re-fetch the canonical sources and fail if the wording, the section
numbers, or the version changed — because a site that names CNAs against a rule
must not go on quoting a superseded one.

This exists because it already happened. The first draft of this project cited
RBP Policy v1.0's arithmetic thresholds (>5% of trailing-12-month public IDs,
>50% for three months) as though they were current. They were withdrawn: the
CVE Board approved v2.0.0 on 2026-08-13, which removes every numeric threshold
and replaces them with discretionary action. The v1.0 text is still hosted by
third parties and still ranks in search, which is how it got picked up.
"""
from __future__ import annotations

import io
import json
import os
import pathlib
import re
import urllib.request

import pytest

FIX = pathlib.Path(__file__).parent / "fixtures"
RULES = json.loads((FIX / "cna_rules_4-5.json").read_text())
POLICY = json.loads((FIX / "rbp_policy_v2.json").read_text())

live_only = pytest.mark.skipif(
    os.environ.get("RBP_LIVE_TESTS") != "1",
    reason="fetches canonical policy sources; set RBP_LIVE_TESTS=1",
)


# --------------------------------------------------------------------------
# the 72-hour clock — what makes an individual record late
# --------------------------------------------------------------------------

def test_4514_is_the_72_hour_must():
    r = RULES["rules"]["4.5.1.4"]
    assert "MUST publish a CVE Record" in r
    assert "within 72 hours of Publicly Disclosing a CVE ID assigned by the CNA" in r
    # The escalation the site describes when a record goes past 72 hours.
    assert "MAY direct the appropriate CNA-LR to publish" in r


def test_4516_is_the_72_hour_should_for_third_party_disclosure():
    r = RULES["rules"]["4.5.1.6"]
    assert "SHOULD publish CVE Records within 72 hours" in r
    assert "Publicly Disclosed by a party other than the CNA" in r


def test_4513_is_the_24_hour_should():
    assert "SHOULD publish a CVE Record to the CVE List within 24 hours" in RULES["rules"]["4.5.1.3"]


def test_must_and_should_are_not_interchangeable():
    """The site's central fairness constraint. 4.5.1.4 binds only when the CNA
    itself disclosed; the usual distro case is 4.5.1.6, which is a SHOULD. We
    cannot observe who disclosed, so we must never report a SHOULD as a MUST."""
    assert "MUST" in RULES["rules"]["4.5.1.4"]
    assert "SHOULD" in RULES["rules"]["4.5.1.6"]
    assert "MUST" not in RULES["rules"]["4.5.1.6"]


def test_4517_permits_naming_the_reserving_cna():
    """The redaction finding rests on this: the Secretariat is expressly
    permitted to name the reserving CNA 24 hours after public disclosure, and
    the API redacts it indefinitely instead."""
    r = RULES["rules"]["4.5.1.7"]
    assert "Secretariat MAY publicly identify the CNA who reserved the CVE ID" in r
    assert "24 hours after a CVE ID has been Publicly Disclosed" in r


def test_4535_requires_rejecting_unpublished_ids():
    """A reserved ID that will never be published is supposed to be rejected,
    so a long-lived RBP is not a neutral state under the rules."""
    assert RULES["rules"]["4.5.3.5"].endswith("CNAs MUST reject unused or unpublished CVE IDs.")


def test_rules_version_is_pinned():
    assert RULES["version"] == "4.1.0"
    assert RULES["approved"] == "May 14, 2025"


# --------------------------------------------------------------------------
# RBP policy v2.0.0 — what replaced the arithmetic
# --------------------------------------------------------------------------

def test_policy_version_is_pinned():
    assert POLICY["version"] == "2.0.0"
    assert POLICY["board_approval"] == "August 13, 2026"


def test_policy_sets_the_72_hour_expectation():
    t = POLICY["full_text"]
    assert "published within 72 hours" in t
    assert "CNA Rule 4.5.1.4" in t and "CNA Rule 4.5.1.6" in t


def test_policy_v2_has_no_numeric_thresholds():
    """The heart of the correction. v1.0 gated ID issuance on >5% of trailing
    12-month public IDs and cut output at >50% for three months. v2.0.0 carries
    no such trigger, so the site must not compute or display one."""
    t = POLICY["full_text"]
    assert "5%" not in t
    assert "50%" not in t
    assert "past 12 months" not in t
    # No percentage-of-portfolio construction survives anywhere in the document.
    assert not re.search(r"\b\d{1,3}\s?%", t), re.findall(r".{40}\d{1,3}\s?%.{40}", t)


def test_enforcement_is_discretionary_not_automatic():
    """Every lever is permissive. There is no condition that triggers anything
    by itself, which is precisely what the site exists to point out."""
    t = POLICY["full_text"]
    for lever in ("Warning", "Reservation Caps", "Intervention", "Formal Review"):
        assert lever in t
    assert "The CVE Program may take further action" in t
    assert "may be applied" in t


def test_enforcement_names_no_deadline_of_its_own():
    """Remediation timelines are set case by case by a TL-Root or Root, so no
    externally checkable clock exists past the 72 hours."""
    t = POLICY["full_text"]
    assert "required" in t and "remediation timeline" in t
    assert "as defined by the TL-Root and/or Root" in t


def test_v1_thresholds_are_recorded_as_withdrawn():
    """Kept in the fixture so nobody reintroduces them from a cached PDF."""
    assert "NO LONGER IN FORCE" in POLICY["supersedes"]
    assert "5%/50%" in POLICY["supersedes"]


# --------------------------------------------------------------------------
# live — fail loudly when the canonical sources move
# --------------------------------------------------------------------------

def _fetch(url, binary=False):
    req = urllib.request.Request(url, headers={"User-Agent": "rbptracker.org"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read() if binary else r.read().decode("utf-8")


@live_only
def test_live_cna_rules_still_match_the_fixture():
    d = json.loads(_fetch(RULES["origin"]))
    assert d["versionNumber"] == RULES["version"], (
        f"CNA Rules moved to {d['versionNumber']} — re-capture the fixture and "
        "re-read every section the site cites before shipping.")
    paras = [p for sec in d["pageSections"] for sub in sec.get("subSections", [])
             for p in sub.get("subSectionParagraphs", [])]
    flat = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", "", " ".join(paras))
                  .replace("&nbsp;", " ").replace("’", "'"))
    for section, text in RULES["rules"].items():
        assert text in flat, f"{section} no longer matches the canonical text"


@live_only
def test_live_rbp_policy_is_still_v2_and_still_thresholdless():
    import pypdf  # pure-python: the CI runner has no pdftotext

    reader = pypdf.PdfReader(io.BytesIO(_fetch(POLICY["url"], binary=True)))
    text = "\n".join(page.extract_text() or "" for page in reader.pages)
    assert "Document Version: 2.0.0" in text, "RBP policy version changed — re-read it"
    assert "published within 72 hours" in text
    assert not re.search(r"\b\d{1,3}\s?%", text), (
        "a numeric threshold reappeared in the RBP policy — the site's framing "
        "needs revisiting before the next deploy")

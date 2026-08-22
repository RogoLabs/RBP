"""
The suppression lever (review item 4).

The site promised a CNA that a wrong row, or one "under coordinated disclosure",
would be "corrected or suppressed on the next build", and that "suppressions are
counted publicly in aggregate". None of it existed.

Two properties dominate these tests.

A suppressed row must leave EVERY published artefact, not just the site. The
grader ledger lives on the public data branch, so gating display alone would
withhold the row from the page while writing the inferred CNA name into
precision.json. Writing this file caught a second instance of the same shape:
dropping suppressed rows from `reportable` removed them from `counted`, which sent
every one of them into held_back.json with an invented reason.

And the committed list must not itself be a disclosure. A plaintext file in a
public repo saying "somebody reported CVE-2026-XXXX as embargoed" is worse than
the listing it removes, and git history makes it permanent.
"""
from __future__ import annotations

import json
import os

import pandas as pd
import pytest

from rbp import inference, report, site, suppress
from rbp.attribution import Attributor

KEY = "test-key-not-the-real-one"


@pytest.fixture(autouse=True)
def _key(monkeypatch):
    monkeypatch.setenv("RBP_SUPPRESS_KEY", KEY)
    monkeypatch.setenv("GITHUB_TOKEN", "t")


# --------------------------------------------------------------------------
# the committed list is not a disclosure
# --------------------------------------------------------------------------

def test_the_committed_list_never_contains_a_cve_id(tmp_path):
    """The whole reason for hashing. A plaintext entry in a public repository is a
    permanent, git-archived statement that a specific reserved CVE ID was reported
    as sensitive, which is strictly worse than the row it removes."""
    p = tmp_path / "suppressions.txt"
    p.write_text(f"# a comment\n{suppress.digest('CVE-2026-1234', KEY)}\n\n")
    entries = suppress.read_list(str(p))
    assert entries == [suppress.digest("CVE-2026-1234", KEY)]
    assert "CVE" not in p.read_text().upper().replace("# A COMMENT", "")
    for e in entries:
        assert len(e) == 64 and all(c in "0123456789abcdef" for c in e)


def test_membership_works_without_the_list_ever_holding_the_id(tmp_path):
    s = suppress.Suppressions([suppress.digest("CVE-2026-1234", KEY)], [], key=KEY)
    assert "CVE-2026-1234" in s
    assert "cve-2026-1234" in s, "case must not matter"
    assert " CVE-2026-1234 " in s, "surrounding whitespace must not matter"
    assert "CVE-2026-9999" not in s


def test_a_different_key_cannot_confirm_a_guess():
    """With the key in Actions secrets, holding the file is not enough to test
    whether a suspected id is on it."""
    right = suppress.digest("CVE-2026-1234", KEY)
    wrong = suppress.digest("CVE-2026-1234", "some-other-key")
    assert right != wrong
    assert "CVE-2026-1234" not in suppress.Suppressions([right], [], key="other")


def test_an_unevaluable_list_refuses_to_publish(tmp_path, monkeypatch):
    """PLAN 8b class 1, and one of the few configuration errors that should stop a
    publication: without the key the entries cannot be evaluated, and the run
    would publish every row that someone reported as wrong or under embargo."""
    monkeypatch.delenv("RBP_SUPPRESS_KEY", raising=False)
    p = tmp_path / "suppressions.txt"
    p.write_text(suppress.digest("CVE-2026-1234", KEY) + "\n")
    with pytest.raises(SystemExit) as e:
        suppress.load(str(p), allow_remote=False)
    msg = str(e.value)
    assert "RBP_SUPPRESS_KEY" in msg
    assert "would publish every one of them" in msg


def test_an_empty_list_with_no_key_is_fine(tmp_path, monkeypatch):
    """Nothing to evaluate is not an error, or every fresh clone fails."""
    monkeypatch.delenv("RBP_SUPPRESS_KEY", raising=False)
    s = suppress.load(str(tmp_path / "nope.txt"), allow_remote=False)
    assert len(s) == 0


# --------------------------------------------------------------------------
# reading private advisories
# --------------------------------------------------------------------------

def test_a_read_failure_does_not_stop_the_build(tmp_path, monkeypatch):
    """The opposite direction from the missing key. Refusing to publish four times
    a day over a credential would freeze the site; the degraded banner is already
    on every page."""
    monkeypatch.setattr(suppress, "from_issues",
                        lambda **kw: (set(), "gh api failed: 401"))
    s = suppress.load(str(tmp_path / "none.txt"))   # must not raise
    assert s.report["degraded"] is True


def test_cve_ids_are_extracted_from_issue_text(monkeypatch):
    payload = json.dumps([
        {"title": "Withhold CVE-2026-1111", "body": ""},
        {"title": "wrong owner", "body": "see cve-2026-2222 please"},
        {"title": "no id here", "body": ""},
    ])

    class P:
        returncode, stdout, stderr = 0, payload, ""
    monkeypatch.setattr(suppress.subprocess, "run", lambda *a, **k: P())
    ids, err = suppress.from_issues()
    assert err is None
    assert ids == {"CVE-2026-1111", "CVE-2026-2222"}


def test_a_pull_request_is_not_read_as_a_withhold_request(monkeypatch):
    """The issues endpoint returns pull requests too, so a PR mentioning a CVE ID
    in its title would otherwise withhold that row."""
    payload = json.dumps([
        {"title": "CVE-2026-1111", "body": "", "pull_request": {"url": "x"}},
        {"title": "CVE-2026-2222", "body": ""},
    ])

    class P:
        returncode, stdout, stderr = 0, payload, ""
    monkeypatch.setattr(suppress.subprocess, "run", lambda *a, **k: P())
    ids, _ = suppress.from_issues()
    assert ids == {"CVE-2026-2222"}


def test_the_auto_path_is_capped(tmp_path, monkeypatch):
    """No verification of who may ask is the right call, and it means anyone with a
    GitHub account can remove a row. One issue naming 500 ids would empty the site,
    which is a denial of service against the project's whole purpose."""
    many = {f"CVE-2026-{3000 + i}" for i in range(suppress.MAX_AUTO + 12)}
    monkeypatch.setattr(suppress, "from_issues", lambda **kw: (many, None))
    s = suppress.load(str(tmp_path / "none.txt"))
    assert len(s.auto) == suppress.MAX_AUTO
    assert s.report["capped"] == 12
    assert s.report["from_reports"] == suppress.MAX_AUTO


def test_the_published_report_carries_counts_and_never_ids(tmp_path, monkeypatch):
    monkeypatch.setattr(suppress, "from_issues",
                        lambda **kw: ({"CVE-2026-1111"}, None))
    p = tmp_path / "s.txt"
    p.write_text(suppress.digest("CVE-2026-2222", KEY) + "\n")
    rep = suppress.load(str(p)).report
    assert rep["committed"] == 1
    assert rep["from_reports"] == 1
    assert rep["capped"] == 0
    assert rep["degraded"] is False and rep["detail"] is None
    # The property that actually matters, asserted over the whole serialised
    # payload rather than a field list, so a NEW key cannot smuggle an id in.
    assert "CVE" not in json.dumps(rep).upper()
    assert not any(isinstance(v, (list, set, tuple)) for v in rep.values()), (
        "the published report must be scalars only; a collection is how a set of "
        "ids gets published by accident")


# --------------------------------------------------------------------------
# a suppressed row must leave EVERY artefact
# --------------------------------------------------------------------------

def _corpus():
    ids = [f"CVE-2026-{1000 + i}" for i in range(20)]
    return pd.DataFrame({"cve_id": ids, "state": ["PUBLISHED"] * 20,
                         "assigner": ["acme"] * 20, "vendor": ["Acme"] * 20,
                         "product": ["widget"] * 20})


def _backlog(*cids):
    return [{"cve_id": c, "state": "RESERVED", "public_date": "2026-06-01",
             "sources": "debian", "refs": f"debian:{c}", "description": "a flaw",
             "product_map_owner": None, "product_map_confidence": 0.0,
             "product_map_method": "none", "days_public": 60,
             "dates": {}, "feed_count": 1} for c in cids]


def test_a_suppressed_row_never_reaches_the_grader_ledger(tmp_path):
    """The property that makes this more than a display filter. precision.json is
    published on the data branch, so a row withheld because a CNA reported an
    embargo would otherwise be named in public anyway."""
    ledger = tmp_path / "precision.json"
    rows = _backlog("CVE-2026-1010", "CVE-2026-1011")
    inference.apply_to_backlog(
        rows, _corpus(), str(ledger), today="2026-08-20",
        suppressed={"CVE-2026-1010"},
        covered={"acme"}, sightings={"acme": 99})
    preds = json.load(open(ledger)).get("predictions") or {}
    assert "CVE-2026-1010" not in preds, "suppressed row was recorded in the ledger"


def test_a_suppressed_row_carries_no_owner_at_all(tmp_path):
    rows = _backlog("CVE-2026-1010")
    inference.apply_to_backlog(
        rows, _corpus(), str(tmp_path / "p.json"), today="2026-08-20",
        suppressed={"CVE-2026-1010"}, covered={"acme"}, sightings={"acme": 99})
    r = rows[0]
    assert r["suppressed"] is True
    assert r["owner"] is None
    assert r["owner_tier"] == "suppressed"


def test_an_unsuppressed_row_is_marked_false_not_left_absent(tmp_path):
    """Absent on some rows and False on others is how a missing field gets read as
    a healthy default."""
    rows = _backlog("CVE-2026-1010")
    inference.apply_to_backlog(
        rows, _corpus(), str(tmp_path / "p.json"), today="2026-08-20",
        suppressed=set(), covered={"acme"}, sightings={"acme": 99})
    assert rows[0]["suppressed"] is False


def test_the_suppressed_count_is_returned_for_publication(tmp_path):
    rows = _backlog("CVE-2026-1010", "CVE-2026-1011")
    v = inference.apply_to_backlog(
        rows, _corpus(), str(tmp_path / "p.json"), today="2026-08-20",
        suppressed={"CVE-2026-1010"}, covered={"acme"}, sightings={"acme": 99})
    assert v["suppressed"] == 1


def test_run_coverage_excludes_suppressed_rows_from_both_halves(tmp_path):
    """Leaving them in the denominator would make a withhold look like an
    abstention and drag the published naming rate down for no reason."""
    rows = _backlog("CVE-2026-1010", "CVE-2026-1011")
    v = inference.apply_to_backlog(
        rows, _corpus(), str(tmp_path / "p.json"), today="2026-08-20",
        suppressed={"CVE-2026-1010"}, covered={"acme"}, sightings={"acme": 99})
    # One row left, and it is nameable, so coverage is 1.0 rather than 0.5.
    assert v["run_coverage"] == 1.0


def test_assert_artefact_refuses_a_suppressed_row(tmp_path):
    with pytest.raises(SystemExit) as e:
        site.assert_artefact(
            [{"cve_id": "CVE-2026-1", "owner": None, "owner_nameable": False,
              "counted": True, "description": "x", "suppressed": True}],
            "rbp.json")
    assert "suppressed" in str(e.value)


def test_a_suppressed_row_does_not_land_in_held_back(tmp_path):
    """A bug I introduced and then caught. Dropping suppressed rows from
    `reportable` removed them from `counted`, so every one of them fell into
    held_back.json with an invented reason of undated or within-buffer. That is
    the file whose earlier leak proved a single-artefact assertion is not an
    assertion, and it publishes the CVE ID."""
    rows = _backlog("CVE-2026-1010", "CVE-2026-1011")
    for r in rows:
        r.update(owner=None, owner_tier="abstain", owner_method="x",
                 indep_sources=1, hours_public=1440, past_expectation=True,
                 rule="4.5.1.6", rule_strength="SHOULD", rule_certainty="unmeasurable",
                 rule_basis="unattributed", self_disclosed=False, clock_known=True,
                 vendor="Acme", package="widget", ecosystem="", advisory_url="u")
    rows[0]["suppressed"] = True
    rows[1]["suppressed"] = False

    sdir = tmp_path / "2026-08-20"
    sdir.mkdir()
    report.build(rows, 0, str(tmp_path), "2026-08-20", [2026], ["debian"],
                 rows=[r for r in rows], min_age=7)

    held = json.load(open(sdir / "held_back.json"))
    backlog_out = json.load(open(sdir / "backlog.json"))
    ids = {r["cve_id"] for r in held} | {r["cve_id"] for r in backlog_out}
    assert "CVE-2026-1010" not in ids, "suppressed id leaked into a published file"
    assert "CVE-2026-1011" in ids


# --------------------------------------------------------------------------
# the routes are actually published (review item 4 part 2)
# --------------------------------------------------------------------------

import pathlib   # noqa: E402
import re        # noqa: E402

ROOT = pathlib.Path(__file__).parent.parent
ISSUE_ROUTE = "issues/new?labels=withhold"
PRIVATE_ROUTE = "github.com/RogoLabs/RBP/security/advisories/new"
MAIL_ROUTE = "mailto:rbp@rogolabs.net"


@pytest.fixture(scope="module")
def built():
    out = ROOT / "site"
    if not (out / "overview.html").exists():
        pytest.skip("site not built; run `python -m rbp.cli build --out site`")
    return out


def test_the_false_promise_is_gone():
    """cna.html promised a correction "on the next build" and that "suppressions
    are counted publicly in aggregate" while `grep -rni suppress rbp/` returned
    nothing. Removing the invitation without providing a route is also not
    acceptable, so the next tests check the route exists."""
    for tpl in (ROOT / "templates").glob("*.html"):
        body = tpl.read_text()
        assert "corrected or suppressed on the next build" not in body, tpl.name


@pytest.mark.parametrize("page", ["method.html", "data.html", "index.html"])
def test_the_private_route_is_published_on_every_surface(built, page):
    """A CNA landing here from a link needs the route on the page they land on,
    not one click away."""
    assert PRIVATE_ROUTE in (built / page).read_text(), page


def test_the_footer_carries_the_route_on_every_dashboard_page(built):
    for page in ("overview.html", "cves.html", "cnas.html", "changes.html",
                 "policy.html", "data.html", "method.html"):
        body = (built / page).read_text()
        assert PRIVATE_ROUTE in body, page
        assert MAIL_ROUTE in body, page


def test_every_route_tells_the_reporter_to_give_the_id_and_nothing_else(built):
    """The single most important instruction in the whole channel. Nobody should
    have to describe a vulnerability, or even say why, to ask that a row about them
    not be listed. Asserted as a property rather than a phrase, because the exact
    wording has already changed once."""
    for page in ("method.html", "data.html", "index.html"):
        text = re.sub(r"\s+", " ",
                      re.sub(r"<[^>]+>", " ", (built / page).read_text())).lower()
        assert "nothing else" in text, page
        assert "no reason" in text or "no reason needed" in text, page
        # And it must not ask the reporter to state a reason.
        for bad in ("explain why", "state the reason", "describe the vulnerability"):
            assert bad not in text, (page, bad)


def test_the_reason_is_not_required_anywhere(built):
    """The mitigation that makes a PUBLIC request acceptable: a request carrying no
    reason does not distinguish an embargo from a wrong owner from a CNA that would
    rather not be listed, so it leaks nothing beyond the identifier."""
    text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ",
                                     (built / "method.html").read_text()))
    assert "does not" in text and "distinguish" in text


def test_security_txt_exists_and_is_well_formed(built):
    """RFC 9116. The site names organisations and invites embargo reports, so the
    one machine-readable place a security team looks must not be empty."""
    p = built / ".well-known" / "security.txt"
    assert p.exists()
    body = p.read_text()
    assert f"Contact: https://{PRIVATE_ROUTE}" in body
    assert "Contact: mailto:rbp@rogolabs.net" in body
    assert re.search(r"^Expires: \d{4}-\d{2}-\d{2}T", body, re.M), "Expires is required"
    assert "Canonical: https://rbptracker.org/.well-known/security.txt" in body


def test_ownership_disputes_are_routed_to_the_authoritative_holder(built):
    """This site can only infer owning_cna. The Root and the Secretariat hold the
    real value, so an ownership dispute has a better destination than us."""
    for page in ("method.html",):
        assert "cveform.mitre.org" in (built / page).read_text(), page


def test_the_two_paths_have_separately_stated_latencies(built):
    """Two different promises. The public request is automatic and lands on the next
    build; the private routes reach a person. Conflating them would over-promise the
    slow half, and promising "next build" for a route the pipeline cannot read would
    be a false statement about the mechanism."""
    text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ",
                                     (built / "method.html").read_text()))
    assert "next build" in text, "the automatic path's latency is unstated"
    assert "five business days" in text, "the human path's latency is unstated"
    # The private routes must be described as reaching a person, not the pipeline,
    # because without a credential the pipeline genuinely cannot read them.
    assert "reach a person" in text or "reaches a person" in text


def test_the_committed_list_in_the_repo_holds_no_cve_id():
    """Asserted on the real file, not a fixture. This is the file that would leak."""
    p = ROOT / "suppressions.txt"
    if not p.exists():
        pytest.skip("no committed suppression list yet")
    for line in p.read_text().splitlines():
        entry = line.split("#", 1)[0].strip()
        if entry:
            assert re.fullmatch(r"[0-9a-f]{64}", entry), (
                f"suppressions.txt holds something that is not a digest: {entry!r}")


def test_a_suppressed_id_appears_in_no_file_report_writes(tmp_path):
    """The end-to-end version, checking EVERY file report.build writes rather than
    the two a hand-picked fixture happened to cover.

    This found a real leak the unit tests above did not: backlog_full.json, the
    ungated audit file, still carried the suppressed row. It is not on
    publish.ALLOWED_SNAPSHOT so it never reaches the data branch, which is exactly
    the reasoning that would justify leaving it there and is wrong twice over.
    That file's earlier version WAS on the branch and needed a history rewrite to
    remove, and a withhold means the id is not written down, not that it is written
    somewhere currently unreachable. An allowlist is one commit away from
    including a filename."""
    victim = "CVE-2026-4242"
    rows = _backlog(victim, "CVE-2026-4243")
    for r in rows:
        r.update(owner=None, owner_tier="abstain", owner_method="x",
                 indep_sources=1, hours_public=1440, past_expectation=True,
                 rule="4.5.1.6", rule_strength="SHOULD", rule_certainty="unmeasurable",
                 rule_basis="unattributed", self_disclosed=False, clock_known=True,
                 vendor="Acme", package="widget", ecosystem="", advisory_url="u")
    rows[0]["suppressed"] = True
    rows[0]["owner_tier"] = "suppressed"
    rows[1]["suppressed"] = False

    sdir = tmp_path / "2026-08-20"
    sdir.mkdir()
    report.build(rows, 0, str(tmp_path), "2026-08-20", [2026], ["debian"],
                 rows=list(rows), min_age=7)

    written = sorted(p.name for p in sdir.iterdir())
    assert len(written) >= 4, f"expected several artefacts, got {written}"
    leaked = [n for n in written if victim in (sdir / n).read_text()]
    assert not leaked, f"suppressed id leaked into {leaked}"
    # And the row that was NOT suppressed is still published, or the test would
    # pass trivially on an empty snapshot.
    assert any("CVE-2026-4243" in (sdir / n).read_text() for n in written)

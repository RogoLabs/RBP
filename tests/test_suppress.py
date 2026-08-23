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
        # Was expected to yield CVE-2026-2222 from the body. It no longer does,
        # and that is the fix: an issue that is not a withhold request cannot
        # withhold a row by mentioning an id in passing.
        {"title": "wrong owner", "body": "see cve-2026-2222 please"},
        {"title": "no id here", "body": ""},
        # The template route: label applied server-side, id in its own field.
        {"title": "Withhold CVE-", "labels": [{"name": "withhold"}],
         "body": "### CVE ID\n\ncve-2026-2222\n"},
    ])

    class P:
        returncode, stdout, stderr = 0, payload, ""
    monkeypatch.setattr(suppress.subprocess, "run", lambda *a, **k: P())
    reqs, err = suppress.from_issues()
    assert err is None
    assert {r["cve_id"] for r in reqs} == {"CVE-2026-1111", "CVE-2026-2222"}
    # The records carry who asked and when, which every anti-abuse decision needs.
    assert all({"author", "created_at", "issue", "confirmed"} <= set(r) for r in reqs)


def test_a_pull_request_is_not_read_as_a_withhold_request(monkeypatch):
    """The issues endpoint returns pull requests too, so a PR mentioning a CVE ID
    in its title would otherwise withhold that row."""
    payload = json.dumps([
        {"title": "Withhold CVE-2026-1111", "body": "",
         "pull_request": {"url": "x"}},
        {"title": "Withhold CVE-2026-2222", "body": ""},
    ])

    class P:
        returncode, stdout, stderr = 0, payload, ""
    monkeypatch.setattr(suppress.subprocess, "run", lambda *a, **k: P())
    reqs, _ = suppress.from_issues()
    assert {r["cve_id"] for r in reqs} == {"CVE-2026-2222"}


def test_the_auto_path_is_capped(tmp_path, monkeypatch):
    """No verification of who may ask is the right call, and it means anyone with a
    GitHub account can remove a row. One issue naming 500 ids would empty the site,
    which is a denial of service against the project's whole purpose."""
    many = [{"cve_id": f"CVE-2026-{3000 + i}", "author": f"a{i}",
             "created_at": f"2026-08-01T00:00:{i:02d}Z", "issue": i,
             "confirmed": False} for i in range(suppress.MAX_AUTO + 12)]
    monkeypatch.setattr(suppress, "from_issues", lambda **kw: (many, None))
    s = suppress.load(str(tmp_path / "none.txt"))
    # The cap no longer decides what is WITHHELD, only what persists without
    # review. A flood is honoured for one cycle and is visible as anomalous.
    assert len(s.auto) == suppress.MAX_AUTO + 12
    assert s.report["needs_review"] == 12
    assert s.report["persists_next_run"] == suppress.MAX_AUTO
    assert s.report["anomalous"] is True


def test_the_published_report_carries_counts_and_never_ids(tmp_path, monkeypatch):
    monkeypatch.setattr(suppress, "from_issues",
                        lambda **kw: ([{"cve_id": "CVE-2026-1111", "author": "a",
                                        "created_at": "2026-08-01T00:00:00Z",
                                        "issue": 1, "confirmed": False}], None))
    p = tmp_path / "s.txt"
    p.write_text(suppress.digest("CVE-2026-2222", KEY) + "\n")
    rep = suppress.load(str(p)).report
    assert rep["committed"] == 1
    assert rep["from_reports"] == 1
    assert rep["needs_review"] == 0
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
    # Globbed, not listed. cnas.html was in this list and no longer exists, and a
    # hardcoded list is equally wrong in the other direction: a new dashboard page
    # would ship without the correction route and nothing would say so.
    pages = sorted(p.name for p in built.glob("*.html")
                   if p.name not in ("index.html",))
    assert len(pages) >= 5, f"only found {pages}; the build did not produce a site"
    for page in pages:
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


# --------------------------------------------------------------------------
# anti-abuse
# --------------------------------------------------------------------------

def _req(cid, author="stranger", created="2026-08-01T00:00:00Z", issue=1,
         confirmed=False):
    return {"cve_id": cid, "author": author, "created_at": created,
            "issue": issue, "confirmed": confirmed}


def test_the_cap_honours_the_oldest_requests_first():
    """The bug this replaced. `sorted(found)[:MAX_AUTO]` sorts by CVE ID string, so
    an attacker naming low-numbered ids sorts ahead of a genuine request filed days
    earlier and silently displaces it.

    A cap that can starve the request it exists to protect is worse than no cap: it
    converts vandalism against the site into denial of the correction channel,
    which is the more serious of the two."""
    genuine = _req("CVE-2026-9999", author="cna", created="2026-08-01T00:00:00Z",
                   issue=1)
    flood = [_req(f"CVE-2020-{1000 + i}", author=f"bot{i}",
                  created="2026-08-20T00:00:00Z", issue=100 + i)
             for i in range(suppress.MAX_AUTO + 10)]
    ids, rep = suppress.triage([genuine] + flood)
    # Nothing can be displaced now: every request holds for the cycle. The
    # ordering still matters because it decides which requests PERSIST without
    # review, and the genuine one filed nineteen days earlier must be among them.
    assert "CVE-2026-9999" in ids, "the earlier genuine request was displaced"
    assert rep["needs_review_ceiling"] > 0
    assert rep["persists_next_run"] <= suppress.MAX_AUTO
    assert rep["anomalous"] is True, "a flood this size must be visible on the site"


def test_one_author_is_honoured_this_cycle_but_not_carried_past_the_cap():
    """The policy inverted on 2026-08-23. Past the per-author cap a request used
    to be silently DROPPED: the row kept publishing, nobody was told, and an
    embargo request could sit unhonoured behind a healthy-looking site.

    Now every request is withheld for the cycle and the cap decides only what
    carries into the next run without review. The failure mode moved from "an
    embargoed row stays published" to "a row is briefly missing"."""
    reqs = [_req(f"CVE-2026-{5000 + i}", author="bot", issue=i)
            for i in range(suppress.MAX_PER_AUTHOR + 8)]
    ids, rep = suppress.triage(reqs)
    assert len(ids) == suppress.MAX_PER_AUTHOR + 8, "every request holds this cycle"
    assert rep["needs_review_per_author"] == 8
    assert rep["persists_next_run"] == suppress.MAX_PER_AUTHOR


def test_a_flood_from_one_author_cannot_crowd_out_another_author():
    """The per-author limit is what makes the global ceiling fair rather than
    first-past-the-post."""
    bot = [_req(f"CVE-2026-{6000 + i}", author="bot",
                created="2026-08-01T00:00:00Z", issue=i) for i in range(20)]
    cna = _req("CVE-2026-7777", author="realcna",
               created="2026-08-02T00:00:00Z", issue=99)
    ids, _ = suppress.triage(bot + [cna])
    assert "CVE-2026-7777" in ids


def test_the_ceiling_is_proportional_when_the_backlog_is_small():
    """25 of 522 rows is nothing. 25 of 40 would be most of the site."""
    reqs = [_req(f"CVE-2026-{7000 + i}", author=f"a{i}", issue=i) for i in range(30)]
    ids, rep = suppress.triage(reqs, backlog_size=40)
    assert rep["ceiling"] == 2, rep
    # Every request holds this cycle; the proportional ceiling now bounds only
    # what survives into the next run without a human confirming it.
    assert len(ids) == 30
    assert rep["persists_next_run"] == 2


def test_the_ceiling_never_drops_below_one():
    """A tiny backlog must not make the channel unusable."""
    _, rep = suppress.triage([_req("CVE-2026-1")], backlog_size=3)
    assert rep["ceiling"] >= 1


def test_a_confirmed_request_bypasses_every_limit():
    """The caps exist to bound an anonymous stranger, not to stop a reviewed
    decision. A genuine mass report must not be held back by a ceiling designed
    for strangers."""
    reqs = [_req(f"CVE-2026-{8000 + i}", author="bot", issue=i, confirmed=True)
            for i in range(60)]
    ids, rep = suppress.triage(reqs, backlog_size=100)
    assert len(ids) == 60
    assert rep["confirmed"] == 60
    assert rep["needs_review_per_author"] == 0 and rep["needs_review_ceiling"] == 0


def test_the_triage_report_is_published_so_abuse_is_visible():
    """"The count went down" is indistinguishable from abuse unless the site says
    how many requests it received and how many it declined."""
    reqs = [_req(f"CVE-2026-{9000 + i}", author="bot", issue=i) for i in range(9)]
    _, rep = suppress.triage(reqs)
    assert rep["requested"] == 9
    assert rep["honoured"] == 9, "everything requested is withheld this cycle"
    assert rep["authors"] == 1
    assert rep["needs_review_per_author"] == 9 - suppress.MAX_PER_AUTHOR
    assert rep["persists_next_run"] == suppress.MAX_PER_AUTHOR


def test_the_published_report_still_carries_no_identifiers(tmp_path, monkeypatch):
    monkeypatch.setattr(suppress, "from_issues",
                        lambda **kw: ([_req("CVE-2026-1111")], None))
    rep = suppress.load(str(tmp_path / "none.txt")).report
    assert "CVE" not in json.dumps(rep).upper()
    assert rep["requested"] == 1 and rep["from_reports"] == 1


def test_a_closed_issue_is_not_read_at_all():
    """Revocation is instant and does not wait for a build: the query asks for open
    issues only, so closing one takes effect on the next read."""
    import inspect
    src = inspect.getsource(suppress.from_issues)
    assert "state=open" in src


def test_a_suppressed_row_is_dropped_from_the_published_count_not_just_the_files():
    """The failure this replaced. Suppression was applied only inside report.build,
    so backlog.json lost the withheld row while clock.summary still counted it, and
    _assert_consistent refused to publish 521 rows under a headline of 522.

    That guard did its job and the build failed closed rather than publishing
    contradictory numbers. But the cause was cli.py's own stated rule being broken:
    one population, computed once, and one writer filtered a population the others
    did not. Grep-style, because the rule lives in a comment and comments do not
    hold."""
    import pathlib
    src = (pathlib.Path(__file__).parent.parent / "rbp" / "cli.py").read_text()
    start = src.index("reportable = [r for r in backlog")
    # Bounded by the next statement rather than by the first "]", which the first
    # version of this test used and which lands inside r["days_public"].
    end = src.index("clock.split_epoch(reportable)", start)
    block = src[start:end]
    assert 'not r.get("suppressed")' in block, (
        "cli.py builds `reportable` without excluding suppressed rows, so "
        "clock.summary and backlog.json will disagree about the total again")


def test_a_previously_named_suppressed_row_loses_its_ledger_prediction():
    """grader.withdraw KEEPS whatever is in record_for. inference refuses to record
    a NEW prediction for a suppressed row, but an old one from an earlier run would
    have survived, leaving the CVE ID and the inferred CNA name in precision.json on
    the public data branch. The withhold would have been complete everywhere a
    reader looks and incomplete in the one file recording who this site accused."""
    import pathlib
    src = (pathlib.Path(__file__).parent.parent / "rbp" / "cli.py").read_text()
    assert "_published_ids -= _suppressed_ids" in src, (
        "suppressed ids are still inside record_for, so grader.withdraw will "
        "retain their earlier predictions")
    # And the subtraction must happen AFTER the lever is loaded, or it subtracts
    # from a set that does not know what is suppressed yet.
    assert src.index("sup = suppress.load(") < src.index("_published_ids -= ")


# --------------------------------------------------------------------------
# a withhold has to reach history, not only today
# --------------------------------------------------------------------------

def test_stage_scrubs_withheld_ids_from_prior_snapshots(tmp_path):
    """The first live withhold left the row absent from rbp.json, rbp.csv,
    summary.json, cnas.json and precision.json, and still present in the PREVIOUS
    day's snapshot on the data branch, where retention keeps it for up to a month.

    A withhold that only applies going forward is not a withhold: the id stays
    fetchable from yesterday. Found by checking the branch rather than the site."""
    from rbp import publish

    victim = "CVE-2026-4242"
    data = tmp_path / "data"
    data.mkdir()
    (data / ".suppressed.json").write_text(json.dumps([victim]))

    snaps = tmp_path / "snapshots"
    for date in ("2026-08-21", "2026-08-22"):
        d = snaps / date
        d.mkdir(parents=True)
        (d / "backlog.json").write_text(json.dumps(
            [{"cve_id": victim, "owner": None}, {"cve_id": "CVE-2026-4243"}]))
        (d / "backlog.csv").write_text(
            f"cve_id,owner\n{victim},\nCVE-2026-4243,\n")
        (d / "summary.json").write_text(json.dumps({"total": 2}))

    state = tmp_path / ".state"
    publish.stage(str(snaps), str(state), str(data))

    for date in ("2026-08-21", "2026-08-22"):
        for f in ("backlog.json", "backlog.csv"):
            body = (state / "snapshots" / date / f).read_text()
            assert victim not in body, f"{date}/{f} still holds the withheld id"
            assert "CVE-2026-4243" in body, "scrub removed the wrong rows"


def test_stage_scrubs_both_root_ledgers(tmp_path):
    """resolutions.json sits at the branch ROOT, so every snapshot-scoped rule
    misses it. On the first live withhold the row was gone from every snapshot
    artefact and still in resolutions.json under `open`."""
    from rbp import publish

    victim = "CVE-2026-4242"
    data = tmp_path / "data"
    data.mkdir()
    (data / ".suppressed.json").write_text(json.dumps([victim]))
    (data / "resolutions.json").write_text(json.dumps(
        {"open": {victim: {"first_public": "2025-03-19", "owner": None},
                  "CVE-2026-4243": {"first_public": "2026-01-01", "owner": None}},
         "resolved": [{"cve_id": victim}, {"cve_id": "CVE-2026-9"}]}))
    (data / "precision.json").write_text(json.dumps(
        {"predictions": {victim: {"predicted": "acme"}}, "graded": []}))
    (tmp_path / "snapshots").mkdir()

    state = tmp_path / ".state"
    publish.stage(str(tmp_path / "snapshots"), str(state), str(data))

    res = json.loads((state / "resolutions.json").read_text())
    assert victim not in res["open"]
    assert "CVE-2026-4243" in res["open"]
    assert not any(r.get("cve_id") == victim for r in res["resolved"])
    prec = json.loads((state / "precision.json").read_text())
    assert victim not in prec["predictions"]


def test_stage_is_unaffected_when_nothing_is_withheld(tmp_path):
    """The scrub must be a no-op on the normal path, not a rewrite of every file."""
    from rbp import publish
    data = tmp_path / "data"
    data.mkdir()
    snaps = tmp_path / "snapshots" / "2026-08-22"
    snaps.mkdir(parents=True)
    original = json.dumps([{"cve_id": "CVE-2026-1"}])
    (snaps / "backlog.json").write_text(original)
    state = tmp_path / ".state"
    publish.stage(str(tmp_path / "snapshots"), str(state), str(data))
    assert (state / "snapshots" / "2026-08-22" / "backlog.json").read_text() == original


def test_a_missing_handoff_file_does_not_break_staging(tmp_path):
    """data/ is gitignored and the file is runner-local, so a `publish stage` run
    without a preceding pipeline must still work rather than crash."""
    from rbp import publish
    (tmp_path / "data").mkdir()
    (tmp_path / "snapshots").mkdir()
    assert publish._suppressed(str(tmp_path / "data")) == set()
    publish.stage(str(tmp_path / "snapshots"), str(tmp_path / ".state"),
                  str(tmp_path / "data"))


@pytest.mark.parametrize("as_real_type", [False, True])
def test_the_resolution_ledger_drops_and_refuses_suppressed_rows(as_real_type):
    """ResolutionLedger.track both stops new entries and removes existing ones.

    Parametrised over a plain set AND the real Suppressions object, because the
    first version of this test used a set and passed while production raised
    `TypeError: 'Suppressions' object is not iterable`. A test that exercises a
    convenient stand-in instead of the type the caller actually passes is checking
    the wrong thing."""
    from rbp import clock
    import tempfile
    ids = {"CVE-2026-1", "CVE-2026-2"}
    sup = suppress.Suppressions([], ids, key=KEY) if as_real_type else ids
    with tempfile.TemporaryDirectory() as d:
        led = clock.ResolutionLedger(os.path.join(d, "r.json"))
        led.state["open"]["CVE-2026-1"] = {"first_public": "2026-01-01", "owner": None}
        dropped = led.track([{"cve_id": "CVE-2026-2", "public_date": "2026-02-01"}],
                            suppressed=sup)
        assert dropped == 1, "an existing entry was not removed"
        assert "CVE-2026-1" not in led.state["open"]
        assert "CVE-2026-2" not in led.state["open"], "a new entry was added anyway"


def test_suppressions_refuses_iteration_with_a_reason():
    """The committed half holds keyed hashes, not CVE IDs, exactly so the list
    cannot be enumerated by anyone holding the file. That property would be quietly
    false if this object could be iterated, and a caller iterating it would get
    only the open-request ids while believing it had them all."""
    s = suppress.Suppressions([suppress.digest("CVE-2026-1", KEY)],
                              {"CVE-2026-2"}, key=KEY)
    with pytest.raises(TypeError) as e:
        list(s)
    msg = str(e.value)
    assert "keyed hashes" in msg
    assert "membership" in msg, "the error must say what to do instead"
    # Membership still works in both halves.
    assert "CVE-2026-1" in s and "CVE-2026-2" in s


def test_no_caller_iterates_the_suppression_set():
    """Grep-style. The production failure was one `for c in suppressed` in a
    module that had no reason to enumerate."""
    import pathlib
    import re
    for f in (pathlib.Path(__file__).parent.parent / "rbp").glob("*.py"):
        if f.name == "suppress.py":
            continue
        body = re.sub(r"#.*", "", f.read_text())
        body = re.sub(r'""".*?"""', "", body, flags=re.S)
        for bad in ("for c in suppressed", "for cid in suppressed",
                    "set(suppressed)", "list(suppressed)", "sorted(suppressed)"):
            assert bad not in body, f"{f.name} iterates the suppression set: {bad}"


def test_a_withhold_reaches_the_dated_archive(tmp_path):
    """"The archive is immutable" and "a withhold removes a row from it" are in
    tension. The resolution is that the archive is REBUILT from the staged snapshots
    on every run rather than appended to, so scrubbing the snapshots is what reaches
    it. Verified rather than assumed, because the alternative failure is an archive
    that quietly becomes the reason a withhold does not work."""
    from rbp import site as site_mod

    victim = "CVE-2026-8888"
    snaps = tmp_path / "snapshots" / "2026-08-22"
    snaps.mkdir(parents=True)
    keep = {"cve_id": "CVE-2026-9999", "owner": None, "owner_nameable": False,
            "counted": True, "days_public": 30, "public_date": "2026-07-01",
            "description": "a flaw", "sources": "debian"}
    # The staged snapshot has already been scrubbed by publish.stage, so the
    # withheld row is simply not in it. The archive must not resurrect it.
    (snaps / "backlog.json").write_text(json.dumps([keep]))
    (snaps / "cnas.json").write_text("[]")
    (snaps / "summary.json").write_text(json.dumps({
        "total": 1, "past_expectation": 1, "oldest_days": 30, "median_days": 30,
        "named_cnas": 0, "must_rows": 0, "should_rows": 1, "clock_unknown": 0,
        "unmeasurable_rows": 1, "candidate_rows": 0, "undated_excluded": 0,
        "min_age_days": 7, "age_buckets": {}, "epoch": None,
        "inference": {"k": 3, "run_coverage": 0.0,
                      "leave_one_out": {"precision": 0.99, "coverage": 0.6,
                                        "decided": 100},
                      "live": {"graded": 0, "correct": 0, "precision": None,
                               "below_floor": True, "outstanding": 0, "by_tier": {}}},
        "feeds": {"requested": [], "failures": [], "attempts": 0, "truncated": [],
                  "detail": {}},
        "coverage": {"total_cnas": 539, "cnas_effective": 1, "cnas_own_channel": 0,
                     "cnas_sighted": 1, "min_sightings": 3, "pct_cnas": 0.2,
                     "pct_effective": 0.2, "observed_pct": 1.0, "profile": "weekly",
                     "top_n": 50, "top_covered": 1, "roster_pinned": True},
    }))
    (tmp_path / "data").mkdir()
    out = tmp_path / "site"
    site_mod.build(str(out), str(tmp_path / "snapshots"), str(tmp_path / "data"))

    dated = out / "data" / "archive" / "2026-08-22" / "rbp.json"
    assert dated.exists()
    body = dated.read_text()
    assert victim not in body, "the archive resurrected a withheld row"
    assert "CVE-2026-9999" in body, "the archive dropped a row it should carry"


# --------------------------------------------------------------------------
# the channel has to be reachable by someone with no repo permissions (item 6)
# --------------------------------------------------------------------------

def _issue(title="Withhold CVE-2026-1234", body="", labels=(), login="stranger"):
    return {"title": title, "body": body, "user": {"login": login},
            "labels": [{"name": n} for n in labels],
            "number": 1, "created_at": "2026-08-20T00:00:00Z"}


def _run_with(monkeypatch, issues):
    payload = json.dumps(issues)

    class P:
        returncode, stdout, stderr = 0, payload, ""
    monkeypatch.setattr(suppress.subprocess, "run", lambda *a, **k: P())
    return suppress.from_issues()


def test_an_unlabelled_request_from_a_stranger_is_read(monkeypatch):
    """THE defect. Every surface linked issues/new?labels=withhold, and the
    `labels` query parameter is honoured only for accounts with triage
    permission. A CNA employee with an ordinary account filed an UNLABELLED
    issue, the query filtered on the label server-side and never returned it,
    and because the API call succeeded no degraded banner fired either. The
    request vanished with no error anywhere, which is the worst possible
    behaviour for a channel whose purpose is that someone can reach us."""
    reqs, err = _run_with(monkeypatch, [_issue(labels=())])
    assert err is None
    assert {r["cve_id"] for r in reqs} == {"CVE-2026-1234"}


def test_the_label_still_works_for_a_template_filed_request(monkeypatch):
    """The template applies the label server-side, so a request filed through it
    matches on both. Neither route may be the only one that works."""
    reqs, _ = _run_with(monkeypatch, [
        _issue(title="Anything at all", body="### CVE ID\n\nCVE-2026-5555\n",
               labels=("withhold",))])
    assert {r["cve_id"] for r in reqs} == {"CVE-2026-5555"}


def test_an_ordinary_issue_mentioning_a_cve_withholds_nothing(monkeypatch):
    """The read is now unfiltered, so the matcher is the ONLY thing standing
    between a bug report and a silent withhold.

    The id is in the TITLE deliberately. An earlier version of this test put it
    in the body, where the template-field parser already excluded it, so
    disabling the matcher entirely still passed."""
    reqs, _ = _run_with(monkeypatch, [
        _issue(title="Wrong package shown for CVE-2026-7777",
               body="The package column says qemu but it is ceph.", labels=())])
    assert reqs == [], (
        "an ordinary issue naming a CVE in its title was read as a request to "
        "withhold that row")


def test_the_issue_read_is_not_filtered_on_the_label(monkeypatch):
    """Asserted on the REQUEST, not the response.

    Every other test here mocks subprocess.run with a fixed payload, so the URL
    is unobservable and restoring the server-side label filter passes all of
    them. That filter is the entire defect: it made the channel unreachable for
    any account without triage permission, which is every account this channel
    exists for."""
    seen = {}

    class P:
        returncode, stdout, stderr = 0, "[]", ""

    def fake_run(cmd, *a, **k):
        seen["cmd"] = cmd
        return P()
    monkeypatch.setattr(suppress.subprocess, "run", fake_run)
    suppress.from_issues()

    url = next(c for c in seen["cmd"] if "issues?" in c)
    assert "labels=" not in url, (
        f"the read filters on the label server-side again: {url}. Only accounts "
        "with triage permission can apply it, so this hides exactly the "
        "requests the channel exists to receive.")
    assert "state=open" in url


def test_prose_in_the_body_cannot_withhold_an_unrelated_row(monkeypatch):
    """`blob = title + body` meant every distinct CVE ID anywhere in the text
    became a request, so "same root cause as CVE-2025-1111" withheld a row
    nobody asked about."""
    reqs, _ = _run_with(monkeypatch, [
        _issue(title="Withhold CVE-2026-1234",
               body="Same root cause as CVE-2025-1111, which is fine to keep.")])
    assert {r["cve_id"] for r in reqs} == {"CVE-2026-1234"}, (
        "an id mentioned in prose was read as a withhold request")


def test_the_issue_template_exists_and_applies_the_label():
    """The template is what makes the label reachable without permissions. A
    broken or missing one silently returns the channel to labels-only."""
    import pathlib
    tpl = (pathlib.Path(__file__).parent.parent
           / ".github" / "ISSUE_TEMPLATE" / "withhold.yml")
    assert tpl.exists(), "no issue template; the label cannot be applied server-side"
    body = tpl.read_text()
    assert f'labels: ["{suppress.WITHHOLD_LABEL}"]' in body
    # The prefilled title must match what from_issues accepts, or a
    # template-filed request relies on the label alone.
    assert 'title: "Withhold CVE-' in body
    assert suppress._TITLE_RE.match("Withhold CVE-2026-1")
    # And it must warn that the id becomes public, since that is the one thing
    # a requester with an embargo needs to know before filing.
    assert "security.txt" in body and "permanent" in body.lower()


def test_every_withhold_link_points_at_the_template():
    """Six surfaces linked ?labels=withhold, which does nothing for the accounts
    this channel is for. Asserted across all of them, because they drifted apart
    once already."""
    import pathlib
    root = pathlib.Path(__file__).parent.parent
    files = list((root / "templates").glob("*.html")) + \
        [root / "placeholder.html", root / "rbp" / "site.py"]
    seen = 0
    for f in files:
        if not f.exists():
            continue
        body = f.read_text()
        if "issues/new" not in body:
            continue
        for line in body.splitlines():
            if "issues/new" in line and "#" not in line.split("issues/new")[0][-4:]:
                seen += 1
                assert "template=withhold.yml" in line, f"{f.name}: {line.strip()[:90]}"
    assert seen >= 4, f"only found {seen} withhold links; the check is not covering them"

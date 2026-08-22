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
    reqs, err = suppress.from_issues()
    assert err is None
    assert {r["cve_id"] for r in reqs} == {"CVE-2026-1111", "CVE-2026-2222"}
    # The records carry who asked and when, which every anti-abuse decision needs.
    assert all({"author", "created_at", "issue", "confirmed"} <= set(r) for r in reqs)


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
    assert len(s.auto) == suppress.MAX_AUTO
    assert s.report["deferred"] == 12
    assert s.report["from_reports"] == suppress.MAX_AUTO


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
    assert rep["deferred"] == 0
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
    assert "CVE-2026-9999" in ids, "the earlier genuine request was displaced"
    assert rep["deferred_ceiling"] > 0
    assert len(ids) <= suppress.MAX_AUTO


def test_one_author_cannot_consume_the_whole_budget():
    reqs = [_req(f"CVE-2026-{5000 + i}", author="bot", issue=i)
            for i in range(suppress.MAX_PER_AUTHOR + 8)]
    ids, rep = suppress.triage(reqs)
    assert len(ids) == suppress.MAX_PER_AUTHOR
    assert rep["deferred_per_author"] == 8


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
    assert len(ids) == 2


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
    assert rep["deferred_per_author"] == 0 and rep["deferred_ceiling"] == 0


def test_the_triage_report_is_published_so_abuse_is_visible():
    """"The count went down" is indistinguishable from abuse unless the site says
    how many requests it received and how many it declined."""
    reqs = [_req(f"CVE-2026-{9000 + i}", author="bot", issue=i) for i in range(9)]
    _, rep = suppress.triage(reqs)
    assert rep["requested"] == 9
    assert rep["honoured"] == suppress.MAX_PER_AUTHOR
    assert rep["authors"] == 1
    assert rep["deferred_per_author"] == 9 - suppress.MAX_PER_AUTHOR


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

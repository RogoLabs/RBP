"""
The end-to-end artefact test (review chair item C2).

Every other test in this repository is either a unit test over a function or a
string match over source. Nothing ran the real pipeline over a fixture corpus and
asserted invariants on the files it actually writes, and that single gap is the
common cause of a long list of defects that each had to be found by hand:

  - `backlog.csv` had its own generator expression, so the de-naming applied to
    `backlog.json` missed it and the CSV kept shipping `owner_nameable=True`.
  - the per-CNA JSON endpoints sat outside `assert_artefact` entirely, so they
    kept emitting named files after every page had stopped.
  - `backlog_full.json` was a third writer of the same rows.
  - the dated archive is rebuilt from prior snapshots, so it republished names
    the current build had stripped.
  - `publish.check` globbed `snapshots/*/*.json`, so the two root ledgers were
    exempt by construction and 121 names sat on the public branch behind a guard
    that returned clean.

Four of those five are the same shape: a SECOND WRITER for rows that already had
a guarded writer. A unit test cannot see that shape, because the thing that is
wrong is the set of files on disk, not the behaviour of any one function.

So the rule this file encodes: **run the build, then walk everything it produced
and assert over the set.** Assertions here should be about the artefacts as a
population ("no file anywhere carries X", "every file agrees about Y"), not about
one file, because a per-file assertion is exactly what an unguarded new writer
slips past.
"""
from __future__ import annotations

import csv
import glob
import importlib
import json
import os
import pathlib

import pandas as pd
import pytest

from rbp import classify, inference, report, schema, site, publish
from rbp.attribution import Attributor

# A synthetic block: acme owns a clean run so one row is nameable at k=3, and the
# space fragments so another must abstain. Deliberately the same shape as the
# pipeline fixture, because the point is to exercise BOTH branches: the row the
# inference names is the one whose name must not reach any artefact.
ACME = list(range(1000, 1010))
FRAGMENTED = {1100: "alpha", 1101: "beta", 1102: "alpha", 1103: "gamma",
              1105: "beta", 1106: "alpha", 1107: "gamma"}
NAMEABLE = "CVE-2026-1004"
ABSTAIN = "CVE-2026-1104"


@pytest.fixture
def corpus():
    rows = [(f"CVE-2026-{n}", "PUBLISHED", "acme", "Acme", "widget")
            for n in ACME if n != 1004]
    rows += [(f"CVE-2026-{n}", "PUBLISHED", a, a, "thing")
             for n, a in FRAGMENTED.items()]
    return pd.DataFrame(rows, columns=["cve_id", "state", "assigner",
                                       "vendor", "product"])


@pytest.fixture
def built(tmp_path, corpus, monkeypatch):
    """Run the pipeline end to end and return every path it wrote.

    Not `cli.run`: that refreshes a 583 MB corpus and calls a live API. This is
    the same sequence with the corpus and the oracle supplied, which is the part
    that writes files.
    """
    monkeypatch.setattr(classify, "_get", lambda cid, attempts=3: {
        "state": "RESERVED", "assigner": "[REDACTED]"})

    def entry(product, sources):
        return {"public_date": "2026-07-01", "sources": set(sources),
                "refs": {f"{s}:x" for s in sources},
                "description": f"{product} flaw", "product": product}

    refs = {NAMEABLE: entry("widget", ["debian", "alas"]),
            ABSTAIN: entry("thing", ["debian", "ghsa"])}

    backlog, fresh, _ = classify.classify(
        refs, corpus, Attributor(corpus), str(tmp_path / "cache.json"),
        workers=2, today="2026-08-20")

    # Inference RUNS. This is the branch that matters: the grader records a real
    # prediction for NAMEABLE, and nothing downstream may publish it.
    inference.apply_to_backlog(backlog, corpus, str(tmp_path / "precision.json"),
                               today="2026-08-20")
    assert any(r.get("owner") for r in backlog), (
        "the fixture no longer produces a named row, so this test would pass "
        "without exercising the de-naming at all")

    snaps = tmp_path / "snapshots"
    sdir, _md, _kpi = report.build(backlog, fresh, str(snaps), "2026-08-20",
                                   {2026}, ["debian", "alas", "ghsa"], min_age=14)

    # cli.run writes summary.json, cnas.json and resolved.json AFTER report.build
    # returns (cli.py:321, :398-399). The harness has to write them too, or it is
    # not exercising the artefact set the site actually reads.
    published = json.loads((pathlib.Path(sdir) / "backlog.json").read_text())
    stats = {
        "date": "2026-08-20", "total": len(published), "past_expectation": 0,
        "oldest_days": 50, "median_days": 50, "named_cnas": 0,
        "must_rows": 0, "should_rows": len(published), "clock_unknown": 0,
        "unmeasurable_rows": len(published), "candidate_rows": 0,
        "undated_excluded": 0, "epoch": None, "epoch_excluded": 0,
        "min_age_days": 14, "age_buckets": {"30d+": len(published)},
        "corroborated": 0, "single_origin": len(published),
        "generated_at": "2026-08-20T00:00:00+00:00",
        "source_commit": schema.source_commit(),
        "source_dirty": schema.source_dirty(),
        "inference": {"k": 3, "run_coverage": 0.5,
                      "leave_one_out": {"precision": 0.99, "coverage": 0.6,
                                        "decided": 10},
                      "live": {"graded": 0, "correct": 0, "precision": None,
                               "below_floor": True, "outstanding": 1,
                               "by_tier": {}}},
        "feeds": {"requested": ["debian", "alas", "ghsa"], "failures": [],
                  "attempts": 3, "truncated": [], "detail": {}},
        "coverage": {"total_cnas": 539, "cnas_effective": 117,
                     "cnas_sighted": 152, "cnas_own_channel": 2,
                     "min_sightings": 3, "pct_cnas": 28.2, "pct_effective": 21.7,
                     "observed_pct": 12.5, "profile": "weekly",
                     "roster_pinned": True, "covered": ["acme"],
                     # Deliberately ABOVE the gate. The launched posture is
                     # where the per-CNA writers live, and a fixture that cannot
                     # clear the gate never reaches them: the first version of
                     # this harness built pre-launch only, and a mutation that
                     # re-enabled the per-CNA JSON endpoints passed all ten
                     # assertions because nothing ever ran that branch.
                     "top_n": 50, "top_covered_effective": 45,
                     "top_covered": 47, "pct_top_effective": 90.0,
                     "top_missed_effective": []},
    }
    (pathlib.Path(sdir) / "summary.json").write_text(json.dumps(stats))
    # cnas.json carries an entry DELIBERATELY, even though v1 publishes no
    # per-CNA aggregates. The per-CNA page and JSON writers iterate this list, so
    # an empty one makes them inert and a mutation re-enabling them passes every
    # assertion in this file. A snapshot restored from the data branch predates
    # the de-naming and looks exactly like this, so it is also realistic.
    (pathlib.Path(sdir) / "cnas.json").write_text(json.dumps([{
        "cna": "acme", "slug": "acme", "outstanding": 0, "oldest_days": 50,
        "median_days_public": 50, "past_expectation": 0, "must_rows": 0,
        "should_rows": 0, "published_12mo": 100, "rate": 0.0,
        "rate_wilson_lower": 0.0, "rate_suppressed": False,
        "resolved_n": 0, "median_days_to_publish": None}]))
    (pathlib.Path(sdir) / "resolved.json").write_text("[]")

    # A PRIOR snapshot, carrying a name, exactly as one restored from the data
    # branch would. Without it there is no dated archive at all and the archive
    # assertions skip, which is how a mutation that republished prior snapshots
    # unstripped passed this file.
    prior = snaps / "2026-08-19"
    prior.mkdir(parents=True, exist_ok=True)
    (prior / "backlog.json").write_text(json.dumps([{
        "cve_id": "CVE-2026-1004", "owner": "acme", "owner_tier": "block",
        "owner_method": "block-k3", "owner_nameable": True, "counted": True,
        "days_public": 49, "public_date": "2026-07-01", "sources": "debian",
        "description": "a flaw"}]))
    # total must match ITS OWN row count, not today's. The archive envelope for a
    # dated snapshot is built from that day's file, so a mismatched total here is
    # a fixture bug that reads exactly like the truncated-artefact defect.
    (prior / "summary.json").write_text(json.dumps(
        {**stats, "date": "2026-08-19", "total": 1, "single_origin": 1,
         "should_rows": 1, "unmeasurable_rows": 1,
         "age_buckets": {"30d+": 1}}))
    (prior / "cnas.json").write_text("[]")

    data = tmp_path / "data"
    data.mkdir(exist_ok=True)
    for name in ("precision.json",):
        src = tmp_path / name
        if src.exists():
            (data / name).write_text(src.read_text())

    # BOTH POSTURES. The launched build is not a variant to check later, it is
    # where several writers live: the per-CNA pages and the per-CNA JSON
    # endpoints are gated on `launched`, so a pre-launch-only harness cannot see
    # them at all. Verified by mutation: re-enabling the per-CNA endpoints passed
    # every assertion here until this loop existed.
    outs = {}
    for launched in (False, True):
        monkeypatch.setenv("RBP_LAUNCHED", "1" if launched else "")
        importlib.reload(site)
        out = tmp_path / ("launched" if launched else "prelaunch")
        site.build(str(out), str(snaps), str(data))
        outs[launched] = out

    state = tmp_path / ".state"
    state.mkdir(exist_ok=True)
    publish.stage(str(snaps), str(state), str(data))

    yield {"site": outs[False], "launched_site": outs[True],
           "sites": [outs[False], outs[True]],
           "snapshots": snaps, "state": state, "data": data, "root": tmp_path}
    monkeypatch.delenv("RBP_LAUNCHED", raising=False)
    importlib.reload(site)


def _json_files(root):
    return [pathlib.Path(p) for p in
            glob.glob(os.path.join(str(root), "**", "*.json"), recursive=True)]


def _row_lists(path):
    """Every list-of-rows in a JSON file, whatever shape wraps it."""
    try:
        body = json.loads(path.read_text())
    except (OSError, ValueError):
        return []
    if isinstance(body, list):
        return [body]
    if isinstance(body, dict):
        out = []
        for v in body.values():
            if isinstance(v, list) and v and isinstance(v[0], dict):
                out.append(v)
        return out
    return []


# --------------------------------------------------------------------------
# the population assertions: about the SET of files, not any one of them
# --------------------------------------------------------------------------

def test_no_produced_file_anywhere_carries_a_name(built):
    """The assertion that would have caught four separate writers at once.

    Walks everything the build wrote, in every directory, rather than an
    allowlist of files known to matter. An allowlist is what let the per-CNA
    endpoints and backlog.csv through: each was a new writer, and nothing added
    it to the list of files anyone checked.
    """
    checked = 0
    # site builds and the STAGED tree, plus the snapshot this run wrote. The raw
    # snapshots/ directory also holds a deliberately dirty prior snapshot, which
    # is INPUT: it stands in for one restored from the data branch, written
    # before the de-naming existed. What must be clean is everything the build
    # produces from it, which is why .state is walked and snapshots/ is not.
    roots = list(built["sites"]) + [built["state"]]
    for root in roots:
        for f in _json_files(root):
            for rows in _row_lists(f):
                for r in rows:
                    if not isinstance(r, dict):
                        continue
                    checked += 1
                    for field in site.NAME_FIELDS:
                        assert r.get(field) is None, (
                            f"{f}: {r.get('cve_id')} carries {field}")
    assert checked > 0, "walked the build and found no rows; the fixture is broken"


def test_no_per_cna_artefact_is_produced_in_either_posture(built):
    """A STRUCTURAL assertion, and it needs to be structural.

    The row-level scans above cannot see this defect. A per-CNA endpoint under
    v1 writes {"cna": "acme", "summary": {...}, "rows": []}: the rows list is
    empty because no row carries that owner any more, so every "does any row
    carry a name" assertion passes while a file NAMED FOR A CNA, containing that
    CNA's short name, is published. Verified by mutation, which is the only
    reason this test exists: re-enabling the endpoint passed all ten of the
    other assertions in this file.

    v1 publishes no attribution, so the claim is simply that no such artefact is
    produced, in either posture. The launched posture matters most: that is where
    the per-CNA writers are gated, so pre-launch-only checking sees nothing.
    """
    for out in built["sites"]:
        assert not list(out.glob("cna/*.html")), f"{out} wrote per-CNA pages"
        assert not list((out / "data").glob("cna/*.json")), (
            f"{out} wrote per-CNA JSON endpoints")
        assert not (out / "cnas.html").exists(), f"{out} wrote the CNA index"

    # And nothing in the staged tree is keyed by CNA either.
    for f in _json_files(built["state"]):
        body = json.loads(f.read_text())
        if isinstance(body, dict):
            assert "cna" not in body, f"{f} is a per-CNA artefact"


def test_no_produced_csv_anywhere_has_an_owner_column(built):
    """CSVs are a separate writer path and were missed by the JSON assertions."""
    found = 0
    roots = list(built["sites"]) + [built["snapshots"], built["state"]]
    for root in roots:
        for p in glob.glob(os.path.join(str(root), "**", "*.csv"),
                           recursive=True):
            rows = list(csv.DictReader(open(p)))
            if not rows:
                continue
            found += 1
            for field in site.NAME_FIELDS:
                assert field not in rows[0], f"{p} has a {field} column"
            for r in rows:
                assert r.get("owner_nameable") == "False", p
    assert found > 0, "no CSV was produced, so this test asserts nothing"


def test_every_envelope_agrees_with_its_own_row_count(built):
    """`len(rows) == counts.total` on every envelope. A truncated artefact that
    still reports the old total is the failure that published a front page
    reading 553 above an empty table."""
    seen = 0
    for f in _json_files(built["site"]):
        body = json.loads(f.read_text())
        if not isinstance(body, dict) or "counts" not in body:
            continue
        rows, total = body.get("rows"), (body.get("counts") or {}).get("total")
        if not isinstance(rows, list) or total is None:
            continue
        seen += 1
        if body.get("kind") == "backlog":
            assert len(rows) == total, f"{f.name}: {len(rows)} rows, counts.total {total}"
    assert seen > 0, "no envelope carried counts; the contract changed"


def test_every_envelope_declares_the_same_schema_version_and_commit(built):
    """A build that produces two schema versions has two writers, one of which
    did not get the memo. Same for provenance: an artefact that cannot say which
    code produced it is the defect review item 1 is about."""
    versions, commits = set(), set()
    for f in _json_files(built["site"]):
        body = json.loads(f.read_text())
        if isinstance(body, dict) and "schema_version" in body:
            versions.add(body["schema_version"])
            if "source_commit" in body:
                commits.add(body["source_commit"])
    assert versions == {schema.SCHEMA_VERSION}, versions
    assert len(commits) == 1, f"artefacts disagree about their source commit: {commits}"
    # Agreement is not enough: every artefact agreeing on None is agreement.
    commit = commits.pop()
    assert commit and commit != "unknown", (
        f"artefacts carry no usable source commit ({commit!r}); a build that "
        "cannot say which code produced it is review item 1")


def test_the_column_contract_holds_in_both_directions(built):
    """Key-set equality, not containment. Containment passes when a writer emits
    an EXTRA field, which is exactly how an ungated product-map field reached 112
    published rows."""
    csvs = glob.glob(os.path.join(str(built["site"]), "**", "*.csv"), recursive=True)
    assert csvs
    for p in csvs:
        header = open(p).readline().strip().split(",")
        assert header == schema.COLUMNS, f"{p} header drifted from the contract"


def test_the_dated_archive_is_judged_like_every_other_artefact(built):
    """The archive is rebuilt from prior snapshots on every run, so it is a
    writer in its own right and was the last one to keep publishing names."""
    arch = built["site"] / "data" / "archive"
    if not arch.exists():
        pytest.skip("no prior snapshot in this fixture, so no archive to judge")
    files = list(arch.glob("*/rbp.json"))
    assert files, "the archive directory exists but is empty"
    for f in files:
        body = json.loads(f.read_text())
        assert body.get("schema_version") == schema.SCHEMA_VERSION
        for r in body.get("rows") or []:
            for field in site.NAME_FIELDS:
                assert r.get(field) is None, f"{f} republished {field}"


def test_the_staged_tree_passes_its_own_guard(built):
    """publish.check over the real staged output."""
    assert publish.check(str(built["state"])) == []


@pytest.mark.parametrize("target", ["precision.json", "resolutions.json",
                                    "snapshots/2026-08-20/backlog.json"])
def test_the_guard_actually_fires_on_a_name_in_each_location(built, target):
    """A POSITIVE CONTROL, and the most important test in this file.

    "check returns [] on a clean tree" is satisfied by a guard that returns []
    on everything, which is exactly what the real one did: it globbed
    snapshots/*/*.json, so the two root ledgers were exempt BY CONSTRUCTION, and
    it reported clean on a branch tip carrying 121 ungated names. A guard is only
    verified by watching it fail.

    Parametrised over the locations rather than asserted once, because the defect
    was not "the guard is broken" but "the guard does not reach here". A single
    injection into a snapshot would have passed against the old guard too.
    """
    path = built["state"] / target
    if not path.exists():
        # resolutions.json is only staged when the pipeline produced one.
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"open": {}}))

    body = json.loads(path.read_text())
    if isinstance(body, list):
        assert body, f"{target} is empty, so this control injects nothing"
        body[0]["owner"] = "acme"
    elif "predictions" in body:
        body["predictions"] = {"CVE-2026-1004": {"predicted": "acme", "tier": "block"}}
    else:
        body.setdefault("open", {})["CVE-2026-1004"] = {"owner": "acme"}
    path.write_text(json.dumps(body))

    problems = publish.check(str(built["state"]))
    assert problems, f"the guard did not fire on a name in {target}"
    assert any(target.split("/")[-1] in p for p in problems), problems


def test_the_staged_tree_contains_only_allowlisted_files(built):
    for base, _dirs, files in os.walk(built["state"]):
        rel = os.path.relpath(base, built["state"])
        for fn in files:
            if rel == ".":
                assert fn in publish.ALLOWED_ROOT, fn
            else:
                assert fn in publish.ALLOWED_SNAPSHOT, os.path.join(rel, fn)


def test_every_internal_link_in_the_built_site_resolves(built):
    """A nav entry pointing at a page the build no longer writes is a 404 on
    every page of the site. /cnas was in the nav after the template was deleted,
    and only a rebuild in a clean directory surfaced it."""
    import re
    out = built["site"]
    pages = list(out.glob("*.html"))
    assert pages
    missing = []
    for p in pages:
        for href in re.findall(r'href="([^"#?:]+\.html)"', p.read_text()):
            target = (p.parent / href).resolve()
            if not target.exists():
                missing.append(f"{p.name} -> {href}")
    assert not missing, f"dead internal links: {missing}"


def test_the_grader_kept_the_name_the_artefacts_dropped(built):
    """The other half of the de-naming contract, and the one an over-eager strip
    would break silently: inference must still be RUNNING and recording, or a v2
    naming release starts from nothing.

    This is deliberately the last assertion in the file. Everything above says
    "no name escapes"; this says "the name still exists internally", and a change
    that satisfied the first by disabling inference would fail here.
    """
    ledger = json.loads((built["root"] / "precision.json").read_text())
    preds = ledger.get("predictions") or {}
    assert NAMEABLE in preds, "the grader recorded nothing; inference is not running"
    assert preds[NAMEABLE].get("predicted") == "acme"

    # And that name is in the runner-local ledger only. The staged copy is clean.
    staged = built["state"] / "precision.json"
    if staged.exists():
        assert "acme" not in staged.read_text()

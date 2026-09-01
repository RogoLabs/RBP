"""
`cli.cmd_run`, executed.

WHY THIS FILE EXISTS. cmd_run is the four-times-daily publish path and nothing
ran it. Two tests referenced it and both did `inspect.getsource`, reading it as
text to assert that a coverage window and a flag name appeared; tests/
test_end_to_end reproduces the SEQUENCE cmd_run performs, with its own copy of
the calls, and says so in a comment. So every line of the function itself was
unexecuted, and the first execution of any edit to it was a scheduled
publication against the live corpus and the live reservation endpoint.

That was found while preparing to deploy a change that touched four lines inside
it: the `degraded_state` call, and three artefact writes moved onto
`schema.write_json`. A signature mismatch or a stale name in any of them would
have left 743 tests green and killed the publish.

WHAT IS FAKED, and it is only the outside world:

    ensure_corpus        a 583 MB download and a parquet index
    feeds.gather         twelve live HTTP feeds
    classify._get        the CVE Services reservation endpoint
    schema.source_commit git, which is real but noisy in a temp tree

Everything between them is the real function: the profile split, the epoch
validation, the oracle accounting, coverage, the clock, the ledger, report.build,
the artefact writes and the summary assembly. If cmd_run raises, this fails.

WHAT IT DOES NOT DO. It does not assert the numbers are right; the modules it
calls have their own tests for that, and duplicating them here would make this
file break for reasons that are not about cmd_run. It asserts that the function
RUNS and that it leaves behind the artefact set the rest of the pipeline reads,
which is the claim nothing else was making.
"""
from __future__ import annotations

import json

import pandas as pd
import pytest

from rbp import classify, cli, cvelist, feeds, schema

def _corpus():
    """A published corpus with the REAL column set.

    Columns come from cvelist.COLUMNS rather than a hand-typed list, for the same
    reason the args come from the real parser: the first draft omitted
    `date_published` and cmd_run died on a KeyError inside coverage.compute, which
    is a fact about the fixture and not about the function under test. A column
    added upstream now shows up here as a missing value rather than as an absent
    key nobody notices.

    Two assigners with forty records each, so coverage.compute has a denominator
    and the three-sighting floor has something to be a floor over.
    """
    rows = []
    for assigner, vendor, product, base in (("acme", "Acme", "widget", 1000),
                                            ("globex", "Globex", "thing", 2000)):
        for n in range(40):
            rows.append({"cve_id": f"CVE-2025-{base + n}", "state": "PUBLISHED",
                         "assigner": assigner, "date_published": "2025-06-01",
                         "vendor": vendor, "product": product})
    df = pd.DataFrame(rows)
    missing = [c for c in cvelist.COLUMNS if c not in df.columns]
    assert not missing, f"the fake corpus is missing real columns: {missing}"
    return df[cvelist.COLUMNS]

# The referenced-but-reserved ids the feeds "found". Dated well past the buffer,
# so they are reportable and the run has rows to publish; a run that produces
# zero reportable rows would exercise a different and much shorter path.
_REFS = {
    "CVE-2026-9001": {"public_date": "2026-06-01", "sources": {"debian", "osv"},
                      "refs": {"debian:x", "osv:PyPI:widget"},
                      "description": "widget flaw", "product": "widget"},
    "CVE-2026-9002": {"public_date": "2026-06-02", "sources": {"ghsa"},
                      "refs": {"ghsa:GHSA-aaaa-bbbb-cccc"},
                      "description": "thing flaw", "product": "thing"},
}


@pytest.fixture
def run(tmp_path, monkeypatch):
    """cmd_run with the network and the corpus replaced, and nothing else."""
    monkeypatch.setattr(cli, "DATA", str(tmp_path / "data"))
    monkeypatch.setattr(cli, "SNAPS", str(tmp_path / "snapshots"))
    monkeypatch.setattr(cli, "PRECISION", str(tmp_path / "data" / "precision.json"))
    monkeypatch.setattr(cli, "RESOLUTIONS", str(tmp_path / "data" / "resolutions.json"))
    monkeypatch.setattr(cli, "CACHE", str(tmp_path / "data" / ".api_cache.json"))
    (tmp_path / "data").mkdir()

    corpus = _corpus()
    monkeypatch.setattr(cli, "ensure_corpus", lambda force=False: (corpus, {}))
    monkeypatch.setattr(feeds, "gather", lambda sources, years: dict(_REFS))
    # SHAPED LIKE THE REAL `health_detail`, including the keys `gather` records
    # per feed since 2026-08-27. A stub that returns fewer keys than the function
    # it stands in for is a fixture that cannot see a consumer of the missing
    # ones, and every assertion about them passes on a dict that never carries
    # them. `newest`/`oldest`/`dated_rows` are recorded in `gather`, which this
    # fixture also stubs, so without them there is nothing here to drift AGAINST.
    monkeypatch.setattr(feeds, "health_detail",
                        lambda: {s: {"status": "ok", "detail": "", "rows": 1,
                                     "ok": True, "truncated": False,
                                     "newest": "2026-08-26",
                                     "oldest": "2025-01-04", "dated_rows": 1}
                                 for s in ("debian", "osv", "ghsa")})
    # Every referenced id is RESERVED with the assigner redacted, which is the
    # live endpoint's actual behaviour for the reserved population.
    monkeypatch.setattr(classify, "_get",
                        lambda cid, attempts=3: {"state": "RESERVED",
                                                 "assigner": "[REDACTED]"})
    # The corpus canary compares the newest published record against today.
    monkeypatch.setattr(cli.cvelist, "assert_corpus_current",
                        lambda corpus, today=None: 0)
    monkeypatch.setattr(schema, "source_commit", lambda: "0" * 12)
    monkeypatch.setattr(schema, "source_dirty", lambda: False)

    def _go(**over):
        # ARGS FROM THE REAL PARSER, not hand-typed. A namespace assembled by hand
        # is a namespace the CLI never produces: the first draft of this fixture
        # omitted `cache_ttl_days`, `k` and `min_confidence` and every test here
        # died on AttributeError rather than on anything about cmd_run. Parsing
        # the actual argv also means a new flag with no default fails here instead
        # of on the live run.
        argv = ["run", "--today", "2026-08-20", "--sources", "debian,osv,ghsa",
                "--workers", "2"]
        for k, v in over.items():
            argv += [f"--{k.replace('_', '-')}", str(v)]
        args = cli.build_parser().parse_args(argv)
        cli.cmd_run(args)
        snaps = sorted(p for p in (tmp_path / "snapshots").iterdir() if p.is_dir())
        assert snaps, "cmd_run wrote no snapshot directory"
        return snaps[-1]
    return _go


def test_cmd_run_completes_and_writes_the_artefact_set(run):
    """The whole point. Every file the site build and the stager read.

    `resolved.json`, `cnas.json` and `summary.json` are written by cmd_run itself
    AFTER report.build returns, which is the part tests/test_end_to_end has to
    reproduce by hand and therefore the part most likely to drift from it.
    """
    sdir = run()
    for name in ("backlog.json", "backlog.csv", "summary.json", "cnas.json",
                 "resolved.json", "held_back.json", "report.md"):
        f = sdir / name
        assert f.exists(), f"cmd_run wrote no {name}"
        assert f.stat().st_size > 0, f"{name} is empty"


def test_the_summary_carries_the_blocks_the_site_asserts_on(run):
    """site.load and site._gate_status read these by key and fail closed on a
    missing one, so an absent block is a build failure four times a day."""
    stats = json.loads((run() / "summary.json").read_text())
    for key in ("total", "degraded", "degraded_reasons", "feeds", "coverage",
                "inference", "generated_at", "source_commit", "min_age_days",
                "limitations"):
        assert key in stats, f"summary.json has no {key!r}"
    assert isinstance(stats["degraded"], bool)
    assert isinstance(stats["degraded_reasons"], list)
    assert stats["feeds"]["detail"], "per-feed health did not reach the summary"


def test_a_clean_run_is_not_marked_degraded(run):
    """`degraded_state` is called from here with five keyword arguments and was
    called with six until 2026-08-26. A signature mismatch is a TypeError on the
    live run and nothing in the suite executed this call."""
    stats = json.loads((run() / "summary.json").read_text())
    assert stats["degraded"] is False, stats["degraded_reasons"]
    assert stats["degraded_reasons"] == []


def test_a_failed_feed_reaches_the_summary_as_a_degradation(run, monkeypatch):
    """The branch that matters, exercised through cmd_run rather than through
    degraded_state directly: a clean fixture makes `False == False` pass and
    proves nothing, which is this project's most repeated defect.

    Faked at `health_summary`, which is what cmd_run actually reads for the four
    lists it passes to degraded_state. Faking `health_detail` alone changed the
    per-feed table and left the degradation flag untouched, and the test passed
    its own setup while asserting nothing about the branch.
    """
    monkeypatch.setattr(feeds, "health_summary",
                        lambda: (["debian: HTTP 503"], [], 3, []))
    monkeypatch.setattr(feeds, "health_detail",
                        lambda: {"debian": {"status": "failed", "detail": "HTTP 503",
                                            "rows": None, "ok": False,
                                            "truncated": False},
                                 "osv": {"status": "ok", "detail": "", "rows": 1,
                                         "ok": True, "truncated": False}})
    stats = json.loads((run() / "summary.json").read_text())
    assert stats["degraded"] is True, "a failed feed did not degrade the run"
    assert any("failed" in r for r in stats["degraded_reasons"]), \
        stats["degraded_reasons"]
    assert stats["feeds"]["failures"] == ["debian: HTTP 503"]


def test_cmd_run_publishes_no_attribution(run):
    """v1 names nobody. The corpus above has two named assigners and every ref's
    product matches one of them, so the run has every opportunity to attach a name.

    WHAT THIS ACTUALLY PROVES, found by mutation. Flipping cmd_run's own local
    `NAMING` does NOT make this fail, because de-naming is enforced at the WRITER:
    report.build calls site._denamed, which reads site.NAMING_ENABLED, so a
    cmd_run that decided to attribute still cannot publish it. Flipping
    site.NAMING_ENABLED does make it fail, on `owner_tier` reaching backlog.json.

    That is the design working ("de-name at the writer, so a dirty snapshot cannot
    republish a name") and it is worth writing down here, because the obvious
    reading of this test is that it guards cmd_run's decision, and it does not.
    It guards the boundary, which is the thing that matters.
    """
    sdir = run()
    rows = json.loads((sdir / "backlog.json").read_text())
    for row in rows:
        for field in schema.ROW_NAME_FIELDS:
            assert row.get(field) is None, f"{row['cve_id']} carries {field}"
    assert json.loads((sdir / "cnas.json").read_text()) == [], \
        "cmd_run wrote a per-CNA table under v1"


def test_an_unknown_source_is_dropped_with_a_warning_not_a_crash(run, capsys):
    """`--sources` is operator input and reaches a dict lookup."""
    run(sources="debian,osv,notafeed")
    assert "ignoring unknown sources" in capsys.readouterr().out


def test_no_valid_source_refuses_the_run(run):
    """Rather than gathering nothing and publishing a count of zero, which is the
    shape of the silent shrink this project exists to notice."""
    with pytest.raises(SystemExit, match="no valid sources"):
        run(sources="notafeed")


def test_the_artefacts_cmd_run_writes_are_all_allowlisted_for_staging(run):
    """`publish check` refuses any file off the allowlist, so a new artefact here
    fails the publish rather than the test that added it."""
    from rbp import publish
    sdir = run()
    unexpected = [f.name for f in sdir.iterdir()
                  if f.name not in publish.ALLOWED_SNAPSHOT
                  and f.name not in ("backlog.csv", "backlog_full.json",
                                     "report.md")]
    assert not unexpected, (
        f"cmd_run writes {unexpected}, which publish.check will refuse to stage")


def test_the_run_measures_what_each_feed_contributed_to_the_published_rows(run):
    """Round 7 B4, through the REAL `cli.run` rather than a hand-written summary.

    The fixture in `_sitefixture` asserts the shape of this block, which it can
    only do because someone typed the numbers into it. This asserts the pipeline
    actually computes them, from the population it actually publishes.

    Both halves matter and they fail differently. A missing key means `/status`
    silently renders a dash for every feed; a key computed off the wrong
    population means the column is confidently wrong, which is worse.
    """
    stats = json.loads((run() / "summary.json").read_text())
    detail = stats["feeds"]["detail"]
    assert detail, "per-feed health did not reach the summary"

    for name, h in detail.items():
        assert "rows_published" in h, f"{name} carries no contribution count"
        assert "rows_only" in h, f"{name} carries no only-source count"
        assert h["rows_only"] <= h["rows_published"], (
            f"{name}: only-source {h['rows_only']} exceeds rows touched "
            f"{h['rows_published']}, which is arithmetically impossible")
        assert h["rows_published"] <= stats["total"], (
            f"{name} touches {h['rows_published']} rows out of a published "
            f"total of {stats['total']}")

    # Sole-source rows partition: no row has two only-sources, so the sum over
    # feeds cannot exceed the total. This is the assertion that catches the
    # contribution being measured against the BACKLOG rather than the published
    # population, which is a superset and would let the sum run over.
    assert sum(h["rows_only"] for h in detail.values()) <= stats["total"]


def test_every_source_on_a_published_row_is_a_feed_the_run_reported_health_for(run):
    """The two halves of `summary.feeds` must describe the same feed set.

    A source string on a published row with no health entry means a row is
    evidenced by something the run never accounted for, and it would be invisible
    to every guard keyed on the health block, `compare_magnitudes` included.
    """
    sdir = run()
    stats = json.loads((sdir / "summary.json").read_text())
    rows = json.loads((sdir / "backlog.json").read_text())
    named = set()
    for r in rows:
        named |= {s for s in (r.get("sources") or "").split(",") if s}
    unaccounted = named - set(stats["feeds"]["detail"])
    assert not unaccounted, (
        f"published rows cite feeds with no health record: {sorted(unaccounted)}")


def test_the_run_records_how_recent_each_feed_is(run):
    """H1's recording, through the summary a consumer actually reads.

    A feed frozen at a constant is invisible to `compare_magnitudes`, which only
    ever asks whether a number went DOWN. `mozilla` returned exactly 607 ids on
    six consecutive published snapshots and `arch` exactly 62; had either stopped
    updating on day one, every guard on this site would have stayed green. The
    row count cannot see that. The newest date can, and it has to reach the
    artefact or it is a log line.
    """
    detail = json.loads((run() / "summary.json").read_text())["feeds"]["detail"]
    for name, h in detail.items():
        assert "newest" in h, f"{name} publishes no newest-advisory date"
        assert "dated_rows" in h, (
            f"{name} publishes no dated-row count, so a feed that cannot be "
            "checked for freshness is indistinguishable from one that was not "
            "looked at")


def test_health_recorded_after_the_fetches_still_reaches_the_degraded_flag(
        run, monkeypatch):
    """THE ORDERING, pinned by making the two reads disagree.

    `health_summary` was read once, up beside the fetches, and that tuple was
    carried down into both the published `failures` list and `degraded_state`.
    But `resolve_dates_ubuntu` does not run until the backlog exists, hundreds
    of lines later, so `ubuntu:dates` was recorded after the snapshot that
    decides whether the run is degraded had already been taken.

    Live on 2026-09-01: the artefact published `ubuntu:dates` with status
    `failed` beside `degraded: false`, a contradiction the flag exists to make
    impossible. A single-read implementation returns the clean first tuple here
    and the run reports itself healthy.
    """
    reads = []

    def _summary():
        reads.append(1)
        if len(reads) == 1:
            return ([], [], 3, [])          # nothing has failed yet
        return (["ubuntu:dates: 12 lookup(s) failed"], [], 3, [])

    monkeypatch.setattr(feeds, "health_summary", _summary)
    stats = json.loads((run() / "summary.json").read_text())
    assert len(reads) >= 2, \
        "health is read once, before the late passes have recorded anything"
    assert stats["degraded"] is True, \
        "a feed that failed after the early read did not degrade the run"
    assert stats["feeds"]["failures"] == ["ubuntu:dates: 12 lookup(s) failed"]

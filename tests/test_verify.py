"""The post-publish check, and the three regressions it exists because of.

On 2026-08-29 and 08-30 this project shipped three variants of one defect to the
live site: state that claims to know something it does not. The offline suite
passed on all three. Every one was obvious in the published artefact.

Detection was never the gap. `feeds.compare_magnitudes` fired on the first and
printed DEGRADED to stdout; nothing acted on it, the site published, and by the
next run the shrunken value was the baseline so the guard went quiet. These tests
pin the parts that were missing: a finding that fails the build, and a comparison
that does not forget.
"""
from __future__ import annotations

import json

from rbp import verify


def _site(tmp_path, rows):
    d = tmp_path / "site" / "data"
    d.mkdir(parents=True, exist_ok=True)
    (d / "rbp.json").write_text(json.dumps({"rows": rows}))
    return str(tmp_path / "site")


def _snap(tmp_path, name, total, feeds_detail):
    d = tmp_path / "snaps" / name
    d.mkdir(parents=True, exist_ok=True)
    (d / "summary.json").write_text(json.dumps(
        {"total": total, "feeds": {"detail": feeds_detail}}))
    return str(tmp_path / "snaps")


def _row(n, url="https://vendor.example/a"):
    return {"cve_id": f"CVE-2026-{1000 + n}", "advisory_url": url,
            "source_urls": {"csaf": url}, "sources": "csaf"}


# --------------------------------------------------------------------------
# the three regressions, replayed
# --------------------------------------------------------------------------

def test_a_provider_going_dark_is_a_finding(tmp_path):
    """REGRESSION 1 AND 3. The cursor returned nothing for a caught-up provider,
    and later a damaged state did the same. Both presented identically: a
    provider reporting 0 ids beside a mark saying it was caught up.

    On the live site this took CISA from 13 rows to 3 and removed three ids
    cited by name in an open GitHub issue."""
    site = _site(tmp_path, [_row(i) for i in range(50)])
    snaps = _snap(tmp_path, "2026-08-29", 100,
                  {"csaf": {"rows": 20000,
                            "parts": {"www.cisa.gov": {"rows": 4467}}}})
    _snap(tmp_path, "2026-08-30", 95,
          {"csaf": {"rows": 300, "parts": {"www.cisa.gov": {"rows": 0}}}})
    problems = verify.check(site, snaps)
    # THE ZERO CASE HAS ITS OWN SENTENCE, and asserting only on "0 now" could
    # not tell it from the ordinary percentage branch, which also renders "0
    # now" for a source at zero. Deleting the zero branch left this green.
    # Confirmed by mutation on 2026-08-30.
    assert any("www.cisa.gov" in p and "goes dark" in p for p in problems), problems


def test_a_shrink_that_persists_does_not_become_its_own_baseline(tmp_path):
    """REGRESSION 2, AND THE REASON IT PRODUCED NO WARNING AT ALL.

    `compare_magnitudes` compares against the previous run. The first shrink
    fired it. The second did not, because by then the shrunken value WAS the
    previous run, so the guard was comparing small against small and saw
    nothing wrong.

    A guard that forgets cannot see a regression that persists, which is the
    only kind that reaches a reader. This compares against the best figure any
    recorded run achieved, so a shrink stays a finding until it recovers."""
    site = _site(tmp_path, [_row(i) for i in range(50)])
    snaps = _snap(tmp_path, "2026-08-28", 1800, {"csaf": {"rows": 20000}})
    _snap(tmp_path, "2026-08-29", 400, {"csaf": {"rows": 300}})   # the shrink
    _snap(tmp_path, "2026-08-30", 395, {"csaf": {"rows": 295}})   # normalised
    problems = verify.check(site, snaps)
    assert any("csaf" in p for p in problems), (
        f"a shrink that persisted for a second run went unreported: {problems}")


def test_the_published_count_collapsing_is_a_finding(tmp_path):
    site = _site(tmp_path, [_row(i) for i in range(50)])
    snaps = _snap(tmp_path, "2026-08-29", 1769, {"csaf": {"rows": 100}})
    _snap(tmp_path, "2026-08-30", 300, {"csaf": {"rows": 100}})
    assert any("1,769" in p and "300" in p for p in verify.check(site, snaps))


# --------------------------------------------------------------------------
# and the complement, because a check that always fires is furniture
# --------------------------------------------------------------------------

def test_normal_churn_is_not_a_finding(tmp_path):
    """Rows leave this list legitimately: a CNA publishes the record and the row
    resolves, which is the outcome the site exists to encourage. Measured churn
    across 2026-08-27 to 08-30 was single digits; the regressions were 30% and
    84%."""
    site = _site(tmp_path, [_row(i) for i in range(50)])
    snaps = _snap(tmp_path, "2026-08-29", 1800, {"csaf": {"rows": 20000}})
    _snap(tmp_path, "2026-08-30", 1750, {"csaf": {"rows": 19500}})
    assert verify.check(site, snaps) == []


def test_a_source_growing_is_never_a_finding(tmp_path):
    """The hand-written version of this check asserted `== 5` publishers and
    `== 8` CISA rows, and raised a false alarm twice because the site had
    IMPROVED. Counts that only grow get floors."""
    site = _site(tmp_path, [_row(i) for i in range(50)])
    snaps = _snap(tmp_path, "2026-08-29", 1800, {"csaf": {"rows": 4416}})
    _snap(tmp_path, "2026-08-30", 1870, {"csaf": {"rows": 21810}})
    assert verify.check(site, snaps) == []


def test_a_row_whose_only_link_disproves_it(tmp_path):
    """cve.org/CVERecord renders NOTHING for a reserved id, so a row pointing
    only there is evidence against itself. A known 63-row gap exists today
    (samsung has no per-id page), so this asserts the gap is not SPREADING
    rather than asserting zero."""
    dead = "https://www.cve.org/CVERecord?id=CVE-2026-1"
    site = _site(tmp_path, [_row(i, dead) for i in range(50)])
    assert any("disproves" in p for p in verify.check(site))
    ok = _site(tmp_path / "b", [_row(i) for i in range(50)]
               + [_row(900 + i, dead) for i in range(3)])
    assert verify.check(ok) == []


def test_an_empty_artefact_is_the_first_thing_reported(tmp_path):
    assert verify.check(_site(tmp_path, [])) == [
        "the published artefact holds no rows at all"]


def test_it_runs_with_no_history_at_all(tmp_path):
    """First run on a fresh checkout: no snapshots to compare against. A check
    that crashes there fails the build for the wrong reason."""
    site = _site(tmp_path, [_row(i) for i in range(5)])
    assert verify.check(site, str(tmp_path / "nothing")) == []
    assert verify.check(site, None) == []


def test_the_cli_exits_non_zero_on_a_finding(tmp_path, capsys):
    """THE PART THAT WAS ACTUALLY MISSING. compare_magnitudes already detected
    the first regression and printed DEGRADED to stdout. Nothing failed, so
    nothing stopped, so nobody was told."""
    site = _site(tmp_path, [])
    assert verify.main(["--site", site, "--snapshots", str(tmp_path / "none")]) == 1
    assert "VERIFY FAILED" in capsys.readouterr().out


def test_the_cli_exits_zero_on_a_clean_artefact(tmp_path, capsys):
    site = _site(tmp_path, [_row(i) for i in range(5)])
    assert verify.main(["--site", site, "--snapshots", str(tmp_path / "none")]) == 0
    assert "no findings" in capsys.readouterr().out

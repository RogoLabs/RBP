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


def _site(tmp_path, rows, degraded=False):
    d = tmp_path / "site" / "data"
    d.mkdir(parents=True, exist_ok=True)
    (d / "rbp.json").write_text(json.dumps({"rows": rows, "degraded": degraded}))
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


def test_rows_with_no_evidence_link_at_all(tmp_path):
    """A row a reader cannot check is the failure; the cve.org fallback was only
    ever the SHAPE that absence took, and it is gone with `advisory_url` (D1).

    Asserted as a ratio that must not get worse rather than as zero, because
    some feeds genuinely publish no per-id page."""
    site = _site(tmp_path, [dict(_row(i), source_urls={}) for i in range(50)])
    assert any("no advisory link" in p for p in verify.check(site))
    ok = _site(tmp_path / "b", [_row(i) for i in range(50)]
               + [dict(_row(900 + i), source_urls={}) for i in range(3)])
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


def test_a_small_source_moving_by_tens_is_not_a_finding(tmp_path):
    """THE FIRST REAL RUN OF THIS CHECK FAILED THE BUILD ON NOISE, which is how
    a guard earns the reputation that gets it ignored.

    It reported nozominetworks at 62 -> 35 and kunbus at 26 -> 15: 44% and 42%,
    and 27 and 11 ids. The site was correct at the time, verified independently.

    Two causes. These are small providers where tens of ids is ordinary
    movement. And `rows` for a provider had just changed meaning, from "CVE rows
    fetched this run" to "distinct ids this provider knows", so the high-water
    mark was being compared across a semantic change."""
    site = _site(tmp_path, [_row(i) for i in range(50)])
    snaps = _snap(tmp_path, "2026-08-29", 1800,
                  {"csaf": {"rows": 20000,
                            "parts": {"csaf.data.security.nozominetworks.com": {"rows": 62},
                                      "psirt.kunbus.com": {"rows": 26}}}})
    _snap(tmp_path, "2026-08-30", 1790,
          {"csaf": {"rows": 19800,
                    "parts": {"csaf.data.security.nozominetworks.com": {"rows": 35},
                              "psirt.kunbus.com": {"rows": 15}}}})
    assert verify.check(site, snaps) == []


def test_a_small_source_going_dark_is_still_a_finding(tmp_path):
    """The floor applies to proportional drops only. A source at zero is a
    finding at any size, because that is how all three regressions presented and
    because zero rows means every id it alone evidenced has left the site."""
    site = _site(tmp_path, [_row(i) for i in range(50)])
    snaps = _snap(tmp_path, "2026-08-29", 1800,
                  {"csaf": {"rows": 20000, "parts": {"psirt.kunbus.com": {"rows": 26}}}})
    _snap(tmp_path, "2026-08-30", 1790,
          {"csaf": {"rows": 19800, "parts": {"psirt.kunbus.com": {"rows": 0}}}})
    assert any("kunbus" in p and "goes dark" in p for p in verify.check(site, snaps))


# --------------------------------------------------------------------------
# a shortfall the run already accounted for
#
# 2026-08-31: Ubuntu's API returned 504 then 503 at the fifth page on two
# consecutive runs. The feed recorded TRUNCATED with the HTTP error in its
# detail, this module failed the build anyway, and because `deploy` is
# `needs: build` the site published nothing either time. One feed of thirteen
# having a bad afternoon stopped the whole site.
# --------------------------------------------------------------------------

def _shortfall(tmp_path, status=None, detail=None, degraded=False):
    """Ubuntu's 2026-08-31 shape: 3,996 ids at its best, 80 now."""
    site = _site(tmp_path, [_row(i) for i in range(50)], degraded=degraded)
    _snap(tmp_path, "2026-08-30", 100, {"ubuntu": {"rows": 3996}})
    now = {"ubuntu": {"rows": 80}}
    if status:
        now["ubuntu"]["status"] = status
        now["ubuntu"]["detail"] = detail
    snaps = _snap(tmp_path, "2026-08-31", 95, now)
    return site, snaps


def test_the_status_literals_are_the_ones_feeds_actually_writes():
    """Typed here rather than imported, because this module is a deploy step and
    imports nothing that opens a socket. That trade is only safe while something
    checks the two agree."""
    from rbp import feeds
    assert verify.EXPLAINS_A_SHORTFALL == (feeds.FAILED, feeds.TRUNCATED)
    assert feeds.CAPPED not in verify.EXPLAINS_A_SHORTFALL
    assert feeds.OK not in verify.EXPLAINS_A_SHORTFALL


def test_a_shortfall_behind_a_recorded_truncation_publishes(tmp_path):
    """The reported case. It is disclosed, so it is weather, not a silent shrink,
    and publishing it beats publishing nothing."""
    site, snaps = _shortfall(tmp_path, "truncated",
                             "stopped at offset 80: HTTP Error 503", degraded=True)
    problems, notes = verify.review(site, snaps)
    assert problems == [], problems
    assert any("ubuntu" in n and "503" in n for n in notes), notes


def test_a_shortfall_behind_a_recorded_failure_publishes(tmp_path):
    site, snaps = _shortfall(tmp_path, "failed", "HTTP Error 500", degraded=True)
    assert verify.check(site, snaps) == []


def test_an_accounted_shortfall_that_the_artefact_does_not_disclose_fails(tmp_path):
    """THE HALF THAT REPLACES THE BUILD FAILURE. Without it this change would be a
    straight loss: a short count would publish with nothing on the site or in the
    JSON marking the run as worse than usual."""
    site, snaps = _shortfall(tmp_path, "truncated", "HTTP Error 503", degraded=False)
    problems = verify.check(site, snaps)
    assert any("degraded=false" in p and "ubuntu" in p for p in problems), problems


def test_a_cap_does_not_excuse_a_shortfall(tmp_path):
    """A configured page cap fires on every run by design, ubuntu's and ghsa's
    both do, so the high-water mark this compares against was itself recorded with
    the cap firing. Letting a cap excuse a shortfall excuses every shortfall on
    those two feeds forever. `cli.degraded_state` draws the same line."""
    site, snaps = _shortfall(tmp_path, "capped", "hit page cap (200)", degraded=True)
    assert any("ubuntu" in p and "down" in p for p in verify.check(site, snaps))


def test_a_feed_that_shrank_while_reporting_itself_healthy_still_fails(tmp_path):
    """The silent shrink, which is the whole reason this module exists. A status
    of `ok` beside a 98% shortfall is the signature of all three 2026-08
    regressions."""
    site, snaps = _shortfall(tmp_path, "ok", "3,996 ids", degraded=True)
    assert any("ubuntu" in p and "down" in p for p in verify.check(site, snaps))


def test_a_shortfall_with_no_status_at_all_still_fails(tmp_path):
    """A snapshot written before statuses were recorded, or a feed that never
    reported one. Absence of evidence is not an account of the shortfall."""
    site, snaps = _shortfall(tmp_path, None, degraded=True)
    assert any("ubuntu" in p for p in verify.check(site, snaps))


def test_a_provider_inherits_its_parents_recorded_failure(tmp_path):
    """A csaf provider that returned nothing because the csaf fetch as a whole
    failed is explained by that failure. Asking only the child calls it a silent
    shrink and blocks the publication for a reason the run already gave."""
    site = _site(tmp_path, [_row(i) for i in range(50)], degraded=True)
    _snap(tmp_path, "2026-08-30", 100,
          {"csaf": {"rows": 20000, "parts": {"www.cisa.gov": {"rows": 4467}}}})
    snaps = _snap(tmp_path, "2026-08-31", 95,
                  {"csaf": {"rows": 300, "status": "failed", "detail": "HTTP 500",
                            "parts": {"www.cisa.gov": {"rows": 0}}}})
    assert verify.check(site, snaps) == []


def test_the_failure_message_names_what_actually_happens_next(tmp_path, capsys):
    """It used to read "The site is already serving this", on the reasoning that
    verify runs after the upload. It does, but `deploy` is `needs: build` with no
    `if:`, so failing here skips the deploy and Pages keeps serving the previous
    artefact. An operator who believed that line went looking for bad data on a
    site that had not changed, and did not learn that publication had stopped.

    Asserted on the message because it is the only thing an operator reads at
    3am, and it was wrong for as long as it existed.
    """
    site, snaps = _shortfall(tmp_path, None, degraded=True)
    assert verify.main(["--site", site, "--snapshots", snaps]) == 1
    out = capsys.readouterr().out
    assert "already serving" not in out, (
        "the failure message still claims the site is serving this artefact; the "
        "deploy is skipped, so it is not")
    assert "deploy is skipped" in out and "previous" in out, out

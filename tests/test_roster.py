"""
The pinned CNA roster (review Part 2, condition 1).

Coverage was measured against a denominator recounted from the corpus every run:
distinct assigners with a published CVE in a rolling three-year window. That number
moves as CNAs publish, shrinks as the window rolls, and steps overnight on
1 January, so a percentage trended over it is weather rather than progress, and the
launch gate is a threshold on exactly that percentage.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request

import pytest

from rbp import coverage, roster


def test_the_roster_loads_and_is_the_size_it_should_be():
    r = roster.load()
    assert r["count"] > 400, "the roster looks truncated"
    assert r["source"] and r["fetched"]
    assert "redhat" in r["names"] and "microsoft" in r["names"]


def test_a_missing_roster_refuses_rather_than_falling_back(tmp_path):
    """A silent fallback to the corpus-derived count would restore the moving
    denominator the pinned roster exists to replace, and would do it invisibly."""
    with pytest.raises(SystemExit) as e:
        roster.load(str(tmp_path / "nope.json"))
    msg = str(e.value)
    assert "launch gate" in msg
    assert "Refusing to fall back" in msg


def test_an_empty_roster_is_refused(tmp_path):
    p = tmp_path / "r.json"
    p.write_text(json.dumps({"cnas": [], "count": 0}))
    with pytest.raises(SystemExit):
        roster.load(str(p))


def test_normalisation_matches_punctuation_variants():
    """CNA short names vary across sources. Matching raw strings would undercount
    exactly the CNAs whose names carry punctuation."""
    assert roster.normalise("GitHub_M") == roster.normalise("GitHub-M")
    assert roster.normalise("Red Hat") == roster.normalise("redhat")
    idx = roster.index(roster.load())
    assert roster.normalise("github_m") in idx


def test_the_denominator_is_the_roster_not_the_corpus():
    """The whole point. Two figures, never confused, and the gate uses the pinned
    one."""
    import pandas as pd
    n = 30
    df = pd.DataFrame({"cve_id": [f"CVE-2025-{i:05d}" for i in range(n)],
                       "state": ["PUBLISHED"] * n,
                       "assigner": ["redhat"] * 20 + ["microsoft"] * 10})
    c = coverage.compute(df, {f"CVE-2025-{i:05d}" for i in range(n)},
                         recent_years=(2025,))
    assert c["total_cnas"] == roster.load()["count"]
    assert c["total_assigners_in_window"] == 2
    assert c["total_cnas"] != c["total_assigners_in_window"]
    assert c["roster_pinned"] is True


def test_an_assigner_absent_from_the_roster_is_reported_not_dropped():
    """A rename (crafter -> Crafter_CMS, facebook -> Meta) excludes a real CNA from
    the numerator. That understates coverage, which is the safe direction, but it
    has to be visible rather than assumed away."""
    import pandas as pd
    n = 20
    df = pd.DataFrame({"cve_id": [f"CVE-2025-{i:05d}" for i in range(n)],
                       "state": ["PUBLISHED"] * n,
                       "assigner": ["redhat"] * 10 + ["definitelynotacna"] * 10})
    c = coverage.compute(df, {f"CVE-2025-{i:05d}" for i in range(n)},
                         recent_years=(2025,))
    assert "definitelynotacna" in c["off_roster"]
    assert c["off_roster_n"] == 1
    assert c["cnas_sighted"] == 1, "an off-roster name must not count as covered"


def test_the_off_roster_list_is_not_truncated():
    """Truncating it would hide the size of the understatement."""
    import inspect
    src = inspect.getsource(coverage.compute)
    assert '"off_roster": off_roster,' in src
    assert "off_roster[:20]" not in src


@pytest.mark.parametrize("_", [0])
def test_the_pinned_roster_has_not_drifted_from_the_program(_):
    """A pinned file that silently drifts is a denominator nobody is measuring. This
    fails when the refresh is overdue, so it becomes a deliberate commit with a
    visible diff rather than a background number that moved.

    Skipped without network, because a build must not depend on a third party being
    up, and this is a hygiene check rather than a correctness one.
    """
    pinned = roster.load()
    try:
        live = json.loads(urllib.request.urlopen(roster.SOURCE_URL, timeout=30).read())
    except (urllib.error.URLError, OSError, ValueError) as e:
        pytest.skip(f"roster source unreachable: {e}")
    live_names = {e["shortName"] for e in live if e.get("shortName")}
    added = live_names - pinned["names"]
    removed = pinned["names"] - live_names
    drift = len(added) + len(removed)
    assert drift <= roster.MAX_DRIFT, (
        f"the pinned roster has drifted by {drift} entries "
        f"(+{len(added)} / -{len(removed)}), above the tolerance of "
        f"{roster.MAX_DRIFT}. Refresh rbp/roster_data/cna_roster.json deliberately: "
        f"added {sorted(added)[:8]}, removed {sorted(removed)[:8]}")


def test_the_pinned_roster_is_not_stale():
    age = roster.age_days(roster.load())
    assert age is not None, "the roster carries no fetch date"
    assert age <= roster.MAX_AGE_DAYS, (
        f"the pinned roster is {age} days old, above {roster.MAX_AGE_DAYS}. "
        "Refresh it; the coverage denominator depends on it.")

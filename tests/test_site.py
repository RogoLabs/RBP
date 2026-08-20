"""
Site build, and the pre-launch front door (PLAN.md phase 4).

The launch gate is 50% CNA coverage. Until then the count is built on partial
coverage of the CNA landscape, so the front door must not present it and search
engines must not index it. The dashboard is still built and reachable, because
the repo is public and the data files are served either way: the gate is on what
the front door presents, not on hiding anything.
"""
from __future__ import annotations

import importlib
import json
import os

import pytest

from rbp import site


@pytest.fixture
def built(tmp_path, monkeypatch):
    """Build the site twice, once in each posture, against a tiny snapshot."""
    snaps = tmp_path / "snapshots" / "2026-08-20"
    snaps.mkdir(parents=True)
    data = tmp_path / "data"
    data.mkdir()

    rows = [{
        "cve_id": "CVE-2026-1", "days_public": 30, "hours_public": 720,
        "past_expectation": True, "rule": "4.5.1.6", "rule_strength": "SHOULD",
        "owner": "acme", "owner_tier": "block", "owner_nameable": True,
        "self_disclosed": False, "package": "widget", "vendor": "Acme",
        "public_date": "2026-07-21", "feed_count": 2, "sources": "debian,alas",
        "advisory_url": "https://example.invalid/a", "description": "a flaw",
    }]
    (snaps / "backlog.json").write_text(json.dumps(rows))
    (snaps / "summary.json").write_text(json.dumps({
        "total": 1, "past_expectation": 1, "oldest_days": 30, "median_days": 30,
        "named_cnas": 1, "must_rows": 0, "should_rows": 1, "clock_unknown": 0,
        "undated_excluded": 4, "min_age_days": 7,
        "age_buckets": {"7-30d": 1},
        "inference": {"k": 3, "run_coverage": 1.0,
                      "leave_one_out": {"precision": 0.9939, "coverage": 0.62,
                                        "decided": 100},
                      "live": {"graded": 0, "correct": 0, "precision": None,
                               "outstanding": 1, "by_tier": {}}},
        "feeds": {"requested": ["debian"], "failures": [], "attempts": 1},
    }))
    (snaps / "cnas.json").write_text(json.dumps([{
        "cna": "acme", "outstanding": 1, "oldest_days": 30,
        "median_days_public": 30, "past_expectation": 1, "must_rows": 0,
        "should_rows": 1, "published_12mo": 100, "rate": 0.01,
        "rate_wilson_lower": 0.002, "rate_suppressed": False,
        "resolved_n": 0, "median_days_to_publish": None,
    }]))

    def build(launched):
        monkeypatch.setenv("RBP_LAUNCHED", "1" if launched else "")
        importlib.reload(site)
        out = tmp_path / ("launched" if launched else "prelaunch")
        site.build(str(out), str(tmp_path / "snapshots"), str(data))
        return out

    yield build
    monkeypatch.delenv("RBP_LAUNCHED", raising=False)
    importlib.reload(site)


def test_prelaunch_front_door_is_the_holding_page(built):
    out = built(False)
    index = (out / "index.html").read_text()
    assert "lead-count" not in index, "the dashboard is on the front door pre-launch"
    assert "Reserved but Public" in index
    assert (out / "overview.html").exists()
    assert "lead-count" in (out / "overview.html").read_text()


def test_prelaunch_holding_page_does_not_link_into_the_dashboard(built):
    """Linking to it would effectively launch it."""
    out = built(False)
    index = (out / "index.html").read_text()
    for page in ("overview.html", "cves.html", "cnas.html", "method.html"):
        assert f'href="{page}"' not in index


def test_prelaunch_dashboard_pages_are_noindex(built):
    out = built(False)
    for name in ("overview", "cves", "cnas", "method", "policy", "data", "changes"):
        html = (out / f"{name}.html").read_text()
        assert 'content="noindex, nofollow"' in html, name
    assert 'content="noindex, nofollow"' in (out / "cna" / "acme.html").read_text()


def test_launched_front_door_is_the_dashboard(built):
    out = built(True)
    index = (out / "index.html").read_text()
    assert "lead-count" in index
    assert 'content="index, follow"' in index
    assert not (out / "overview.html").exists()


def test_nav_follows_the_posture(built):
    pre = built(False)
    assert 'href="overview.html">Overview' in (pre / "cves.html").read_text()
    assert 'href="../overview.html">Overview' in (pre / "cna" / "acme.html").read_text()
    post = built(True)
    assert 'href="index.html">Overview' in (post / "cves.html").read_text()
    assert 'href="../index.html">Overview' in (post / "cna" / "acme.html").read_text()


def test_data_files_are_served_in_both_postures(built):
    """The gate is on presentation, not on withholding data."""
    for launched in (False, True):
        out = built(launched)
        for f in ("rbp.json", "rbp.csv", "summary.json", "cnas.json", "precision.json"):
            assert (out / "data" / f).exists(), (launched, f)
        assert (out / "data" / "cna" / "acme.json").exists()


def test_csv_is_the_gated_view(built):
    """An ungated owner column in a shareable file was a real defect in the
    previous engine."""
    out = built(False)
    header = (out / "data" / "rbp.csv").read_text().splitlines()[0]
    assert "owner" in header
    assert "product_map_owner" not in header


def test_slug_is_url_safe():
    assert site.slug("GitHub_M") == "github-m"
    assert site.slug("Red Hat") == "red-hat"
    assert site.slug("cert@ncsc.nl") == "cert-ncsc-nl"
    assert site.slug("") == "unknown"
    assert site.slug(None) == "unknown"


def test_build_fails_loudly_with_no_snapshots(tmp_path):
    with pytest.raises(SystemExit):
        site.build(str(tmp_path / "out"), str(tmp_path / "empty"), str(tmp_path))

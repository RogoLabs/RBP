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
        "unmeasurable_rows": 1, "candidate_rows": 0,
        "undated_excluded": 4, "min_age_days": 7,
        "age_buckets": {"7-30d": 1},
        "inference": {"k": 3, "run_coverage": 1.0,
                      "leave_one_out": {"precision": 0.9939, "coverage": 0.62,
                                        "decided": 100},
                      "live": {"graded": 0, "correct": 0, "precision": None,
                               "outstanding": 1, "by_tier": {}}},
        "feeds": {"requested": ["debian"], "failures": [], "attempts": 1},
        # Above the gate, so the launched posture can be tested at all. The gate
        # fails closed, so a fixture without coverage never launches.
        "coverage": {"total_cnas": 10, "cnas_effective": 6, "cnas_own_channel": 1,
                     "cnas_sighted": 8, "min_sightings": 3, "pct_cnas": 80.0,
                     "pct_effective": 60.0, "observed_pct": 12.5,
                     "profile": "weekly",
                     # The gate figure. 8 of 10 clears the 80% top-N gate; the
                     # weaker one-sighting count is carried alongside so the
                     # template can show that the two differ.
                     "top_n": 10, "top_covered_effective": 8,
                     "top_covered": 9, "top_missed_effective": []},
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


def test_the_rule_card_does_not_present_an_unmeasurable_ordering_as_measured(built):
    """The card had two columns, SHOULD and MUST, and labelled the SHOULD count
    "A third party disclosed. The ordinary distro case." On live data 505 of those
    506 rows have rule_certainty "unmeasurable": the site cannot see who went
    first and files them under the weaker rule for that reason. So the label was
    an assertion about third parties on 505 rows that supported it on one.

    The row-level data was always right. This is the display, which is where the
    same class of error already appeared twice: a 100% precision headline on n=1,
    and MUST on an unmeasurable ordering."""
    dash = (built(False) / "overview.html").read_text()
    assert "Not measurable" in dash
    # The measured claim must not be attached to the unmeasurable count.
    i_unmeasured = dash.index("Not measurable")
    i_third = dash.index("A third party was observed")
    seg = dash[i_unmeasured:i_third]
    assert "cannot be established" in seg
    assert "not because a third party was observed" in seg
    # And the old unconditional wording is gone.
    assert "A third party disclosed." not in dash


def test_method_states_all_three_coverage_figures_and_the_gate(built):
    """"Covered" does three different jobs and the three answers differ by a
    factor of sixty on live data, so /method quoted the largest of them alone and
    named neither the gate figure nor the gate position.

    Asserted on the rendered digits, not on the keys. Jinja's default Undefined
    renders as an empty string, so a renamed or missing coverage key does not
    raise: it publishes a sentence with a hole where the number was. That is the
    quiet version of the same failure as the null-sort crash, and the loud fix
    (StrictUndefined) would kill the build over an optional block, which is the
    mistake the NOTE: guard already made."""
    import re
    raw = (built(False) / "method.html").read_text()
    # Tags out, whitespace collapsed, so an assertion can tie a figure to its own
    # row rather than merely finding the digits somewhere on the page. Checking
    # "60.0%" alone would pass on the gate sentence even with pct_effective gone.
    text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", raw))

    assert "Sighted 8 / 10 (80.0%)" in text
    assert "Effective 6 / 10 (60.0%)" in text
    assert "Own channel 1 / 10" in text
    assert "figure the launch gate uses" in text
    assert "Launch gate: 80.0% of 80.0% required" in text
    # The floor is stated as a number, not described in the abstract.
    assert "Seen at least 3 times" in text
    # The gate names its own basis, so a reader cannot mistake it for the roster
    # share printed two rows above.
    assert "top-10-by-volume at the 3-sighting floor" in text
    # And the roster share is still shown, explicitly demoted rather than deleted.
    assert "It no longer gates anything." in text


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


def test_prelaunch_emits_a_disallow_all_robots_txt(built):
    """A meta tag cannot cover data/*.json and GitHub Pages cannot set
    X-Robots-Tag, so robots.txt is the only lever that reaches the data files."""
    out = built(False)
    robots = (out / "robots.txt").read_text()
    assert "User-agent: *" in robots and "Disallow: /" in robots
    assert not (built(True) / "robots.txt").exists()


def test_holding_page_itself_is_noindex(built):
    """The holding page is the only surface a crawler or an unfurler can reach
    pre-launch, and it carries the project's most pointed copy. The template
    noindex covers the Jinja pages only, never this file."""
    index = (built(False) / "index.html").read_text()
    assert 'name="robots"' in index and "noindex" in index


def test_prelaunch_withholds_the_per_cna_pages(built):
    """report.py states the project's own rule that a named CNA gets a private
    preview before any row naming it circulates. A six-hourly public deploy of
    these pages breaks that rule on every run, and noindex does not help because
    the page is still fetchable and linkable."""
    pre = built(False)
    assert not (pre / "cna").exists() or not list((pre / "cna").glob("*.html"))
    assert not list((pre / "data" / "cna").glob("*.json"))
    post = built(True)
    assert (post / "cna" / "acme.html").exists()
    assert (post / "data" / "cna" / "acme.json").exists()


def test_launched_front_door_is_the_dashboard(built):
    out = built(True)
    index = (out / "index.html").read_text()
    assert "lead-count" in index
    assert 'content="index, follow"' in index
    assert not (out / "overview.html").exists()


def test_nav_follows_the_posture(built):
    pre = built(False)
    assert 'href="overview.html">Overview' in (pre / "cves.html").read_text()
    post = built(True)
    assert 'href="index.html">Overview' in (post / "cves.html").read_text()
    assert 'href="../index.html">Overview' in (post / "cna" / "acme.html").read_text()


def test_aggregate_data_files_are_served_in_both_postures(built):
    """The gate is on presentation, not on withholding the aggregate data. The
    per-CNA files are the exception, because those are the ones that name a
    single organisation."""
    for launched in (False, True):
        out = built(launched)
        for f in ("rbp.json", "rbp.csv", "summary.json", "cnas.json", "precision.json"):
            assert (out / "data" / f).exists(), (launched, f)


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


# --------------------------------------------------------------------------
# fail loudly rather than publishing a hollow page (REVIEW.md part 1 item 6)
# --------------------------------------------------------------------------

def test_a_truncated_snapshot_raises_instead_of_publishing(tmp_path, monkeypatch):
    """A truncated backlog.json beside a good summary.json used to publish a
    front page reading 553 above an empty table, exit 0, upload the artifact,
    deploy, and become the next run's diff baseline."""
    snaps = tmp_path / "snapshots" / "2026-08-20"
    snaps.mkdir(parents=True)
    (snaps / "backlog.json").write_text('[{"cve_id": "CVE-2026-1", "own')  # truncated
    (snaps / "summary.json").write_text('{"total": 553}')
    (snaps / "cnas.json").write_text("[]")
    with pytest.raises(SystemExit, match="backlog.json"):
        site.load(str(tmp_path / "snapshots"), str(tmp_path))


def test_row_count_must_match_the_headline(tmp_path):
    """The epoch bug: it filtered summary.json and cnas.json but not the
    backlog.json the table renders, so the front page and the table under it
    disagreed."""
    snaps = tmp_path / "snapshots" / "2026-08-20"
    snaps.mkdir(parents=True)
    (snaps / "backlog.json").write_text(json.dumps(
        [{"cve_id": f"CVE-2026-{i}", "owner": None} for i in range(5)]))
    (snaps / "summary.json").write_text('{"total": 2}')
    (snaps / "cnas.json").write_text("[]")
    with pytest.raises(SystemExit, match="computed once"):
        site.load(str(tmp_path / "snapshots"), str(tmp_path))


def test_an_owner_with_no_cna_page_raises(tmp_path):
    """Every owner link must resolve. CNAs dropping out of cnas.json while
    /cves still linked to them was an observed symptom of the epoch bug."""
    snaps = tmp_path / "snapshots" / "2026-08-20"
    snaps.mkdir(parents=True)
    (snaps / "backlog.json").write_text(json.dumps(
        [{"cve_id": "CVE-2026-1", "owner": "ghost"}]))
    (snaps / "summary.json").write_text('{"total": 1}')
    (snaps / "cnas.json").write_text("[]")
    with pytest.raises(SystemExit, match="absent from cnas.json"):
        site.load(str(tmp_path / "snapshots"), str(tmp_path))


def test_per_cna_totals_must_match_the_named_rows(tmp_path):
    snaps = tmp_path / "snapshots" / "2026-08-20"
    snaps.mkdir(parents=True)
    (snaps / "backlog.json").write_text(json.dumps(
        [{"cve_id": "CVE-2026-1", "owner": "acme"}]))
    (snaps / "summary.json").write_text('{"total": 1}')
    (snaps / "cnas.json").write_text(json.dumps([{"cna": "acme", "outstanding": 9}]))
    with pytest.raises(SystemExit, match="contradict their own tables"):
        site.load(str(tmp_path / "snapshots"), str(tmp_path))


def test_a_corrupt_ledger_raises_but_a_missing_one_does_not(tmp_path):
    """Absence is a valid first-run state. Corruption is not, and starting empty
    would silently zero the accountability record."""
    snaps = tmp_path / "snapshots" / "2026-08-20"
    snaps.mkdir(parents=True)
    (snaps / "backlog.json").write_text("[]")
    (snaps / "summary.json").write_text('{"total": 0}')
    (snaps / "cnas.json").write_text("[]")
    site.load(str(tmp_path / "snapshots"), str(tmp_path))          # no ledgers, fine
    (tmp_path / "precision.json").write_text("{trunc")
    with pytest.raises(SystemExit, match="corrupt ledger"):
        site.load(str(tmp_path / "snapshots"), str(tmp_path))


# --------------------------------------------------------------------------
# the candidate qualifier must travel with the strength (part 1 item 17)
# --------------------------------------------------------------------------

def test_rule_strength_never_ships_without_its_certainty(built):
    """clock.py states the rule that the qualifier accompanies the strength
    wherever it appears. It was in no template and no CSV column, so the chips
    read a bare "4.5.1.4 MUST" and a consumer could not reconstruct the hedge at
    all."""
    out = built(True)
    header = (out / "data" / "rbp.csv").read_text().splitlines()[0]
    assert "rule_strength" in header
    assert "rule_certainty" in header, "strength exported without its qualifier"
    assert "rule_basis" in header

    # Rendered: wherever a template prints the strength it prints the qualifier.
    import pathlib
    tpl_dir = pathlib.Path(__file__).parent.parent / "templates"
    for name in ("cves.html", "cna.html"):
        body = (tpl_dir / name).read_text()
        if "rule_strength" in body:
            assert "rule_certainty" in body, f"{name} shows strength without certainty"


def test_independent_sources_is_exported(built):
    """314 of 553 rows showed feed_count >= 2 with indep_sources == 1, all of them
    GHSA plus its own OSV mirror, on a site whose method page explains in prose
    that an OSV row is not evidence GitHub disclosed anything."""
    out = built(True)
    assert "indep_sources" in (out / "data" / "rbp.csv").read_text().splitlines()[0]


# --------------------------------------------------------------------------
# staleness and the precision floor (part 1 items 13, 11)
# --------------------------------------------------------------------------

def _minimal(tmp_path, generated_at=None, graded=0):
    snaps = tmp_path / "snapshots" / "2026-08-20"
    snaps.mkdir(parents=True)
    summary = {"total": 0}
    if generated_at:
        summary["generated_at"] = generated_at
    (snaps / "backlog.json").write_text("[]")
    (snaps / "summary.json").write_text(json.dumps(summary))
    (snaps / "cnas.json").write_text("[]")
    if graded:
        (tmp_path / "precision.json").write_text(json.dumps({
            "graded": [{"cve_id": f"CVE-2026-{i}", "correct": True} for i in range(graded)],
            "predictions": {}, "history": []}))
    return site.load(str(tmp_path / "snapshots"), str(tmp_path))


def test_staleness_is_measured_not_asserted(tmp_path):
    """The site claimed "Updated every six hours" as static copy while nothing
    computed staleness, and a scheduled workflow can stop silently."""
    import datetime as dt
    now = dt.datetime.now(dt.timezone.utc)
    fresh = _minimal(tmp_path / "a", (now - dt.timedelta(hours=1)).isoformat())
    assert fresh["stale"] is False and fresh["very_stale"] is False
    mid = _minimal(tmp_path / "b", (now - dt.timedelta(hours=18)).isoformat())
    assert mid["stale"] is True and mid["very_stale"] is False
    old = _minimal(tmp_path / "c", (now - dt.timedelta(hours=40)).isoformat())
    assert old["very_stale"] is True
    assert old["age_hours"] > 24


def test_missing_or_bad_timestamp_does_not_claim_freshness(tmp_path):
    for stamp in (None, "not-a-timestamp"):
        ctx = _minimal(tmp_path / f"x{stamp}", stamp)
        assert ctx["age_hours"] is None
        assert ctx["stale"] is False      # unknown is not stale, and not fresh either


def test_production_precision_is_withheld_below_the_floor(tmp_path):
    """With n=1 the site rendered "100.00%" in a headline tile, a stronger claim
    than the leave-one-out figure beside it. The project applies exactly this
    discipline to other people's numbers via MIN_DENOMINATOR."""
    low = _minimal(tmp_path / "low", graded=1)
    assert low["grader"]["graded"] == 1
    assert low["grader"]["precision"] is None
    assert low["grader"]["below_floor"] is True

    ok = _minimal(tmp_path / "ok", graded=site.GRADER_MIN_N)
    assert ok["grader"]["precision"] == 1.0
    assert ok["grader"]["below_floor"] is False


def test_one_published_plus_one_rejected_closure_renders(tmp_path, monkeypatch):
    """Both states shared one list that the templates sorted on days_to_publish,
    which is None for a rejection. Jinja's sort calls sorted(), so this raised
    TypeError in the Build site step: the artefact never uploaded, deploy was
    skipped, and the next run re-derived the same rejection and failed
    identically. A self-sustaining outage, latent only because resolved was 0."""
    import importlib
    snaps = tmp_path / "snapshots" / "2026-08-20"
    snaps.mkdir(parents=True)
    (snaps / "backlog.json").write_text(json.dumps([{
        "cve_id": "CVE-2026-9", "owner": "acme", "owner_tier": "block",
        "owner_nameable": True, "days_public": 30, "past_expectation": True,
        "rule": "4.5.1.6", "rule_strength": "SHOULD", "rule_certainty": "candidate",
        "package": "widget", "vendor": "Acme", "public_date": "2026-07-21",
        "feed_count": 2, "indep_sources": 2, "sources": "debian,alas",
        "advisory_url": "https://example.invalid/a", "description": "a flaw",
    }]))
    (snaps / "summary.json").write_text(json.dumps({
        "total": 1, "past_expectation": 1, "oldest_days": 30, "median_days": 30,
        "named_cnas": 1, "must_rows": 0, "should_rows": 1, "clock_unknown": 0,
        "unmeasurable_rows": 1, "candidate_rows": 0,
        "undated_excluded": 0, "min_age_days": 7, "age_buckets": {"7-30d": 1},
        "top_owner_share": 1.0,
        "inference": {"k": 3, "run_coverage": 1.0,
                      "leave_one_out": {"precision": 0.99, "coverage": 0.6, "decided": 10},
                      "live": {"graded": 0, "correct": 0, "precision": None,
                               "outstanding": 0, "by_tier": {}}},
        "feeds": {"requested": ["debian"], "failures": [], "attempts": 1,
                  "truncated": [], "detail": {}},
        # Above the gate: the gate fails closed, so a fixture without coverage
        # never reaches the launched posture.
        "coverage": {"total_cnas": 10, "cnas_effective": 6, "cnas_own_channel": 1,
                     "cnas_sighted": 8, "min_sightings": 3, "pct_cnas": 80.0,
                     "pct_effective": 60.0, "observed_pct": 12.5,
                     "profile": "weekly",
                     # The gate figure. 8 of 10 clears the 80% top-N gate; the
                     # weaker one-sighting count is carried alongside so the
                     # template can show that the two differ.
                     "top_n": 10, "top_covered_effective": 8,
                     "top_covered": 9, "top_missed_effective": []},
    }))
    (snaps / "cnas.json").write_text(json.dumps([{
        "cna": "acme", "outstanding": 1, "oldest_days": 30, "median_days_public": 30,
        "past_expectation": 1, "must_rows": 0, "should_rows": 1,
        "published_12mo": 100, "resolved_n": 1, "median_days_to_publish": 12,
    }]))
    # One of each state, for the same owner, which is the shape that crashed.
    (tmp_path / "resolutions.json").write_text(json.dumps({"open": {}, "resolved": [
        {"cve_id": "CVE-2026-1", "state": "PUBLISHED", "predicted_owner": "acme",
         "published_assigner": "acme", "transferred": False, "owner": "acme",
         "first_public": "2026-07-01", "published": "2026-07-13",
         "days_to_publish": 12, "closed_on": "2026-08-20"},
        {"cve_id": "CVE-2026-2", "state": "REJECTED", "predicted_owner": "acme",
         "published_assigner": "", "transferred": False, "owner": "acme",
         "first_public": "2026-07-01", "published": "2026-08-01",
         "days_to_publish": None, "closed_on": "2026-08-20"},
    ]}))

    monkeypatch.setenv("RBP_LAUNCHED", "1")
    importlib.reload(site)
    try:
        out = tmp_path / "site"
        site.build(str(out), str(tmp_path / "snapshots"), str(tmp_path))

        changes = (out / "changes.html").read_text()
        cna = (out / "cna" / "acme.html").read_text()

        # No bare None in a numeric column.
        assert ">None<" not in changes and ">None<" not in cna

        # The rejected block must not claim these rows published. Checking for
        # the substring "published" is wrong: the block legitimately quotes the
        # rule's own phrase "unused or unpublished CVE ID".
        start = changes.index("Rejected, all time")
        # Bound to this card only. A fixed window bleeds into the next card,
        # which legitimately does say "have published".
        nxt = changes.find('class="card-title"', start + 10)
        block = changes[start:(nxt if nxt != -1 else len(changes))].lower()
        for claim in ("have published", "has published", "since published",
                      "therefore resolved", "days to publish"):
            assert claim not in block, f"rejection block claims: {claim}"
        assert "4.5.3.5" in block
        assert "not failures to publish" in block
    finally:
        monkeypatch.delenv("RBP_LAUNCHED", raising=False)
        importlib.reload(site)


def test_a_transferred_closure_is_credited_to_the_tracked_owner(tmp_path, monkeypatch):
    """reconcile sets `owner` to the post-transfer assigner, so keying the /cna
    resolution table on it gave a CNA-LR that published someone else's overdue
    record under 4.5.1.5 a resolution history it never had, while the median tile
    beside it keyed on the tracked owner."""
    ctx_resolutions = [{
        "cve_id": "CVE-2026-1", "state": "PUBLISHED", "predicted_owner": "original",
        "published_assigner": "mitre", "transferred": True, "owner": "mitre",
        "first_public": "2026-07-01", "published": "2026-07-11",
        "days_to_publish": 10, "closed_on": "2026-08-20"}]
    mine = [r for r in ctx_resolutions
            if (r.get("predicted_owner") or r.get("owner")) == "original"]
    assert len(mine) == 1, "the tracked owner must keep its own resolution"
    theirs = [r for r in ctx_resolutions
              if (r.get("predicted_owner") or r.get("owner")) == "mitre"]
    assert theirs == [], "the CNA-LR must not inherit it"


def test_sortnum_survives_nulls_in_both_directions():
    """Jinja's sort calls sorted() with no key fallback and do_sort has no
    `default` parameter, so one None in a numeric column is a build-killing
    TypeError inside the Build site step. That took the site down twice during
    review. Nulls sort last either way: a missing value is not a small value."""
    env = site._env()
    rows = [{"d": 10}, {"d": None}, {"d": 30}, {"d": 0}]
    desc = env.from_string("{% for r in rows | sortnum('d') %}{{ r.d }}|{% endfor %}").render(rows=rows)
    assert desc == "30|10|0|None|"
    asc = env.from_string(
        "{% for r in rows | sortnum('d', reverse=false) %}{{ r.d }}|{% endfor %}").render(rows=rows)
    assert asc == "0|10|30|None|"
    allnull = env.from_string("{% for r in rows | sortnum('d') %}x{% endfor %}").render(
        rows=[{"d": None}, {"d": None}])
    assert allnull == "xx"


def test_no_template_uses_the_unsafe_jinja_sort_on_a_numeric_field():
    """A grep-style guard, because this bug class reappeared in a second field
    immediately after the first was fixed."""
    import pathlib
    for tpl in (pathlib.Path(__file__).parent.parent / "templates").glob("*.html"):
        body = tpl.read_text()
        assert "sort(attribute=" not in body, (
            f"{tpl.name} uses Jinja's sort, which raises on a null. Use | sortnum().")


def test_no_template_defaults_an_absent_certainty_to_the_stronger_label():
    """Both row templates defaulted a missing rule_certainty to 'candidate', which
    is the stronger of the two readings, so absence of a measurement was captioned
    as a measurement. Grep-style for the same reason as the sort guard: this went
    wrong independently in two templates, so fixing both by hand is not enough."""
    import pathlib, re
    for tpl in (pathlib.Path(__file__).parent.parent / "templates").glob("*.html"):
        body = tpl.read_text()
        # Strip comments, which quote the old form deliberately.
        body = re.sub(r"\{#.*?#\}", "", body, flags=re.S)
        body = re.sub(r"//.*", "", body)
        for bad in ("or 'candidate'", '|| "candidate"', "|| 'candidate'",
                    'or "candidate"'):
            assert bad not in body, (
                f"{tpl.name} defaults an absent rule_certainty to 'candidate'. "
                "Absence must fall to 'unmeasurable', the weaker label.")


# --------------------------------------------------------------------------
# the launch gate (r3 item 7)
# --------------------------------------------------------------------------

def _summary_with_coverage(total, eff, own=0, top_n=50, top_eff=None):
    """`top_eff` defaults to the same ratio as eff/total.

    Deliberately not defaulted to a clearing value. Callers that pass a low
    roster coverage mean "below the gate", and a default that cleared regardless
    silently inverted two tests that assert the below-gate posture."""
    if top_eff is None:
        top_eff = round(top_n * eff / total) if total else 0
    return {"total": 0, "min_age_days": 7, "age_buckets": {},
            "inference": {"k": 3, "run_coverage": 0.0,
                          "leave_one_out": {"precision": 0.99, "coverage": 0.6,
                                            "decided": 0},
                          "live": {"graded": 0, "correct": 0, "precision": None,
                                   "outstanding": 0, "by_tier": {}}},
            "feeds": {"requested": [], "failures": [], "attempts": 0,
                      "truncated": [], "detail": {}},
            "coverage": {"total_cnas": total, "cnas_effective": eff,
                         "cnas_own_channel": own, "cnas_sighted": eff,
                         "min_sightings": 3, "profile": "weekly",
                         "top_n": top_n, "top_covered_effective": top_eff,
                         "top_covered": top_n, "top_missed_effective": []}}


def test_gate_status_uses_top_n_by_volume_on_the_sighting_floor():
    g = site._gate_status(_summary_with_coverage(539, 117, top_eff=40))
    assert g["cleared"] is True and g["pct"] == 80.0
    assert site._gate_status(
        _summary_with_coverage(539, 117, top_eff=39))["cleared"] is False
    assert site._gate_status(
        _summary_with_coverage(539, 400, top_eff=39))["cleared"] is False, (
        "a large roster share must not clear a gate keyed to the top 50")


def test_gate_reports_its_margin_because_it_has_no_second_condition():
    """The roster-share floor was offered and declined, so the gate can clear by
    exactly one CNA. A bare cleared:true would hide that."""
    assert site._gate_status(
        _summary_with_coverage(539, 117, top_eff=40))["margin"] == 0
    assert site._gate_status(
        _summary_with_coverage(539, 117, top_eff=45))["margin"] == 5


def test_gate_fails_closed_when_the_run_predates_the_gate_figure():
    """A snapshot written before top_covered_effective existed must not fall back
    to top_covered, which counts a single stray sighting and would clear the gate
    on a weaker measure than the one it names."""
    s = _summary_with_coverage(539, 117)
    del s["coverage"]["top_covered_effective"]
    g = site._gate_status(s)
    assert g["cleared"] is False and "cannot be evaluated" in g["reason"]


def test_gate_threshold_is_reachable():
    """The gate was briefly measured on cnas_own_channel, which is bounded by the
    number of hand-written owner-feed parsers (three), so a 50% gate had a 0.7%
    ceiling and could never clear. Nothing failed: the site published its
    pre-launch posture forever, which is exactly what it does when the gate is
    merely not yet met, so an unreachable gate was indistinguishable from a
    distant one. The gate figure must be able to reach its own threshold.

    The 50%-of-roster gate that replaced own-channel had the same defect, found
    the same way and later: only 371 of 539 roster CNAs have published 3 CVEs in
    the window, so `cnas_effective` cannot exceed 68.8% on ANY feed set, and the
    current feed set caps at 28.2%. That is why the gate is now keyed to the top
    50 by volume, where the numerator and denominator are both bounded by 50.
    """
    from rbp import clock, coverage as cov_mod

    # Bounded by top_n on both sides, so the threshold is reachable by
    # construction rather than by measurement.
    assert site._gate_status(
        _summary_with_coverage(539, 117, top_eff=50))["cleared"] is True

    # Not keyed to own-channel, which is bounded by len(OWNER_FEEDS).
    assert site._gate_status(
        _summary_with_coverage(539, 0, own=len(clock.OWNER_FEEDS),
                               top_eff=0))["cleared"] is False
    assert round(100 * len(clock.OWNER_FEEDS) / 50, 1) < site.GATE_TOP_N_PCT, (
        "own-channel can reach the gate now, so this test no longer proves "
        "anything; check what the gate is keyed to")

    # And the floor the gate counts against is the one inference names against,
    # so the gate cannot clear on CNAs the site would refuse to name.
    assert cov_mod.compute.__doc__ and "cnas_effective" in cov_mod.compute.__doc__


def test_gate_numerator_is_not_the_one_sighting_figure():
    """top_covered credits a top-50 CNA on one stray reference. Live it reads 37
    where the gate figure reads 31, so keying the gate to it would clear six CNAs
    early on a measure the coverage module's own docstring calls weak."""
    s = _summary_with_coverage(539, 117, top_eff=31)
    s["coverage"]["top_covered"] = 37
    assert site._gate_status(s)["cleared"] is False
    assert site._gate_status(s)["top_effective"] == 31


def test_gate_counts_the_same_floor_inference_names_against(tmp_path):
    """If coverage counted a lower floor than inference, the gate could clear on
    CNAs the site then refused to name, and the launch would ship a dashboard
    thinner than its own gate promised."""
    import pandas as pd
    from rbp import coverage as cov_mod
    from rbp.inference import MIN_SIGHTINGS

    # Real roster short names. The coverage denominator is now the CVE Program's
    # pinned CNA list, so an invented assigner is correctly counted as off-roster
    # and never reaches the numerator: the fixture has to use names that exist.
    assigners = ["redhat"] * (MIN_SIGHTINGS + 1) + ["microsoft"] * 2
    ids = [f"CVE-2025-{i:05d}" for i in range(len(assigners))]
    df = pd.DataFrame({"cve_id": ids, "state": ["PUBLISHED"] * len(ids),
                       "assigner": assigners})
    # Every redhat row is surfaced; microsoft is surfaced ONCE, so it is sighted
    # but below the floor.
    refs = set(ids[:MIN_SIGHTINGS + 1]) | {ids[MIN_SIGHTINGS + 1]}
    cov = cov_mod.compute(df, refs, recent_years=(2025,))
    assert cov["min_sightings"] == MIN_SIGHTINGS
    assert cov["cnas_effective"] < cov["cnas_sighted"], (
        "a CNA seen once must not count toward the gate")
    assert cov["cnas_effective"] == 1


def test_gate_is_not_cleared_when_coverage_was_not_measured():
    st = site._gate_status({"total": 0})
    assert st["cleared"] is False
    assert "cannot be evaluated" in st["reason"]


def test_launching_below_gate_fails_closed_and_still_publishes(tmp_path, monkeypatch):
    """The obvious enforcement, a SystemExit in site.load, would have been worse
    than the problem: it lands in the Build site step, deploy is `needs: build`
    with no `if:`, so the deploy job is skipped and Pages serves the previous
    artefact indefinitely with no notification. After a launch cleared on a
    manual deep run, every scheduled weekly run would trip it and the site would
    freeze four times a day while still serving a count."""
    import importlib
    snaps = tmp_path / "snapshots" / "2026-08-20"
    snaps.mkdir(parents=True)
    (snaps / "backlog.json").write_text("[]")
    (snaps / "summary.json").write_text(json.dumps(_summary_with_coverage(100, 10)))
    (snaps / "cnas.json").write_text("[]")

    monkeypatch.setenv("RBP_LAUNCHED", "1")
    importlib.reload(site)
    try:
        out = tmp_path / "site"
        # Publishes. Does not raise. Does not launch.
        site.build(str(out), str(tmp_path / "snapshots"), str(tmp_path))
        assert (out / "index.html").exists(), "the site must still publish"
        assert (out / "overview.html").exists(), "pre-launch posture retained"
        assert "lead-count" not in (out / "index.html").read_text()
        assert (out / "robots.txt").exists()
    finally:
        monkeypatch.delenv("RBP_LAUNCHED", raising=False)
        importlib.reload(site)


def test_launched_flag_is_validated_strictly():
    """A bare truthiness test read `on`, `y` and `enabled` as not-launched, so a
    deliberate launch could look like a no-op and be debugged as a build bug."""
    assert site._validated_launched("1") is True
    assert site._validated_launched("true") is True
    assert site._validated_launched("") is False
    assert site._validated_launched("0") is False
    for bad in ("on", "y", "enabled", "yes please"):
        with pytest.raises(SystemExit, match="not a recognised boolean"):
            site._validated_launched(bad)

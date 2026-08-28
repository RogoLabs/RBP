"""
v1 publishes no attribution, asserted over the ARTEFACTS rather than the flag.

`site.NAMING_ENABLED = False` was enforced at the row boundary and nowhere else,
and five artefacts published CNA names around it. Each escaped through a key the
leak guard does not know about:

    /data/cnas.json                 keyed `cna`, seven CNAs ranked by outstanding
    /data/resolved.json             `published_assigner` joined to dates
    summary.json inference.*        `by_cna` (40 CNAs), `largest_stratum`
    origin/data precision.json      the grader ledger, on a public branch
    origin/data backlog.csv         a retained pre-schema-v2 file, 223 names

`publish.NAME_FIELDS` lists nine field names and not one of those keys is among
them, so `publish.check()` returned clean on all of it. The guard is blind along
the field-name axis and along the format axis, and both blindnesses are
invisible to a test that only ever feeds it the fields it knows.

So these tests assert on STRUCTURE: no roster CNA short name may appear as a
value or a key, anywhere, in anything the pipeline writes, whatever the
surrounding field is called.
"""
from __future__ import annotations

import json

import pytest

from rbp import attribution, cli, inference, roster


def _roster_names():
    """The 539 certified CNA short names, from the pinned roster.

    The denominator the site already uses, so this test cannot drift from what
    the project counts as a CNA name.
    """
    return set(roster.load()["names"])


def _walk(obj, path="$"):
    """Every (path, key, value) in a nested structure, keys included.

    Keys matter as much as values here: `by_cna` was a MAPPING KEYED BY CNA, so a
    walk that only inspected values would have reported it clean.
    """
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield f"{path}.{k}", k, v
            yield from _walk(v, f"{path}.{k}")
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield f"{path}[{i}]", None, v
            yield from _walk(v, f"{path}[{i}]")


def names_in(obj, names):
    """Roster CNA short names appearing as a key or a scalar value."""
    hits = []
    for path, key, val in _walk(obj):
        if key is not None and key in names:
            hits.append(f"{path} (as a KEY)")
        if isinstance(val, str) and val in names:
            hits.append(f"{path} = {val!r}")
    return hits


# --------------------------------------------------------------------------
# the strippers
# --------------------------------------------------------------------------

def test_a_per_cna_table_is_stripped_from_the_inference_block():
    """summary.json carried leave_one_out.by_cna: 40 CNAs with decided, correct,
    wrong, precision and coverage each. That is a per-target operating table for
    de-anonymising the reserved space, published by the site that argues on
    /policy that this exact capability makes a blanket unblinding unsafe."""
    block = {"precision": 0.99, "decided": 29614,
             "by_cna": {"GitHub_M": {"decided": 7211, "precision": 1.0},
                        "Linux": {"decided": 4497, "precision": 1.0}},
             "largest_stratum": "GitHub_M"}
    out = cli._unattributed_stratum(block)
    assert out["precision"] == 0.99 and out["decided"] == 29614, (
        "the aggregate warrant was thrown away with the breakdown")
    assert "by_cna" not in out and "largest_stratum" not in out
    assert not names_in(out, _roster_names())


def test_the_stratum_stripper_reaches_nested_blocks():
    """`live` and `leave_one_out` are siblings and either can carry by_cna."""
    out = cli._unattributed_stratum(
        {"live": {"graded": 1, "by_cna": {"suse": {"decided": 1}}}})
    assert "by_cna" not in out["live"]


def test_a_closure_record_does_not_name_the_assigner():
    """46 of 47 rows in resolved.json carried published_assigner joined to
    first_public, published and days_to_publish. That join is a dated per-CNA
    lateness table, and the assigner is AUTHORITATIVE rather than inferred, which
    makes it a stronger claim than anything the site puts on a page."""
    out = cli._unattributed_closure(
        {"cve_id": "CVE-2026-43980", "published_assigner": "GitHub_M",
         "first_public": "2026-06-03", "published": "2026-08-21",
         "days_to_publish": 79})
    assert out == {"cve_id": "CVE-2026-43980", "first_public": "2026-06-03",
                   "published": "2026-08-21", "days_to_publish": 79}
    assert not names_in(out, _roster_names())


def test_the_closure_stripper_covers_every_naming_field():
    for field in ("published_assigner", "assigner", "owner", "predicted",
                  "predicted_owner"):
        assert field not in cli._unattributed_closure({field: "suse", "cve_id": "x"})


# --------------------------------------------------------------------------
# not computing it at all
# --------------------------------------------------------------------------

def test_the_null_attributor_answers_the_same_shape():
    """classify._row unpacks three values from attribute(). A shim that returned
    a different arity would fail at row one of the first real run rather than
    here."""
    real = attribution.Attributor.attribute
    got = attribution.NullAttributor().attribute("some product", "a description")
    assert isinstance(got, tuple) and len(got) == 3
    assert got[0] is None, "the null attributor produced a name"
    assert real.__code__.co_argcount == \
        attribution.NullAttributor.attribute.__code__.co_argcount


def test_a_run_that_did_not_infer_reports_unmeasurable_not_zero():
    """"Did not attempt" and "attempted and scored nothing" are different facts.
    precision 0.0 reads as measured-and-wrong; None reads as not measurable, and
    summarise_state and the site already render it that way.

    Same distinction feeds.record_feed draws between a failed feed and an empty
    one, and the one the feed scorecard had to grow an `unmeasurable` verdict
    for."""
    v = inference.unattributed_validation(k=3)
    assert v["leave_one_out"]["precision"] is None
    assert v["live"]["precision"] is None
    assert v["not_run"] is True and v["not_run_reason"]


def test_the_not_run_validation_matches_the_real_one_key_for_key():
    """A shim that drifts from the real return shape breaks a consumer on the day
    naming is switched back on, which is the one day nobody is looking at this
    path.

    DERIVED FROM THE REAL FUNCTION, which is what this test's name claimed and
    what it did not do. It computed the real keys from the source with a regex,
    left that in an unused local, and compared the shim against a hand-typed list
    of nine names. A key added to the real block was not checked by anything,
    which is exactly the drift this exists to catch, in the test written to catch
    it.

    Parsed rather than grepped: the regex matched every quoted key anywhere in the
    body, nested literals included, so it could not have been used as it stood.
    """
    import ast
    import inspect
    tree = ast.parse(inspect.getsource(inference.apply_to_backlog).lstrip())
    returns = [n for n in ast.walk(tree.body[0])
               if isinstance(n, ast.Return) and isinstance(n.value, ast.Dict)]
    assert returns, "apply_to_backlog no longer returns a dict literal; this " \
                    "test can no longer read its shape and must be rewritten"
    real = {k.value for k in returns[-1].value.keys if isinstance(k, ast.Constant)}
    shim = set(inference.unattributed_validation())

    missing = real - shim
    assert not missing, (
        f"the shim is missing {sorted(missing)}, which the real block returns. A "
        "consumer branching on the shim gets a KeyError on the day naming comes "
        "back on.")
    # The shim may add keys the real block does not have; `not_run` and its reason
    # are the whole point of it. It may not SILENTLY add them, so they are named.
    extra = shim - real
    assert extra <= {"not_run", "not_run_reason"}, (
        f"the shim invents {sorted(extra - {'not_run', 'not_run_reason'})}, which "
        "no consumer of the real block will ever see")


def test_the_not_run_validation_carries_no_name():
    assert not names_in(inference.unattributed_validation(), _roster_names())


# --------------------------------------------------------------------------
# the flag is singular
# --------------------------------------------------------------------------

def test_the_pipeline_reads_the_one_flag_rather_than_defining_a_second():
    """NEXT.md: "site.NAMING_ENABLED is the single flag." A second one in cli
    would be a posture that can disagree with itself."""
    import inspect
    src = inspect.getsource(cli.cmd_run)
    assert "NAMING = site.NAMING_ENABLED" in src
    assert "NAMING_ENABLED =" not in src.replace("NAMING = site.NAMING_ENABLED", "")




# --------------------------------------------------------------------------
# the value guard: what publish.check refuses, and what it must not
# --------------------------------------------------------------------------

def _tree(tmp_path, files):
    for rel, body in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body if isinstance(body, str) else json.dumps(body))
    return str(tmp_path)


@pytest.mark.parametrize("rel,body,why", [
    ("snapshots/d/cnas.json", [{"cna": "GitHub_M", "outstanding": 222}],
     "seven named CNAs ranked by outstanding count, on the live site"),
    ("snapshots/d/resolved.json", [{"cve_id": "CVE-1", "published_assigner": "GitHub_M"}],
     "a dated per-CNA lateness table"),
    ("snapshots/d/summary.json",
     {"inference": {"leave_one_out": {"by_cna": {"Patchstack": {"decided": 2561}}}}},
     "a 40-CNA operating table, keyed BY CNA so a value-only walk misses it"),
    ("snapshots/d/summary.json2", {"inference": {"largest_stratum": "GitHub_M"}},
     "the largest stratum, named"),
    ("precision.json", {"graded": [{"actual": "VulnCheck"}]},
     "the grader ledger on a public branch"),
    ("snapshots/d/backlog.csv", "cve_id,owner\nCVE-1,suse\n",
     "223 names in a CSV the JSON-only walk could not see"),
])
def test_the_guard_refuses_each_leak_that_actually_shipped(tmp_path, rel, body, why):
    """All five, replayed. Every one returned CLEAN from publish.check on
    2026-08-26, each through a different key or a different format."""
    if rel.endswith("summary.json2"):
        rel = rel[:-1]
    problems = publish.check(_tree(tmp_path, {rel: body}))
    assert problems, f"the guard still cannot see: {why}"
    assert any("certified CNA" in p for p in problems), problems


@pytest.mark.parametrize("rel,body,why", [
    ("snapshots/d/backlog.json", [{"cve_id": "CVE-1", "dates": {"redhat": "2025-01-01"}}],
     "`dates` is keyed by FEED, and several feeds share a name with a CNA"),
    ("snapshots/d/backlog.json", [{"cve_id": "CVE-1", "sources": "redhat,suse"}],
     "which feeds saw the row is a fact about our feeds"),
    ("snapshots/d/backlog.json", [{"cve_id": "CVE-1", "package": "libreswan"}],
     "the affected package, which is also a CNA. Real row, 2026-08-25"),
    ("snapshots/d/backlog.json", [{"cve_id": "CVE-1", "description": "glibc"}],
     "an advisory summary that is exactly a package name. Real row"),
    ("snapshots/d/summary.json", {"coverage": {"covered": ["suse", "redhat"]}},
     "the covered set, published on purpose so the naming gate is inspectable"),
    ("snapshots/d/summary.json",
     {"coverage": {"near_floor": [{"cna": "suse", "sightings": 2, "short_by": 1}]}},
     "near-floor CNAs: aggregate coverage in the same sense top_missed_effective "
     "already is, and strictly weaker, since it is a list of what this site "
     "CANNOT yet do. Round 7; this guard refused the publication until it was "
     "allowlisted, which is the allowlist working"),
    ("snapshots/d/summary.json", {"coverage": {"corroborating_feeds": ["mozilla"]}},
     "a list of FEED names. mozilla is a feed that shares its name with a CNA, "
     "exactly like redhat and suse in `dates` above"),
    ("snapshots/d/backlog.csv", "cve_id,package,description\nCVE-1,glibc,A flaw in suse packaging\n",
     "a CSV description mentioning a CNA in prose"),
])
def test_the_guard_permits_what_is_not_attribution(tmp_path, rel, body, why):
    """The other half, and the half that decides whether this guard is usable.

    A guard that fires on the affected package empties the table it protects.
    The line is: naming a CNA as the OWNER of a row is forbidden; naming the
    feeds we read, the packages affected, and the coverage we have is the site's
    own transparency and is published deliberately.
    """
    problems = [p for p in publish.check(_tree(tmp_path, {rel: body}))
                if "certified CNA" in p]
    assert not problems, f"false positive on {why}: {problems}"


def test_the_legitimacy_list_is_an_allowlist_not_a_denylist():
    """The failure that produced this guard was a denylist of nine field names
    that five leaks walked around. A new field must default to REFUSED."""
    assert publish._roster_name_hits({"brand_new_field": "GitHub_M"},
                                     {"GitHub_M"})


def test_the_round_7_coverage_allowlist_entries_are_not_over_broad(tmp_path):
    """Allowlisting two coverage fields must not open `coverage` as a whole.

    `_name_path_allowed` is a SUBSTRING test, so a careless entry like
    ".coverage." would have permitted every future field under it, including one
    that did attribute a row. The two entries added in round 7 name their fields
    in full, and this asserts an unrelated coverage field still defaults to
    REFUSED.
    """
    problems = [p for p in publish.check(_tree(tmp_path, {
        "snapshots/d/summary.json": {"coverage": {"invented_later": ["suse"]}}}))
        if "certified CNA" in p]
    assert problems, (
        "a new field under `coverage` was permitted without anyone justifying "
        "it, which is the denylist failure this guard replaced")


def test_a_prose_word_that_is_also_a_cna_does_not_fire_in_markdown(tmp_path):
    """report.md is prose. `Go`, `Linux` and `curl` are roster short names and
    ordinary words, and the exclusion applies to prose ONLY: the first version of
    it also excluded suse, apple and microsoft, and a backlog.csv with 223 names
    sailed through the check written to catch it."""
    problems = [p for p in publish.check(
        _tree(tmp_path, {"snapshots/d/report.md":
                         "Go and curl were unaffected; see the Linux tracker.\n"}))
        if "certified CNA" in p]
    assert not problems, problems


def test_the_prose_exclusion_does_not_reach_structured_fields(tmp_path):
    """suse in a CSV owner column must fire even though suse is prose-excluded."""
    problems = [p for p in publish.check(
        _tree(tmp_path, {"snapshots/d/backlog.csv": "cve_id,owner\nCVE-1,suse\n"}))
        if "certified CNA" in p]
    assert problems, "the prose exclusion leaked into the structured check again"


from rbp import publish


def test_the_ledger_denamer_covers_the_authoritative_fields_too():
    """`actual` and `published_assigner` were missing from _LEDGER_NAME_FIELDS.

    denamed_ledger exists to stop the ledgers naming CNAs on a public branch and
    it left precision.json's entire graded history and 46 closures in
    resolutions.json untouched. Both carry an AUTHORITATIVE assigner read from
    the published record, which is a stronger claim than anything on a page.

    Found by the value guard, not by the field-name guard, which is the whole
    argument for having one.
    """
    out = publish.denamed_ledger({
        "graded": [{"cve_id": "CVE-1", "predicted": "suse", "actual": "GitHub_M"}],
        "resolved": [{"cve_id": "CVE-2", "published_assigner": "GitHub_M",
                      "days_to_publish": 79}]})
    assert not names_in(out, _roster_names()), out
    assert out["resolved"][0]["days_to_publish"] == 79, (
        "the de-namer took the measurement with the name")


def test_the_scrubber_and_the_guard_refuse_exactly_the_same_fields():
    """`publish._named_paths`'s own docstring: "the guard must refuse exactly what
    the scrubber removes or the two drift". They had drifted.

    `denamed_ledger` dropped _LEDGER_NAME_FIELDS plus six names unioned in by
    hand. `_named_paths` refused _LEDGER_NAME_FIELDS plus THREE, unioned in by
    hand somewhere else. So the scrubber removed `owner_contested`,
    `product_map_confidence` and `product_map_method` and the guard would have
    let all three through, on the exact invariant the docstring asserts. Nothing
    tested it: the claim was made in prose and was false when it was written.

    Both now read one list. This asserts the property rather than the
    implementation, so re-introducing a hand-written union on either side fails
    here even if it happens to be correct on the day.
    """
    from rbp import schema
    probe = {f: "GitHub_M" for f in schema.LEDGER_NAME_FIELDS}
    probe["cve_id"] = "CVE-2026-1"
    probe["days_to_publish"] = 12

    scrubbed = set(probe) - set(publish.denamed_ledger(probe))
    refused = {path for path in publish._named_paths(probe)}

    assert scrubbed == refused, (
        "the scrubber and the guard disagree.\n"
        f"  removed but not refused: {sorted(scrubbed - refused)}\n"
        f"  refused but not removed: {sorted(refused - scrubbed)}")
    # And neither of them ate the measurement alongside the name.
    assert publish.denamed_ledger(probe)["days_to_publish"] == 12


def test_there_is_one_definition_of_what_names_a_cna():
    """Four lists across three modules, two of them byte-identical.

    The value of `NAME_FIELDS` is entirely that "adding a new owner_* field cannot
    leak by being forgotten here". Forgotten in one of two copies is the same leak
    with one more step, and the two copies of the per-CNA key list lived in the
    two modules that write the two different artefacts.

    Asserted by identity, not equality: two lists that happen to be equal today
    are exactly the state this replaced.
    """
    from rbp import cli, schema, site
    assert site.NAME_FIELDS is schema.ROW_NAME_FIELDS
    assert site._LEDGER_NAMES is schema.LEDGER_NAME_FIELDS
    assert site._PER_CNA_KEYS is schema.PER_CNA_KEYS
    assert cli._PER_CNA_KEYS is schema.PER_CNA_KEYS
    assert cli._CLOSURE_NAME_FIELDS is schema.LEDGER_NAME_FIELDS
    assert publish._LEDGER_NAME_FIELDS is schema.LEDGER_NAME_FIELDS


def test_the_row_fields_and_the_ledger_fields_both_cover_the_owner_family():
    """They are different shapes, not different opinions: a ledger entry records
    a prediction and its verdict, so it has `predicted`/`actual` where a row has
    `owner`. What must not differ is the owner_* family, which appears in both.
    """
    from rbp import schema
    family = {f for f in schema.ROW_NAME_FIELDS
              if f.startswith(("owner_", "product_map_"))}
    missing = family - set(schema.LEDGER_NAME_FIELDS)
    assert not missing, (
        f"{sorted(missing)} qualify a name on a row and are not stripped from a "
        "ledger entry, which is where the same row is recorded with its verdict")


# --------------------------------------------------------------------------
# the site must be clean even from a DIRTY snapshot
# --------------------------------------------------------------------------

def test_the_site_publishes_no_name_even_from_a_named_snapshot(tmp_path):
    """THE MECHANISM BY WHICH /data/cnas.json WENT LIVE.

    site._write_data copies cnas.json, precision.json, summary.json and
    resolved.json out of the RESTORED SNAPSHOT into the published tree. The data
    branch keeps 90 days of snapshots plus one per month for ever, and the
    archive rebuild reads them every run, so fixing the pipeline that writes a
    snapshot does nothing about the ones already on the branch.

    This builds from a snapshot carrying every leak and asserts the published
    tree carries none, which is what makes the branch cleanup a tidy-up rather
    than the thing the guarantee rests on.
    """
    import glob
    from rbp import site as _site

    snaps = tmp_path / "snapshots" / "2026-08-20"
    snaps.mkdir(parents=True)
    rows = [{"cve_id": f"CVE-2026-{n}", "owner": "suse", "owner_tier": "block",
             "public_date": "2026-08-01", "days_public": 19, "sources": "osv",
             "description": "a flaw", "package": "p", "rule": "4.5.1.6",
             "rule_strength": "SHOULD", "indep_sources": 1, "single_origin": True,
             "past_expectation": True, "clock_known": True}
            for n in range(3)]
    (snaps / "backlog.json").write_text(json.dumps(rows))
    (snaps / "cnas.json").write_text(json.dumps(
        [{"cna": "GitHub_M", "slug": "github-m", "outstanding": 222}]))
    (snaps / "resolved.json").write_text(json.dumps(
        [{"cve_id": "CVE-2026-9", "published_assigner": "GitHub_M",
          "days_to_publish": 79}]))
    (snaps / "summary.json").write_text(json.dumps({
        "date": "2026-08-20", "total": len(rows), "past_expectation": len(rows),
        "min_age_days": 7, "epoch": None, "oldest_days": 19, "median_days": 19,
        "must_rows": 0, "should_rows": len(rows), "clock_unknown": 0,
        "unmeasurable_rows": len(rows), "candidate_rows": 0, "named_cnas": 1,
        "undated_excluded": 0, "epoch_excluded": 0, "corroborated": 0,
        "single_origin": len(rows), "age_buckets": {"30d+": len(rows)},
        "generated_at": "2026-08-20T00:00:00+00:00", "source_commit": "0" * 12,
        "source_dirty": False,
        "inference": {"k": 3, "run_coverage": 0.5,
                      "leave_one_out": {"precision": 0.99, "coverage": 0.6,
                                        "decided": 100,
                                        "by_cna": {"GitHub_M": {"decided": 7211}},
                                        "largest_stratum": "GitHub_M"},
                      "live": {"graded": 0, "correct": 0, "precision": None,
                               "below_floor": True, "outstanding": 0}},
        "feeds": {"requested": ["osv"], "failures": [], "attempts": 1,
                  "truncated": [], "detail": {}},
        "coverage": {"total_cnas": 539, "cnas_effective": 1, "cnas_sighted": 1,
                     "cnas_own_channel": 0, "min_sightings": 3, "pct_cnas": 0.2,
                     "pct_effective": 0.2, "observed_pct": 1.0, "profile": "weekly",
                     "roster_pinned": True, "covered": [], "top_n": 50,
                     "top_covered_effective": 45, "top_covered": 45,
                     "pct_top_effective": 90.0, "top_missed_effective": []}}))
    data = tmp_path / "data"
    data.mkdir()
    (data / "precision.json").write_text(json.dumps(
        {"graded": [{"cve_id": "CVE-1", "predicted": "suse", "actual": "GitHub_M"}],
         "predictions": {}, "history": [],
         "by_cna": {"GitHub_M": {"decided": 7211}}}))

    out = tmp_path / "site"
    _site.build(str(out), str(tmp_path / "snapshots"), str(data))

    names = _roster_names()
    offenders = []
    for f in glob.glob(str(out / "data" / "**" / "*.json"), recursive=True):
        hits = names_in(json.loads(open(f).read()), names)
        if hits:
            offenders.append(f"{os.path.relpath(f, out)}: {hits[0]}")
    assert not offenders, ("the published tree names CNAs the snapshot named:\n  "
                           + "\n  ".join(offenders))


import os


def test_the_publish_path_does_not_even_import_the_attribution_stack():
    """834 lines that exist to guess which CNA owns a reserved ID, on a site that
    names nobody.

    Asserted as an IMPORT-GRAPH property rather than a comment, because "we do
    not call it" is a claim someone can break with one convenient import and
    nobody would notice: the code would still work, and it would be back on the
    four-times-daily path.
    """
    import subprocess
    import sys
    out = subprocess.run(
        [sys.executable, "-c",
         "import rbp.cli, sys;"
         "print([m for m in sys.modules if m in ('rbp.inference','rbp.attribution')])"],
        capture_output=True, text=True, cwd=str(pathlib.Path(__file__).parent.parent))
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "[]", (
        f"importing rbp.cli pulls in {out.stdout.strip()}; the attribution stack "
        "is back on the publish path")


import pathlib

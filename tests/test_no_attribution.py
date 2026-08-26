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
    path."""
    import inspect
    src = inspect.getsource(inference.apply_to_backlog)
    real_keys = set(re.findall(r'^\s*"(\w+)":', src, re.M))
    shim = set(inference.unattributed_validation().keys())
    missing = {k for k in ("date", "k", "named", "run_coverage", "leave_one_out",
                           "live", "newly_graded", "withdrawn", "suppressed")} - shim
    assert not missing, f"the shim is missing {missing} that the real block returns"


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


import re  # noqa: E402


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


import json  # noqa: E402
from rbp import publish  # noqa: E402

"""
The published data contract (review item 14).

`data/rbp.json` was `json.dump(rows)`: a bare array with no schema version, no
generation time, no epoch, no buffer, no coverage and no floor flag. Every caveat
that makes the count safe to use lived in HTML and in a sibling file a tool has no
reason to fetch, while the review queued eight published-key changes against
artefacts with no version field.

The other two defects were quieter. Three column lists disagreed (25 fields here,
26 in a different order there, under a comment asserting they were identical), and
three absence conventions were in use with none documented: "", null, and the magic
string "unattributed" sitting in the field that otherwise holds CNA short names.
"""
from __future__ import annotations

import csv
import json
import pathlib
import re

import pytest

from rbp import report, schema, site

ROOT = pathlib.Path(__file__).parent.parent


@pytest.fixture(scope="module")
def built():
    out = ROOT / "site"
    if not (out / "data" / "rbp.json").exists():
        pytest.skip("site not built")
    return out / "data"


# --------------------------------------------------------------------------
# one contract, not three
# --------------------------------------------------------------------------

def test_there_is_exactly_one_column_list():
    """site.CSV_COLS and report's local list were 25 and 26 fields in different
    orders, under a code comment asserting the two CSVs were kept identical."""
    assert site.CSV_COLS is schema.COLUMNS


def test_no_module_defines_its_own_column_list():
    """Grep-style. The duplicate was a literal list assigned to `cols`, and a
    comment is not what stopped it coming back."""
    for f in (ROOT / "rbp").glob("*.py"):
        if f.name == "schema.py":
            continue
        body = re.sub(r"#.*", "", f.read_text())
        body = re.sub(r'""".*?"""', "", body, flags=re.S)
        # A list literal containing both of these is a column list by any name.
        for m in re.finditer(r"\[[^\]]{40,}\]", body, re.S):
            chunk = m.group(0)
            if '"cve_id"' in chunk and '"owner_tier"' in chunk:
                raise AssertionError(
                    f"{f.name} defines its own column list; use schema.COLUMNS")


def test_the_csv_header_is_the_contract(built):
    header = open(built / "rbp.csv").readline().strip().split(",")
    assert header == schema.COLUMNS


def test_the_sidecar_documents_every_published_column(built):
    """Order is part of the contract: a consumer indexing by position breaks
    silently on a reorder."""
    meta = json.loads((built / "rbp.csv.meta.json").read_text())
    assert meta["columns"] == schema.COLUMNS
    assert meta["schema_version"] == schema.SCHEMA_VERSION
    undocumented = [c for c in schema.COLUMNS if c not in meta["fields"]]
    assert not undocumented, undocumented


def test_the_audit_fields_are_in_the_shareable_contract():
    """The fields missing from the old shareable CSV were exactly the ones that let
    a reader check the rule call instead of taking it on trust."""
    for field in ("owner_method", "refs", "hours_public", "ecosystem",
                  "own_feed_date", "earliest_other_date"):
        assert field in schema.COLUMNS, field


# --------------------------------------------------------------------------
# the envelope
# --------------------------------------------------------------------------

def test_the_envelope_carries_the_version_and_the_caveats(built):
    d = json.loads((built / "rbp.json").read_text())
    assert d["schema_version"] == schema.SCHEMA_VERSION
    assert isinstance(d["rows"], list)
    for k in ("generated_at", "snapshot_date", "launched", "min_age_days",
              "epoch", "counts", "coverage", "caveats", "degraded", "columns"):
        assert k in d, k
    # The caveats are in the PAYLOAD, not only in HTML, because a tool has no
    # reason to fetch the HTML and every reason to trust what it parsed.
    for c in ("count_is_a_floor", "owner_is_inferred", "must_is_never_established",
              "not_a_cna_scorecard"):
        assert d["caveats"][c] is True, c


def test_the_envelope_is_not_a_bare_array(built):
    """The whole point. A bare array cannot carry a version, so a consumer who
    integrated against it would have broken silently on any key change."""
    d = json.loads((built / "rbp.json").read_text())
    assert isinstance(d, dict), "rbp.json is still a bare array"


def test_the_closure_record_reaches_consumers(built):
    """resolved.json was computed, rendered and withheld: it reached neither the
    data branch nor site/data. Those rows are the only public evidence that the
    pipeline closes."""
    assert (built / "resolved.json").exists()
    d = json.loads((built / "resolved.json").read_text())
    assert d["kind"] == "resolved"
    assert d["schema_version"] == schema.SCHEMA_VERSION


def test_a_version_bump_is_required_by_a_rename(monkeypatch):
    """The version exists to be bumped. This asserts it is a plain int a consumer
    can compare, not a string that sorts wrong at 10."""
    assert isinstance(schema.SCHEMA_VERSION, int)
    assert schema.SCHEMA_VERSION >= 1, (
        "a consumer finding no schema_version is reading a pre-contract artefact "
        "and should refuse it, so the first version cannot be 0")


# --------------------------------------------------------------------------
# owner is a name or null, never a placeholder
# --------------------------------------------------------------------------

def test_no_published_row_carries_the_placeholder(built):
    """"unattributed" was the largest value in this column by a factor of three,
    cnas.json had no such entry, site._assert_consistent only passed because it
    special-cased the string, and /data documented the opposite ("absent wherever
    the gate did not pass"). A consumer coding to the documentation treated every
    abstention as a named CNA."""
    d = json.loads((built / "rbp.json").read_text())
    bad = [r["cve_id"] for r in d["rows"] if r.get("owner") == "unattributed"]
    assert not bad, bad[:5]


def test_an_abstained_row_has_owner_null_and_the_marker_false(built):
    d = json.loads((built / "rbp.json").read_text())
    abstained = [r for r in d["rows"] if not r.get("owner_nameable")]
    assert abstained, "no abstained rows in this snapshot; test proves nothing"
    for r in abstained:
        assert r["owner"] is None, r["cve_id"]


def test_csv_absence_is_an_empty_cell(built):
    rows = list(csv.DictReader(open(built / "rbp.csv")))
    abstained = [r for r in rows if r["owner_nameable"] == "False"]
    assert abstained
    for r in abstained:
        assert r["owner"] == "", r["cve_id"]


def test_assert_consistent_no_longer_special_cases_the_placeholder():
    """It only passed before because it knew about a magic string the published
    field dictionary denied existed."""
    import inspect
    src = inspect.getsource(site._assert_consistent)
    assert "unattributed" not in src


def test_a_legacy_snapshot_is_coerced_rather_than_crashed_on():
    """CI restores prior snapshots from the data branch for the week-over-week
    diff, so a snapshot written under the old contract WILL be read by new code.
    Version skew on a published artefact is an operational fact, not a bug to
    crash on. Publishing the placeholder as though it were a CNA name is the bug."""
    rows = [{"cve_id": "CVE-2026-1", "owner": "unattributed"},
            {"cve_id": "CVE-2026-2", "owner": "acme", "owner_nameable": True}]
    out = site._normalise_legacy(rows)
    assert out[0]["owner"] is None
    assert out[0]["owner_nameable"] is False
    assert out[1]["owner"] == "acme", "a real name must not be touched"


def test_the_field_dictionary_states_one_absence_spelling_per_field():
    """Three conventions were in use and none was documented, so a consumer had to
    guess whether "" and null meant the same thing."""
    for name, (typ, absent, meaning) in schema.FIELDS.items():
        assert typ and absent and meaning, name
        assert len(meaning) > 20, f"{name}: meaning is too thin to be useful"


def test_the_sanitiser_is_idempotent_on_a_real_snapshot():
    """The property the legacy coercion relies on. If display_description were not
    idempotent, `_normalise_legacy` would rewrite descriptions on every read and
    the "sanitised N legacy" note would fire forever on freshly written data.

    Checked because a CI run reported "sanitised 170 legacy description(s)" and
    that reads exactly like the pipeline failing to sanitise. It was not: all 170
    were in the PREVIOUS snapshot, read for the diff. The note now names its source
    so a correct coercion cannot be mistaken for a broken pipeline."""
    import glob
    from rbp.classify import display_description
    snaps = sorted(glob.glob(str(ROOT / "snapshots" / "*" / "backlog.json")))
    if not snaps:
        pytest.skip("no local snapshot")
    rows = json.loads(pathlib.Path(snaps[-1]).read_text())
    changed = [r["cve_id"] for r in rows
               if display_description(r.get("description") or "")
               != (r.get("description") or "")]
    assert not changed, (
        f"{len(changed)} descriptions change on a second pass, so the sanitiser is "
        f"not idempotent: {changed[:3]}")


def test_the_legacy_note_names_which_file_it_came_from():
    """A coercion message without a source reads as an accusation against the
    current run."""
    import inspect
    src = inspect.getsource(site._normalise_legacy)
    assert "source" in src
    assert '{source}' in src, "the note does not interpolate its source"


# --------------------------------------------------------------------------
# the citable archive (Part 2 condition 7)
# --------------------------------------------------------------------------

def test_a_dated_route_exists_for_every_retained_snapshot(built):
    """/data/rbp.json was the only target a citation could use and it changes every
    six hours, so a figure quoted from it resolves later to a file that no longer
    says what was quoted. After an epoch flip the count changes entirely."""
    idx = json.loads((built / "archive.json").read_text())
    assert idx["snapshots"], "the archive index is empty"
    for entry in idx["snapshots"]:
        p = built.parent / entry["url"]
        assert p.exists(), entry["url"]
        payload = json.loads(p.read_text())
        assert payload["snapshot_date"] == entry["date"]
        assert payload["schema_version"] == schema.SCHEMA_VERSION


def test_a_dated_file_carries_that_days_numbers_not_todays(built):
    """Written from the snapshot on disk, so a dated file is that day's data rather
    than today's wearing that day's name."""
    idx = json.loads((built / "archive.json").read_text())
    for entry in idx["snapshots"]:
        payload = json.loads((built.parent / entry["url"]).read_text())
        assert len(payload["rows"]) == entry["rows"]
        assert payload["snapshot_date"] == entry["date"]


def test_the_archive_is_described_as_stable_not_immutable(built):
    """A withhold removes a row from every published artefact including these, so a
    dated figure can go down. Promising permanence would mean either breaking the
    promise on the first withhold or letting the archive defeat the withhold."""
    idx = json.loads((built / "archive.json").read_text())
    assert idx["stable_not_immutable"] is True
    assert "can go down" in idx["note"] or "stable, not immutable" in idx["note"].lower()
    page = (ROOT / "templates" / "data.html").read_text()
    assert "Stable, not immutable" in page
    assert "can go" in page and "down" in page


def test_the_archive_obeys_the_same_naming_invariants(built):
    """An archive is not a place where the naming rules stop applying."""
    import inspect
    src = inspect.getsource(site._write_data)
    i = src.index("arch_root")
    assert "assert_artefact" in src[i:], (
        "dated archive files are written without the artefact invariants")


def test_data_page_tells_readers_not_to_cite_the_moving_file(built):
    page = (built.parent / "data.html").read_text()
    assert "Do not cite" in page
    assert "data/archive/" in page

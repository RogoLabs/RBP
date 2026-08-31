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

import _sitefixture
from rbp import schema, site

ROOT = pathlib.Path(__file__).parent.parent


@pytest.fixture
def built(built_site):
    """The published data directory of a site built for this session.

    Was `ROOT / "site" / "data"`, skipped when absent, which is always in CI.
    Thirteen assertions about the published JSON contract skipped in the job that
    gates the publication. See tests/_sitefixture.py.
    """
    return built_site / "data"


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
    # owner_method was in this list: it distinguished a plausibility-checked
    # name from an unchecked one, which only matters when a name is published.
    #
    # `own_feed_date` and `earliest_other_date` were in it too, on the reasoning
    # that they are "the entire input to the rule call". They were declared in
    # FIELDS and written by NOTHING: absent from every row of every snapshot,
    # emitted as empty cells by `csv.DictWriter`. A contract entry for a value
    # no code produces is worse than no entry, because a consumer builds against
    # it and waits for it to fill. Removed at schema 4.
    for field in ("refs", "hours_public", "ecosystem"):
        assert field in schema.COLUMNS, field
    for gone in ("own_feed_date", "earliest_other_date"):
        assert gone not in schema.COLUMNS, (
            f"{gone} is back in the contract; nothing writes it")
        assert gone not in schema.FIELDS, gone


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


def test_every_published_row_is_unnameable_and_carries_no_owner(built):
    """Was: an ABSTAINED row has owner null and the marker false, which allowed
    the complementary case, a nameable row with a name. v1 has no such case, so
    the assertion covers every row rather than a subset."""
    d = json.loads((built / "rbp.json").read_text())
    assert d["rows"], "no rows in this snapshot; test proves nothing"
    for r in d["rows"]:
        assert r.get("owner_nameable") is False, r["cve_id"]
        for field in site.NAME_FIELDS:
            assert field not in r, (r["cve_id"], field)


def test_the_csv_carries_no_owner_column_at_all(built):
    """An always-empty owner column would invite a consumer to build against it
    and wait for it to fill, so the column is gone rather than blank."""
    rows = list(csv.DictReader(open(built / "rbp.csv")))
    assert rows
    for field in site.NAME_FIELDS:
        assert field not in rows[0], field
    for r in rows:
        # `false`, lowercase: the CSV encodes booleans the way every other
        # consumer of this site's data spells them, since F4. This test asserted
        # Python's `False`, which is what the file used to contain.
        assert r["owner_nameable"] == "false", r["cve_id"]


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
    assert "owner" not in out[0], "v1 strips the field, not just its value"
    assert out[0]["owner_nameable"] is False
    # Was: "a real name must not be touched". Under v1 a real name is exactly
    # what must be touched, and the legacy coercion now runs ahead of the strip
    # rather than instead of it.
    assert "owner" not in out[1], "a real name must be stripped like any other"


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

    # The fixture snapshot ALWAYS, plus any real ones this machine happens to
    # hold. This used to be real-snapshots-only with a `pytest.skip`, so it never
    # ran in CI: an idempotence property asserted only where somebody had
    # previously run the pipeline by hand.
    sources = [("fixture", _sitefixture.ROWS + _sitefixture.HELD_BACK)]
    for path in sorted(glob.glob(str(ROOT / "snapshots" / "*" / "backlog.json"))):
        sources.append((path, json.loads(pathlib.Path(path).read_text())))
    for label, rows in sources:
        assert rows, f"{label}: no rows, so idempotence is asserted over nothing"
        changed = [r["cve_id"] for r in rows
                   if display_description(r.get("description") or "")
                   != (r.get("description") or "")]
        assert not changed, (
            f"{label}: {len(changed)} descriptions change on a second pass, so "
            f"the sanitiser is not idempotent: {changed[:3]}")


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
    # The human-readable half. Moved into the slide-over on 2026-08-26 when /data
    # was deleted: without it the only place the site said so was the JSON key
    # asserted above, and a promise about permanence that lives only in a JSON key
    # is not a promise anyone has been told about.
    page = (ROOT / "templates" / "_panel.html").read_text()
    assert "Stable, not immutable" in page
    assert "can go" in page and "down" in page


def test_the_archive_obeys_the_same_naming_invariants(built):
    """An archive is not a place where the naming rules stop applying."""
    import inspect
    src = inspect.getsource(site._write_data)
    i = src.index("arch_root")
    assert "assert_artefact" in src[i:], (
        "dated archive files are written without the artefact invariants")


def test_the_front_door_tells_readers_not_to_cite_the_moving_file(built_site):
    """rbp.json is overwritten four times a day, so citing it cites whatever it
    says next week. The dated archive is what a citation should point at.

    /data was removed on 2026-08-26 and its content moved into the slide-over on
    the front door, so this reads the page that actually ships.
    """
    front = (built_site / "overview.html").read_text()
    assert "archive" in front.lower(), (
        "the front door does not mention the dated archive at all")
    assert "archive.json" in front, (
        "the archive index is not linked where a citer will look")


def test_the_archive_is_judged_by_the_rules_that_applied_when_it_was_written(tmp_path):
    """The first version validated every historical snapshot against TODAY's covered
    set and cnas.json, which fails the moment a CNA named in an older snapshot is
    absent from today's list, or falls outside today's covered set because a feed
    moved. CI reproduced it on the first run: the archive refused to publish a
    historical row that was correct when it was written.

    A historical artefact has to be judged by the rules that applied when it was
    produced, and the site publishes its own covered set alongside each snapshot for
    exactly that reason. Failing closed on correct history is still failing."""
    from rbp import site as site_mod

    def snap(date, owner, covered, cnas):
        d = tmp_path / "snapshots" / date
        d.mkdir(parents=True)
        (d / "backlog.json").write_text(json.dumps([{
            "cve_id": "CVE-2026-1", "owner": owner, "owner_nameable": bool(owner),
            "counted": True, "days_public": 30, "public_date": "2026-07-01",
            "description": "a flaw", "sources": "debian"}]))
        (d / "cnas.json").write_text(json.dumps(cnas))
        (d / "summary.json").write_text(json.dumps({
            "total": 1, "past_expectation": 1, "oldest_days": 30, "median_days": 30,
            "named_cnas": len(cnas), "must_rows": 0, "should_rows": 1,
            "clock_unknown": 0, "unmeasurable_rows": 1, "candidate_rows": 0,
            "undated_excluded": 0, "min_age_days": 7, "age_buckets": {}, "epoch": None,
            "inference": {"k": 3, "run_coverage": 0.0,
                          "leave_one_out": {"precision": 0.99, "coverage": 0.6,
                                            "decided": 100},
                          "live": {"graded": 0, "correct": 0, "precision": None,
                                   "below_floor": True, "outstanding": 0,
                                   "by_tier": {}}},
            "feeds": {"requested": [], "failures": [], "attempts": 0,
                      "truncated": [], "detail": {}},
            "coverage": {"total_cnas": 539, "cnas_effective": 1, "cnas_own_channel": 0,
                         "cnas_sighted": 1, "min_sightings": 3, "pct_cnas": 0.2,
                         "pct_effective": 0.2, "observed_pct": 1.0,
                         "profile": "weekly", "top_n": 50, "top_covered": 1,
                         "roster_pinned": True, "covered": covered},
        }))

    def cna_row(name):
        return {"cna": name, "outstanding": 1, "oldest_days": 30,
                "median_days_public": 30, "past_expectation": 1, "must_rows": 0,
                "should_rows": 1, "published_12mo": 50, "resolved_n": 0,
                "median_days_to_publish": None}

    # Yesterday named a CNA that today does not list at all.
    snap("2026-08-21", "goneaway", ["goneaway"], [cna_row("goneaway")])
    snap("2026-08-22", None, ["stillhere"], [])
    (tmp_path / "data").mkdir()

    site_mod.build(str(tmp_path / "out"), str(tmp_path / "snapshots"),
                   str(tmp_path / "data"))          # must not raise
    dated = (tmp_path / "out" / "data" / "archive" / "2026-08-21" / "rbp.json")
    assert dated.exists()
    body = dated.read_text()
    # The ROW survives: failing closed on correct history is still failing, and
    # that is what this test was written for.
    assert "CVE-2026-1" in body, (
        "a row that was correct when written was dropped from its own archive")
    # The NAME does not. Under v1 the archive is de-named on read like every
    # other artefact, and this is the assertion that matters: the previous
    # withhold lever scrubbed the current run and left the same row published
    # verbatim inside /data/archive/<yesterday>, so a withheld id stayed public
    # for a full cycle. An archive that preserves names it can no longer correct
    # is the leak, not the feature.
    assert "goneaway" not in body, (
        "the dated archive republished a name the current build strips")


def test_the_published_csv_actually_parses(built_site):
    """F4. `csv.DictWriter` calls `str()` on what it is handed, so `source_urls`
    reached the file as a Python `repr` with single quotes and `json.loads`
    raised on row one. `rbp.csv.meta.json` declared that column's type as
    `object`, called it "This is the evidence", and said nothing about how an
    object is spelled in a cell, so the declared type and the encoding never
    contradicted each other.

    Six to nine further columns rendered Python's True/False rather than the
    true/false everything else about this site publishes."""
    import csv as _csv
    import json as _json

    path = built_site / "data" / "rbp.csv"
    rows = list(_csv.DictReader(path.open(encoding="utf-8")))
    assert rows, "the published CSV has no rows"

    meta = _json.loads((built_site / "data" / "rbp.csv.meta.json").read_text())
    assert "csv_encoding" in meta, (
        "the sidecar declares types without saying how they are written")

    obj_cols = [c for c, f in meta["fields"].items()
                if f.get("type") in ("object", "array") and c in rows[0]]
    assert obj_cols, "no object column in the CSV to check"
    for r in rows[:50]:
        for c in obj_cols:
            if r[c]:
                _json.loads(r[c])          # raises if it is a repr again

    bool_cols = [c for c, f in meta["fields"].items()
                 if f.get("type") == "bool" and c in rows[0]]
    for r in rows[:50]:
        for c in bool_cols:
            assert r[c] in ("", "true", "false"), (
                f"{c} is {r[c]!r}; the CSV publishes Python booleans")


# The published column set, pinned to the version that publishes it.
#
# Removing a column WITHOUT bumping SCHEMA_VERSION left the whole suite green,
# which is the one thing that constant exists to prevent. Its own docstring says
# "Bump on ANY published key rename, removal, or meaning change", and nothing
# enforced it: schema 4 removed five columns and 926 tests passed either way.
#
# A consumer pinned to a major version and reading by position is the party this
# protects. They cannot detect a silent removal; the version is the only signal
# they get.
#
# To change the contract: edit both. That is the point, not an inconvenience.
_V4_COLUMNS = (
    "cve_id", "state", "days_public", "hours_public", "public_date",
    "public_date_origin", "clock_known", "rule", "rule_strength",
    "rule_certainty", "rule_basis", "self_disclosed", "owner_nameable",
    "veto_evaluated", "clock_origin", "advisory_date",
    "advisory_days_public", "sources", "feed_count", "refs", "source_urls",
    "package", "ecosystem", "description", "state_verified_this_run",
)


def test_removing_a_published_column_bumps_the_schema_version():
    """SCHEMA_VERSION says "Bump on ANY published key rename, removal, or
    meaning change" and nothing enforced it. Schema 4 removed five columns and
    the suite passed identically with the constant left at 3.

    A consumer pinned to a major version and reading by position cannot detect a
    silent removal. The version is the only signal they get, so it has to move
    when the columns do."""
    assert schema.SCHEMA_VERSION == 4, (
        "SCHEMA_VERSION changed; update _V4_COLUMNS to the new set and rename it, "
        "so the pin travels with the contract rather than being deleted")
    assert tuple(schema.COLUMNS) == _V4_COLUMNS, (
        "the published column set changed without a SCHEMA_VERSION bump.\n"
        f"  added:   {sorted(set(schema.COLUMNS) - set(_V4_COLUMNS))}\n"
        f"  removed: {sorted(set(_V4_COLUMNS) - set(schema.COLUMNS))}")


def test_every_published_column_is_documented_and_nothing_else_is():
    """The other direction. A FIELDS entry for a column that does not exist is
    how `own_feed_date` and `earliest_other_date` survived: declared, described
    as "the entire input to the rule call", and written by nothing."""
    undocumented = [c for c in schema.COLUMNS if c not in schema.FIELDS]
    assert not undocumented, f"published but undocumented: {undocumented}"

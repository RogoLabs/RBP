"""
What leaves the runner (REVIEW.md r3 items 1 and 2).

This logic was shell loops and heredocs in the deploy workflow until it failed on
its first real execution. It lives in a module now so it can be tested, which is
the point: it is the last thing standing between an inferred CNA name and a
public branch.
"""
from __future__ import annotations

import json
import re

from rbp import publish


def _snap(tmp_path, date, files):
    d = tmp_path / "snapshots" / date
    d.mkdir(parents=True)
    for name, body in files.items():
        (d / name).write_text(json.dumps(body) if not isinstance(body, str) else body)
    return d


ROW_OK = {"cve_id": "CVE-2026-1", "owner": "acme", "counted": True}
ROW_HELD_NAMED = {"cve_id": "CVE-2026-2", "owner": "acme", "counted": False}
ROW_HELD_CLEAN = {"cve_id": "CVE-2026-2", "owner": "unattributed", "counted": False}


# --------------------------------------------------------------------------
# staging
# --------------------------------------------------------------------------

def test_stage_copies_only_allowlisted_files(tmp_path):
    _snap(tmp_path, "2026-08-20", {
        "backlog.json": [ROW_OK],
        "summary.json": {"total": 1},
        "backlog_full.json": [ROW_OK],      # must not travel
        "report.md": "Internal / pre-preview. Do not forward.",
    })
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "precision.json").write_text('{"predictions": {}, "graded": []}')

    publish.stage(str(tmp_path / "snapshots"), str(tmp_path / ".state"),
                  str(tmp_path / "data"))
    staged = sorted(p.name for p in (tmp_path / ".state" / "snapshots" / "2026-08-20").iterdir())
    assert staged == ["backlog.json", "summary.json"]
    assert (tmp_path / ".state" / "precision.json").exists()


def test_stage_is_idempotent(tmp_path):
    _snap(tmp_path, "2026-08-20", {"backlog.json": [ROW_OK]})
    (tmp_path / "data").mkdir()
    for _ in range(2):
        publish.stage(str(tmp_path / "snapshots"), str(tmp_path / ".state"),
                      str(tmp_path / "data"))
    assert publish.check(str(tmp_path / ".state")) == []


# --------------------------------------------------------------------------
# the check: the backstop
# --------------------------------------------------------------------------

def test_check_passes_on_a_clean_tree(tmp_path):
    st = tmp_path / ".state"
    (st / "snapshots" / "2026-08-20").mkdir(parents=True)
    (st / "README.md").write_text("x")
    (st / "snapshots" / "2026-08-20" / "backlog.json").write_text(json.dumps([ROW_OK]))
    assert publish.check(str(st)) == []


def test_check_refuses_a_file_off_the_allowlist(tmp_path):
    st = tmp_path / ".state"
    (st / "snapshots" / "2026-08-20").mkdir(parents=True)
    (st / "snapshots" / "2026-08-20" / "backlog_full.json").write_text("[]")
    problems = publish.check(str(st))
    assert any("backlog_full.json" in p for p in problems)


def test_check_refuses_a_name_on_an_uncounted_row(tmp_path):
    """The path check cannot catch this: held_back.json IS allowlisted, and its
    rows were the problem. This is the content check."""
    st = tmp_path / ".state"
    (st / "snapshots" / "2026-08-20").mkdir(parents=True)
    (st / "snapshots" / "2026-08-20" / "held_back.json").write_text(
        json.dumps([ROW_HELD_NAMED]))
    problems = publish.check(str(st))
    assert any("names a CNA on an uncounted row" in p for p in problems)


def test_check_allows_a_properly_withheld_held_back_row(tmp_path):
    st = tmp_path / ".state"
    (st / "snapshots" / "2026-08-20").mkdir(parents=True)
    (st / "snapshots" / "2026-08-20" / "held_back.json").write_text(
        json.dumps([ROW_HELD_CLEAN]))
    assert publish.check(str(st)) == []


def test_check_refuses_a_ledger_naming_an_unpublished_row(tmp_path):
    """The ledger sits at the branch root, so every snapshot-scoped rule missed
    it while it held 366 CVE-to-CNA name pairs."""
    st = tmp_path / ".state"
    (st / "snapshots" / "2026-08-20").mkdir(parents=True)
    (st / "snapshots" / "2026-08-20" / "backlog.json").write_text(json.dumps([ROW_OK]))
    (st / "precision.json").write_text(json.dumps(
        {"predictions": {"CVE-2026-999": {"predicted": "acme"}}, "graded": []}))
    problems = publish.check(str(st))
    assert any("unpublished row" in p for p in problems)


def test_check_refuses_unreadable_json(tmp_path):
    st = tmp_path / ".state"
    (st / "snapshots" / "2026-08-20").mkdir(parents=True)
    (st / "snapshots" / "2026-08-20" / "backlog.json").write_text("{trunc")
    assert any("unreadable" in p for p in publish.check(str(st)))


# --------------------------------------------------------------------------
# retention and ledger pruning
# --------------------------------------------------------------------------

def test_retention_keeps_recent_and_one_per_month(tmp_path):
    st = tmp_path / ".state"
    for d in ("2026-06-01", "2026-06-15", "2026-07-02", "2026-07-20",
              "2026-08-19", "2026-08-20"):
        (st / "snapshots" / d).mkdir(parents=True)
    dropped = publish.prune_snapshots(str(st), keep=2)
    left = sorted(p.name for p in (st / "snapshots").iterdir())
    assert left == ["2026-06-15", "2026-07-20", "2026-08-19", "2026-08-20"]
    assert set(dropped) == {"2026-06-01", "2026-07-02"}


def test_retention_is_a_noop_below_the_keep_count(tmp_path):
    st = tmp_path / ".state"
    (st / "snapshots" / "2026-08-20").mkdir(parents=True)
    assert publish.prune_snapshots(str(st), keep=2) == []


def test_ledger_pruning_drops_unpublished_and_keeps_graded(tmp_path):
    st = tmp_path / ".state"
    (st / "snapshots" / "2026-08-20").mkdir(parents=True)
    (st / "snapshots" / "2026-08-20" / "backlog.json").write_text(json.dumps([ROW_OK]))
    (st / "precision.json").write_text(json.dumps({
        "predictions": {"CVE-2026-1": {"predicted": "acme"},
                        "CVE-2026-999": {"predicted": "beta"}},
        "graded": [{"cve_id": "CVE-2026-5", "correct": True}]}))
    dropped = publish.prune_ledger(str(st), str(st / "snapshots"))
    led = json.loads((st / "precision.json").read_text())
    assert dropped == 1
    assert set(led["predictions"]) == {"CVE-2026-1"}
    assert len(led["graded"]) == 1, "graded verdicts are authoritative, never pruned"


def test_cli_stage_then_check_exits_zero(tmp_path, capsys, monkeypatch):
    _snap(tmp_path, "2026-08-20", {"backlog.json": [ROW_OK], "summary.json": {"total": 1}})
    (tmp_path / "data").mkdir()
    monkeypatch.chdir(tmp_path)
    assert publish.main(["stage"]) == 0
    assert publish.main(["check"]) == 0


def test_cli_check_exits_nonzero_on_a_leak(tmp_path, monkeypatch):
    _snap(tmp_path, "2026-08-20", {"held_back.json": [ROW_HELD_NAMED]})
    (tmp_path / "data").mkdir()
    monkeypatch.chdir(tmp_path)
    publish.main(["stage"])
    assert publish.main(["check"]) == 1


def test_check_refuses_a_row_naming_a_cna_outside_its_covered_set(tmp_path):
    """coverage.top_missed said "we do not read this CNA" while a row said "this
    CNA owns this vulnerability". Both shipped in the same snapshot."""
    st = tmp_path / ".state"
    (st / "snapshots" / "2026-08-20").mkdir(parents=True)
    (st / "snapshots" / "2026-08-20" / "backlog.json").write_text(json.dumps(
        [{"cve_id": "CVE-2026-1", "owner": "siemens", "counted": True}]))
    (st / "snapshots" / "2026-08-20" / "summary.json").write_text(json.dumps(
        {"coverage": {"covered": ["redhat", "debian"]}}))
    problems = publish.check(str(st))
    assert any("outside its own covered set" in p for p in problems)


def test_check_allows_a_row_inside_the_covered_set(tmp_path):
    st = tmp_path / ".state"
    (st / "snapshots" / "2026-08-20").mkdir(parents=True)
    (st / "snapshots" / "2026-08-20" / "backlog.json").write_text(json.dumps(
        [{"cve_id": "CVE-2026-1", "owner": "redhat", "counted": True}]))
    (st / "snapshots" / "2026-08-20" / "summary.json").write_text(json.dumps(
        {"coverage": {"covered": ["redhat", "debian"]}}))
    assert publish.check(str(st)) == []


# --------------------------------------------------------------------------
# the gate's own diagnostic output
# --------------------------------------------------------------------------

def _site_with_coverage(tmp_path, total=434, effective=121, sighted=159, own=2):
    d = tmp_path / "site" / "data"
    d.mkdir(parents=True)
    (d / "summary.json").write_text(json.dumps({"coverage": {
        "total_cnas": total, "cnas_effective": effective, "cnas_sighted": sighted,
        "cnas_own_channel": own, "min_sightings": 3, "profile": "weekly"}}))
    return str(tmp_path / "site")


def test_gate_line_pairs_each_count_with_its_own_percentage(tmp_path, capsys):
    """Nothing asserted this function's output, so when the gate moved from
    cnas_own_channel to cnas_effective the format string kept the old label and CI
    logged "own-channel 2/434 = 27.9%". 2/434 is 0.5%. The percentage was correct
    and the count beside it belonged to a different figure, which is worse than
    either being wrong alone: someone reading the line to find out why a launch
    did not happen would be reading a contradiction."""
    assert publish.gate(_site_with_coverage(tmp_path)) == 0
    line = [ln for ln in capsys.readouterr().out.splitlines()
            if ln.startswith("gate:")][0]

    # The count and the percentage on the gate figure must agree.
    m = re.search(r"effective (\d+)/(\d+) = ([\d.]+)%", line)
    assert m, f"gate line does not state the effective figure: {line!r}"
    eff, total, pct = int(m.group(1)), int(m.group(2)), float(m.group(3))
    assert eff == 121 and total == 434
    assert abs(pct - round(100 * eff / total, 1)) < 0.05, (
        f"{eff}/{total} is {round(100 * eff / total, 1)}%, not {pct}%: {line!r}")

    # The other two figures appear, and are not confusable with the gate figure.
    assert "sighted 159" in line
    assert "own-channel 2" in line
    assert "own-channel 2/434" not in line, (
        "own-channel must not be printed as a ratio next to the gate percentage")


def test_gate_fails_loudly_when_a_launch_is_requested_below_it(tmp_path, capsys, monkeypatch):
    from rbp import site as site_mod
    monkeypatch.setattr(site_mod, "LAUNCHED", True)
    assert publish.gate(_site_with_coverage(tmp_path, effective=10)) == 1
    out = capsys.readouterr().out
    assert "FAIL" in out and "below the 50.0% gate" in out
    # And the reason names the floor, so the log says what to move.
    assert "seen at least 3 times" in out

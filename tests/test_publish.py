"""
What leaves the runner (REVIEW.md r3 items 1 and 2).

This logic was shell loops and heredocs in the deploy workflow until it failed on
its first real execution. It lives in a module now so it can be tested, which is
the point: it is the last thing standing between an inferred CNA name and a
public branch.
"""
from __future__ import annotations

import json

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

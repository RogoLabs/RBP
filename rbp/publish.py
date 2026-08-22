"""
What leaves the runner, and the checks that decide whether it may.

This logic lived in the deploy workflow as shell loops and heredocs. It moved
here for two reasons. The heredocs were fragile: a YAML block scalar plus an
indented heredoc terminator produced `NameError: name 'PRUNE' is not defined` and
failed the staging step on its first real execution. And logic that gates a
publication should be testable, which shell inside YAML is not.

Three operations, in the order the workflow runs them:

    stage   copy the allowlisted artefacts into the checkout of the data branch
    prune   apply retention, and drop ledger entries the site no longer publishes
    check   refuse to publish anything off the allowlist or any leaked name

The check is the backstop. The previous protection was a copy loop plus a
post-hoc `rm -f` for two filenames, on a branch that deliberately carries no
.gitignore, and that branch's own history records a leak in each direction:
workflow files that leaked in at creation, and a green state commit that silently
dropped every snapshot.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import shutil
import sys

# The only files that may exist on the data branch. Anything else is refused,
# rather than removed by name after the fact.
ALLOWED_ROOT = {"README.md", "precision.json", "resolutions.json"}
ALLOWED_SNAPSHOT = {"backlog.json", "backlog.csv", "cnas.json", "summary.json",
                    "held_back.json", "resolved.json"}


def stage(snap_root, state_dir, data_dir):
    """Copy the allowlisted artefacts into the data-branch checkout."""
    os.makedirs(state_dir, exist_ok=True)
    for name in ("precision.json", "resolutions.json"):
        src = os.path.join(data_dir, name)
        if os.path.exists(src):
            shutil.copyfile(src, os.path.join(state_dir, name))

    dest_root = os.path.join(state_dir, "snapshots")
    os.makedirs(dest_root, exist_ok=True)
    copied = 0
    for d in sorted(glob.glob(os.path.join(snap_root, "*"))):
        if not os.path.isdir(d):
            continue
        dst = os.path.join(dest_root, os.path.basename(d))
        os.makedirs(dst, exist_ok=True)
        for f in sorted(os.listdir(d)):
            if f in ALLOWED_SNAPSHOT:
                shutil.copyfile(os.path.join(d, f), os.path.join(dst, f))
                copied += 1
    return copied


def prune_ledger(state_dir, snap_root):
    """Drop open predictions for rows the current snapshot does not publish.

    The ledger sits at the branch ROOT, so every snapshot-scoped cleanup rule
    missed it, and it once held 366 CVE-to-CNA name pairs including rows the site
    withholds. The pipeline now only records published rows; this is the backstop
    for entries written before that, and for a row whose name was later withdrawn.

    Graded verdicts are never touched: those rest on an authoritative assigner
    from the published CVE record rather than on inference.
    """
    path = os.path.join(state_dir, "precision.json")
    snaps = sorted(d for d in glob.glob(os.path.join(snap_root, "*")) if os.path.isdir(d))
    if not os.path.exists(path) or not snaps:
        return 0
    try:
        published = {r["cve_id"] for r in json.load(
            open(os.path.join(snaps[-1], "backlog.json")))}
        led = json.load(open(path))
    except Exception:  # noqa: BLE001
        return 0
    before = len(led.get("predictions") or {})
    led["predictions"] = {k: v for k, v in (led.get("predictions") or {}).items()
                          if k in published}
    dropped = before - len(led["predictions"])
    if dropped:
        json.dump(led, open(path, "w"), indent=1)
    return dropped


def prune_snapshots(state_dir, keep=2, keep_monthly=True):
    """Retention: the current snapshot, the previous one, and one per month.

    An unbounded public log of every row ever named, including names later
    withdrawn, grew four times a day and no correction on the site could reach
    the history.
    """
    root = os.path.join(state_dir, "snapshots")
    snaps = sorted(d for d in glob.glob(os.path.join(root, "*")) if os.path.isdir(d))
    if len(snaps) <= keep:
        return []
    survives = set(snaps[-keep:])
    if keep_monthly:
        by_month = {}
        for d in snaps:
            by_month[os.path.basename(d)[:7]] = d
        survives |= set(by_month.values())
    dropped = []
    for d in snaps:
        if d not in survives:
            shutil.rmtree(d, ignore_errors=True)
            dropped.append(os.path.basename(d))
    return dropped


def check(state_dir):
    """Every reason this tree must not be published. Empty list means clean."""
    problems = []
    for path in glob.glob(os.path.join(state_dir, "**", "*"), recursive=True):
        if os.path.isdir(path) or f"{os.sep}.git{os.sep}" in path:
            continue
        rel = os.path.relpath(path, state_dir)
        parts = rel.split(os.sep)
        if len(parts) == 1:
            if rel not in ALLOWED_ROOT:
                problems.append(f"file at branch root is not allowlisted: {rel}")
        elif parts[0] == "snapshots" and len(parts) == 3:
            if parts[2] not in ALLOWED_SNAPSHOT:
                problems.append(f"snapshot file is not allowlisted: {rel}")
        else:
            problems.append(f"unexpected path: {rel}")

    # No artefact may name a CNA on a row the site does not count. This is the
    # content check that caught held_back.json when the path check could not,
    # because that file IS on the allowlist and its rows were the problem.
    for f in sorted(glob.glob(os.path.join(state_dir, "snapshots", "*", "*.json"))):
        try:
            rows = json.load(open(f))
        except Exception:  # noqa: BLE001
            problems.append(f"unreadable JSON about to be published: {f}")
            continue
        if not isinstance(rows, list):
            continue
        for r in rows:
            if not isinstance(r, dict):
                continue
            named = r.get("owner") not in (None, "", "unattributed")
            if named and r.get("counted") is False:
                problems.append(
                    f"{os.path.basename(f)}: {r.get('cve_id')} names a CNA on an "
                    "uncounted row")

    # And the ledger may not carry a prediction for a row that is not published.
    led_path = os.path.join(state_dir, "precision.json")
    snaps = sorted(d for d in glob.glob(os.path.join(state_dir, "snapshots", "*"))
                   if os.path.isdir(d))
    if os.path.exists(led_path) and snaps:
        try:
            published = {r["cve_id"] for r in json.load(
                open(os.path.join(snaps[-1], "backlog.json")))}
            preds = set((json.load(open(led_path)).get("predictions") or {}))
        except Exception:  # noqa: BLE001
            preds, published = set(), set()
        stray = sorted(preds - published)
        if stray:
            problems.append(
                f"ledger names {len(stray)} unpublished row(s), first: {stray[0]}")
    return problems


def gate(site_dir):
    """Fail the run when a launch was requested below the coverage gate.

    Deliberately separate from the publication. rbp.site already fails closed on
    the flag and serves the pre-launch page, so the site is never frozen by this
    check; what this adds is that an attempted launch below gate produces a red
    check rather than silently not launching, which would otherwise look like a
    build problem.
    """
    from . import site as site_mod
    path = os.path.join(site_dir, "data", "summary.json")
    if not os.path.exists(path):
        print(f"no {path}; nothing to gate")
        return 0
    summary = json.load(open(path))
    status = site_mod._gate_status(summary)
    requested = site_mod.LAUNCHED
    cov = summary.get("coverage") or {}
    print(f"gate: own-channel {status.get('own_channel')}/{status.get('total')} "
          f"= {status.get('pct')}% (need {status['required']}%), "
          f"sighted {status.get('sighted')}, profile {cov.get('profile')!r}")
    if requested and not status["cleared"]:
        print(f"FAIL: launch requested but {status['reason']}. The site was "
              "published in its pre-launch posture, which is correct, but the "
              "launch did not happen and should not look like it did.")
        return 1
    print("launch requested and gate cleared" if requested
          else "not launched; gate not required")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog="rbp.publish")
    ap.add_argument("action", choices=["stage", "check", "gate"])
    ap.add_argument("--state", default=".state")
    ap.add_argument("--snapshots", default="snapshots")
    ap.add_argument("--data", default="data")
    ap.add_argument("--keep", type=int, default=2)
    ap.add_argument("--site", default="site")
    args = ap.parse_args(argv)

    if args.action == "stage":
        n = stage(args.snapshots, args.state, args.data)
        print(f"staged {n} snapshot file(s)")
        dropped = prune_snapshots(args.state, keep=args.keep)
        print(f"pruned {len(dropped)} old snapshot(s)" + (f": {dropped}" if dropped else ""))
        stale = prune_ledger(args.state, args.snapshots)
        print(f"dropped {stale} stale ledger prediction(s)")
        return 0

    if args.action == "gate":
        return gate(args.site)

    problems = check(args.state)
    if problems:
        print("REFUSING TO PUBLISH:")
        for p in problems[:40]:
            print(f"  {p}")
        if len(problems) > 40:
            print(f"  ... and {len(problems) - 40} more")
        return 1
    print("publish check passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())

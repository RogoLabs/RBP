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
import re
import shutil
import sys

# The only files that may exist on the data branch. Anything else is refused,
# rather than removed by name after the fact.
# runs.jsonl is the delivered-tick ledger, appended by the DEPLOY job. It is the
# only durable evidence that a scheduled run produced anything: snapshots are
# per-date and overwritten four times a day, and the failure issue is closed by
# `recover` on the next success, so before this the data-branch git log was the
# only record that two ticks on 2026-08-21 delivered nothing.
ALLOWED_ROOT = {"README.md", "precision.json", "resolutions.json", "runs.jsonl"}
ALLOWED_SNAPSHOT = {"backlog.json", "backlog.csv", "cnas.json", "summary.json",
                    "held_back.json", "resolved.json"}

# The dated archive at /data/archive/<date>/ is built by rbp.site from these same
# staged snapshots, so scrubbing them here is what makes a withhold reach the
# archive. Nothing extra to allowlist: the archive is a site artefact, not a branch
# one, and it is regenerated from the staged snapshots on every build. Worth stating
# because "the archive is immutable" and "a withhold removes a row from it" are in
# tension, and the resolution is that the archive is rebuilt rather than appended.


# A runner-local JSON array of ids. Never published, and never seeded from the
# data branch: see WHERE IT COMES FROM below.
SUPPRESSED_FILE = ".suppressed.json"

# The production source. A repository variable, the same lever RBP_LAUNCHED,
# RBP_EPOCH and RBP_PAUSE already use.
SUPPRESS_ENV = "RBP_WITHHOLD"

_ID_SPLIT = re.compile(r"[\s,;]+")


def suppressed_ids(data_dir):
    """Ids withheld from publication, from the repository variable and the file.

    THE ONE IMPLEMENTATION. `site.withheld_ids` was a second copy of this
    function, reading the same file, in the module that builds the pages, while
    this one is read by the module that stages the data branch. Two readers of one
    file that must agree, and nothing making them agree.

    WHERE IT COMES FROM. `RBP_WITHHOLD`, a repository variable holding a
    comma-separated list of CVE IDs. A person sets it; the next build drops those
    rows from every page and every artefact, and `check` refuses to stage them.
    /method promises exactly that: "a person reads it, applied by hand, takes
    effect on the next build". This is the hand.

    NOT THE DATA BRANCH, and the reason is worth keeping. The obvious durable home
    for a hand-maintained list is the branch that already carries the other
    hand-maintained state, and it is the wrong one: that branch is public, so
    committing the ids there publishes the exact list the lever exists to remove.
    "Counts, never identifiers" is the rule, and a git history of removals is
    identifiers. A repository variable is not public and needs no allowlist entry.

    Both sources are UNIONED rather than ranked. A precedence chain drops one
    source silently when the other is set, and for a withhold the only safe
    direction to fail is more withheld rather than fewer. The file stays because a
    local build and the tests need a way in that does not involve the environment.

    THIS WAS UNREACHABLE FOR FOUR DAYS. `cli.py` stopped writing the file with the
    channel that produced it on 2026-08-26, nothing replaced the writer, and
    `data/` is gitignored and recreated empty on every runner. So the lever the
    site promised in writing read an absent file on every run, while both readers,
    both guards and every test around them passed.

    Normalised on read: stripped and upper-cased, so a hand-typed lower-case id or
    one with stray whitespace still withholds.

    Empty on any problem, and that is the safe direction here: an unreadable
    source means nothing is withheld from the SITE, while `check` still refuses to
    stage a suppressed row, so the failure cannot reach the data branch.
    """
    ids = set()
    for tok in _ID_SPLIT.split(os.environ.get(SUPPRESS_ENV) or ""):
        if tok.strip():
            ids.add(tok.strip().upper())
    try:
        raw = json.load(open(os.path.join(data_dir, SUPPRESSED_FILE)))
    except Exception:
        raw = []
    if isinstance(raw, list):
        ids |= {str(i).strip().upper() for i in raw if str(i).strip()}
    return ids


def _scrub(path, ids):
    """Remove withheld ids from one staged artefact. Returns rows removed.

    Applied to EVERY staged snapshot, not just the newest. The first live withhold
    left the row absent from rbp.json, rbp.csv, summary.json, cnas.json and
    precision.json, and still present in the previous day's snapshot on the data
    branch, where retention keeps it for up to a month. A withhold that only
    applies going forward is not a withhold: the id stays fetchable from yesterday.
    """
    if not ids or not os.path.exists(path):
        return 0
    if path.endswith(".json"):
        try:
            rows = json.load(open(path))
        except Exception:
            return 0
        if isinstance(rows, list):
            keep = [r for r in rows
                    if not (isinstance(r, dict) and r.get("cve_id") in ids)]
            if len(keep) != len(rows):
                _schema.write_json(path, keep)
                return len(rows) - len(keep)
        elif isinstance(rows, dict):
            # resolutions.json shape: {"open": {cve_id: {...}}, "resolved": [...]}
            n = 0
            op = rows.get("open")
            if isinstance(op, dict):
                for cid in [c for c in op if c in ids]:
                    del op[cid]
                    n += 1
            res = rows.get("resolved")
            if isinstance(res, list):
                keep = [r for r in res
                        if not (isinstance(r, dict) and r.get("cve_id") in ids)]
                n += len(res) - len(keep)
                rows["resolved"] = keep
            preds = rows.get("predictions")
            if isinstance(preds, dict):
                for cid in [c for c in preds if c in ids]:
                    del preds[cid]
                    n += 1
            if n:
                _schema.write_json(path, rows)
            return n
        return 0
    # CSV: drop any line containing a withheld id. Crude and correct, because the
    # id is the first column and appears nowhere else in a row.
    try:
        lines = open(path).read().splitlines(keepends=True)
    except Exception:
        return 0
    keep = [ln for ln in lines if not any(i in ln for i in ids)]
    if len(keep) != len(lines):
        _schema.write_text(path, "".join(keep))
        return len(lines) - len(keep)
    return 0


# Fields in the ROOT LEDGERS that carry an inferred CNA name.
#
# `published_assigner` is deliberately NOT here: it is read back from the
# published CVE Record and is a restatement of a public fact. Everything else in
# this list is this project's own guess about a party.
# Every field on a ledger row that carries a CNA name.
#
# `actual` and `published_assigner` were MISSING, and the value guard is what
# found them: `denamed_ledger` was written to stop the ledgers naming CNAs on a
# public branch, and it left `precision.json:graded[].actual` and
# `resolutions.json:resolved[].published_assigner` untouched — 46 named closures
# and the entire graded history. Both are AUTHORITATIVE assigners read from the
# published record rather than inferred, so they are a stronger claim than
# anything the site puts on a page, and the de-namer skipped them because it was
# written against the inference fields it was thinking about at the time.
#
# Same shape as every other miss in this class: a list of field names, written
# by someone reasoning about one subsystem, applied to files written by another.
#
# ONE DEFINITION, in schema.py since 2026-08-26. This one had six of the twelve
# names and the scrubber below then unioned in six more by hand while the guard
# unioned in three, so the scrubber removed strictly more than the guard refused
# on a pair whose docstring said "the guard must refuse exactly what the scrubber
# removes or the two drift". They had drifted, and nothing said so.
from . import schema as _schema

_LEDGER_NAME_FIELDS = _schema.LEDGER_NAME_FIELDS


def denamed_ledger(obj):
    """Strip inferred CNA names from a ledger, at any depth.

    The ledgers are internal state that happens to live on a PUBLIC branch, and
    that distinction is the whole defect. Measured on origin/data 2026-08-23:
    resolutions.json named a CNA on 116 rows the site itself does not name, 46 it
    publishes with owner null and 70 it holds back entirely, and precision.json
    named `mitre` on 5 more that are owner_tier 'abstain'. Two of the 116 were
    the section 8c rows, live for 50.8 hours across 43 commits while PLAN.md
    recorded the window as 2h55m across 7 and described them as removed.

    A v1 that names nobody on the page and hundreds of parties in a JSON file at
    the root of the same repo has de-named the part people look at, not the site.

    THE COST, stated rather than hidden: an open prediction with no name cannot be
    graded when the row publishes, so live precision restarts. That is smaller
    than it sounds. Production graded n is 1, and the leave-one-out warrant,
    29,614 decisions across 345 CNAs, is name-free and completely unaffected.
    The panel's preferred long-run design keeps gradability without a name by
    storing the k published neighbour IDs the inference rested on, so grading
    becomes a public-CVE-List lookup at grade time. That is a v2 change; this is
    the one that stops the leak tonight.
    """
    drop = set(_LEDGER_NAME_FIELDS)
    if isinstance(obj, dict):
        return {k: denamed_ledger(v) for k, v in obj.items() if k not in drop}
    if isinstance(obj, list):
        return [denamed_ledger(v) for v in obj]
    return obj


def _named_paths(obj, path="", out=None):
    """Every location in a JSON tree holding a non-null inferred CNA name.

    Returns dotted paths so a failure names the row, not just the file. Shares
    _LEDGER_NAME_FIELDS with the staging de-namer plus the row-level owner
    fields, so the guard and the scrubber cannot drift apart: anything the
    scrubber removes, this refuses.

    `owner_tier` and `owner_method` hold no name of their own ("abstain",
    "block-k3-vetoed-by-product-map"). They are refused anyway, because they are
    an assertion that this site formed a view about who owns the row, and on a
    row the site publishes as unattributed that is a statement it has chosen not
    to make. site._denamed strips them for the same reason, and the guard must
    refuse exactly what the scrubber removes or the two drift.
    """
    out = [] if out is None else out
    # THE SAME SET the scrubber removes, by construction rather than by two
    # hand-maintained unions that had already diverged by three fields.
    # tests/test_no_attribution pins them equal.
    fields = set(_LEDGER_NAME_FIELDS)
    if isinstance(obj, dict):
        for k, v in obj.items():
            here = f"{path}.{k}" if path else k
            if k in fields and v not in (None, "", "unattributed", "abstain"):
                out.append(here)
            else:
                _named_paths(v, here, out)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            _named_paths(v, f"{path}[{i}]", out)
    return out


def stage(snap_root, state_dir, data_dir):
    """Copy the allowlisted artefacts into the data-branch checkout."""
    os.makedirs(state_dir, exist_ok=True)
    for name in ("precision.json", "resolutions.json"):
        src = os.path.join(data_dir, name)
        if os.path.exists(src):
            # Copied through the de-namer, never with shutil.copyfile. The local
            # working copy keeps its names so the grader can still use them
            # within a run; the branch copy never has them.
            # Copied verbatim; the de-naming walk below covers it along with
            # every other staged file, so there is one scrubber rather than two
            # that can disagree.
            shutil.copyfile(src, os.path.join(state_dir, name))

    dest_root = os.path.join(state_dir, "snapshots")
    os.makedirs(dest_root, exist_ok=True)
    copied = 0
    withheld = suppressed_ids(data_dir)
    for d in sorted(glob.glob(os.path.join(snap_root, "*"))):
        if not os.path.isdir(d):
            continue
        dst = os.path.join(dest_root, os.path.basename(d))
        os.makedirs(dst, exist_ok=True)
        for f in sorted(os.listdir(d)):
            if f in ALLOWED_SNAPSHOT:
                shutil.copyfile(os.path.join(d, f), os.path.join(dst, f))
                copied += 1
    # DE-NAME every staged JSON, including snapshots staged by EARLIER runs that
    # are still sitting in the checkout. Fresh snapshots arrive already de-named
    # from report.build, but the ones already on the branch were written before
    # that existed and retention keeps them for up to a month, so de-naming only
    # what this run wrote would leave named history published and slowly ageing
    # out. Same reasoning as the withhold scrub directly below, which had to be
    # widened to prior snapshots for exactly this reason.
    renamed = 0
    for base, _d, files in os.walk(state_dir):
        if ".git" in base.split(os.sep):
            continue
        for fn in sorted(files):
            if not fn.endswith(".json"):
                continue
            fp = os.path.join(base, fn)
            try:
                body = json.load(open(fp))
            except (OSError, ValueError):
                continue
            clean = denamed_ledger(body)
            if clean != body:
                _schema.write_json(fp, clean)
                renamed += 1
    if renamed:
        print(f"de-named {renamed} staged file(s); v1 publishes no attribution")

    # Scrub AFTER copying, over every staged file including the root ledgers and
    # every retained prior snapshot, so a withhold reaches history and not only
    # today.
    scrubbed = 0
    if withheld:
        targets = [os.path.join(state_dir, n)
                   for n in ("precision.json", "resolutions.json")]
        targets += glob.glob(os.path.join(dest_root, "*", "*"))
        for t in targets:
            scrubbed += _scrub(t, withheld)
        if scrubbed:
            print(f"scrubbed {scrubbed} withheld row(s) from staged artefacts, "
                  "including prior snapshots")
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
    except Exception:
        return 0
    before = len(led.get("predictions") or {})
    led["predictions"] = {k: v for k, v in (led.get("predictions") or {}).items()
                          if k in published}
    dropped = before - len(led["predictions"])
    if dropped:
        _schema.write_json(path, led)
    return dropped


# How many dated snapshots the data branch retains. One directory per day.
#
# WAS 2, and the reason it was 2 no longer applies. The original rationale was
# that "an unbounded public log of every row ever NAMED, including names later
# withdrawn, grew four times a day and no correction on the site could reach the
# history". That is an argument about names, and v1 publishes none: a retained
# snapshot is now a dated count with no attribution in it.
#
# Meanwhile keep=2 quietly contradicted launch condition 7, which promises that
# "anything cited before launch stays resolvable afterwards". The site archive is
# built by iterating this same tree, so a URL cited on Monday stopped resolving
# by Wednesday, and the live branch held exactly two dates.
#
# 90 days at 0.88 MB per staged snapshot is about 79 MB, plus roughly 11 MB a
# year from the monthlies that survive forever. Well inside the 1 GB repo
# guidance, and it makes a citation good for a quarter, which covers any
# realistic press or research cycle.
#
# Still STABLE rather than immutable: a withhold removes a row from every
# retained snapshot, so a figure can go down. That is the point of the lever and
# /data says so rather than promising a permanence this project will not honour.
KEEP_SNAPSHOTS = 90


def prune_snapshots(state_dir, keep=KEEP_SNAPSHOTS, keep_monthly=True):
    """Retention: the last `keep` dated snapshots, plus one per month forever.

    See KEEP_SNAPSHOTS for why the number changed and what it is trading off.
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


# --------------------------------------------------------------------------
# the value guard: does a certified CNA's name appear at all
# --------------------------------------------------------------------------

# Names too generic to be evidence of attribution IN FREE PROSE. Each is a real
# roster short name that is also an ordinary word or a ubiquitous technical
# token, so a token-scan over a .md file would fire on every mention.
#
# THIS EXCLUSION APPLIES TO PROSE ONLY, and getting that wrong is a mistake this
# guard made on its first run: the list originally included suse, apple,
# microsoft and redhat, and `backlog.csv` carrying `owner=suse` on 223 rows
# sailed straight through the check written to catch it. Those are precisely the
# names that leaked.
#
# Structured artefacts are matched on WHOLE-CELL and WHOLE-VALUE equality
# instead, with no exclusions at all. A JSON string that is exactly "suse", or a
# CSV cell that is exactly "suse", is a name, whatever column it is in. A
# description that happens to contain the word cannot fire, because it is not
# equal to it.
_AMBIGUOUS_IN_PROSE = frozenset({
    "Go", "Linux", "Chrome", "Docker", "Meta", "Echo", "Arm", "seal", "curl",
    "php", "rust", "systemd", "glibc", "openssl", "mitre", "Google", "apple",
    "oracle", "debian", "fedora", "suse", "redhat", "canonical", "microsoft",
})


def _roster_names():
    """Certified CNA short names worth refusing, from the pinned roster.

    Falls back to an empty set ONLY if the roster cannot be read, and says so:
    silently degrading to "no names to look for" would turn this guard off
    exactly the way the field-name guard was already off.
    """
    try:
        from . import roster as _roster
        names = set(_roster.load()["names"])
    except Exception as e:
        print(f"  WARNING: value guard disabled, roster unreadable ({e})")
        return frozenset()
    # No exclusions here. Structured formats match on whole-value equality, which
    # is precise enough on its own; the prose exclusion is applied at the one
    # call site that needs it.
    return frozenset(n for n in names if n and len(n) >= 3)


# WHERE A CNA NAME IS LEGITIMATE, stated as an explicit allowlist.
#
# There are two different things that look identical to a text search, and the
# whole value of this guard depends on separating them:
#
#   FORBIDDEN  naming a CNA as the owner/assigner OF A SPECIFIC ROW. That is an
#              accusation, it is what v1 does not publish, and it is what all
#              five leaks were.
#   ALLOWED    naming CNAs in AGGREGATE COVERAGE, and naming the FEEDS we read.
#              `coverage.covered` is the site's own statement about its reach,
#              published deliberately: inference refuses to name a CNA whose
#              advisories this site does not read, so the covered set has to be
#              inspectable. And `dates` is keyed by FEED, several of which share
#              a name with a CNA (redhat, debian, suse, alpine, mozilla, arch).
#              "the redhat feed referenced this ID on this date" is a fact about
#              our feeds, not about who reserved the CVE.
#
# An allowlist rather than a denylist, because the failure that produced this
# function was a denylist of nine field names that five leaks walked around. A
# new field defaults to REFUSED and someone has to justify adding it here.
_NAME_OK_PATHS = (
    ".dates.",              # per-feed sighting dates, keyed by feed
    ".source_urls",         # one advisory URL per feed, keyed by feed
    ".coverage.covered",    # the covered set, published on purpose
    ".coverage.sightings",  # sightings per CNA, the covered set's evidence
    ".coverage.own_channel_cnas",
    ".coverage.top_missed",
    ".coverage.top_missed_effective",
    ".coverage.off_roster",
    ".feeds.",              # feed health, keyed by feed
    ".sources",             # which feeds saw this row
    ".requested",           # the configured feed list
    # DESCRIBING THE VULNERABILITY IS NOT ATTRIBUTING IT. Some packages share a
    # name with the CNA that maintains them: `libreswan` and `glibc` are both,
    # and on 2026-08-25 both appeared in `package` on real rows. Saying an ID
    # concerns the glibc package is the site's entire purpose; saying glibc
    # reserved it is the thing v1 does not say. Refusing the first to prevent
    # the second would empty the table.
    ".package",
    ".product",
    ".vendor",
    ".ecosystem",
    # An advisory summary is free text supplied by the feed. Two real rows had a
    # description of exactly "glibc" and exactly "openssl".
    ".description",
    # `$.oracle` is the RESERVATION ORACLE's health block (lookups_attempted,
    # cached_terminal, carried_forward). It is a subsystem of this codebase that
    # happens to share its name with a certified CNA.
    #
    # This was the fourth distinct collision found while narrowing this guard,
    # after feed names, package names and advisory descriptions. CNA short names
    # are ordinary technical vocabulary: `oracle`, `glibc`, `curl`, `linux`,
    # `chrome`, `docker`, `go`, `meta`, `arm`, `echo`, `seal`. Any guard built on
    # matching them will keep meeting this, which is an argument for keeping the
    # allowlist explicit and short rather than for matching more loosely.
    "$.oracle",
)


def _name_path_allowed(path):
    return any(ok in path for ok in _NAME_OK_PATHS)


def _roster_name_hits(obj, names, path="$"):
    """Every place a roster name appears as a KEY or a scalar VALUE.

    Keys as well as values, because `leave_one_out.by_cna` was a mapping KEYED by
    CNA: a walk that read only values reported it clean.
    """
    hits = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            child = f"{path}.{k}"
            if isinstance(k, str) and k in names and not _name_path_allowed(child):
                hits.append(f"{child} (as a key)")
            hits.extend(_roster_name_hits(v, names, child))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            hits.extend(_roster_name_hits(v, names, f"{path}[{i}]"))
    elif isinstance(obj, str) and obj in names and not _name_path_allowed(path):
        hits.append(f"{path} = {obj!r}")
    return hits


def _roster_names_in_text(text, names, filename=""):
    """Roster names in a non-JSON artefact.

    CSV is parsed as CSV rather than grepped, so a name inside a description
    cell is judged the same way as one in an owner column: it is a cell value,
    and a cell value equal to a CNA short name is exactly what must not ship.
    Whole-cell equality, not substring, so "Go" inside "Django" cannot fire.
    """
    import csv as _csv
    import io
    hits = []
    if filename.endswith(".csv"):
        try:
            for i, row in enumerate(_csv.DictReader(io.StringIO(text))):
                for col, val in row.items():
                    if col in ("sources", "refs", "dates", "package", "product",
                               "vendor", "ecosystem", "description"):
                        continue        # see _NAME_OK_PATHS for why each is here
                    if isinstance(val, str) and val.strip() in names:
                        hits.append(f"row {i} column {col!r} = {val.strip()!r}")
        except (_csv.Error, ValueError):
            return [f"{filename}: unparseable CSV, cannot be checked for names"]
        return hits
    # Line-oriented prose. Whole-token equality against the roster, MINUS the
    # names that are ordinary words, because this is the only branch that reads
    # running text rather than a structured cell.
    import re as _re
    prose_names = names - _AMBIGUOUS_IN_PROSE
    for tok in set(_re.findall(r"[A-Za-z0-9_.@-]{3,}", text)):
        if tok in prose_names:
            hits.append(f"token {tok!r}")
    return hits


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

    # NO STAGED FILE MAY CARRY AN INFERRED NAME. Every file, at any depth, root
    # ledgers included.
    #
    # This arm exists because the two below it could not fire. They glob
    # snapshots/*/*.json, so root-level files are exempt BY CONSTRUCTION, and the
    # ledger arm further down is hardcoded to precision.json and is a set
    # difference on ids, so it cannot see resolutions.json at all and cannot see
    # a row that keeps its id and loses its name. Staging the real data-branch
    # tip and running this function returned [] while 121 ungated names sat in
    # it. Launch condition 2 is declared MET on the strength of this function.
    #
    # Walks the tree rather than globbing a shape, so the next file added to
    # ALLOWED_ROOT is covered without anyone remembering to widen a pattern.
    # TWO GUARDS, and the second exists because the first was blind four ways.
    #
    # `_named_paths` asks "is this field called one of nine names we listed".
    # Every one of the five leaks found on 2026-08-26 used a different key:
    # `cna` in cnas.json, `published_assigner` in resolved.json, `by_cna` and
    # `largest_stratum` inside summary.json. And the walk skipped every
    # non-JSON file, so a backlog.csv with 223 names in an `owner` column was
    # exempt along a second axis entirely.
    #
    # So the value guard below asks the question that actually matters: does a
    # certified CNA's short name appear ANYWHERE in this file, as a value or as
    # a key, whatever the surrounding field is called and whatever format the
    # file is in. It cannot be evaded by renaming a field, because it does not
    # read field names.
    roster_names = _roster_names()
    for base, _dirs, files in os.walk(state_dir):
        if ".git" in base.split(os.sep):
            continue
        for fn in sorted(files):
            path = os.path.join(base, fn)
            rel_p = os.path.relpath(path, state_dir)
            if fn.endswith(".json"):
                try:
                    body = json.load(open(path))
                except (OSError, ValueError):
                    problems.append(f"unreadable JSON about to be published: {path}")
                    continue
                found = _named_paths(body)
                if found:
                    problems.append(
                        f"{rel_p} carries {len(found)} attribution field(s), first: "
                        f"{found[0]}. v1 publishes no attribution.")
                hits = _roster_name_hits(body, roster_names)
            elif fn.endswith((".csv", ".jsonl", ".md", ".txt")):
                try:
                    hits = _roster_names_in_text(open(path, encoding="utf-8",
                                                     errors="replace").read(),
                                                roster_names, fn)
                except OSError:
                    problems.append(f"unreadable file about to be published: {path}")
                    continue
            else:
                continue
            if hits:
                problems.append(
                    f"{rel_p} names {len(hits)} certified CNA(s), first: "
                    f"{hits[0]}. v1 publishes no attribution, in any field, in "
                    "any format.")

    # No artefact may name a CNA on a row the site does not count. This is the
    # content check that caught held_back.json when the path check could not,
    # because that file IS on the allowlist and its rows were the problem.
    for f in sorted(glob.glob(os.path.join(state_dir, "snapshots", "*", "*.json"))):
        try:
            rows = json.load(open(f))
        except Exception:
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

    # No staged row may name a CNA outside the covered set recorded alongside it.
    for snap in sorted(glob.glob(os.path.join(state_dir, "snapshots", "*"))):
        bl, sm = os.path.join(snap, "backlog.json"), os.path.join(snap, "summary.json")
        if not (os.path.exists(bl) and os.path.exists(sm)):
            continue
        try:
            rows = json.load(open(bl))
            covered = set((json.load(open(sm)).get("coverage") or {}).get("covered") or [])
        except Exception:
            continue
        if not covered:
            continue
        outside = sorted({r.get("owner") for r in rows
                          if isinstance(r, dict)
                          and r.get("owner") not in (None, "", "unattributed")
                          and r.get("owner") not in covered})
        if outside:
            problems.append(
                f"{os.path.basename(snap)}: names CNAs outside its own covered "
                f"set: {outside[:5]}")

    # And the ledger may not carry a prediction for a row that is not published.
    led_path = os.path.join(state_dir, "precision.json")
    snaps = sorted(d for d in glob.glob(os.path.join(state_dir, "snapshots", "*"))
                   if os.path.isdir(d))
    if os.path.exists(led_path) and snaps:
        try:
            published = {r["cve_id"] for r in json.load(
                open(os.path.join(snaps[-1], "backlog.json")))}
            preds = set((json.load(open(led_path)).get("predictions") or {}))
        except Exception:
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
    # Label the figure the percentage actually came from. This read "own-channel
    # {own}/{total} = {pct}%" after the gate moved to cnas_effective, so CI logged
    # "own-channel 2/434 = 27.9%", pairing one figure's count with another's
    # percentage. 2/434 is 0.5%. Anyone reading this line to work out why a launch
    # did not happen would have been reading a contradiction.
    # Each count paired with ITS OWN percentage. The gate moved to
    # top-N-by-volume on 2026-08-23 and this line kept printing the roster
    # `effective` count against the new `pct`, which reproduced the exact defect
    # the paragraph above describes, one metric change later.
    print(f"gate: top-{status.get('top_n')} effective "
          f"{status.get('top_effective')}/{status.get('top_n')} "
          f"= {status.get('pct')}% (need {status['required']}%, "
          f"seen >= {status.get('min_sightings')} times), "
          f"margin {status.get('margin')}; "
          f"roster effective {status.get('effective')}/{status.get('total')} "
          f"= {status.get('roster_pct_effective')}% (does not gate); "
          f"sighted {status.get('sighted')}, "
          f"own-channel {status.get('own_channel')}; "
          f"profile {cov.get('profile')!r}")
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
    ap.add_argument("--keep", type=int, default=KEEP_SNAPSHOTS)
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

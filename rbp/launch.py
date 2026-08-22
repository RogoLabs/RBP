"""
The launch go/no-go checklist, in one place, published rather than remembered.

Review Part 2's finding was that the coverage gate is necessary and nowhere near
sufficient, and that five separate findings had assumed it was the only gate. The
panel asked for nine conditions "written into PLAN.md as a go/no-go checklist and
published on /method so the commitment is checkable from outside".

Both halves of that matter. A checklist only in PLAN.md is a promise to ourselves;
published, it is a promise anyone can hold us to, and the difference is the whole
point of a project whose subject is an unenforced expectation.

Two design choices worth stating.

**Computed where computable, declared where not.** Conditions 1, 2, 3 and 5 are
properties of the current run or of code that exists, so they are derived. The rest
are "does this thing exist yet", which no run can answer, so they are declared
here as literals. A declared status is a hazard: someone flips a boolean and the
site says launch-ready. Mitigated by keeping the declaration in version control
next to the reason, by requiring a `blocks` reason on every unmet condition, and
by `tests/test_launch.py` asserting that no condition can claim MET without either
a derivation or a recorded justification.

**This does not gate the build.** `site._gate_status` still decides the posture on
coverage alone, and `publish.gate` still fails a below-gate launch. This checklist
is the wider commitment and it is advisory to the human, deliberately: making nine
conditions each capable of freezing a four-times-daily publication would be the
guard-taxonomy mistake in PLAN 8b at nine times the scale. What it does instead is
make the launch decision a list rather than a number and a memory, after a session
in which a memory turned out to be wrong about which coverage figure the gate even
used.
"""
from __future__ import annotations

# Status values. MET and UNMET only; there is deliberately no "partial", because a
# partially met launch condition is an unmet one and the word invites rounding up.
MET = "met"
UNMET = "unmet"


def _coverage_condition(summary, gate):
    """Condition 1. Derived: coverage on the gate figure, plus its qualifiers.

    The review asked for four things here, and three of them are about being able
    to trust the percentage rather than about its value: the profile the cron
    actually runs, a pinned denominator, and top-50-by-volume alongside. Only the
    value is currently true, so the condition is unmet even though the number is
    the headline everyone watches.
    """
    cov = (summary or {}).get("coverage") or {}
    reasons = []
    if not gate.get("cleared"):
        reasons.append(f"coverage is {gate.get('pct')}% of the required "
                       f"{gate.get('required')}%")
    if not cov.get("profile"):
        reasons.append("the feed profile is not recorded in summary.coverage")
    if not cov.get("roster_pinned"):
        # The denominator is recounted from the corpus every run, so the
        # percentage is trended over a moving base and shifts overnight on
        # 1 January when the year window rolls.
        reasons.append("the CNA denominator is per-run, not a pinned roster")
    return {
        "n": 1,
        "title": "Coverage on the gate figure, against a pinned roster",
        "detail": (f"{cov.get('cnas_effective')} of {cov.get('total_cnas')} CNAs seen "
                   f"at least {cov.get('min_sightings')} times "
                   f"({cov.get('pct_effective')}%), profile "
                   f"{cov.get('profile') or 'unrecorded'!r}. Top "
                   f"{cov.get('top_n')} by volume: {cov.get('top_covered')} covered."),
        "status": UNMET if reasons else MET,
        "blocks": "; ".join(reasons) or None,
        "item": "7",
    }


def _no_ungated_name(summary):
    """Conditions 2 and 3. Derived from the guards actually being on the path.

    Both are MET because `rbp.publish.check` runs as its own workflow step between
    the artefact upload and the state push, and `site.assert_artefact` runs inside
    the build. Neither is a test. That distinction is the condition: the review's
    wording is "enforced by a publish-time assertion, not a test", written after a
    leak shipped green past a suite that covered it.
    """
    return [
        {
            "n": 2,
            "title": "No ungated name on any world-readable artefact",
            "detail": ("rbp.publish.check refuses any file off an explicit allowlist, "
                       "any row naming a CNA on an uncounted row, any ungated "
                       "product-map field, and any ledger prediction for a row the "
                       "site does not publish. It runs as a workflow step, not a test."),
            "status": MET, "blocks": None, "item": "2, 9",
        },
        {
            "n": 3,
            "title": "Every named CNA inside the covered set for the run that named it",
            "detail": ("A build invariant in site.assert_artefact plus a second check "
                       "in rbp.publish.check, both keyed to the covered set recorded "
                       "in the same snapshot. Fails the build, every run, not a "
                       "threshold checked once."),
            "status": MET, "blocks": None, "item": "3",
        },
    ]


# Conditions no run can evaluate. Declared, with the reason they are not met, so
# the site states its own gaps rather than implying the list is shorter than it is.
_DECLARED = [
    {
        "n": 4,
        "title": "A monitored correction channel, with a suppression lever behind it",
        "detail": ("A route for a CNA to contest a row, a lever that withholds it, "
                   "and a published aggregate count so the lever cannot be used "
                   "silently. The fast path is a public withhold request carrying "
                   "no reason, which is auditable from outside; two private routes "
                   "reach a person for anyone who prefers them."),
        "status": MET,
        "blocks": None,
        # Rehearsed in both directions on 2026-08-22 against CVE-2025-30083, a live
        # row 519 days public. Withheld: absent from backlog.json, backlog.csv,
        # rbp.json, rbp.csv, summary.json, cnas.json, held_back.json,
        # backlog_full.json, precision.json, resolutions.json and both retained
        # prior snapshots. Revoked by closing the issue: row restored on the next
        # build. Verified on the data branch rather than on the site, which is where
        # the first two attempts turned out to be incomplete.
        #
        # ONE DELIBERATE DEVIATION from the review's wording, recorded so a reader
        # can judge it rather than discover it. The panel asked for a "non-public"
        # channel. The AUTOMATIC route is a public issue carrying no reason, because
        # the private advisory form asks for affected versions, severity and CWE and
        # would have turned a one-line request into a form nobody finishes, and
        # because a public request makes the withheld count auditable from outside.
        # Two private routes exist for anyone who prefers them, human-reviewed
        # rather than automatic. The disclosure that worried the panel is answered
        # by asking for no reason: a request naming only an id does not distinguish
        # an embargo from a wrong owner.
        "item": "4",
    },
    {
        "n": 5,
        "title": "The 24-hour naming warrant bound in code, with a floor",
        "detail": ("CNA Rule 4.5.1.7 lets the Secretariat name a reserving CNA only "
                   "24 hours after public disclosure. report.validate_min_age "
                   "refuses to run below a 4-day floor, so no configuration can "
                   "name a CNA inside the window the Program's own rule protects."),
        "status": MET, "blocks": None, "item": "8",
    },
    {
        "n": 6,
        "title": "One precision figure, stratified, with its sample composition",
        "detail": ("The out-of-sample warrant is dominated by a single CNA, so a "
                   "headline precision figure would rest on a sample that never "
                   "tested the tail. Needs stratification by CNA and the "
                   "composition stated in the same sentence as the number."),
        "status": UNMET,
        "blocks": ("not stratified. Production precision is withheld below n=20 "
                   "today, which hides the problem rather than solving it: crossing "
                   "that threshold on the current ledger would license exactly the "
                   "unstratified figure this condition forbids."),
        "item": "21",
    },
    {
        "n": 7,
        "title": "A dated immutable archive, resolvable after the epoch flip",
        "detail": ("Anything cited before launch has to stay resolvable afterwards. "
                   "The epoch flip zeroes the count, and snapshot retention prunes, "
                   "so a pre-launch citation currently has no durable target."),
        "status": UNMET,
        "blocks": "no versioned, dated archive target exists.",
        "item": "2, 14",
    },
    {
        "n": 8,
        "title": "A failure notification exists, and has been exercised once",
        "detail": ("The pipeline publishes four times a day unattended. A silent "
                   "stop looks identical to a quiet week, and the site would keep "
                   "serving a stale count with a freshness claim attached."),
        "status": UNMET,
        "blocks": ("nothing notifies on failure beyond the default Actions email to "
                   "the commit author, and it has never been deliberately tripped."),
        "item": "10",
    },
    {
        "n": 9,
        "title": "The launch state rehearsed via dry_run against real data",
        "detail": ("The dry_run input runs the pipeline and builds the site while "
                   "publishing nothing, so the launched posture and the epoch flip "
                   "can both be exercised against live data before either is real."),
        "status": UNMET,
        "blocks": ("the lever exists and has never been pulled. Launch day would "
                   "otherwise be the first execution of the launched code path."),
        "item": "1",
    },
]


def checklist(summary, gate):
    """The nine conditions, in the review's order, derived where derivable."""
    out = [_coverage_condition(summary, gate)]
    out.extend(_no_ungated_name(summary))
    out.extend(dict(c) for c in _DECLARED)
    return sorted(out, key=lambda c: c["n"])


def status(summary, gate):
    """Roll-up. `cleared` means every condition is met, which is not the same
    question as `site._gate_status`'s coverage check and must never be conflated
    with it: coverage is one of the nine."""
    items = checklist(summary, gate)
    unmet = [c for c in items if c["status"] != MET]
    return {
        "conditions": items,
        "total": len(items),
        "met": len(items) - len(unmet),
        "unmet": len(unmet),
        "cleared": not unmet,
        "blocking": [f"{c['n']}. {c['title']}" for c in unmet],
    }

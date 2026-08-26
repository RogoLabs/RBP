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
    actually runs, a pinned denominator, and top-50-by-volume alongside.

    Top-50-by-volume is no longer merely reported alongside: as of 2026-08-23 it
    IS the gate. The roster share it used to sit beside was unreachable, because
    only 371 of 539 roster CNAs have published three CVEs in the window, so that
    figure cannot exceed 68.8% on any feed set. The roster share is still
    computed, still published, and still checked here for the qualifiers, because
    a denominator that stops being a threshold does not stop needing to be sound.
    """
    cov = (summary or {}).get("coverage") or {}
    reasons = []
    if not gate.get("cleared"):
        reasons.append(f"the gate figure is {gate.get('pct')}% of the required "
                       f"{gate.get('required')}% on {gate.get('basis')}")
    if not cov.get("profile"):
        reasons.append("the feed profile is not recorded in summary.coverage")
    if not cov.get("roster_pinned"):
        reasons.append("the CNA denominator is per-run, not a pinned roster")
    if cov.get("top_covered_effective") is None or not cov.get("top_n"):
        # This is now the gate numerator, not a qualifier. Absent, the gate
        # cannot be evaluated at all and the condition must not read as met.
        reasons.append("top-N-by-volume coverage on the sighting floor is not "
                       "reported, so the gate figure does not exist this run")
    return {
        "n": 1,
        "title": "Coverage on the gate figure, top-N by volume, against a pinned roster",
        "detail": (f"Gate: {cov.get('top_covered_effective')} of the top "
                   f"{cov.get('top_n')} CNAs by volume seen at least "
                   f"{cov.get('min_sightings')} times "
                   f"({cov.get('pct_top_effective')}%), profile "
                   f"{cov.get('profile') or 'unrecorded'!r}. "
                   f"Roster share, which no longer gates: "
                   f"{cov.get('cnas_effective')} of {cov.get('total_cnas')} "
                   f"({cov.get('pct_effective')}%), against the pinned roster of "
                   f"certified CNAs rather than the "
                   f"{cov.get('total_assigners_in_window')} assigners seen "
                   f"publishing in the window."),
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
    # CONDITION 4 IS RETIRED, not met. Removed 2026-08-26 with the channel it
    # described. Kept here as a comment rather than deleted, so a reader of this
    # list can see that it was answered rather than quietly dropped, and so the
    # decision has to be argued with rather than rediscovered.
    #
    # It asked for "a monitored correction channel, a suppression lever behind
    # it, and a published aggregate withheld count". That existed: a GitHub issue
    # reader, an HMAC-keyed list, per-author caps, an anomaly threshold and a
    # degraded-run term, about 1,470 lines across five modules and six copy
    # surfaces, plus a repository secret and an `issues: read` permission on the
    # publishing job.
    #
    # WHY IT WENT. The panel asked for it so a CNA could contest a row that NAMED
    # it. v1 names nobody. Every row here is a CVE ID already referenced in a
    # public advisory and held for the reportable buffer before it is listed, so
    # there is nothing to withhold that is not already public. Jerry's call,
    # 2026-08-26: "if it's public after 72 hours it's public. That is too much
    # overhead for a side project."
    #
    # WHAT REMAINS: an email address in /.well-known/security.txt and on /method,
    # read by a person. No credential, no API call, no scheduled component that
    # can silently stop working, which is the failure mode the original channel
    # actually suffered.
    #
    # WHAT THIS COSTS, stated rather than hidden: there is now no automatic route
    # and no published withheld count, so a removal is a human decision with no
    # audit trail on the site. If the site ever names a party again, this
    # condition comes back with it and is not optional.
    {
        "n": 5,
        # Hand-verified on this date; _expire flips it to UNMET once stale.
        "verified_on": "2026-08-23",
        "title": "A self-imposed naming floor, bound in code",
        "detail": ("CNA Rule 4.5.1.7 lets the Secretariat name a reserving CNA only "
                   "24 hours after public disclosure. report.validate_min_age "
                   "refuses to run below a 4-day floor, so no configuration can "
                   "name a CNA inside the window the Program's own rule protects."),
        # PARTLY FALSIFIED 2026-08-23. The MECHANISM is real and works:
        # report.validate_min_age refuses to run below the 4-day floor and no
        # configuration defeats it. The DOCTRINE was wrong. report.py:95-97 and
        # :123 and this condition's old title described Rule 4.5.1.7 as this site's
        # sole permission for naming anyone, while policy.html:96-98 says in bold
        # that it "is not this site's permission to name anyone, and the site
        # does not claim it as one". /policy holds the correct and stronger
        # position, so the title changed rather than the code. Moot in v1, which
        # names nobody, and it must not silently become load-bearing again if
        # NAMING_ENABLED is ever flipped.
        "status": MET, "blocks": None, "item": "8",
    },
    {
        "n": 6,
        # Hand-verified on this date; _expire flips it to UNMET once stale.
        "verified_on": "2026-08-22",
        "title": "One precision figure, stratified, with its sample composition",
        "detail": ("One floored figure, computed in one place, stratified by CNA with "
                   "the floor applied per stratum, and published with its composition "
                   "beside it. A CNA below the floor reads \"not separately "
                   "measurable\" rather than inheriting the global value."),
        "status": MET,
        "blocks": None,
        # The floor moved into inference.summarise_state, so there is one
        # implementation and the two-answers bug is gone: summary.json used to carry
        # precision 1.0 at graded 1 beside precision.json's null, both live.
        #
        # Leave-one-out is stratified by true owner with the floor per stratum, and
        # publishes its composition: 345 CNAs, 56 above the floor, largest 24.3% of
        # decisions, tail 99.19% over 22,413. /cna renders that CNA's own row or says
        # "not separately measurable" rather than inheriting the global figure.
        #
        # One correction to the item's premise, recorded because it changes the
        # conclusion: the LEAVE-ONE-OUT figure is NOT dominated by one CNA. The n=224
        # out-of-sample probe is (213 of 224), and the live ledger is, and both now
        # carry that composition wherever they appear including PLAN.md. Reporting
        # the LOO figure as equally lopsided would have been repeating the review
        # rather than checking it.
        "item": "21",
    },
    {
        "n": 7,
        # Hand-verified on this date; _expire flips it to UNMET once stale.
        "verified_on": "2026-08-23",
        "title": "A dated immutable archive, resolvable after the epoch flip",
        "detail": ("Anything cited before launch stays resolvable afterwards at "
                   "/data/archive/<date>/rbp.json, with /data/archive.json as the "
                   "index. Stable rather than immutable: a withhold removes a row "
                   "from the archive too, and /data states that rather than promising "
                   "permanence this project would not honour. Retention is 90 "
                   "days of dailies, then one snapshot per month indefinitely, "
                   "and /data states that as a number rather than an adjective."),
        # Was FALSIFIED on 2026-08-23 and fixed the same day. prune_snapshots ran
        # with keep=2 on every six-hourly tick, so the branch held exactly two
        # dated snapshots and a URL cited on Monday stopped resolving by
        # Wednesday. Verified on origin/data, which held 2026-08-22 and
        # 2026-08-23 and nothing else.
        #
        # MET is claimed on a BOUNDED promise, which is the only kind this can
        # honestly be. A dated URL resolves for 90 days; after that the exact
        # date resolves only if it was its month's last. The condition's title
        # says "immutable" and the archive is not, deliberately, because a
        # withhold must be able to reach it. What changed is that the window is
        # now longer than the time it takes to write something citing it, and it
        # is published rather than implied.
        "status": MET,
        "blocks": None,
        # /data/archive/<YYYY-MM-DD>/rbp.json per retained snapshot, plus
        # /data/archive.json as the index. Written from that day's snapshot rather
        # than from today's numbers wearing that day's name, and through the same
        # envelope and the same assert_artefact invariants as every other artefact:
        # an archive is not a place where the naming rules stop applying.
        #
        # Described as STABLE rather than immutable, deliberately. A withhold request
        # removes a row from every published artefact including these, so a dated
        # figure can go down. Promising permanence would mean either breaking the
        # promise on the first withhold, or letting the archive become the reason the
        # withhold does not work. /data says which of those this project chose.
        "item": "2, 14",
    },
    {
        "n": 8,
        # Hand-verified on this date; _expire flips it to UNMET once stale.
        "verified_on": "2026-08-22",
        "title": "A failure notification exists, and has been exercised once",
        "detail": ("One issue per failure episode, opened on the first failure, "
                   "commented on subsequent ones so the duration is visible, and "
                   "closed automatically on the next success. A fire_drill input "
                   "exercises the path on demand without breaking the build."),
        "status": MET,
        "blocks": None,
        # Exercised for real on 2026-08-22, and not by the fire drill: a bug of mine
        # failed the build and the notification opened RogoLabs/RBP#2 with the run
        # link and the statement that nothing published and no state advanced. The
        # next successful run closed it. Both halves of the cycle observed.
        #
        # Deduplicated to one issue per failure episode, because a pipeline broken
        # for two days would otherwise file eight issues and eight issues from a bot
        # is indistinguishable from noise, which is the same muted-alert failure as
        # having no alert at all.
        "item": "10",
    },
    {
        "n": 9,
        # Hand-verified on this date; _expire flips it to UNMET once stale.
        "verified_on": "2026-08-22",
        "title": "The launch state rehearsed via dry_run against real data",
        "detail": ("dry_run plus rehearse_launch and rehearse_epoch build the "
                   "launched posture and an epoch flip against live data while "
                   "publishing nothing, so launch day is not the first execution of "
                   "the launched code path. Refused outside a dry run rather than "
                   "silently ignored."),
        "status": MET,
        "blocks": None,
        # Rehearsed 2026-08-22 against live data, on the third attempt. The first two
        # attempts are the reason this is worth recording rather than ticking:
        #
        #   1. Impossible. RBP_LAUNCHED and RBP_EPOCH were repository variables, so
        #      the only way to see the launched posture was to set them, which means
        #      going live to find out whether going live works. Added dry-run-only
        #      dispatch overrides.
        #   2. Green and did not rehearse. publish.gate went report-only on a dry run
        #      but site.load's demotion is a SECOND check, so the run built the
        #      holding page while every lever said LAUNCHED. Added RBP_REHEARSE as a
        #      separate lever.
        #   3. Broke the suite. RBP_REHEARSE was in the workflow's top-level env, so
        #      it reached the test job and switched off the demotion a test asserts.
        #      Scoped it to the build job and made the suite hermetic.
        #
        # What the passing rehearsal produced, from the pipeline rather than the
        # suite: LAUNCHED posture built, / is the dashboard, 8 pages + 1 CNA page,
        # epoch 2026-08-01 holding back 442 rows with the oldest at 521 days and 80
        # counted, headline core 50, gate reported at 21.7% without failing the run,
        # deploy skipped and no state persisted.
        "item": "1",
    },
]


# How long a hand-verified condition may claim MET before it has to be checked
# again. A declared status is a memory, and this project has been wrong about a
# memory more than once: four of the six declared conditions were false on the
# day someone finally looked.
VERIFIED_MAX_AGE_DAYS = 30


def _expire(cond, today=None):
    """Flip a hand-verified condition to UNMET once its check has gone stale.

    THE WHOLE POINT OF THE CHECKLIST is that the commitment is "checkable from
    outside", and a condition that cannot go false is not checkable. Six of nine
    were hard-coded MET, and four of those six were false when the review looked.

    Deriving what the run can observe is the better fix and is done above. For
    the rest, "met once in August" must stop reading as "met today", so a
    declared MET carries the date it was verified and expires. Absent a date it
    expires immediately, because an undated claim is exactly the thing this
    guards against.
    """
    if cond.get("status") != MET or "verified_on" not in cond:
        return cond
    import datetime as _dt
    try:
        then = _dt.date.fromisoformat(cond["verified_on"])
        now = _dt.date.fromisoformat(today) if today else _dt.date.today()
    except (TypeError, ValueError):
        cond = dict(cond)
        cond["status"] = UNMET
        cond["blocks"] = ("this condition is hand-verified and carries no usable "
                          "verification date, so it cannot claim to be met")
        return cond
    age = (now - then).days
    cond = dict(cond)
    cond["verified_age_days"] = age
    if age > VERIFIED_MAX_AGE_DAYS:
        cond["status"] = UNMET
        cond["blocks"] = (f"last verified by hand {age} days ago, past the "
                          f"{VERIFIED_MAX_AGE_DAYS}-day limit; re-check it")
    return cond


def checklist(summary, gate, today=None):
    """The conditions, in the review's order, derived where derivable.

    Everything the run can observe is derived. What cannot be is declared with a
    verification date and expires, so no condition is permanently true.
    """
    out = [_coverage_condition(summary, gate)]
    out.extend(_no_ungated_name(summary))
    for c in _DECLARED:
        c = dict(c)
        out.append(_expire(c, today))
    return sorted(out, key=lambda c: c["n"])


def status(summary, gate, today=None):
    """Roll-up. `cleared` means every condition is met, which is not the same
    question as `site._gate_status`'s coverage check and must never be conflated
    with it: coverage is one condition of several.

    `total` is len(items) and every consumer must read it rather than typing a
    number. /method said "nine conditions" above "8 of 8 are met" for the whole
    life of the retirement of condition 4.
    """
    items = checklist(summary, gate, today)
    unmet = [c for c in items if c["status"] != MET]
    return {
        "conditions": items,
        "total": len(items),
        "met": len(items) - len(unmet),
        "unmet": len(unmet),
        "cleared": not unmet,
        "blocking": [f"{c['n']}. {c['title']}" for c in unmet],
    }

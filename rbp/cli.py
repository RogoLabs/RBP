"""
RBP-CVEs weekly runner: 100% standalone.

    python -m rbp.cli run                      # full pipeline (current+prior year, all feeds)
    python -m rbp.cli run --years 2026 --sources alas,ubuntu,debian,ghsa
    python -m rbp.cli index                    # (re)build the corpus index only

Pipeline: ensure corpus (download baseline + index) -> gather feeds -> classify
against the corpus + reservation endpoint -> infer + grade owner -> write snapshot + WoW diff.
"""
from __future__ import annotations

import argparse
import datetime as dt
import glob
import json
import os

# ATTRIBUTION AND INFERENCE ARE NOT IMPORTED HERE.
#
# v1 publishes no attribution, so neither module runs on the publish path. They
# are imported lazily inside the one branch that would use them, which makes the
# claim checkable rather than asserted: if this import list ever grows them back,
# something on the four-times-daily path is reaching into 834 lines that exist to
# guess which CNA owns a reserved ID.
from . import (cvelist, feeds, classify, report, coverage,
               clock, site, schema)

# Source profiles: the weekly cron stays lean; the heavy enterprise/ICS sources
# (CSAF aggregator + Microsoft) move to a deeper monthly cadence.
# csaf and msrc were "deep" only, on a monthly cadence that existed in no cron.
# The gate is measured on the profile the cron actually runs, so anything outside
# `weekly` was outside the measurement: siemens showed as an uncovered top-50 CNA
# while already being a configured CSAF provider.
#
# Measured before promoting, 2026-08-22: msrc 10,516 ids in 5.8s for +1 CNA,
# csaf 3,401 ids in 135.8s for +12 (ABB, CERTVDE, CyberDanube, PTC, Rockwell,
# SICK_AG, TPLink, fortinet, jci, palo_alto, schneider, siemens). 142 seconds
# against a 9-minute warm run and a 15-minute target.
PROFILES = {
    "weekly": ("alas,ubuntu,debian,ghsa,ghsa-repos,redhat,alpine,osv,mozilla,arch,"
               "csaf,msrc,samsung"),
    # Kept as a distinct name even though it is now identical to weekly, so the
    # workflow's --profile argument and the docs do not have to change, and so a
    # future heavy source has somewhere to go.
    "deep": ("alas,ubuntu,debian,ghsa,ghsa-repos,redhat,alpine,osv,mozilla,arch,"
             "csaf,msrc,samsung"),
}

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DATA = os.path.join(ROOT, "data")
INDEX = os.path.join(DATA, "index")
SNAPS = os.path.join(ROOT, "snapshots")
CACHE = os.path.join(DATA, ".api_cache.json")
PRECISION = os.path.join(DATA, "precision.json")
RESOLUTIONS = os.path.join(DATA, "resolutions.json")
BASELINE = os.path.join(DATA, "all_CVEs.zip.zip")
# Runner-local handoff from `run` to `publish stage`. Never published.


def degraded_state(*, failures, truncated, capped, dropped, shrunk):
    """One flag a consumer can branch on, plus the reasons. `(bool, [str])`.

    EXTRACTED FROM cli.run so it can be tested. It could not be before, and the
    result was that the single most-rendered piece of state on the site had no
    test at all.

    `capped` is deliberately NOT a degradation. A configured page cap fires on
    every run by design: ubuntu's 200-page cap always fires and ghsa's 40-page
    cap always fires. Folding those in made `degraded` permanently true, so
    base.html rendered "This run is incomplete ... not comparable to the previous
    run" on every page of every run, three hundred lines above a card that
    compares this run to the previous one. A warning that is always on is not a
    warning, it is furniture, and it teaches a reader to ignore the one that
    means something.

    The banner itself was removed on 2026-08-26 and this flag now drives /status
    and the `degraded` key in rbp.json. The distinction matters MORE for those,
    not less: a banner a reader learns to skip costs attention, and a JSON flag
    that is true on every run costs a consumer the ability to branch on it at all.

    Degraded means THIS RUN IS WORSE THAN USUAL. The standing caps are published
    separately as `limitations`, because they are real, permanent, and something
    a reader needs: a capped advisory API is observed over a much shorter window
    than a tracker read in full, so counts from the two are not comparable.
    """
    reasons = (
        [f"{len(failures)} feed(s) failed" for _ in [0] if failures]
        + [f"{len(truncated)} feed(s) stopped early, outside their configured limits"
           for _ in [0] if truncated]
        + [f"{dropped} id(s) unresolved and not carried forward"
           for _ in [0] if dropped]
        # `reports_unreadable` stood here: a fifth reason, for a correction route
        # that had silently stopped working. It was the right instinct and it went
        # with the automated withhold channel on 2026-08-26. The caller passed a
        # hardcoded False from that day on, so the branch could not fire and the
        # parameter was a keyword every caller had to supply to say "no". The
        # instinct still applies if an automated route ever comes back.
        + [f"{len(shrunk)} feed(s) returned far fewer ids than last run"
           for _ in [0] if shrunk])
    return bool(reasons), reasons


def ensure_corpus(force=False):
    """Bring the corpus current. Cheap within a day, cheap across a few days,
    and only re-pulls the 583 MB baseline when the delta chain cannot cover the
    gap. See cvelist.refresh_corpus."""
    return cvelist.refresh_corpus(BASELINE, INDEX, force=force)


def _previous_reserved(snap_root, today):
    """CVE IDs that were RESERVED in the most recent snapshot before `today`.

    The input to carry-forward. Reads the previous backlog rather than the ledger
    because the ledger holds only rows that were *published*, and a row can be in
    the backlog while held back by the buffer or the epoch; dropping those on a
    brownout would still shrink the count once they aged in.

    Tolerant on purpose: no previous snapshot is the normal first-run state, and a
    corrupt one must not stop a publication. The cost of returning empty is that
    unresolved ids drop, which is the old behaviour, and `oracle["dropped"]`
    reports it.
    """
    try:
        dirs = sorted(d for d in glob.glob(os.path.join(snap_root, "*"))
                      if os.path.isdir(d) and os.path.basename(d) < today)
        if not dirs:
            return set()
        rows = json.load(open(os.path.join(dirs[-1], "backlog.json")))
        return {r["cve_id"] for r in rows if isinstance(r, dict) and r.get("cve_id")}
    except Exception as e:
        print(f"  NOTE: no usable previous snapshot for carry-forward ({e})")
        return set()


def _validate_epoch_against_data(today, min_age_days):
    """Refuse an epoch that the buffer guarantees will exclude everything.

    The newest reportable advisory date is always at least `min_age_days` before
    today, by construction: that is what the buffer does. So an epoch set to today
    excludes 100% of reportable rows for the whole buffer window, and the guard
    that catches it sits AFTER the corpus download, the feed fetch and 674 API
    lookups. Flipping RBP_LAUNCHED and RBP_EPOCH together therefore produced a red
    cron four times a day for about a week while Pages kept serving the holding
    page, with no notification anywhere in the workflow. The observable result of
    launching was that nothing happened and nobody was told.

    Checked here, before any network work, with the arithmetic in the message so
    the fix is obvious rather than deducible.
    """
    if not clock.EPOCH:
        return
    try:
        epoch = dt.date.fromisoformat(clock.EPOCH)
        newest_possible = dt.date.fromisoformat(today) - dt.timedelta(days=min_age_days)
    except ValueError:
        return                      # clock._validated_epoch already refused this
    if epoch > newest_possible:
        raise SystemExit(
            f"RBP_EPOCH={clock.EPOCH} cannot match any reportable row.\n"
            f"  today                     {today}\n"
            f"  buffer                    {min_age_days} days\n"
            f"  newest reportable date    {newest_possible.isoformat()}\n"
            f"  epoch                     {clock.EPOCH}\n"
            "A row is reportable only once it has been public for the whole buffer, "
            "so nothing public on or after the epoch can be reportable yet. This "
            f"would publish 0 for {(epoch - newest_possible).days} more day(s). "
            f"Set the epoch to {newest_possible.isoformat()} or earlier, or unset "
            "it. Refusing before spending the corpus download and the API lookups.")


def cmd_build(args):
    site.build(args.out, SNAPS, DATA)


def cmd_index(args):
    ensure_corpus(force=True)


# --------------------------------------------------------------------------
# v1 publishes no attribution, and that has to be true of EVERY artefact
# --------------------------------------------------------------------------
#
# `site.NAMING_ENABLED` is the single flag and it was enforced at the row
# boundary only. Five artefacts published CNA names around it, each through a
# key the leak guard does not know about: `cna` in cnas.json,
# `published_assigner` in resolved.json, and the `by_cna` / `largest_stratum`
# keys inside summary.json's inference block. publish.NAME_FIELDS lists nine
# field names and none of those is among them.
#
# So these strip by STRUCTURE rather than by field name: a per-CNA table is
# keyed by CNA, and a mapping keyed by CNA is the thing that must not ship,
# whatever the key is called.

# Keys inside the inference block whose VALUES are per-CNA mappings.
#
# ONE DEFINITION, in schema.py since 2026-08-26. This was a byte-identical second
# copy of site._PER_CNA_KEYS, on a rule whose entire value is that adding a new
# per-CNA key cannot leak by being forgotten. Forgotten in one of two copies is
# the same leak with an extra step, and the two copies were in the two modules
# that write the two different artefacts.
_PER_CNA_KEYS = schema.PER_CNA_KEYS


def _unattributed_stratum(block):
    """An inference summary with every per-CNA table removed.

    The aggregate figures are the warrant and they stay: leave-one-out precision
    over 29,614 decisions is the strongest claim the site makes and it is
    name-free. What goes is the breakdown that says which CNA each decision was
    about.
    """
    if not isinstance(block, dict):
        return block
    return {k: (_unattributed_stratum(v) if isinstance(v, dict) else v)
            for k, v in block.items() if k not in _PER_CNA_KEYS}


# Fields on a closure record that name the assigner. Authoritative rather than
# inferred, which makes publishing them a STRONGER claim than anything on a
# page, not a weaker one.
#
# The ledger list, not a fifth hand-written subset of it. A closure record IS a
# ledger entry, and this used to name five of the twelve fields, so a closure
# carrying `owner_tier` or `product_map_owner` shipped it.
_CLOSURE_NAME_FIELDS = schema.LEDGER_NAME_FIELDS


def _unattributed_closure(row):
    if not isinstance(row, dict):
        return row
    return {k: v for k, v in row.items() if k not in _CLOSURE_NAME_FIELDS}


# The two shims that stand in for attribution when nothing is attributed.
#
# Local, so `rbp.cli` does not import 834 lines it never calls. Both mirror the
# real shapes exactly: a three-tuple from attribute(), and a validation block
# keyed like apply_to_backlog's, so no consumer needs a branch and nothing
# breaks on the day naming is switched back on.

# Block half-width for the k-either-side test. Only meaningful when naming.
DEFAULT_K = 3


class _NoAttribution:
    """Attributes nothing. `abstain` is what the real Attributor returns when it
    does not know, so downstream needs no special case."""

    def attribute(self, product, description):
        return None, 0.0, "abstain"


def _no_attribution_validation(k=DEFAULT_K, today=None):
    """The validation block for a run that did not infer anything.

    precision is None, NOT 0.0. "Did not attempt" and "attempted and scored
    nothing" are different facts, and the site already renders None as "not
    measurable". Same distinction feeds.record_feed draws between a failed feed
    and an empty one.
    """
    today = today or dt.date.today().isoformat()
    empty = {"method": "not-run", "k": k, "decided": 0, "abstained": 0,
             "total": 0, "correct": 0, "wrong": 0, "coverage": 0.0,
             "precision": None, "below_floor": True, "not_run": True}
    return {
        "date": today, "k": k,
        "named": {"block-corroborated": 0, "block": 0, "abstain": 0},
        "run_coverage": 0.0,
        "leave_one_out": dict(empty),
        "live": {**empty, "graded": 0, "outstanding": 0},
        "newly_graded": 0, "withdrawn": 0, "suppressed": 0,
        "not_run": True,
        "not_run_reason": "v1 publishes no attribution; inference is not run",
    }


def cmd_run(args):
    today = args.today or dt.date.today().isoformat()
    # The single flag, read once. site.py owns it; nothing here defines a second.
    NAMING = site.NAMING_ENABLED
    years = ({int(y) for y in args.years.split(",")} if args.years
             else {int(today[:4]), int(today[:4]) - 1})
    src_str = args.sources or PROFILES.get(args.profile, PROFILES["weekly"])
    requested = [s.strip() for s in src_str.split(",") if s.strip()]
    sources = [s for s in requested if s in feeds.ADAPTERS]
    dropped = [s for s in requested if s not in feeds.ADAPTERS]
    if dropped:
        print(f"  WARNING: ignoring unknown sources {dropped}; valid: {sorted(feeds.ADAPTERS)}")
    if not sources:
        raise SystemExit(f"no valid sources in {requested!r}; valid: {sorted(feeds.ADAPTERS)}")
    args.min_age_days = report.validate_min_age(args.min_age_days)
    _validate_epoch_against_data(today, args.min_age_days)
    print(f"RBP run | today={today} | years={sorted(years)} | profile={args.profile if not args.sources else 'custom'} | sources={sources}")

    corpus, prod_cna = ensure_corpus(force=args.reindex)
    print(f"corpus: {len(corpus):,} records | product->CNA: {len(prod_cna):,}")
    # The canary, immediately after the corpus is in hand. Everything downstream
    # trusts the corpus as ground truth for closure detection, so a stale one is
    # the one failure that makes every other health surface lie.
    corpus_lag = cvelist.assert_corpus_current(corpus, today=today)

    refs = feeds.gather(sources, years)
    print(f"  total unique referenced IDs: {len(refs)}")

    # A feed that fails must never read as an improvement. Counts are a floor,
    # so a silent shrink looks like progress; this is the failure mode most
    # likely to actually happen (PLAN.md R4). The OSV npm ecosystem was dropped
    # from every run for exactly this reason before it was caught.
    # `if failures:` could never fire on truncation, because health_summary
    # returned only FAILED entries. Every run truncates ubuntu, so the live
    # snapshot published `failures: []` beside `truncated: ["ubuntu"]` on a run
    # with known data loss, and the DEGRADED line never printed once.
    failures, truncated, attempts, capped = feeds.health_summary()
    if failures or truncated:
        what = []
        if failures:
            what.append(f"{len(failures)} of {attempts} feeds failed")
        if truncated:
            what.append(f"{len(truncated)} truncated")
        print(f"  DEGRADED: {', '.join(what)}. This run's counts are a lower "
              f"floor than usual and are NOT comparable to the previous run.")
        for f in failures + truncated:
            print(f"    - {f}")

    # THE ATTRIBUTOR, and everything downstream of it, is not built when v1 is
    # publishing no attribution.
    #
    # Its only outputs are product_map_owner / _confidence / _method, all three
    # of which are in publish.NAME_FIELDS and all three of which are therefore
    # stripped before publication. Computing a name in order to delete it is how
    # this project acquired five leaks, a de-namer, a backstop that could not see
    # four of them, and a KeyError that killed three consecutive scheduled builds
    # because the de-namer removed the field the grader needed.
    if NAMING:
        from . import attribution
        attributor = attribution.Attributor(corpus)
    else:
        attributor = _NoAttribution()
    # The ids that were RESERVED last run, so an id the endpoint cannot resolve
    # this run is carried forward instead of vanishing from the count.
    prev_reserved = _previous_reserved(SNAPS, today)
    backlog, fresh, oracle = classify.classify(
        refs, corpus, attributor, CACHE, workers=args.workers, today=today,
        ttl=args.cache_ttl_days, previous_reserved=prev_reserved)
    print(f"  RBP backlog: {len(backlog)}  (published-since-baseline: {fresh})")
    if oracle["carried_forward"]:
        print(f"  carried forward {oracle['carried_forward']} unverified row(s) "
              f"from the previous snapshot")

    # The covered set has to exist before inference, because inference refuses
    # to name a CNA outside it. It needs only the corpus and the refs, both of
    # which are already in hand.
    cyr = int(today[:4])
    cov = coverage.compute(corpus, refs, recent_years=(cyr - 2, cyr - 1, cyr),
                           sources=sources, own_channels=clock.OWNER_FEEDS)
    cov["profile"] = args.profile if not args.sources else "custom"
    _covered = set(cov.get("covered") or [])
    _sightings = cov.get("sightings") or {}
    print(f"  covered set: {len(_covered)} CNAs sighted, naming gated on it "
          f"(min {coverage.MIN_SIGHTINGS} sightings)")

    # Name what the gate allows, and grade what earlier runs predicted.
    # Which rows will actually be published, decided BEFORE inference so the
    # grader ledger can be scoped to them. days_public depends only on the
    # advisory date, so this needs nothing from inference and avoids annotating
    # twice.
    _published_ids = {
        r["cve_id"] for r in backlog
        if isinstance(clock.age_days(r.get("public_date"), today), int)
        and clock.age_days(r.get("public_date"), today) >= args.min_age_days
        and not clock.before_epoch(r)
    }
    # THE WITHHOLD CHANNEL IS GONE, deliberately, 2026-08-26.
    #
    # It was a monitored GitHub-issue reader, an HMAC-keyed suppression list, a
    # per-author cap, an anomaly threshold and a degraded-run term: about 1,470
    # lines across five modules and six copy surfaces, plus a repository secret
    # and an `issues: read` permission on the publishing job.
    #
    # It existed so a CNA could contest a row that NAMED it. v1 names nobody, and
    # every row here is a CVE ID that is already referenced in a public advisory
    # and has been for at least the reportable buffer. There is nothing to
    # withhold that is not already public, and the machinery cost more than the
    # risk it covered.
    #
    # WHAT REPLACES IT: an email address in /.well-known/security.txt and on
    # /method, read by a person. Zero running cost, no credential, no API call,
    # and no fourth thing that can silently stop working. Launch condition 4 is
    # retired rather than met; see rbp/launch.py.
    if NAMING:
        from . import attribution, inference
        validation = inference.apply_to_backlog(backlog, corpus, PRECISION,
                                                record_for=_published_ids,
                                                covered=_covered, sightings=_sightings,
                                                bulk_reporters=attribution.BULK_REPORTER_NAMES,
                                                today=today, k=args.k)
    else:
        # No inference, no grader, no ledger. MEASURED before removing it: on the
        # live published data the entire stack changed exactly one field,
        # `rule_basis`, whose two values are "inferred-owner" and "unattributed".
        # That is a statement about whether our own machinery succeeded, not
        # about the CVE. All 582 rows were rule 4.5.1.6 / SHOULD, self_disclosed
        # false, owner null, and must_rows was 0.
        validation = _no_attribution_validation(k=args.k)

    # The 72-hour clock, and the MUST/SHOULD split that must ride on every row.
    clock.annotate(backlog, today=today)
    ledger = clock.ResolutionLedger(RESOLUTIONS)
    closed = ledger.reconcile(corpus, today=today)
    _all = clock.summary(backlog, [], today=today)
    print(f"  clock: {_all['past_expectation']}/{_all['total']} past the "
          f"{clock.EXPECTATION_HOURS}h expectation | oldest {_all['oldest_days']}d | "
          f"median {_all['median_days']}d | {_all['clock_unknown']} undated")
    print(f"  rule split: {_all['should_rows']} x 4.5.1.6 (SHOULD), "
          f"{_all['must_rows']} x 4.5.1.4 (MUST, self-disclosed)")
    if closed:
        days = [c["days_to_publish"] for c in closed if isinstance(c["days_to_publish"], int)]
        print(f"  resolved since last run: {len(closed)}"
              + (f", median {clock._median(days)}d to publish" if days else ""))
    else:
        print(f"  resolved since last run: 0 "
              f"({len(ledger.state['open'])} tracked, "
              f"{len(ledger.state['resolved'])} resolved all-time)")

    print(f"  CNA coverage: {cov['covered_cnas']}/{cov['total_cnas']} CNAs "
          f"({cov['pct_cnas']}%); observed {cov['observed_pct']}% of CVEs")
    # One population, computed once, then passed to every writer. Buffer, then
    # epoch, then suppression. report.build no longer derives its own.
    #
    # Suppression belongs HERE and not only inside report.build. It was applied
    # only there, so backlog.json lost the withheld row while clock.summary still
    # counted it, and _assert_consistent refused to publish 521 rows under a
    # headline of 522. That guard did its job: the numbers were contradictory and
    # the build failed closed rather than publishing them. But the cause was this
    # comment's own rule being broken, one writer filtering a population the
    # others did not, which is the fifth time in this project that two stages have
    # disagreed about which rows exist.
    reportable = [r for r in backlog
                  if isinstance(r.get("days_public"), int)
                  and r["days_public"] >= args.min_age_days
                  ]
    reportable, pre_epoch = clock.split_epoch(reportable)
    if pre_epoch:
        oldest = max((r["days_public"] for r in pre_epoch), default=None)
        print(f"  launch epoch {clock.EPOCH}: {len(pre_epoch)} rows held back "
              f"(public before the epoch, oldest {oldest}d), {len(reportable)} counted")
        if not reportable:
            raise SystemExit(
                f"epoch {clock.EPOCH} excludes every reportable row. Refusing to "
                "publish a site that reads 0 with no explanation. Move the epoch "
                "back or unset it.")

    sdir, md, kpi = report.build(backlog, fresh, SNAPS, today, years, sources, cov,
                                 min_age=args.min_age_days, min_conf=args.min_confidence,
                                 rows=reportable)

    # Clock artefacts the site reads directly. Written after report.build so the
    # per-CNA view reflects the same buffered, owner-gated rows the tables show.
    undated = sum(1 for r in backlog if not r.get("clock_known"))
    # Track the PUBLISHED population, not the whole backlog. Tracking everything
    # meant the ledger held 724 open IDs against 553 published rows, so sourcing
    # /changes from it would have closed 171 rows nobody ever counted, 84 of them
    # rows the clock calls unreportable at any buffer.
    ledger.track(reportable)
    ledger.save()
    if len(ledger.state["open"]) != len(reportable):
        print(f"  NOTE: ledger tracks {len(ledger.state['open'])} open vs "
              f"{len(reportable)} published rows (carry-over from earlier runs)")
    # The authoritative closure record for this interval, committed with the
    # snapshot so any diff is recomputable from artefacts rather than from
    # whatever the mutable ledger happens to hold at render time.
    # `published_assigner` joined to first_public / published / days_to_publish
    # is a dated per-CNA lateness table, and 46 of 47 rows carried one. The
    # assigner is authoritative rather than inferred, which makes it a stronger
    # claim than anything the site puts on a page, not a weaker one.
    schema.write_json(os.path.join(sdir, "resolved.json"),
                      [_unattributed_closure(c) for c in closed])
    # THE PER-CNA TABLE, which is a leaderboard when it is not empty.
    #
    # /data/cnas.json was serving seven named CNAs ranked descending by
    # outstanding count, with oldest_days and past_expectation each, on a site
    # that says in bold on every page that it names nobody. It is on
    # ALLOWED_SNAPSHOT, every row key is `cna` rather than `owner`, and
    # publish.check only ever looked for NAME_FIELDS, so the backstop returned
    # clean on it four separate ways.
    #
    # Not written rather than de-named. A de-named per-CNA table is a list of
    # empty rows, and the guard that was supposed to empty it is the one that
    # could not see it in the first place.
    cnas = clock.per_cna(reportable, ledger, corpus, today=today) if NAMING else []
    stats = clock.summary(reportable, cnas, today=today, undated_excluded=undated,
                          epoch_excluded=len(pre_epoch))
    stats["min_age_days"] = args.min_age_days
    # The corroborated subset: rows referenced by two or more INDEPENDENT origins,
    # collapsing feeds that share a source (OSV re-publishes GHSA, ALAS is a RHEL
    # rebuild). Computed by report.build since the beginning, printed to the build
    # log, and published nowhere, so the front page led with the least defensible
    # figure while the more defensible one existed one variable away.
    stats["corroborated"] = len(kpi)
    stats["single_origin"] = stats["total"] - len(kpi)
    stats["inference"] = {
        "k": validation["k"],
        "run_coverage": validation["run_coverage"],
        # `by_cna` and `largest_stratum` are stripped, not summarised.
        #
        # leave_one_out.by_cna was a 40-CNA table of decided / correct / wrong /
        # precision / coverage. That is a per-target operating table for
        # de-anonymising the reserved space, published from the site that argues
        # on /policy that exactly this capability is why a blanket unblinding
        # would be unsafe. The aggregate figures it rolls up to are the warrant
        # and they stay.
        "leave_one_out": _unattributed_stratum(validation["leave_one_out"]),
        "live": _unattributed_stratum(
            {k: v for k, v in validation["live"].items() if k != "misses"}),
    }
    stats["feeds"] = {"requested": sources, "failures": failures, "attempts": attempts,
                      "detail": feeds.health_detail(),
                      "truncated": [k for k, v in feeds.health_detail().items()
                                    if v.get("status") == feeds.TRUNCATED]}
    # The reservation oracle's own health. Previously the tally was printed to a
    # build log and discarded, so `unresolved` and `never_allocated` reached no
    # artefact: a brownout at the endpoint and a quiet week were indistinguishable
    # from outside, and the brownout shrank the headline.
    # A feed can shrink hard without failing or truncating, which is the
    # silent-shrink signature and is invisible to a status field. Compared against
    # the previous snapshot's per-feed id counts.
    _prev_detail = {}
    try:
        _pd = sorted(d for d in glob.glob(os.path.join(SNAPS, "*"))
                     if os.path.isdir(d) and os.path.basename(d) < today)
        if _pd:
            _prev_detail = ((json.load(open(os.path.join(_pd[-1], "summary.json")))
                             .get("feeds") or {}).get("detail") or {})
    except Exception:
        _prev_detail = {}
    shrunk = feeds.compare_magnitudes(_prev_detail, feeds.health_detail())
    if shrunk:
        print("  DEGRADED: a feed returned far fewer ids than last run, without "
              "failing or truncating. This is the silent shrink; the count below "
              "is NOT comparable to the previous run.")
        for line in shrunk:
            print(f"    - {line}")
    stats["feeds"]["shrunk"] = shrunk
    stats["oracle"] = oracle
    stats["corpus_lag_days"] = corpus_lag
    # Counts only, never ids. Publishing which rows are withheld would undo the
    # withholding; publishing nothing would make the lever a quiet way to shrink
    # the count, which is exactly what the site promised it was not.
    # One flag any consumer can branch on, rather than three they have to combine
    # correctly. True whenever this run's count is a lower floor than usual.
    stats["degraded"], stats["degraded_reasons"] = degraded_state(
        failures=failures, truncated=truncated, capped=capped,
        dropped=oracle["dropped"], shrunk=shrunk)
    stats["limitations"] = capped
    # item 14: coverage was computed every run, printed to a build log, and
    # reached no artefact and no template. The launch gate depends on it.
    stats["coverage"] = cov
    stats["generated_at"] = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    # Which code produced this run. Read by every envelope and rendered in the
    # site footer, so a stale artefact identifies itself instead of being
    # mistaken for a defect in whatever is being compared against it.
    stats["source_commit"] = schema.source_commit()
    stats["source_dirty"] = schema.source_dirty()
    stats["min_age_days"] = args.min_age_days
    schema.write_json(os.path.join(sdir, "cnas.json"), cnas)
    schema.write_json(os.path.join(sdir, "summary.json"), stats)
    print("\n" + "=" * 64)
    print(f"HEADLINE core (reportable, >=2 independent sources): {len(kpi)}")
    if NAMING:
        from . import inference
        named = sum(v for k_, v in validation["named"].items()
                    if k_ != inference.TIER_NONE)
        print(f"owner named on {named}/{len(backlog)} rows | "
              f"method precision {inference._pct(validation['leave_one_out']['precision'])} (LOO), "
              f"{inference._pct(validation['live']['precision'])} (live, "
              f"n={validation['live']['graded']})")
    else:
        print(f"owner named on 0/{len(backlog)} rows | inference not run "
              "(v1 publishes no attribution)")
    print(f"snapshot written: {sdir}")
    print("  report.md | backlog.csv | backlog.json")


def build_parser():
    """The argument parser, split out from main() so tests can produce the exact
    namespace cmd_run receives.

    tests/test_cmd_run assembled one by hand first and spent its first run dying
    on missing attributes rather than on anything about the function under test.
    A hand-built namespace is also a namespace that silently stops matching the
    parser: a new flag with no default would be absent in the test and present in
    production, which is the direction that hides a bug rather than showing one.
    """
    ap = argparse.ArgumentParser(prog="rbp")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--years", default="")
    r.add_argument("--profile", choices=list(PROFILES), default="weekly",
                   help="source set: 'weekly' = fast distro/OSS + Mozilla (default); "
                        "'deep' = also CSAF aggregator + Microsoft (heavy, monthly cadence)")
    r.add_argument("--sources", default="",
                   help="explicit comma list, overrides --profile")
    r.add_argument("--today", default="")
    r.add_argument("--workers", type=int, default=classify.DEFAULT_WORKERS,
                   help=f"concurrent reservation lookups (default {classify.DEFAULT_WORKERS}; "
                        "the endpoint allows 25,000/min, so this is ~22%% of the ceiling)")
    r.add_argument("--k", type=int, default=DEFAULT_K,
                   help="published neighbours required on EACH side, all agreeing, "
                        f"before a CNA is named (default {DEFAULT_K}: measured "
                        "100%% precision at 59.8%% coverage out-of-sample)")
    r.add_argument("--min-age-days", type=int, default=report.DEFAULT_MIN_AGE_DAYS,
                   help="only report RBPs provably public >= this many days (default "
                        f"{report.DEFAULT_MIN_AGE_DAYS}, a conservative buffer past the 72h "
                        "expectation so normal latency and short coordination windows are "
                        "excluded). Raise it if CNAs dispute the window; that strengthens "
                        "the remaining rows rather than weakening the project.")
    r.add_argument("--min-confidence", type=float, default=0.7,
                   help=argparse.SUPPRESS)   # superseded by the --k block-inference gate
    r.add_argument("--cache-ttl-days", type=int, default=6,
                   help=argparse.SUPPRESS)   # RESERVED is now re-verified every run
    r.add_argument("--reindex", action="store_true")
    r.set_defaults(func=cmd_run)
    b = sub.add_parser("build", help="render the static site from the newest snapshot")
    b.add_argument("--out", default="site")
    b.set_defaults(func=cmd_build)
    i = sub.add_parser("index")
    i.set_defaults(func=cmd_index)
    return ap


def main():
    args = build_parser().parse_args()
    args.func(args)


if __name__ == "__main__":
    main()

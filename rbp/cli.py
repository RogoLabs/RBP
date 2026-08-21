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
import json
import os

from . import cvelist, feeds, classify, report, attribution, coverage, inference, clock, site

# Source profiles: the weekly cron stays lean; the heavy enterprise/ICS sources
# (CSAF aggregator + Microsoft) move to a deeper monthly cadence.
PROFILES = {
    "weekly": "alas,ubuntu,debian,ghsa,redhat,alpine,osv,mozilla,arch",
    "deep": "alas,ubuntu,debian,ghsa,redhat,alpine,osv,mozilla,arch,csaf,msrc",
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


def ensure_corpus(force=False):
    """Bring the corpus current. Cheap within a day, cheap across a few days,
    and only re-pulls the 583 MB baseline when the delta chain cannot cover the
    gap. See cvelist.refresh_corpus."""
    return cvelist.refresh_corpus(BASELINE, INDEX, force=force)


def cmd_build(args):
    site.build(args.out, SNAPS, DATA)


def cmd_index(args):
    ensure_corpus(force=True)


def cmd_run(args):
    today = args.today or dt.date.today().isoformat()
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
    print(f"RBP run | today={today} | years={sorted(years)} | profile={args.profile if not args.sources else 'custom'} | sources={sources}")

    corpus, prod_cna = ensure_corpus(force=args.reindex)
    print(f"corpus: {len(corpus):,} records | product->CNA: {len(prod_cna):,}")

    refs = feeds.gather(sources, years)
    print(f"  total unique referenced IDs: {len(refs)}")

    # A feed that fails must never read as an improvement. Counts are a floor,
    # so a silent shrink looks like progress; this is the failure mode most
    # likely to actually happen (PLAN.md R4). The OSV npm ecosystem was dropped
    # from every run for exactly this reason before it was caught.
    failures, attempts = feeds.health_summary()
    if failures:
        print(f"  DEGRADED: {len(failures)} of {attempts} feed fetches failed. "
              f"This run's counts are a lower floor than usual and are NOT "
              f"comparable to the previous run.")
        for f in failures:
            print(f"    - {f}")

    attributor = attribution.Attributor(corpus)
    backlog, fresh = classify.classify(refs, corpus, attributor, CACHE, workers=args.workers,
                                       today=today, ttl=args.cache_ttl_days)
    print(f"  RBP backlog: {len(backlog)}  (published-since-baseline: {fresh})")

    # Name what the gate allows, and grade what earlier runs predicted.
    validation = inference.apply_to_backlog(backlog, corpus, PRECISION,
                                            today=today, k=args.k)

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

    cyr = int(today[:4])
    cov = coverage.compute(corpus, refs, recent_years=(cyr - 2, cyr - 1, cyr))
    print(f"  CNA coverage: {cov['covered_cnas']}/{cov['total_cnas']} CNAs "
          f"({cov['pct_cnas']}%); observed {cov['observed_pct']}% of CVEs")
    # One population, computed once, then passed to every writer. Buffer, then
    # epoch. report.build no longer derives its own.
    reportable = [r for r in backlog
                  if isinstance(r.get("days_public"), int)
                  and r["days_public"] >= args.min_age_days]
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
    json.dump(closed, open(os.path.join(sdir, "resolved.json"), "w"), indent=1)
    cnas = clock.per_cna(reportable, ledger, corpus, today=today)
    stats = clock.summary(reportable, cnas, today=today, undated_excluded=undated,
                          epoch_excluded=len(pre_epoch))
    stats["min_age_days"] = args.min_age_days
    stats["inference"] = {
        "k": validation["k"],
        "run_coverage": validation["run_coverage"],
        "leave_one_out": validation["leave_one_out"],
        "live": {k: v for k, v in validation["live"].items() if k != "misses"},
    }
    stats["feeds"] = {"requested": sources, "failures": failures, "attempts": attempts,
                      "detail": feeds.health_detail(),
                      "truncated": [k for k, v in feeds.health_detail().items()
                                    if v.get("status") == feeds.TRUNCATED]}
    # item 14: coverage was computed every run, printed to a build log, and
    # reached no artefact and no template. The launch gate depends on it.
    stats["coverage"] = cov
    stats["generated_at"] = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    stats["min_age_days"] = args.min_age_days
    json.dump(cnas, open(os.path.join(sdir, "cnas.json"), "w"), indent=1)
    json.dump(stats, open(os.path.join(sdir, "summary.json"), "w"), indent=1)
    print("\n" + "=" * 64)
    print(f"HEADLINE core (reportable, >=2 independent sources): {len(kpi)}")
    named = sum(v for k_, v in validation["named"].items() if k_ != inference.TIER_NONE)
    print(f"owner named on {named}/{len(backlog)} rows | "
          f"method precision {inference._pct(validation['leave_one_out']['precision'])} (LOO), "
          f"{inference._pct(validation['live']['precision'])} (live, "
          f"n={validation['live']['graded']})")
    print(f"snapshot written: {sdir}")
    print("  report.md | backlog.csv | backlog.json")


def main():
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
    r.add_argument("--k", type=int, default=inference.DEFAULT_K,
                   help="published neighbours required on EACH side, all agreeing, "
                        f"before a CNA is named (default {inference.DEFAULT_K}: measured "
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
    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()

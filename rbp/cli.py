"""
RBP-CVEs weekly runner — 100% standalone.

    python -m rbp.cli run                      # full pipeline (current+prior year, all feeds)
    python -m rbp.cli run --years 2026 --sources alas,ubuntu,debian,ghsa
    python -m rbp.cli index                    # (re)build the corpus index only

Pipeline: ensure corpus (download baseline + index) -> gather feeds -> classify
against the corpus + reservation endpoint -> infer + grade owner -> write snapshot + WoW diff.
"""
from __future__ import annotations

import argparse
import datetime as dt
import os

from . import cvelist, feeds, classify, report, attribution, coverage, inference

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
BASELINE = os.path.join(DATA, "all_CVEs.zip.zip")


def ensure_corpus(force=False):
    os.makedirs(INDEX, exist_ok=True)
    if force or not os.path.exists(os.path.join(INDEX, "corpus.parquet")):
        cvelist.download_baseline(BASELINE)
        print("indexing corpus (one pass)...")
        cvelist.build_index(BASELINE, INDEX)
    return cvelist.load_index(INDEX)


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

    attributor = attribution.Attributor(corpus)
    backlog, fresh = classify.classify(refs, corpus, attributor, CACHE, workers=args.workers,
                                       today=today, ttl=args.cache_ttl_days)
    print(f"  RBP backlog: {len(backlog)}  (published-since-baseline: {fresh})")

    # Name what the gate allows, and grade what earlier runs predicted.
    validation = inference.apply_to_backlog(backlog, corpus, PRECISION,
                                            today=today, k=args.k)

    cyr = int(today[:4])
    cov = coverage.compute(corpus, refs, recent_years=(cyr - 2, cyr - 1, cyr))
    print(f"  CNA coverage: {cov['covered_cnas']}/{cov['total_cnas']} CNAs "
          f"({cov['pct_cnas']}%); observed {cov['observed_pct']}% of CVEs")
    sdir, md, kpi = report.build(backlog, fresh, SNAPS, today, years, sources, cov,
                                 min_age=args.min_age_days, min_conf=args.min_confidence)
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
                        "'deep' = also CSAF aggregator + Microsoft (heavy — monthly cadence)")
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
    r.add_argument("--min-age-days", type=int, default=14,
                   help="only report RBPs provably public >= this many days (default 14; "
                        "a conservative buffer well past the 72h publish rule, so normal "
                        "latency and short coordination windows are excluded)")
    r.add_argument("--min-confidence", type=float, default=0.7,
                   help=argparse.SUPPRESS)   # superseded by the --k block-inference gate
    r.add_argument("--cache-ttl-days", type=int, default=6,
                   help=argparse.SUPPRESS)   # RESERVED is now re-verified every run
    r.add_argument("--reindex", action="store_true")
    r.set_defaults(func=cmd_run)
    i = sub.add_parser("index")
    i.set_defaults(func=cmd_index)
    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()

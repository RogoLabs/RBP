# Feed scorecards

Written by `python -m rbp.feedlab`. FEEDS.md section 3: **no feed is merged
without its scorecard in the diff.**

This directory is committed. The baseline's working state, which holds every
referenced id from every merged feed, is not: it lives in `data/feedlab/` and is
gitignored along with the rest of `data/`.

| file | what it is |
|---|---|
| `_baseline.json` | the merged set the marginal figures are marginal to: which feeds, when, how many ids each, how long, how many roster CNAs it reaches |
| `_audit.json` | every merged feed scored against all the others, with its verdict |
| `<feed>.json` | one feed's full scorecard |
| `_csaf_probe.json` | `.well-known/csaf/` probe results, per CNA |

## The two admissibility tests

FEEDS.md section 2. A candidate is merged only if it clears both.

1. **Marginal CNA yield >= 1.** At least one roster CNA crosses the 3-sighting
   floor that no already-merged feed crosses. `cnas_new_effective`.
2. **Disclosure lead > 0.** At least one referenced ID was, at the time of
   reference, not yet published. `disclosure.lead_n` or
   `disclosure.unpublished_n`.

A feed that clears (1) and fails (2) is **corroborating**: mergeable, and
excluded from the coverage numerator. It can strengthen a row it did not find; it
cannot credit a CNA as observable. Crediting a CNA on a feed that is structurally
incapable of surfacing an unpublished ID is how a launch gate clears while the
site's actual claim gets weaker.

## Running it

```
python -m rbp.feedlab baseline                 # ~26 min, all merged feeds
python -m rbp.feedlab audit                    # offline, from that baseline
python -m rbp.feedlab score <name>             # one candidate, live
python -m rbp.feedlab near-floor               # offline, from the last snapshot
python -m rbp.feedlab probe-csaf --cnas a,b,c  # .well-known/csaf sweep
```

`near-floor` lists roster CNAs that are SIGHTED and short of the sighting floor,
which is a different kind of miss from never having been seen and a much cheaper
one. On 2026-08-27 three of the eight top-50 misses (`dell`, `TR-CERT`, `sap`)
had exactly one sighting against a floor of three, and twelve further roster CNAs
were one sighting short. The set was always derivable, as the difference between
the published `top_missed_effective` and `top_missed` lists, and was never
derived. Add `--top-only` for just the top-50 ones.

Note that FEEDS.md section 4 sequences the tail by VOLUME descending, on the
grounds that volume maximises the chance of finding a real RBP. These two
orderings disagree, and which one wins is a decision rather than a measurement.

`baseline` is the only command that fetches the whole merged set. `audit` and
re-scoring are offline, so changing the floor or rebuilding the corpus does not
put twelve more fetches on twelve third parties.

## What a number here is not

`stability` is null until a feed has been fetched at least twice, and FEEDS.md
asks for three fetches 24 hours apart. A single invocation cannot produce that
number, and returning one anyway is how a scorecard field becomes decoration.

It WAS decoration on every merged feed until 2026-08-27, and for a reason worth
recording: only `score` called `record_fetch`, and every merged feed had been
scored by `audit`, which is offline by design. Observations now accrue in
`baseline`, the only command that really fetches every feed, and `audit` reads
that history without appending to it. The distinction is the fix: appending in
`audit` would replay one baseline's stored rows N times and report a 0% swing
over N "fetches" that were a single fetch. A fabricated perfect reading is worse
than null, because null says "not measured" and 0% says "measured, and perfect".

So it fills in over successive baseline rebuilds, 24 hours apart or more, which
is what section 3 asked for in the first place.

`disclosure.lead_n` is a backtest against today's corpus, not a record of what
was knowable at the time. An ID referenced while reserved and published an hour
later scores a lead of 0 days and reads as a mirror. It therefore understates
lead, which is the safe direction: it can refuse a good feed, and it cannot admit
a mirror.

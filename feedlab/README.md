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
python -m rbp.feedlab baseline                 # ~20 min, all merged feeds
python -m rbp.feedlab audit                    # offline, from that baseline
python -m rbp.feedlab score <name>             # one candidate, live
python -m rbp.feedlab probe-csaf --cnas a,b,c  # .well-known/csaf sweep
```

`baseline` is the only command that fetches the whole merged set. `audit` and
re-scoring are offline, so changing the floor or rebuilding the corpus does not
put twelve more fetches on twelve third parties.

## What a number here is not

`stability` is null until a feed has been fetched at least twice, and FEEDS.md
asks for three fetches 24 hours apart. A single invocation cannot produce that
number, and returning one anyway is how a scorecard field becomes decoration.

`disclosure.lead_n` is a backtest against today's corpus, not a record of what
was knowable at the time. An ID referenced while reserved and published an hour
later scores a lead of 0 days and reads as a mirror. It therefore understates
lead, which is the safe direction: it can refuse a good feed, and it cannot admit
a mirror.

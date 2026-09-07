# Feed scorecards

Written by `python -m rbp.feedlab`. FEEDS.md section 3: **no feed is merged
without its scorecard in the diff.**

This directory is committed. The baseline's working state, which holds every
referenced id from every merged feed, is not: it lives in `data/feedlab/` and is
gitignored along with the rest of `data/`.

| file | what it is |
|---|---|
| `_baseline.json` | the merged set the marginal figures are marginal to: which feeds, when, how many ids each, how long, how many roster CNAs it reaches, and how deep its `csaf` read marks were |
| `_live.json` | the live run's own published profile, pinned: per-CNA sightings, rows per feed, and the commit that produced them |
| `_audit.json` | every merged feed scored against all the others, with its verdict |
| `<feed>.json` | one feed's full scorecard |
| `_csaf_probe.json` | `.well-known/csaf/` probe results, per CNA |

## The two admissibility tests

FEEDS.md section 2. A candidate is merged only if it clears both.

1. **Marginal CNA yield >= 1.** At least one roster CNA crosses the 3-sighting
   floor that no already-merged feed crosses. `live.cnas_new_effective` when
   there is a pinned live run, `cnas_new_effective` when there is not. See
   "what a candidate is marginal to" below: they are different sets, and on
   2026-09-06 they differed by 16 effective CNAs.
2. **Disclosure lead > 0.** At least one referenced ID was, at the time of
   reference, not yet published. `disclosure.lead_n` or
   `disclosure.unpublished_n`.

A feed that clears (1) and fails (2) is **corroborating**: mergeable, and
excluded from the coverage numerator. It can strengthen a row it did not find; it
cannot credit a CNA as observable. Crediting a CNA on a feed that is structurally
incapable of surfacing an unpublished ID is how a launch gate clears while the
site's actual claim gets weaker.

**A feed that fails (1) and clears (2) is `redundant`, and that is a different
verdict.** It is mergeable and it STAYS IN THE NUMERATOR, because it can surface
an unpublished id; it just reaches no CNA the others do not. Both used to be
spelled `corroborating`, and `corroborating_feeds` reads the verdict string, so
`mozilla`, `samsung` and `ubuntu` were all in the live run's published exclusion
list on 2026-09-06 with lead references apiece and not a mirror among them. This
document had already recorded the right answer for `mozilla`, in FEEDS.md's
2026-08-24 audit: "it clears admissibility test 2, so it stays in the numerator."
Correcting it moves the published figure by zero CNAs, because there is no
publication mirror in the profile and the exclusion set is now empty.

The five verdicts: `detecting`, `redundant`, `corroborating`, `unmeasurable`,
`reject`. **Only `corroborating` leaves the coverage numerator.** `unmeasurable`
does not, because a feed nobody could measure is not a proven mirror.

## What a candidate is marginal to

Two sets, and they are not the same size.

`_baseline.json` is what THIS MACHINE reached. `_live.json` is what the SITE
reached, pinned from `https://rbptracker.org/data/summary.json`, which publishes
per-CNA sightings and rows per feed four times a day. On 2026-09-06 the local
baseline was 20,141 `csaf` rows and 16 effective roster CNAs short of the live
run, on the same fifteen feeds, the same window and the same commit: `deploy.yml`
caches `data/csaf_state.json` across runs and a provider emits everything it has
ever seen, so the live state is as deep as every run before it and a local state
is as deep as the runs that happened locally. Three providers here are 125,588
advisories behind.

Neither half is broken and the consequence is one-directional: **a candidate
scored against the local baseline alone looks better than it is**, because the
CNAs the site already covers are missing from the set it is supposed to be
marginal to. Thirteen roster CNAs sat below the floor locally and were already
effective live, and three more were not sighted here at all: 247 effective
against 263, and the local set is a strict subset of the live one.

So every card carries both figures. `cnas_new_effective` is marginal to this
machine; `live.cnas_new_effective` is marginal to the site, and it decides the
verdict when it exists. `live.rows_short` says how much colder this machine was
when the card was written, and `live.upper_bound` says the live figure is still a
ceiling: only counts are published, not ids, so the candidate's overlap with the
LOCAL baseline can be removed exactly and its overlap with the live-only ids
cannot. That residue shrinks as the local state drains and is bounded by
`rows_short`.

Re-pin before believing a card: `python -m rbp.feedlab pin-live`. The pin is a
committed file with a visible diff, like `roster_data/cna_roster.json`, and
`test_the_pinned_live_run_is_not_stale` fails at 14 days.

**Sightings combine by the UNION OF IDS, never by adding the counts.** A sighting
is a published CVE the site saw, and `coverage.compute` counts distinct ids, so
two feeds referencing one CVE are one sighting. Summing per-CNA counts credited a
feed for re-referencing what the merged set already had, which is exactly the
mirror test 1 exists to refuse: ten of the fifteen committed cards carried
marginal CNAs no id had earned (`alas` 2 -> 0, `debian` 4 -> 0, `ubuntu-osv`
4 -> 0, `ghsa` 3 -> 0, `alpine` 1 -> 0, `osv` 5 -> 1, `redhat` 6 -> 3, `csaf`
84 -> 80). `combine` on each card records which arithmetic produced it.

## Running it

```
python -m rbp.feedlab pin-live                 # one fetch of the site's own summary
python -m rbp.feedlab baseline                 # ~26 min, all merged feeds
python -m rbp.feedlab baseline --rescore       # offline, re-derive against today's corpus
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

The 24 hours is now enforced rather than only asked for, and so is a second
condition FEEDS.md did not think to state: the fetches must have read the SAME
WINDOW. Both were violated on committed cards. Ten of the fifteen carried a 0.0%
swing measured four hours apart, `jvn`'s two fetches were thirty minutes apart in
one session, and the day the gather window went from two years to four every
feed's next reading would have been a 20-50% swing that was the window moving and
not the feed. `csaf` had already shown that shape one level down: its 29.3% is
sixteen CSAF providers against eighteen, recorded before there was anywhere to
say so. So each fetch now records the window it read, `stability` compares only
fetches of the newest one, and it reports null until two of those are a day
apart.

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

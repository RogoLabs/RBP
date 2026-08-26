# Feed expansion plan

How the feed inventory grows from 9 sources to whatever the ceiling turns out to be, and
what the coverage number is allowed to mean while it happens.

Drafted 2026-08-22. Sections 0, 1, 4 (Tiers 0 and 1) and the top of section 5 were
measured against the pinned roster (539 CNAs, fetched 2026-08-22) and the local corpus
(381,619 records), with `msrc`, `csaf`, `arch`, `mozilla` and all 46 OSV ecosystems fetched
live. Tier 2 and Tier 3 are estimates and are labelled as such in every table. One estimate
has already been checked and cancelled outright, which is section 4's argument for checking
the rest before writing any of it.

---

## 0. The ask, and the correction it needs

The instruction was "50% is the minimum, get as close to 100% as possible." The second
half of that is not reachable, and the reason is arithmetic rather than effort. This
section is the correction. The rest of the document is the plan under the corrected
target, and the corrected target is still ambitious.

There are **two** ceilings, they bracket the problem from opposite sides, and the 50% gate
sits between them. Both are measured against the live `origin/data` run of 2026-08-23
(`cnas_effective` 117, `cnas_sighted` 152, roster 539).

**Ceiling A, the current feed set: 28.2%.** If every CNA the nine feeds sight even once
were promoted to 3-plus sightings, `cnas_effective` would be 152, which is 28.2% of the
roster. **No amount of tuning reaches the gate.** The 50% threshold cannot be cleared
without new feeds, and clearing it needs ~118 CNAs the current feeds see zero published
CVEs from. This bound is the panel's, and it is the one that says the plan is necessary.

**Ceiling B, any feed set: 68.8%.** Derived below. This is the one that says the plan has
an end.

The band is therefore **28.2% to 68.8%**.

> **The gate moved on 2026-08-23, after this section was written.** The 50%-of-roster
> threshold was retired precisely because of the two ceilings above: it was never
> re-derived when the metric changed underneath it, and it sat 21.8 points above what the
> current feed set can reach. The gate is now **top-50-CNAs-by-volume at 80%, on the same
> 3-sighting floor**, with no roster-share floor beside it. Both ceilings still bound the
> roster share, which is still measured and published; it just no longer gates anything.
> Sections 4 and 5 are written against the new gate. Section 6 records the re-derivation.

**`cnas_effective` cannot exceed 68.8% of the roster.** The gate figure counts roster
CNAs for which at least `MIN_SIGHTINGS` (3) of their **published** CVEs were surfaced by
our feeds inside the rolling window. A CNA that has not published three CVEs in the
window cannot be counted no matter how many feeds we read, because there is nothing to
sight.

| bound | roster CNAs reaching >= 3 published | % of 539 |
|---|---:|---:|
| window 2024-2026 (what the site uses) | 371 | **68.8%** |
| window 2022-2026 | 384 | 71.2% |
| window 2020-2026 | 390 | 72.4% |
| unbounded window, every CVE ever | 392 | **72.7%** |

128 roster CNAs published nothing at all in the current window. 147 have never published
three CVEs under any assigner string that matches their roster short name. A perfect
omniscient feed inventory scores 68.8%, and widening the window to the beginning of the
CVE Program buys 3.9 points and costs the window its meaning.

So the honest formulation of the goal is:

> **Target: 100% of the reachable set, which is 68.8% of the roster.**
> Publish both numbers, always together, with the ceiling named.

Everything below is measured against **371**, not 539. Current position is **117 of 371
reachable, 31.5%**, which is the same fact as 21.7% of the roster.

On the gate's own metric the position is **31 of the top 50 by volume, 62%**, needing 40.

**Do not respond to the ceiling by moving the denominator.** Lowering `MIN_SIGHTINGS`
raises coverage on paper, and it is the same constant inference uses to decide whether it
is willing to attach a CNA's name to a row. It was deliberately made the same constant.
Loosening it to clear a gate would mean the site starts naming CNAs it has seen twice, to
make a coverage number look better. That is the single change this plan forbids outright.

---

## 1. Where the missing coverage actually is

254 reachable CNAs are currently unsighted. Their volume distribution is the whole story
of what this project costs:

| published CVEs in window | reachable CNAs | still missing | missing share |
|---|---:|---:|---:|
| 1,000+ | 17 | 2 | 12% |
| 200 to 999 | 44 | 21 | 48% |
| 50 to 199 | 85 | 45 | 53% |
| 10 to 49 | 132 | 106 | 80% |
| 3 to 9 | 93 | 80 | 86% |

The missing CNAs hold 24.5% of window volume between them. **186 of the 254 published
fewer than 50 CVEs in three years.** There is no aggregate feed that carries them. Each
one is a vendor with its own advisory page, or a national CERT, and each one is a
separately written, separately maintained parser that buys exactly one CNA.

The 20 largest missing CNAs, which is where the first half of the work is:

```
14,264 Patchstack      552 Samsung_Mobile   420 twcert       299 juniper
 1,961 WPScan          531 qualcomm         418 MediaTek     285 Google_Devices
   715 dell            531 google_android   366 CERTVDE      281 hpe
   597 siemens         526 TR-CERT          364 fortinet     276 JetBrains
                       508 sap              356 HCL          206 autodesk
                       444 huawei           337 qnap         206 ProgressSoftware
```

Note `siemens`: it is already a configured CSAF provider. It is missing because **`csaf`
and `msrc` are in the `deep` profile and the gate measures the `weekly` profile**, which
is nine feeds. Some of the gap is not missing code at all.

---

## 2. The rule that has to come before any new feed

A feed can raise coverage while being structurally incapable of finding a single RBP.

Coverage counts sightings of **published** CVEs. RBP detection needs a public reference to
an ID that has **no published record**. A feed that only ever lists CVEs after they are
published, an NVD mirror, a vendor page that links out to cve.org, an aggregator that keys
off published records, credits its CNAs on the coverage number and can never surface the
thing the site exists to publish. Adding feeds to hit 50% without this rule is a way to
pass the launch gate while making the site's actual claim weaker.

The same divergence shows up on the other side. `msrc` was run live on 2026-08-22: **10,516
referenced IDs, and exactly one new CNA** (`google_android`). Microsoft's own output is
already sighted through other feeds many times over. Volume is not yield, in either
direction.

This is not hypothetical. In the 2026-08-20 snapshot, per-feed RBP yield was:

```
feed      RBP rows   sole-source rows
osv          411          42
ghsa         371           5
debian       230          36
ubuntu       113           0
alpine        81          23
alas          71           0
redhat        62          10
mozilla        0           0
arch           0           0
```

`mozilla` and `arch` are in the profile the gate is measured on. They contribute to
coverage and have produced no RBP row. They may be doing useful corroboration work, and
`arch` is cheap, so this is not an argument to remove them. It is proof that the two
properties come apart, and that nothing currently measures the difference.

**Admissibility test. A candidate feed is merged only if it clears both:**

1. **Marginal CNA yield >= 1.** At least one roster CNA crosses 3 sightings that no
   already-merged feed crosses. Measured, not argued.
2. **Disclosure lead > 0.** At least one referenced ID in a 90-day backtest was, at the
   time of reference, either absent from the corpus or in RESERVED state. A feed that has
   never referenced an unpublished ID is a publication mirror.

A feed that clears (1) and fails (2) may still be merged, and is then **tagged
`corroborating` and excluded from the coverage numerator**. It can strengthen a row it did
not find. It cannot credit a CNA as observable.

This means `coverage.compute` grows a source filter, and `cnas_effective` is computed over
detecting feeds only. **The cost of that honesty was measured, and it is close to zero.**
`arch` and `mozilla` were fetched live on 2026-08-22: 62 and 607 IDs, reaching 11 roster
CNAs at 3 or more sightings between them (`GitHub_M`, `Go`, `apache`, `apple`, `curl`,
`hackerone`, `isc`, `mitre`, `mozilla`, `redhat`, `suse`). Ten of those eleven are covered
several times over by `debian`, `ubuntu`, `osv` and `ghsa`, so the realistic drop is
**0 to 1 CNA**, not the material fall an earlier draft of this section assumed.

That makes the split cheap to do and therefore inexcusable to defer. It ships before the
expansion, so the expansion is never measured against a base that flattered it.

> ### MEASURED 2026-08-24. Every merged feed, scored against all the others.
>
> `python -m rbp.feedlab audit`, offline against the corpus and the recorded baseline
> (32,704 ids, 12 feeds, 137 effective roster CNAs). Full scorecards in `feedlab/`.
>
> | feed | verdict | marginal CNAs | lead refs | unpublished now |
> |---|---|---:|---:|---:|
> | osv | detecting | 19 | 4,762 | 460 |
> | csaf | detecting | 11 | 582 | 171 |
> | debian | detecting | 9 | 0 | 401 |
> | redhat | detecting | 3 | 1,515 | 103 |
> | ubuntu | detecting | 3 | 22 | 113 |
> | msrc | detecting | 2 | 4,677 | 3 |
> | alas | detecting | 1 | 393 | 75 |
> | alpine | detecting | 1 | 0 | 107 |
> | ghsa | detecting | 1 | 1,364 | 371 |
> | samsung | detecting | 1 | 260 | 76 |
> | mozilla | **corroborating** | 0 | 34 | 0 |
> | arch | **unmeasurable** | 0 | 0 of 0 dated | 0 |
>
> Marginal figures are each measured against ALL THE OTHERS, so they do not sum: two feeds
> that uniquely cover the same CNA each score 0.
>
> **The answer to this section's open question: the split would exclude nothing, and the
> numerator would fall by zero CNAs.** The estimate above was "0 to 1", from an argument
> about which feeds cover which CNAs. Measured, it is 0, and for a better reason than the
> argument gave: no merged feed is a proven publication mirror.
>
> `mozilla` is corroborating rather than mirroring. It adds no marginal CNA, and it has
> referenced 34 ids ahead of their publication, median 6 days. It can strengthen a row it
> did not find, and it clears admissibility test 2, so it stays in the numerator.
>
> **`arch` is unmeasurable, and getting that wrong was this harness's own first defect.**
> It returns 62 references and dates none of them, so its historical lead is 0 out of 0.
> The classifier read that as "no disclosure lead" and returned `reject`, which is a claim
> the data cannot support: the same "cannot read is not nothing to read" error that
> `feeds.record_feed` and `inference.summarise_state` both exist to avoid, committed by the
> tool built to police it. A feed nobody has measured is not a proven mirror, and excluding
> it would lower a launch gate on the strength of a missing date field. Fixed, and
> `tests/test_feedlab.py` asserts the distinction in both directions.
>
> Note what the table also shows: `debian` and `alpine` date nothing either, and both clear
> test 2 only on `unpublished_n`. The distro trackers are the shape this measure is weakest
> on, and the site's largest single source of rows is one of them.

---

## 3. The harness, which is built before the second feed

Thirty new adapters written by hand and merged on judgement is how this project acquires
thirty silent failure modes. The feed count is going up by roughly 4x; the per-feed
guarantees have to get stronger, not weaker, or the one error the site cannot tolerate
(a feed quietly shrinking to nothing while the build reports success) becomes 4x more
likely to be somewhere nobody is looking.

**`rbp/feedlab.py`, a scoring harness. One command, one candidate, one verdict.**

```
python -m rbp.feedlab score <name> --years 2025,2026
```

emits, for a single candidate, against the live corpus and the current merged set:

| field | why it is there |
|---|---|
| `ids` | referenced IDs in scope |
| `cnas_new_effective` | roster CNAs crossing 3 sightings that nothing else covers. **The number that justifies the merge.** |
| `rbp_rows`, `rbp_sole_source` | did it find anything, and anything nobody else found |
| `disclosure_lead_n`, `disclosure_lead_pct` | admissibility test 2 |
| `wall_seconds`, `bytes` | against the 15-minute warm-run budget |
| `stability` | ids on 3 fetches 24h apart; a feed whose count swings 40% on its own has no usable shrink baseline |

The harness writes `feedlab/<name>.json`, and the merge commit includes it. **No feed
is merged without its scorecard in the diff.** That is the artefact that makes this plan
auditable from outside, in the same way the launch checklist is.

> **BUILT 2026-08-24, and the path above is a correction.** This section said
> `data/feedlab/<name>.json`. `.gitignore` line 3 is `data/`, because the 583 MB corpus
> lives there, so a scorecard written under `data/` could never appear in any diff and the
> rule it exists to enforce would have been decorative from the day it was written. The
> scorecards are in `feedlab/`, which is committed; the baseline's working state, which
> holds every referenced id from every merged feed, stays under `data/` and stays ignored.
> `tests/test_feedlab.py` asserts both directions with `git check-ignore`, so the split
> cannot silently invert.
>
> Two fields are honest about their own limits rather than reported as measurements.
> `stability` is null until a feed has been fetched at least twice, because one invocation
> cannot produce "ids on 3 fetches 24h apart" and returning a number anyway is how a
> scorecard field becomes decoration. And `disclosure_lead` is a backtest against today's
> corpus: an id referenced while reserved and published an hour later scores 0 and reads as
> a mirror, so the measure UNDERSTATES lead. That is the safe direction. It can refuse a
> good feed; it cannot admit a mirror.

**Three guards that must exist before feed 10, not after feed 30:**

- **Per-feed shrink baselines survive the profile change.** `compare_magnitudes` compares
  a feed's row count to its own previous run. Adding feeds to the weekly profile creates
  N feeds with no baseline, and the function skips any feed whose previous count is
  missing. Ten new feeds means ten feeds silently exempt from the shrink guard on their
  first run and, if one of them fails on run one, exempt forever, because `was <= 0` also
  skips. Fix: a new feed's first successful run seeds its baseline from the scorecard, and
  a feed with no baseline after two runs is a build warning.
- **A failure budget, expressed as a fraction.** Today one feed failing is visible.
  With 40 feeds, three failing is a rounding error in the log and a real hole in coverage.
  The gate must fail if **any detecting feed that contributed to the last published
  `cnas_effective` is FAILED this run**, because that is coverage silently dropping below
  the gate the site is publishing against.
- **Runtime.** Warm run is 9 minutes against a 15-minute target and a 6-hour hard limit.
  Feeds are independent; `gather` is a serial `for` loop. Parallelising it is a
  prerequisite for the count going past ~15, and it must preserve per-feed health
  recording exactly as it is, because that recording is the shrink guard's input.

> **Two silent-shrink defects were found by building the harness, and both are fixed.**
> Neither is in the list above, and both are the same shape as the ones that are: a state
> an adapter recorded and something else discarded.
>
> **`gather` erased every cap in the same call that recorded it.** It re-stamped any feed
> whose status was not in `(TRUNCATED, FAILED)`, and `CAPPED` was missing from that tuple.
> `feed_ghsa` records `CAPPED` when it runs out of pages rather than out of data, and the
> caller overwrote it with `ok` on every run, so `health_summary`'s `capped` list could
> never be non-empty and `stats["limitations"]`, the field the site publishes to say which
> feeds are read over a shorter window than the trackers, was permanently empty. The live
> 2026-08-20 snapshot reads `ghsa ok 3321 ids`. Two tests already asserted that GHSA
> records its cap, and both passed throughout, because both call the adapter directly and
> the pipeline never does.
>
> **`feed_csaf` recorded no health at all**, on the one adapter that fans out to more than
> a dozen third parties. A provider answering 401 on every advisory, a provider behind a
> WAF returning 403, and a provider whose 121 directories were cut to 12 all reported
> identically to a clean read, because `gather` filled in `ok, N ids` from the providers
> that did work. It now records unreachable providers, capped directory listings and
> providers that yielded nothing, named, every run. That last one is the standing version
> of this document's own note that "the provider list has never been validated against what
> it actually yields".

> ### MEASURED 2026-08-26. The GHSA cap, and the rows no cap could have reached.
>
> The recorded cap above was correct and understated. `feed_ghsa` read the newest 4,000
> reviewed advisories in one descending scan, which is **83 days** (2026-05-18 to 08-26).
> 9,512 reviewed advisories were published between 2026-01-01 and 08-26, so the scan
> covered **42% of the year it reported on**, at a roughly constant count every run, which
> is the shape `compare_magnitudes` reads as healthy.
>
> It now walks one publication month per shard, from January of the earliest requested year
> to today. Measured reviewed volume per month in 2026:
>
> | Jan | Feb | Mar | Apr | May | Jun | Jul |
> |---:|---:|---:|---:|---:|---:|---:|
> | 491 | 765 | 1,639 | 1,583 | 1,701 | 1,494 | 1,278 |
>
> The worst month is 18 pages against a 40-page shard cap, so the cap became headroom, and
> a month that does exceed it is named in the health record rather than folded into one
> whole-feed count.
>
> **`type=reviewed` is now explicit, and the reason is a trap rather than a preference.**
> The endpoint's default population depends on whether `published` is present, which is
> undocumented and was measured:
>
> | request | population returned |
> |---|---|
> | `sort=published&direction=desc` | 100% reviewed |
> | the same plus `published=<range>` | 94% unreviewed |
>
> So the shard window that fixes the cap widens the population by itself. Over the 83-day
> window the old scan covered: 3,323 reviewed rows against 22,571 unreviewed, a sevenfold
> read for advisories that cannot be RBP by construction, since unreviewed advisories are
> GitHub's imports of already-PUBLISHED CVE records. All 371 rows `ghsa` contributed to the
> 2026-08-20 snapshot are reviewed and none are unreviewed.
>
> **`ghsa-repos` is a new feed, because raising the cap reaches none of what follows.** A
> repository advisory with no package ecosystem never enters `github/advisory-database`, so
> `GET /advisories` cannot return it at any cap, in any window, with any `type`. Measured
> against the 2026-08-20 snapshot: the 1,875 watchlisted repos yielded **1,030 CVE ids
> absent from the backlog entirely, 1,018 of them RESERVED** at the reservation oracle the
> same day. A 150-id sample of those was probed against the global endpoint and **150 of
> 150 were absent from it**. One worked example, so the claim is checkable rather than
> statistical: CVE-2026-12521 is public as `zephyrproject-rtos/zephyr`
> GHSA-g5v9-xmfp-7gxm with a full technical writeup, 404 at `/advisories/GHSA-g5v9-xmfp-7gxm`,
> and RESERVED at MITRE.
>
> Cost, on the scorecard's terms. A cold sweep of 1,875 repos is 164s and about 1,900
> requests; a warm sweep is 136s and 4 requests, because the poll is conditional and a 304
> does not decrement the rate limit (measured). Wall clock is the real cost here, not quota.
>
> **The state file is a cache and not durable state, which is the opposite of the obvious
> choice.** It holds CVE ids by construction, and `publish.suppressed_ids` states the rule
> that settles it: counts, never identifiers, because committing ids to a public branch
> publishes the exact list the withhold lever exists to remove. Scrubbing the staged copy
> is not an escape either, because the feed reads its rows back from that file and a
> scrubbed copy would permanently drop those rows on the next 304. The cost, stated: an
> evicted cache is a cold start spanning two runs, disclosed as `CAPPED` with the repo
> counts and the resume point rather than as a quiet shrink.
>
> **What this feed deliberately does NOT do.** It is not in `clock.OWNER_FEEDS`, so none of
> its rows become MUST. The note there records that restoring GitHub as an owner feed needs
> an advisory attributed to an org rather than to GitHub-the-database, which this feed does
> supply structurally, and a way to resolve that org to the CNA owning the id, which
> nothing here does. It also collapses to the `github` origin in `report._ORIGIN`, so a row
> carried by both GitHub feeds counts as one independent source rather than two.

---

## 4. The expansion, in tiers, with what each is worth

Yields below marked **measured** were computed against the corpus and the pinned roster
on 2026-08-22. Yields marked *estimate* are upper bounds from CNA volume and are exactly
the kind of number this plan exists to stop trusting; they get a scorecard before they get
a merge.

### Tier 0: no new feed code, but three prerequisites

**Promote `csaf` and `msrc` into the weekly profile.** They are written, tested, and
already run in `deep`. The gate is measured on `weekly`, so `siemens`, `redhat`'s CSAF
channel, `microsoft`, `ABB`, `Schneider`, `Huawei`, `Nozomi`, `SICK`, `KUNBUS`,
`Stackable`, `Open-Xchange`, `Cisco` and `SUSE` are all outside the measured profile
today. The BSI aggregator was fetched live: it lists **14 providers**, of which roughly 10
are CNAs.

**Measured live, 2026-08-22.** Both were run against 2025-2026:

```
msrc   10,516 ids     5.8s     +1 new CNA   (google_android)
csaf    3,401 ids   135.8s    +12 new CNAs
```

The 12 from CSAF are `ABB`, `CERTVDE`, `CyberDanube`, `PTC`, `Rockwell`, `SICK_AG`,
`TPLink`, `fortinet`, `jci`, `palo_alto`, `schneider`, `siemens`. **Tier 0 is +13 CNAs,
21.7% to 24.1% of roster, for 142 seconds of runtime.** That is the best ratio anywhere in
this document and it requires no new code.

Note what the run also exposed, none of which was visible from the config: **Cisco returns
403** to a non-browser agent, and **SUSE, Huawei and `www.sick.com` each returned zero
advisories in scope**. Four of the 17 discovered providers contribute nothing, and one is
a duplicate host of a provider that works. The provider list has never been validated
against what it actually yields, and `feedlab` scorecards are how that stops being true.

**The gate must be measured on the profile the cron actually runs**, which is condition 1
of the launch checklist, so the fix was never "measure `deep` and run `weekly`". Prefer a
second `schedule:` entry selecting `deep` from `github.event.schedule` over widening
`weekly`, so the two slowest adapters do not enter every six-hourly tick and every docs
commit.

#### Tier 0 is not free, and this is the part the first draft got wrong

The panel accepted the measurement and rejected the sequencing. Promoting CSAF lands ICS
and OT rows, which are the most consequential population on the site, and three defects
are waiting for them. Two were verified directly in the code:

- **A CSAF row links to a page that disproves it.** `report._u` (report.py:53-74) has
  branches for nine sources and none for `csaf`. `csaf` is in the fallthrough tuple at
  line 76, but `_u("csaf")` returns `""`, so every CSAF row takes the last-resort URL,
  `https://www.cve.org/CVERecord?id=<id>`, which renders **nothing** for a RESERVED ID.
  The site would publish an ICS row whose only evidence link is a blank page. `feeds.py`
  already captures the publisher and tracking id, so the branch is available, not absent.
- **Every CSAF provider collapses to one origin.** `_ORIGIN` (report.py:130) has no `csaf`
  key, so `_indep` maps every provider to the single token `csaf`. Siemens and Schneider
  independently carrying the same row yields `indep_sources: 1`, and the headline counts
  only rows with two or more independent origins. CSAF's corroboration is discarded at
  exactly the moment it starts mattering. Key the origin on the provider, not the adapter.
- **Bulk-reporter naming and per-adapter instrumentation** (panel items 7 and 14) land
  first for the same reason.

So Tier 0's real cost is not 142 seconds. It is 142 seconds plus those fixes, and the
order is not negotiable: **land them before the promotion, or the first ICS rows arrive as
single-origin, uncheckable, coordinator-named claims with a dead evidence link.**

### Tier 1: ecosystems already reachable through a written adapter

**OSV currently reads 6 of 46 ecosystems.** All 46 were enumerated live and the extra 29
were downloaded and scored against the corpus. The result is the most useful measurement
in this document, and it is bad news:

| ecosystem | ids in scope | effective CNAs | **new** |
|---|---:|---:|---:|
| ~~GIT~~ | ~~31,366~~ **450** | ~~121~~ **10** | ~~+18~~ **+0** |
| Android | 622 | 11 | **+7** |
| Red Hat, SUSE, Rocky, AlmaLinux, Chainguard, Wolfi, openEuler, Mageia, TuxCare, Azure Linux, Bitnami, BellSoft, Maven, NuGet, Packagist, Hex, CRAN, Pub, Hackage, Julia, opam, VSCode, SwiftURL, GitHub Actions, Linux, Root, UVI | 47,000+ | up to 53 each | **0** |

**All 29 extra ecosystems together buy 25 CNAs. 21.7% to 26.3% of the roster, 31.5% to
38.3% of reachable.** Every distro ecosystem buys zero, because the distros are exactly
what the existing nine feeds already read. OSV breadth is nearly exhausted, and it is the
cheapest thing on this list.

Merge `GIT` and `Android` and the remaining 27 anyway, since the adapter exists and the
marginal cost is bandwidth, but **the 27 go in tagged `corroborating`** until they pass
the disclosure-lead backtest, and none of them are counted as progress.

> ### CORRECTION, 2026-08-23. The GIT row above was wrong by its entire value.
>
> The 31,366 ids and +18 CNAs came from a full-text regex over the ecosystem's
> archive. **`feed_osv` returns 450 rows from GIT and +0 new CNAs**, because the
> adapter reads CVE *aliases* and GIT records carry their CVE references in other
> fields. The probe and the adapter were measuring different things, and only the
> adapter's number can be banked.
>
> **Tier 1 is +7, not +25.** All of it is Android. GIT is not merged.
>
> This is the second estimate in this document to be cancelled by measurement, and
> the first was cancelled in the opposite direction (the Android bulletin parser
> was unnecessary because OSV already carried it). Estimates here have now been
> wrong by their entire value in both directions, which is the case for section 3's
> harness rather than against it. **Every remaining figure in Tier 2 and Tier 3 is a
> probe, not an adapter measurement.**

**Tier 0 and Tier 1 together, measured through the adapters:** **+20 CNAs**, taking the
roster share from 21.7% to about 25.4% and the reachable share from 31.5% to about 37%.

That is the entire cheap half of the plan. Two days of work, no new parsers, and it stops
well short of the gate.

### Tier 2: aggregate feeds that are not OSV

Each carries multiple CNAs per fetch, which is what makes them worth writing.

| candidate | probe | carries | *estimate* |
|---|---|---|---|
| ~~**Android Security Bulletin**~~ | **cancelled, see below** | | **0** |
| ~~**Samsung Mobile SMR**~~ | **BUILT 2026-08-23** | SamsungMobile | **+1, measured** |
| **Patchstack** | `patchstack.com/database/` 200; needs a machine-readable route, not the HTML | Patchstack (14,264 CVEs, the largest missing CNA on the roster) | +1 |
| **WPScan** | `api/v3` route 404; API is token-gated | WPScan (1,961) | +1, blocked on credentials |
| **CSAF provider sweep** | probe `.well-known/csaf/` per vendor. Sampled: SonicWall **200**, Palo Alto **404**, Dell **403** | one CNA each, no parser each | +5 to +15 |
| **National CERT feeds** | CERT-FR **200**, TWCERT **200**, JVN **200**, CERT-VDE **200**, CISA ICS **200** | TR-CERT, twcert, CERTVDE, INCD, CERT-In, CIRCL, DIVD, JPCERT | +5 to +8 |
| **GitLab advisory DB** | repo **200** | mixed, overlaps GHSA heavily | unknown, likely low |
| **Distro leftovers** (Oracle ELSA **200**, Rocky errata API **200**, Gentoo GLSA **200**) | all 200 | overlap with OSV distro ecosystems, which scored 0 new | likely 0, scorecard first |

**The Android bulletin parser was cancelled by measurement, and that is the whole argument
for the harness.** It was the top row of this table on the first draft, worth an estimated
4 to 6 CNAs, and it needed an HTML scraper walking a monthly index whose dated URL already
probed 404. Scoring OSV's `Android` ecosystem first showed it delivers **`google_android`,
`Google_Devices`, `qualcomm`, `MediaTek`, `Unisoc`, `imaginationtech` and `Arm`** for one
line of config. The entire claimed yield of a fragile scraper was already sitting behind an
adapter we have shipped for months. `Samsung_Mobile` is the only name the bulletin would
have added that OSV does not carry, and Samsung publishes its own feed, which probed 200.

Assume the same is true elsewhere in this table. **Nothing in Tier 2 gets written before
its scorecard is run against the already-merged set**, because the first estimate in this
document that got checked was wrong by its entire value.

The CSAF sweep is the highest-leverage item here and it is not one feed. It is a probe
that runs `.well-known/csaf/provider-metadata.json` against every roster CNA's known
domain, keeps what answers, and turns each hit into a config line rather than a parser.
The existing `feed_csaf` already handles ROLIE and directory distributions, so a
discovered provider costs one tuple entry. The 403 on Dell is the shape of the problem:
some vendors serve CSAF behind a WAF that refuses a non-browser agent, and this plan does
not authorise working around that.

> ### RUN 2026-08-24 against the ten top-50 CNAs the gate cannot see. It buys nothing.
>
> `python -m rbp.feedlab probe-csaf --cnas WPScan,dell,TR-CERT,sap,huawei,twcert,HCL,qnap,juniper,hpe`,
> probing only hosts each CNA itself published to the Program (advisory pages, security
> contact, disclosure policy) rather than hosts guessed from an organisation name. Result
> in `feedlab/_csaf_probe.json`:
>
> | | |
> |---|---|
> | serve provider metadata at the well-known path | **1 of 10** (huawei) |
> | 404 at the well-known path | WPScan, sap, qnap, hpe, HCL, juniper |
> | 200 but not CSAF (an HTML error page) | dell, TR-CERT, HCL, juniper |
> | 403, a WAF refusing a non-browser agent | sap (`www.sap.com`) |
> | TLS certificate verification failure | twcert |
>
> **And the one hit is not usable.** `www.huawei.com` serves provider metadata publicly,
> listing 121 distributions, one directory per advisory. Every one of those directories
> returns **401 Unauthorized**: `changes.csv` and `index.txt` alike. The `/clear` root
> exists and is empty. So Huawei publishes a CSAF catalogue that no unauthenticated client
> can read, which is the cause of this document's own Tier 0 note that Huawei "returned
> zero advisories in scope", and the same run confirmed it live at `+0`.
>
> That also exposed the cap. `CSAF_MAX_DIRS = 12` against Huawei's 121 selects an arbitrary
> eleven advisories and reports a clean read, so even an authenticated Huawei would have
> arrived as a tenth of itself. The cap stays; it is now reported (see section 3).
>
> **The conclusion for the launch gate: the CSAF sweep does not buy margin.** Of the ten
> CNAs standing between the gate and headroom, nine publish no CSAF at the well-known path
> and the tenth publishes it behind authentication. Margin has to come from Tier 2's
> national CERT feeds or from Tier 3, both of which are parsers rather than config lines.

Tier 2 lands somewhere around **35 to 42% of roster, 51 to 61% of reachable**, and the
range is that wide because six of eight rows are estimates.

### Tier 3: the long tail, which is 186 CNAs at one CNA per parser

This is where 50% of roster is either reached or abandoned. Nothing about it is clever:
it is a vendor advisory page at a time, RSS where it exists, HTML where it does not, each
one a separately breaking dependency on someone else's CMS.

**Rate: assume 2 to 3 CNAs per working day**, including the scorecard and the test. To go
from Tier 2's ~200 effective CNAs to 270 (50% of roster) is roughly **25 to 35 working
days**. To go from there to the 371 ceiling is roughly **another 40 to 50**, because the
remaining CNAs are the smallest and the least likely to publish a machine-readable feed.

Sequence the tail by **volume descending**, so the highest-volume unsighted CNA is always
next. That ordering is also the ordering that maximises the chance of finding real RBPs,
which is the point of the exercise rather than the number.

---

## 5. What this costs, honestly

| stage | new feeds | cumulative roster % | cumulative reachable % | effort |
|---|---:|---:|---:|---|
| now | 9 | 21.7% **measured** | 31.5% **measured** | |
| after the admissibility split | 9 | 21.5 to 21.7% **measured** | 31.3 to 31.5% **measured** | 1 to 2 days |
| Tier 0 | 11 | 24.1% **measured** | 35.0% **measured** | 1 day + 3 prerequisites |
| Tier 1 | 11 | ~25.4% **measured** | ~37% **measured** | 2 days |
| Tier 2 | ~25 | ~35 to 42% *estimate* | ~51 to 61% *estimate* | 2 to 3 weeks |
| Tier 3 to gate | ~90 | **50%** *estimate* | 73% *estimate* | 5 to 7 weeks |
| Tier 3 to ceiling | ~250 | **68.8%** | 100% | 4 to 6 months |

The first four rows are measured against the live corpus and the pinned roster. Everything
from Tier 2 down is an estimate, and the gap between the two halves of this table is the
honest statement of what is known.

Three things this table is saying that are worth saying in words.

**THE GATE CLEARS.** Samsung Mobile shipped 2026-08-23 and took top-50-by-volume
effective coverage from 39 to **40 of 50, exactly 80%**. One page, one fetch, 420 rows,
72 SamsungMobile sightings against a floor of 3.

Measured before a line of the adapter was written, which is now the rule: the OSV `GIT`
probe predicted +18 CNAs and the adapter delivered +0 because the two were reading
different fields. This one was checked the same way first and delivered what it promised.

The margin is **zero**, which is the cost of the gate having no second condition. Ten
top-50 CNAs remain under the floor (WPScan, dell, TR-CERT, sap, huawei, twcert, HCL,
qnap, juniper, hpe) and any one of them would give headroom.

**The cheap work did not reach the gate on its own, and this was the last step.** Tier 0 and Tier 1 take top-50-by-volume effective coverage from **31/50 to
39/50, 62% to 78%**, against an 80% gate that needs 40. The roster share reaches about
25.4%. One more top-50 CNA clears it; the nearest are Samsung Mobile, which publishes its
own feed and probed 200, then dell, sap, huawei, twcert, juniper, hpe, qnap, HCL, TR-CERT
and WPScan.

**The last 30 points cost more than the first 30.** Going from 50% to the 68.8% ceiling is
roughly 160 more CNAs averaging fewer than 20 published CVEs each. Each is a parser with
the same maintenance cost as `dell` and a hundredth of the yield.

**Maintenance is the real bill.** 250 adapters against 250 third-party pages will break
continuously. At a very optimistic 1% breakage per feed per month, 250 feeds means 2 to 3
broken feeds at any given time, permanently. That is why sections 2 and 3 come first: at
that scale, the guards are the product and the adapters are the easy part.

---

## 6. Stopping rule

The plan needs a defined end, or it becomes a permanent reason not to launch.

**First, a fact about the 50% that changes what the stopping rule can honestly be.**

`GATE_PCT = 50.0` was set when the gate figure was `cnas_sighted` over a corpus-derived
denominator. The numerator later moved to `cnas_effective` and the denominator to the
pinned 539-CNA roster, and **the threshold was never re-derived.** 50% is not a considered
judgement about the current metric. It is a number left behind by two metric changes that
each made it harder to clear, and it now sits 21.8 points above what the current feed set
can reach at all.

That is a real problem and it has an obvious wrong answer. Lowering the threshold to meet
the measurement is exactly what this site exists to criticise:

> A project whose thesis is that the CVE Program removed its numeric thresholds and
> replaced them with private discretion cannot launch by quietly moving its own threshold.

So the threshold gets re-derived **in `PLAN.md`, in public, with the date, the old metric,
the new metric and the reasoning**, or it does not move. There is no third option, and
"leave 50% in place and never launch" is not the safe choice it looks like: an unreachable
gate is a private decision not to launch, wearing a number.

**The panel's proposed replacement, which is a conjunction rather than a single number:**

- a volume-weighted condition, achievable and already close: **top-50-by-volume at 80%**,
  currently **37 of 50**, with `pct_volume_attributable` at 90.1%
- **plus** a roster-share floor set from the reachable ceiling rather than from a round
  number, so the two ceilings in section 0 are what the gate is derived from

A conjunction is harder to game than a percentage, and the volume-weighted half is the one
that actually tracks whether the site can see the CNAs that matter. This is **your call,
not the plan's**, and it is the single decision blocking everything downstream of Tier 1.

If the threshold stays at 50% of roster, that is 73% of reachable, and section 5 says it
costs roughly 5 to 7 weeks of Tier 3 after Tier 2. The remaining 100 CNAs then become the
post-launch beat that PLAN.md section 9 already argues for.

**Stop adding tail feeds when three consecutive scorecards show `rbp_rows == 0` over a
90-day backtest.** At that point new feeds are buying coverage and not detection, the two
have come apart, and continuing is optimising the gauge instead of the engine.

**Reassess the ceiling if the roster changes shape.** 68.8% is a fact about today's
roster and today's window. `tests/test_roster.py` already fails on drift; the ceiling
should be recomputed and republished on every roster refresh, because a number this
load-bearing must not be a comment in a markdown file.

---

## 7. What has to change in the code

Ordered by dependency, not by size.

0. **Prerequisites to Tier 0, which are not feed work and come first:** a `csaf` branch in
   `report._u` keyed on the captured publisher and tracking id; a `csaf` entry in
   `_ORIGIN` keyed on **provider** so two vendors corroborating a row count as two;
   plus panel items 7 and 14 (bulk-reporter matcher, per-adapter instrumentation).
1. `rbp/coverage.py`: split feeds into detecting and corroborating; compute
   `cnas_effective` over detecting only; return `reachable_total`, `pct_reachable`, and
   `ceiling_pct` so the site can publish the ceiling beside the count.
2. `rbp/feedlab.py`: new. The scorecard harness in section 3.
3. `rbp/feeds.py`: parallelise `gather` without disturbing per-feed health recording;
   seed shrink baselines for new feeds; expand `feed_osv` ecosystems; add the CSAF
   `.well-known` discovery probe.
4. `rbp/cli.py`: profile change once Tier 0's runtime is measured.
5. `rbp/launch.py`: condition 1 reads the new fields; the gate fails when a detecting feed
   that contributed to the published figure is FAILED.
6. `rbp/site.py` and `/method`: publish reachable, ceiling, per-feed detecting or
   corroborating status, and per-feed RBP yield. The feed inventory stops being a list of
   names and becomes a table with a yield column.
7. `tests/`: a scorecard fixture per merged feed; a test that fails if a feed is counted in
   `cnas_effective` without a passing disclosure-lead backtest on file.

Item 1 lowers the published number. It ships first anyway.

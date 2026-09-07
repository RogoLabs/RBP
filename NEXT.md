# Where this stands, and what to pick up next

Rewritten 2026-08-29. **This file is not a changelog.** It had become one: 900
lines, twelve round-by-round sections, most of them describing work that had
already shipped. That history is not lost and does not belong here. It is in
`git log`, which records every change with its reasoning, and in
`docs/reviews/`, which holds the review output verbatim.

What belongs here is three things and nothing else:

1. **what the site is now**, so nobody has to reconstruct it from code;
2. **what is open**, so the next session starts on real work;
3. **what will bite you**, including decisions already settled, so they are not
   re-opened by accident.

If you change what the site does, this file is part of the change. If you find
yourself adding a section that begins "Round N, what shipped", that belongs in
the commit message instead.

---

## What the site is now

**A list.** "Here are the CVE IDs that are reserved and public, and where they
are showing up." Five routes: `/` (the rows, a command bar, a slide-over
carrying the argument), `/method.html`, `/policy.html`, `/status.html`,
`/about-this-count.html`.

`/slides.html` is deliberately not one of them. It is an unlinked conference
deck, noindexed in both postures, reachable only by typing the URL. It is
counted here so it stops being the thing nobody remembered was on the publish
path: a page absent from this list is a page that stops being reviewed, and the
first review it got found an absolute claim on it that the site's own published
data contradicts.

**It names no CNA.** `site.NAMING_ENABLED = False` is the single flag, enforced
at the writer. `python -m rbp.publish check` refuses to stage any tree in which
a certified CNA short name appears at all. Inference still runs off the publish
path so a future release starts from measured precision.

**It is LAUNCHED.** `RBP_LAUNCHED=1` is a repository variable, `/` is the
dashboard, and **merging to `main` publishes to the live site**. `deploy.yml`
fires on push to main and on a six-hourly cron.

**Live numbers move every run and are not quoted here on purpose.** The previous
version of this file pinned nineteen of them and every one was wrong within two
days. Read them from `snapshots/<latest>/summary.json`, or from
`GATE_TOP_N_PCT` in `rbp/site.py` for the gate. A number in a document is a
number nobody is measuring.

**CSAF has no count cap.** Each provider is read every run, bounded by
`CSAF_PROVIDER_BUDGET_S` rather than by a number of advisories, and `/status`
publishes what each one returned.

**CSAF is read incrementally.** Each provider keeps two read marks and every
reference it has seen in `data/csaf_state.json`, cached across runs by
`deploy.yml`. Fetching is incremental; RETURNING NEVER IS. A provider emits
everything it knows on every run whether it fetched anything or not, because
`gather` keeps no memory of its own and a provider that returns nothing removes
its rows from the site. `CSAF_PROVIDER_BUDGET_S` bounds how fast a backlog
drains, not what the site can see.

---

## What is open

Six items, and they are not the same KIND of thing, which is worth knowing before
reading them in order:

- **two are decisions, not work.** 5a (`feed_ubuntu`: keep it or delete it) and 6
  (`euvd`: leave it out) are both measured, both carry a recommendation, and
  neither needs code. Taking them is how this list gets shorter today.
- **two are waiting on accumulated data, not on effort.** 4 drains over
  successive runs by design. The `months` half of 2 wants a few weeks of
  snapshots to backtest its thresholds, and picking them early is the exact
  mistake that entry exists to prevent.
- **and two are real work.** 1 is the largest, because it is the harness
  disagreeing with the pipeline about what the merged set IS. 3 is a rehearsal
  that has to touch a real run.

No numbers in that list on purpose. It routes; the items carry the measurements.

### 1. The harness's `csaf` is colder than the pipeline's, and nothing said so

**Found 2026-09-06 by fixing the window below, rebuilding the baseline at four
years, and then failing to reproduce the live run's numbers with it.**

The rebuild read the same fifteen feeds over the same four years as the live run
of the same commit, and fourteen of them returned the same row count to the id:
`alas` 19,976, `ubuntu` 3,993, `jvn` 1,968, `msrc` 17,397. `csaf` returned
**42,659 against the live run's 62,800**. That one feed is the entire difference
between the harness's 247 effective roster CNAs and the live run's 263, and it is
why `twcert` is sighted 15 times live and **zero** times here, with 550 of its
ids sitting in the window waiting to be sighted.

Neither half is broken. `deploy.yml` caches `data/csaf_state.json` across runs
and a provider emits everything it has ever seen, so the live state is as deep as
every run before it, while a local state is as deep as the runs that happened
locally: three providers were still catching up in this one and three more
stopped on the time budget. The consequence is one-directional and it is the
permissive one. **A candidate scored against this baseline looks better than it
is**, because the CNAs `csaf` already covers are missing from the set it is
marginal to. That is exactly what
`test_the_recorded_baseline_describes_the_profile_that_actually_runs` exists to
prevent, arriving one level below where it looks: the feed LIST matches the
pipeline and the STATE behind one of those feeds does not.

It also means the harness cannot answer a question the site answers four times a
day, which is what makes it worth fixing rather than annotating forever. Three
routes, none scoped: publish the read marks where the harness can fetch them, the
way the roster is pinned; drain the backlog locally over successive runs and
accept that a baseline is only as good as the last drain; or record the depth in
the baseline and subtract it when reading a card. The third costs nothing and is
half done, in that `health.csaf` in `feedlab/_baseline.json` now carries the
provider count and the two catching-up figures.

**Until one of them lands, read `cnas_new_effective` as an upper bound.** The
fifteen committed cards are now measured over the right window, which they were
not before, and they are still marginal to a merged set 20,141 `csaf` ids short
of the live one.

The corpus half of the same question was measured at the same time and is NOT a
gap: the index was ten days stale, refreshing it moved 3,696 referenced ids into
the corpus, and it changed the effective count by nothing. `corpus_newest` is
recorded in the baseline now so the next reader does not have to re-measure that
to rule it out.

### 2. FEEDS.md section 3's three remaining guards

Per-feed shrink baselines surviving a profile change; a failure budget expressed
as a fraction rather than a count; `gather` parallelised while preserving
per-feed health recording exactly.

**A fourth guard landed 2026-09-02 and one half of it is unfinished.**
`feeds.withdrawn_history` catches a feed that stops evidencing a period it had
ALREADY served, which is the case none of the count guards could see: Microsoft
withdrew `2026-Aug` from its CVRF index, msrc lost 1,637 ids, and 10.9% cleared
both `MAGNITUDE_DROP` (0.40) and `verify.MAX_ROW_DROP` (0.25). `stale_feeds`
caught it only because the withdrawn month happened to be the newest one.

The horizon half is measured and needs nothing: zero backward steps across the 12
snapshots on the data branch except the event itself. **The bucket half is not.**
`MONTH_MIN_ROWS` and `MONTH_DROP` were picked to fire only on wholesale
withdrawal because `months` was a new field with no history to backtest, and both
halves therefore report on the degraded path rather than the blocking one. Once a
few weeks of `months` have accumulated in the snapshots, measure the real
per-month variation and tighten them, the way `FRESHNESS_FLOOR_DAYS` was derived
from the feeds' own cadences rather than picked. Until that is done, do not
promote either half into `verify`.

### 3. Rehearse the withhold lever end to end

`RBP_WITHHOLD` drops rows from every published artefact and is tested, but has
never been exercised against a real run.

### 4. Loose threads from the uncapping

SUSE, Red Hat's CSAF endpoint and CERT-Bund each hold far more than one budget
can read, so the count climbs over several runs rather than jumping.

### 5. `ubuntu-osv`: a decision (a) and a measurement (b)

`feed_ubuntu_osv` was merged 2026-08-31 on the Ubuntu Security Team's own
recommendation. Scorecard in `feedlab/ubuntu-osv.json`, reasoning and every
measurement in `FEEDS.md` under "MERGED 2026-08-31".

Both follow-ups used to be blocked on `ubuntu.com/security/` answering 503, and
**a is now answered and b is runnable**: the host was up on 2026-09-06. It goes
down without warning and has cost this section a 25-minute wasted rebuild once
already, so **check the endpoint first anyway**, and read the per-feed line rather
than the exit status when you do.

**a. THE AUDIT HAS RUN, 2026-09-06, at the four-year window, and it says
`feed_ubuntu` earns nothing on coverage.** `cnas_new_effective` **0**, 16 of its
3,993 ids not already seen by the other fourteen feeds, verdict **corroborating**
rather than detecting. Its cost that run was 88.0s, against 1,070s on 2026-08-27,
93.1s on 2026-08-31 and 257.5s earlier on 2026-09-06; price the bad case.

**The three reasons for keeping it were then priced, and two of them changed.**

*The dependency reason is gone.* `resolve_dates_ubuntu` does not go through
`feed_ubuntu`: it asks `cves.json?q=<id>` by name, and `cli.py:444` calls it on
the undated rows of ANY feed. Its own docstring says it exists BECAUSE the walk
cannot reach those rows. Deleting the adapter would not touch it. What the site
depends on either way is the HOST, and deleting a feed does not reduce that.

*The rows reason survives and is small.* Of the 156 distinct ids `feed_ubuntu`
references that are unpublished now, **7 are referenced by no other feed in the
profile**. That is what deleting it costs today, beside 0 marginal CNAs. For
scale, on the same baseline: `ghsa-repos` is sole source for 1,129, `csaf` 303,
`samsung` 64, `alpine` 45, `ubuntu-osv` 30. One measurement, not a rate.

*And the obvious compromise does not work.* Six of those 7 sit at rank ~3,730 of
3,993 in the feed's own newest-first order, which is the far edge of what the
200-page cap reaches. **Shrinking the cap to make it cheaper would lose six of
the seven.** Its unique contribution lives exactly at the bottom of its reach,
which is also why raising the cap was measured and rejected at 1,128 pages.

So the trade is 7 candidate rows against 88s in the good case and ~18 minutes in
the bad one, inside a 60-minute job ceiling where a cancelled job publishes
nothing. **Recommend KEEPING it and closing this item.** The project's standing
bias is to delete, but that bias is about accreting guards and surfaces, not
about dropping the only source of rows the site exists to publish; and the cost
is bounded by a cap that is already there rather than open-ended. The 2026-08-31
independent failure is the second reason and it is unchanged. If it goes, the
diff should say it is trading 7 rows for 18 bad-case minutes, because that is
what it is.

Read that 0 against item 1: the merged set it is marginal to is 20,141 `csaf` ids
short of the live one, and that error runs the other way, making a feed look
BETTER than it is. `ubuntu` scoring zero against an understated baseline is a
stronger result than the same zero against a complete one, not a weaker one.

All fifteen cards now describe one baseline, recorded at one moment, over the
window the pipeline actually gathers. Before this pass they did not: two were
newer than the other thirteen, and every one of them measured two years.

`ubuntu-osv` reaches 15,500 ids to the tracker's 3,994 and beats it on every
scorecard axis, but it is **not a superset**: 31.9% of the tracker's ids have no
OSV record. All the RBP candidates in that 31.9% are already sighted elsewhere,
so the tracker's remaining contribution is *sightings*, which feed
`cnas_effective`, which is the gate. The audit is the only thing that can price
that. Two things push the other way and must be costed in: the tracker's endpoint
is what `resolve_dates_ubuntu` queries by name (130 rows still depend on it), and
on 2026-08-31 the two feeds demonstrably failed independently. **Do not delete
`feed_ubuntu` before the audit.**

**b. Two things from Canonical's second reply, 2026-09-01**, both in FEEDS.md
under "CANONICAL ANSWERED THE OPEN QUESTION". The 31.9% non-overlap figure quoted
to them was inflated: it charged tarball snapshot lag to scope, and the same
subtraction now gives 38.9% purely because the tracker fetch got newer.
**Neither number is a scope measurement; do not quote either.** Separating scope
from lag needs per-release status for a sample of the gap, which needs
`cves.json?q=`, which was 503 on 25 of 30 queries.

**The host was answering 200 on 2026-09-06**, checked before the rebuild:
`cves.json?limit=1` in 41.0s and `notices.json?limit=1` in 3.6s. So this is
runnable right now rather than blocked, and 41s for a one-record query is the
thing to budget for. It re-blocks itself without warning, so **check again before
starting rather than trusting this line.**

Second: `osv-all.tar.xz` was **30.5 hours stale** when checked, while
`canonical/ubuntu-security-notices` runs its OSV conversion every five to six
hours. The lag window held 293 new in-window ids and 202 RBP candidates, and
**zero** of them unseen by the other thirteen feeds. So it costs sightings, not
rows. Reading the git repo's delta beside the tarball is the obvious follow-up
and is unscoped.

**The baseline was rebuilt a third time 2026-09-06, at the right window:
15 feeds, 77,219 ids, 247 effective roster CNAs, `[ubuntu] 3993 rows`, 26
minutes, no feed failed and no feed shrank.** Every feed grew or held against the
two-year rebuild it replaced (51,070 ids, 208 CNAs) and none lost an effective
CNA, which is the shape a window widening should have. Two feeds barely moved and
both are explained rather than suspicious: `ubuntu` by 5 rows because its
200-page cap binds long before the window does, reading back 36 days of a window
that opens 2023-01-01, and `samsung` by 4 because its feed does not reach back
either. `corpus_newest` and the endpoint check are in the record: the host was
answering 200 when it ran.

The 2026-08-31 rebuild it replaced read 14 feeds, 45,895 ids and 183 effective
CNAs. The
first attempt at it is the reason the endpoint warning above is the first line of
this section: it ran while the host was answering 503 and then timing out, and
produced `[ubuntu] 80 rows, 750.2s` against a usual 3,994. **That run exited 0.**
Committing it would have made every future candidate look better than it is, in
exactly the direction
`test_the_recorded_baseline_describes_the_profile_that_actually_runs` warns
about. It cost 25 minutes to catch and only the `[ubuntu] 80 rows` line said so.

One local artefact survives it. `data/feedlab/ubuntu.fetches.json` (gitignored
working state, not in any diff) holds **80, then 3,968, then 3,988**, so
`stability` reports a ~98% swing for `ubuntu`. All three fetches are real and the
file is kept for that reason, but the 80 is an outage rather than variation, so
**do not read that swing as a shrink baseline**. `ubuntu-osv` beside it has five
fetches between 15,500 and 16,338, a 5.1% swing, which is the shape a healthy
history has.

**Every `stability` figure on every card is null as of 2026-09-06, deliberately,
and this is the fix rather than a regression.** `record_fetch` now stamps the
window each fetch read and `stability` compares only fetches of the newest window
that are at least `MIN_FETCH_INTERVAL_H` (24) apart, which is what FEEDS.md asked
for and nothing enforced. Both filters were needed and both were violated by
committed numbers:

- ten of the fifteen cards carried **0.0%** from two fetches four hours apart, on
  a feed nobody had watched for a day;
- `jvn`'s two fetches were **thirty minutes** apart, both 1,117, so the next
  audit would have committed a perfect reading of one observation;
- `csaf`'s **29.3%** was sixteen CSAF providers against eighteen, and `ubuntu`'s
  **98.0%** was the 503 outage below. Neither is the feed moving;
- and the window itself moved on 2026-09-06, so the first four-year fetch beside
  a two-year history would have read as a 20-50% swing on **every feed at once**.

So the histories restart at this window. The first rebuild at least a day after
2026-09-06 produces the first honest pair, and until then null is the correct
answer. The raw files keep every fetch, including `ubuntu`'s 80-row outage: the
filtering happens when the history is read, so nothing was deleted to get here.

This was item 2's "per-feed shrink baselines surviving a profile change" one
level down, at the harness rather than at `verify`. It is done HERE and not
there: `feeds.py` and `verify` still compare row counts across runs with nowhere
to record which profile or window produced them.

### 6. `euvd`: the one argument for it is gone

`euvd` is measured and **refused as a numerator source**: zero disclosure lead on
9,066 dated references and 60 of 60 of its absent ids PUBLISHED at the live
oracle. It is a publication mirror. That has never been in doubt.

The open question was whether to merge it tagged `corroborating` anyway, and the
single reason for was that **it is the only source measured that references
`TR-CERT` and `twcert` at all**, the two top-50 misses nothing else reached.

**That reason did not survive the four-year window.** The first live run after
the 2026-09-06 merge sights `TR-CERT` 6 times and `twcert` 15, both over the
3-sighting floor, from feeds already merged, and `top_missed_effective` came back
as `huawei` alone. Neither CNA needs euvd and neither ever needed a new parser;
they needed more years of the feeds already in the profile.

The harness reproduces `TR-CERT` at exactly 6 and sights `twcert` **zero** times,
which is item 1 and not a contradiction of this: fourteen feeds returned
identical row counts in both runs and `csaf` did not, so every id the live run
had and the harness lacked came from `csaf`. Which locates `twcert` for anyone
who needs it later: it is reached through a CSAF provider, by a feed already
merged, and still not through euvd.

So what is left is the cost side on its own: no incremental route was found,
`api/search` is not date-ordered, and covering the window means roughly 150,000
records and 1,500 requests for rows that only corroborate. **Recommend leaving it
out and closing this item.** It is written down rather than deleted because the
reasoning above is what a future reader will otherwise re-derive from euvd's CNA
count, which still looks like the best row in FEEDS.md.

---

---

## Settled, so they are not re-opened by accident

Each of these was decided with reasoning that is in `git log`. Re-litigating one
costs a session.

- **Prefer the DELETE list when in doubt.** Every review this project has run
  came back weighted towards removal; round 9's own balance was 21 removals
  against 7 additions. The documented failure mode is accreting guards and
  caveats around a list and its links, and the last four rounds each ended by
  deleting something that had been kept because deleting it looked risky.
- **No attribution.** No CNA is named on any row, in any field, in any format.
- **The window is four years, and five is the wrong way to widen it.**
  `coverage.WINDOW_YEARS = 4` since 2026-09-05, measured with four full gathers
  rather than argued. Four admits ~40 reserved rows over three and is the widest
  window at which no feed truncates that is not already truncating. Five buys 13
  rows more and breaks two feeds, and the breakage does not stay in the years
  being added: `ubuntu-osv` returns 5,502 ids numbered 2024 at three and four
  years, 2,375 at five and none uncapped. **If five ever looks attractive, the
  thing to change is `ubuntu-osv`'s 8 GB ceiling and `ghsa`'s 40-page cap, not
  the window.** Full table and reasoning in the block comment on
  `coverage.WINDOW_YEARS`.
- **The corroborated / independent-origin count is gone**, not repointed. It
  produced a second headline beside `summary.total`.
- **The launch-day epoch is retired, unused.** Setting it now would take a
  publicly indexed count to zero. The lever works and is kept as insurance.
- **The front page opens on the last 90 days**, announced above the rows with a
  control that clears it. Unfiltered and oldest-first, the first screen was ten
  near-identical rows naming one vendor's platform.
- **There is no removal channel and no email address on the site.** The embargo
  case has no route here, and that cost is real and stated. It took nine rounds
  to retire because no single file was wrong: four surfaces still promised a
  correction route while `.well-known/security.txt` on the same origin denied
  one, and each file was internally consistent.
  `tests/test_copy.py::test_no_page_offers_a_route_that_security_txt_denies`
  reads the built artefacts against each other in BOTH directions, so
  reinstating the channel fails the suite until that test is rewritten
  deliberately. That is the intended cost, not an obstacle to route around.
- **The hedge above the rows is gone.** A reader who copies rows into a ticket
  carries the rows and none of the qualification. Stated because it is a real
  reduction in disclosure.
- **`/method` publishes no launch checklist.** A launched site publishing its own
  pre-launch conditions reads as a site that has not launched.
- **UI chrome is title case.** Control labels, options, optgroups, buttons.
- **The About/panel duplication stays**, on measured evidence.
- **A harness-artefact test may not stop a publication.** The four tests marked
  `harness_artefact` compare a committed `feedlab/` artefact to the code, and
  `deploy.yml` deselects them because `rbp/feedlab.py` is imported by nothing the
  site builds: a stale scorecard cannot make a page wrong, and a cron tick cannot
  rebuild a baseline. Three of the four resolve against
  `coverage.window(TODAY'S YEAR)`, so before the marker they would have gone red
  on **1 January** and halted the live site until somebody was free to run a
  26-minute rebuild. ci.yml runs the suite unfiltered on every pull request and
  every push to main, so all four are still enforced where somebody is present to
  act on them. This is the same rule `deploy.yml` already applied to the render
  suite, and the reasoning is in `pyproject.toml` beside the marker. **Deleting
  the marker re-arms the tripwire**; verified by moving `WINDOW_YEARS` to 5 with
  no rebuild, which fails the commit path and publishes anyway.
- **CSAF provider identity is DERIVED, not in `sources`.** `?src=csaf:cisa` is
  built in the template from `refs`. Putting the host in `sources` breaks
  `origin_kind` (an unmapped slug reads as a tracker and silently stops the
  72-hour clock), changes `feed_count`'s meaning, collides with the 250-char
  `refs` truncation, and breaks every `?src=csaf` link already shared. The
  review panel reached the same conclusion from six directions.

## What will bite you

**Merging to `main` publishes to the live site.** There is no staging step
between a push and rbptracker.org.

**A cancelled job publishes nothing.** The 2026-08-29 16:43Z run hit the
45-minute ceiling at 46m09s and `deploy` never ran; the site silently kept
serving the previous artefact. `timeout-minutes` is 60 now. Headroom is what
keeps a slow third party from costing a publication rather than costing rows.

**The coverage gate can demote a launched site.** `publish.gate` fails the build
red if the top-50 figure drops below `GATE_TOP_N_PCT`, and `site.build` fails
closed to the pre-launch page.

**PLAN.md predates the pivot in places** and documents pages that no longer
exist. Trust `git log` and the code over it.

**A guard can be arithmetically unable to report the thing it is for.** /status
answered "does this site actually run every six hours?" with a numerator counting
EVERY successful publish and a denominator counting only the cron schedule.
Merging to `main` publishes, so a week with 29 pushes read **"46 of 28 scheduled
runs published in the last 7 days (164.3%)"**. The ratio over 100% was the
harmless half and the only visible one. The other half: a push cannot evidence a
scheduled tick, so a week in which every cron tick was evicted still read green
provided somebody was merging. Measured when it was found: 15 of 28 scheduled
ticks delivered, longest gap between publishes 20.6 hours, reported as 164.3%.

The page now publishes three figures, because the scheduled one alone overstates
staleness: scheduled ticks against the schedule, total publishes from any trigger,
and the longest gap. A low first figure beside a healthy second and a small gap is
a fresh site whose cron ticks are being evicted by its own pushes, which is a real
thing worth seeing and is not a stale site. **Do not collapse these back into one
number.**

**The count in the heading is rewritten in the browser, and the unfurl is not.**
`tests/test_copy.py::test_the_unfurl_and_the_heading_carry_the_same_count` asserts
that og:title, og:description and the h1 render the same summary key, and all
three did, in the served bytes. The h1's number is then replaced client-side, and
the page opens on a 90-day window nobody asked for, so first paint read **1,601**
under a preview that said **2,016**. `#viewnote` explained the gap correctly and,
measured at 375x812, did it at y=1213 against an 812px fold: a screen and a half
below the number. The lead now states the window beside the count, and
`tests/render/test_filters.py` asserts where it renders, not merely that it does.
The template-level guard could never have seen this; a test that reads the source
of a client-rendered page is measuring the wrong artefact.

**A gather that exits 0 is not a gather that worked, and the exit status is the
only part of it nobody has to read.** A run against a 503-ing host produced
`[ubuntu] 80 rows, 750.2s` against a usual 3,994 and exited 0; the only thing
that said so was one per-feed line in the log. A feed that quietly shrinks is the
one failure this site cannot tolerate, because the count goes down and the page
still looks fine, and by the next run the shrunken value is the baseline.
**Read the per-feed lines, every time, whatever the status says.** This is a
general rule and not a note about one host: it has been paid for twice.

**A green build is not a correct site.** Three regressions reached the live site
on 2026-08-29 and 08-30, each a variant of "state that claims to know something
it does not", and the offline suite passed on all three. Every one was obvious in
the published artefact within seconds. `python -m rbp.verify` runs as a deploy
step after the upload and fails the build on a finding; `tests/test_verify.py`
replays all three. Detection was never the gap: `compare_magnitudes` fired on the
first one and printed DEGRADED to stdout, nothing acted on it, and by the next
run the shrunken value was the baseline so it went quiet.

**A number written into a document is a number nobody is measuring.** This file
had nineteen of them and all nineteen went stale in two days. The review panel's
context block had the same problem and produced findings against a site that no
longer existed. Write pointers, not values.

**A comment that records a defect will outlive the defect, and it does not know
that.** Deleting `table.rbp` was blocked for nine rounds by a comment saying two
attempts had "broken the dark-theme contrast rule", and the rule it pointed at
carried a note saying that without it `.text-muted` reads 2.54:1 in dark.
Measured on 2026-09-06 before touching it: deleting that rule changes dark theme
by **nothing**, because `style.css` sets `[data-theme="dark"] .text-muted` from
`--color-text-secondary` with `!important` and always wins. The 2.54 was that
TOKEN going un-asserted for dark, a different fix, still in place, and guarded by
`test_a_root_override_does_not_silently_undo_the_dark_theme`. What the rule
actually buys is light theme, 6.07 against 5.30, both clear of AA. **The blocker
was a sentence, not a defect.** Re-measure a scary comment before you let it stop
you; this one cost more than the deletion did.

**Deleting a component silently disarms every check scoped to it.** Four render
assertions filtered on `.rbp` and would have gone on iterating over an empty list
and reporting green at all 19 widths. They were deleted rather than left. Two
detectors in `tests/render/_measure.py` were found in the same pass with no
caller at all: `row_overflow` had never been called by anything since it was
written, and it is the row layout's own version of the measurement the whole
render package exists for. It is wired in now. **When you delete a component,
grep the tests for its class name before you grep for its rules.**

### The lesson that still costs the most time

**"The test passes" and "the test works" are different claims**, and almost
every survivor of a mutation pass on this project is *fixture blindness* rather
than a product bug. The shape recurs and is worth recognising early: the unit is
proved and the seam is not.

Real examples, all from 2026-08-29:

- a budget test started cold, so it never exercised the code path it was written
  for, and reversing that path left it green;
- `csaf_id_date` was fully tested and nothing proved `feed_csaf` ever called it;
- a chip test allowed any label that was not one of two others, so an unrelated
  feed name satisfied it;
- the render fixture carried `csaf` in `sources` with no CSAF ref at all, so
  every assertion about the publisher filter would have passed on an empty list.

**So: reintroduce the defect and confirm a test fails.** First passes typically
catch about half. When a mutation survives, the usual fix is the fixture, not
the assertion.

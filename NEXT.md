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
drains, not what the site can see. SUSE, Red Hat's CSAF endpoint and CERT-Bund
each hold more than one budget reads, so their counts climb over several runs
rather than jumping. That is the drain working, and it needs nothing.

**Adapters fetch on four threads; everything that records runs on one.**
`GATHER_WORKERS = 4` since 2026-09-07, and the wall clock is now the longest
single feed, so the number to tune it from is the `seconds` each feed records in
`summary.feeds.detail`, not the four. A feed's first run is compared against its
scorecard's `ids` when no previous count exists. A feed that FAILS is weighed by
`coverage.effective_by_feed`, the effective CNAs that rested on it alone in the
last published run, and named under `feeds.failed_bearing` when that weight was
positive; it does not block publication. FEEDS.md section 3, "BUILT 2026-09-07".

---

## What is open

Nothing, as of 2026-09-08. The four items that were here that morning went four
ways the same day: one fixed (#43) and then measured, and the measurement's own
fix built in #45; two decided into "Settled" below; one measured into FEEDS.md
("MEASURED 2026-09-08", under the Canonical section).

That is not a claim that the site is finished. It is a claim that nothing known
is waiting. The things that WILL come are the ones this file cannot list yet: a
feed shrinking for a reason nobody has seen, a guard firing on a shape nobody
measured. When one arrives, it goes here with its measurement and its fix
specified, the way item 1 did, and it leaves here when it ships.

---

## Settled, so they are not re-opened by accident

Each of these was decided with reasoning that is in `git log`. Re-litigating one
costs a session.

- **`withdrawn_history` has no bucket half for a feed assembled from parts,
  and its thresholds stay where they were picked.** Measured 2026-09-08 over
  the six snapshots carrying `months`: eleven feeds never moved a month by more
  than 2% between runs; `csaf` moved one 46% when SUSE went unreachable and
  another 38% when it came back, because the cross-provider `seen` dedupe
  credits an id to the first provider in config order with that provider's
  date. A month count on such a feed measures which parts answered, not what
  the source serves, so `csaf` and `osv` keep the horizon half (exact, no
  threshold) and lose the buckets; `_explains_a_gap` now reads an unreachable
  part's `accounted` mark, which `health_detail` rolls up as status but not as
  reason. Per-part buckets would give the bucket half back and are not built.
  Neither half goes into `verify` on thresholds that were picked; if the
  buckets are ever wanted on `csaf`, build them per part first, then measure
  again. Block comment above `MONTH_MIN_ROWS`; `tests/test_degraded.py`
  replays both csaf days.
- **`feed_ubuntu` stays.** Decided 2026-09-08 on the audit of 2026-09-06 at the
  four-year window: zero marginal effective CNAs, and 7 candidate rows that no
  other feed references, six of them at the far edge of the 200-page cap, so a
  smaller cap loses them and a larger one was measured and rejected at 1,128
  pages. Cost is 88s in the good case and a 900s budget in the bad one, which
  since #41 publishes as degraded instead of freezing the site. The two Ubuntu
  sources failed independently on 2026-08-31, which is the second reason and
  unchanged. The project's bias to delete is about guards and surfaces, not the
  only source of rows the site exists to publish. If it ever goes, the diff
  says it trades 7 rows for bad-case minutes. FEEDS.md section 2, "CORRECTED
  2026-09-06"; pricing in `git log` for this entry. The tracker-minus-OSV gap
  that used to be item 3b was measured the same day, FEEDS.md "MEASURED
  2026-09-08": it is mostly records not-affected on every Ubuntu release, not
  EOL scope, and neither of the two figures quoted to Canonical was right.
- **`euvd` stays out.** Decided 2026-09-08. It is a publication mirror: zero
  disclosure lead on 9,066 dated references, 60 of 60 absent ids PUBLISHED at
  the oracle. The one argument for merging it tagged `corroborating` was that
  it alone referenced `TR-CERT` and `twcert`; the four-year window reaches both
  over the 3-sighting floor through feeds already merged, `twcert` via a CSAF
  provider. Covering it means roughly 150,000 records and 1,500 requests a run
  with no incremental route, for rows that only corroborate. Written down
  because its CNA count in FEEDS.md still reads as the best row there, and the
  next reader would re-derive the argument from it.
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
- **A cap and a budget are different things, and the difference is cadence.**
  A cap fires on every run by design and defines the normal read: `CAPPED`, a
  standing limitation, never `degraded`. A budget bounds a bad day and fires only
  on one: `TRUNCATED`, `degraded`, published through `verify`'s
  `EXPLAINS_A_SHORTFALL` rather than blocked. `feed_ubuntu`'s wall-clock exit was
  CAPPED until 2026-09-08 on a written rationale that measured false (zero budget
  firings in 18 daily snapshots; the cap costs 289-341s on the runner against
  900s), and the one morning it fired, `verify` correctly refused to let a cap
  excuse the shortfall and the site froze. The resolver's and CSAF's budgets stay
  CAPPED for reasons of their own: neither can remove a row. Reasoning on the
  `budget_spent` branch of `feed_ubuntu` and in #41.
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
- **And there is no lever behind the scenes either.** `RBP_WITHHOLD` outlived the
  advertised channel by eleven days on the distinction between a capability and
  an advertisement, and went on 2026-09-07 because the reasoning that retired the
  channel does not stop at the advertisement. It was an EMBARGO lever, not a
  naming one: it dropped ids, and `NAMING_ENABLED` is what drops names. **So the
  cost is one notch worse than the channel's and is stated rather than softened:**
  an embargo request arriving by email now has no hand to apply, only a commit,
  in public, against the code that produces the list. What the site gains is that
  a published count can no longer change without one. Removed from
  `publish`/`site`/`cli`/`clock`/`inference`/`report`, from `deploy.yml`'s `env:`,
  and from the four surfaces that described it. The repository variable can stay
  set and does nothing.
- **The archive is stable rather than immutable on reasons that need no lever.**
  The claim was justified by the withhold lever until 2026-09-07 and would have
  become a promise about a deleted mechanism. It rests on two structural facts
  instead: a dated file is REBUILT from that day's snapshot by today's code on
  every run rather than appended once, and retention is bounded by
  `publish.KEEP_SNAPSHOTS`, so a dated URL outside that window stops resolving.
  The slide-over renders the bound as a number read from the constant, which is
  what `site._publish_keep` was written for and had had no reader since /data was
  deleted. `tests/test_copy.py` asserts it inside the paragraph rather than
  anywhere on the page, because the front page's age filter carries "90 days" in
  its JavaScript and the retention window happens to be 90 too.
- **The hedge above the rows is gone.** A reader who copies rows into a ticket
  carries the rows and none of the qualification. Stated because it is a real
  reduction in disclosure.
- **`/method` publishes no launch checklist.** A launched site publishing its own
  pre-launch conditions reads as a site that has not launched.
- **UI chrome is title case.** Control labels, options, optgroups, buttons.
- **The About/panel duplication stays**, on measured evidence.
- **A harness-artefact test may not stop a publication.** The tests marked
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
  no rebuild, which fails the commit path and publishes anyway. Four more joined
  them on 2026-09-06, covering the pinned live run and the depth every card was
  measured at; the same reasoning applies unchanged, and one of them goes red on
  a calendar at 14 days rather than on 1 January: re-pin the live run with
  `python -m rbp.feedlab pin-live`, which is one fetch.
- **The CSAF read marks are not published for the harness to fetch.** It was one
  of three routes considered for the harness's cold `csaf` state, and it is
  refused by a rule this repo already applies to `ghsa_repos_state.json`: counts,
  never identifiers. That state holds every CVE id every provider has ever
  referenced, which is a far larger set than the site publishes and one nothing
  has validated as publishable, and the data branch carries only what
  `publish.ALLOWED_ROOT` names. Putting it anywhere public (a data-branch commit,
  an Actions artifact on a public repo) publishes a list the site never decided to
  publish. **The rule used to be stated as "the exact list the withhold lever
  exists to remove"**; the lever went on 2026-09-07 and the rule did not, because
  it never rested on the lever, only borrowed it as the nearest example. The
  harness pins the live run's PUBLISHED coverage instead, which is counts, and
  gets a tighter answer for one fetch. Draining the backlog locally was the third
  route and is what the local state does on its own.
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

And one from 2026-09-07, because the seam was the HELPER rather than the fixture:
a new copy assertion checked that the retention bound appears on the front page
as a number, using the file-wide `_text()`. That helper strips tags and keeps
`<script>` bodies, and the age filter's JavaScript says "90 days" in five places
while `publish.KEEP_SNAPSHOTS` is also 90. Deleting the number from the copy left
the test green, and so did making `_publish_keep` return None so the paragraph
read "None days". Two mutations, both survived, on an assertion written the same
hour. Scoped to the paragraph it is about, both fail. **An assertion about one
sentence has to be evaluated against that sentence.**

**So: reintroduce the defect and confirm a test fails.** First passes typically
catch about half. When a mutation survives, the usual fix is the fixture, not
the assertion.

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

### 1. Whether three years back is far enough

`coverage.WINDOW_YEARS = 3` is now the single definition, read by the feed
gather, by the coverage figure and by feedlab. They had drifted: feeds read two
years while coverage measured three, so every 2024 CNA counted as covered was
measured against ids the pipeline could not surface.

Going further back is a judgement about relevance, not cost. Widening from two
to three was measured at debian +1.0s and alas +0.0s, because these feeds
download in bulk and filter locally.

### 2. The review panel's list, `docs/reviews/REVIEW-round9.md`

24 FIX items and 12 DELETE items, ranked, with the refuted items recorded
separately so they are not silently lost. F2, the blocker, is fixed. One
reader-facing item remains:

- **F1.** The front page promises a correction route that
  `.well-known/security.txt` denies on the same origin.

Done: D1, D2, D3, D5, D6, D7, D10, D11, D12, and the F3/F4 prerequisites.
`SCHEMA_VERSION` is 4 and `tests/test_schema.py` now pins the column set to the
version, so removing a column without bumping fails the suite.

Done: every FIX prerequisite and DELETE item except one.

NOT done, with the reason: **D11's `table.rbp` removal**. The component renders
nowhere, but `rbp.breakpoints.card_layout_boundary()` parses
`table.rbp thead { display: none }` out of the stylesheet to derive the render
sweep's breakpoint, and five a11y tests assert against it. That is a subsystem
change, not a deletion, and two attempts at it in one sitting each broke the
dark-theme contrast rule, which shares one body across three selector lines.

The panel's own balance was 21 removals against 7 additions. Prefer the DELETE
list when in doubt; this project's documented failure mode is accreting guards
and caveats around a list and its links.

### 3. FEEDS.md section 3's three remaining guards

Per-feed shrink baselines surviving a profile change; a failure budget expressed
as a fraction rather than a count; `gather` parallelised while preserving
per-feed health recording exactly.

### 4. Rehearse the withhold lever end to end

`RBP_WITHHOLD` drops rows from every published artefact and is tested, but has
never been exercised against a real run.

### 5. Loose threads from the uncapping

SUSE, Red Hat's CSAF endpoint and CERT-Bund each hold far more than one budget
can read, so the count climbs over several runs rather than jumping.

### 6. `ubuntu-osv` landed with two things unfinished, both blocked on one host

`feed_ubuntu_osv` was merged 2026-08-31 on the Ubuntu Security Team's own
recommendation. Scorecard in `feedlab/ubuntu-osv.json`, reasoning and every
measurement in `FEEDS.md` under "MERGED 2026-08-31". Two follow-ups, and they are
blocked on the same thing:

**a. The baseline was never rebuilt, so `test_feedlab.py::
test_the_recorded_baseline_describes_the_profile_that_actually_runs` is red.**
Not an oversight. `ubuntu.com/security/` answered 503 and then timed out for the
whole afternoon of the merge, so the rebuild produced `[ubuntu] 80 rows, 750.2s`
against its usual 3,994. Committing that baseline would have made every future
candidate look better than it is, in exactly the direction that test's own
docstring warns about, so the good 13-feed baseline was kept. **Re-run
`python -m rbp.feedlab baseline --years 2025,2026` when `ubuntu.com` is healthy,
confirm `[ubuntu]` comes back near 3,994 in the log before trusting it, and
commit.** Check the endpoint first; it costs 20 minutes to find out afterwards.

One local artefact of that aborted run is worth knowing about before it confuses
you. `data/feedlab/ubuntu.fetches.json` (gitignored working state, not in any
diff) now holds a single fetch of **80 ids**, from the outage. `stability` takes
min and max over the whole history, so until ubuntu is fetched again its swing
will read as ~98%. That is a true record of a real outage rather than noise, and
it is being kept for that reason, but do not read it as normal variation.
`ubuntu-osv` in the same directory has three fetches at 15,500 and a 0.0% swing.

**b. Then run `python -m rbp.feedlab audit` and answer whether `feed_ubuntu` is
still worth 1,070s and 355 MB.** `ubuntu-osv` reaches 15,500 ids to the tracker's
3,994 and beats it on every scorecard axis, but it is **not a superset**: 31.9% of
the tracker's ids have no OSV record. All the RBP candidates in that 31.9% are
already sighted elsewhere, so the tracker's remaining contribution is *sightings*,
which feed `cnas_effective`, which is the gate. The audit is the only thing that
can price that. Two things push the other way and must be costed in: the tracker's
endpoint is what `resolve_dates_ubuntu` queries by name (130 rows still depend on
it), and on 2026-08-31 the two feeds demonstrably failed independently. **Do not
delete `feed_ubuntu` before the audit.**

---

## Settled, so they are not re-opened by accident

Each of these was decided with reasoning that is in `git log`. Re-litigating one
costs a session.

- **No attribution.** No CNA is named on any row, in any field, in any format.
- **The corroborated / independent-origin count is gone**, not repointed. It
  produced a second headline beside `summary.total`.
- **The launch-day epoch is retired, unused.** Setting it now would take a
  publicly indexed count to zero. The lever works and is kept as insurance.
- **The front page opens on the last 90 days**, announced above the rows with a
  control that clears it. Unfiltered and oldest-first, the first screen was ten
  near-identical rows naming one vendor's platform.
- **There is no removal channel and no email address on the site.** The embargo
  case has no route here, and that cost is real and stated.
- **The hedge above the rows is gone.** A reader who copies rows into a ticket
  carries the rows and none of the qualification. Stated because it is a real
  reduction in disclosure.
- **`/method` publishes no launch checklist.** A launched site publishing its own
  pre-launch conditions reads as a site that has not launched.
- **UI chrome is title case.** Control labels, options, optgroups, buttons.
- **The About/panel duplication stays**, on measured evidence.
- **CSAF provider identity is DERIVED, not in `sources`.** `?src=csaf:cisa` is
  built in the template from `refs`. Putting the host in `sources` breaks
  `origin_kind` (an unmapped slug reads as a tracker and silently stops the
  72-hour clock), changes `feed_count`'s meaning, collides with the 250-char
  `refs` truncation, and breaks every `?src=csaf` link already shared. The
  review panel reached the same conclusion from six directions.

---

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

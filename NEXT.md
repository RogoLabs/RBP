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

**The read cursor is BUILT AND SWITCHED OFF.** `incremental=False`. It caches
the read position but not the result, and this pipeline needs the result: a
caught-up provider correctly returns nothing and every id whose only evidence
was that provider drops off the site. It shipped, shrank the live list, and was
turned off the same day. See "What is open" below. Do not turn it on without
reading that entry.

---

## What is open

### 1. The year window. A scope decision, and it is Jerry's.

`--years` defaults to the current year and the previous one, so runs use
`[2025, 2026]`. An uncapped sweep of all seventeen CSAF providers on 2026-08-29
found 422 reserved, publicly referenced IDs the site does not have. **104 of
them are 2024-numbered and the window excludes them permanently**, including
every one over 700 days: `CVE-2024-31884` at 971 days, `CVE-2024-0234` at 968,
and a long CERT-Bund tail in the 860 to 960 range. The site's oldest visible row
is 572 days.

Widening to 2024 is a one-flag change and roughly doubles the age ceiling the
site can show. It also enlarges every feed's fetch, so measure it against the
job budget first. Not done, deliberately.

### 2. The review panel's list, `docs/reviews/REVIEW-round9.md`

24 FIX items and 12 DELETE items, ranked, with the refuted items recorded
separately so they are not silently lost. Two are reader-facing today:

- **F2, blocker.** Land on `/`, paste a CVE ID public for more than 90 days, and
  the page says "Nothing matches", because `DEFAULT_AGE = "90-"` is applied
  alongside the text filter. That is exactly what happens when someone follows a
  link from an outreach email holding one ID.
- **F1.** The front page promises a correction route that
  `.well-known/security.txt` denies on the same origin.

The panel's own balance was 21 removals against 7 additions. Prefer the DELETE
list when in doubt; this project's documented failure mode is accreting guards
and caveats around a list and its links.

### 3. Finish the CSAF read cursor, or delete it

`incremental=False` in `rbp/feeds.py`. The marks, the plan and the budget are
correct and tested. What is missing is that **the state carries two timestamps
and not the references**, and `gather` builds the reference set from what each
adapter returns on the current run, so a provider that reads nothing contributes
nothing.

Measured live, 2026-08-29 22:21Z, the first run able to restore the cursor
cache: twelve of seventeen providers reported "+0 new (0 in scope)", every word
true, and the list fell 1,769 to 1,760 while the CSAF publisher facet went from
five publishers to two. All eight CISA rows vanished. `/status` published
`csaf:www.cisa.gov  OK  0 ids  caught up across all 1,833 advisories`, an
accurate sentence about a provider whose rows had just been erased. That is the
silent shrink this adapter exists to prevent, introduced by the change that
removed the cap to stop losing rows.

To finish it, the per-provider state has to hold the references it has seen and
replay them for a caught-up provider. Roughly 22,000 ids at a few hundred bytes,
the same order as `data/ghsa_repos_state.json` already in the Actions cache.

`test_a_caught_up_provider_still_returns_its_rows` is the property that was
missing, and is marked `xfail(strict=True)`. Every other cursor test asserted
what was FETCHED; none asserted what was RETURNED, which is how a change that
fetched nothing and returned nothing passed all of them. Fixing the cursor makes
that test XPASS and fails the suite, which is the prompt to remove the marker.

Deleting the cursor is a legitimate answer. Without it every run re-reads each
provider inside the time budget, which is what happens today and is already far
better than the old cap: cold runs read 10,838 and 21,810 ids where the cap
yielded 4,416.

### 4. FEEDS.md section 3's three remaining guards

Per-feed shrink baselines surviving a profile change; a failure budget expressed
as a fraction rather than a count; `gather` parallelised while preserving
per-feed health recording exactly.

### 5. Rehearse the withhold lever end to end

`RBP_WITHHOLD` drops rows from every published artefact and is tested, but has
never been exercised against a real run.

### 6. Loose threads from the uncapping

SUSE, Red Hat's CSAF endpoint and CERT-Bund each hold far more than one budget
can read, so the count climbs over several runs rather than jumping.

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

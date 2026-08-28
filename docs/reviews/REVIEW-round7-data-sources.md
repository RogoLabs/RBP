# Round 7: the data sources, and what expansion is actually cheap

Written 2026-08-27, after round 6 closed. Same rule as round 6: every figure below
was measured, once against the repo at `3b806a1` and once against the live
`origin/data` snapshot for 2026-08-27 or the upstream source itself. Where a
figure is a probe rather than an adapter measurement it is labelled, because
FEEDS.md has now had two estimates cancelled by measurement in opposite
directions and a third is cancelled in this document.

**Status, updated 2026-08-27 after the first pass.** Round 6 was written against
a launched front end and closed inside a day. This one is written against a
pipeline that is green, publishing four times a day, and clearing its gate at 42
of 50. The findings are not outages. They are the difference between what the
pipeline reports about itself and what it is doing.

**Everything in this document is closed except B3's second half, M4 and E3**,
which are one decision and one project, both named below. Every blocker, every
high item and every medium is done; E1 is merged behind its own scorecard, E4 is
rejected on measurement and E5 is re-costed. The suite went from **852 to 898
offline tests**, and the whole set was verified against a live pipeline run and a
site build, not only against fixtures.

Completed items are marked inline rather than deleted, because the reasoning is
the record.

**Five defects were found by the fixes rather than by the review**, including one
in a fix for a finding in this document, one that had made a five-day-old
measurement in FEEDS.md unsound, and one where the publication guard refused this
review's own work and was right to. All five are under "Found while fixing".

**The four D-list questions are still yours.** Nothing below decides them.

---

## First, the thing to agree on

**This is a GitHub advisories tracker with distro corroboration, and no surface
says so.**

Of the 1,709 rows published on 2026-08-27:

| | rows touched | rows that exist only because of it |
|---|---:|---:|
| `ghsa` + `ghsa-repos` | 1,436 (84.0%) | **1,021 (59.7%)** |
| `osv` | 415 | 40 |
| `alas` + `ubuntu` + `debian` + `alpine` + `redhat` | 196 | 132 |
| `csaf` + `msrc` + `samsung` + `mozilla` + `arch` | 110 | 88 |

`ghsa-repos` alone is 1,188 rows and is the **sole** source for 1,015 of them.
1,156 of the 1,709 rows (67.6%) carry exactly one source.

That single feed shipped yesterday, has never been scored by the harness that
exists to score it, and reads from a hand-curated file of 1,875 repositories whose
own header says it does not refresh itself. It is the site.

None of this is wrong. A GitHub-heavy result is the honest consequence of where
ecosystem-less repository advisories live, and `ghsa-repos` was written precisely
because those advisories reach no other endpoint. The problem is that thirteen
feeds are advertised, `/status` prints thirteen row counts, and the reader has no
way to learn that two of them have never put a row on the page and that one of
them is six tenths of it.

**And the cheap expansion is close to spent.** Round 7's second half is the
expansion review that was asked for, and its finding is that the two candidates
`NEXT.md` currently recommends do not have the routes that recommendation assumed,
a third is rejectable today for 17MB and no code, and what remains that is
genuinely cheap is not a new feed at all.

---

## Blockers: fix before the next feed goes in

### B1. The feed that is 69% of the site was merged without a scorecard. FIXED 2026-08-27

`feedlab/README.md`, line 3: *"no feed is merged without its scorecard in the
diff."*

`feedlab/_audit.json` scores twelve feeds: `alas`, `alpine`, `arch`, `csaf`,
`debian`, `ghsa`, `mozilla`, `msrc`, `osv`, `redhat`, `samsung`, `ubuntu`.
`ghsa-repos` is not among them, and it is not in `_baseline.json` either. It
shipped on 2026-08-26 in `8e3479d` and now carries 1,188 of 1,709 rows.

So the rule was written, tested against twelve feeds that predate it, and broken
by the first feed merged after it, which is also the largest contributor the
project has. There is no `cnas_new_effective` for it, no `lead_n`, no
`unpublished_n`, and no verdict. The site's dominant source has never been asked
either of the two admissibility questions.

This is not a claim that it would fail. It would almost certainly score
`detecting`: the file header records 150 of 150 sampled RESERVED ids absent from
the global endpoint, which is `unpublished_n` evidence in everything but name.
The point is that the number is not in the diff, so nothing can be compared
against it later, and the one feed whose collapse would take six tenths of the
site has no recorded baseline to collapse from.

**What landed.** The baseline was rebuilt over all thirteen feeds and `audit`
re-scored every one of them. `ghsa-repos` scores **`detecting`**, and not
narrowly:

```
              verdict      new CNAs   lead   unpublished   secs
ghsa-repos    detecting           4  5,771         1,231  146.7
csaf          detecting          13    610            61  163.2
ubuntu        detecting           3     20           102 1070.6
mozilla       corroborating       0     34             0    5.5
arch          unmeasurable        0      0             0    3.0
```

`lead_n` 5,771 and `unpublished_n` 1,231 are the highest of any feed by a wide
margin, which is what you would expect from the feed that exists to read
advisories no other endpoint carries. Its four marginal CNAs are `ClickHouse`,
`Gridware`, `ThinkstAppliedResearch` and `zephyr`.

So the prediction in this section was right and that is not the point. The point
is that it is now **in the diff**, so the next person can compare against it, and
`test_every_feed_in_the_running_profile_has_a_scorecard` fails the build if any
future profile feed arrives without one.

### B2. The scorecard baseline is stale, and the error points the wrong way. FIXED 2026-08-27

`feedlab/_baseline.json` was scored at 2026-08-24T14:38Z. Its `per_feed_rows`
against today's run:

```
            baseline    2026-08-27
ghsa           3,321        10,832      +226%
csaf           3,190         2,695       -16%
debian        17,335        17,901
redhat        16,185        16,468
ghsa-repos         -         9,861      absent entirely
```

`ghsa` tripled because `8e3479d` replaced the 40-page cap with a windowed read.
`ghsa-repos` did not exist. Every marginal figure a future `feedlab score`
produces is marginal to a merged set that is roughly 20,000 ids smaller than the
real one.

**The direction matters.** A baseline that is too small makes a candidate look
like it reaches CNAs nobody else reaches, because the feeds that already reach
them were measured before they could. A stale baseline does not make the harness
cautious. It makes it permissive, and the next scorecard it produces is the one
that decides whether TWCERT gets two days of work.

`README.md` says `baseline` takes about 20 minutes and is the only command that
fetches the whole merged set. It has not been re-run through three merges and one
adapter rewrite.

**What landed.** Rebuilt 2026-08-27: **39,405 ids, 141 effective roster CNAs,
1,576.8s, 1,247 MB**, over all thirteen feeds.
`test_the_recorded_baseline_describes_the_profile_that_actually_runs` now fails
the day the two diverge.

**And the rebuild reproduced this defect inside its own fix.** The first attempt
passed `--years 2024,2025,2026`, which looks like the site's window and is not:
`coverage_years` is 2024-2026, but the pipeline GATHERS `{2025, 2026}`. It took
`alas` from 11,674 rows to 16,026 and would have recorded a merged set the
pipeline never reads, which is precisely B2. Caught by comparing the first log
line against the live snapshot before letting it finish.
`test_the_baseline_gathers_the_years_the_pipeline_gathers` is the guard for it.

### B3. Ubuntu is read over five weeks, not three years, and nothing says so. HALF FIXED 2026-08-27

Measured live against `https://ubuntu.com/security/cves.json`, 2026-08-27:

```
limit=20    200, 20 rows, total_results 75,993
limit=50    error       limit=100  error       limit=500  error
offset=0        newest row published 2026-08-26
offset=3,980    newest row published 2026-07-20     <- the adapter's last page
offset=7,980    newest row published 2026-05-22
```

`feed_ubuntu` (`rbp/feeds.py:454`) uses `page_cap=200` at the API's hard limit of
20 rows per page, so it reads 4,000 of 75,993 records, **5.3% of the endpoint**,
and on 2026-08-27 that reached back **38 days**. The window the rest of the
pipeline uses is 2024 to 2026.

The published limitation reads:

    ubuntu: hit the 200-page cap; rows beyond it were not read

Every word is true and it tells a reader nothing. The same sentence would be
published if the cap cost one day or three years. `/status` prints it beside
`3,994 ids` and an amber "Capped" chip, and a reader has no way to convert that
into "this feed sees five weeks and the others see three years."

**This exact defect was fixed for a different feed the day before this review.**
`8e3479d`, 2026-08-26, on `feed_ghsa`:

> *The cap was real and understated. `feed_ghsa` read the newest 4,000 reviewed
> advisories in one descending scan, which is 83 days ... against distro trackers
> observed over years ... at a roughly constant count every run, which is the shape
> `compare_magnitudes` reads as healthy.*

Newest-first, a fixed row cap, a reach measured in weeks against a window measured
in years, and a constant count that reads as health. Every clause of that
describes `feed_ubuntu` today, and the fix that landed for GHSA was to shard the
walk by publication month so the cap became headroom. Ubuntu's endpoint is
offset-paginated with a hard 20-row limit and no date filter, so the same fix does
not transfer, but the same finding does and it was written down 24 hours ago.

Two consequences, and the second is the one that matters:

- **Coverage.** Ubuntu's sightings are counted in `cnas_effective` on the same
  footing as `debian`, which reads its whole tracker. A CNA whose Ubuntu-visible
  CVEs are six weeks old is invisible to this feed and the coverage figure does
  not know it.
- **Cost.** `feedlab/_audit.json` records `ubuntu` at **486.2 seconds** of a
  783.8-second full-baseline fetch. One feed is **62% of the wall clock** for
  5.3% of its own endpoint, 114 published rows, and **0 rows it is the only
  source for**. `csaf` is a further 193.9s, so two feeds are 87% of the fetch.

> **The 2026-08-27 rebuild measured it far worse than that.** Ubuntu took
> **1,070.6 seconds and 355 MB** for its 3,994 rows, out of a 1,576.8-second
> baseline: **68% of the wall clock and 28% of the bytes**, for one feed. Beside
> it, in the same run:
>
> | | rows | seconds | MB |
> |---|---:|---:|---:|
> | `ubuntu` | 3,994 | **1,070.6** | 355 |
> | `debian` | 17,909 | **1.5** | 87 |
>
> Debian reads **4.5x the rows in one seven-hundredth of the time**, over the
> whole window rather than five weeks. Whatever the answer to the cap is, this is
> the comparison that has to be in front of it.

**Fix, in order of what it buys:** first make the health line say what the cap
costs in time, not in pages, since that is a string change and it is the part a
reader sees. Then decide whether the cap moves. The endpoint is newest-first, so
a deeper read is purely a question of how many sequential 20-row pages the run
will pay for, and `gather` is still a serial loop (M4).

### B4. Two of the thirteen advertised feeds have never put a row on the site. FIXED 2026-08-27

Every source string in the 2026-08-27 backlog, checked against
`summary.feeds.requested`:

```
contributing to zero published rows:  mozilla, arch
```

- **`mozilla`**: 607 ids per run, 6.0s, on every run since 2026-08-22, and 607 on
  every single one of the six published snapshots. Its own scorecard says
  `corroborating`: `lead_n` 34, `unpublished_n` **0**, `cnas_new_effective` **0**.
- **`arch`**: 62 ids per run, 1.5s, 62 on all six snapshots. Its scorecard verdict
  is `unmeasurable`: 0 lead, 0 unpublished, 0 new CNAs. `feed_arch`'s own
  docstring says it is not a CNA and its rows are undated, so it cannot even feed
  the clock.

Four runs a day, 669 ids fetched, zero rows.

`mozilla` has a defence and `arch` does not. Mozilla is one of the three
`cnas_own_channel` names `/method` publishes, so it earns its place on the
coverage side even while contributing nothing to the backlog. Arch earns nothing
anywhere: 0 new CNAs, 0 detection, no dates, no CNA.

**What the reader sees is the real defect.** `templates/status.html:238-262`
renders one row per feed with `h.rows`, which is **ids fetched**. `templates/
method.html:283` prints the full requested list. Nothing on the site distinguishes
ids fetched from rows published, so "arch OK 62 ids" reads exactly like "csaf OK
2,695 ids", and csaf is the sole source for 22 rows while arch is the sole source
for none.

**Fix:** publish rows-contributed beside ids-fetched on `/status`, which is the
honest column and makes both of these visible without an argument about deletion.
Then take `arch` out, or record in `feedlab/arch.json` why an `unmeasurable` feed
is kept.

### B5. `compare_magnitudes` cannot see a CSAF provider go dark, and the code says so while relying on it. FIXED 2026-08-27, and it fired the same night

`_record_csaf_health` (`rbp/feeds.py:1477`) writes **one** health record for all
17 providers, with one `rows` total. `feed_osv` (`rbp/feeds.py:1047`) calls
`record_feed(f"osv:{eco}", ...)` per ecosystem, so `health_detail` nests eleven
`parts` under `osv` and `compare_magnitudes` compares each one at `PART_DROP`.

CSAF has no parts. Its own docstring leans on the guard that cannot do the job:

> *A provider that was working and stops is caught by `compare_magnitudes`, which
> compares this feed's row count to its own previous run and IS a degradation.
> That is the mechanism for "worse than usual", and it already exists.*

It exists at the aggregate. csaf's totals across five published runs:

```
08-23  3,296     08-24  3,202     08-25  3,938     08-26  2,213     08-27  2,695
```

That is a 44% swing inside one week on a feed of 17 providers, and only the
08-25 to 08-26 step crossed `MAGNITUDE_DROP`. A provider holding 8% of csaf's ids
can stop entirely and land inside that noise permanently.

This is the SUSE failure with the serial numbers filed off. SUSE dropped 14,486
in-scope advisories, was reported as "no advisories in scope", and the aggregate
absorbed it. The fix that landed corrected the parsing bug. It did not give the
adapter the per-provider instrumentation that would have named the loss.

**Fix:** `record_feed(f"csaf:{publisher}", ...)` per provider, exactly as OSV
does. The fan-out already tracks per-provider rows to build the health string; it
throws the numbers away and keeps the prose.

> **It earned its keep on the first live run after it shipped.** The 2026-08-28
> build published:
>
>     csaf:www.suse.com: provider unreachable: Expecting value: line 1 column 1
>     csaf: 16/17 providers read; 2789 ids
>
> **SUSE**, of all providers, went unreachable that night, and it is named on its
> own limitation line with its own row count of zero. Under the previous
> instrumentation this would have been one aggregate moving 2,992 to 2,789, a 7%
> dip well inside `MAGNITUDE_DROP`, with the provider's name appearing only if it
> happened to fall inside a list truncated at six.
>
> That is the same provider whose silent loss of 14,486 advisories is the worked
> example this finding was argued from. Recorded here rather than in a commit
> message because a guard that fires within hours of shipping is the strongest
> evidence a review can offer that the finding was real.

---

## High: worth fixing in the same pass

### H1. A feed frozen at a constant is indistinguishable from a healthy one. FIXED 2026-08-27

`mozilla` returned exactly 607 on all six published snapshots. `arch` exactly 62
on all six. `samsung` exactly 420 on all five since it shipped. `compare_magnitudes`
compares run to run, so a feed that has silently stopped updating never drops and
never fires.

`tests/test_ghsa_feeds.py:11` already names this shape for GHSA and calls it "a
standing truncation that reads as a healthy feed." The same hole is open for every
low-cardinality feed on the list, and three of them are sitting in it right now.
Samsung's 420 is probably correct, since SMR bulletins are monthly. Nothing
checks.

**The missing guard is not a count, it is a date.** No test asserts that a feed's
newest `public_date` has moved. That is one line per feed of recorded state and it
catches the one failure the row-count guard is structurally blind to.

**What landed.** `gather` records `newest`, `oldest` and `dated_rows` per feed,
generically, so thirteen adapters cannot drift out of step on it. `stale_feeds`
flags a feed whose newest advisory is past a floor, and it degrades the run:
unlike a page cap this is not a standing limit fired by design, so it stays loud
until someone fixes it.

**The floor is 45 days and it is derived, not picked.** Newest advisory per feed
over the rebuilt baseline:

```
csaf, ghsa, ghsa-repos, osv, redhat, ubuntu    0 days
alas                                           1
mozilla                                        9
msrc                                          16   (Patch Tuesday, monthly)
samsung                                       26   (SMR bulletin, monthly)
alpine, arch, debian                     undated
```

The slowest genuine cadence is monthly, whose newest advisory is legitimately
~35 days old just before the next bulletin. 45 leaves ten days of slack and still
catches a dead feed inside seven weeks. Verified against real data on the live
run: no false positives.

**Three feeds cannot be checked at all.** `alpine`, `arch` and `debian` return no
dates whatsoever, `debian` being the largest feed on the site by rows. They are
published as `freshness_unmeasurable` beside the stale list rather than silently
skipped, because letting "cannot be checked" read as "checked and fine" is the
same error as letting a page cap read as a complete read.

### H2. The corroborating rule is written in two places and enforced in none. FIXED 2026-08-27

`feedlab/README.md`: *"A feed that clears (1) and fails (2) is corroborating:
mergeable, and excluded from the coverage numerator."* FEEDS.md section 2 says the
same.

`coverage.compute` (`rbp/coverage.py:35`) takes `sources` and records them in the
output. Nothing anywhere filters a sighting by its feed's verdict. `mozilla` is
verdict `corroborating`, contributes 605 sightings, and is counted in
`cnas_sighted` (179) and `cnas_effective` (140) like every other feed.

Whether this moves the gate I cannot say without a re-run, and I am not going to
guess: Firefox CVEs are also carried by `debian`, `ubuntu` and `redhat`, so most
Mozilla sightings are probably corroborated elsewhere and the numerator may not
move at all. That is the measurement to take.

**What landed: enforced, after measuring that it was safe to.** The measurement
this section asked for, taken against the rebuilt baseline:

```
effective with every feed          141
excluding mozilla (corroborating)  141    delta 0, nothing lost
excluding arch (unmeasurable)      141    delta 0, nothing lost
```

Firefox CVEs are carried by `debian`, `ubuntu` and `redhat` too, so every Mozilla
sighting is corroborated elsewhere. Enforcing costs nothing today, which is the
only condition under which it is safe to switch on beside a gate clearing by two.

`coverage.compute` takes `corroborating=` and excludes those feeds from the gate
figure. Three things it deliberately does not do:

- It narrows `cnas_effective` **only**. `sightings`, `covered` and `observed_*`
  describe what the site actually saw and are honest as they stand; narrowing
  them would make the site under-report its own reach to satisfy a rule about a
  different question.
- It excludes the **feed**, not the row. A CVE seen by both a detecting feed and
  a corroborating one still counts, because the rule's own sentence is "it CAN
  strengthen a row it did not find". Excluding the id would make adding a
  corroborating feed *reduce* coverage.
- It does not treat `unmeasurable` as corroborating. `arch` published nothing
  datable to score, which is an absence of evidence rather than evidence it
  cannot detect, and conflating them would quietly demote any new feed whose
  first scorecard was thin.

The excluded set is published as `coverage.corroborating_feeds` so the
subtraction is auditable, and an unreadable verdict file excludes nothing and
says so rather than stopping a publication.

### H3. The gate's cheapest headroom is three CNAs nothing in the repo surfaces. FIXED 2026-08-27

`top_missed_effective` on 2026-08-27 is eight names. They are not the same kind of
miss. Sightings are from the 2026-08-27 run; window volumes are FEEDS.md's
2026-08-22 measurement against the pinned roster and have not been re-taken:

| | sightings | published in window |
|---|---:|---:|
| `dell` | **1** | 715 |
| `TR-CERT` | **1** | 526 |
| `sap` | **1** | 508 |
| `huawei` | 0 | 444 |
| `twcert` | 0 | 420 |
| `HCL` | 0 | 356 |
| `qnap` | 0 | 337 |
| `juniper` | 0 | 299 |

Three of the eight are **two sightings** from crossing the floor, not one parser
from being seen at all. `MIN_SIGHTINGS` is 3 and they are at 1. Flipping all three
takes the gate from 42 to 45 of 50.

Nothing in `feedlab` or `coverage` reports this. `top_missed_effective` and
`top_missed` are both published and the difference between the two lists is
exactly the near-floor set, but no surface says "these three are close" and
FEEDS.md section 4 sequences the tail by volume descending, which puts `dell`
first for the right reason and gives no weight at all to how close it already is.

**Fix:** a `feedlab near-floor` report listing roster CNAs at 1 or 2 sightings with
the feed that sighted them. It is an offline query over data already in
`summary.json`, and it changes which parser gets written next.

### H4. `ghsa_repos.txt` decays and no guard measures the decay. FIXED 2026-08-27

From the file's own header:

> *NOT SELF-REFRESHING. Discovering a repository that publishes its FIRST advisory
> is a mining problem and it is not solved here: a new publisher is invisible to
> this file until the list is widened.*

1,875 repositories, frozen 2026-08-26, drawn from a 10,000-repo sweep that kept
89% of the yield for 17% of the cold-start request budget.

The header is honest and the decision was right. The gap is that the site's
largest source degrades continuously in a direction no number tracks: the id count
stays healthy while the share of the real population it can see falls. A
`compare_magnitudes` drop cannot fire, because the repos on the list keep
publishing.

**Fix:** record the sweep as a job rather than as a past event, with a date on the
file and a `/status` line for how old the list is. Re-running it is the expansion
item with the best measured yield in this document (see E3).

---

## Medium: in rough priority order

**M1. `deep` is dead config. FIXED 2026-08-27.** `rbp/cli.py:40` defines `weekly` and `deep` as
byte-identical strings. The comment says it is kept "so a future heavy source has
somewhere to go," which is a fair reason to keep the name and not a reason to keep
`--profile` in `deploy.yml` describing a choice that does not exist. `/status`
publishes `profile: weekly` as though the alternative were meaningful.

**M2. `stability` is null on all twelve scorecards. FIXED 2026-08-27.** FEEDS.md
section 3 asks for three fetches 24 hours apart; no feed had them. `README.md`
already says "returning one anyway is how a scorecard field becomes decoration,"
and the field was decoration on every merged feed. The cause: only `score` called
`record_fetch`, and every merged feed had been scored by `audit`, which is
offline by design. It now accrues in `build_baseline`, the only place a real
fetch of every feed happens, and `audit` READS the history without appending.
That distinction is the whole fix: appending in `audit` would replay one
baseline's stored rows N times and report a 0% swing over N "fetches" that were
one fetch. A fabricated perfect reading is worse than null, because null says
"not measured" and 0% says "measured, and perfect".

**M3. Huawei is closed and should be written down as closed. FIXED 2026-08-27.** FEEDS.md already
records it: `www.huawei.com` serves provider metadata listing 121 per-advisory
directories, every one of which answers 401. The `capped: www.huawei.com
12/121 directories` note disappeared from the health line between 08-26 and 08-27
while huawei stayed in "no advisories in scope," which is the correct behaviour
after the cap fix and reads like a regression. One sentence in `CSAF_PROVIDERS`
saying "reachable, unreadable, do not re-probe" saves the next person the sweep.

**M4. `gather` is a serial loop.** `rbp/feeds.py:1670`. 783.8 seconds of fetches
in sequence, of which `ubuntu` is 486.2 and `csaf` is 193.9. Already on NEXT.md's
list as the third of FEEDS.md section 3's remaining guards, correctly scoped as
"preserving per-feed health recording exactly." B5's per-provider records land
first, since parallelising the recording and then changing its shape is two
migrations.

**M5. FEEDS.md and the code disagree about OSV. FIXED 2026-08-27.** FEEDS.md Tier 1 says "OSV
currently reads 6 of 46 ecosystems" and instructs "merge GIT and Android and the
remaining 27 anyway." The adapter now reads **11 of 46**: the original six plus
`Packagist`, `NuGet`, `Pub`, `Hex` and `Android`. GIT was correctly not merged
after the correction. The other 27 were neither merged nor un-recommended, so the
document still carries an instruction that was half executed. See E1 and E2 for
what the remainder is actually worth.

---

## Where the data layer is already in good shape

Worth saying, because the list above is uniformly critical and the tree is not.

- **The admissibility split is real and it works.** `feedlab` asked both questions
  of twelve feeds, and the answers were not all flattering. `mozilla` was
  labelled `corroborating` and `arch` `unmeasurable` by the project's own harness,
  months before this review noticed either contributes zero rows. The harness
  found it first. What failed is that nothing acted on the verdict.
- **Health states are genuinely load-bearing.** `OK` / `CAPPED` / `TRUNCATED` /
  `FAILED` carry different meanings all the way to whether a banner renders, and
  the distinction between a standing limit and a degradation is argued out in the
  code rather than assumed. The 08-25 and 08-26 runs both published
  `degraded: true` with accurate reasons.
- **The two 403s were separated correctly.** Cisco's edge wanted a
  scheme-qualified crawler identity; CISA's blocks cloud egress and no header
  reaches it. One health line, two causes, two different fixes, and the pinned
  CISA route announces itself on every run instead of hiding.
- **Estimates get cancelled by measurement, repeatedly, and the cancellations are
  written down.** GIT (+18 claimed, +0 delivered), the Android bulletin parser
  (cancelled by scoring OSV's ecosystem first), SUSE, `www.sick.com`. This
  document adds one more, and the only reason it was cheap to add is that FEEDS.md
  established the habit.
- **Evidence links survive the feed they came from.** `report._u` now has a branch
  for `csaf` and `ghsa-repos`, each pointing at the advisory itself. All 1,709
  published rows carry an `http` advisory URL.

---

## The expansion, scored before it is written

The ask was "any easy expansion we can do." The honest answer is that the easy
half is spent, one candidate is rejectable today, two are not what the current
plan believes they are, and what is left that is genuinely cheap is not a feed.

Everything in this section was measured on 2026-08-27. Rows marked **probe** are
upstream measurements, not adapter measurements, and FEEDS.md's rule applies: a
probe is not a yield.

### E1. The eight small OSV ecosystems. 346KB, one config line. **DONE 2026-08-27, four merged.**

Sizes fetched from the OSV bucket:

```
GitHub Actions   99,027      SwiftURL   106,669     Hackage   51,080
opam             48,706      VSCode      21,448     CRAN      12,434
GSD               5,644      UVI          1,091
                                          total    346,099 bytes
```

Against `osv`'s current 305MB per run, this is 0.1%. FEEDS.md measured all 29
unmerged ecosystems at **+0 new effective CNAs** on 2026-08-22, and that
measurement stands. What was never measured for any of them is `unpublished_n`,
the detection half, which is the half this site is about. `GitHub Actions` and
`SwiftURL` in particular carry advisories against repositories rather than
registries, which is the population `ghsa-repos` exists for.

**Scored as their own candidate before anything was merged**, which is the point
of the harness: the thing scored is the thing being decided about, not the whole
feed it would fold into.

```
osv-small   58 ids, 6 not already seen, 0 marginal CNAs, 7 unpublished now
            disclosure lead on 24 of 51 dated references, median 13d, max 97d
            1.1s, 0.3 MB          VERDICT: corroborating
```

So it fails test 1 and **clears test 2**, which is exactly the case FEEDS.md
section 2 says may be merged: "corroborating is not a soft rejection." It buys no
coverage and no gate movement and is not counted as either. What it buys is seven
currently-unpublished ids for a tenth of a percent of this adapter's bandwidth.

**Merged: `GitHub Actions`, `SwiftURL`, `Hackage`, `opam`.** `VSCode`, `CRAN`,
`GSD` and `UVI` returned zero in-scope ids and were deliberately left out and
recorded as measured-at-zero with the date, so the next person does not re-probe
them. Scorecard committed at `feedlab/osv-small.json`.

**And the attempt found a latent bug worth more than the merge.** See F3 below:
`feed_osv` could not fetch any ecosystem whose name contains a space, which is
five of the 46, including three named in this document's own merge instruction.

### E2. The six large OSV ecosystems. 195MB. **Do not, on this evidence.**

```
MinimOS 67.1MB   Linux 55.2MB   Chainguard 30.0MB
Wolfi   19.3MB   Root  14.2MB   Bitnami     9.2MB
```

Every one is a distro or rebuild channel for packages the existing feeds already
read, which is exactly the category FEEDS.md measured at +0. 195MB per run, four
runs a day, for a measured zero on the coverage side and no reason to expect
better on the detection side. Score `Linux` alone if anyone wants to test the
premise, since kernel CVEs are the one plausible exception.

### E3. Widen `ghsa_repos.txt`. **The highest expected yield in this document.**

No adapter, no parser, no new third-party dependency. The discovery method
already exists and already ran once: a 10,000-repo sweep that kept 1,875 for 89%
of the measured yield. The feed it feeds is 69% of the site.

The reason it is the best item here is arithmetic. Every other candidate is a bet
on a CNA that our feeds see zero times. This one widens the aperture on the
population that has already produced 1,015 rows nothing else found.

It is not free: the cold start is one request per new repo against the GitHub API,
and the file header records that the poll amortises across runs via a saved
cursor. Budget it as a discovery job with a rate-limit ceiling, not as a text-file
edit, and land B1's scorecard first so there is a baseline to measure the
widening against.

### E4. GitLab advisory database. **Reject. Measured today, no adapter written.**

FEEDS.md Tier 2 lists this as "repo 200; mixed, overlaps GHSA heavily; unknown,
likely low." Downloaded and measured, 2026-08-27:

```
archive                17.1 MB
advisory files         51,818
distinct CVE ids       31,396      in window 2024-2026: 13,211
files citing a GHSA    41,656      (80.4%)
newest pubdate         2026-07-28
ecosystems             npm, maven, packagist, pypi, go, nuget, cargo,
                       gem, conan, swift, pub
```

Two facts kill it, and the second kills it permanently. 80% of the advisories are
GHSA re-publications, and every ecosystem present is one OSV already covers. Then
the repository's own `.gitlab-ci.yml`:

    yq -N 'select((now | to_unix) - (.pubdate | to_unix) > 30*24*3600) | filename'

The community mirror syncs **only advisories older than 30 days**, by design. The
newest `pubdate` in the archive is 2026-07-28, exactly 30 days before the fetch.

A feed with a mandated 30-day publication lag cannot clear admissibility test 2 at
any effort, because by the time it carries a reference the ID has had a month to
be published. It is not a weak detector. It is structurally incapable of being
one, which is the exact failure mode FEEDS.md section 2 was written to catch.

Cost of establishing this: one 17MB download and reading someone else's CI file.
Cost of the alternative: a YAML parser over 51,818 files and a scorecard to find
out the same thing. **Third estimate in this project cancelled by measurement.**

### E5. The national CERTs, re-probed. **The current recommendation does not hold.**

`NEXT.md` recommends: *"Buy margin first. Target TWCERT and TR-CERT, the two that
probed 200 on their own advisory sites. Two CNAs for two days."*

Re-probed 2026-08-27:

| | result |
|---|---|
| `twcert.org.tw/tw/lp-132-1.html` | 200, 30KB of HTML, Traditional Chinese listing page |
| `twcert.org.tw/en/lp-132-1.html` | **302**, no English locale at that path |
| `twcert.org.tw/{tw,en}/rss-100.xml` | **404** both locales |
| `usom.gov.tr/` | 200, 7,091 bytes |
| `usom.gov.tr/bildirim` | 200, **7,091 bytes** |
| `usom.gov.tr/rss.xml` | 200, **7,091 bytes**, `Content-Type: text/html`, a full HTML page |

**TR-CERT serves the same 7,091-byte HTML document at every path tried, including
`/rss.xml`.** There is no machine-readable route behind that 200. TWCERT has a
real listing page and no feed, so it is an HTML scrape against a Chinese-locale
CMS with pagination, in the same family as the Android bulletin parser that was
cancelled for being fragile.

FEEDS.md's own CSAF probe already recorded `dell`, `TR-CERT`, `HCL` and `juniper`
as "200 but not CSAF (an HTML error page)". The Tier 2 national-CERT row still
counts TR-CERT's 200 as a positive signal. It is the same 200.

Also re-probed, since they were in the same row: JVN RDF 200 (17KB, real RDF),
MyJVN `getVulnOverviewList` 200 (86KB, real XML), CERT-FR `/avis/feed/` 200 (22KB,
real XML). All three are usable. JVN and MyJVN map to `jpcert`, already
effective at 12 sightings. CERT-FR maps to ANSSI, which appears nowhere in the
top-50 miss list, so whatever it is worth it is not gate margin. Real feeds, no
established marginal CNA, and each would still need a scorecard to claim one.

**Two days is not the cost of TWCERT and TR-CERT.** Re-cost them before budgeting,
or pick a different pair.

### E6. The rest of the top-50 misses, probed. Nothing is a config line.

| | probe, 2026-08-27 |
|---|---|
| `dell` | `/support/security/en-us/api/security-advisories` 404; CSAF well-known 403 |
| `sap` | CSAF well-known 403 (WAF); document routes 403 |
| `qnap` | `/en/security-advisories` 200, **190KB of HTML containing zero CVE ids and zero QSA ids** (JS-rendered) |
| `juniper` | both known advisory routes 301 into a portal |
| `HCL` | `support.hcl-software.com/csm` 200, 210KB ServiceNow portal shell |
| `huawei` | CSAF metadata 200, all 121 directories 401 (settled, see M3) |

Six of eight are behind a WAF, a JS renderer, or authentication. This is
consistent with FEEDS.md's CSAF sweep conclusion and extends it past CSAF: the
gate's remaining misses are not missing because nobody wrote a parser. They are
missing because there is nothing to parse without a headless browser, and this
plan does not authorise pretending to be one.

---

## Decisions for you, not defects

### D1. Does the tail get sequenced by volume, or by distance to the floor?

FEEDS.md section 4: *"Sequence the tail by volume descending... That ordering is
also the ordering that maximises the chance of finding real RBPs, which is the
point of the exercise rather than the number."*

That reasoning is sound and it is now in tension with H3. Volume-descending puts
`dell` (715 CVEs, 1 sighting) ahead of nothing in particular. Distance-to-floor
puts `dell`, `TR-CERT` and `sap` together as three CNAs needing two sightings
each, and says nothing about which is likeliest to yield an RBP.

They are different objectives. Volume optimises the mission, distance optimises
the gate, and right now the gate is what has a margin problem. My read: measure
both, publish the near-floor list, and let the ordering be an explicit choice per
feed rather than a standing rule. But it is your call whether the gate is allowed
to influence the ordering at all, given that the whole project exists to argue
against moving a number to meet a measurement.

### D2. Does `arch` stay?

0 rows, 0 new CNAs, 0 lead, 0 unpublished, no dates, not a CNA, 1.5s per run,
four runs a day, verdict `unmeasurable`. The only argument for keeping it is that
rolling-distro breadth might matter later. The argument against is that it is on
`/status` and on `/method` telling a reader it is one of thirteen sources.

If it stays, the reason belongs in `feedlab/arch.json` so the next reviewer does
not re-derive this.

### D3. Does `/status` publish rows-contributed?

B4's fix is a new column, and a new column is a claim. "arch: 62 ids, 0 rows" is
the most honest line the status page could carry and it is also an invitation to
ask why arch is there. That is the right conversation to have in public and it is
still a choice.

### D4. Is 69% concentration in one feed acceptable, and does the site say so?

`/method` publishes coverage three ways and none of them is "where the rows come
from." A reader who wanted to know that 1,015 of 1,709 rows rest on GitHub's
per-repository advisory API and a hand-curated repo list cannot learn it from the
site.

Publishing it is a small change and a large admission. Not publishing it means the
concentration is discoverable only from `data/rbp.csv`, which is at least public.

---

## What is deliberately not done

Three items, and none of them is an oversight.

**B3's second half: the Ubuntu cap itself.** The disclosure is fixed and the
health line now states the cost in days. Whether the cap MOVES is a question about
how much wall clock the run will spend, it is inseparable from M4, and the honest
answer needs a number nobody has: the endpoint offers no date filter, so the only
way to learn what a full three-year read costs is to walk it. At the measured rate
that is several hours. It should be measured once, deliberately, not guessed at
inside this pass.

**M4: `gather` is a serial loop.** Already on NEXT.md as the third of FEEDS.md
section 3's remaining guards, correctly scoped as "preserving per-feed health
recording exactly". It is now more urgent than when that was written, since Ubuntu
is 68% of the wall clock rather than 62%, and it is also more delicate, since the
health recording it must preserve now includes per-provider CSAF parts and
per-feed date spans. Parallelising the recording and then changing its shape is
two migrations; this pass changed the shape, so the parallelisation comes next
rather than alongside.

**E3: widening `ghsa_repos.txt`.** This is the item this document called the
highest expected yield, and it is the one thing here that is a project rather than
a fix. The measurement infrastructure for it landed (the file now carries a
machine-readable `curated:` date and its age reaches the health line every run),
but the widening itself is a mining problem: there is no public endpoint that
lists repositories holding security advisories, which is the same fact that makes
`feed_ghsa_repos` necessary at all. It needs a search strategy and a GitHub API
budget, both of which are decisions rather than code. Starting a partial sweep
here would have produced a list nobody could reason about the completeness of,
which is worse than the frozen one that at least documents its own provenance.

---

## What landed, in order

Grouped so each block is committable and the guards land before the thing they
guard.

Executed in this order, each block committable on its own.

**1. Restore the harness (B1, B2). DONE.** Score `ghsa-repos`, rebuild `_baseline.json`
and `_audit.json` with all thirteen feeds. Nothing downstream is trustworthy until
the baseline includes the feed that is 69% of the site. One commit, about 25
minutes of fetching.

**2. Make the instruments say what is happening (B4, B5, H1). DONE.** Per-provider
`record_feed` for csaf; rows-contributed beside ids-fetched on `/status`; a
newest-`public_date` staleness assertion per feed. These are the three that turn
existing silent failures into loud ones, and they are prerequisites for trusting
anything measured after them.

**3. Say what the Ubuntu cap costs (B3, first half). DONE.** Health line in days, not
pages. String change, immediate reader benefit, no decision required.

**4. Resolve the written-and-unenforced rules (H2, M2, M3, M5). DONE.** Enforce the
corroborating exclusion or strike the sentence; schedule the stability fetches or
drop the field; close huawei in the config comment; correct FEEDS.md's OSV
paragraph to the code's 11 of 46.

**5. Then, and only then, expand. DONE except E3.** E1 (346KB of small OSV ecosystems, scored),
then E3 (widen the repo list, with a baseline to measure against). E4 is already
rejected. E5 needs re-costing before it is scheduled. E6 says the remaining
top-50 misses are not cheap and should stop being described as if they were.

**6. Decide the Ubuntu cap and the serial `gather` together (B3 second half, M4). OPEN, see above.**
They are one question: how much wall clock the run is willing to spend, and on
what. Answering it after step 2 means the answer is measured against
rows-contributed rather than ids-fetched.

Deliberately not in this list: any change to `MIN_SIGHTINGS` or `GATE_TOP_N_PCT`.
FEEDS.md section 0 forbids the first and section 6 has already re-derived the
second once. Neither is a lever for this document.

### What went into the suite alongside the fixes

All five are in, plus guards for the four defects the fixes turned up. The suite
went from 852 to 898 offline tests in about twenty seconds.

- `test_every_feed_in_the_running_profile_has_a_scorecard`, so B1 cannot recur.
  A directory listing against a config tuple.
- `test_the_recorded_baseline_describes_the_profile_that_actually_runs`, which
  turns B2 from a thing someone notices into a red build. Both of these were
  written BEFORE the baseline rebuild and watched to fail, naming `ghsa-repos`,
  which is the only way to know a guard guards.
- `test_a_feed_that_stopped_updating_is_caught_on_dates_not_counts`, H1's guard,
  plus `test_the_floor_clears_every_real_feed_cadence`, which pins the 45-day
  floor against the measured cadences so a later tightening has to argue with
  real numbers.
- `test_one_csaf_provider_going_dark_is_caught_while_the_aggregate_looks_normal`,
  a mutation test: it asserts the collapse is caught WITH per-provider parts and
  then asserts the same comparison returns nothing once the parts are stripped,
  which is the record this adapter used to write. Round 6's lesson was that a
  guard which passes either way is not a guard.
- `test_every_source_on_a_published_row_is_a_feed_the_run_reported_health_for`
  and `test_the_run_measures_what_each_feed_contributed_to_the_published_rows`,
  both through the real `cli.run`, so a feed contributing zero rows is visible to
  the suite rather than to whoever runs the query by hand.

Plus guards for the four defects the fixes turned up, and one the fixture needed:
`_sitefixture`'s feed block was `detail: {}`, so `/status`'s feed table fell
through to the legacy "no per-feed detail" branch and every assertion about that
table was being satisfied by a paragraph. It now carries the five cases the table
has to tell apart.

---

## Found while fixing, not in the original review

### F1. An unreachable CSAF provider recorded no part at all

B5's first version added `record_feed(f"csaf:{host}")` at the bottom of the
provider loop. The unreachable branch `continue`s well before that, so the one
provider worth tracking most, the one that had just gone dark, got no part.

`compare_magnitudes` iterates the CURRENT parts, so a part that vanishes from the
dict is compared against nothing. A provider going from 500 rows to unreachable
would have been invisible to the guard the change exists to feed. **The original
bug, reintroduced by its own fix**, which is the third time in this project a fix
has recreated the defect it closed at one remove.

Found by `test_an_unreachable_csaf_provider_never_escalates_the_parent`, which
was written for something else entirely: the status coupling between
`_record_csaf_health` and `health_detail`. It failed on a `KeyError` rather than
on its own assertion. `test_a_provider_that_goes_from_healthy_to_unreachable_is_still_compared`
now pins the real behaviour.

### F2. The status test asserted against an empty dict and passed

`test_the_feed_table_and_the_published_payload_report_the_same_contribution` was
written against `data/rbp.json`. The envelope publishes a deliberately curated
subset for consumers of the ROWS and carries no `feeds` block at all, so
`env.get("feeds")` was `{}` and the loop that checks every feed's contribution
ran zero times.

It was repointed at `data/summary.json`, which does publish per-feed detail. The
finding it exposed on the way is D4's, sharpened: **a tool holding `rbp.json`
cannot learn that 60% of the rows in it rest on a single feed.** Whether the
envelope should carry that is still a decision, not a defect. Leaving a green
assertion over an empty dict was the defect.

### F3. `feed_osv` could not fetch five of OSV's 46 ecosystems, at all

The URL was built by f-string with no encoding:

    url = f"https://osv-vulnerabilities.storage.googleapis.com/{eco}/all.zip"

Five OSV ecosystem names contain a space: **GitHub Actions, Red Hat, Rocky Linux,
Azure Linux, BellSoft Hardened Containers.** Unquoted, `urllib` raises `URL can't
contain control characters` before any request is made, so the adapter could not
fetch any of them and would have recorded each as a hard `FAILED`.

Latent, because none of the five was configured. Found by trying to merge them
rather than by reading the code, which is the only way it could have been found.

**It matters past the five.** FEEDS.md's standing instruction is to merge the
remaining 27 ecosystems, and three of these are in that set, so acting on that
instruction would have half-failed on merge with a degraded run to show for it.
Worse, the 2026-08-22 measurement that scored all 29 unmerged ecosystems at
+0 CNAs was a **full-text probe over the archives, not this adapter** -- so those
three were scored through a route the adapter cannot even open. That is the same
probe-and-adapter-measure-different-things gap that made the GIT estimate wrong
by its entire value, sitting unnoticed in the same table for five days.

Fixed with `urllib.parse.quote`. `test_osv_can_fetch_an_ecosystem_whose_name_contains_a_space`
asserts on the URL rather than on a download, so it costs no network.

### F4. The de-naming guard refused this review's own work, and was right to

Pushed to `main`, and the build failed closed:

    REFUSING TO PUBLISH:
      snapshots/2026-08-28/summary.json names 37 certified CNA(s), first:
      $.coverage.corroborating_feeds[0] = 'mozilla'

`deploy` was skipped, the site was not republished, and nothing leaked.

Both new `coverage` fields publish roster names. `near_floor` is a list of CNAs
by construction, and `corroborating_feeds` contains `mozilla`, which is a feed
name that collides with a certified CNA. `publish._NAME_OK_PATHS` is an explicit
allowlist whose own docstring says *"a new field defaults to REFUSED and someone
has to justify adding it here"*, because it replaced a denylist of nine field
names that five separate leaks walked around.

**So this is the guard working, and it is worth writing down as such.** Round 7
spent its length arguing that guards which pass either way are not guards, and
then added two fields that a guard correctly stopped. The fix was to write the
justification the allowlist asks for, in the guard's own taxonomy: `near_floor`
is aggregate coverage in exactly the sense `top_missed_effective` already is, and
strictly weaker, since it is a list of what the site CANNOT yet do;
`corroborating_feeds` is a list of feeds, which is the case the `.dates.` entry
was already written for.

One thing that had to be got right on the way in. `_name_path_allowed` is a
**substring** test, so an entry of `".coverage."` would have permitted every
future field under it, including one that did attribute a row. Both entries name
their field in full, and
`test_the_round_7_coverage_allowlist_entries_are_not_over_broad` asserts an
unrelated new `coverage` field still defaults to REFUSED.

The lesson for the next reviewer is narrower than "the guard works": **a finding
that adds a published field has a publication guard to satisfy, and the review
that adds it should say so before the push rather than after.** Nothing in this
document's order of work mentioned `publish check`, and it should have.

### And one that was not this review's subject at all

`tests/conftest.py` and `tests/render/conftest.py` are both imported by pytest
under the top-level module name `conftest`, neither being in a package, so the
second to arrive loses its name. `tests/test_sitefixture.py` did `import conftest`
and read `POSTURE_VARS` off it, which resolved correctly when that file ran alone
and to the render conftest on a full-suite run.

So `test_every_posture_lever_is_listed_here` failed with `AttributeError` on every
full run of the suite and passed in isolation. It is the guard that catches an
unlisted posture lever, and an unlisted lever is one that silently drops rows from
every fixture build. The shape, a test that is green alone and red together, is
the one that gets called flaky and rerun rather than fixed.

`POSTURE_VARS` now lives in `_sitefixture`, a unique module name, and
`test_no_test_imports_the_ambiguous_conftest_module` fails the next `import
conftest` anyone writes.

---

## Reproducing this

Everything in this document, in the order it was measured.

```
git show origin/data:snapshots/2026-08-27/summary.json
git show origin/data:snapshots/2026-08-27/backlog.json
```

Source contribution and sole-source counts, the table under "the thing to agree
on" and B4:

```
python3 - <<'PY'
import json, collections
rows = json.load(open('backlog.json'))
c, solo = collections.Counter(), collections.Counter()
for r in rows:
    s = [x for x in (r.get('sources') or '').split(',') if x]
    for x in s: c[x] += 1
    if len(s) == 1: solo[s[0]] += 1
for k, v in c.most_common(): print(f'{k:12}{v:>6}{solo[k]:>7}')
PY
```

Ubuntu's reach, B3:

```
curl -s 'https://ubuntu.com/security/cves.json?limit=20&offset=0'
curl -s 'https://ubuntu.com/security/cves.json?limit=20&offset=3980'
curl -s 'https://ubuntu.com/security/cves.json?limit=50&offset=0'      # errors
```

OSV ecosystem inventory and sizes, E1 and E2:

```
curl -s https://osv-vulnerabilities.storage.googleapis.com/ecosystems.txt
curl -sI "https://osv-vulnerabilities.storage.googleapis.com/<eco>/all.zip"
```

GitLab, E4. The CI file is the whole finding:

```
curl -sO https://gitlab.com/gitlab-org/advisories-community/-/archive/main/advisories-community-main.tar.gz
tar xzf advisories-community-main.tar.gz
grep -n '30\*24\*3600' advisories-community-main/.gitlab-ci.yml
grep -rhoE 'pubdate: "[0-9-]+"' advisories-community-main | sort | tail -1
```

The CERT and vendor probes, E5 and E6, are plain `curl -s -o /dev/null -w
"%{http_code} %{content_type} %{size_download}"` against the URLs in those tables,
with the project's own User-Agent. The 7,091-byte figure repeating across three
USOM paths is the finding; check the size, not the status.

Scorecards and verdicts, throughout:

```
python3 -c "import json;d=json.load(open('feedlab/_audit.json'));
print({k:(v['verdict'],v['cnas_new_effective'],v['wall_seconds']) for k,v in d['feeds'].items()})"
```

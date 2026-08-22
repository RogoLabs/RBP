# RBP Tracker: combined panel review, round 3

**Verdict.** The measurement instinct in this codebase is sound and better than the site
built on top of it: the buffer, the abstention tier, the three-bucket change split, the
withdrawn-threshold reasoning and the refusal to publish a rate are all correct calls
that most projects would not have made. But it is not launchable in its current state,
because four rounds of review have established that the site names organisations on
evidence it cannot check, publishes those names on a world-readable branch that no gate
governs, promises a correction mechanism that does not exist, and would fail its own
launch procedure on launch day.

Eight reviewers sat: Python, Web Design and Layout, GitHub Actions, CNA Operator,
CVE Program (MITRE), CISA / Government, CVE Consumer Working Group, RogoLabs Marketing.
Where a defect was found independently by more than one discipline it is recorded below,
because cross-discipline convergence was the strongest signal on the table. Roughly
ninety findings were raised; they merge into thirty items, of which sixteen block launch.

Ordering rationale for Part 1: what is already public and false about a third party
comes first, then what the next unattended cron tick will publish, then what breaks on
the day `RBP_LAUNCHED` is flipped, then the rest by consequence over effort.

---

## Part 1: launch blockers, in the order to do them

### 1. Stop the next scheduled run before touching anything else
**BLOCKER. Effort: ten minutes. Raised by: GitHub Actions (r2, r3), Python (r2), all five
`held_back` findings.**

`origin/data`'s tip is `9d0433d "state: run 2026-08-20T22:43Z"`; every remediation commit
on `main` is later. No run has executed since the fixes landed, so the next tick is the
first execution of the current `.github/workflows/deploy.yml`, and in one unattended pass
it will publish `held_back.json` for the first time: 79 rows, 38 of them carrying an
inferred CNA name, 63 undated and 16 inside the coordination buffer, built with
`report._publishable` (rbp/report.py:244) rather than `_gated`, so `owner` survives and
`owner_nameable` is absent entirely. The workflow has no `if:` key on any job or step, no
`dry_run` input, no pause switch and no `if: always()` notification, so there is no lever
to hold that moment.

Do now, in one commit:
- Delete `held_back.json` from the copy loop at `.github/workflows/deploy.yml:167`. One
  line. Once it lands on the branch it is in that branch's history permanently and the
  remedy becomes item 2's history rewrite.
- Add an `RBP_PAUSE` repository variable, checked as a job-level
  `if: vars.RBP_PAUSE != '1'` on the persist and deploy jobs, document it in PLAN.md as
  the incident switch, and set it while items 2 and 3 land.
- Add a `dry_run` dispatch input that runs pipeline, build and upload and skips persist
  and deploy, so launch day, a candidate epoch and a gate flip can each be rehearsed
  against real data with no publication. There is currently no way to see what a
  configuration change will do without publishing it.

### 2. Retract the CNA names already on the public data branch
**BLOCKER. Raised independently by: Python (r2), CNA (r2), Consumer (r2), CISA (r2),
Marketing (r2), MITRE.**

This is the only ungated-name exposure that has already shipped, and it is roughly ten
times the volume of the `held_back.json` leak the panel spent five findings on.
`git show origin/data:precision.json` parses to a `predictions` map naming a CNA for 366
reserved CVE IDs (GitHub_M 316, mitre 36, apple 4, Chrome 2, microsoft 2, and six
single-row CNAs), against one graded verdict. Five of those CNAs have no `cnas.json`
entry, therefore no `/cna` page, therefore no correction surface anywhere on the site.
The file sits at the branch root, so the snapshot-scoped `rm -f` at deploy.yml:176 and
every proposed snapshot-directory test cannot reach it, and `rbp/site.py`'s
`Disallow: /` is irrelevant to it. `snapshots/2026-08-20/backlog_full.json` (712 rows,
366 named, 182 carrying the ungated `product_map_owner`) and `report.md` (whose first
line reads "Internal / pre-preview. Do not forward") are also still at the tip.

The write is unavoidable at its current call site: `inference.apply_to_backlog` calls
`grader.record` over the whole backlog and `grader.save()` before `rbp/cli.py:119`
computes `reportable`, so no buffer, epoch, gate or downstream suppression can reach it.

Sequence, and the sequence matters because a force-push over `data` destroys the only
copy of both ledgers and the entire dated snapshot series:
1. Mirror `precision.json`, `resolutions.json` and every `snapshots/<date>/` directory
   off-repo. Cut a dated GitHub Release per run carrying the whitelisted artefacts;
   release assets are immutable, survive a branch rewrite, satisfy the citability
   requirement in item 14, and are the off-repo ledger mirror.
2. Move `grader.record` onto the `reportable` population, and split the persisted ledger:
   keep the full `predictions` map runner-local, push a redacted copy carrying
   `{cve_id, tier, k, on}` with `predicted` omitted. Graded verdicts can stay in full,
   because grading only happens once the true assigner is public in the CVE List.
3. Land the enforcement before the purge, or the same class of leak returns: after
   `git add -A` in the persist step, run `git diff --staged --name-only` and exit
   non-zero on any path outside an explicit allowlist, and on any staged JSON carrying a
   non-null `owner` on a row that is not counted. The whitelist is currently a copy loop
   plus a post-hoc `rm -f` for two filenames, on a branch that deliberately carries no
   `.gitignore`, and that branch's own history records a leak in each direction
   (`85a6eee` removed workflow files that leaked in at branch creation; `45c0fbc` records
   a green state commit that silently dropped every snapshot).
4. With the schedule paused, rewrite history with `git filter-repo` removing only
   `backlog_full.json`, `report.md` and the `predictions` map, preserving the commit
   series and both ledgers. Verify the old blob SHAs 404 and treat a request to GitHub
   Support as required, not contingent: unreferenced commits stay fetchable by SHA on a
   public repo until GitHub acts.
5. Add a retention policy: keep the current snapshot, the previous one and a monthly
   archive, prune the rest, and restore only what the diff needs in the seed step. An
   unbounded public log of every row ever named, including names later withdrawn, is a
   standing liability that grows four times a day and that no correction can reach.

Also correct the false statements around it: the `rm -f` comment at deploy.yml:176
describes a cleanup it performs only at the tip, and `rbp/report.py:295-296` and `:419`
both assert that "named CNAs receive a private preview and correction window before any
external circulation", in a document that is itself published on the branch.

### 3. Fix the naming gate, and make a withdrawal reach the ledger
**BLOCKER. The two known-wrong rows are still named. Raised by all eight disciplines;
the veto-inert finding was reached independently five times.**

> **CLOSED 2026-08-22.** Covered-set gate, three-sighting floor, bulk-reporter
> second-signal rule and the grader withdrawal path all shipped. Both rows now read
> `unattributed` / `abstain` / `owner_nameable: false`, and zero WordPress-ecosystem
> CNAs are named anywhere in production. The notification question this item asked to be
> decided either way is decided: **do not notify**, recorded with its measured exposure
> and its counterargument in PLAN.md 8c.
>
> Two corrections to this item's own text, both found while closing it. Its headline
> claim that the rows "are still named" was already false when written: it came from a
> narrow-feed local snapshot, and both rows were vetoed in production. And the sighting
> floor it asks for was added to *naming* but not to *coverage counting*, so the launch
> gate still credited a CNA on one incidental sighting until that was fixed separately.

The product-map contradiction gate (`rbp/inference.py:149-151`) is inert on exactly the
population it was written for. Its only input is `attributor.attribute(e.get("product",
""), ...)` and `rbp/attribution.py:89-101` matches the product field only, while
`feed_alas` (feeds.py:283), `feed_ubuntu` (:305), `feed_ghsa` (:358), `feed_csaf` (:697)
and `feed_msrc` (:514) all emit `"product": ""`. Measured: 52 of 96 named rows have an
empty package, 78 of 96 have no product-map verdict at all, `owner_method` counts are
`block-k3-abstain 133, block-k3 79, block-k3+product-map 17`, and **zero** rows are
vetoed. Both rows the panel identified as wrong (a WordPress-ecosystem CNA named on an
Ansible collection flaw, and another named on a QEMU 9pfs flaw, both distro-only rows
with `sources: "alas,ubuntu"` and an empty product) carry
`product_map_method: "none"` and are still named in the current snapshot. The same
inertness will apply to the entire CSAF population, which is every ICS and enterprise
vendor row, i.e. the population the coverage gate depends on adding.

Implement the covered-set gate, which the panel converged on as the best available fix:
- `rbp/coverage.py:29-32` already computes the `covered` set and discards it. Return it,
  and refuse to name a CNA outside it, recording
  `owner_method: "uncorroborated-cna-not-reached"` and publishing the withheld count.
  This suppresses both known-wrong rows today with no product string, no description
  matching and no hard-coded exclusion list, and it states in one sentence that survives
  a hostile reading: we name only CNAs whose advisories we read. The live
  `coverage.top_missed` lists both of those CNAs, so today one published artefact says
  "we do not read this CNA" and another says "this CNA owns this row".
- Harden `covered` before gating on it. It currently credits a CNA on a single sighting
  of one published ID anywhere in any feed, so one incidental reference re-admits a CNA
  and the gate silently reopens with no code change. Require a sighting floor, and pin
  the gate to a rolling union over the last N successful runs or to a committed roster,
  because a per-run set means a CNA appears Monday, vanishes Tuesday on a feed failure,
  and each appearance is a fresh publication of the claim.
- Give the grader a withdrawal path. `Grader.record` is first-prediction-wins by design
  (`inference.py:230`) with no removal path except grading, so a name the gate withdraws
  stays in the ledger and is republished by CVE ID and CNA name in the `/method` misses
  table when the record publishes. Add a `withdrawn` bucket carrying the reason and a
  `superseded_by` entry, excluded from the precision denominator. This preserves the
  anti-gaming property the docstring wants without making a correction impossible.
- Add the build assertions that make silence distinguishable from agreement: fail when a
  named row's product key is empty, publish `veto_evaluated` per row, and fail when a
  published artefact names an owner absent from `covered_cnas`. Today
  `owner_contested: false` ships on 150 of 150 rows as though it were a measurement.
- Require a second independent signal before naming any CNA in
  `attribution.BULK_REPORTERS` or operating as a Root, TL-Root or CNA-LR. That set is
  defined in `rbp/attribution.py:29-33` as CNAs "rarely the canonical owner of a
  distro-shipped OSS component" and is excluded from the product map on that ground,
  while block inference names them on 35 of 58 named rows. Move the set into one shared
  definition both the product map and inference import, and add the WordPress-ecosystem
  CNAs, which are absent today.
- Raise the naming standard to match the headline standard. `report.py:174` holds the
  aggregate to `indep_sources >= 2`; `report.py:188-189` holds a named-CNA claim to
  `owner is not None`. Measured: 43 of 58 named rows are single-origin and single-feed.
  Either require two independent origins to name, publishing the withheld count, or
  publish `single_origin: true` on the row and on the `/cna` page and state the
  asymmetry. A build assertion should make the naming standard never weaker than the
  headline-core standard.
- Rewrite `rbp/inference.py:131` and `tests/test_inference.py:257-258` to reference the
  bug class, not the identifiers. Both wrong (CVE ID, CNA) pairs are currently committed
  in the public repo's source and test docstrings, indexed by code search, permanent in
  git history, and no purge of the data branch retracts them. Do not implement the
  suppression as a deny list of literal IDs in tracked code, which would commit them a
  fourth time in a file whose purpose is to name them. Do not force-push `main` for this;
  the cost exceeds the benefit. Do decide explicitly whether to notify the two CNAs and
  record the decision.

### 4. Build a correction channel before any name is public
**BLOCKER. Cheapest item on the list. Raised by: Design, CNA (r3), CISA (r3), Marketing
(r3), MITRE, Consumer.**

`templates/cna.html:27-33` promises that a wrong row, or one "under coordinated
disclosure", will be "corrected or suppressed on the next build" and that "suppressions
are counted publicly in aggregate". `grep -rni suppress rbp/` returns nothing: there is
no suppression list, no pin, no counter, and `rbp/cli.py` recomputes `owner` by block
inference every run. The only route offered is a public GitHub issue on a public
repository, so acting on the site's own instruction requires disclosing an embargo in
public in order to ask for it to be respected. `grep -rniE 'mailto:|security\.txt|
contact'` over `templates/`, `placeholder.html` and `static/` returns no contact address
of any kind, and there is no `SECURITY.md`. The site's own front page (index.html:33-38)
and `/method` (:67-69) both state that an overdue record and a live coordinated-disclosure
hold are indistinguishable from outside.

Do all four parts in one commit, and do not do only the first:
1. Cut the paragraph at `templates/cna.html:27-33`, and the two identical claims at
   `rbp/report.py:295-296` and `:419`.
2. Publish a monitored non-public role address in `templates/base.html`'s footer, on
   `placeholder.html`, `/method`, `/cna` and `/data`, plus a `/.well-known/security.txt`,
   with a stated response window and an explicit line that an embargo report needs only
   the CVE ID and the word embargo, no detail.
3. Build the lever before advertising it: a committed suppression list read inside
   `report._gated` **and** inside `inference.apply_to_backlog` ahead of `grader.record`,
   with an aggregate suppressed count published in `summary.json` and rendered, so the
   mechanism cannot be used to hide the problem.
4. Replace the promise with what is true today: rows are recomputed from public data on
   every build, a withheld row is counted in an aggregate and never named, and here is
   where to write. Route ownership disputes to the reserving CNA's Root or the
   Secretariat as well, since they hold the authoritative `owning_cna` this site can only
   infer.

Removing the invitation without providing a route is not acceptable either: a live
coordinated-disclosure row is this project's highest-consequence risk, and removing the
only way to report it makes the site more dangerous while looking more careful.

### 5. Rejected and transferred closures: one crash, three false statements
**BLOCKER. Reproduced by execution by three reviewers. Raised by: CNA, CISA, MITRE,
Consumer, Python.**

`clock.reconcile` is terminal on `PUBLISHED` and `REJECTED` (clock.py:329) and sets
`days_to_publish: None` for rejections (:357), then appends both states to one list
(:361). `templates/changes.html:158` and `templates/cna.html:104` both sort that list on
`days_to_publish`, and Jinja's `sort` filter calls `sorted()`, so one PUBLISHED plus one
REJECTED closure raises `TypeError: '<' not supported between instances of 'int' and
'NoneType'` before any page is written. `changes.html` is in `site.PAGES`, so this kills
the pre-launch build too, and because the raise lands in the Build site step the artefact
never uploads, `deploy` is skipped, Pages keeps serving the last good build, and nothing
notifies. The next run re-derives the same rejection and fails identically: the outage is
self-sustaining. It is latent only because `resolved` is currently 0, so it fires on the
first closure after launch, and rule 4.5.3.5 makes rejection the lawful and likely end
state for the oldest rows.

Below the crash threshold the render is worse than the crash. A single rejection with no
publications emits, verbatim, `/cna/<slug>.html` under the heading "Resolved" with the
prose "RBPs attributed here that have since published" and a cell reading `None`, and
`/changes` reads "1 RBPs have published since this tracker started". A 4.5.3.5 rejection
is the CNA complying with the rules; the site reports it as the opposite.

- Split at the render boundary, in `site.load`, not in the templates:
  `resolutions_published` and `resolutions_rejected`, count only the former in
  `resolutions_n`, sort only the former. Note `sort(..., default=0)` does not exist in
  Jinja; `do_sort`'s signature has no `default` parameter.
- Give rejections their own card headed under 4.5.3.5, with prose stating that rejecting
  an unused or unpublished ID is lawful and is not a failure to publish, and a visually
  distinct treatment rather than an identically styled table under a different heading.
- Guard every `days_to_publish` render the way `changes.html:79` already does. Never
  print a bare `None` in a `td.num` column of right-aligned integers.
- Key `site.py:397` on `predicted_owner`, not `r.get("owner")`, which `reconcile` sets to
  the post-transfer assigner. Today `clock.by_owner` (:373) and `site.py:397` key the
  median tile and the table beneath it on the same `/cna` page to two different parties,
  so a CNA-LR that publishes another CNA's overdue record under 4.5.1.5 acquires a
  resolution history it never had. Render a differing pair as "published by X,
  transferred", as `changes.html:82` already does.
- Add `rejected`, `transferred` and `withdrawn-by-correction` outcome buckets to
  `Grader.grade`, none counting as a miss. Today a correct inference on a transferred row
  publishes as a named method miss in the `/method` misses table.
- Close a prediction on `REJECTED` as well as `PUBLISHED`. `grade` filters
  `state == "PUBLISHED"` only, so a prediction on an ID that is later rejected can never
  be graded, sits in the public ledger forever, and the precision figure is
  survivorship-biased onto IDs that published, which is the opposite of the region where
  block inference is weakest.
- Drop the `[-200:]` truncation at `site.py:160`, or compute `resolutions_n` from the
  same truncated list; they diverge silently past 200 closures.
- Add a test that renders every template against a ledger holding one closure of each
  state for the same owner, and asserts the word "published" does not appear in the
  rejected block.

### 6. Design launch day before setting `RBP_EPOCH`
**BLOCKER. Raised by: Design, CNA, Actions, MITRE, CISA, Marketing, Python.**

Measured: the newest `public_date` in the reportable set is exactly `min_age_days` before
the snapshot date, so a launch-day epoch excludes 100% of reportable rows for the whole
buffer window, and `rbp/cli.py:127-131` raises `SystemExit` on exactly that condition.
Flipping `RBP_LAUNCHED` and `RBP_EPOCH` together therefore produces a red cron four times
a day for about a week while Pages keeps serving the pre-launch holding page, with no
notification step anywhere in the workflow. The observable result of launching is that
nothing happens and nobody is told.

The alternative branch is no better. `templates/index.html:226-228` is the entire empty
state, one `.caveat warn` line reading "No reportable rows in this snapshot" under a
104px zero, and because the whole body including every disclosure sits inside
`{% if summary.total %}` (index.html:23), the zero-state page collapses to a header, one
paragraph and one yellow line, under an `og:description` reading "0 CVE IDs are reserved,
publicly referenced, and unpublished".

Then `/changes` inverts on the same run. The comparability guard is
`if prev_sum.get(key) is not None and prev_sum.get(key) != now_sum.get(key)`
(site.py:229-230), and `clock.summary` emits `"epoch": EPOCH or None` (:476), so the
None-to-date transition short-circuits and the pair is declared comparable. Reproduced by
execution: `comparable: True, incomparable_reason: None, no_longer_listed: 150 of 150`.
At live scale that is roughly 500 CVE IDs rendered as a comma-joined mono ID dump under
"No longer listed, cause unverified" on the first day anyone reads the site. The guard
catches the harmless direction (unsetting the epoch) and misses the one that will happen.

- Publish `held_back.json` under `site/data`, gated or with `owner` dropped entirely, and
  give it a named archive route ("The backlog at launch") carrying its count, age
  distribution and rows, linked directly beneath the lead count and listed on `/data`.
  The oldest row, at 519 days, is the single strongest piece of evidence the project has
  and the epoch currently deletes it from the site with no home anywhere.
- Relabel the lead metric on an epoch build as "new since `<epoch>`" with the epoch on the
  lead screen, and move the empty state outside the `{% if summary.total %}` guard so a
  designed zero still carries the epoch, the held-back count and the coverage bound.
- Keep the `SystemExit` only behind an explicit `RBP_EPOCH_ALLOW_ZERO`, so a deliberate
  clean slate publishes the designed zero and only an accidental epoch refuses.
- Validate the epoch against the data at startup in `cmd_run`, before any network work,
  and put the arithmetic in the message: "RBP_EPOCH=X excludes every row; the newest
  reportable advisory date is Y and the buffer is N days".
- Fix the comparability guard to key on presence (`key in prev_sum`), not truthiness, for
  `epoch`, `min_age_days` **and** the feed set (`site.py:237` is `if a and b and a != b`,
  the same hole a third time). Read the previous `backlog.json` with `_read_strict` when
  the directory exists; today the tolerant `_read(..., [])` turns a missing previous
  backlog into "every row is new" while `comparable` stays True.
- Better than a flag: compute `gone` against the previous snapshot restricted to IDs
  epoch-eligible under the current epoch, so an epoch change moves rows into the archive
  rather than through the diff at all.
- Add an explicit `epoch_started` case on `/changes` that names the epoch as the cause and
  shows no movement. Cap the rendered `no_longer_listed` list (show 50, link the JSON);
  a 7,000-character ID paragraph defeats the caveat above it.
- Sequence: design the zero state, publish the archive, then set the epoch. Never the
  reverse.

### 7. Make the launch gate mean something, and enforce it at the transition
**BLOCKER, and the gate definition itself should change. Raised by: Python, Actions,
MITRE, CISA, Marketing, Consumer.**

Three separate defects, and the panel's original fix for the first would have caused a
worse failure than the one it prevented.

*Unenforced.* `rbp/site.py:43` is a bare `os.environ.get("RBP_LAUNCHED", ...)` with no
coverage precondition; `grep` for a gate constant across `rbp/` and `.github/` returns
only prose comments; no workflow step reads `summary.json`. One repository variable edit
flips the front door, un-noindexes every page and starts writing `/cna` pages, with no
check and no audit trail.

*Measured on a number the cron cannot produce.* `PROFILES["deep"]` (cli.py:24) is the only
profile carrying `csaf` and `msrc`; the cron defaults to `weekly` (deploy.yml:124).
PLAN.md records weekly at 36.4% and deep at 40.6%, and the live snapshot publishes 18.7%
because that run used three feeds. One field, three values, selected by an undeclared
dispatch input, with no `profile` recorded in `summary.coverage`.

*The wrong unit.* `coverage.compute` credits a CNA as covered on a single sighting:
`surfaced_ids = {c for c in refs if c in pub_ids}` then `covered = {assigner[c] ...}`.
Nothing requires the site to read that CNA's own channel or any channel that
systematically carries its products, which is the property PLAN.md says the gate exists
to guarantee. The nine-feed weekly profile is distro and OSS package feeds, which never
carry ICS or OT products, and the site's own `top_missed` confirms it (siemens, sap,
huawei, dell, ibm, qualcomm, google_android). So the gate can be cleared while zero
critical-infrastructure CNAs are measurable, which is exactly the position PLAN.md says
must not be launched from. The denominator also floats: `total_cnas` is derived from
corpus assigners in a rolling three-year window recomputed from the run date, so both
sides of the ratio move overnight on 1 January. Verified bugs in the same function:
`state = dict(zip(...))` at coverage.py:27 is allocated and never used, and
`total_cnas = int((vol > 0).sum())` is a no-op filter, since `value_counts()` never emits
a zero.

*And the proposed enforcement would freeze the site.* A `SystemExit` in `site.load` lands
in the Build site step; `deploy` is `needs: build` with no `if:`, so the whole deploy job
is skipped and Pages serves the previous artefact indefinitely, with no notification
anywhere in the workflow. After a legitimate launch cleared on a manual `deep` run, every
scheduled `weekly` run would trip the refusal, so the site would freeze permanently four
times a day while continuing to serve a count and a six-hour cadence claim.

- Publish three coverage numbers and gate on the strictest: `cnas_sighted` (the current
  figure, relabelled), `cnas_own_channel_ingested` (`OWNER_FEEDS` intersected with the
  run's `feeds.requested`, computable today), and `cnas_detectable` (CNAs for which some
  ingested feed systematically carries their products). State on `/method` which number
  the gate uses. Report the ICS/OT sector separately and state plainly, while it is true,
  that no critical-infrastructure CNA is measurable here.
- Pin the CNA roster in a committed fixture so the denominator stops moving, and report
  roster size, CNAs with any published record, and CNAs the feeds touch as three separate
  integers. A percentage over a floating denominator cannot be trended or held to.
- Move `csaf` into the scheduled profile, or add a second less-frequent cron running
  `deep`, before the gate is measured for real. Land item 22's CSAF budget first, or the
  first scheduled deep run hits `timeout-minutes: 45`.
- Enforce at the transition, not per run: on the run that clears the gate, persist a
  `launch_gate` record (coverage value, profile, run id, date); on a launched build assert
  the record exists and the current coverage has not fallen more than a stated fraction
  below it; refuse only on a missing record or a large regression, and degrade to a banner
  on every page otherwise. Below gate, ignore `RBP_LAUNCHED` and keep serving the
  pre-launch page (fail closed on the flag) while a separate `run:` step exits non-zero
  (fail loud in CI). Never fail dark on the publication.
- Add the condition the aggregate numbers do not cover, and make it a build invariant
  rather than a threshold: every CNA named anywhere on the site is inside the covered set
  for the run that named it (item 3).
- Validate `RBP_LAUNCHED` strictly the way `clock._validated_epoch` validates the epoch,
  so `on`, `y` and `enabled` raise instead of silently meaning not-launched.

### 8. Bind the 24-hour naming warrant in code
**BLOCKER, launch gate candidate. Raised by: MITRE (r3). Not caught in rounds 1 or 2.**

The project's entire warrant for naming a reserving CNA is the 24-hour permission in CNA
Rule 4.5.1.7, quoted on `placeholder.html`, on `/policy` and named as the R5 mitigation in
PLAN.md. Nothing binds the buffer to it. `--min-age-days` is
`type=int, default=report.DEFAULT_MIN_AGE_DAYS` (rbp/cli.py:203) with no lower bound, and
`deploy.yml:28` passes `vars.RBP_MIN_AGE_DAYS` through unvalidated, so a repository
variable of `0` publishes inferred CNA names on IDs public for under 24 hours, inside the
window the Program's own rule tells its own Secretariat not to name in, with no error and
no visible change. Compare `rbp/clock.py:69-96`, where the epoch got a validator that
raises because a silent config error would be catastrophic: the same discipline, one file
away, on the less consequential variable. Two rendered claims also break silently:
`index.html:26` and `method.html:62` hardcode "more than twice the
{{ expectation_hours }}-hour window", true only at `min_age_days >= 7`.

Add `MIN_AGE_FLOOR_DAYS = 4` and refuse to run below it, with an error naming the
24-hour 4.5.1.7 horizon as the absolute floor and the 72-hour expectation as the
operating one. Derive the "more than twice" clause from the numbers. Publish
`min_age_days` and the floor in the artefact envelope. Pin the floor in
`tests/test_policy.py` beside the existing 4.5.1.7 quotation assertion, so the code
constraint and the quoted rule are held together.

### 9. Move the artefact invariants onto the publishing path
**BLOCKER. Raised by: Actions (r2), Python, Consumer, CNA, CISA, Marketing, MITRE.**

The remediation plan above rests on assertions that currently have nowhere to run.
`deploy.yml`'s build job has nine steps and none is pytest; `pip install -r
requirements.txt` does not install pytest, which lives in `requirements-dev.txt`; tests
run only in `ci.yml`, a separate workflow with no dependency in either direction, so a
red `ci.yml` does not stop a deploy and the four scheduled publishes a day never invoke
the suite at all. At least fourteen findings on this table end in "add a test".

Separately, the one artefact assertion that does exist is a one-element tuple:
`tests/test_pipeline.py:153` iterates `for name in ("backlog.json",)` in a directory that
had just gained a new file, which is precisely why the `held_back.json` leak shipped
green. And `grep -rn "rows=" tests/*.py` returns nothing, so all three `report.build`
call sites in the suite take the `rows is None` branch that production never uses.

- Put the invariants that protect published artefacts where the cron enforces them:
  extend `site._assert_consistent` (which already refuses to publish rows naming CNAs
  absent from `cnas.json`, and is therefore the working precedent), add an equivalent in
  `report.build`, and add the staged-path and owner checks to the persist step. Run
  `_assert_consistent` over every artefact `_write_data` and `report.build` emit, not just
  `backlog.json`: `held_back.json`'s named owners include two CNAs absent from
  `cnas.json`, so it publishes exactly the values the existing assertion refuses.
- The invariant set: no non-null `owner` on a `counted == false` row; no `owner` value
  outside `{unattributed}` plus the `cnas.json` keys; no `owner` outside `covered_cnas`;
  `owner_nameable` present on every row of every artefact; no named row with an empty
  product key; no `advisory_url` equal to the cve.org last-resort fallback; no `http` or
  `NOTE:` in a published description; no boolean single-valued across the whole published
  set; every emitted `cna/` href resolving to a file the build wrote; no built page
  containing `&amp;`.
- Then gate the commit path: add a `test` job to `deploy.yml` (install
  `requirements-dev.txt`, `pytest tests/ -q`) with `build: needs: test`, or make `ci.yml`
  a reusable workflow `deploy.yml` calls. Keep the pipeline-time assertions regardless; a
  cron run has no commit to gate on.
- Widen `tests/test_pipeline.py:153` from the tuple to
  `pathlib.Path(sdir).glob("*.json")` plus the CSVs, assert on `owner` and
  `owner_nameable` as well as `product_map*`, parse the allowlist out of `deploy.yml` so
  adding a file forces a test update, and add the missing structural test that
  `report.build(..., rows=[one_row], min_age=999)` applies no filter of its own. Delete
  the `rows is None` branch once `cli` is the only caller.

### 10. Decide the guard taxonomy once, before six guards are written in the same shape
**BLOCKER (design decision, blocks items 6, 7, 15). Raised by: Actions (r3), with
amendments from Consumer, CISA and Marketing on five separate findings.**

At least six proposed guards land in the pipeline or build step, both of which precede
`upload-pages-artifact` and the persist step, with `deploy` on a default `success()`:
the epoch zero-count exit, the count floor, the oracle circuit breaker, the coverage
gate, the ledger non-decrease guard and the corrupt-ledger raise. Each one as proposed
converts a data fault into a frozen site with no signal, and `grep -rn
"always()\|failure()\|cancelled()\|notif" .github/` returns nothing.

Split them:
- **Artefact-safety guards**, where publishing is itself the harm (a named row no gate
  cleared, a staged path outside the whitelist, an owner absent from `cnas.json`, a
  shrunken ledger, a snapshot failing `_assert_consistent`): refuse to publish, as a hard
  non-zero exit before the upload.
- **Data-quality guards** (unresolved oracle lookups, feed truncation, a count below
  floor, coverage below gate, an epoch that excludes everything): publish with a banner
  and go red. Write the condition into `summary.json`, let the site render it, and put the
  assertion in its own named `run:` step. The governing principle: refuse to publish
  wrong data, never refuse to publish correct data that is merely surprising.
- Add a `notify` job with `if: always()` inspecting `needs.*.result` explicitly for
  `failure`, `cancelled` and `skipped`, opening or updating a single tracking issue.
  `if: failure()` does not match `cancelled`, which is what `concurrency: group: pages`
  with `cancel-in-progress: false` produces for a displaced tick. Do this before the
  guards, because every guard makes a frozen site more likely.
- Dedent the empty-population check out of `if pre_epoch:` (`rbp/cli.py:122-131`), which
  makes it unreachable whenever `RBP_EPOCH` is unset, i.e. today. Replace the zero test
  with a fractional-drop comparison against the previous snapshot's `summary["total"]`
  (already restored in-process by the seed step). Do not use an absolute floor: zero is
  this project's goal state, not an error state, and a 4.5.3.5 bulk rejection sweep is a
  legitimate large drop.

### 11. The copy and citation pass
**BLOCKER, and the cheapest work on this list: roughly two hours, all templates. Raised
by: CNA, MITRE (x4), CISA, Marketing (x3), Design.**

Every item here is a place where the site's public surfaces contradict each other or omit
what cuts against them, on a project whose entire authority rests on quoting accurately.

- `templates/index.html:131` still reads "after about a year public" while
  `templates/policy.html:135-137` labels that figure a correction ("closer to four months
  than a year"). One click apart, front page holding the wrong version.
- `index.html:139-140` says the Metrics page reports "nothing on the overlap between
  them, which is the gap this site fills" while `policy.html:141` says "The two are not
  comparable and this site does not replace it". Take the `/policy` wording as canonical.
- `<th>Advisory title</th>` still ships at `cves.html:55`, `cna.html:64` and
  `changes.html:126` while `data.html:58-66` retracts exactly that word. Rename to
  "Advisory summary", and move the disclosure out from under the card headed "Licence" to
  a line directly above each table.
- `templates/base.html:7` sets `<meta name="description">` beginning "Every CVE ID that
  is reserved..." on every page. "Every" is the absolute the placeholder h1 was corrected
  to remove, contradicted five times by the site's own copy, on a run at 18.7% CNA
  coverage, in the one string search engines and link previews quote verbatim.
- **Quote the clauses that cut against the site.** `grep` over `templates/` and
  `placeholder.html` returns zero hits for "incident response", "short delays",
  "resource constraints" and "volume, complexity". The front page quotes the policy's
  "does not condone any unnecessary, intentional, or routine delay" and omits, from the
  same paragraph, "recognizing that such publication may, at times, coincide with ongoing
  vulnerability or incident response activities" and "internal processes may necessitate
  short delays"; and from Notification and Remediation, that a CNA must publish "no later
  than the deadline stated by their TL-Root or Root (which may account for factors such as
  volume, complexity, and resource constraints)"; and from Enforcement, "The CVE Program
  may take further action depending on the CNA's volume, history, and severity of RBPs."
  Quote all five **in the sections they occupy**, since two of them are not in Timely
  Publication and misfiling them would be the exact error `tests/test_policy.py` exists to
  prevent. Then answer them in the same breath with the buffer, the median and the 180d+
  bucket, and add the sentence they license: the only deadline that binds a specific row
  is one a Root set privately, which is why this site measures days public and never calls
  a row overdue. `/policy:38-41` already states the project's own standard here
  ("quoting only the discretionary parts would be selective"); it is broken on the section
  that governs the headline.
- **Re-anchor the ask on the in-force document.** `policy.html:143-146` asks for the
  return of a v1.0-era quarterly table under a policy that withdrew the arithmetic that
  table scored, which is answerable with "that was v1.0". `grep` for "metrics and audits"
  returns one hit, in PLAN.md, and none in any template: RBP Policy v2.0.0 names "Program
  metrics and audits" as one of its own identification channels. Ask for the public face
  of that channel and present the archived series as one shape it could take.
- **State the exculpatory inferences, do not just assemble the facts.** `/policy` collects
  the whole innocent explanation and stops one sentence short of it three times: a final
  column already reading N/A means the series had stopped being populated before anyone
  commented it out; a flow falling 4,326 to 350 describes a problem that was measurably
  shrinking; and RBP was item 2 of a three-item restructuring, so name items 1 and 3 so a
  reader can confirm it was not singled out. Carry all three onto `index.html`, which has
  none of them. Fix "appeared"/"went live" on both pages to distinguish markup added in
  February 2021 from public reachability at the 29 September 2021 cve.org launch.
- **Fix `placeholder.html`, the only page anyone can reach.** Lines 59-66 imply this site
  publishes the Program's archived metric ("The Program used to publish a count of
  these"), which `/policy` retracts on a page nobody can reach. Add the flow-versus-stock
  distinction and the coverage bound in one clause, and add the N/A fact, since the
  holding page is where good faith is cheapest to establish.
- **Keep the framing assets alive past launch.** `rbp/site.py:365-379` copies
  `placeholder.html` over `index.html` only in the `not LAUNCHED` branch, so flipping the
  variable deletes the glossary-provenance paragraph ("That is not our term. It is the CVE
  Program's own"), the full 4.5.1.7 quotation, and the narrow ask with its own
  safety reasoning. `grep` on the built dashboard returns zero occurrences of "unblind"
  and zero of "glossary"; the only surviving ask is `<small class="text-muted">` in the
  footer. Keep the page as a permanent route (`/about-this-count.html`) and lift its three
  load-bearing paragraphs onto the dashboard.
- **Put the legitimacy claim above the accusation.** The site's best sentence, "RBP is a
  state, not a verdict... the headline count on this site is the state, which makes it the
  Program's own metric", is the second paragraph of `/method`, item four in the nav. The
  lead screen's first substantive claim is about the Program withholding a field. Invert
  that order on both front doors, move the standing offer out of footer small print, and
  write the one sentence you want quoted into `<meta name="description">` and
  `og:description`, then read it with a hostile headline attached.
- Add a rendered-site grep test asserting that no built page contains "about a year",
  `>Advisory title<`, or an interval stated as a completed fact, and pin `#835`, `#842`,
  both dates and the cve.org launch date in `tests/test_policy.py`. Every policy quotation
  is pinned and none of the historical claims are, which is backwards, since the
  historical claims are the contested ones.

### 12. Stop rendering unmeasurable as measured
**BLOCKER. `must_rows` raised independently six times; the false-by-construction field
audit raised by Consumer (r2); the rule default by CNA (r2).**

The panel's characteristic finding, in five places at once.

*`must_rows: 0`.* `clock.OWNER_FEEDS` holds three entries after GitHub_M was removed
("removing it dropped the site's MUST count from 241 to 0"), so the 4.5.1.4 test is
unavailable to 431 of 434 CNAs, and `msrc` is not in the weekly profile so one of the
three cannot be measured on the scheduled cadence at all. That zero renders as a plain
`.metric-value` on the front page under "The owning CNA's own advisory feed carried it",
as a bare `0` in a "Candidate MUST" column for every CNA on `/cnas`, as a `0` tile on
every `/cna` page, and as an offered `/cves` filter that returns a header-only table with
no message. Remove the front-page tile entirely while the count is structurally zero: a
tile whose value is a sentence explaining why there is no value is worse than no tile.
Publish `owner_feeds: {configured, ingested}` in `summary.json` and `own_feed_ingested`
per CNA in `cnas.json` and every `data/cna/<slug>.json`, derived from
`feeds.health_detail()` status ok rather than mere membership in `requested` (ubuntu is
requested and truncated every run). Split `/method:128-132` into configured and
fetched-this-run. Hide the `/cves` MUST filter option. Do not render "not measured, own
feed not ingested" as a blanket replacement: redhat and mozilla *are* fetched on the
scheduled profile, so that string would be false. The honest headline is the denominator:
the test is available for 3 of 434 CNAs.

*`should_rows: 150`.* `clock.annotate` sets `rule = RULE_MUST if must else RULE_SHOULD`
unconditionally, so 4.5.1.6 is assigned to 100% of rows including the 92 where no CNA is
identified at all, and rendered as "A third party disclosed. The ordinary distro case."
4.5.1.6 carries three predicates (assigned by that CNA, disclosed by a party other than
the CNA, the CNA became aware), none observable on an unattributed row, and its clock runs
from awareness, which the site cannot see. Add a third state: `rule: null`,
`rule_strength: null`, `rule_basis: "unattributed"`, and a published
`rule_unassignable` count. Restrict `should_rows` to rows with an inferred owner (58, not
150). Render the three-way split with the unassignable share largest, because 61%
unassignable is the most honest thing the site can say about itself. Relabel the SHOULD
tile to what is observed ("an advisory from a party other than the inferred owner is the
earliest this site can see"). Anchor `past_expectation` explicitly to the RBP Policy
v2.0.0 72-hour publication expectation, which has an observable start, and stop citing
4.5.1.6 as the basis for the age tiles.

*Eight of 27 published row fields are single-valued.* Measured over all 150 rows: `state`
RESERVED, `clock_known` True, `rule` 4.5.1.6, `rule_strength` SHOULD, `rule_certainty`
candidate, `self_disclosed` False, `past_expectation` True, `owner_contested` False. Three
are false because the test could not run. Worse, `held_back.json` publishes all 63 undated
rows with `days_public: null, clock_known: false` beside `past_expectation: false,
rule: "4.5.1.6", rule_strength: "SHOULD"`, i.e. a fully populated rule verdict on rows
`clock.py:29-30` calls unageable at any threshold. Emit `null` for a test that could not
run, or add explicit companions (`expectation_measurable`, `self_disclosure_measurable`,
`veto_evaluated`) and document that false means measured-false. Move the genuinely
constant fields into the envelope rather than repeating them per row. Add the build
assertion that fails when a boolean is single-valued across the whole published set: that
single check would have caught four separate findings here, and it is the cheapest general
detector on this list.

### 13. `self_disclosed` defaults to MUST on every ambiguous shape
**BLOCKER. Reproduced by execution by five reviewers. Raised by: Python, Consumer, CNA,
CISA, MITRE, Marketing.**

`clock.py:192-195` is `mine = [...]; theirs = [...]; if not mine: return True` then
`return not theirs or min(mine) <= min(theirs)`. All four ambiguous shapes return MUST:
own feed undated with a dated third party; own feed dated with undated co-sources; a
same-day tie; and no dates at all. `feeds.gather` only records a per-source date when
`public_date` is truthy, and `feed_debian` (:331), `feed_alpine` (:419) and `feed_arch`
(:769) all emit `""`, so those three feeds can never populate `theirs`, and they are all
in the weekly profile. Measured on the live snapshot: of 52 multi-source rows, every one
carries dates for only a subset. `feed_redhat` passes a null `public_date` straight
through, so the CNA most likely to be tested is the one whose own dates are least reliable.
The docstring above the function claims this defect was fixed, and the comment at
`clock.py:157-159` states this ordering property as the condition for restoring `ghsa` to
`OWNER_FEEDS`, which would reinstate all 241 MUST rows on a function that cannot order
them.

Write it once as one rule: claim MUST only when at least one dated own-feed entry and at
least one dated non-owner entry exist and `min(mine) < min(theirs)`; the own feed being
the only source is a legitimate MUST; every other shape abstains with
`rule_certainty: "unmeasurable"`. Absence of a date is never evidence, in either
direction. Fix it in one place: `annotate` and `report._gated` both compute
`self_disclosed` today and only `annotate` derives `rule` from it, so a divergence
publishes a row with `self_disclosed: true` and `rule: 4.5.1.6`. Then delete or rewrite
the `clock.py:157-159` comment so it reads as an unmet condition.

### 14. Give consumers an envelope, a versioned schema and a citable target
**HIGH, launch blocker. Raised by: Consumer (r2, r3), CISA (r2), Design, Marketing, CNA,
MITRE.**

`data/rbp.json` is `json.dump(ctx["rows"], ...)`: a bare array with no `schema_version`,
no `generated_at`, no `epoch`, no `min_age_days`, no coverage, no floor flag. Every
caveat that makes the count safe to use lives in HTML and in a sibling file the tool has
no reason to fetch. Meanwhile this review queues at least eight published-key changes
against artefacts with no version field, so any consumer who integrates in the meantime
breaks silently.

- Wrap both JSON artefacts: `{schema_version, generated_at, run_id, snapshot_date,
  profile, launched, min_age_days, epoch, counts: {total, undated_excluded,
  epoch_excluded, rule_unassignable}, coverage: {...}, caveats: {count_is_a_floor: true,
  owner_is_inferred: true, must_measurable: false}, rows: [...]}`. Bump `schema_version`
  on any key rename and publish the current value on `/data`. For the CSV, freeze the
  column list as a documented contract with stable order and ship an
  `rbp.csv.meta.json` sidecar.
- **Stop overloading `owner`.** 92 of 150 rows carry the magic string `"unattributed"` in
  the field that otherwise holds CNA short names, it is the largest value in that field by
  a factor of three, `cnas.json` has no such entry, and `site._assert_consistent` only
  passes because it special-cases the string. `data.html:40-41` documents the opposite
  ("absent wherever the gate did not pass"), so a consumer who codes to the documentation
  treats all 92 as named. Emit `owner: null` and an empty CSV cell, keep
  `owner_nameable: false` as the marker, and put the presentational placeholder in a
  separate documented field if one is wanted.
- **One column contract, not three.** `rbp.json` carries 27 fields, `site.CSV_COLS` 22,
  and the data-branch `backlog.csv` 26 in a different order, with the code comment at
  `report.py:216` asserting the two CSVs are kept identical. The five fields missing from
  the documented CSV are the audit fields: `dates` (the sole input to the rule call),
  `owner_method` (the only field distinguishing a plausibility-checked name from an
  unchecked one), `refs`, `hours_public`, `ecosystem`. Define the list once in a shared
  module, make the CSV a declared subset that includes `owner_method` and `refs`, publish
  `own_feed_date` and `earliest_other_date` as scalars so the rule call is checkable
  without parsing nested JSON, and publish a field dictionary on `/data` (name, type,
  value-for-absent, meaning, which views carry it). Three absence conventions are in use
  today (`""`, `null`, `"unattributed"`) and none is documented.
- **Export the closure record.** `_write_data` writes five artefacts; `resolved.json`,
  `held_back.json` and the `_changes` dict are computed, rendered and withheld, and
  neither reaches consumers through any channel (verified: neither is on `origin/data`).
  "Which RBPs closed since the last run, and was each PUBLISHED or REJECTED" is the most
  useful signal this project produces and the only way to get it is to diff two `rbp.json`
  snapshots, which reproduces the exact "left the set therefore published" error the site
  removed from its own code. Publish `changes.json` verbatim including `comparable` and
  `incomparable_reason`, plus `resolved.json` and a gated `held_back.json`, list them on
  `/data` with field meanings, and add an Atom or JSON Feed so new/published/rejected is
  subscribable. Make the `data/cna/<slug>.json` row on `/data` conditional on `launched`;
  it currently documents a 404.
- **Give every run an identity, and something immutable to cite.** Four runs a day
  overwrite `snapshots/<date>/` on a public branch with no run id, no per-artefact
  timestamp and no content hash, and `_prev_snapshot` selects strictly by date so all four
  diff against yesterday and re-publish the same `new` set. Add `run_id`, `generated_at`
  and a hash to every artefact and as git trailers on the state commit; bound the change
  buckets with `from_run_id`/`to_run_id`; diff against the previous run, not the previous
  date. Cut a dated GitHub Release per day and add a "Cite this as" line on `/data`; that
  one control also gives item 2 its off-repo mirror and its purge-survivable archive. Add
  a small `latest.json` pointer so polling does not require refetching the whole file.
  Protect `data` against force-push and deletion with a ruleset that still allows the
  bot's fast-forward push. Choose a data licence (CC0 or ODC-BY) alongside MIT for the
  code and say on `/data` which applies to the rows; MIT on a dataset says nothing about
  attribution or redistribution.
- Add a check that fails when an artefact a writer depends on is absent from the persist
  allowlist. That would have caught the dead week-over-week diff: `report.build:251` still
  reads the previous snapshot's `backlog_full.json`, which the allowlist removed and the
  `rm -f` deletes, so that diff is permanently inert in CI with nothing reporting it.

### 15. Stop publishing degraded runs as clean ones
**HIGH, launch blocker. Raised by: Python (x3), CNA, MITRE, Actions, CISA, Consumer,
Marketing.**

The one direction of error this project cannot afford is a silent shrink, because a
shrinking count reads as the Program improving. Four mechanisms produce one today.

- **The oracle tally is computed and thrown away.** `classify.py:171` returns
  `backlog, fresh_resolved`; `cli.py:86` unpacks two values; `unresolved` is absent from
  `summary.json`. An ERROR'd ID is never appended to `backlog` at all, so it vanishes from
  the snapshot, lands in `_changes.no_longer_listed` as an unexplained departure, stays in
  `ledger.state["open"]` forever, and keeps an outstanding grader prediction. So a
  brownout both shrinks the headline and manufactures fake departures. Do **not** fix this
  with a bare abort: the correct primitive is carry-forward, keeping a row that was
  RESERVED in the previous snapshot with `state_verified_this_run: false` and counting it,
  and only then a threshold for how much unverified carry-forward is tolerable. Publish
  `unresolved`, `lookups_attempted` and `never_allocated` (the `_NOT_FOUND` count, a
  genuinely valuable data-quality population currently printed to a log and discarded).
  Count 429 separately, read `Retry-After`, and add jitter to `time.sleep(2 ** i)`, which
  24 workers currently execute in lockstep against a MITRE endpoint this project depends
  on and does not own.
- **`record_feed` is called from 2 of 9 degrade paths.** Only ubuntu's cap and osv's
  sub-fetches record anything; `feed_ghsa`'s `for _ in range(page_cap)` has no `else:`,
  and `gather` then stamps `record_feed(s, OK, ...)`. Add `for ... else` on loop
  exhaustion and record TRUNCATED (not FAILED) on any break that keeps partial results.
  Do not record on `feed_redhat`'s `if len(rows) < per: break`, which is normal pagination
  exhaustion. Add per-provider `record_feed(f"csaf:{host}", ...)` on metadata failure,
  feed failure and cap: `feed_csaf` calls `record_feed` on no path at all, and CSAF is the
  only route to CISA, Siemens, SICK, Cisco and SUSE, so "Huawei yields 0" and "Huawei was
  never reached" are currently indistinguishable. `health_detail`'s parent rollup already
  supports sub-names.
- **A 404 is laundered into an empty page.** `_get` returns `None, 404, {}` and every
  paginated caller binds `code` and never reads it, so a retired path or a WAF 404 ends
  pagination through the normal `if not rows: break`, with no exception and no loop
  exhaustion, and `gather` records OK. This defeats the `for...else` fix above: a project
  that implemented every other health fix here would still publish a 404-truncated Ubuntu
  feed as `status: ok`. Give `_get` a `not_found_ok=False` default, read the status in
  every paginated adapter, and refuse to record OK for any feed that returned zero rows
  without an adapter-level record.
- **`health_summary` returns only FAILED entries**, so `cli.py:78`'s `if failures:` can
  never fire on truncation, and the live snapshot publishes `failures: []` beside
  `truncated: ["ubuntu"]` on a run with known data loss. Return failed and truncated
  separately and print DEGRADED for both. Rewrite `method.html:232-236` ("No feed failed
  outright this run") to name what it covers; that sentence currently asserts the negation
  of a state its input cannot express.
- **The comparability guard cannot catch the churn that actually happens.** Three findings
  proposed adding `feeds.truncated` to the guard keys; two authors withdrew it. Ubuntu is
  truncated on *every* run, so both snapshots compare equal in exactly the case where the
  200-page boundary has moved and taken rows with it, and those rows render as "No longer
  listed, cause unverified" with the IDs printed. Record per-feed ID-set size and the
  oldest returned advisory date for every paginated or windowed feed, compare magnitudes
  and window edges rather than status names, suppress an ID from `no_longer_listed` when
  its only sourcing feed degraded or its window moved past its `public_date`, and count
  the suppressions. Raise the ubuntu cap and the ghsa 40-page cap (against a measured
  83-day rolling window) before `/changes` is presented as a record of anything. The
  exposure is large: 60 of 150 rows are ubuntu-only and 36 of 58 named rows are.
- **Move the degraded and truncated banners into `templates/base.html`** beside the
  staleness banner, so they render on every page including `/cna`. Every published build
  is a truncated build and the only disclosure is on `/method`, which simultaneously
  asserts no feed failed. PLAN.md:383-385 states the rule ("never publish a degraded run
  without a banner") and it is broken on every run.
- **Assert corpus completeness.** `refresh_corpus` discards `applied` and writes
  `corpus_date=baseline_date` unconditionally, so a delta day that parses to zero rows is
  stepped over permanently: `wanted` selects `d >= have`, `missing` only covers days
  absent from the release feed, and `gap` is then 0 forever. A single change to the delta
  zip's internal layout freezes the corpus silently and forever, and the open
  `restore-keys: corpus-index-v2-` prefix restores the frozen index on every subsequent
  run. Because the corpus is the ground truth for `reconcile`, `Grader.grade`,
  `published_last_12mo` and `coverage`, a frozen corpus stops detecting closures entirely:
  already-published IDs keep accruing `days_public` against named CNAs while every health
  surface reads green. Advance `corpus_date` only to `max(applied)`; fail when `applied` is
  empty while `wanted` was not; bind the cache key to `hashFiles('rbp/cvelist.py')` plus
  the schema; validate the restored index against the release survey; and add the one-line
  canary that catches the whole class: assert `max(corpus["date_published"])` is within a
  day or two of today, right after `ensure_corpus`.

### 16. Make the freshness claim falsifiable, and notice when the pipeline stops
**HIGH, launch blocker. Raised by: Python, Actions, MITRE, Design, Consumer, CISA,
Marketing.**

`stats["generated_at"]` is written at `cli.py:170` and `age_hours` is computed in
`site.load` against `now()` in the next step of the same job, so `stale` (>12h) and
`very_stale` (>24h) are always False and the footer freezes at "(0.0h ago)" forever.
Verified empirically: `grep -c stale-banner` over all eight built pages returns 0. The
failure this was written to detect (a schedule disabled after repository inactivity, a
displaced tick, a build failure) leaves the last successful page deployed, and that page
asserts it is fresh. The test that "proves" the feature writes a synthetic timestamp the
pipeline cannot produce.

- Emit `generated_at` as `<time datetime="...">` and compute the age in the browser
  against `Date.now()`, which is the only clock a static page has, in a reserved
  fixed-height slot so the banner does not push a 104px lead count down after first paint.
  Keep the server value for the footer only.
- Make `templates/data.html:8` ("Stable URLs, rebuilt every six hours") data-driven from
  the same value. A stalled pipeline currently puts "This data is 40 hours old" directly
  above "rebuilt every six hours" on the one page a consumer builds against, and that page
  is wrong in two further places: it describes `precision.json` by fields the published
  file does not have, and documents a `data/cna/<slug>.json` directory the pre-launch
  build does not write.
- Add the external check against the published `generated_at`. A workflow that stops
  running emits no in-repo signal at all, so this is the only control that survives the
  failure. Add the `notify` job from item 10; an issue write is also repository activity,
  which helps keep the schedule alive.
- Move the cron off the top of the hour (`'17 */6 * * *'`), the slot most likely to be
  delayed or dropped. And harden the recovery path before trusting `timeout-minutes: 45`:
  a gap over `MAX_DELTA_GAP_DAYS` forces the full-baseline branch, which is
  `urllib.request.urlretrieve(url, dest)` with no timeout, no retry and no size cap
  against a 583 MB asset, inside a budget calibrated on 6.9 to 14.9 minute warm runs. The
  least-tested path is the one an outage guarantees you take. Add a greppable test that no
  template states an interval as a completed fact.

### 17. Accessibility and the primary data surface
**HIGH, launch blocker for the stated audience. Raised by: Design (r2, r3), endorsed by
CISA on Section 508 grounds, and by Marketing on positioning grounds.**

Two reviewers independently measured these and one called them disqualifying for a
federal reader: a documented WCAG failure on the primary data table is a bar to citing or
embedding a third-party resource from official guidance, regardless of data quality. All
of the fixes are small.

- **Contrast.** Ten measured AA failures across both themes, all traceable to three
  inherited cve.icu tokens never re-audited against the striped-row background this
  project introduced at `rbp.css:200`. Worst: `td.unattributed` at **1.75:1** on the
  stripe, on 92 of 150 rows. Also failing: every link on every even row (3.80:1), the
  column headers themselves (3.95:1), `.qualifier` and `td.desc` (3.95:1),
  `.result-count` and `.filters label` (4.45:1), the `.page-header` subtitle on every page
  including all `/cna` pages (4.10:1), and in dark theme `td.unattributed` (3.30:1) plus
  everything taking `--color-primary`. Introduce project-owned text tokens in `rbp.css`
  measured against `--color-bg-content`, `--color-bg-secondary` and `--color-bg-hover` in
  both themes, and pin the ratios in a check. Do not audit against white; half the rows
  are not white, which is the mistake the false comment at `rbp.css:206` already documents
  making (that comment claims AA "against the card background" for a class that only ever
  renders in a table). The semantic point matters as much as the standard: the least
  certain cell on the page, the site's own abstention marker, is the least legible, so the
  site's conservatism is the part a reader cannot see.
- **The sticky header never sticks.** `.tablewrap { overflow-x: auto }` makes the wrapper a
  scroll container on both axes, so `th { position: sticky; top: 0 }` binds to a scrollport
  with `max-height: none` that never scrolls. Proven three ways; at 4000px scroll the `th`
  sits at -3,630px. So an 11,982px table (about 44,000px at live scale) is read with no
  column labels visible at any point, and the columns a reader loses are Inferred owner,
  Confidence and Rule, which carry all the hedging. Fix:
  `.tablewrap { max-height: calc(100vh - 8rem); overflow: auto }` and
  `th { top: 0; z-index: 20 }`, give the header its own fill (it currently shares the
  even-row stripe token), and make the header height a token since two sticky offsets must
  agree.
- **Keyboard and screen reader.** Sorting is a click listener on a non-focusable `<th>`
  (SC 2.1.1, level A): seven columns unreachable without a pointer, while `aria-sort` is
  maintained correctly, so the state is announceable and the control is inoperable. The
  322px-overflowing scroll container has no `tabindex`, `role` or accessible name.
  `render()` replaces `#body.innerHTML` wholesale with no `aria-live` anywhere, so a
  filter that matches nothing announces nothing. No `<caption>` on any table, no `scope`
  on any `th`, and one `outline` rule in the entire project, so no focus treatment was ever
  designed. Fixes: a `<button>` inside each sortable `th`;
  `<div class="tablewrap" tabindex="0" role="region" aria-label="...">`; `aria-live` on
  `.result-count`; an explicit empty-state row; a `<caption>` carrying the certainty
  statement (which also fixes item 20's constant-qualifier problem).
- **`/cves` below 768px.** The table lays out at min-content 2,488px in a 351px wrapper, a
  7.1x overflow that `min-width: 940px` guarantees can never reflow, so 86% of every row
  is off screen and the Inferred owner column is never visible on a phone. The filter bar
  is actively mislabelled: `.filters` wraps between each label and its own control, so
  three visible labels sit beside controls they do not describe. `rbp.css` contains **zero**
  `@media` rules, so this is the first breakpoint in a layer that has none. Below 768,
  render each row as a card from the client-side JSON, with hedges adjacent to the claims
  they qualify.
- **No `<h1>` on the front page.** `document.querySelectorAll('h1')` is empty on
  `index.html` and `overview.html`; the outline starts at H2. Every other template has
  one and `style.css:459` already styles `.page-header h1`. The same page is also the only
  one with no distinct `{% block title %}` and no `og_title` override, so the page that
  will be ranked and linked most is headingless and generically titled. One small commit.
- **No empty-state design anywhere.** `/changes` ships today as an `<h1>` plus one grey
  sentence, 167 characters of `<main>`, as item four of seven in the primary nav, and that
  is also what launch day looks like. `index.html:150` already handles the same condition
  correctly, so the pattern exists and was not applied. A zero-row `/cves` renders the
  full filter bar plus CSV and JSON links that produce a header-only file. Design one
  empty-state treatment (a plain bordered block, not `.caveat warn`; empty is not a
  warning) and use it in all three places, and suppress export links on a zero-row table.
- **Print strips every hedge.** `rbp.css` has no `@media print`, and the inherited print
  block forces `color: #212529 !important` on `td, th, span, a`, collapsing the whole
  certainty vocabulary to one ink (a candidate MUST becomes indistinguishable from a
  SHOULD, `td.unattributed` loses its distinction), while not resetting `.tablewrap`'s
  `overflow` or the table's `min-width`, so an overflow box with no scrollbar clips
  everything past about 680px with no indication. A PDF is the most likely way a named CNA
  circulates its own page internally. Add a print block: reset the overflow and min-width,
  drop to the four columns that carry the claim, re-express the chip and unattributed
  distinctions as border or weight, and print the standing hedges immediately after the
  `<h1>`.

### 18. Strip introducing and fixing commits out of published descriptions
**BLOCKER, cheap. Raised by: Marketing (r3), with CISA (r2) amending its own detail-boundary
finding to the same conclusion.**

Measured over the 150 published rows: 13 descriptions contain a URL and 11 carry Debian
security-tracker annotations, including `NOTE: Introduced with: <commit URL>` and
`NOTE: Fixed by: <commit URL>`, several cut mid-URL at the 180-character ceiling. 46 of
150 carry mechanism language and 62 are cut mid-sentence. An "Introduced with" pointer is
not a description of a flaw, it is a pointer to the vulnerable code, reproduced inside a
curated list of CVE IDs selected precisely because no record has been published. The
defence that Debian already publishes it is true and will not survive the headline, and it
is gratuitous: the annotation identifies nothing a defender needs.

Strip URLs and `NOTE:` / `DEBIANBUG` annotations before `description` leaves
`report.py`, then cut at the first sentence boundary rather than at 180 raw characters.
Add the build assertion that no published description contains `http` or `NOTE:`. Keep the
field: with an empty package on 52 of 96 named rows, and no package at all on CSAF rows,
the description is the only identifier a defender has, so deleting it makes the site less
useful without making anyone safer. Then amend PLAN.md section 3, which still lists
"vulnerability detail beyond the verbatim advisory title" under "Never say", so the plan
describes what the code does.

### 19. Decide the MITRE framing before a journalist decides it
**BLOCKER (a decision, not a code change). Raised by: Marketing (r2, r3), MITRE (r2),
CNA (r2), CISA (r3), Design.**

Three facts that are individually documented above and only become a problem together.
`mitre` holds 33 of 58 named rows, exactly the anonymous "56.90% Share of named rows held
by the single largest CNA" rendered as the first metric tile. Those rows are third-party
OSS plausibly assigned through the CNA-of-Last-Resort path (gst-plugins-good MKV demuxer,
mbedtls, an NXP ENET IRQ handler, mongoose, a GIMP LBM parser), 29 of 33 sourced from
`ubuntu` alone and 30 of 33 at `indep_sources: 1`. And the ask is addressed to the
Secretariat. `grep -rn 'CNA-LR\|Last Resort\|requester\|delegat' rbp/` returns nothing, so
no field distinguishes an ID a CNA-LR reserved for a third-party requester from one a
vendor reserved for its own advisory. The pinned policy fixture makes it worse: under
v2.0.0 a Root can delegate publication to a CNA-LR, so the largest accusation on the site
may be concentrated on the mechanism the policy defines as the fix.

The story "MITRE is the largest holder of CVE IDs that violate MITRE's own publication
policy" is irresistible, is what the front page's first tile says once the name is filled
in, is not supported by the data, and would make the ask unwinnable.

- Do not build a delegation inference; the data does not support one. State the limitation
  on `/method` and on the `/cna` page of any Root, TL-Root or CNA-LR, quoting the
  delegation sentence, and say plainly that some rows may be IDs delegated to this CNA for
  publication rather than withheld by it, and that this tool cannot tell which.
- Replace the single-share tile with a distribution over named CNAs, captioned as a
  property of block width, feed coverage and assignment role rather than of CNA behaviour.
  Do **not** simply name the CNA in the tile: a lead-screen tile naming one CNA as holder
  of the majority is a leaderboard with one entrant, which PLAN 2a forbids and which
  `clock.py:440-447` deliberately refuses to build in the per-CNA view.
- Say once, in the lead block, that the count is a Program-level transparency measurement
  and not a CNA scorecard.
- Draft the two-sentence answer to "so MITRE is the worst offender?" and make sure the site
  already contains it.
- Pin the delegation sentence in `tests/test_policy.py`, since it is now load-bearing for
  the site's own caveats.

### 20. Bound the lead screen, and lead with the defensible number
**HIGH, launch blocker. Raised by: Design (x3), CISA, Consumer, Marketing (x2), CNA.**

The count is the whole product and it carries none of its qualifiers. `grep -rn coverage
templates/` finds `summary.coverage` only at `method.html:249-257`; the built front page
contains no occurrence of the denominator 434; `undated_excluded` (63 against a headline of
150) appears on `/cves` inside a caveat block measured at y=9,665, projecting past y=44,000
at live scale; `summary.feeds.truncated` is `["ubuntu"]` with the banner only on `/method`.
`base.html:19` emits `og:description` as the raw count with no guard on all seven noindex
pages under a hard-coded root `og:url`, which is the one string that travels into Slack,
Teams and every link preview, and unfurlers do not read `robots.txt`.

Worse, the number being led with is the least defensible one. Measured: `indep_sources` is
1 on 98 of 150 rows (65%), 60 of 150 rows are `ubuntu`-only (40%), and `ubuntu` is the feed
that admits truncation on every run. The site already computes and publishes the
corroborated subset (`kpi_core`, `indep_sources >= 2`, 52 rows here and 179 at live scale)
and renders none of it on the front page.

- Lead with the corroborated figure in the sentence, with the total beside it: "N CVE IDs
  are reserved, referenced in two or more independent public advisories, and still
  unpublished", "and M seen in at least one".
- Add one bound strip directly under `.lead-unit`, generated from `summary` rather than
  written, so it cannot drift: feeds reach N of M CNAs (X%), K IDs excluded as undated and
  unageable at any threshold, E held back pre-epoch, F feeds truncated this run, each
  linking to `/method`. Put it inside `.lead-sub`, which already has the rule and the 62ch
  measure.
- Rewrite `og:description` to carry the corroborated figure and the coverage bound, and
  gate it on `launched` so a pre-launch paste stops publishing the pre-gate count. Emit
  per-page `og:url` and `og:title`, add a canonical link, and give `placeholder.html`
  `og:title`, `og:description`, a `<meta name="description">` and a 1200x630 image, since
  it is the only page anyone can reach and currently unfurls as a bare link.
- Fix the tile row: every tile has a different unstated base. "56.90%" is 33 of 58 named
  rows, which a reader takes as a share of the backlog and is therefore read 2.6x too high
  (it is 22% of the 150 rows on the page); "5 CNAs" is against a roster of 434 that appears
  nowhere; "185 days oldest" excludes 63 unageable rows, so it is the oldest *datable* row.
  Put the base in every tile as a second line, move the two instrument metrics
  (top-owner share, named-CNA count) into the bound strip where they belong, relabel
  "Days, oldest outstanding", and change the `pct` filter (`site.py:297`) to one decimal or
  an integer while keeping the raw ratio in the JSON. Two decimals on a 58-row base implies
  a precision of one part in ten thousand.
- Drop the precision `n/a` tile. It renders the literal string "n/a" in a 2rem
  `.metric-value` with a 70-character label, and measures 182-204px against 136px for its
  siblings, so a withheld figure sets the height of the whole row. Adopt the rule once: a
  tile holds a number or it does not exist, and absence is prose. Then fix the surviving
  three, which currently mix three denominators and one non-accuracy metric (run coverage)
  under one accuracy heading with no base rendered on any of them.

---

## Part 2: what should join the 50% coverage gate

The panel's clear consensus is that the coverage gate as defined is necessary and
nowhere near sufficient, and that five findings assumed it was the only gate. Promotion
should require all of the following, written into PLAN.md as a go/no-go checklist and
published on `/method` so the commitment is checkable from outside:

1. **Coverage** measured as `cnas_detectable` on the profile the cron actually runs,
   against a pinned roster, at or above the stated threshold, with the profile recorded in
   `summary.coverage`. Top-50-by-volume coverage reported alongside it. (Item 7.)
2. **No ungated name on any world-readable artefact**, enforced by a publish-time
   assertion, not a test. (Items 2, 9.)
3. **Every CNA named anywhere on the site inside the covered set** for the run that named
   it, as a build invariant that fails forever, not a threshold checked once. (Item 3.)
4. **A monitored non-public correction channel exists, and a suppression lever exists
   behind it**, with a published aggregate withheld count. (Item 4.)
5. **The 24-hour naming warrant is bound in code** with a floor that refuses to run below
   it. (Item 8.)
6. **One precision figure, stratified, with its sample composition stated** in the same
   sentence as the number. (Item 21.)
7. **A dated immutable archive exists** so anything cited before launch stays resolvable
   after the epoch flip. (Items 2, 14.)
8. **A failure notification exists** and has been exercised once. (Item 10.)
9. **The launch state has been rehearsed** via `dry_run` against real data, including the
   epoch flip. (Item 1.)

---

## Part 3: wanted, not blocking

Ranked by value per unit of effort. Several of these are prerequisites for items in
Part 1 and are marked as such.

21. **Stratify the precision claim, and publish one value.** HIGH. (CNA r2, MITRE r2,
    Consumer.) The out-of-sample warrant is 100% on n=224, and PLAN.md records twelve
    lines later that 213 of the 224 were one CNA; verified against
    `tests/fixtures/probe_2026-08-20.json` (GitHub_M 213 of 224 published cases). Eleven
    cases inform every other CNA in the Program, and both known-wrong rows are outside
    that 213. The outstanding ledger is 90 of 96 two block-holding CNAs, so the next 20
    verdicts will be too and crossing `GRADER_MIN_N` would license a figure that never
    tested the tail. The kill criterion is insensitive to the only failure mode that has
    occurred: with both wrong rows graded wrong and the other 94 right, precision reads
    97.9% and clears PLAN.md's ~97% floor while the tail error rate is 2 in 3. Group
    `validate_loo` by true owner, publish per-CNA precision and coverage with
    `MIN_DENOMINATOR` applied so a CNA below the floor reads "not separately measurable"
    rather than inheriting the global figure, record contiguous-run length per prediction
    now (it cannot be backfilled) so density bands are reportable later, make the floor and
    the kill criterion per-stratum, and render the owning CNA's own row on `cna.html`
    instead of the global figure. State the composition wherever the n=224 figure appears,
    PLAN.md included. **Also fix the two-answers bug**: the `GRADER_MIN_N` floor lives only
    in `site.py:48,170-172`, so `Grader.summary()` publishes the unfloored value into
    `summary.json` (`inference.live.precision: 1.0` at graded 1, already live on
    `origin/data`) beside `precision.json`'s `precision: null, below_floor: true`. Move the
    floor into `Grader.summary()`, delete the recomputation, stop appending the unfloored
    value into `history[].cumulative_precision`, and rename the derived file to
    `accuracy.json` so one basename stops carrying two incompatible schemas (one has
    `graded` as an int, the other as a list, and `/data` documents the fields of neither).
22. **CSAF: publisher identity, coordinator separation, and a time budget.** HIGH, and a
    prerequisite for item 7. (CNA, CISA r2/r3, Consumer, Python r2/r3.) Four defects in one
    adapter. (a) `out, seen = [], set()` is initialised outside the provider loop and the
    guard is on `cve_id` alone, so the first provider to yield an ID wins and every later
    publisher's row is discarded before `gather` sees it, which means the surviving row's
    `public_date` is whichever provider was enumerated first. Dedupe on
    `(cve_id, publisher)`. (b) `_ORIGIN` maps `"csaf": "csaf"`, so a vendor's own CSAF
    advisory counts as independent of that vendor's own feed and the row enters `kpi_core`;
    emit `csaf:<publisher-slug>` as the source so it lands in both `sources` and `dates`,
    map slugs onto origins, and add the test `_indep("redhat,csaf:redhat") == 1`. (c) The
    agreed fix is unsafe unless the two uses are split: `_ORIGIN` must fold a coordinator's
    or aggregator's republication onto the originating vendor for independence counting,
    while `OWNER_FEEDS` must contain vendor slugs only. Keep an explicit
    `COORDINATOR_PUBLISHERS` set (CISA, BSI CERT-Bund, JPCERT, CERT/CC, TR-CERT, INCIBE and
    aggregator-discovered mirrors), populate it from the CSAF document's own publisher
    category (`vendor` versus `coordinator`, already parsed), and assert at import that it
    is disjoint from `OWNER_FEEDS`, or a US-government republication becomes evidence that
    the vendor self-disclosed. (d) There is no wall-clock budget: the worst case for a
    single provider is roughly 69 minutes against `timeout-minutes: 45`, `_get_text` has no
    retry so one blip demotes a provider from dated `changes.csv` to undated `index.txt`
    (and undated entries then sort last and are cut by `entries[:cap]`), and
    `_expand_csaf_providers` reads the provider list out of a third party's
    `aggregator.json` in that file's order with no sort, so a remote party decides which
    CNAs `coverage.compute` credits. Add `deadline = time.monotonic() + budget` checked per
    provider and per directory, record TRUNCATED when it trips, sort providers on a stable
    key before truncating, and record the resolved provider list in `summary.json`. Also:
    every CSAF row currently publishes `advisory_url` as the cve.org last-resort fallback,
    a page that shows no record for a RESERVED ID, with `vendor`, `package` and `ecosystem`
    all empty, on the entire ICS and enterprise-vendor population. The entry `href` is in
    scope at `feeds.py:684` and discarded; carry it, add a `csaf` branch to `_u`, map the
    publisher into `_SRC_VENDOR`, and parse a product token out of the product tree, which
    also gives item 3's veto an input on ICS rows.
23. **Split the workflow into three jobs and shrink the token.** HIGH. (Actions x2, CISA,
    Consumer, MITRE, Marketing.) `permissions` is per job, so the `contents: write` +
    `pages: write` + `id-token: write` token is in the environment of the step that parses
    roughly 2 GB of third-party archives from hosts a remote aggregator chooses, after two
    checkouts that leave `x-access-token` in `.git/config` (`persist-credentials: false`
    appears nowhere), with three unpinned dependency ranges resolved from PyPI *after*
    those checkouts and no lockfile. `refs/remotes/origin/data` is the only copy of both
    ledgers, and `contents: write` is repository-wide, so a leak is persistence, not just
    data loss: an attacker pushes to `main`, which the next tick executes with the same
    permissions. Split into `build` (`permissions: contents: read`, which still lifts
    api.github.com to 1,000 req/hr, all item 8's token was for), `deploy`
    (`needs: build`, pages + id-token), and `persist` (`needs: deploy`, the only holder of
    `contents: write`, receiving the snapshot tree as a workflow artifact since
    `snapshots/` is gitignored). That single change also makes the comment at
    deploy.yml:147-149 true (the persist step is currently the last step of the job
    `deploy` depends on, so a push rejection discards an already-uploaded artefact) and
    gives the staged-path assertion a natural home. Add `git fetch && git rebase` with one
    retry, `permissions: {}` to `ci.yml`, a `requirements.lock` with
    `pip-compile --generate-hashes` installed via `--require-hashes`, SHA-pinned actions
    with Dependabot, `$GITHUB_STEP_SUMMARY` echoing the resolved
    `{profile, min_age_days, epoch, launched, coverage, reportable_rows}` before the
    pipeline runs, git trailers carrying `run_id` and `sha` on the state commit, and
    `.state/` to `.gitignore`.
24. **Ledger durability.** HIGH. (Python, Actions, CNA, CISA, Consumer, MITRE.) Three
    policies contradict each other for one artefact: both constructors do
    `except Exception: pass` and start empty, both `save()` methods then overwrite the
    original, `site.py:72-74` refuses to publish from a corrupt ledger, and the suite pins
    both policies at once (`tests/test_clock.py:250-254` asserts the silent reset,
    `tests/test_site.py:227` asserts the raise, for the same file). The site's guard is
    unreachable in the deploy flow because the pipeline overwrites before the build reads.
    `grep -rn "os.replace\|fsync\|\.tmp" rbp/` returns one unrelated hit across ~20
    writers, and `json.dump(obj, open(path, "w"))` truncates the file at the moment of the
    call with no explicit close, so a serialisation error leaves a partial file. Order the
    work by reachability, per the Actions amendment: the reachable destruction path in CI is
    *absence*, not an interrupted write, because the runner is ephemeral and
    `actions/cache` saves only on success. So: (a) the seed step must exit non-zero when
    `.state` is checked out and non-empty but a ledger file is missing, instead of printing
    "starting fresh" and continuing; (b) capture `len(graded)`/`len(resolved)` into
    `$GITHUB_OUTPUT` at seed and fail the persist step if either decreased, dropping the
    `2>/dev/null || true` masks, since a missing `precision.json` at persist time is a bug;
    (c) mirror both ledgers off-repo (item 2's releases); (d) add one `_atomic_write` helper
    (tmp, flush, fsync, `os.replace`, unlink on failure) and route all writers through it,
    including the parquet writes; (e) on a parse failure of a non-empty file,
    `os.replace(path, path + ".corrupt")` and raise, and delete the test that pins the
    reset. These two files are the only artefacts on the branch not regenerable from a
    snapshot, and `resolutions.json` is the only record that can ever say something good
    about a CNA.
25. **Ledger population drift.** MEDIUM. (Consumer, CNA, MITRE, CISA, Actions.)
    `ledger.track` only ever inserts and nothing prunes, and the assertion item 7 asked for
    shipped as a `print` at `cli.py:146-148` that leaves the run green. The drifted
    population is published twice, as `resolutions_tracked` on `/changes` and through
    `by_owner()` into every `cnas.json` entry and per-CNA median. It becomes unbounded the
    moment `RBP_EPOCH` is set. Have `track` reconcile both directions with a `withdrawn`
    bucket carrying a reason, publish the withdrawn counts, and make the mismatch fail
    (bounded, not strict equality, since a transient oracle ERROR legitimately drops a row
    for one run).
26. **`cnas.json` publishes both operands of the ratio the code forbids publishing.**
    HIGH. (Consumer r3, new in round 3.) `clock.py:443-450` explains at length why a rate
    column must not exist: `outstanding/published_12mo` is exactly the arithmetic v1.0
    attached its withdrawn 5% and 50% sanction triggers to, the v1.0 PDF is still hosted by
    third parties, and "a rate column is a leaderboard whatever the caption says". The
    artefact then ships the numerator and the denominator one key apart, per named CNA,
    in a file `/data` documents as "Descriptive only, no thresholds", and
    `published_12mo` is rendered nowhere. Drop `published_12mo` from `cnas.json` and
    `data/cna/<slug>.json` and keep the scale context on the page as a non-divisible band,
    or publish a `ratio_note` in the same object; a note does not survive a
    `read_json` and a column selection, which is the whole argument in that comment. Fix
    `data.html:24-25`, state the decision in PLAN.md next to the leaderboard prohibition,
    and assert at build time that a per-CNA numerator and denominator are never published
    together without the note.
27. **`cnas.json` absence conflates four states.** MEDIUM. (Consumer r3.) The file is five
    entries against a 434-CNA roster with no field marking absence, so it reads as "these
    are the CNAs with outstanding RBPs and everyone else is clean", which is the inverse of
    the site's own floor language and lands hardest on the CNAs the feeds do reach.
    Publish it as an envelope with the roster counts and an explicit
    `meaning_of_absence` naming all four states (no rows, feeds not ingested, below the
    inference gate, held back), plus `own_feed_ingested` and `reached` per entry.
28. **Payload and column budget on `/cves`.** MEDIUM. (Design, CISA on the Pages bandwidth
    ceiling, Consumer.) The page is 132,322 bytes of which the inline `<script id="rows">`
    blob is 118,952 (89.9%) for 150 rows, duplicating `data/rbp.json`, with 10 of 27 keys
    rendered by no cell. At 553 rows that is roughly 440 KB of inline JSON before anything
    paints. Emit a purpose-built minimal projection rather than the full row set, and keep
    `data/rbp.json` as the consumer artefact free to carry the full field set; do not have
    the page fetch it, since "no network, no runtime API calls: every page is a file" is a
    stated property. Decide this before writing the server-rendered tbody, which would
    otherwise add the rendered rows on top of the blob. Fold Sources and Independent
    sources into one origins cell ("2 independent of 3 feeds: alas, ubuntu"); the two
    columns and a sub-line currently render one idea, and the Independent-sources column
    alone is 166px of a 1,474px table that must fit 1,152px.
29. **The constant qualifier, and the false AA claim in the stylesheet.** MEDIUM.
    (Design r1/r2, CNA, Consumer.) `rule_certainty` is set unconditionally to "candidate"
    on all 150 rows and `rule_basis` takes two values, so the per-row `.qualifier`
    sub-line is one of two constant strings and costs about 21% of the table's height
    (11,982px against 9,475px) for text that repeats the owner cell two columns away. Move
    "candidate" into the `<th>` and a `<caption>`; keep `rule_basis` as a per-row token,
    since a 58/92 split on whether the rule reading rests on a guessed name is the most
    fairness-relevant fact in the row. Delete or fix the false accessibility claim at
    `rbp.css:206`, which asserts AA against a background the class never renders on. Do
    the same in the artefacts: a constant belongs in the envelope, not repeated 150 times
    per file.
30. **Component vocabulary, and the `&mdash;` entity.** LOW to MEDIUM. (Design, MITRE,
    CISA, CNA.) One `.caveat` treatment carries four meanings across 15 uses, including
    `<blockquote class="caveat">` on verbatim RBP Policy v2.0.0 and CNA Rule 4.5.1.7 text,
    so a reader cannot tell the Program's words from the site's. Split `.quote` out first,
    with a citation line naming document and section; that one is citation integrity, not
    style. Then `.caveat` for standing hedges, `.notice` for run-scoped degradation, and a
    plain empty-state treatment, allocating distinct fills, since `.caveat`'s current fill
    is the same token as the table header and the even-row stripe. Do this before the
    queued `_caveats.html` partial adds a fifth use. Separately, four `&mdash;` literals
    sit inside Jinja expressions under `select_autoescape` and render as `&mdash;d` in
    numeric cells (`cna.html:42`, `cnas.html:48-49`, `changes.html:79`); do not touch
    `cna.html:51`, which is template text and correct. Add the render assertion that no
    built page contains `&amp;`, which catches the whole class.
31. **Corpus and OSV hardening.** MEDIUM. (Python r1/r2, Actions, CISA, Consumer.)
    `cvelist.py` uses none of the hardening `feeds.py` built: `_releases` is a bare
    `urlopen` with no retry, called from `ensure_corpus` before any feed, so one transient
    5xx from api.github.com ends the run before a line of data is read, four times a day
    (fix this first, it is three lines and the highest-frequency single point of failure);
    `_delta_rows` reads an uncapped blob; `download_baseline` is `urlretrieve` with no
    timeout on 583 MB; `apply_deltas` reads and rewrites `corpus.parquet` in place with no
    try, while `refresh_corpus` has a rebuild fallback for every other failure mode.
    `_iter_records` also materialises the inner zip in RAM outside both size guards and
    never closes its handles. Move `_OPENER`, `_get` and the byte caps into a shared
    module; note the real hardening gap is narrow and precise: `download_baseline` passes
    `browser_download_url`, read from a remote JSON body, to `urlretrieve`, which honours
    `http://` and `file://` and follows redirects unvalidated. Separately, `feed_osv` never
    closes its `ZipFile` and unlinks the temp file only on the success path, and any
    exception in the record loop escapes into `gather`, which records the whole `osv` feed
    FAILED and skips every remaining ecosystem; wrap each ecosystem in try/except that
    records `osv:<eco>` FAILED and continues, and make `_stream_zip` a context manager
    owning both objects (closing before unlinking).
32. **One writer per row field.** MEDIUM. (Python r3, new in round 3.) Three of the bugs
    this project has shipped were one stage reading or writing a field another stage owns,
    each found in production. The duplication that made them possible is still there:
    `report._age` duplicates `clock.age_days`; `_gated` recomputes `self_disclosed` and
    hard-codes `False` for unattributed rows while `_publishable` (which writes
    `held_back.json`) preserves what `annotate` computed, so one run publishes the field
    under two rules into two artefacts on the public branch; `owner_contested` exists only
    inside `_publishable` and is derived from a field `report.py` then strips, so it is
    unreproducible from any published field. Delete the duplicates, move `owner_contested`
    into `annotate`, and generalise the existing precedent at
    `tests/test_pipeline.py:171` (which already asserts only `clock.py` defines
    `OWNER_FEEDS`) to assert that only `clock.py` assigns `days_public`, `self_disclosed`,
    `past_expectation`, `rule`, `rule_strength` and `owner_contested`. That test would have
    caught all three historical bugs and is cheaper than any of the three fixes was.
33. **Age histogram draws a structural zero and the oldest row identically.** MEDIUM.
    (Design r3, new in round 3.) `index.html:63-67` hard-codes five buckets including
    `<7d`, which is empty by construction while `min_age_days > 0` and has no key in
    `summary.json` at all; measured bar heights are `[2, 80, 34, 6, 2]`, so the impossible
    bucket and the single 180d+ row (the most rhetorically load-bearing datum on the page)
    draw as the same 2px nub, with no axis, no scale, and counts recoverable only from a
    0.65rem label row measuring 2.07:1. Drop the `<7d` bucket, give any `n >= 1` a floor
    that reads as present, label a genuine zero as "none", state the peak, and raise
    `.histo-labels` to an accessible token.
34. **Two visual identities.** LOW. (Design r3, amended.) `placeholder.html` loads neither
    stylesheet and defines its own palette, measure and hierarchy, and is measurably the
    more accessible surface. Restyle it into the cve.icu system rather than the reverse:
    looking like cve.icu is a deliberate credibility asset and re-tokenising it to the
    holding page's teal would spend that asset to fix a consistency problem. Import the
    holding page's accessibility advantages as token corrections inside `rbp.css` (item 17
    is the vehicle). Do this before the page becomes a permanent route, or the preserved
    page arrives as a visual orphan.
35. **Export-link sizing.** LOW. (Design r2, amended.) The CSV and JSON links render at
    41x21 and 49x21, styled from a cve.icu chart-hover control revealed by `:focus-within`,
    on the only route to the bulk data from a page whose sibling says "Others building on
    this is the point". Give them a project-owned class sized as a primary action and raise
    the search input (34px) and selects (36px) to one consistent control-row height. Do not
    restyle `.chart-export-btn` itself; `style.css` stays a re-pullable upstream copy.
36. **Delete the dead `else` branch, and assert the build output.** LOW, but do the
    assertion. (Actions, amended twice including by its author.) `deploy.yml:138-145` still
    has a success path that publishes a one-page holding site over the live dashboard if
    `rbp/site.py` is ever absent. The valuable half is the output assertion that replaces
    it: `test -s site/index.html`, a non-empty and row-counted `site/data/rbp.json`, a
    minimum page count, every emitted `cna/` href resolving to a file, and no `cna/`
    directory pre-launch. That assertion also catches a template that renders empty and the
    five dead `/cna` links currently on the deployed `/cnas` page.

---

## Part 4: dropped, and downgraded

Recorded so they are not silently lost, with the reason the refutation won.

- **"Add `feeds.truncated` to the `_changes` comparability keys."** Proposed by three
  findings, **withdrawn by two of their authors**. Ubuntu is truncated on every run, so
  both snapshots compare equal in exactly the case where the cap boundary has moved and
  taken rows with it. The guard would fire on the rare transition and miss the every-run
  condition. Superseded by per-feed row counts and window edges (item 15).
- **"Raise `SystemExit` in `site.load` when coverage is below gate."** Proposed by five
  findings, **withdrawn or amended by four reviewers including two authors**. It makes the
  promotion gate able to take a launched site down: the coverage denominator moves every
  run and steps on 1 January, a feed outage moves the numerator, and the deploy job is
  skipped on a failed build, so the observable result is a permanently frozen site with no
  notification. Superseded by item 7's transition gate plus item 10's taxonomy.
- **"Refuse to publish when `len(reportable)` is below an absolute floor."** Refuted: zero
  is this project's goal state, not an error state, and 4.5.3.5 makes a bulk rejection
  sweep a legitimate large drop. Superseded by a fractional-drop comparison against the
  previous snapshot.
- **"Add a hard-coded deny list of the two wrong CVE IDs."** Proposed by four findings,
  **withdrawn by two authors**. It fixes two rows and leaves the class; it is a permanent
  public artefact reading "these two names were wrong and we patched them by hand"; and it
  would not even work, because both names are already in the ledger under
  first-prediction-wins, so a downstream suppression leaves them published. Superseded by
  the covered-set gate plus the withdrawal bucket (item 3).
- **"`must_rows: 0` should render as 'not measured, own feed not ingested'."** Proposed by
  four findings, refuted on fact: `PROFILES["weekly"]` contains `redhat` and `mozilla`, so
  that string would be false on every scheduled build. The zero in the snapshot on disk
  comes from a three-feed hand run. Superseded by removing the tile and rendering the
  denominator (item 12).
- **"Name the largest CNA in the front-page concentration tile."** Refuted: a lead-screen
  tile naming one CNA as holder of the majority is a leaderboard with one entrant, which
  PLAN 2a forbids and which `clock.py:440-447` deliberately refuses to build. Superseded by
  a distribution plus the CNA-LR disclosure (item 19).
- **"Rewrite `policy.html:134-141` to remove the errata framing."** **Refuted outright.**
  The premise that the wrong claim never circulated is false (the repository is public and
  the erroneous wording is in public template and commit history), and the errata is an
  asset: a dated in-page record of the project correcting its own two strongest claims
  against the Program is the cheapest demonstration that it accepts the standard it is
  asking for. Keep it, reframe it as a dated Corrections section, and fix
  `index.html:131` so the retracted figure is not the only live version.
- **"Force-push an orphan `data` branch as the first remediation step."** Refuted: it
  destroys the only copy of both ledgers and the entire dated series, which PLAN.md R1
  names as the mitigation for the reservation endpoint being closed. Superseded by item
  2's ordering (mirror, enforce, pause, then a targeted `filter-repo`).
- **"`top_missed` should be removed from the published envelope."** Refuted by three
  reviewers: it is the single most useful self-limiting disclosure in `summary.json` and
  the only machine-readable description of the shape of the floor. Keep it, rename it
  `cnas_not_reached`, and publish it as an object carrying its own `meaning` string so the
  explanation cannot be separated from the names by a consumer that keeps only the array.
  The proposed regex test on key names was also dropped; the invariant is that the list
  travels with its meaning, not that a string is absent.
- **"Gate `data/rbp.json`, `rbp.csv` and `cnas.json` on `RBP_LAUNCHED`, or swap `owner` to
  'withheld-prelaunch'."** Both branches amended. Gating means the two documented primary
  URLs 404 pre-launch and then appear, which is the worst possible contract; a value
  substitution changes a field's meaning with no version marker. If redaction is chosen it
  must be a declared schema state with a version bump and an explicit `owner_redacted`
  flag. And note the code comments contradict each other about whether the gate is a
  disclosure control at all (`site.py:32-34` versus `:386-391`); fix the comments to
  describe what the code does.
- **"`observed_pct >= 25%` as a launch condition."** **Withdrawn by its author.** At 7.04%
  of published CVEs, over a corpus dominated by CNAs with no distro or ecosystem presence,
  25% may be structurally unreachable, so the gate would either never open or be quietly
  relaxed. Publish `observed_pct` as a disclosure figure instead.
- **"Validate `RBP_LAUNCHED` strictly because `=on` silently means not-launched."**
  Downgraded to LOW: the lax parse fails *closed*, so it cannot cause a premature launch.
  Worth one line for symmetry with the epoch validator; not a safety item.
- **Downgraded on severity, keep the fix:** the `&mdash;` entity (LOW; latent, zero
  occurrences in any current build, but keep the render assertion); the two-CSV column
  divergence (the Consumer statement at HIGH supersedes the Python statement at LOW,
  because the missing fields are the audit fields); the corrupt-ledger atomicity half
  (MEDIUM; the reachable CI path is absence, so the workflow guards outrank the 20-writer
  refactor); mutable-tag action pinning (LOW; first-party `actions/*`, and the three
  unpinned PyPI ranges in the same job are the higher risk); the dead `else` branch (LOW;
  reaching it requires a committed rename); `design-r2-two-visual-identities` (LOW);
  `marketing-the-ask-disappears-on-launch-day` (MEDIUM; the ask does survive on `/policy`
  and `/method`, the front page and the holding page's composition are what is lost).
- **Corrected evidence, conclusions kept:** the `/cves` table is 1,474px intrinsic at
  1280px and 2,488px at 375px, so the column budget is a mild desktop annoyance and a
  total mobile failure; the qualifier sub-lines cost 0px of *width* and about 21% of table
  *height*, not "+42% row height"; removing the Independent-sources column takes 1,474 to
  1,308, which still overflows 1,152, and relaxing `td.desc { min-width }` buys nothing;
  the export links pass SC 2.5.8's spacing exception (52.9px apart) so the WCAG citation
  was struck while the sizing complaint stands; "last column Q3 2021" and "final column
  already reading N/A" are not contradictory, they are an asymmetry of emphasis, and the
  finding should say so or a critic who checks `Metrics.vue` will discount the rest; two of
  the four omitted policy clauses are in Notification and Remediation, not Timely
  Publication, and filing them wrongly would be the error `tests/test_policy.py` exists to
  prevent; the archived quarterly table's dependence on v1.0's thresholds is a hypothesis,
  not an established fact, and should not be asserted; "a third of the headline will leave
  the same way it arrived" is wrong, rows do not exit by ageing, so arrival is lumpy and
  departure is not, which is worth stating rather than implying symmetry.

---

## Part 5: chair additions

Four things the panel did not raise.

**C1. This document must not carry the wrong attributions, and probably should not be
public yet.** The previous `REVIEW.md` draft contains two of the disputed
(CVE ID, CNA) pairs (`grep -c` returns 2) and, in the panel record, verbatim
`held_back.json` rows including a named CNA on a one-day-old within-buffer ID. Committing
that to a public repository republishes the false attributions that item 3 exists to
retract, in a file whose stated purpose is to say they are false, and hands a reader a
catalogue of the project's unremediated disclosure exposures with file and line numbers.
This version refers to bug classes rather than identifiers throughout, deliberately. Keep
it that way, and consider holding the file out of the public repo until Part 1 items 1 to 4
have landed. This is the same defect as `cisa-r3-wrong-attributions-committed-in-source-comments`,
one layer up, and the panel produced it while diagnosing it.

**C2. PLAN.md is a public file, and nobody asked whether it should be.** It carries the
risk register, the launch-gate arithmetic, the "Never say" boundary the code now breaks
(item 18), and R3's assertion that the correction mechanism is a live mitigation when it
does not exist (item 4). Every panellist quoted PLAN.md as authority; a hostile reader will
too, and the first quote will be a control the plan claims and the code lacks. Decide
deliberately whether PLAN.md is a public artefact. If it stays public it has to be kept
strictly current, because a stale plan asserting controls that do not exist is exactly the
defect the whole site is about, committed by the site's own author.

**C3. The gate will be met long before the remediation is, and there is no written go/no-go.**
Coverage is at 40.6% against a 50% gate; that is one CSAF profile change away. Part 1 is
weeks of work. The predictable failure mode of a review this size is that the gate opens,
the pressure to launch arrives, and half of Part 1 is done. Write Part 2's checklist into
PLAN.md as a hard go/no-go before touching any code, so the launch decision is against a
list rather than against a number and a memory.

**C4. Pick six items and defer the rest explicitly.** Ninety findings and one maintainer.
My recommended cut, in order: items 1, 2, 3, 4, 5, then 11 (the copy pass, because it is
two hours and changes how the site reads more than anything else on the list). Items 9 and
10 are prerequisites that make everything after them stick, so they come next. Everything
in Part 3 should be written down as a post-launch list with owners and dropped from the
pre-launch conversation entirely, because the alternative is that all thirty items are
80% done, which is the state this review has just finished documenting.

---

## What the panel disagreed about most, and why it matters

**Whether a guard should refuse to publish.** This produced more amendments than any other
question: six findings proposed an in-process refusal and four reviewers argued in each
case that a refusal converts a data fault into a silent publication outage, since the
deploy job is skipped on a failed build and no notification exists. The disagreement
matters because both sides are right about different classes of fault, and resolving it
per-guard would have produced six inconsistent behaviours on an unattended six-hourly
cron. The rule the panel converged on, and which item 10 records, is worth writing into
PLAN.md verbatim: refuse to publish wrong data, never refuse to publish correct data that
is merely surprising, and never fail dark. This project already has the vocabulary to
publish honestly while degraded (a floor claim, a truncation banner, an unattributed
state, a not-comparable flag), and a refusal throws all of it away.

**How weak the evidence for a *veto* may be.** The naming pipeline deliberately bans
description matching, because `glibc` once matched `glib` and named Red Hat. Three
reviewers argued the ban should not extend to withholding a name, because a veto's failure
mode is abstention rather than defamation, and that asymmetry is sound. Two argued against
re-litigating a self-imposed ban under launch pressure. The panel landed on neither: the
covered-set gate achieves the same suppression with no new inference surface, so the
asymmetry principle should be written down on `/method` as a stated design rule and cashed
in later, not this week. That is the right outcome, and it is a good example of the panel
finding a third option under cross-examination rather than splitting the difference.

**Whether the launch epoch is a good idea at all.** Two reviewers argued it forfeits the
project's strongest evidence at the exact moment of promotion; one argued, late and
persuasively, that a post-epoch cohort flow net of closures is much closer in shape to the
archived quarterly series the site is asking the Program to restore, which makes the epoch
defensible on the merits rather than merely as a stability measure. That reframing also
means the site's own non-comparability paragraph becomes wrong in the opposite direction on
the day the epoch is set, unremarked, on both the page that makes the ask and the page that
leads with the count. Nobody has decided which framing the project holds. It should be
decided before `RBP_EPOCH` is set, not after, and the answer determines whether item 6's
archive route is a courtesy or the load-bearing part.

**Whether the concentration finding is about data or about positioning.** The data
reviewers treated the 57% top-owner share as a measurement problem (block width, feed
coverage, an undifferentiated CNA-LR pool); the marketing and Program reviewers treated it
as the single most likely story to be written from this site, and the one that would make
the ask unwinnable. Both readings are correct and they imply different fixes: better
attribution versus a different presentation. The panel's answer is to do the presentation
fix now, because it is cheap and reversible, and to state the attribution limitation
rather than infer around it. That is the right call, and it is the clearest instance of the
general lesson in this review: on a site whose only asset is being trusted with a number,
the presentation of a limit is not decoration, it is the measurement.

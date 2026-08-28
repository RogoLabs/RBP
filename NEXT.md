# Where this stands, and what to pick up next

Rewritten 2026-08-26, after the single-page pivot and the cleanup that followed
it. Everything below is checked against the repo on that date, not planned.

The previous version of this file was written on 08-24 and was superseded within
two days without being touched. Its first action item told you to rehearse a
withhold channel that had been deleted; its headline figure was a launch
condition that had been retired. **If you change what the site does, this file is
part of the change.**

---

## What the site is now

**A list.** "Here are the CVE IDs that are reserved and public, and where they are
showing up." Five routes:

| route | what it is |
|---|---|
| `/` | the rows, a command bar over them, and a slide-over carrying the argument |
| `/method.html` | how the count is built, the coverage table, the limits |
| `/policy.html` | the policy text and what changed in v2.0.0 |
| `/status.html` | whether the last run was complete, per-feed health, cadence, movement |
| `/about-this-count.html` | the holding-page copy in the site chrome, written in both postures |

It previously led with the count as an instrument panel: a 104px number and around
650 words before the first CVE, over a seven-column table. `cves`, `changes`,
`data` and `backlog-at-launch` are gone and their content is in the slide-over.

**No CNA is named.** `site.NAMING_ENABLED` is the single flag. Inference and the
grader still run, so a v2 naming release starts from real graded n rather than
from one.

**The gate clears.** `GATE_TOP_N_PCT = 80.0` on top-50-CNAs-by-volume at the
3-sighting floor. 42 of 50 on 2026-08-27, up from 41 on 08-24. The re-derivation is
in the constant's own comment in `rbp/site.py`.

**809 offline tests in about fifteen seconds, plus 43 browser tests.** The offline
suite gates the publication; the browser suite and the linter are on the commit
path only and cannot stop a publish.

**The front page opens on the last 90 days.** Not on everything, since 2026-08-27.
The default is stated above the list with the full count and a control that clears
it. See the decisions section below for why, and for what it does not fix.

---

## What shipped in the cleanup, 2026-08-26

A full review of the tree after the pivot. The theme, in one sentence: **the pivot
changed what renders and the guards were only partly repointed**, so 735 tests
passed while three defects sat on shipping pages.

### Live defects that a green suite was not seeing

- **The front page had no `<h1>`.** The outline started at the panel's `h2`,
  inside a hidden dialog. The test for exactly this passed throughout, because it
  read `templates/index.html` after that template stopped being rendered.
- **`/method` linked to `/data.html`, which 404s**, inside a
  `{% if summary.epoch %}` block. The link checker was correct; the end-to-end
  fixture sets `epoch: None`, so it could not see the markup. It would have
  appeared the morning an epoch was set, which is launch day.
- **`/method` said "one of nine conditions" above "8 of 8 are met."** Condition 4
  was retired and the prose was not.
- **Every even table row failed AA in dark theme at 2.6:1**, links at 1.56:1.
  `rbp.css` already carried a comment describing this exact defect and a corrected
  rule *scoped to `table.rbp`*, leaving the unscoped original live. The pivot then
  deleted every page `table.rbp` was on, so the fix covered one table and the bug
  covered the rest of the site.
- **The launch-day zero state was gone**, dropped in the move to `list.html`. An
  epoch set on launch morning would have rendered `0` over a blank page.
- **Three surfaces still promised the deleted withhold channel**: `/method` in
  full, the footer on every page, and the holding page.

### Guards that had stopped guarding

- **14 tests asserted against templates that are never rendered.** Repointed where
  the concern was still live, deleted where the pivot made it obsolete.
- **The contrast sweep silently skipped 14 cases.** `contrast.rule_colors`
  required a trailing `;` on the `color:` declaration, which nobody writes when
  minifying, so every rule the pivot added parsed as declaring no colour and
  skipped saying it "inherits". All 14 pass once measured. There is a cap now.
- **The scrubber and the guard had drifted.** `publish._named_paths`'s docstring
  says "the guard must refuse exactly what the scrubber removes or the two drift".
  They differed by three fields, and nothing tested the claim.
- **Four overlapping lists of "fields that name a CNA"**, two byte-identical, on a
  rule whose whole value is that a new field cannot be forgotten. One definition
  now, in `schema.py`.
- **The withhold lever had no writer.** `cli.py` stopped writing
  `.suppressed.json` when the channel was removed, nothing replaced it, and
  `data/` is recreated empty on every runner. The lever the site promised in
  writing read an absent file on every run. It is `RBP_WITHHOLD` now, a repository
  variable, and not the `data` branch: that branch is public, so committing the
  ids there would publish the list the lever exists to remove.

### Also fixed

**/about-this-count had no site chrome.** It served a byte-for-byte copy of the
standalone `placeholder.html`: no header, no nav, no footer, no theme toggle, and
its own teal palette. It is in the nav as "About", so clicking it landed a reader
somewhere that looked like a different site with no way back. The words now live
in `templates/_about-copy.html` and two shells wrap them, `about.html` with the
site chrome and `holding.html` for the pre-launch front door, which still must not
link into the dashboard.

### Removed

1,351 lines of unrendered templates; `placeholder.html`, whose copy moved into the
partial above unchanged; 18 KB of imported CSS styling components this
site does not have; `env.get_template("cna.html")` for a template that did not
exist, so flipping `NAMING_ENABLED` raised `TemplateNotFound` on the first build.

### Added

`/status.html`, and a linter.

**The degraded banner is gone from the pages that carry the count.** It rendered
above the first CVE on every page whenever a feed failed, stopped early or shrank.
It was first shortened to one line plus a link, and then removed outright on
Jerry's call: the reader of a list of CVE IDs should not be interrupted by the
state of the build that produced it.

PLAN.md carries a rule reading "never publish a degraded run without a banner",
written when `/method` was three clicks away and no page had the run as its
subject. **That rule is superseded by this decision, not overlooked**, and the
condition is still disclosed in four places, none of them a banner:

- `/status.html`, whose whole subject is the last run, in the nav on every page
  and on every run rather than only the bad ones;
- `degraded` and `degraded_reasons` in `data/rbp.json`, which is what a consumer
  reusing the count actually reads;
- the standing hedge above the rows, which says the count is a floor on every run;
- the staleness banner, which is a different thing and stays: it fires when the
  pipeline has *stopped*, is computed in the browser because a stopped pipeline
  cannot recompute anything server-side, and says the numbers are old rather than
  incomplete.

The cost, stated rather than left to be found: a reader who looks only at the list
on a degraded run is not told on that page that the count is a lower floor than
usual. `tests/test_status.py` asserts the absence in both postures, so reversing
this is a deliberate act rather than a drift.

There was no linter: 52 `# noqa` directives and no tool
anywhere that reads one. Every rule now selected found a real defect on its first
run.

---

## Decisions taken 2026-08-27, so they are not re-opened by accident

Four of these were open questions in `docs/reviews/REVIEW-round6-pre-announce.md`.
They are settled now, and each one is settled in a place a reader will find it
rather than only here.

**The corroborated count is gone, not repointed.** The `>=2 independent origins`
figure produced a second headline: the `<h1>` rendered `summary.total` while
`og:description` rendered `summary.corroborated`, so one link preview carried
1,709 and 201 on adjacent lines. `report._indep`, `report._ORIGIN`,
`indep_sources`, `single_origin` and `summary.corroborated` are all removed;
`SCHEMA_VERSION` is 3. `sources` and `refs` still ship in full, so independence
stays derivable by anyone who wants to compute it.

**The launch-day epoch is retired, unused.** See PLAN.md. Setting it now would
take a publicly indexed count to zero. The mechanism stays as insurance.

**The front page opens on the last 90 days.** Sorted oldest-first with no filter,
the first ten rows were all Android. The default is announced on the page with the
full count and a control that turns it off, because the rows it hides are the
oldest and therefore the strongest evidence the site has. **It only partly works,
and the number is in the review**: distinct package groups in the first ten rows
went from 2 to 4. The rows arrive in batches from one advisory, so any date sort
clusters; the fix that attacks the cause is collapsing runs from one package, and
it is not built.

**`/method` no longer publishes the launch checklist.** A launched site publishing
its own launch checklist reads as either out of date or not actually launched.
`rbp/launch.py` and `tests/test_launch.py` are untouched and now have **no
production caller**, which is a loose end left deliberately: the eight conditions
are the design record, and deleting the module is a separate decision.

**The hedge above the rows is gone, and NEXT.md's own argument is weaker for it.**
"A floor, not a total..." sat ahead of the first CVE because it had been a
`<caption>`, so the qualifier travelled with a copy, a print or a screen-reader
pass. Jerry removed it. **The entry above about the degraded banner leaned on this
hedge as one of four standing disclosures, and that leg is now gone**: the floor
claim survives in the panel, which is a hidden dialog, on /method and in
`rbp.json`, and none of those travels with a selection. So on a degraded run a
reader who copies the rows carries neither the floor caveat nor a note that the
count is lower than usual. Three disclosures remain, not four. If that gap ever
looks too wide, the cheapest fix is a one-line floor note rather than the banner.

**There is no removal channel and no email address on the site.** Retired from all
five surfaces: the footer, the panel, the About copy, /method and
`.well-known/security.txt`. The reasoning is the project's own from 2026-08-26: a
row is listed only after the reservation endpoint confirms the ID is reserved and
unpublished, so there is nothing to correct, and every row is an ID already
referenced in a public advisory and held for the buffer, so there is nothing to
withhold that is not already public.

The cost, and it is the one accuracy does not reach: the case the channel answered
was the **embargo**, not the error. A row can be entirely correct and its listing
still cut across a live coordinated disclosure. That case now has no route here.

`security.txt` stays valid on the GitHub private-advisory URL alone (RFC 9116
needs one Contact) and now says explicitly that it is for a vulnerability in this
site's own code and that the site operates no removal channel. **`RBP_WITHHOLD` is
untouched**: it still drops rows from every artefact, `publish.check` still refuses
to stage them, and it is still tested. The capability is kept and not advertised,
which is a deliberate distinction. Item 3 below still asks for it to be rehearsed.

**UI chrome is title case.** Control labels, options, optgroups, buttons, status
chips and metric labels. Prose is not: placeholders, empty-state sentences, card
headings and body copy stay sentence case, because title-casing a sentence reads
as broken. Two guards asserted the old lower-case literals and are case-insensitive
now, since what they are about is that a label exists rather than how it is cased.

**The About/panel duplication STAYS, and this is the evidence.** Eight of the ten
paragraphs on `/about-this-count` are byte-identical to the front-page panel, and
every one of them is pinned to both surfaces by an existing test:
`test_the_about_page_and_the_front_door_share_one_copy`,
`test_the_front_page_quotes_the_clauses_that_cut_against_it`,
`test_the_n_a_final_column_fact_is_on_both_front_doors` and
`test_the_flow_versus_stock_distinction_is_on_the_holding_page`. The duplication
is the mechanism by which the front page is not selective about the policy. Anyone
trimming it is deleting that standard, not deleting a copy-paste.

---

## Pass 3, 2026-08-27: the polish items

All six mediums and the reachable half of H5, each with a guard that fails
without it, mutation-tested by putting the defect back.

- **M2.** `.card-prose` is centred. It capped the measure at 78ch with no auto
  margin, so /about-this-count was the only page whose cards stopped two thirds of
  the way across, border ending mid-screen.
- **M3.** The skip link is fully off screen. `top: -40px` against a computed
  height of 41.6px left 1.6px of blue in the top-left corner of every page. The
  offset derives from its own height now, so a padding change cannot uncover it.
- **M4.** Six tables have `.sr-only` captions. The card heading above each one is
  not in scope for someone moving table to table with a screen reader.
- **M6.** The mobile menu closes: Escape (returning focus to the toggle), a click
  outside, following a link, and crossing the breakpoint. It could only be opened.
- **M7.** 71 rules deleted from `style.css`, 7,685 bytes, 23% of the file. Every
  one referenced only classes that appear in no built page and no template:
  `homepage-chart-*`, `stat-card`, `chart-export-*`, `dropdown-menu`,
  `insight-card`, `quick-select-*`, `viz-*`, `year-grid`, `btn`, `row`. This is
  the file whose duplicate unscoped rule caused the dark-theme AA failure.
  `rbp/contrast.py` already worked *around* this dead CSS by filtering to
  rendered classes; that workaround has less to do now.
- **M8.** **Inter is self-hosted and the site makes no third-party request at
  all.** One 48 KB variable woff2 under `static/fonts`, OFL text alongside it, one
  `@font-face` at `font-weight: 100 900`, preloaded with `crossorigin` because the
  face now lives inside `rbp.css` and would otherwise be discovered a round trip
  late. Google served the *same* variable file for all five weights it declared,
  so the four downloads were byte-identical; the site was also requesting a 300
  weight nothing renders. `test_the_site_makes_no_third_party_request` asserts the
  absence over every sub-resource rather than over the two font hosts by name, so
  a future embed or analytics snippet fails it too.
- **H5, half.** A `<noscript>` block on the list page pointing at `rbp.csv`,
  `rbp.json` and the field definitions. The rows are drawn from the JSON island,
  so zero CVE IDs appear in the served markup and the page was a command bar over
  a blank space for reader modes, text browsers and non-rendering crawlers. Its
  guard asserts the links resolve, and asserts the premise: if CVE IDs ever start
  appearing in the markup it fails rather than passing about a problem that has
  gone away.

**H5's other half is not done and is a v2 conversation.** No individual CVE ID has
a URL on this site, so a search for a specific reserved CVE will never reach it.
That is the largest remaining gap in the design for a site whose purpose is to be
cited.

---

## The three things waiting for you

### 1. Decide whether the margin is acceptable

**Unchanged, and still yours.** The gate is at 41 of 50 (82.0%), clearing by one
CNA. It moved from 40 to 41 overnight on 08-24 because HPE published and a feed
saw it three times. A gate that moves without a commit can move back.

The CSAF sweep is closed: one of ten uncovered top-50 CNAs serves CSAF at the
well-known path and it returns 401 on all 121 advisories. What remains is a parser
each, at FEEDS.md's rate of 2 to 3 CNAs per working day including the scorecard.

The nine that would buy headroom: WPScan, dell, TR-CERT, sap, huawei, twcert, HCL,
qnap, juniper.

> **UPDATED 2026-08-27 by round 7. They are not nine of a kind, and the two this
> section recommends do not have the routes it assumed.**
>
> **Three of them are two sightings short, not a parser short.** `dell`,
> `TR-CERT` and `sap` each have exactly ONE sighting against a floor of three, so
> they are counted in `cnas_sighted` and not in `cnas_effective`. Two more
> sightings apiece takes the gate from 42 of 50 to 45. Twelve further roster CNAs
> are a single sighting short. `python -m rbp.feedlab near-floor` now reports it;
> nothing did before, although the difference between the published
> `top_missed_effective` and `top_missed` lists was exactly this set all along.
>
> **The TWCERT and TR-CERT 200s are HTML pages.** Re-probed 2026-08-27: TR-CERT
> serves the same 7,091-byte document at `/`, `/bildirim` AND `/rss.xml`, and
> TWCERT's English locale 302s while only a 30KB Chinese-locale CMS listing
> answers. Neither has a machine-readable route. "Two CNAs for two days" is not
> costed against what is actually there. See FEEDS.md section 4 for the table.
>
> The recommendation below therefore stands as a QUESTION, not an answer: buy
> margin, yes, but from the near-floor three rather than from the two named here,
> and re-cost before budgeting either.

- **Launch at one CNA of margin.** A quiet fortnight at two of them un-clears the
  gate. The failure is loud and reversible: `publish.gate` makes it a red check
  and the site demotes to the pre-launch posture rather than breaking.
- **Buy margin first.** Target TWCERT and TR-CERT, the two that probed 200 on
  their own advisory sites. Two CNAs for two days.
- **Widen the gate's basis.** Nothing has touched `GATE_TOP_N_PCT`, deliberately:
  it has been re-derived once already and moving it to solve a margin problem
  would be the least defensible derivation yet.

The recommendation from 08-24 stands: **buy the two CNAs.** One CNA of margin on a
figure that moves with someone else's publishing schedule is not much better than
none.

Whichever you pick, run `python -m rbp.feedlab score <name>` before merging any
new feed. No feed goes in without its scorecard in the diff.

### 2. FEEDS.md section 3's three remaining guards

Due the moment option 2 above is chosen, and correctly not started before then:
they are "before feed 10, not after feed 30".

- per-feed shrink baselines survive a profile change
- a failure budget expressed as a fraction, not a count
- `gather` parallelised, preserving per-feed health recording exactly

The second is the one not to defer past the first new feed. One measurement to
carry forward: the scorecard baseline fetched all 12 feeds in 784 seconds and
`ubuntu` alone was 486 of them. One feed is most of the wall clock and `gather` is
a serial loop.

> **UPDATED 2026-08-27.** The third is now both more urgent and more delicate.
> The rebuilt baseline fetched all THIRTEEN feeds in 1,576.8 seconds and `ubuntu`
> alone was **1,070.6** of them: 68% of the wall clock, 355 MB, for 3,994 rows
> over a 38-day reach. `debian` read 17,909 rows over the whole window in 1.5
> seconds. More delicate because the health recording `gather` must preserve now
> includes per-provider CSAF parts and per-feed date spans, both added in round 7.
> Parallelising the recording and then changing its shape is two migrations; the
> shape changed first, so this is next rather than alongside.
>
> Round 7 also added a guard that was not on this list: a feed frozen at a
> constant row count is invisible to `compare_magnitudes` by construction, and is
> now caught on the date of its newest advisory instead.

### 3. Rehearse the withhold lever end to end

**New, and it replaces the retired condition 4.** The lever now reads
`RBP_WITHHOLD`, and it has never fired in production. The last version of this
mechanism was falsified on 2026-08-23 because it was unreachable by the people it
existed for, and nothing reported that; this one was unreachable for four days for
a different reason and nothing reported that either.

    set the repository variable RBP_WITHHOLD to one live CVE ID, wait for the
    next scheduled run, and confirm the row leaves every surface: the page, the
    rows island, data/rbp.json, data/rbp.csv, the dated archive, and the staged
    data branch. Then unset it and confirm the row comes back.

Covered by tests, which is not the same claim. If it does not work, the failure is
worth more than the fix.

---

## Round 7: the data sources, 2026-08-27

`docs/reviews/REVIEW-round7-data-sources.md`. A review of where the rows actually
come from, and of what expansion is genuinely cheap. Every blocker, high and
medium item is closed; the suite went 852 to 898.

**The finding to carry.** This is a GitHub advisories tracker with distro
corroboration and no surface said so. Of 1,709 rows, `ghsa` and `ghsa-repos`
touch 1,436 and **1,021 exist only because of them**. `ghsa-repos` alone is the
sole source for 1,015, 59% of the headline, off a hand-curated 1,875-repo file
that does not self-refresh. Meanwhile `mozilla` (607 ids/run) and `arch` (62)
had put **zero** rows on the site since they merged, and `/status` showed all
thirteen feeds with one number each: ids fetched.

**What changed on the surfaces**

- `/status` publishes **IDs read, Rows, and Only source** per feed. `arch` now
  reads `62 / 0 / 0` on the live page, which is the whole finding in three cells.
- A feed that has stopped returning recent advisories degrades the run, checked
  on the date of its newest advisory. A frozen feed returns a perfect row count
  for ever, so no count-based guard could ever see it.
- Feeds that publish no dates at all (`alpine`, `arch`, `debian`) are named as
  `freshness_unmeasurable`, because "cannot be checked" must not read as "fine".
- CSAF records one health entry **per provider**, so a provider going dark is
  caught. Seventeen shared one number, which is how SUSE's 14,486 advisories were
  lost and published as a fact about SUSE.

**What changed underneath**

- `ghsa-repos` finally has a scorecard: `detecting`, 1,231 unpublished
  references and 5,771 disclosure lead, the highest of any feed. It had been 69%
  of the site for a day with no verdict at all.
- The baseline was rebuilt over all thirteen feeds and every feed re-audited.
- FEEDS.md section 2's corroborating rule is **enforced** rather than only
  written, after measuring that it costs zero effective CNAs today.
- Four small OSV ecosystems merged behind their own scorecard, for seven
  currently-unpublished ids at 0.3 MB. And `feed_osv` turned out to be unable to
  fetch any ecosystem whose name contains a space, which is five of the 46.
- GitLab's advisory DB is **rejected on measurement**: 80% GHSA re-publications
  and a 30-day publication lag written into its own CI config, so it cannot clear
  admissibility test 2 at any effort.

**Still open, deliberately**: whether the Ubuntu cap moves (it reads 38 days of a
three-year window and is 68% of the run's wall clock), `gather`'s serial loop, and
widening the repo list, which is a mining problem rather than a fix. Plus four
D-list decisions in the review that are yours.

---

## Round 8, 2026-08-28: the filter that stopped filtering

Reported by a front-end review before the announcement, then reproduced in a
browser here rather than read off the source. Three defects, all on the list page,
all reachable by pasting a URL or by typing.

**The reported one.** `/?src=mozilla&age=any` rendered every row instead of none:
1,672 of 1,672 measured on the live page by the review, 60 of 60 measured here in
the render fixture.
The source options are built from the slugs present in the current rows, and
assigning a `<select>` a value it has no `<option>` for neither throws nor sticks:
`value` reads back `""`, `selectedIndex` becomes -1, and `matches()` then skips the
filter entirely. `mozilla` and `arch` have contributed zero rows since they merged,
which is round 7's B4 finding, so this was the live behaviour for two of the
thirteen feeds and for any feed that goes quiet later.

It inverts the only promise the control makes. A view here is meant to be citable,
and a citation of a quiet feed became a link showing everything.

**Two more in the same twenty lines, both measured.** The empty state concatenated
the reader's own filter text into `innerHTML` raw, so `?q=<img src=x
onerror=...>` matched no rows, rendered the tag and ran the handler: script
execution under this origin, from a link, on a site whose entire product is a link
other people are asked to trust. And that box had no wrapping rule at all, so 400
unbroken characters typed into the filter scrolled the document sideways by
2,466px at 1280 wide, and 80 characters did it at 375. The second one needs no
crafted link, only a pasted package coordinate.

**What changed**

- An unknown `src` slug gets an option of its own and keeps filtering, which for a
  feed with no rows is a zero-result view. The option is marked `(0 rows)`, because
  the dropdown is otherwise a list of the feeds behind today's rows.
- `?age=45+` and `?age=45-` now work. The offered thresholds are the
  `age_buckets` boundaries; a bound of a reader's own was silently dropped the same
  way. A value that parses as no bound at all falls back to the explicit `any`
  rather than to a blank select, which filtered nothing while looking like it
  might.
- The URL readers are keyed on the control map and iterated from it, so the two
  cannot drift. A control with no reader throws at load, which the browser suite
  catches. Two lists is how `minage` outlived its rename.
- `esc()` at the `innerHTML` sink, and `describeFilters()` is documented as plain
  text. One lookup on `NAMES`, guarded with `hasOwnProperty`, so `?src=constructor`
  cannot label a control with the source of `Object`.
- `.empty { overflow-wrap: anywhere }`, at every width. The rule existed for
  `.mono, code, pre` and only below 768px.

**Guards.** `tests/test_filter_links.py` is offline and therefore gates the
publication: it asserts the structure, which is weaker than measuring and is the
half that can stop a publish. `tests/render/test_filters.py` measures the
behaviour in a browser, including the escaping and the sideways scroll at both
widths. Fourteen mutations run across the two files, every one caught. The browser
suite is 53, up from 43.

**Two things left standing, deliberately.** The marked option stays in the
dropdown after the filter is cleared: it names a feed a reader linked to, and
choosing it again gives the same honest zero. And the review reported that this
defect was written up in the README. It was not, in the README or anywhere else in
the tree, which is worth knowing about the next report from the same source.

---

## What to be careful of

**THE SITE IS LAUNCHED.** `RBP_LAUNCHED=1` was set as a repository variable on
2026-08-26 at 18:00Z. `/` serves the list, `/overview.html` is gone, there is no
`robots.txt`, and the pages are indexable. Verified against the live host, not
assumed.

Two days earlier this same section read "no repository variables are set, so the
site deploys in its pre-launch posture", and it was true when it was written. It
was still sitting here, unchanged and now false, when it was quoted back into a
pull-request description as a reason merging was low-risk. **A launch is a
settings change, deliberately, so that it is not a commit; the cost is that
nothing in the repository changes when it happens and no test can see it.** If you
flip a repository variable, this paragraph is part of the flip.

**Ubuntu's feed now retries a failed page before truncating.** Three consecutive
scheduled runs truncated on 503s and a connection reset, at offsets 0, 1280 and
3000, each marking the run degraded. `_get` already retried three times at 1.5s,
3s and 4.5s, so more of the same was not the answer: 200 back-to-back requests to
one host hits load shedding. The retry is at the pagination level now, two extra
attempts at 5s and 20s, bounded by a 120s budget for the whole feed. A feed that
only completed because it waited says so in its status detail, so a healthy
endpoint and one being carried by retries do not look identical on `/status`.

**Merging to `main` publishes to that live site.** `deploy.yml` fires on
`push: branches: [main]`, four scheduled runs a day plus every push. There is no
staging environment. `RBP_PAUSE=1` holds a publication; a `workflow_dispatch` with
`dry_run=true` builds the artefact and discards it, which is the way to see what a
change does to real data without shipping it.

**The coverage gate can still demote it.** `publish.gate` fails the build red if a
launched posture is requested below `GATE_TOP_N_PCT`, and `site._gate_status`
serves the pre-launch page rather than a launched one. So a fortnight of quiet at
two top-50 CNAs does not break the site; it takes the front door back to the
holding page and turns the check red. Loud and reversible, which is the design,
and worth knowing before it happens on a live site rather than after.

**The render job and the lint step first executed in CI on 2026-08-26** (run
33009236143), green: 753 offline, 32 browser, lint clean. Neither can affect a
publication, by construction: they are in `ci.yml`, and `deploy.yml` does not
reference them.

**PLAN.md predates the pivot in places.** Section 301 documents a `/data` page
route that no longer exists, and 837-838 describes conftest guards on templates
that were deleted. It is the design record, not a description of the current
tree; `README.md` is the second.

**The lesson that still costs the most time.** Every fix in these sessions was
mutation-tested by reintroducing the defect and confirming a test failed, and
first passes typically catch about half. Almost every survivor is **fixture
blindness rather than a product bug**, and this session was the clearest case yet:
the suite was green, and it was green partly because 14 of its tests were reading
files nobody rendered and 14 more were skipping while reporting coverage.

On this project, *the test passes* and *the test works* are different claims.

---

## Round 8, 2026-08-28: the 82 rows with no age

Reported as a single missing CVE and it was not one. Someone pointed at
[CVE-2026-44235](https://ubuntu.com/security/CVE-2026-44235) and asked whether
the site had an Ubuntu gap. `cveawg` returns `CVE_RECORD_DNE` for it, Ubuntu
published it 2026-06-11 and shipped USN-8437-1 on 2026-06-16, so it is an RBP by
the site's own definition. It was already in the data, in `held_back.json`, in
every snapshot since 2026-08-22, `state: RESERVED`, `sources: debian`,
`held_back_reason: undated`.

**The mechanism, which is not about Ubuntu being missing.** `alpine`, `arch` and
`debian` return no dates at all. A row only those feeds saw has no age at any
threshold, so `report.build` holds it back and it is never counted. Ubuntu can
date such a row and mostly cannot be walked to it: the walk reads newest-first,
the cap is 4,000 records, and offset 3,980 lands on 2026-07-25. This advisory is
six weeks past that edge.

**The size of it, measured against the live endpoint.** All 82 rows held back as
`undated` on 2026-08-27 were asked for by name. On a pass with no failed lookups:
**64 have an Ubuntu date, every one of the 64 clears the 7-day buffer, every one
is beyond the walk's reach.** The remaining 18 Ubuntu genuinely does not carry.
The headline goes 1,670 to 1,734. They are also the OLDEST evidence the site has,
151 days down to 36, which is the opposite of a marginal population:
`CVE-2026-35332/3/4` have been public since 2026-04-22.

**Not a reason to move the cap, and that was checked first.** `0389f41` had
already settled the walk: the full window is 1,128 pages and 35 to 44 minutes. It
is also the wrong lever. `cves.json?q=<id>` is an exact-match filter that answers
in one request, so the rows that need a date can be asked for BY NAME and depth
stops mattering. The pass is bounded by the size of the held-back population, not
by how far back the rows go. And it is the better trade on the walk's own terms:
the feed being bought is the sole source for zero published rows.

**What landed.** `feeds.resolve_dates_ubuntu`, run in `cli` between `classify`
and `clock.annotate`, gated on `ubuntu` being a configured source. Live over the
real population: 82 ids in ~300s at 4 workers. Three passes returned 59, 62 and
64 dated, and the difference is entirely transient lookup failures rather than
anything about the rows. That spread is the reason a failed lookup is retried on
the next run rather than recorded as a final answer.

**It dates rows, it does not sight them,** and that is the load-bearing decision.
Every id it is given is one another feed already found, because that is the only
way into the backlog, so the lookup can never add a row `ubuntu` alone would have
seen. Crediting `ubuntu` with a sighting would raise `feed_count` out of a sample
chosen by which rows were already undated, which is corroboration climbing
precisely where corroboration is weakest. For the same reason the date stays out
of `dates`, whose consumers all read it against `sources`. It lands in
`public_date` only, which starts the buffer and cannot start the 72-hour clock,
because `ubuntu` is a tracker in `clock._ORIGIN_KIND` and this endpoint's
`published` is a tracker date whether it arrives by walk or by name.
`public_date_origin` is published beside it so a reader can tell the two apart.

**FOUND WHILE WRITING IT.** `q=` is a SEARCH, not a key lookup, and it matches
description text. Taking `cves[0]` would have dated a row from another CVE's
record, and the row would have been published with a confident, invented age.
The resolver matches on `id` and skips everything else. Separately, `_get`
returns `(None, 404, {})` rather than raising, and an unknown id answers 200 with
an empty list, so a 404 here is the endpoint moving: reading it as "no date"
would have turned a retired path into a silently undated backlog.

**The health states are three, and the middle one is a judgement.** Two failed
lookups in eighty-two is this endpoint on an ordinary afternoon, and reporting
that as TRUNCATED would degrade most runs, which is the furniture problem
`degraded_state` rejects reached from a fourth direction. Staying green is safe
here for a reason not true of a feed walk: a row this pass fails to date stays in
`held_back.json` as `undated`, exactly where it already was, and the next run
asks again. The population self-heals, so the cost is a day of latency on a floor
rather than a silent shrink, and the count is still stated in `detail`. A spent
budget is CAPPED, because a configured limit belongs in `limitations`. Every
lookup failing is FAILED, because then there is no self-healing to appeal to and
`ok, dated 0` would be the silent shrink wearing that excuse as a disguise.

**Still open.** The 18 rows Ubuntu genuinely does not carry are still undated and
no configured feed can date them. And the deeper one this exposed: Ubuntu's
`cves.json` carries `notices` and `notices_ids` on every row, with the USN id and
its publication timestamp, and the adapter reads `id`, `published` and
`description` and drops them. `clock._ORIGIN_KIND` calls `ubuntu` a tracker on
the note that "none of the three reads DSA/DLA, USN or ASA", which is true of the
adapter and not of the endpoint. Reading `notices` would give real advisory dates
and move rows from SHOULD/4.5.1.6 toward MUST/4.5.1.4. That changes what the site
ASSERTS, not how many rows it shows, so it wants its own measurement and its own
round.

**Guards.** `tests/test_ubuntu_dates.py`, 13 offline tests. 930 pass, lint clean.

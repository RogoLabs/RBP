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

# RBP Tracker: combined panel review

Chair's verdict: the pipeline, the inference method and the epistemic instincts in this
codebase are better than the site built on top of them, and nothing here is
unrecoverable. But the project is not currently in a state where it should be shown to
anyone, because the public surfaces misquote the rules they enforce, name at least two
organisations for vulnerabilities that are almost certainly not theirs, and promise a
correction mechanism that does not exist.

Eight reviewers sat: Python, Web Design and Layout, GitHub Actions, CNA Operator, CVE
Program (MITRE), CISA / Government, CVE Consumer Working Group, RogoLabs Marketing.
Where more than one discipline reached the same defect independently, that is recorded,
because it is the strongest signal on this list.

---

## Part 1: launch blockers, in the order they should be done

Ordering weighs three things: is it already public, does it make a false statement about
a named third party, and how cheap is it. Items 1 to 4 are the ones that are wrong
*right now* on a page anyone can reach.

### 1. Fix the live holding page (Marketing, MITRE, CISA, CNA, Actions)

`placeholder.html` is the only page a search engine or an unfurler can reach today, it
carries the project's most aggressive copy, and it carries none of the hedges. Four
one-line changes, today, independent of everything else on this list.

- Quote CNA Rule 4.5.1.7 in full. The site quotes sentence one and drops sentence two
  ("Otherwise, the Secretariat SHOULD NOT publicly identify the CNA until the CVE Record
  has been published"), which is the sentence that *mandates* the redaction the site
  calls a choice. Verified against the project's own pinned fixture
  `tests/fixtures/cna_rules_4-5.json`. Also stop citing the rule as the site's own
  permission: both sentences bind the Secretariat by name and neither addresses third
  parties, so the site cannot "satisfy" 4.5.1.7 and should not claim to.
- Add `<meta name="robots" content="noindex, nofollow">` to `placeholder.html` (verified
  absent) and emit `robots.txt` with `Disallow: /` from `rbp/site.py` while unlaunched.
  The `noindex` in `templates/base.html:11` covers only the Jinja pages, and GitHub Pages
  cannot set `X-Robots-Tag`, so today the holding page and every file under `site/data/`
  are simply public.
- Rewrite the h1. "Every reserved CVE the List won't show you" asserts refusal where the
  finding is absence, and is refutable in one sentence: a reserved ID has no record to
  show. The dashboard's own lead block already says it correctly.
- Rewrite the removed-metric paragraph per item 9 before it is indexed anywhere.

Add `og:title`, `og:description` and a 1200x630 `og:image` at the same time, or suppress
the description entirely while unlaunched. `placeholder.html` currently has no Open Graph
tags at all.

### 2. Pull the two wrong named rows and the pages they generate (MITRE, CNA, CISA, Marketing, Python, Consumer)

Six disciplines converged on the same two rows in the deployed build.

- `CVE-2026-16566`, owner WPScan, description an Ansible `community.general`
  `jenkins_credential` flaw, sources `alas,debian,redhat,ubuntu`.
- `CVE-2026-9238`, owner Wordfence, description a QEMU 9pfs `v9fs_readdir` flaw, sources
  `alas,debian,ubuntu`.

Both are WordPress-ecosystem CNAs named on Linux distribution rows. Both have a deployed
`/cna/<slug>.html` page whose entire content is that one row, quoting the corpus-average
precision as though it described the row. Both carry `indep_sources: 3`, so the
"require two independent sources" proposal on the table would not have caught either.

Do three things now: pull both rows, remove `site/cna/wpscan.html` and
`site/cna/wordfence.html`, and land the one gate that catches them mechanically today.
That gate is the **product-map contradiction gate**: withhold the name when
`product_map_owner` is non-null, at confidence >= 0.85, and disagrees with the block
inference owner. Measured on the current snapshot it fires on 11 of 282 named rows
(GitHub_M/redhat 7, zdi/redhat 1, GitHub_M/Google 1, plus the two exemplars), costs 3.9%
of naming coverage, and includes exactly one MUST row. Both bad rows carry a firing
verdict already (`ansible -> redhat` at 0.85, `qemu -> redhat` at 0.9).

Also delete the false absolute from `templates/method.html:30-34`: "a typo in a downstream
advisory cannot inflate the count". `CVE_ID_NOT_FOUND` screens only IDs that were never
allocated; a mistyped ID landing on an allocated-but-reserved neighbour passes every check.

### 3. Stop making promises the code cannot keep, and build the accountability surface (CNA, MITRE, CISA, Python, Marketing, Design, Consumer)

Seven findings, one root cause. `templates/cna.html:26-32` promises that a wrong or
embargoed row "will be corrected or suppressed on the next build, with the correction
visible" and that "suppressions are counted publicly in aggregate". `grep -rni suppress`
over `rbp/` returns only `rate_suppressed` and two `argparse.SUPPRESS`. There is no
suppression list, no override file, no counter, no private contact route anywhere in
`templates/` or `placeholder.html`, and `owner` is recomputed by block inference on every
run (`rbp/cli.py:91`), so a hand correction cannot persist even in principle.

Worse, the only channel offered is a public GitHub issue, so a CNA holding an embargoed
row must disclose the embargo publicly in order to get it delisted. That is a harm the
site creates, not merely a promise it has not kept.

Today, before anything else ships:

- Cut the promise paragraph from `templates/cna.html`.
- Gate the per-CNA pages and `data/cna/<slug>.json` on `RBP_LAUNCHED` in
  `rbp/site.py:241-251`, not just the front door. `rbp/report.py:363-364` already states
  the project's own rule that named CNAs get a private preview before any row naming them
  circulates, and the six-hourly public deploy breaks it on every run.

Before any CNA is notified:

- `data/overrides.json` on `main` (not the machine-written `data` branch), with **three**
  record types, not two: `SUPPRESS` (row removed everywhere, reason code recorded),
  `CORRECT` (owner pinned, marked CNA-supplied), and `DENY` (name withheld, row retained
  and counted as unattributed, `owner_method: cna-denied`). `DENY` is the record a
  wrongly-named CNA actually needs and every design on the table omitted it: without it
  the only options are to defame a third party or to help the site hide a real RBP.
- Apply suppressions **once in `rbp/cli.py`** before `report.build`, and owner overrides
  after `apply_to_backlog` and before `clock.annotate`. Also apply before `ledger.track`
  and `grader.record`, or a suppressed row keeps moving the accountability numbers.
- Publish the three counts and a reason-code breakdown on `/method` and `/cves` from the
  first build that has any, not later.
- Add a private intake route (GitHub private vulnerability reporting or a security
  address) and name it on `/cna` as *the* embargo channel. Add a Root and Secretariat
  route as well: under the policy the Root, not the CNA, is the party who can act.
- Add an About page linked in the nav, stating the author's name, the cve.icu and
  cnascorecard.org relationship, the day-job affiliation, and that no commercial product
  consumes this data. Verified today: zero hits for a byline, affiliation, mailto or About
  route anywhere. The blast radius of a wrong name is cve.icu's neutrality, and an
  undisclosed portfolio overlap is a story rather than a footnote.
- Test that a suppressed ID is absent from `backlog.json`, `backlog.csv`, `rbp.json`,
  `rbp.csv`, every `data/cna/*.json`, `resolutions.json['open']` and
  `precision.json['predictions']`, and present only in the aggregate.

### 4. Stop the exports naming CNAs the site withholds, and stop pushing the ungated set (Python, Consumer, CISA)

`rbp/report.py:174-178` `_gated` returns `{**r, "owner": "unattributed", ...}` and
overwrites only four keys, so `product_map_owner`, `product_map_confidence` and
`product_map_method` survive into `backlog.json` and from there into `data/rbp.json` and
every `data/cna/<slug>.json`. Measured: 112 of 553 published rows carry an 85%-precision
CNA name on a row the site renders as unattributed (GitHub_M 63, redhat 41, drupal 3,
suse 2, plus four singletons), and `data/cna/github-m.json` carries rows where block
inference says GitHub_M and the product map says redhat in the same object with no
precedence field. `templates/method.html:160-165` says that map "can promote a named row
to corroborated but never create a name".

- Strip the three `product_map_*` keys inside `_gated`, on both branches. Publish only a
  boolean `owner_contested` if the signal is wanted publicly.
- Stop pushing `backlog_full.json` and `report.md` to the public `data` branch
  (`.github/workflows/deploy.yml:132-142`). `backlog_full.json` carries 724 rows including
  170 inside the buffer or undated, 85 of them named. `report.md` opens "Internal /
  pre-preview. Do not forward." on a world-readable branch, and still describes the owner
  column with a confidence gate that `/method` contradicts (`rbp/report.py:311`).
- Test that no published artefact contains any key matching `product_map*`, and that no
  row has a non-null owner absent from `cnas.json`.

### 5. One population, computed once, asserted once (Python, CNA, CISA, Consumer, Actions, Design, Marketing)

The single highest-consensus defect class on the board, found independently by six
reviewers, and the codebase already documents two prior instances of it in comments
(`rbp/clock.py:139-142`, `rbp/clock.py:154-157`, plus the commit "fix: the MUST/SHOULD
split was inert in production").

Verified ordering: `rbp/cli.py:119` calls `report.build(backlog, ...)`, which derives its
own `reportable` (`rbp/report.py:142`) and writes `backlog.csv` and `backlog.json`
(`rbp/report.py:186-191`); only afterwards, at `rbp/cli.py:130`, does `clock.split_epoch`
run, feeding `cnas.json` and `summary.json` alone; `rbp/site.py:74` reads `backlog.json`.
Simulated with an epoch of 2026-08-01 on the live snapshot: front page 78, `/cves` table
553 rows with its own counter reading "553 of 553", per-CNA cards reading "9 Outstanding"
above 236 rows, and CNAs dropping out of `cnas.json` entirely while `/cves` still links to
their now-nonexistent pages.

The fix is structural, not a patch:

- `rbp/cli.py` computes the published population once (buffer, then epoch, then
  suppressions) and **passes rows in**. `report.build` takes a `rows` argument and filters
  nothing. Add a structural test asserting `report.build` applies no filter of its own.
- Write the excluded rows with a reason rather than dropping them: `counted: false` plus
  `held_back_reason` in `("pre-epoch", "within-buffer", "undated")` in a separate
  `held_back.json` in the snapshot, and publish the held-back count *and the oldest
  held-back age* beside the headline. An epoch that removes the oldest and strongest
  evidence must read as deliberate conservatism, not be discovered as a discrepancy.
- Emit `epoch` and `epoch_excluded` into the published envelope.
- Cross-stage regression test: `len(json.load(backlog.json)) == summary["total"]`, every
  per-CNA page's row count equals its `outstanding`, and every owner link resolves.

Three things travel with this, because they are the same launch-day mechanism:

- **Validate `RBP_EPOCH`.** `rbp/clock.py:69` reads a raw string and `:80` compares it
  lexicographically. Verified: `'2026-12-31' < '2026-8-20'` is `True`, so a single missing
  zero in a hand-typed repository variable classifies every row as pre-epoch, reports 0,
  and exits 0. Validate with `dt.date.fromisoformat` at import, and make "a non-empty
  epoch that excludes 100% of reportable rows" a hard error. Do the same for
  `RBP_LAUNCHED` (`rbp/site.py:43` silently accepts only `1|true|yes`).
- **Decide the launch-day semantics deliberately.** Verified: the newest `public_date` in
  the reportable set is exactly `min_age_days` before the snapshot date, so an epoch set to
  launch day yields **zero** counted rows for the first seven days, `index.html:23`
  collapses the whole dashboard to a one-line empty state, and `og:description` reads
  "0 CVE IDs are reserved, publicly referenced, and unpublished". Counts at candidate
  epochs on live data: launch day 0, 2026-08-13 gives 38, 2026-08-01 gives 78, 2026-07-01
  gives 338, 2026-01-01 gives 543. Either set the epoch well back and disclose the cutoff
  on the lead screen, or keep a launch-day epoch and make the lead metric "new since
  launch" with the pre-epoch backlog published as a named, separately counted archive so
  the 519-day row still has a home. Never inherit the zero. Give
  `{% if summary.total %}` a real empty state either way.
- **The epoch is keyed on a mutable field.** `public_date` is a min-across-feeds scalar
  that gets revised *backwards* between runs (two rows measured moving 2026-08-05 to
  2026-08-04 at the same URL under the same date label, with no revision marker and no
  `public_date_source`). Verified against HEAD: that revision flips a row from counted to
  held-back across an epoch boundary with no publication event, which after the fix above
  renders as "Published, and therefore resolved". Record the epoch decision per ID once in
  the ledger, or key it on first-seen, and surface a `revised_public_date` flag.

### 6. Make the site fail loudly instead of publishing a hollow page (Python, Actions)

`rbp/site.py:60-64` `_read` swallows every artefact parse error and returns a default.
Reproduced by execution: with a truncated `backlog.json` beside a good `summary.json`,
`site.build` prints "site: 7 pages + 9 CNA pages", exits 0, and publishes a front page
reading 553 above an empty table, `data/rbp.json` containing `[]`, `data/rbp.csv`
containing only a header, and nine per-CNA pages each asserting outstanding rows above a
table of none. Because the step exits 0 the artifact uploads, the deploy runs, and the
truncated snapshot is committed as the next run's `/changes` baseline. Every writer in the
pipeline is a bare non-atomic `json.dump`, so one interrupted write produces exactly this.

- Read `backlog.json`, `summary.json` and `cnas.json` strictly (raise `SystemExit` naming
  the file). Keep the swallow only for the two ledgers, where genuine absence is a valid
  first-run state.
- Assert the cross-stage invariant in one place and **raise**: `len(rows) ==
  summary["total"]`, `sum(c["outstanding"]) == named row count`, every owner either
  `unattributed` or present in `cnas.json`. This one assertion also catches item 5 and the
  two-copies divergence, so it is one guard covering three blockers.
- Write every ledger and snapshot artefact atomically (`path.tmp`, `fsync`, `os.replace`)
  in `rbp/inference.py:261`, `rbp/clock.py:281`, `rbp/classify.py:144`,
  `rbp/report.py:190-191`, `rbp/site.py:188-197`. On a parse failure of a **non-empty**
  ledger, rename to `.corrupt` and raise instead of starting empty. Note that
  `tests/test_clock.py:245-249` currently pins the silent-reset behaviour as desirable, so
  deleting that test is part of the change.
- Add the workflow guard: capture `len(graded)` and `len(resolved)` at seed time and fail
  the run if either decreased before `git add`. `deploy.yml:87-101` currently prints "no
  grader ledger yet, starting fresh" and continues on exit 0, and `deploy.yml:134-136`
  masks its copies with `2>/dev/null || true`, so the accountability record can be zeroed
  by a green run in two independent ways.

### 7. "Resolved, the record published" must be verified, and it must not be one bucket (all eight disciplines)

The highest-consensus correctness defect on the board. `rbp/site.py:131-137` computes
`resolved = before - now` over CVE ID sets from two `backlog.json` files with no corpus
check, and `templates/index.html:146` and `templates/changes.html:21` label it
"Published, and therefore resolved" / "Resolved, the record published", with the raw ID
list printed at `changes.html:41`. `clock.ResolutionLedger.reconcile` already computes the
honest answer and its return value is discarded after a print at `rbp/cli.py:97`.

A row leaves the set for at least six reasons other than publication: a transient oracle
error, a failed or truncated feed, a **feed profile change** (`deploy.yml:109` defaults to
`weekly`, which `rbp/cli.py:22-25` excludes `csaf` and `msrc` from, so one `deep` dispatch
followed by the next cron reports every CSAF-only and MSRC-only row as published), a
raised `--min-age-days`, a `public_date` revision, and an ID that was **REJECTED**.

- Three rendered buckets with three labels, never merged: `published` (verified PUBLISHED
  in the corpus, from the ledger), `rejected` (state REJECTED, per rule 4.5.3.5), and
  `no longer listed` (unverified: feed, profile or API change). The word "published" never
  appears on the last two.
- Write the reconciled closures into the committed snapshot as `resolved.json` so any
  interval is recomputable from artefacts, not from whatever the mutable ledger happens to
  hold at render time. Export it; today `data/resolutions.json` is computed, persisted, and
  then withheld from consumers while the unverified number is rendered as fact.
- **Prerequisite:** fix the ledger's population first. `rbp/cli.py:98` calls
  `ledger.track(backlog)` on the full backlog before the buffer filter and the epoch split.
  Measured: the ledger holds 724 open IDs against 553 published rows; 171 tracked IDs were
  never listed, 84 of them rows `rbp/clock.py:29-30` calls "never reportable at any
  buffer". Sourcing `/changes` from `reconcile` today would close 171 rows nobody ever
  counted. Move `track` after the buffer and epoch, and assert
  `len(ledger.state["open"]) == summary["total"]` immediately after.
- Stop summing REJECTED into `fresh_resolved` (`rbp/classify.py:169`) and remove
  "self-healed" from `rbp/report.py:287`. Under 4.5.3.5 rejection is lawful and is the
  likely outcome for the oldest rows, and it is *worse* for defenders than an open RBP.
- Record the feed profile, the buffer, the feed health and the unresolved-lookup count in
  every snapshot, and refuse to diff two snapshots that disagree on any of them. Show
  "not comparable" instead.
- Ownership transfer is the policy's own remedy (4.5.1.4, 4.5.1.5) and will contaminate
  both surfaces. `reconcile` sets `owner` to the *post-transfer* assigner
  (`rbp/clock.py:262`) and `rbp/site.py:249` credits the resolution to that CNA's page and
  median-time-to-publish card. Keep `predicted_owner` and `published_assigner` as separate
  fields, key `cna_resolved` on the tracked owner, render a differing pair as "published
  by X, transferred", and give the Grader a third outcome bucket so a transfer is never
  reported as an inference miss. Land this before the first resolution closes.

### 8. The MUST claim: one CNA, one feed, one aggregator, no token (all eight disciplines)

Five findings on concentration, three on the feed, one on the aggregator. Measured on the
snapshot: `must_rows` is 210 to 241 and **every one is GitHub_M**; all 241 carry `ghsa` in
sources and zero survive without it; 194 to 197 of them are `ghsa` plus its own OSV mirror,
so `indep_sources` is 1. `rbp/clock.OWNER_FEEDS` has four entries and three of their feeds
are not fetched on the scheduled `weekly` profile, so `self_disclosed` is structurally
incapable of returning True for anyone but GitHub_M.

Three separate problems, one work item:

- **The evidence does not mean what the code assumes.** `api.github.com/advisories`
  carries no assigner field at all, so `ghsa in sources` cannot distinguish "GitHub_M
  assigned and disclosed this" from "another CNA's advisory is in GitHub's database". The
  site's own export proves it in both directions: four `apple/swift-nio` repository
  advisories arrive through `ghsa` and are scored SHOULD, which is Apple's own channel
  read as a third party's, and simultaneously proves `ghsa` cannot corroborate GitHub_M.
  This is exactly the reasoning `rbp/clock.py:114-119` applies one level down to exclude
  OSV. Retain `source_code_location` and `repository_advisory_url` in `feed_ghsa`
  (`rbp/feeds.py:296-304` discards them) and emit the source as `ghsa:<org>`.
- **The feed is unauthenticated and silently windowed.** `grep -rn 'secrets\.'
  .github/workflows/` returns nothing (verified), so up to 45 anonymous
  `api.github.com` calls per run run against a 60/hour shared-IP budget, and
  `cvelist._releases` (`rbp/cvelist.py:29-42`) builds its own request with no token lookup,
  no retry and no hardened opener, propagating a 403 straight through `ensure_corpus` to
  kill the whole run before any feed is read. Meanwhile `ghsa`'s oldest returned row is
  2026-05-29 against a two-year scan window, which is exactly `page_cap=40 x per_page=100`
  at GHSA's publish rate: an 83-day rolling window, with no cap detection at all
  (`for _ in range(page_cap)` just ends). Rows age out of `ghsa` while staying in the
  backlog and silently downgrade from candidate MUST to SHOULD at roughly five a day, for
  reasons that have nothing to do with any CNA. Add `env: GITHUB_TOKEN: ${{
  secrets.GITHUB_TOKEN }}` to the pipeline step, plumb it into `cvelist` and
  `_gh_headers`, make a missing token *raise* so `gather` records a failure, record
  `ghsa`'s oldest returned advisory date in `summary.json` and treat "oldest date moved
  forward" as truncation, then raise `page_cap` to cover the window.
- **Stop presenting it as an ecosystem measurement.** Take `must_rows` off the front-page
  metric grid (`templates/index.html:31-37`) until more than one CNA is eligible, and
  remove the duplicate `210` tile at `index.html:95`. Replace the "6 CNAs with at least one
  row named" card with the top-owner share, which is the only breadth signal on the lead
  screen and currently implies the opposite of the truth. Split `OWNER_FEEDS` on
  `/method` into "configured" and "fetched this run". Add an "own feed ingested" yes/no
  column to `/cnas` and to `cnas.json`, and render the per-CNA MUST card as "not measured,
  own feed not ingested" rather than `0` (today `/cna/microsoft.html` shows a measured-
  looking zero for a test that could not fire). Key `_ORIGIN` and self-disclosure on the
  CSAF publisher, which is already retained in `refs` as `csaf:<publisher>:<id>` and is not
  discarded as three findings claimed, excluding aggregator republications.

Also fix the MUST clock itself: `rbp/feeds.py:751-752` collapses every source to the
minimum date and discards per-source dates, and `self_disclosed` is pure set membership
with no ordering test, so on 18 of 210 MUST rows the site measures a 4.5.1.4 clock from a
third party's advisory when the ordering is checkable from data the pipeline already
fetched and threw away. Retain `dates: {source: date}`, claim MUST only where the owner's
own feed date is earliest, and add the regression test.

### 9. The citation pass: quote what you cite, whole (MITRE, CISA, CNA, Marketing, Consumer)

Four separate instances of the same pattern were found: the site quotes the duties in a
document and omits the allowances in the same paragraph. A reader who checks three
citations and finds all three cropped in the site's favour stops evaluating the data. All
of these are copy changes in `templates/policy.html`, `templates/index.html`,
`templates/method.html`, `templates/cves.html` and `placeholder.html`.

- **4.5.1.7 in full**, and not as the site's own permission. See item 1.
- **Enforcement.** Delete "There is no condition that triggers anything by itself": it is
  false on the document's face. Quote the mandatory step ("The TL-Root or Root **will**
  notify the CNA of affected CVE ID(s) and the required remediation timeline"), the MUST
  ("CNAs MUST prioritize requests from their TL-Root or Root to publish CVE Records for
  RBPs identified as critical") and the ladder ("up to and including CNA
  decertification"), then make the claim that survives contact: the process exists and is
  entirely unobservable from outside, so nobody can tell whether it ran.
- **Timely Publication in full.** Three mitigating clauses appear nowhere on the site and
  are the first thing a CNA will quote back: publication "may, at times, coincide with
  ongoing vulnerability or incident response activities"; "internal processes may
  necessitate short delays"; and the remediation timeline "may account for factors such as
  volume, complexity, and resource constraints". Answer them in the same breath with the
  buffer, the median (42 to 45 days) and the age distribution, which is the strongest
  response available and is already computed.
- **The removed metric.** Drop "the public face of that channel has been switched off for
  four and a half years" and the concealment framing. The documented sequence, in the repo
  the site already links, is: cve-website issue #835 (2022-01-25) removes the v1.0 PDF "Per
  the Program Lead ... It will be replaced with a new version of the document at a later
  date"; issue #842 comments out the RBP table thirteen days later as item 2 of a
  three-item quarterly-to-annual restructuring; the block survives commented in
  `Metrics.vue` with its nav anchors intact and its final quarter already `N/A`; and the
  RBP glossary entry is still live on cve.org today. Also correct "about a year in public":
  cve.org did not launch publicly until 2021-09-29, so the table's public life was about
  four months. Cite the issues by number, pin them in `tests/test_policy.py`, and make the
  conclusion an ask: restore the series now that v2.0.0 is in force.
- **"Program metrics and audits".** Delete the implied broken commitment. That bullet is
  an internal identification channel for TL-Roots, Roots and the Secretariat, not a
  publication promise, and construing it as one is the weakest inference on the site.
- **"This site publishes what that table would show".** Delete it. The archived series is a
  quarterly *flow* of newly identified RBPs (4,326 in Q1 2017 down to 350 in Q3 2021)
  measured with authoritative internal access; the headline is a live *stock* discovered
  from feeds reaching a minority of CNAs with roughly half the owners inferred. Reproduce
  the archived table with its source link and state the non-comparability, then ask for the
  Program's series back rather than claiming to have replaced it.
- **"Masked on exactly the population the policy governs".** Retire it. The redaction
  covers roughly 55,000 reserved 2026 IDs by the Program's own published figure, over 99%
  of which are not RBP and none of which the endpoint can distinguish. Replace with the
  mechanism plus the grantable ask: unblind `owning_cna` only for reserved IDs already
  publicly referenced for more than 24 hours. Say out loud that the site's own block
  inference is the reason a blanket unblinding would be unsafe, because exposed block
  boundaries make pre-disclosure ownership derivable. That reframes the project from
  accuser to the party that found both the gap and the safe way to close it.
- **"Every row listed is already past the 72-hour publication expectation"** (front page
  and `/cves`) contradicts `/method`, `rbp/clock.py:24-28` and `rbp/report.py:360-361` on
  the same site. Restate as the observation: publicly referenced for at least N days, more
  than twice the 72-hour window, measured from the earliest advisory this site can see.
  Then anchor the normative weight on the policy's own sentence, which appears nowhere on
  the site and measures from public disclosure exactly as `days_public` does: "The CVE
  Program does not condone any unnecessary, intentional, or routine delay between Public
  Disclosure of vulnerability information (e.g., advisory or Fix) and CVE Record
  publication."
- **RBP is a state, not a violation.** The policy defines an RBP as a pure state and
  separately conditions its notification steps on "an RBP ... in violation of Program
  Rules 4.5.1.4 or 4.5.1.6 exceeding the 72 hours", assigning that determination to Roots,
  TL-Roots and the Secretariat. The site's headline count is definitionally identical to
  the Program's own published glossary term, which makes it undisputable; converting it to
  a violation count makes all 553 rows contestable on three grounds the site cannot rebut.
  Make the headline a state count, quote the definition and link the live glossary entry,
  and confine violation language to a separate, smaller, explicitly candidate figure.
- **The buffer does not absorb coordinated disclosure.** Replace the justification in
  `index.html:24-29` and `method.html:44-50`. The RBP signature and the multi-party embargo
  signature are identical from outside, the live median is 42 to 45 days, and no buffer
  length distinguishes them. Say so, add a paragraph to the `/cna` caveat block stating
  that a listed row may be under a legitimate hold and that the site cannot tell, and name
  the private route. Consider a distinct row state, "held pending coordinated disclosure,
  asserted by the CNA", counted separately: the panel's single best idea, because it is the
  only proposal that turns the site into a mechanism a CNA can participate in.
- **Delete "roughly half of them get fixed"** from `templates/changes.html:32-33`. It is
  literal prose, it renders on the second run, `data/resolutions.json` holds
  `resolved: 0`, and the front page has already been de-numbered so the two pages now
  contradict each other. Either drop the figure or compute it from the ledger with its n,
  suppressed below a stated floor.
- **Advisory titles are not titles.** `templates/data.html:55-59` claims "Advisory titles
  are reproduced verbatim" and "No vulnerability detail beyond those titles appears
  anywhere on this site". The rendered field is `e["description"][:180]`
  (`rbp/classify.py:188`), often a body rather than a title, 60 rows are hard-truncated
  mid-token, and the content includes exploit-mechanism prose for IDs with no published
  record. Restrict the column to a genuine title or the package name, or restate the claim
  exactly, and rename the column header, which currently repeats the false statement over
  the data. This is a prerequisite for item 10.

### 10. Submit the list through the channel the policy names, then say you did (MITRE, CISA, Marketing)

RBP Policy v2.0.0's RBP Tracking section names "Monitoring public sources for disclosed
CVE IDs" and "Reports from vendors, researchers, CNAs, or the public" as sanctioned
identification routes. The site is precisely those two things at scale and says so
nowhere; there is no Secretariat or Root contact anywhere in `templates/` and no statement
that the list has ever been submitted.

The first question at a Board meeting is "did you send us the list?". If the answer is no,
the framing collapses from "the Program is not publishing this" to "an outside party
published accusations without using the reporting channel the policy provides". Submit the
current list to the Secretariat and to the Roots covering the named CNAs, in writing, with
a stated response window, before launch. Then quote the two bullets on `/method` and
`/policy`, state when it was submitted and what happened, and keep that paragraph updated.
This is the cheapest and highest-leverage change on the board.

Write the adversarial-use statement in the same pass, after item 9's description fix.
`grep -rni "attacker|exploit|adversar|misuse|harm"` over `templates/` and
`placeholder.html` returns zero. Five points, headed with the question: every row is
already public and linked; nothing is derived from non-public information; the inference
uses only the public CVE List and is reproducible without this site; the population is an
absence of records, not a presence of exploit detail; the intended use is that a defender
whose tooling is CVE-driven can see what it is missing. Then state the residual risk you
do accept and its bound.

### 11. Precision: measure the problem you actually solve, and gate on the cell (CISA, CNA, Python, Design, Consumer, Marketing)

Seven findings, and the panel resolved a genuine disagreement here by measurement, so this
supersedes the individual proposals.

Three defects compound. `validate_loo` masks exactly one published ID
(`rbp/inference.py:143-144`) while production faces a run of unpublished IDs, so the
99.38% headline measures a strictly easier problem: run-masked, precision falls to roughly
94.7% at m=29 and 84.5% at m=78, and the live bracketing gap has median 4 to 5, mean 12.8,
p90 44, max 86. The aggregate hides strata below the project's own 97% kill floor: WPScan
81.1% (n=95), Wordfence 87.3% (n=228), redhat 94.1%, VulDB 96.1%. And 282 named rows rest
on only **167 distinct block judgments**, with one judgment carrying 29 consecutive rows,
while `Grader.summary` divides by row count.

The decisive measurement: the two proposed gates are anti-correlated. A flat `gap <= 10`
gate drops 30 to 31 mitre rows measured at 97.7 to 99.8% and keeps 23 GitHub_M rows in the
11-30 band measured at roughly 90.7%; a flat per-CNA floor does the reverse. Neither alone
cleans the site and one of them deletes its most accurate attributions. Precision is a
joint function of predicted CNA and gap width and does not separate.

- Change `validate_loo` to mask a contiguous run drawn from the observed live gap
  distribution, and publish that figure as the method's precision, with its method string
  changed so no consumer keeps citing the old number under the old name.
- Compute a (predicted CNA, gap-width band) precision table every build, store it in
  `summary.inference`, and abstain on any cell below the 97% floor. Disclose the withheld
  count by reason.
- Store the block signature `(year, left tuple, right tuple)` with each prediction, report
  distinct-block n beside row n everywhere precision appears, and grade one verdict per
  block. Any minimum-n floor must be a floor on distinct blocks, or a single judgment
  clears it: the first mitre block to resolve would take the grader from n=1 to n=30 on one
  judgment.
- Apply the project's own `MIN_DENOMINATOR` discipline to its own claim. `rbp/site.py:86-88`
  has no minimum n and `pct` renders two decimals, so the first graded case publishes
  "100.00%" or "0.00%" in a headline tile and on every `/cna` page. Below the floor, remove
  the tile (a metric card containing an em dash reads as a broken widget) and render one
  sentence at body size. Put the floor in `Grader.summary()` so both consumers inherit it,
  and delete `site.load`'s independent recomputation, which can legitimately disagree with
  `summary.json`.
- On `/cna`, render that CNA's own cell figures with their n and interval, never the corpus
  average. Publish per-row gap width and per-CNA precision in `cnas.json` and every
  `data/cna/<slug>.json` so a consumer can apply its own threshold.
- Require more than one inferred row before a standalone `/cna` page exists at all. A page
  whose entire content is one inferred row cannot survive one wrong inference, and we now
  know two such pages existed and both rows were wrong.
- Add the corpus-derived ecosystem gate as the second plausibility check: withhold when the
  sources' ecosystems are disjoint from the ecosystems the inferred CNA has published in,
  computed from corpus assigner-by-ecosystem counts. Note that the existing `ecosystem`
  field cannot be used for this: it is an OSV package-ecosystem label and is empty on
  exactly the distro rows that need it.

### 12. Feed health must have three states, and a bad run must be visible (Python, Actions, MITRE, Consumer, CISA)

Five reviewers, one defect. `feeds.gather` records `record_feed(s, True, f"{len(rows)} ids")`
for any adapter that returns without raising (`rbp/feeds.py:742`), and nine internal paths
break, cap or skip and return partial results (`feeds.py:241, 263, 295, 327, 354, 435, 447,
574, 599`). `templates/method.html:196-201` then renders "All N feed fetches succeeded. A
feed that fails is reported here rather than simply yielding fewer rows", which is false on
every run today because the Ubuntu 200-page cap fires every run. The `gather` docstring
asserts the invariant the code breaks, verbatim. `feed_osv` already does it correctly
(`feeds.py:377, 383, 415`), so this is a consistency fix, not new machinery.

- Change `record_feed(name, status, detail)` to three states (ok, truncated, failed) and
  call it from every cap and break path. Truncation must fire on loop exhaustion, not only
  on an exception, because `feed_ghsa` has no cap-detection path at all.
- Fix the unit before adding numbers. Verified: `summary.feeds.attempts` is 20 for 10 feeds
  (19 for 9) because OSV records per ecosystem *and* `gather` records again for `osv`, so
  "All 20 feed fetches succeeded" describes a unit that does not exist, and any consumer
  health check of the form `failures == [] and attempts == len(requested)` is broken on
  arrival. Emit a structured per-feed block `{name: {ok, rows, truncated, detail}}`; three
  other proposed fixes depend on that input, which does not exist today. Reset the
  `FEED_HEALTH` module global at the top of `gather`.
- Add the circuit breaker PLAN phase 1 promised. `rbp/classify.py:161-168` tallies ERROR,
  prints a warning, and returns only `(backlog, fresh_resolved)`, so an oracle brownout
  silently shrinks the headline and those rows are then reported as resolved. Return the
  tally, put `unresolved` in `summary.json` and the envelope, and abort **before**
  `report.build` writes the snapshot when unresolved exceeds ~2% of `len(unknown)` (not of
  `refs`) or ~25 absolute. A breaker that trips after the snapshot is on disk is worse than
  none, because the date-keyed directory means it poisons the day's baseline.
- Add the R4 rolling-median guard as a named `run:` step that reads `summary.json` and
  exits non-zero, keyed on the feed profile, and apply it to `must_rows` as well as to
  per-feed counts.
- Move the degraded banner into `templates/base.html` so it renders on every page. A health
  disclosure that lives only on `/method` is invisible to a reader who arrived on `/` from
  a shared link, and to a CNA who arrived on `/cna/<slug>` from an email.
- Add jitter to the retry backoff (`classify.py:81-88` sleeps `2 ** i` across 24 workers;
  `feeds.py:170` has the same lockstep inside three nested pools), read `retry-after`, and
  count a rate-limit refusal separately from a network error.

### 13. Nothing may claim a cadence it cannot verify (Actions, CISA, Consumer, MITRE, CNA)

`templates/base.html:7` and `templates/data.html:8` assert "Updated every six hours" as
static copy. `grep` finds no staleness, `generated_at` or `age_hours` logic anywhere, and
`.github/workflows/deploy.yml` has no `if: failure()` step, no notification and no
`timeout-minutes`. Two silent-stop paths exist (GitHub disables scheduled workflows after
60 days of repository inactivity; cron is best-effort), and neither produces a failure to
condition on. Note that `.stale-banner` already exists in `static/css/rbp.css:169-176` and
is referenced by nothing, so this is a wiring job.

- Emit an ISO-8601 UTC `generated_at` into `summary.json` and the envelope. Its only time
  field today is a day-granularity `date` for a pipeline that runs four times a day, so
  even an external monitor cannot detect a stall shorter than 24 hours.
- Compute freshness at render time, banner past 12h, hard-warn past 24h, and make the
  six-hourly sentence conditional on it.
- Add a notification step with `if: always()` and an explicit conclusion check, because
  `concurrency: group: pages` with `cancel-in-progress: false` reports a skipped tick as
  `cancelled`, which `failure()` does not catch. Add the external check against the
  published timestamp, since a workflow that stops running emits no signal at all.
- Set `timeout-minutes: 45` on build and `10` on deploy (measured wall times are 6.9 to
  14.9 minutes against a 360-minute default). Do **not** set `cancel-in-progress: true`;
  it creates a corruption window on the in-place parquet write and can cancel an in-flight
  `deploy-pages`.
- Give `_stream_zip` a wall-clock deadline checked per chunk, and replace
  `urllib.request.urlretrieve` in `rbp/cvelist.py:108` (which accepts no timeout at all,
  on the 583 MB cold path) with a streamed download through the hardened opener.
- Move `upload-pages-artifact` ahead of the persist step, and give persist a
  `git fetch origin data && git rebase && git push` retry. Keep persist gated on success;
  `if: always()` would commit a half-written ledger over the good one. Better still, split
  into build, deploy, persist jobs so state only advances after publication succeeds.

### 14. Publish the coverage bound, and enforce the gate in code (CNA, MITRE, CISA, Consumer, Marketing)

Four reviewers found the same omission: `rbp/cli.py:116` computes coverage on every run,
prints it to a build log, and it reaches `summary.json` nowhere and no template. The
launch gate itself is enforced by nothing: `RBP_LAUNCHED` is a bare truthiness test at
`rbp/site.py:43` with no coverage precondition anywhere in the code or the workflow, and
the variable does not exist yet, so the gate is currently one uncontested settings edit.

- Write `cov` into `summary.json` and the `rbp.json` envelope, and render "feeds currently
  reach N of M CNAs" as one data-driven sentence directly beneath the lead count, not only
  on `/method`. Publish `observed_pct` as the honest floor. Track it over time so a count
  delta can be normalised against a coverage delta; today every count change is
  uninterpretable.
- Make `rbp/site.py` refuse `LAUNCHED` below the gate unless an explicit override variable
  is set, and add a workflow step that reads `summary.json` and exits non-zero if
  `RBP_LAUNCHED` is truthy while coverage is under gate, so the gate produces a red check
  rather than depending on memory.
- Fix the denominator. `coverage.compute` derives its universe from corpus assigners
  (verified: 434 for the 2024-2026 window, against 479 assigners with any published
  record), not from the Program's partner roster, so the gate's denominator moves every run
  and the gate can be crossed by the denominator drifting. Worse, a CNA that publishes
  nothing is excluded from the denominator, structurally unnameable by k=3 inference,
  suppressed from the rate column and invisible to coverage: the pathological RBP case is
  invisible by construction. Pin the roster in a fixture, report roster size / CNAs with
  any published record / CNAs the feeds touch as three separate numbers, and publish the
  zero-publication cohort as a named blind spot. Validate every named owner against the
  roster before rendering.

### 15. Delete the `/cnas` rate column and the Wilson bound (CISA, MITRE, Python, CNA, Consumer, Design)

Two findings that resolve to one deletion, and the panel moved from "disclose" to "delete"
during review.

`rate = outstanding_rbp_rows / published_last_12mo` (`rbp/clock.py:341-346`) is
arithmetically the exact quantity RBP Policy v1.0 attached its 5% and 50% sanction
triggers to. v2.0.0 withdrew every numeric threshold, the v1.0 PDF is still mirrored by
third parties and still ranks in search (which is how this project first picked up the
thresholds), and the site never states anywhere that v1.0 was withdrawn. So the site
publishes the withdrawn metric's arithmetic against named CNAs while pointing readers at
the document that gives it teeth. The numerator and denominator are also different
populations: outstanding RBPs are by definition unpublished, so this is not a proportion,
the Wilson interval rendered beneath it at `cnas.html:57` as ">= X%" is meaningless, and
`clock.wilson_lower` raises `ValueError: math domain error` whenever `k > n` (verified:
`wilson_lower(20,20)` returns 0.839, `wilson_lower(21,20)` raises), which is precisely the
profile of the worst offender the site exists to find.

- Delete `rate`, `rate_wilson_lower` and `rate_suppressed` from `cnas.json`, every
  `data/cna/<slug>.json` and the `/cnas` column. Keep `published_12mo` as raw scale
  context beside `outstanding`. PLAN 2a already forbids leading with a per-CNA leaderboard,
  and a rate column is a leaderboard whatever the caption says.
- Clamp `wilson_lower` (`p = min(k / max(n, 1), 1.0)`) as a crash guard with a `k > n`
  test, since the function is public, then reuse it where the inputs genuinely are a
  proportion: the grader's `correct / graded` and `_score`.
- Add one sentence to `/policy`: RBP Policy v1.0 was removed from cve.org in January 2022
  at the Program Lead's direction pending a new version, copies still circulating are not
  in force, and its 5% and 50% thresholds should not be cited.

### 16. Make the site readable, operable and archivable (Design, CISA, Consumer, Marketing)

WCAG 2.1 AA is the practical gate on federal reuse, and the site fails it in four separate
ways. Two disciplines argued this is launch-blocking for citation, not polish, and the
chair agrees: a page that cannot be excerpted into an agency product is a page that does
not get cited.

- **Contrast.** `.text-muted` (#6c757d, 14 to 16px) measures 4.45:1 on the body and 3.95:1
  at the far end of the `.page-header` gradient; `td.unattributed` (#adb5bd) measures 1.97
  to 2.07:1 and is the label on 43% of rows; the six chip foregrounds measure 3.3 to 3.8:1
  at 11.52px; and `.metric-value` (#2196f3 on the #e3f2fd to #bbdefb card gradient)
  measures 2.74:1 and 2.22:1, failing even the 3:1 large-text allowance, so **every number
  on the site except the lead count** is under AA in light theme. Dark theme is mostly fine
  except `.chip-block` at 4.16:1. Introduce an AA-compliant caption token, darken
  `td.unattributed` and drop its italic (abstention is the site's most creditable act and
  is currently rendered as a whisper), give `.metric-value` an ink colour, raise the chip
  to about 12.5px, delete the dead `.chip-none`, and pin the required ratios in a check.
  Three separate contrast defects have now been found in the same inherited layer.
- **Table geometry.** `table.rbp` is 1322px inside an 1152px wrapper at a 1492px desktop,
  so 170px of the advisory column is clipped at every width, and at 375px the unscoped
  `th, td { white-space: nowrap }` at `style.css:1620-1623` makes it 2262px inside a 351px
  viewport. Replace `td.desc { min-width: 22rem }` with `max-width: 44ch` plus a line
  clamp, restore `white-space: normal`, widen the container on the table routes only, cut
  the column budget (fold Feeds and Sources into one origins cell), and bound `.tablewrap`
  with `max-height: min(75vh, 900px)`, which also makes the sticky header work (it is
  currently inert because `overflow-x: auto` makes the unbounded wrapper the scroll
  container) and lifts the `/cves` caveat block from y=25,622 to on-screen.
- **Keyboard and no-JS.** Sortable headers are click-only with no `tabindex`, `role` or
  keydown handler while correctly emitting `aria-sort`, which announces an affordance a
  screen reader cannot operate; the scroll container is not focusable; `#count` has no
  `aria-live`; there is no `<caption>`; and the entire tbody is JS-rendered from an inline
  JSON blob with **zero** `<noscript>`, so a crawler, an archive capture or a strict
  corporate browser sees an empty table under a headline count. Server-render the tbody in
  Jinja (the rows are already in the context) and let JS take over. That one change fixes
  the accessibility and the archivability together.
- **Document identity.** `/overview.html` has **no h1 at all** (the lead is a `<span>`, the
  outline starts at h2) and subpages ship bare one-word titles like `<title>Data</title>`.
  Wrap the lead as an h1 and append the site name to the title block.
- **Caveat placement.** There is no `{% include %}` anywhere in `templates/`, so each page
  carries a hand-written subset of the hedges and the page a named CNA is deep-linked to
  carries the fewest plus the one unimplemented promise. Add one `_caveats.html` partial
  with a required minimum set (days public is a floor, owner is inferred and gated, a MUST
  reading is a candidate, counts are a floor bounded by coverage at N of M CNAs), include
  it on every page that renders a row or a name, render it at body size in the `.caveat`
  treatment, and cap the front page at one "how to read this number" strip so future
  hedges have a defined home instead of accumulating as unread paragraphs.
- **Per-CNA fairness.** `templates/cna.html:70-71` stamps a "past 72h" chip on every row
  (220 to 241 of them) using the exact rendering `templates/cves.html:91` suppresses with
  a code comment explaining that it is noise, and it is the one page missing the
  days-public-is-a-floor caveat. Pass a single `show_late` boolean from `site.py` into both
  templates and move the caveat onto the page a CNA actually reads.

### 17. Carry the candidate qualifier everywhere the strength appears (CNA, Consumer, CISA, MITRE, Design)

`rbp/clock.py:162-168` sets `rule_certainty = "candidate"` and states "The site is
required to carry this qualifier wherever it shows `rule_strength`". Verified: `grep` finds
`rule_certainty` and `rule_basis` in no template and in neither CSV column list, the
rendered chips read a bare "4.5.1.4 MUST" 210 times, and the deployed `data/rbp.json` does
not even contain the keys, so a consumer cannot reconstruct the qualifier at all. The word
"candidate" appears in three prose paragraphs and on zero rows.

Render it in the Rule cell as a second line at an AA-compliant colour (not in a `title`
attribute, which is invisible on touch and to screen readers, and not appended inside an
11.52px chip). Add `rule_certainty`, `rule_basis`, `owner_nameable`, `state`,
`indep_sources` and `clock_known` to `CSV_COLS`. Consider welding the pair into one column
name so the hedge survives a downstream column drop. Add a test that no rendered page and
no exported column contains `rule_strength` without the adjacent certainty.

Same pass: render `indep_sources` as the Feeds column. Verified 314 of 553 rows show
`feed_count >= 2` with `indep_sources == 1`, all of them GHSA plus its own OSV mirror, on a
site whose `/method` explains in prose that an OSV row is not evidence GitHub disclosed
anything. The honest number is already computed at `rbp/report.py:147` and rendered
nowhere.

### 18. Version and identify the published data before anyone can pin it (Consumer, Actions, Python, CISA)

`rbp/site.py:188` writes `rbp.json` as a bare top-level array with no version, no
timestamp, no run identity and no degraded flag; `report.py:180-183` and
`site.py:179-181` define **different** column lists for two published CSVs of the same
rows; and the field set has already drifted twice at a stable public URL with no marker
(the deployed rows lack `rule_basis` and `rule_certainty` which the snapshot rows carry,
and the persisted `summary.json` predates the `epoch` keys its own code emits). Adding an
envelope after launch is itself the breaking change, so it has to land before anyone pins.

- Wrap as `{schema_version, generated_at, run_id, git_sha, snapshot_dir, profile,
  min_age_days, epoch, epoch_excluded, undated_excluded, coverage, feeds: {requested,
  failed, truncated}, degraded, unresolved, counts, rows}`. Same header block in
  `summary.json`, and a version plus comment lines in the CSV.
- Key the snapshot directory on the **run timestamp**, not the date. Verified: five state
  commits on 2026-08-20 against exactly one `snapshots/2026-08-20/` directory, so three of
  four daily runs overwrite the day's snapshot, `site.py:72`'s `snaps[-2]` baseline is
  actually yesterday's final run, and the diff interval oscillates between roughly 2 and 20
  hours within one day. Land it together with a retention policy (see item 24) or the fix
  for a diffing bug becomes a repo-size bug.
- Stamp `github.run_id` and `github.sha` into the snapshot, the built site and the state
  commit message (today it is `state: run <date>` with neither), so a published number is
  attributable to the code and configuration that produced it.
- Publish `sources`, `refs` and the per-source dates as JSON **arrays**. They are currently
  unescaped delimited strings in a JSON file, 391 ref tokens contain more than one colon,
  and one delimiter position now carries third-party free text (`csaf:Schneider Electric
  CPCERT:...`, `csaf:Bundesamt fur Sicherheit in der Informationstechnik:...`), so a
  publisher name containing a comma or semicolon corrupts the list for every consumer.
  Split the CSAF reference into explicit `publisher` and `tracking_id` fields, which also
  unblocks the publisher keying in item 8. Stop truncating `refs` at 250 characters, or
  truncate on a token boundary and set a flag.
- Fix the `/data` page's description of `precision.json`, which is wrong: the published
  file is a summary dict where `graded` is an integer count, with no predictions in it.
  Rename the published file so it cannot be confused with the real ledger the workflow
  copies under the same name.
- Add `owner_nameable` to the CSV so abstention is machine-readable rather than inferable
  from a magic string, and publish the slug-to-assigner mapping as the authoritative join
  table. Assert slug uniqueness and fail the build on a collision: verified two collisions
  in the real assigner namespace (`Hillstone`/`hillstone`, `NETGEAR`/`netgear`) which would
  silently overwrite one CNA's page and export with another's.
- Pin `CSV_COLS`, both column lists and the JSON key set in a test so drift fails CI.

### 19. Lock down the token and the branches (Actions, Python, CISA, Consumer)

`deploy.yml:40-43` grants `contents: write`, `pages: write` and `id-token: write` at
workflow level, so both jobs get all three, and verified server-side that nothing
constrains it: `/branches/data/protection` returns 404, `/rulesets` returns `[]`,
`allowed_actions` is `all`, `sha_pinning_required` is `false`. The `data` branch is the
**only** copy of `precision.json`, `resolutions.json` and every snapshot (nine paths, no
mirror), and the checkout keeps the credential on disk in the same job that parses roughly
2 GB of untrusted remote archives. Deleting that branch also breaks step two of every
future run, since `actions/checkout` fails hard on a missing ref with no fallback, so the
pipeline never self-heals.

- Add rulesets on `main` and `data` blocking deletion and non-fast-forward pushes. This is
  the immediate win: no code change, and it closes the irrecoverable outcome.
- Split permissions per job (`build: contents: write`, `deploy: pages + id-token,
  contents: read`), set `persist-credentials: false`, add `permissions: {}` to `ci.yml`,
  and turn on the repository's `sha_pinning_required` setting, which exists and is off.
- Mirror both ledgers outside this repo (a release asset per run, or a second repository)
  so `contents: write` here is not sufficient to destroy the accountability record.
- Make the state checkout tolerant and bootstrap an orphan `data` branch when it is
  missing, and document that prerequisite so the build is reproducible from a fork.
- Move `RBP_MIN_AGE_DAYS`, `RBP_EPOCH` and `RBP_LAUNCHED` into a committed file on `main`.
  Three unversioned settings decide the headline number, they leave no trace after the
  90-day log retention, and a site whose thesis is that private discretion is
  indistinguishable from no enforcement should not compute its own headline from private,
  unreviewable configuration. If they stay as variables, echo the resolved triple to
  `$GITHUB_STEP_SUMMARY`, write it into `summary.json`, and put it in the state commit as
  git trailers.
- Generate a hash-pinned lockfile (`pip-compile --generate-hashes`) and install with
  `--require-hashes`. `pandas>=2.0,<3.0` and `pyarrow>=14,<21` with no lockfile, four times
  a day, unattended, into a job holding `contents: write`, is the real supply-chain path
  here; the actions themselves are all first-party and SHA-pinning them is lower priority.
  Point `cache-dependency-path` at the lockfile when you do.
- Delete the dead `else` branch at `deploy.yml:123-129`. It is a success path that
  publishes a one-page holding site over the live dashboard if `rbp/site.py` is ever
  renamed. Replace it with an output assertion.

### 20. Delete the loaded gun in `report.py` (Python, MITRE, CNA, CISA)

`rbp/report.py:99-100` defines a dead `_OWNER_FEEDS` mapping `GitHub_M` to
`{"ghsa", "osv"}` (verified: referenced nowhere), two hundred lines from the live
`clock.OWNER_FEEDS`, which deliberately excludes `osv` with a comment explaining that
including it would rest the site's strongest claim on the weakest evidence available. On
the live snapshot, reconnecting it would move roughly 200 rows from SHOULD to MUST on
mirror evidence. Delete it and add a grep-style test asserting `clock` is the only module
defining an owner-feed mapping, the way `tests/test_clock.py:358` already pins the OSV
exclusion. Keep `report._gated`'s recomputation of `clock.self_disclosed`: the project has
already shipped a production outage from reading a field an earlier stage set, so
recomputing from the single live table is the defensive direction.

---

## Part 2: the launch gate

The stated gate is 50% CNA coverage (currently 36.4 to 40.6%). Keep it exactly as stated:
it is in a public repo, and swapping it for easier-sounding conditions after failing to
reach it reads as moving the goalposts, with the diff as evidence. Add these conditions on
top, in the same commit, and say plainly that the additions are about concentration and
fairness rather than breadth.

1. **No single CNA above 50% of named rows.** Today one CNA is 84 to 96% of named rows and
   100% of the MUST count. Breadth is not what makes this unfair; concentration is.
2. **At least 10 CNAs whose own advisory feed is ingested**, so a candidate MUST is
   reachable for more than one organisation. Today it is one on the scheduled profile.
3. **No named CNA below the 97% floor** at the (CNA, gap-width) cell its live rows
   actually occupy. This is the condition that would have caught both bad rows before
   anyone had to notice them by eye.
4. **Every named CNA notified, with the correction window elapsed**, through a route that
   exists, including a private one. The project's own rule (`rbp/report.py:363-364`)
   already requires this and the six-hourly deploy currently breaks it.
5. **The list submitted to the Secretariat and the relevant Roots**, with the outcome
   stated on the site.
6. **All Part 1 blockers closed and their CI assertions green**, including the
   `len(rows) == summary["total"]` invariant and the epoch integration test.

Also: coverage must be published and the gate enforced in `site.py`, or none of the above
is a gate. And measure it against the Program's partner roster, not against corpus
assigners.

---

## Part 3: wanted, not blocking

Ranked by value per unit of effort.

1. **Rejected-while-public as a first-class class** (CISA, Consumer, MITRE, CNA, Python,
   Marketing). The best additive idea on the board and the best post-launch beat. A CVE ID
   cited in a public advisory and then rejected is a permanent orphan reference: the
   advisory stays up, the ID resolves to nothing forever, and every CVE-keyed pipeline gets
   a permanent miss. It is strictly worse for defenders than an RBP, nobody publishes it,
   and the code currently counts it as the backlog healing itself. Prerequisite: stop
   caching REJECTED in `rbp/classify.py` (`_IMMUTABLE` plus permanent caching means these
   rows are already unreachable; 13 are sitting in the local cache today), because after
   that the population is unrecoverable without a cache wipe.
2. **KEV cross-reference** (CISA, Marketing, CNA, MITRE, Consumer). A `kev` boolean and
   `kev_date_added` joined on `cve_id` from CISA's free catalog, with a front-page line and
   a `/cves` filter. It is the single change that turns an age-ordered compliance list into
   something a defender acts on, and it adds exactly zero information to an attacker
   because those entries are already exploited and already federally published. Keep the
   scope discipline: no CVSS, no EPSS, no severity of the site's own. Publish the zero when
   the intersection is empty; volunteering the reassuring result is what makes the alarming
   one credible.
3. **A time series.** There is no count-over-time surface anywhere and no history export,
   so the site can only ever produce bad news, and the snapshot-per-date overwrite is
   destroying the raw history as it is produced. Append one record per run to
   `data/history.json` (timestamp, total, past_expectation, median, coverage, degraded,
   profile, sha) and render one line chart beneath the lead count. This is what makes the
   count citable more than once, and it is the only surface on which the project's own
   declared win condition could ever be visible.
4. **Delta and resolution exports.** `data/changes.json` (three verified buckets),
   `data/resolutions.json`, `data/held_back.json`. `changes` and `resolutions` are already
   built into the render context and discarded to HTML, so this is two `json.dump` calls.
   Hold the Atom feed until `/changes` can distinguish "new because a CNA missed a
   deadline" from "new because a feed was added": a subscription surface converts that
   ambiguity into a stream of individually wrong notifications aimed at named
   organisations.
5. **Per-CNA change feed.** More valuable to the named party than a site-wide feed: add
   new/resolved/dropped to `data/cna/<slug>.json` and print the URL on the page, so a CNA
   can be notified rather than ambushed.
6. **Per-row proof link.** Nothing on any row links to the evidence of non-publication; the
   CVE ID links offsite to a third-party advisory. The row already carries `state` and
   `cve_id`, so a reservation-endpoint link is free, and it lets `/method` say every row is
   independently checkable in one click. Mark external links with `rel` and a consistent
   affordance, and fix the footer links, which are currently pixel-identical to plain text
   in both themes (1.0:1 link-versus-text contrast) including all four normative citations.
7. **Quote hierarchy.** The standing offer ("Unredact `owning_cna` and publish an RBP
   metric, and this site will point at yours instead") renders at 11.67px in the footer,
   the smallest text on the site, while the lead count is 104px: a 9:1 type ratio between
   the most defensible sentence and the most contestable framing. Promote it into the lead
   block at body size, and decide the one sentence the project wants quoted.
8. **Wire the good product map back in.** `product_cna.parquet` (17,366 products at the
   equivalent gate) is built, cached, restored and read every run only to have its length
   printed, while `Attributor` rebuilds a degraded 7,698-product map from the corpus's
   first-affected-product column, which is exactly the degradation `apply_deltas`'
   docstring says it exists to prevent. Use it **negatively** (contradiction and
   plausibility gates), not to promote more rows to corroborated. `cvelist.load_index` is
   entirely unreferenced; delete it or use it.
9. **Corpus integrity guards.** Row-count floor, monotonic non-decrease, zero PUBLISHED
   rows with an empty assigner, column-order assertion, a content hash and the pyarrow
   version in `corpus_state.json`, atomic parquet write, and a guarded read that falls
   through to the full rebuild rather than raising. The `assigner` column is simultaneously
   the grader's ground truth and the substrate of every name on every `/cna` page, and
   `drop_duplicates(keep="last")` can blank it with no check. Two wedge paths exist: an
   unreadable parquet the warm path cannot recover from, and `refresh_corpus` stamping the
   corpus as current when zero deltas were applied (reproduced), which freezes the grader,
   the ledger and `published_last_12mo` while every symptom reads as a finding about CNA
   behaviour.
10. **One hardened HTTP path.** Move `_OPENER`, `_url_ok`, `_get` and `_stream_zip` into
    `rbp/http.py` and have `classify` and `cvelist` use it, with a test that no module
    calls `urllib.request` directly. The SSRF control exists in exactly one of three
    network modules; the exposed ones are the two that fetch from URLs taken out of remote
    JSON.
11. **Per-source provenance.** `dates`, `products` and `descriptions` keyed by source, an
    explicit documented precedence constant instead of iteration order, and
    `public_date_source` published. Verified: `gather` resolves product and description by
    first-non-empty in profile-string order, so reordering one string literal changes every
    row's displayed text and re-resolves the product map across the corpus, and an
    ALAS-only row reaches the attributor with `product == ""` by construction, which is why
    the plausibility gates cannot fire on exactly the rows that produced the two bad names.
    Publish a per-feed date-semantics table on `/method`: the six date fields do not all
    mean the same event, and for the 112 rows dated only by flaw-date feeds the floor
    property is not guaranteed.
12. **Naming coverage over the published set.** `run_coverage` is computed over the full
    724-row backlog and rendered beside a 553-row table. The numeric difference is 0.3
    points, so this is a labelling fix: rename the published key `backlog_coverage`, add
    `published_coverage`, and label it as abstention rather than as shortfall, since
    declining to name half the rows is the site's best evidence of discipline.
13. **Histogram.** The lowest band is derived from a hardcoded 7 while `min_age_days` gates
    the set, so `<7d` can never be produced (the key is absent from the published
    `age_buckets` entirely, which is also an undeclared sparse-schema hazard for
    consumers), and `.histo-bar { min-height: 2px }` draws 0 and 8 identically. Derive the
    lowest band from `min_age_days`, emit all bands explicitly, remove the min-height, and
    rebband to the real mass. The panel split on whether to keep the chart at all; the
    chair's view is keep it, because it is the only visual that answers "this is just
    publication latency", which is the objection that decides how the site is read.
14. **Linked-filter degradation.** A shared `?owner=X` URL silently renders all rows and
    `writeUrl` then erases the evidence that a filter was requested, on a page that
    promises linkable views; a bogus `?sort=` renders source order while presenting itself
    as sorted; and `'&mdash;'` inside three Jinja expressions renders as literal
    `&amp;mdash;` under autoescape. Inject a disabled option and a visible notice, move
    `aria-sort` to the restored column, and use a plain ASCII placeholder (the house style
    excludes em dashes anyway).
15. **Data branch retention.** Verified 1.44 MB per snapshot day, append-only, with two
    directories ever read and no pruning anywhere, so the branch grows roughly 525 MB a
    year toward the 1 GB ceiling the project's own `.gitignore` documents, and every run
    downloads and copies all of it. Dropping `backlog_full.json` and `report.md` from the
    pushed set (item 4) removes about 90% of the growth. Add a retention policy before
    timestamp-keyed snapshots multiply the rate.
16. **Baseline index memory and the cold path.** `build_index` holds the 647 MB inner zip
    in RAM (measured 2.44 GB peak) while its docstring claims the opposite, the zip-bomb
    ceiling is applied after the largest allocation, and the `ZipFile` objects are never
    closed. Stream to a temp file, close the handles, move the ceiling ahead of the
    allocation, and correct the docstring. Comfortable on a 16 GB runner today; the
    docstring is the real hazard.
17. **Nav and orientation.** No current-page indicator on any of eight route types though
    `.nav-menu a.active` is already styled and `page` is already in the context, and no
    breadcrumb on the per-CNA page, which is the deep-link entry point. One expression per
    nav item, no new CSS.
18. **Share previews.** Per-page overridable `og_title` and `og_description` blocks (the
    title is already a block that no child overrides), the CNA name and row count on
    `/cna`, `og:url` from the page path rather than a constant, `twitter:card`, and a
    1200x630 image carrying the floor caveat rather than a number that goes stale in six
    hours. Build the floor into the verb ("At least N CVE IDs...") rather than a
    parenthetical that truncation will eat first.

---

## Part 4: dropped, and why

These were argued and did not survive, or survived only in amended form. They are recorded
so they are not silently reopened.

- **"Two public copies of 2026-08-20 disagree by 151 rows" as a live blocker.** Withdrawn
  by its author: both files compared are gitignored local builds from two hand-run
  invocations, not published copies. What survives is real and is folded into item 18:
  missing run identity, a date-keyed snapshot directory that overwrites in place, and a
  persist step that runs before the Pages upload so the branch can advance past a snapshot
  the public never saw.
- **A flat `gap <= 10` abstention gate.** Refuted by measurement: it deletes 30 mitre rows
  at 97.7 to 99.8% precision and keeps 23 GitHub_M rows at roughly 90.7%. Superseded by
  the joint (CNA, gap band) cell gate in item 11.
- **A per-CNA precision floor as the sole gate.** Self-corrected by its author for the
  mirror-image reason: it keeps all 236 GitHub_M rows including the weak mid-gap band. Also
  superseded by the cell gate.
- **"Require two or more independent sources before naming."** Both known-bad rows carry
  `indep_sources: 3`. Independent-origin counting is a mirror-collapse gate, not a
  plausibility gate, and must not be presented as a correctness check on the owner name. It
  does still bite for MUST specifically, where 197 of 210 rows are single-origin.
- **Using `attribution.CURATED` against the free-text description as a suppression signal.**
  Measured roughly 50/50: it would suppress a probably-correct zdi row (100% precision on
  n=102) alongside the true catches, and it reintroduces the substring hazard
  `attribution.py` documents having already fixed once. Replaced by the product-map
  contradiction gate and the corpus-derived ecosystem gate.
- **Gating on the existing `ecosystem` field.** It is an OSV package-ecosystem label,
  populated on 374 of 553 rows and empty on exactly the distro-sourced rows the gate needs,
  including both exemplars. The corpus-derived version stands.
- **`if: always()` on the persist step.** Would commit a half-written ledger over the good
  one, which is the corruption the atomicity finding is trying to prevent. Keep persist
  gated on success; the reorder and the retry loop stand.
- **`cancel-in-progress: true` on the pages concurrency group.** Creates an interruption
  window on the in-place parquet rewrite and can cancel an in-flight `deploy-pages`.
  Timeouts plus atomic writes get the same recovery without the corruption window.
- **Cross-branch or fork poisoning of the corpus cache.** Refuted: Actions cache entries
  are scoped to the current ref and the default branch, so poisoning requires push access
  to `main`. The guards stand as robustness and reproducibility work, not as an attack
  path.
- **SHA-pinning the actions as a priority item.** All five are first-party `actions/*`;
  the unhashed pip range is the real exposure. Reduced to low, and the server-side
  `sha_pinning_required` setting is a better fix than per-line comments.
- **Deleting 4.5.3.5 from the site.** Amended, not adopted. Its current use on `/policy`
  ("a long-lived reservation is not a neutral state") overreaches and should go, because
  read literally it makes every reserved ID a live breach and it points a pressured CNA at
  the outcome worst for defenders. But the rule is load-bearing in its correct home: it is
  why rejection is a lawful terminal outcome, which is the basis for the rejected-while-
  public class.
- **Exporting `owner` as null in JSON and empty in CSV.** Refuted: a blank reads as missing
  data, invites `row.product_map_owner or row.owner` coalescing, and a spreadsheet fill-down
  turns it into a real misattribution. Keep the `unattributed` sentinel, add
  `owner_nameable` and `owner_status`, and do not rename the published key on an
  unversioned file.
- **Renaming `past_expectation` to `days_public_exceeds_expectation_floor`.** Refuted as
  unusable. Keep the field, add `expectation_clock: "floor-from-first-public-reference"` to
  the envelope, and fix the on-page copy, which is where the risk actually lives.
- **Repairing the `/cnas` rate statistic (relabelling, or a composite denominator).**
  Refuted in favour of deletion, item 15.
- **Deleting `report._gated`'s `self_disclosed` recomputation.** Refuted: reading a field an
  earlier stage set is the direction that caused a shipped production outage. The dead
  `_OWNER_FEEDS` table is the real defect.
- **Building a render-time duration filter for "four and a half years".** Refuted as
  premature: the paragraph is being rewritten. If a span survives, state the two dates
  (2022-01-25 "will be replaced at a later date" to 2026-08-13 v2.0.0), which is checkable
  and is also the only version of the claim that is unarguable.
- **"There is no public record that a CNA was notified" as an unscoped absolute.**
  Downgraded to low. The claim appears to be true, but it is asserted from absence of
  search rather than from evidence, and "the Board archives and working group minutes are
  public" is a complete rebuttal to the sentence as written. Scope it and turn it into the
  ask: report RBP notification and remediation volumes in aggregate.
- **Replacing the 50% coverage gate.** Self-refuted by its author. Keep it and add
  conditions, Part 2.
- **A site-wide Atom feed of newly appearing rows.** Deferred, not dropped, and it must not
  ship before the notification path and the feed-addition ambiguity are fixed. A resolutions
  feed is the safe one to ship first.
- **The claim that `/changes` says "since last run".** Refuted: the templates render
  "Against snapshot {{ changes.previous_date }}". The interval defect is real and the
  phrasing is in PLAN.md, not on the site.
- **The claim that the CSAF publisher is parsed and discarded** (asserted in four
  findings). It is retained in `refs` as `csaf:<publisher>:<id>` and is already published,
  which makes the publisher-keying fixes cheaper than the panel believed, and which is also
  why item 18's array-and-escaping fix is a prerequisite rather than a nicety.
- **`deploy.yml:128` as the pre-launch mechanism.** It is dead code; the holding page is
  installed by `rbp/site.py:235-239`. The holding-page conclusions are unaffected, and the
  dead branch is its own small hazard (item 19).
- **The claim that a single-feed failure would publish hundreds of false resolutions.**
  Measured: feeds overlap heavily, and total loss of any one feed strands at most about 5%
  of rows (osv 36, debian 35, alpine 23, csaf 12, redhat 9, ghsa 5, ubuntu 0, alas 0). The
  unbounded departure causes are the feed profile switch and the MUST bucket. Argue it on
  the profile, not on hundreds.

---

## Part 5: chair's additions

Five things the panel did not raise, and which the chair believes belong on the list.

1. **Hand-review every named row before the first notification, and every new CNA's first
   appearance thereafter.** There are roughly 280 named rows across 9 CNAs. That is a few
   hours of reading, it would have caught both bad rows before six reviewers had to find
   them, and it is the only control that catches the error class no gate anticipates. Make
   it a standing rule: the first time a CNA appears on this site, a human looks at the row.
   Record the review in the repo so the discipline is visible.
2. **Verify mechanically that the CVE ID appears in the advisory you link.** The typo class
   is currently addressed only by rhetoric (a false absolute on `/method`). Fetch the
   `advisory_url` and confirm the CVE ID string is present in the page or the feed record
   that produced it. That is a real check against transcription errors upstream, it is
   cheap on a few hundred rows, and it converts "a typo cannot inflate the count" from a
   claim into a measurement. Publish the count of rows that failed the check.
3. **Bound the floor with a sampling audit.** The site says "counts are a floor" everywhere
   and never estimates how far below the true number it is. Take a random sample of reserved
   IDs from the corpus-adjacent population, check by hand whether each is publicly
   referenced, and publish the estimated miss rate with its interval. Without that, the
   floor claim is unfalsifiable, which is exactly the property the site criticises in the
   Program. It is also the strongest possible answer to "your feeds only reach a third of
   CNAs".
4. **Decide the publishing entity, the terms, and the corrections policy before
   notification.** An individual publishing accusatory claims about named organisations, on
   a domain with no entity, no terms of use, no data licence and no stated corrections
   policy, is carrying risk that a paragraph and a page would materially reduce. Publish:
   who publishes this, under what licence the data is reusable, how a correction is
   requested, how long it takes, and what happens when the site declines. The appeals ladder
   is part of the mechanism, not an afterthought.
5. **Decide deliberately whether PLAN.md stays public.** It is on `main` in a public repo
   and it contains the launch strategy, the predicted attacks, the risk register and the
   project's own assessment of where it is weakest. That is a gift to a hostile reader and
   also, arguably, the most honest artefact the project has. Either is defensible; inheriting
   it is not. If it stays, it should be written knowing it will be read, and the review
   documents that accompany it (including this one) should be too.

---

## Part 6: what the panel disagreed about most, and why it matters

The sharpest disagreement was not about any single finding. It was about **whether a defect
that fails closed is serious**, and it split cleanly along discipline lines.

The engineers repeatedly downgraded findings on the grounds that the failure is safe: the
Wilson `ValueError` kills the run rather than publishing a wrong number, so it is not a
blocker; a partial scan aborts and leaves the previous good site live; a 2.44 GB peak fits
in a 16 GB runner; an unversioned export cannot make a false statement about a named CNA.
The non-engineers repeatedly upgraded findings on the grounds that the failure is
quotable: a hand-typed "roughly half" beside a rendered zero, a 104px accusation above a
1.97:1 hedge, a "Do not forward" banner on a public branch, a half-quoted rule. Neither
side was wrong, and the resolution is that this project has two failure modes with
different physics. A wrong number can be corrected. A demonstrated pattern of cropping the
documents you cite cannot, because the second time a reader finds one they stop checking
and start assuming.

That is why the ordering above puts the citation pass and the two wrong rows ahead of
several genuinely more severe code defects. The code defects are all recoverable by a
commit. The framing defects are recoverable only before anyone reads them, and one of them
is already live.

The second disagreement worth recording: **the epoch**. Three reviewers found that the
launch-day reset produces a literal zero for a week, and the panel could not agree whether
the answer is to move the epoch, to drop it, or to change the lead metric. That decision is
not a bug fix, it decides what the product is: a stock of outstanding rows, which supports
"the dashboard the CVE Program should have published", or a flow of new arrivals, which is
a different and narrower claim. It should be made deliberately, in writing, by one person,
before any of the epoch code is touched.

The third: **whether the fix rate should be published at all**. One reviewer wanted the
hardcoded "roughly half" simply deleted; another argued it is the single best credibility
asset the project has and should be computed, published with its n, and moved to the front
page, because a site that publishes how often the problem resolves itself is an instrument
and a site that publishes only the backlog is a campaign. The chair sides with the second,
conditional on it coming from the verified ledger over the published population. That
sentence is the difference between the two things this project could become.

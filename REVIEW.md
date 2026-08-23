# RBP Tracker: combined panel review, round 4

**Verdict.** The measurement underneath this project is honest and unusually careful, and
several of its judgement calls (the abstention tier, the coordination buffer, the refusal
to publish a rate, the withdrawn-threshold reasoning, the transfer-aware resolution
ledger) are better than anything comparable in this space. It is still not launchable,
for a reason that has not changed across four rounds: the site publishes names about
third parties through artefacts that no gate inspects, promises a correction mechanism
that the people it names cannot reach, and measures its own accuracy with the errors
those people report removed from the denominator.

Eight reviewers sat: Python, Web Design and Layout, GitHub Actions, CNA Operator,
CVE Program (MITRE), CISA / Government, CVE Consumer Working Group, RogoLabs Marketing.
Roughly ninety findings were raised over three rounds of cross-examination; they merge
into thirty-four items below, of which eighteen block launch. Cross-discipline
convergence is recorded on every item, because where four disciplines independently
found the same defect from four different directions, that was the strongest signal the
panel produced.

Ordering rationale for Part 1: first make the artefact legible enough that a fix can be
verified, then stop what is already publishing false statements about named third
parties, then repair the channel those parties would use to complain, then everything
that breaks on the day `RBP_LAUNCHED` flips.

One correction to the standing project note before anything else. The memory line
*"checklist 8 of 9, coverage is the only condition left"* is false. This round
establishes that conditions 2, 4, 5 and 7 are contradicted by the live artefact or by
the code they name, condition 6 is satisfied by a figure stratified on the wrong axis,
and the 50% coverage threshold is unreachable by construction (ceiling 28.2% on the
current feed set). Coverage is not the only condition left; it is the only condition
anyone was still counting.

---

## Part 1: launch blockers, in the order to do them

### 1. Make the artefact self-describing before fixing anything else
**BLOCKER. Effort: half a day. Raised by: Python (r2), MITRE (r2), Marketing (r2),
Consumer, GitHub Actions (r2).**

Five findings this round, including two filed as blockers, were written against a stale
local build and refuted on the live branch. That is not a reviewer failure; it is the
predictable consequence of an artefact that cannot say which code produced it. The same
gap will meet the first CNA who disputes a row.

Three changes, all cheap:

- **Run identity.** Export `github.sha`, `github.run_id`, `github.run_attempt` and
  `github.event_name` into the `Run pipeline` and `Build site` step envs in
  `.github/workflows/deploy.yml` (they are available and currently unused). Write
  `run_id` and `build_rev` into every file a snapshot contains, into
  `schema.envelope` (`rbp/schema.py:167-196`), and into the footer beside the build
  timestamp (`templates/base.html:118-120`). Have `site.load` refuse to build when two
  files in one snapshot carry different `run_id`s, and refuse to build from a snapshot
  written by a different revision.
- **Snapshot as a transaction.** `report.build` writes `snapshots/<today>` with
  `exist_ok=True` and never clears it (`rbp/report.py:268`); ten files land there from
  two modules across the run. `stat` on `snapshots/2026-08-20/` in this working tree
  shows three writes twenty-one hours apart in one directory. Build into
  `snapshots/.<date>T<hhmm>Z.tmp-<pid>/`, then `os.replace` the directory into place.
  Key it on `<date>T<hh>Z` and item 12's archive-stability problem dissolves with it.
- **Atomic writes, once.** `grep -c os.replace rbp/` returns zero. Every one of the 26
  `json.dump(obj, open(path, "w"))` call sites is non-atomic (`rbp/inference.py:449`,
  `rbp/clock.py:437`, `rbp/publish.py:77,99,178`, `rbp/cli.py:308,380,381`,
  `rbp/site.py:727-731`), as are both `to_parquet` writes
  (`rbp/cvelist.py:190,291`). Write one `_write_json(path, obj)` helper using tmp plus
  `os.replace` and use it everywhere. This is the shared root cause of the ledger reset
  (item 26), the torn snapshot above, and the poisoned corpus cache (item 27).

Then extend `site._assert_consistent` (`rbp/site.py:225-244`) past `len(rows) != total`
to recompute `corroborated`, `single_origin`, `named_cnas` and `top_owner_share` from
`rows` and raise on disagreement. That is the cheap detector for the whole torn-artefact
class, and it is what would have caught the state this panel spent a round arguing about.

### 2. The public ledgers name CNAs the site's own gate refused
**BLOCKER, launch gate. Effort: half a day plus a re-run. Raised by: Python (r1, r2),
Consumer (r3), CNA, MITRE, CISA, Marketing.**

Live on `origin/data` right now, verified by six reviewers independently:

- `resolutions.json` (65 KB, branch root, documented nowhere) names a CNA on **116 rows
  the site publishes as unattributed or holds back entirely**. Forty-six of those are
  published rows carrying `owner: null` with `owner_method` of
  `block-k3-vetoed-by-product-map` or `bulk-reporter-needs-second-signal`, that is, the
  gate fired and the ledger published the refused name anyway. Seventy more are rows the
  7-day buffer or the undated rule held back. Distribution: GitHub_M 75, mitre 36, plus
  Wordfence, WPScan, zdi, XEN and microsoft.
- `precision.json` names `mitre` on five published rows whose live `owner` is `null`
  (CVE-2026-36849, CVE-2026-39043, CVE-2026-39044, CVE-2025-28269, CVE-2025-65852).

Mechanism: `Grader.record` is first-wins (`rbp/inference.py:373`) and `Grader.withdraw`
is keyed on ids, not names (`rbp/inference.py:388-391`), so a row that keeps its place in
`record_for` but loses its name is never withdrawn. `ResolutionLedger` records the
ungated prediction. `publish.check`'s ledger rule is a set difference on ids
(`rbp/publish.py:274-276`) and is hardcoded to `precision.json` by name, so it is
structurally blind to both.

Changes:

- Write the gated owner, not the raw prediction. `ResolutionLedger` records `null` when
  `owner_nameable` is false and carries no owner at all for held-back rows. If the raw
  prediction is needed for grading, keep it de-identified (tier, k, method, dates).
- Make `withdraw` name-aware: in `apply_to_backlog`, build
  `named_now = {r["cve_id"] for r in backlog if r.get("owner")}` and call
  `grader.withdraw(record_for & named_now)`.
- Extend `publish.check` content rules to every file on `ALLOWED_ROOT`, not just
  `snapshots/*`: no id in any root ledger may carry a non-null owner unless the newest
  `backlog.json` names the same CNA on the same id.
- Re-run once and confirm clean **before** promotion, and land it together with item 20,
  because the data branch is append-only and deleting these from the tree does not remove
  them from history.

Launch condition 2 ("No ungated name on any world-readable artefact",
`rbp/launch.py:90-99`) is declared MET today and is false today. So is
`docs/github-support-request.md`'s claim that the mitigation already shipped.

### 3. The last guard before publication cannot see most of what it guards
**BLOCKER. Effort: half a day. Raised by: Python (r1, r2, r3), GitHub Actions, CISA (r2),
Consumer.**

Four independent holes in `rbp/publish.py`, all in the one function whose job is to stand
between the tree and the push:

- **Dotfiles are invisible.** `glob.glob(state_dir, "**", "*", recursive=True)`
  (`publish.py:210`) never matches a leading-dot path component. Executed: a staged tree
  containing `.github/workflows/deploy.yml` and `.gitignore` returns `check() == []`,
  while `git add -A` (`deploy.yml:318`) does add them. `PLAN.md` records this exact
  incident: an inherited `.gitignore` on the data branch listed `snapshots/` and the
  first state commit silently dropped every snapshot while reporting success. Replace
  with `os.walk`, pruning `.git` by name at the top level only. The same blindness is in
  `stage` (127), `_scrub`'s target list (143) and `prune_snapshots` (190); replace all
  four.
- **An unreadable ledger passes.** The snapshot loop appends
  `"unreadable JSON about to be published"` on a parse error (229-233); the ledger block
  twenty lines below swallows it into `preds, published = set(), set()` (269-274) and
  returns clean. `prune_ledger` (174-180) has the same swallow. Make both fail.
- **Problem strings publish what they refuse.** `publish.py:237-239` embeds
  `r.get("cve_id")`, `:260-262` embeds a list of CNA short names, `:274-275` embeds a
  stray CVE ID, and `publish.main` prints them all (`:344-348`) into a world-readable
  Actions log on a public repository, retained 90 days, which no scrub, prune or history
  rewrite in this project can reach. The `notify` job then plants a permanent public
  pointer to that log in an issue body (`deploy.yml:348,359`). Report file, class and
  count only; keep the detail in a runner-local file behind a debug flag; use
  `::add-mask::` for anything that must be echoed. Do this **before** strengthening the
  guards, or the first thing a stronger guard does is publish what it caught.
- **The primary artefact is never inspected.** `publish check` is invoked as
  `--state .state` and `publish.main()` accepts no site argument, so `site/` leaves the
  runner with no allowlist and no content rule. Add a `--site` mode that reuses
  `site.assert_artefact` over `site/data/*.json` and `site/data/archive/**` rather than
  reimplementing the rules.

Fix `rbp/launch.py:95-96` in the same pass: it tells `/method` that `publish.check`
refuses "any ungated product-map field". No such check exists in that module; the only
one is in `site.assert_artefact` (`site.py:297`), which does not run over the staged tree.

### 4. The withhold lever does not reach the artefacts it promises
**BLOCKER, launch gate. Effort: one to two days. Raised by: Python (r1 x2, r3 x3),
GitHub Actions (r2, r3), CNA, CISA, Consumer, MITRE, Marketing.**

`method.html:552-554` states the guarantee: *"A withheld row is removed from every
published artefact including the accuracy ledger, not merely stripped of its owner,
because for an embargo the listing itself is the disclosure."* Six separate paths defeat
it. They are one work item because most of them are one workflow reordering.

- **Ordering.** `deploy.yml` runs `Run pipeline` (213), `Build site` (259),
  `upload-pages-artifact` (271), then `Stage durable state` (285), then
  `Check what is about to be published` (293), then `Launch gate` (304). `publish.stage`
  is the only code that scrubs. So the site is built from an unscrubbed snapshot tree,
  the Pages artifact is uploaded before either guard runs, and on a public repository
  that artifact is downloadable by anyone. Move `Stage durable state`,
  `Check` and `Launch gate` **above** `Build site` (not merely above the upload), split
  `stage` so pruning stays after the build, and add
  `if: ${{ vars.RBP_PAUSE != '1' && inputs.dry_run != true }}` to the upload step so
  `dry_run`, `fire_drill` and `rehearse_launch` really do publish nothing as their own
  input descriptions promise (lines 24, 28, 32). Set `retention-days: 1` explicitly.
- **`/changes` prints the withheld id.** `site._changes` computes `gone = before - now`
  from the unscrubbed previous backlog (`site.py:623`), a newly withheld row lands in
  `no_longer_listed` (`site.py:634`), and `changes.html:133` renders it as raw
  comma-joined text under a heading saying the cause is unverified. The mechanism that
  removes an id from public view publishes that id, by name, on the same build. Add
  `no_longer_listed` to the scrub explicitly.
- **The CSV scrub matches substrings.** `keep = [ln for ln in lines if not any(i in ln
  for i in ids)]` (`publish.py:108`), under a comment claiming the id "appears nowhere
  else in a row". Executed: withholding `CVE-2026-123` removes `CVE-2026-1234` and
  `CVE-2026-12345`. This is armed on today's data (`CVE-2026-5744` sits beside
  `CVE-2026-57441` and `CVE-2026-57442`), and the comment is false on 216 of 522 rows
  anyway because `advisory_url` repeats the id, and on seven rows because `description`
  cites a different CVE. Parse with `csv.reader` and match `row[0]` exactly.
- **The scrub desynchronises the counts.** It removes rows and leaves `summary.json` and
  `cnas.json` describing the old population, so a dated archive file publishes
  `total: 522` over 521 rows, which tells any reader exactly how many rows were removed
  from that date. Recompute the counts after scrubbing, and apply the two timeless
  invariants (`len(rows) == total`, `sum(outstanding) == len(named)`) from `publish.check`
  over every staged snapshot and from the archive loop.
- **`graded` is never scrubbed.** `_scrub`'s dict branch handles `open`, `resolved` and
  `predictions` (`publish.py:83-95`) and not `graded`. A withhold therefore deletes the
  open prediction that would have counted against the score and preserves the graded
  CVE-to-wrong-CNA pairing forever. Both directions are wrong. Add `graded`,
  de-identifying rather than deleting.
- **Committed digests miss history.** The durable, human-reviewed lever reaches prior
  snapshots only when the row is in this run's publishable set (`cli.py:223-229`),
  while the anonymous issue path always does. Build the scrub input from the union of
  ids in any retained snapshot instead.

Also add `data/precision.json` to the scrub, since `site.py:394` reads the `data/` copy
and `stage` only scrubs the `.state/` copy.

### 5. Two real CNAs collide on one `/cna/` slug
**BLOCKER, launch gate. Effort: two hours. Raised by: CNA, Python, Design, Consumer,
Marketing, MITRE, CISA.**

`site.slug` (`rbp/site.py:104-106`) collapses case and punctuation. Over the pinned
539-entry roster it produces 538 distinct slugs: `{'Snow', 'Snow Software'}` and
`{'SNOW', 'Snowflake'}` both become `snow`. `site.py:844` and `:979-980` write in loops
with no uniqueness check, so the second write silently overwrites the first, and
`_assert_consistent` is satisfied because both CNAs are in `cnas.json`.

The result would be one company's overdue list served at another company's URL and under
another company's name, in HTML and in `data/cna/<slug>.json`, which `/data` advertises
as a per-CNA endpoint. This is the only defect on the table where the harm lands entirely
on a party that is not even in the dataset, and it is silent.

Refuse the build when two CNAs in the pinned roster share a slug (not merely two named
CNAs, or the guard passes until the day it matters). Disambiguate from the `organization`
field rather than a numeric suffix, and render `short_name` and `organization` together
in the H1 **and** in the per-CNA JSON, so a URL quoted out of context still identifies
one company. Add a test asserting slugs are injective over the full roster.

### 6. The correction channel is unreachable, silent, and destructive
**BLOCKER, launch gate. Effort: two to three days. Raised by: CNA (r1 x2, r2 x2, r3),
CISA (r1, r2 x3, r3), Marketing, GitHub Actions, Consumer, MITRE, Python.**

Nine defects, one channel. Every surface of the site and `.well-known/security.txt` point
at it; launch condition 4 is declared MET on it. Fix as one change and re-rehearse it as
one, from an account with **no permissions on the repository**, which is the only
configuration in which most of these reproduce.

1. **The one-click route cannot apply its own label.** All six surfaces link
   `issues/new?labels=withhold` (`base.html:136`, `method.html:478`, `data.html:169`,
   `cna.html:61`, `placeholder.html:91`, and `site.py:923` writing security.txt). The
   `labels` query parameter requires triage or write permission; a CNA employee with an
   ordinary account files an unlabelled issue, and `suppress.from_issues`
   (`suppress.py:169`) queries `state=open&labels=withhold` and reads nothing else. `ls -a
   .github` returns only `workflows`: there is no issue template applying the label
   server-side. The read succeeds, so `err` is None and no degraded banner fires either.
   Ship `.github/ISSUE_TEMPLATE/withhold.yml` with `labels: [withhold]` in front matter
   and a dedicated CVE ID field; point all six surfaces at
   `issues/new?template=withhold.yml`; widen `from_issues` to also match unlabelled issues
   whose title begins `Withhold CVE-`.
2. **The parser reads the whole body.** `blob = title + body` and every distinct
   `CVE_RE` match becomes a request (`suppress.py:188-198`), so "same root cause as
   CVE-2025-1111" withholds an unrelated row and spends one of the author's five. Parse
   only the template's field, falling back to the title, never the free body. Echo the
   parsed list back as a comment before the next build acts on it.
3. **Deferrals are silent in every direction.** Past `MAX_PER_AUTHOR = 5` the request is
   appended to `deferred_author` and not honoured (`suppress.py:252-254`); the row keeps
   publishing; no reply reaches the requester; `degraded` (`cli.py:361-364`) has no
   deferral term. Invert it: withhold everything requested for one cycle unconditionally,
   and require the `confirmed` label for it to **persist**. That bounds the abuse case,
   which is what the caps were written for, to a single cycle, and makes the failure mode
   "a row is briefly missing" instead of "an embargoed row is published".
4. **The ceiling collapses on launch day.** `ceiling = min(MAX_AUTO, max(1, int(backlog_size
   * 0.05)))` (`suppress.py:244`) is passed the post-buffer, post-epoch published set
   (`cli.py:205`). At the rehearsed epoch (80 counted rows) that is 4; in the first week it
   is 1. `method.html:537` prints that number to the public as the designed value. Compute
   the share against the full observed backlog. Collapse the duplicate `MAX_AUTO` binding
   (`suppress.py:110` and `:218`) while there.
5. **The public route publishes the identifier the same page says must not be published.**
   `method.html:549-552` says "Counts, never identifiers: publishing which rows are
   withheld would undo the withholding"; `method.html:477-483` recommends a public issue
   with the CVE ID prefilled in the title, as the fast path. `label:withhold` on a public
   repository is a permanent, indexed list of reserved CVE IDs someone urgently wanted
   delisted. Invert the recommended default in the copy: private route first for anything
   that might be an embargo, public issue for ownership and delisting preferences.
6. **The private route is advertised as slower than it is.** `/method`, `/cna`, the
   footer and security.txt all say five business days, which is up to twenty builds. The
   committed HMAC list is read every run, so a maintainer can honour a request in one
   cycle today. Publish a same-cycle commitment for anything flagged embargo, and keep five
   business days for ownership disputes only. Add a monitored-alias delivery check, since an
   unread mailbox is indistinguishable from no reports.
7. **The maintainer's own operating document is wrong.** `suppressions.txt`'s committed
   header tells the maintainer that GitHub private vulnerability reports "are honoured
   automatically and do NOT need an entry here". No code reads them; `deploy.yml:219`
   records that the path was abandoned because it needed a fine-grained PAT. That is the
   file a maintainer opens under time pressure during an embargo call. Correct the header,
   give the literal command, and add a test that fails if the header claims a channel the
   code does not read.
8. **There is no lever except deletion, and deletion censors the score.** `suppress.py`
   recognises `withhold` and `confirmed` and nothing else; there is no dispute,
   annotation or contested state anywhere (`owner_contested` is about the product map
   disagreeing with block inference, not about the named CNA disagreeing). And suppressed
   ids are removed from `record_for` (`cli.py:228-229`) so `grader.withdraw`
   (`inference.py:585`) deletes the still-open prediction: the misattribution can never
   become a graded miss. So the published precision figure, which `/cna` tells the named
   CNA is "the figure to hold this page to", is computed with exactly the errors CNAs
   reported removed from it. **Stated plainly: the site's accuracy score improves every
   time it is caught being wrong.** Add a `dispute` label handled as an annotation (row
   stays, stays counted, `owner` clears to null with an explicit
   `withdrawn-on-cna-dispute` chip), and move censored predictions to a de-identified
   `censored` list published as `censored_open: n` beside `graded`, split by reason class
   so a structural epoch withdrawal is not summed with an evidentiary dispute.
9. **There is no right of reply.** The site states three times, in its own voice, that it
   cannot tell a delegated ID from a withheld one and that the CNA is the only party who
   can say. It then offers that CNA no way to say it. Add a committed `cna_notes.json`
   keyed on CNA short name (never on `cve_id`, so no individual row is confirmed or
   denied), rendered verbatim and attributed at the top of that CNA's page, length-capped
   and refusing any vulnerability detail. This is one JSON file and one template block,
   and it is the single change most likely to convert a legal response into a working
   relationship.

Fix `.well-known/security.txt` (`rbp/site.py:908-930`) in the **same commit**: it is the
machine-readable route a security team parses first, and it currently carries the broken
withhold URL, the five-day SLA, a public route listed first, and an `Expires` recomputed
to now+365 on every build so it can never signal a dead deployment.

### 7. Coordinator CNAs are nameable, because the guard that stops it matches nothing
**BLOCKER, launch gate. Effort: half a day. Raised by: CISA, Python, MITRE, CNA,
Marketing, Consumer.**

The naming gate is raw, case-sensitive membership: `if owner in bulk_reporters`
(`rbp/inference.py:236`), fed `BULK_REPORTER_NAMES` directly. Counted against the live
381,619-record corpus, **seven of eighteen entries match zero assigners**: `cisa`, `ZDI`,
`Fortinet`, `SSD`, `Zero Day Initiative`, `huntr`, `cert@ncsc.nl`. The spellings that
actually occur are `icscert` (3,829), `certcc` (3,458), `zdi` (3,420), `jpcert` (3,220),
`fortinet` (1,950), `twcert` (892), `cisa-cg` (182). A normalising helper,
`attribution.is_bulk_reporter`, exists and has exactly one caller: a test. A third
matcher, `(cna or "").lower() in BULK_REPORTERS`, governs the product map. Three matchers
for one list, and the strictest gate has the weakest one.

Live coverage confirms all five coordinators are already through the covered-set gate:
certcc 60 sightings, zdi 115, icscert 15, jpcert 10, cisa-cg 6, against
`MIN_SIGHTINGS = 3`. Zero ICS **vendor** CNAs are sighted at all. So the first
ICS-shaped name this site publishes will be a coordinator, and a coordinator holding a
reserved ID through a multi-party window is the mechanism working, not failing.

Route `inference.py:236` through `is_bulk_reporter`, delete the duplicate rule at
`attribution.py:88`, and add the roster spellings explicitly (normalising does not
recover `cisa` to `cisa-cg`): icscert, cisa-cg, certcc, jpcert, krcert, twcert, CERTVDE,
CIRCL, INCIBE, TR-CERT, SK-CERT, CERT-In, NCSC, NCSC-FI, NCSC-NL, NCSC.ch, MON-CSIRT,
TCS-CERT. Then generalise: assert in CI that every entry in the list matches at least one
assigner spelling in the live corpus, so a dead entry cannot sit in the list looking like
protection. Apply the same reachability assertion to `report._ORIGIN` over
`feeds.ADAPTERS` and to `clock.OWNER_FEEDS`.

Additionally: a coordinator-held row should never carry `past_expectation` as an
assertion about that CNA. The guard needs to be a rule-strength gate as well as a naming
gate.

### 8. The site claims a warrant it does not have, and a coverage guarantee it does not meet
**BLOCKER, launch gate. Effort: one day, mostly copy. Raised by: MITRE (r2, r3), CNA
(r3), CISA, Marketing, Consumer.**

Five statements the site makes about the Program or about itself, each refuted by another
page of the same site. All are live, all are in the launched nav, and all are the sort of
thing a reader can falsify by scrolling.

- **"Warrant".** `report.py:95-97` and the `SystemExit` at `:123` say CNA Rule 4.5.1.7
  "is this site's entire warrant for naming anyone", and `launch.py:147` titles condition
  5 "The 24-hour naming warrant bound in code". `policy.html:98-100` says, in bold: *"That
  is a rule about the Secretariat's own conduct. It is not this site's permission to name
  anyone, and the site does not claim it as one."* The `/policy` version is correct and is
  the stronger position. Delete "warrant" from `report.py:95-97`, `report.py:123`,
  `launch.py:147-152` and `PLAN.md:458`; retitle condition 5 "A self-imposed naming floor,
  bound in code". Note that `tests/test_policy.py:181-202` pins the wrong doctrine into CI
  and must change with it.
- **"The Program's own metric".** `index.html:84` and `method.html:28-29`. Three hundred
  lines below on the same rendered page: *"This site does not replace that series and is
  not comparable to it."* Cut the clause. "The Program's own **definition**, measured from
  outside, reported as a floor" is accurate and stronger.
- **"Redacted for exactly this population".** `index.html:87-89`, `index.html:282`,
  `classify.py:26`, `inference.py:6`, `site.py:11`. `policy.html:80-86` states the true
  scope and explicitly labels itself a precision correction: the redaction covers every
  reserved ID, tens of thousands a year, most of which are not RBP. The true version is a
  better argument for the ask, because it explains why the Program has not already solved
  this. Five sites, one phrasing, propagated from one original; add the copy test.
- **"Never name a CNA whose advisories this site does not actually read"**
  (`inference.py:222-225`, and `method.html:463`'s "whose advisories this site reads
  best"). The gate does not test that. `covered` counts that CNA's already-published CVE
  IDs appearing anywhere in any ingested feed. Live: `cnas_effective` 121,
  `cnas_own_channel` **2** (`mozilla`, `redhat`). The property the comment asserts holds
  for 1.7% of nameable CNAs, and specifically does not hold for GitHub_M, which holds
  96.4% of named rows and which `clock.py:135-160` spends twenty lines establishing is
  *not* reachable through its own channel. Rewrite the comment to say what the gate does
  (a floor on visibility, not evidence of reading that CNA's advisories), fix
  `method.html:463`, and put one sentence on `/cna` stating which of the three coverage
  conditions that CNA satisfies.
- **The ask refutes itself on the same card.** `policy.html:83-86` says the endpoint
  cannot tell which reserved IDs are publicly referenced; `policy.html:100-103` asks it to
  unblind "only for reserved IDs already publicly referenced for more than 24 hours".
  Lead instead with the grantable ask that is currently the last line of the last card:
  restore the RBP metric as a Program publication through the "Program metrics and audits"
  channel the policy itself names.

Add a copy test for each, since four of the five have already propagated across files.

### 9. Per-CNA precision answers the wrong question, and cuts off the CNAs that could check it
**BLOCKER, launch gate. Effort: half a day. Raised by: CNA, MITRE, CISA, Consumer,
Marketing, Python.**

`templates/cna.html:35-38` offers a named CNA a figure and says *"That is the figure to
hold this page to, not the global one."* The figure is `by_cna[X]`, accumulated as
`per[truth]` (`inference.py:263,278,281`), that is, P(prediction correct | X is the true
owner). The question a named CNA is asking is P(correct | this site named X), and the
published figure contains **zero** of the cases where X was wrongly named on someone
else's ID, because those are filed under the other CNA. With one dominant stratum the
bias has a direction: errors committed in GitHub_M's name are charged to the small CNAs
least able to absorb them.

Worse, `summarise_state` keys the live stratum on `g.get("actual") or g.get("predicted")`
(`inference.py:484`), so the axis is *mixed*: truth-keyed when the record publishes with
an assigner, prediction-keyed when it does not. A stratum built from two conditioning
events is not a rate of anything.

Three changes in the same function:

- Accumulate `per_pred[pred]` alongside `per[truth]`; publish the prediction-keyed figure
  on `/cna` as "when this site names X, it is right P% of the time (n=...)"; relabel the
  existing figure as recall or drop it from that page. Apply `MIN_GRADED` per stratum
  independently and publish `n` even when it is below the floor, because "we have never
  graded a prediction of your name" is itself the material fact.
- Remove `out["by_cna"] = dict(ranked[:40])` (`inference.py:297`). It sits two lines above
  `measurable_strata`, which counts over **all** strata, so roughly sixteen CNAs that clear
  the n=20 floor are told from their own page that they are "not separately measurable",
  which the same artefact contradicts. Live: 345 strata, 56 measurable, 40 published, and
  `icscert`, `certcc`, `cisa-cg` and `jpcert` are all among the cut. Publish every stratum
  above the floor, record `by_cna_truncated: n`, and assert
  `len([v for v in by_cna.values() if not v["below_floor"]]) == measurable_strata`.
- Add a fourth grader outcome, `transferred-on-publish`, set when `predicted != actual`
  and the resolution ledger flagged the same id `transferred`, scored `scored: false`.
  `clock.ResolutionLedger.reconcile` already computes exactly this boolean and its comment
  states why: under 4.5.1.5 the assigner on the published record is often the CNA-LR or
  Root that cleaned up somebody else's overdue ID. `Grader.grade` has no transfer concept
  and labels it `wrong`. As built, the `/method` misses table will name the party that
  applied the policy's own remedy as the *actual owner* of an overdue record. That is a
  defamatory implication against the only party in the transaction that behaved correctly,
  and it is structurally guaranteed rather than accidental.

### 10. Every 72-hour claim rests on a clock started by a tracker record
**BLOCKER, launch gate. Effort: one day. Raised by: CNA (r1 x2), MITRE, CISA, Consumer,
Marketing, Python.**

Two halves of one defect.

- **Wording.** `index.html:30-31` leads with "referenced in **two or more independent**
  public advisories". The pinned policy fixture says "referenced in one or more public
  **sources**", and `index.html:161` on the same page already says "sources".
  `report._ORIGIN` counts `debian`, `ubuntu` and `alpine` as independent origins, and none
  of those three adapters reads DSA/DLA, USN or ASA: they ingest tracker JSON wholesale.
  Measured, 64 of the 162 corroborated rows (39.5%) rest entirely on distro trackers. One
  word, two places, and it removes the first objection any Board member will raise.
- **Clock.** The policy separates membership ("referenced in one or more public sources")
  from the 72-hour trigger ("Publicly Disclosing", exemplified as an advisory or a Fix).
  `clock.annotate` derives `past_expectation` from `public_date`, which is the earliest
  date any ingested source carried, tracker rows included, and the result is
  `past_expectation: true` on **522 of 522** published rows. A claim asserted on every row
  is doing no discriminating work while carrying all the accusatory weight.

Add a per-origin `kind` (`advisory` vs `tracker`) and a `clock_origin` field. Keep
`days_public` as-is on tracker-only rows, because "referenced N days" is a true statement
and the floor framing survives it. Gate only `past_expectation` and the rule chip on
`clock_origin == "advisory"`. Publish the advisory-backed corroborated count as the
defensible headline. Say on `/method` that a tracker record is a public source under the
RBP definition and is not by itself a Public Disclosure under 4.5.1.4 or 4.5.1.6.

Note the same defect reaches the naming floor: `MIN_AGE_FLOOR_DAYS` exists to keep the
site outside 4.5.1.7's horizon, and that horizon runs from Public Disclosure. Gate naming
on the advisory-derived date, not on `days_public`.

### 11. The front page ships a per-CNA leaderboard with one entrant
**BLOCKER, launch gate. Effort: two hours. Raised by: MITRE, Marketing, plus ten
endorsements across every discipline.**

`templates/index.html:189-204` renders a five-row table sorted descending by count, each
name hyperlinked, with a column headed "Share of the N named CNAs' rows". Rendered:
GitHub_M 215, 96.4%. `PLAN.md` 2a forbids exactly this. The comment at `index.html:97-103`
records why the equivalent anonymous *tile* was removed ("the headline that writes itself
... was handing it over") and then leaves in place a table that prints the same number
with the name attached and a link.

Three aggravating facts the panel established: the concentration is substantially an
artefact of GHSA being the feed the pipeline reads deepest (item 14); the denominator that
would make 215-versus-1 legible is withheld on every surface where the numerator appears
(GitHub_M published 10,411 records in twelve months against suse's 85, and `/cnas` states
there is deliberately no rate column); and because there is no `og:image`, this table *is*
the social card, since it is the most screenshot-worthy element on the page.

Replace it with a shape that carries no name: how many CNAs hold 1 row, 2-9, 10+, plus the
count of named CNAs and the corroborated split. `rbp.css` already ships `.histo` and
`.histo-bar`, unused on this card. Move the names to `/cnas`, where the caveats are the
page rather than a caption. Deleting the table also fixes the front page's 262px of
horizontal overflow at 375px, since that table is its sole cause.

### 12. The site cannot tell when it has stopped, and it has already stopped twice
**BLOCKER, launch gate. Effort: one day. Raised by: GitHub Actions (r1 x2, r2, r3),
Python, MITRE, CISA, Consumer, Marketing.**

- **The staleness banner is structurally incapable of firing.** `site.py:517-519` computes
  `stale = age_hours > 12` from `summary["generated_at"]`, written by the same pipeline
  invocation minutes earlier (`cli.py:378`), with `Run pipeline` and `Build site` adjacent
  in the workflow. On success it is always ~0; on failure the job aborts before
  `Build site`, so the already-deployed HTML keeps a frozen `stale: false`. The comment at
  `site.py:426-429` names the exact failure it cannot catch. Compute staleness in the
  browser from an emitted `generated_at`, keeping the build-time value as the no-JS
  fallback, and emit `snapshot_date` beside it since the two move at different rates.
- **Two scheduled ticks already produced nothing.** Measured in UTC on `origin/data` and
  `origin/main`: the 2026-08-21 06:00Z tick has a 10h12m commit gap with **zero pushes** in
  the window, so nothing could have been queued or evicted; the 18:00Z tick the same day is
  the same story. Every successful non-dry-run necessarily commits, because `summary.json`
  carries a per-run `generated_at` and `git diff --staged --quiet` therefore cannot be
  true. Delivered ticks are also chronically late: 06:47Z and 12:50Z on 2026-08-22, the
  standard penalty for scheduling on minute 0.
- **Nothing records what was owed.** Snapshots are per-date and overwritten four times a
  day; the failure issue is the only artefact recording a failed tick and `recover` closes
  it on the next success; the data-branch git log is the only surviving evidence and is
  precisely what item 20's fix would force-push away.

Add a `runs.jsonl` on the data branch, appended as the **last step of `deploy`** (not
`build`), carrying run_id, run_attempt, event_name, the cron, the sha, the deploy
conclusion and page_url. Add an external dead-man's switch as its sibling, because it is
the only control that can observe a run that never started. Move the cron off `0 */6` to
`17 */6 * * *`. Publish delivered-ticks-in-the-last-7-days on `/method`, since the site
asks readers to trust a cadence it currently cannot evidence.

### 13. `notify` cannot see the two most likely failures, and `recover` clears alarms that were never resolved
**BLOCKER, launch gate. Effort: two hours. Raised by: GitHub Actions, plus broad
endorsement.**

`notify` is `needs: [test, build]` (`deploy.yml:337`); `deploy` is absent, so a failed
`actions/deploy-pages@v4` opens no issue. `recover` is gated on `test` and `build`
success only (`:382-383`) and unconditionally closes any open `pipeline-failure` issue,
including on a `dry_run`, on a paused run, and on a run whose deploy just failed, none of
which published anything. The issue body promises "This issue closes itself on the next
successful run."

Add `deploy` to both jobs' `needs`; gate `recover` on `needs.deploy.result == 'success'`;
match `timed_out` as well as `failure`. Note the correction from cross-examination: adding
`cancelled` to `notify` cannot report a run evicted at queue time, because `notify` is a
job inside the cancelled run. Only the external heartbeat in item 12 covers that case.
Verify `gh issue create --label pipeline-failure` against a repo where the label is
absent: `ls .github/` shows no label definitions anywhere, and with `set -euo pipefail` a
missing label makes the notification job itself die and file nothing.

Also: `recover` closing the issue destroys the only durable record that a failure
occurred, so land item 12's run ledger first.

### 14. Feed health is saturated in one direction and false in the other
**BLOCKER, launch gate. Effort: one to two days. Raised by: Python (r1 x2), MITRE,
GitHub Actions, Marketing, Consumer, CISA, Design.**

The project's own stated intolerable failure is a feed shrinking silently, and it has
happened twice. Today:

- **GHSA truncates invisibly.** `feed_ghsa` exhausts `for _ in range(page_cap)` with no
  `record_feed(..., TRUNCATED, ...)` call, twelve lines below `feed_ubuntu`, which does
  exactly that. `gather` then stamps it `ok` with the truncated count: the live summary
  reads `ghsa: {status: "ok", detail: "3321 ids"}`. Because a fixed cap returns a roughly
  constant count every run, `compare_magnitudes` reads stable truncation as a healthy feed.
  GHSA sources roughly 300 of 522 rows, and it bounds that population's observation window
  to about 83 days while distro trackers are observed over years, which invalidates every
  cross-CNA comparison the site prints without saying so.
- **Six of nine adapters swallow partial failure** and return what they have: ghsa,
  redhat, alpine, msrc, mozilla, csaf. `record_feed(f"osv:{eco}", ...)` never passes
  `rows=`, so every OSV part carries `rows: null`, and `compare_magnitudes` skips any name
  containing a colon. `tests/test_degraded.py:353` **pins that blindness as correct
  behaviour**: osv:npm 5000 to 100 must yield `[]`, on a component contributing 25% of
  osv's ids.
- **The flag is saturated on the page and false in the payload.** Ubuntu's 200-page cap
  fires every run, so `degraded` is permanently true and `base.html:99-105` renders "This
  run is incomplete ... not comparable to the previous run" on every page of every run,
  three hundred lines above a Movement card that compares this run to the previous one.
  Meanwhile `schema.envelope` does `bool(summary.get("degraded"))` and the served
  `rbp.json` says `degraded: false, degraded_reasons: []` on the same build. A warning
  that is always on is not a warning, and the machine-readable copy says the opposite.
- **No out-of-band signal exists at all.** There is no `GITHUB_STEP_SUMMARY` and no
  `::warning::` anywhere in `deploy.yml`; one `::error::` and one `::notice::`.

Changes: have each adapter return `(rows, ended)` and let `gather` be the only caller of
`record_feed` for adapter status, so instrumentation cannot drift from the adapter list
(which is what `gather`'s own docstring already claims). Pass `rows=added` at
`feeds.py:542` and let `compare_magnitudes` descend into parts. Emit identified reasons,
not counts (`feeds.health_summary()` already returns strings carrying the feed name; `cli`
throws them away). Split known-permanent structural truncation from new degradation via a
committed allowlist keyed on `(feed, reason)`, publish the allowlist on `/method` so it
cannot become a quiet way to silence new failures, and reserve the banner for a change.
Emit `degraded_reasons` to `$GITHUB_STEP_SUMMARY` plus one `::warning::` per reason, and
make a `compare_magnitudes` shrink a **hard non-zero exit**: a >40% drop has no benign
reading, and the cost of a false positive is six hours of staleness on a site that already
tolerates that. Publish each feed's observed window (earliest and latest `public_date`) in
the envelope, not only on `/method`. Fix the literal "1 feed(s) truncated" pluralisation.

### 15. The accessibility suite has never rendered a page, and six failures shipped green
**BLOCKER, launch gate. Effort: two days for the harness, two more for the fixes.
Raised by: Design (r1 x6, r2, r3 x3), CISA, MITRE, Marketing, Consumer, Python.**

`tests/test_a11y.py` is 267 lines and 17 tests, every one a `re.search` over CSS or
template text. Nothing in CI has ever loaded a document. The consequences are all on this
table:

- **Every chip fails AA in light theme.** Composited over the real row backgrounds:
  chip-none 1.75, chip-ok 2.41, chip-must 3.24, chip-corrob 3.32, chip-block 3.34,
  chip-should 3.38, chip-unmeasurable 3.95, chip-late 4.35, all at 11.52px/600 so the bar
  is 4.5. `chip-ok` at 2.41 is the marker rendering the nine-condition launch checklist.
  `chip-none` at 1.75 is the exact ratio `rbp.css:304-327` boasts of having fixed: the fix
  created a new token and applied it to `td.unattributed`, and the chip kept the old one.
  Dark theme fails on three. The a11y test parametrises three flat hex tokens and no chip.
- **Prose is on the unfixed tokens too.** `.lead-unit` and `.lead-sub`, the sentence
  defining what the lead number counts, measure 3.95 to 4.45 across the `.page-header`
  gradient. `blockquote.caveat`, which `rbp.css:204-206` describes as "the passages that
  cut AGAINST the site", measures 3.95, while the site's own claims render at 6.07. Point
  `rbp.css:19,27,179,210` at the project tokens and add the real backgrounds
  (`#f8f9fa`, `#e9ecef`, `#0f1117`) to the test's sets.
- **768px is the worst width on the site.** `style.css:1573` opens
  `@media (max-width: 768px)` with `table { min-width: 600px }` and
  `th, td { white-space: nowrap }`; `rbp.css:417` opens the card layout at
  `max-width: 767px` and never resets white-space. At 375px `/cves.html` has 926px of
  horizontal page scroll and `/method` 1656px, both WCAG 1.4.10 failures. At exactly 768px
  the card layout is off and nowrap is on: 76% of every row off-screen. Four
  `table.table-sm` tables (the CNA leaderboard, the coverage table, the launch checklist)
  get no `rbp.css` treatment at all; the launch checklist measures 1994px inside a 375px
  viewport with no scroll container. Note `tests/test_a11y.py:212` asserts the literal
  string `@media (max-width: 767px)`, so aligning the breakpoint fails the test written to
  protect mobile.
- **The sort buttons have no focus ring.** `table.rbp th button.sortbtn { all: unset }`
  (`rbp.css:375`) is specificity (0,2,3) against the project's only focus rule at (0,1,1),
  and `all: unset` resets `outline-style` to `none`. Hover is styled; focus is not. The
  commit that bought SC 2.1.1 sold SC 2.4.7.
- **With JS off, `/cves.html` states a count above an empty table.** `<tbody id="body">`
  is literally empty and `grep -c noscript site/*.html` is 0 on all ten pages, while the
  server-rendered caption asserts the row count. The no-JS reader also always gets light
  theme, because there is no `prefers-color-scheme` rule anywhere. Server-render the first
  ~50 rows (the JSON blob is already inline, so this costs build time only) and add the
  noscript.
- **Every per-CNA link is a 404 in the posture being served.** `site.py:964-967` writes
  `cna/<slug>.html` only when launched; `index.html:199`, `cnas.html:44` and
  `cves.html:166` link it unconditionally. The currently-served site carries roughly 228
  dead links, five on the front page and 218 on the primary table, each attached to the
  site's most consequential claim. `_assert_consistent`'s error message says "Every owner
  link would 404. Refusing to publish", and what it computes is set membership in
  `cnas.json`, which passes. The rehearsal cannot find it, because `rehearse_launch` builds
  the launched posture.

Ship one headless-Chrome smoke test in the deploy-gating suite that loads every built
page at 320, 375, 768 and 1280 in both postures and asserts: `documentElement.scrollWidth
<= clientWidth`; every `chip-*` element clears 4.5:1 against its composited background in
both `data-theme` states; inside every `table.rbp`, `count(td[data-label]) == count(td)`;
every page has a non-empty tbody or a noscript; every focusable element has a computed
`outlineStyle !== 'none'` on `:focus-visible`; zero unresolved internal hrefs. That single
test catches six of the design findings and every future instance. Keep the source-string
tests as fast pre-checks and stop treating them as coverage.

### 16. The launch checklist is a claim, not an instrument
**BLOCKER, launch gate. Effort: one day, plus the decisions. Raised by: CISA, MITRE (r2),
Marketing (r2), Consumer, Python, CNA.**

`rbp/launch.py:_DECLARED` hard-codes six of nine conditions as MET. The docstring says the
checklist exists so the commitment is "checkable from outside" and that "the difference is
the whole point of a project whose subject is an unenforced expectation." A condition that
cannot go false is not checkable.

This round establishes that four of the six declared conditions are **false today**:

- **Condition 2** ("no ungated name on any world-readable artefact") is falsified by 121
  live ledger names (item 2), and by the guard it cites, which compares id sets and cannot
  see a name.
- **Condition 4** ("a monitored correction channel") is falsified by item 6: the automatic
  route is unreachable by any non-collaborator. It also renders MET twenty lines below the
  banner saying withhold requests could not be read this run, on runs where the issue read
  fails, from data the run already computes.
- **Condition 5** describes a warrant `/policy` disclaims (item 8).
- **Condition 7** asserts "anything cited before launch stays resolvable afterwards" while
  `prune_snapshots(keep=2)` deletes it in about two days (item 17).

And **condition 1's threshold is unreachable.** `GATE_PCT = 50.0` was set when the gate
figure was `cnas_sighted` over a corpus-derived base. The numerator moved to
`cnas_effective` and the denominator to the pinned 539-CNA roster, and the number was
never re-derived. Live: `cnas_effective` 117, `cnas_sighted` 152, `pct_effective` 21.7%.
Fifty percent of 539 needs 270. Converting **every** currently-sighted CNA to effective
yields 28.2%, so clearing requires ~118 CNAs the feeds see zero published CVEs from, and
the 13 uncovered top-50 names (dell, siemens, SamsungMobile, qualcomm, huawei, twcert,
MediaTek, fortinet, HCL, qnap, juniper, Google_Devices, hpe) are none of them reachable by
distro or OSS-package feeds. `tests/test_site.py:554` asserts only that 434/434 clears,
which is synthetic arithmetic that proves nothing about reachability. Meanwhile 105 roster
CNAs have published nothing in the window and can never be sighted at all.

Changes: derive every condition the run can observe (4 from `summary.suppression.degraded`
plus an end-to-end rehearsal from a permissionless account; 8 from a committed
`notify_last_fired.json` written by the notify job; 2 and 7 from checks over the staged
tree and the retention policy). For conditions that genuinely cannot be derived, require an
explicit `verified_on` date and flip to UNMET when it ages past a stated interval, so "met
once in August" cannot keep reading as "met today". Re-derive the coverage threshold in the
open, in `PLAN.md`, with the date, the old metric, the new metric and the reason, as a
conjunction: a volume-weighted condition that is achievable and already near
(top-50-by-volume at 80%, currently 37 of 50; `pct_volume_attributable` is 90.1%) plus a
roster-share floor set from the reachable ceiling.

**A project whose thesis is that the CVE Program removed its numeric thresholds and
replaced them with private discretion cannot launch by quietly moving its own threshold.**
Do it in public, with the reasoning, or not at all.

### 17. The dated archive is neither stable within its date nor durable past two days
**BLOCKER, launch gate. Effort: half a day. Raised by: CISA, Consumer, Python, MITRE,
CNA, GitHub Actions, Marketing.**

`/data` tells consumers not to cite `rbp.json` and to cite
`/data/archive/<YYYY-MM-DD>/rbp.json` instead. `launch.py:183-187` publishes condition 7 as
MET with "Anything cited before launch stays resolvable afterwards." Three things falsify
it:

- The snapshot directory is keyed on the calendar date, so all four scheduled runs (and,
  at the observed cadence, a dozen push-triggered runs) overwrite it. Today's dated URL
  returns different numbers at 06:00 and 18:00.
- `prune_snapshots(keep=2, keep_monthly=True)` retains `snaps[-2:]` plus
  `by_month[basename[:7]]`, which within the current month **is** today and therefore
  already inside `snaps[-2:]`. Net retention for 30 days out of 31: today and yesterday.
  `git ls-tree -r origin/data` confirms exactly two dated directories.
- `archive.json`'s `url` is document-relative (`site.py:821`), so resolved against
  `/data/archive.json` it yields `/data/data/archive/<date>/rbp.json`, a 404. The HTML link
  works because `/data.html` sits at the root; the machine index does not. The test
  (`tests/test_schema.py:233`) passes only because it resolves against the site root rather
  than the index's own location.
- The archive re-wraps historical rows in **today's** contract: `columns`, `caveats`,
  `counts` keys and `launched` all come from the current build. After the epoch flip every
  pre-launch snapshot republished through that loop will assert `launched: true`.

Fix: freeze the envelope at write time and copy it verbatim rather than regenerating it;
key the archive path per run (`<date>T<hh>Z`), which also dissolves item 1's merge problem;
decouple archive retention from working-snapshot retention (the dated envelopes are ~500 KB
and the whole 49-commit branch is 343 KB packed, so retaining them indefinitely costs
single-digit MB a year); keep every date ever published in `archive.json` with
`"pruned": true` and a reason rather than dropping the entry; make the `url` root-relative
and change the test to resolve against the index's own location. Rewrite condition 7's
`detail` to state the retention that actually exists.

### 18. Named rows already circulate, contradicting a rule the project prints in its own outbound artefact
**BLOCKER, launch gate. Effort: two hours, plus a decision. Raised by: CNA, MITRE (r2),
Python, Consumer, Marketing, CISA.**

`site.py:964-967` and `:841` gate the per-CNA HTML and JSON on `launched`. `rbp.json`,
`rbp.csv` and `cnas.json` are not gated at all and `owner` is a published column;
`cnas.json` is on `publish.ALLOWED_SNAPSHOT` so it also reaches the public data branch.
Live on `origin/data`: 223 named rows across GitHub_M, apple, Chrome, microsoft, suse, plus
the 116 in `resolutions.json` from item 2. `noindex` affects ranking, not availability.

Meanwhile `report.py:384` states the rule as the reason a held-back row is never named, and
`report.py:449` prints, in the document that goes to CNAs: *"CNAs receive a private preview
and correction window before any external circulation."*

Pick one and make it true. The panel's preference, and mine, is to gate `owner` out of
`rbp.json`, `rbp.csv` and `cnas.json` until the notification condition is met (publish
`owner_nameable` and counts only, which loses nothing the site currently uses), and then
flip both together. If that is not acceptable, delete the sentence from `report.py:384` and
`:449` and state on `/method` that named rows circulated before notice, which is defensible
provided the site says so rather than promising the opposite. Do not leave the promise
standing without the mechanism.

Note the timing consequence: the correction window in the proposed condition 10 has to be
measured from when the names first became publicly fetchable, which was weeks ago, not from
when the export is sent.

---

## Part 2: what should join the 50% coverage gate

The current gate is one condition on one number, and this review shows that number is both
unreachable and not the thing anyone should be waiting for. Proposed additions, each
derived from a committed artefact rather than declared:

**Condition 10: the named CNAs were told.** For every CNA that will appear on `/cnas` at
promotion, a per-CNA export was sent and a stated correction window has elapsed, recorded
as `{cna, root, sent_on, window_days}` in a committed file the condition reads. This is
`PLAN.md` Phase 6's "makes 'you never told us' unavailable", and it is the only substantive
commitment in the project with no gate, no artefact and no code behind it. Address the note
to each CNA's **Root** as well as the CNA, because RBP Policy v2.0.0 routes notification
through the Root, and note that the pinned roster currently discards that relationship
(item 30). Five business days is not a correction window for an organisation that has to
route this through legal and product security.

**Condition 11: the accuracy claim is measured, not asserted.** Production graded `n >=
MIN_GRADED` before any name is promoted, using the prediction-keyed stratification from
item 9, and published with `censored_open` beside it. Live `graded` is 1 against 228
outstanding. Condition 6 is about *presenting* one stratified figure; that is not the same
as *having* a measurement, and the two have been treated as the same thing.

**Condition 12: minimum evidence per named CNA.** No CNA gets a `/cnas` row or an aggregate
page below a floor of corroborated rows. Today microsoft and suse each hold exactly one
inferred row, single-origin, `disclosure_order: unmeasurable`, with production accuracy
unmeasured. A dedicated page asserting a named company is delinquent on one inferred row is
the least defensible artefact this site produces.

**Condition 13: the sector figure is published.** `cnas_effective_ics` computed against a
committed critical-infrastructure CNA list and published as a fourth row in the coverage
table, with the plain statement, while it remains true, that **no critical-infrastructure
CNA is measurable here**. The panel split on whether a non-zero ICS floor should *block*;
the majority position is that a gate which cannot clear stops being a control, so publish
the figure as a hard requirement and take the floor as a separate, argued decision.

**Condition 14 (chair): the sunset criteria are written down.** The footer line
*"Unredact owning_cna and publish an RBP metric, and this site will point at yours
instead"* is the best sentence on the site and the only claim it makes with no stated
standard attached. Publish on `/policy`: what fields an official RBP metric would need
(count, definition, cadence, whether `owning_cna` is unredacted), what this site does on
the day it appears (front page points at it, tracker stops updating, archive stays
resolvable and says why it stopped), and who decides. Four bullets. An offer with no
criteria cannot be accepted, which is exactly how a Program representative will read it.

**Re-derive condition 1** per item 16, and record the derivation.

---

## Part 3: wanted, not blocking

Ranked within the section by consequence over effort.

**19. Rows the site publishes carry a rule number it says it cannot determine.**
HIGH. Raised by CNA, MITRE, CISA, Consumer, Marketing, Python. `rule` is `"4.5.1.6"` and
`rule_strength` is `"SHOULD"` on 522 of 522 rows while `rule_certainty` is `unmeasurable`
on 521. 4.5.1.6's text presumes a third party disclosed, which is the fact the site says it
cannot observe. The `/cves` Rule filter offers only `any`, MUST and SHOULD, so a reader
cannot select the honest bucket, and selecting SHOULD returns the whole site. Render
unmeasurable rows without a rule number ("rule undetermined"), add the third filter option,
and in the export set `rule: null` when `rule_certainty == "unmeasurable"` rather than
documenting the dependency, because documentation does not reach a filter. This is a
version bump.

**20. Retention and withholding are enforced against the working tree of a branch whose
history is public and permanent.** HIGH. Raised by GitHub Actions, Consumer, CNA, MITRE,
CISA, Marketing. `prune_snapshots`'s docstring says it exists because "no correction on the
site could reach the history"; `_scrub`'s says "a withhold that only applies going forward
is not a withhold". The transport is `git add -A` on an append-only branch, and
`git show <sha>~1:snapshots/2026-08-20/backlog.json` recovers 542 rows with 281 names.
`PLAN.md` R8 specified a compacted orphan branch and it was never built.
`docs/github-support-request.md` records this already forcing one history rewrite, with the
correct conclusion ("complete against discovery and incomplete against replay") never
applied to the branch design. Correct the size argument first: the whole branch is 343 KB
packed, roughly 7 KB per commit, so this is a privacy finding and not a quota finding.
**Sequencing matters and the panel was firm about it:** the branch history is currently the
only recovery path for a silently reset ledger and the only record of missed ticks, so land
atomic writes, the monotonic `graded` canary, the run ledger and a private encrypted backup
**first**, verify the backup restores, then re-root. Either way, stop `prune_snapshots`'
docstring claiming a property the push does not provide.

**21. Every artefact on the data branch is uncontracted, and it is the easiest one to
fetch.** HIGH. Raised by Consumer (r3). Eleven files, `grep -c schema_version` returns 0 on
all of them, `snapshots/<date>/backlog.json` is a bare 522-element array with no envelope
and none of the six caveats, and the branch README reads like documentation. `schema.py:38`
states the project's own rule that a consumer finding no `schema_version` should refuse the
artefact; the project publishes eleven of them, at stable raw.githubusercontent URLs that
need no HTML and no JavaScript. Decide what the branch is and make the artefact say so:
either state in the first line of its README that it is machine state and not an interface,
or contract it (write snapshots through `schema.envelope`, stamp version, run_id and
build_rev, list the paths on `/data`). Add `resolutions.json` to `schema.FIELDS` or stop
publishing it.

**22. The published `counts` block is wrong in three ways.** HIGH. Raised by Consumer,
MITRE, CNA. `counts.named` holds `named_cnas` (5) in a block whose other members are row
counts, while 223 rows carry an owner: a consumer computing `named/total` gets 1.0% against
a true 42.7%, a factor of 45, in the versioned envelope `/data` calls the contract. The
sidecar envelopes are worse: `held-back.json` wraps 167 rows and declares `total: 506`, and
`resolved.json` wraps **zero** rows and declares the same, because
`schema.envelope` builds `counts` from `summary` alone and `site.py:742-750` passes the
same summary object to all three calls. Rename to `named_cnas`, add `named_rows`, drop
`counts` entirely for `kind != "backlog"` and always emit `row_count == len(rows)`, and
document every `counts` key on `/data`, which today documents row columns only. Version
bump.

**23. Two declared columns are produced by no code, and nothing checks the key set.**
HIGH. Raised by Consumer, CNA, MITRE, Marketing, Python. `own_feed_date` and
`earliest_other_date` appear only in `rbp/schema.py` and are absent from 522 of 522 JSON
rows and empty in every CSV row, while `schema.py:111-112` calls them "the entire input to
the rule call" and says the call is therefore checkable without parsing nested JSON. So the
site documents an audit path for its central claim and ships nothing behind it. Meanwhile
three keys are published and undeclared (`dates`, `disclosure_order`, `suppressed`), and
`disclosure_order` is strictly more informative than the documented `rule_certainty` it
feeds. Either populate the two from `row["dates"]` at the point the rule is decided, or
remove them and the claim. Add a write-time invariant asserting the key set of every
published row equals `set(schema.COLUMNS)` in **both directions**;
`report._publishable` is currently a denylist, which is why nothing ever compares a row to
the contract. Rewrite `tests/test_schema.py:78-83` to assert non-emptiness on the built
artefact.

**24. The licence statement contradicts the repository, and the republished advisory text
has no licence at all.** HIGH. Raised by Consumer, CNA, MITRE, CISA, Marketing, GitHub
Actions. `templates/data.html:165` says MIT; `LICENSE` is Apache-2.0; there is no README to
break the tie and `grep -rn -i spdx .` returns nothing. The substantive half is that
`description` and `refs` are upstream advisory text republished verbatim, up to 345
characters, from GHSA, OSV, distro trackers and CSAF documents with differing terms, and no
field, envelope key or page states the terms under which it may be redistributed. A
vendor's ingestion review stops here. Fix the SPDX id, split the card into a code licence
and a data licence, name the data licence, and add a `sources`-to-attribution map to the
envelope and to `rbp.csv.meta.json`. Add a test asserting the string on `/data` matches
`LICENSE`.

**25. Two claims about the site the site cannot keep: robots and mirrors.** HIGH. Raised by
CISA (r3). `site.py:901` writes robots.txt only when `not launched`, so the launched
artefact ships **no robots.txt at all** and the full named row set, the dated archives,
every per-CNA page and `/changes`'s raw ID dump become crawlable and archivable on day one.
Write a launched robots.txt too, at minimum `Disallow: /data/` and `Disallow:
/changes.html`, which keeps the machine route fully available to anyone who reads `/data`
while stopping the bulk named rows being mirrored by default. Separately, state the honest
scope of a withhold everywhere the guarantee appears: withheld from this site, its data
files and its data branch on the next build; third-party caches, mirrors and archives are
outside this project's reach. The site already makes exactly this argument twice about
someone else's document (the withdrawn v1.0 PDF) and has never applied it to its own rows.

**26. Both ledgers reset to empty on any load error and write that back over the durable
file.** HIGH. Raised by Python, GitHub Actions, Consumer, CNA, MITRE, CISA, Marketing.
`Grader.__init__` (`inference.py:352-359`) and `ResolutionLedger` (`clock.py:334-342`)
swallow every exception into empty state; `save()` then writes it over
`data/precision.json`; `stage` copies it to the branch; the next run's `Seed ledger` step
copies it back. The reset is self-perpetuating and the live value is `graded: 1`, so it
would be indistinguishable from normal. `deploy.yml:160-163` explains that the ledger was
moved onto a durable branch *specifically* to stop the accuracy figure silently resetting.
Distinguish "file absent" from "file present but unreadable or wrong shape" and raise on the
second (note `self.state.update(loaded)` also accepts `{}`); add the atomic writes from item
1; and put the monotonicity canary in `publish check` rather than `cmd_run`, since the
workflow already prints the incoming counts at `deploy.yml:198` and throws them away.

**27. The corpus cache and the corpus canary.** MEDIUM. Raised by Python, GitHub Actions.
Three separate items with a shared theme:
(a) the cache key hashes the whole of `rbp/cvelist.py`, so a docstring edit invalidates a
6.6 MB restore and forces the 583 MB cold path (commit `5e9d072`, a pure prose commit, would
have done exactly that); key it on `SCHEMA`, which the module already versions for precisely
this purpose. (b) `assert_corpus_current` keys on `max(date_published)` with a length filter
rather than a validity filter, so one future-dated upstream record disables the only
frozen-corpus detector permanently and silently, and one 10-character non-ISO value raises an
unhandled `ValueError` inside the pipeline; use a small quantile of dates at or before today,
wrapped in a try. (c) `apply_deltas` does unconditional last-write-wins, so one malformed
delta downgrades a PUBLISHED row to state `""` or blanks its assigner for up to ten days, and
a blanked assigner makes `Grader.grade` record `unattributed-on-publish`, which closes the
prediction without scoring it. Make the upsert monotone and refuse the three regressions.
Also assert `list(corpus.columns) == list(COLUMNS)` at the top of `apply_deltas`: the delta
DataFrame is built positionally.

**28. The build job holds contents/pages/id-token write while parsing ten untrusted feeds.**
HIGH. Raised by GitHub Actions, Python. Both secrets are injected into `Run pipeline`
(`deploy.yml:238,243`), and both checkouts leave a write-scoped token in `.git/config`
because `persist-credentials` defaults to true. `upload-pages-artifact` needs neither
`pages: write` nor `id-token: write`; `deploy-pages` already carries its own. Delete those
two grants from `build` today, independently of the larger job split, because `id-token:
write` is the only grant that reaches outside the repository. Set `persist-credentials:
false` on both checkouts and give the push an explicit token in its own step. Then split the
job: `build` at `contents: read, issues: read` uploading `.state` as an internal artifact,
and a `persist` job with `contents: write`. That split also fixes item 29 and the
state-advances-on-build problem. Note the shortest path to the token is not the feed parsers
but `pip install -r requirements.txt`: the ranges are unpinned and unhashed, and import-time
code in any transitive dependency runs with the token in `.git/config`. Use a hash-pinned
lock with `--require-hashes`. Pin every action to a commit SHA and add
`.github/dependabot.yml` and `CODEOWNERS` on `.github/workflows/**`, none of which exist.

**29. A failed `git push` at the last step of `build` cancels the publication.** HIGH.
Raised by GitHub Actions. The comment at `deploy.yml:268-270` states the opposite intent.
The push has no retry, no rebase and no `--force-with-lease`, so any divergence on `data`
wedges every run until a human intervenes, and the branch has already diverged once. Harden
the push **first and unconditionally** (bounded retry with `git fetch origin data && git
rebase origin/data`, `--force-with-lease=data:$(git rev-parse origin/data)`), because the
workflow-level `concurrency: group: pages` is currently the only thing serialising it, and
two other proposed fixes would remove that without replacing it. Note `.state` is checked
out at default `fetch-depth: 1`, so a rebase across the shallow boundary fails in exactly
the divergence case the retry exists to heal; set `fetch-depth: 0` (the branch is 343 KB) or
re-stage rather than rebase. Then separate the locks: `concurrency: group: pages` on the
`deploy` job only, `group: rbp-data` on `persist`, and a workflow-level group keyed on
`github.event_name` so a push burst cannot evict a scheduled tick. Also: a failed push loses
the **scrub**, because `stage` has already mutated `.state` in place.

**30. Documentation commits republish the live count.** MEDIUM. Raised by GitHub Actions,
Consumer, MITRE, CISA, Marketing. `on: push: branches: [main]` has no `paths-ignore`, and
`origin/data` shows 49 state commits in 51 hours against a schedule accounting for 8, on a
repo whose recent history is dominated by `PLAN.md` and `REVIEW.md`. So roughly 80% of all
pipeline executions are triggered by prose, each one a full fetch of ten third-party feeds
plus the OSV bulk archives, a public commit naming CNAs, and a `generated_at` bump that
presents to every polling consumer as a new dataset version. Prefer the positive `paths:`
allowlist over `paths-ignore`, so a new top-level file defaults to not triggering.

**31. `/changes` has an unexplained bucket the site can already explain.** HIGH. Raised by
MITRE, CNA, CISA, Consumer, Marketing, Design. `no_longer_listed` is everything unaccounted
for, and because GHSA reads a fixed 40 pages sorted by published desc, a GHSA-sourced row
necessarily ages out of the feed while remaining RESERVED and public. Those ids then render
as a comma-joined dump beside a tile labelled "Published, verified against the CVE List".
Re-query the reservation oracle for `gone - resolved` (a handful of requests against a
25,000/min unauthenticated limit, using the client `classify.py` already has) and split into
three: PUBLISHED, REJECTED, and "still RESERVED, no longer referenced by any feed this site
reads". The third is a feed-coverage measurement, must be labelled as one, and is the only
direct estimate the project can produce of what its own window costs the count. Do the query
in `cmd_run` and write it to the snapshot, so `site.build` stays offline.

**32. `refs` is the audit field and has no grammar.** MEDIUM. Raised by Consumer (r3).
Documented in eleven words. The token after `feed:` is a GHSA id for ghsa, a CVE ID for
alas/redhat/ubuntu, a bare package name for debian/alpine, and ecosystem-plus-package for
osv, which is not fixed-arity within itself (Maven coordinates embed a colon). No consumer
can parse it with a fixed rule. Publish it as an array of objects in JSON, keep the packed
string in the CSV with its grammar stated in `rbp.csv.meta.json`, add a `refs_truncated`
boolean, and document the closed `sources` vocabulary. Version bump.

**33. The CSV encodes booleans as Python repr.** MEDIUM. Raised by Consumer. `clock_known`
and `past_expectation` are the strings `True` on 522 of 522 rows; `single_origin` splits
`{'True': 350, 'False': 172}`. In Python, `bool("False")` is `True`, so the most common way
a consumer will read this file inverts the meaning of the clock booleans on every row. The
sidecar `rbp.csv.meta.json` republishes the **JSON's** type strings beside the CSV. Write
through an explicit serialiser, declare the encoding, and add a round-trip test asserting
each boolean column parses to the same value as the corresponding JSON row.

**34. The independence map is unpublished, untested, and fails open.** HIGH. Raised by
Consumer, CNA, CISA, MITRE. `_indep` does `_ORIGIN.get(s, s)`, so any feed name absent from
the map counts as a **new independent origin**, and `corroborated` (the headline) is defined
entirely by that map, which appears in no template, no envelope and no test. All eleven
current adapters happen to be covered, so it is armed rather than firing, and the thing about
to arm it is the CSAF promotion, where the map is wrong in the *other* direction: every CSAF
provider flattens to one token, so Siemens and Cisco corroborating one row yields
`indep_sources: 1`. Publish the map as an `origins` object in the envelope, make `_indep`
raise on an unmapped name, key CSAF on the provider, and add the CI reachability assertion.

**35. Nine adapters, no ICS feed, and a monthly cadence that does not exist.** HIGH. Raised
by CISA, MITRE, CNA, Consumer, Marketing, Python, GitHub Actions. The only schedule is
`0 */6` passing `--profile weekly`, which excludes `csaf` and `msrc`, while `cli.py:22-23`
and the `--profile` help both assert a "monthly cadence" that exists in no cron. Zero ICS/OT
CNAs appear in `coverage.sightings`; siemens is in `top_missed`; CISA's own CSAF
provider-metadata URL is configured at `feeds.py:601` and never called. `FEEDS.md:212-239`
already measured the fix (+12 CNAs, 8 of them ICS/OT, 142 seconds). Delete the false cadence
claims. **Order matters and the panel was specific:** land the bulk-reporter matcher (item 7),
the CSAF provider identity and `advisory_url` branch (item 36), and the adapter
instrumentation (item 14) *before* promoting the profile, or the first ICS rows arrive as
single-origin, uncheckable, coordinator-named claims about the most consequential population
on the site. Prefer a second `schedule:` entry selecting `deep` from `github.event.schedule`
over changing the weekly profile, so the slowest adapters do not enter every six-hourly tick
and every docs commit.

**36. CSAF rows would link to a page that disproves them.** HIGH. Raised by CNA, MITRE,
CISA, Consumer, Marketing, Python. `report._u` has branches for nine sources and none for
`csaf`, so every CSAF row falls through to `https://www.cve.org/CVERecord?id=<id>`, which for
a RESERVED ID renders nothing. `feeds.py:764` already captures publisher and tracking id in
`source_ref` and the templates render `sources` instead. Carry the entry `href` through (it
is bound at `feeds.py:757` and discarded), emit `source` as `csaf:<provider>`, and add a
guard refusing any row whose `advisory_url` is the cve.org fallback. Widen it: 36 live rows
carry `osv.dev/list?q=` search URLs and 32 carry tracker pages, while `schema.FIELDS` calls
the field "a place to look the ID up. Always populated." Either rename it or split it into
`advisory_url` and `lookup_url`.

**37. Neither `/cna` nor `/cnas` shows independent sources, and "corroborated" means two
different things.** BLOCKER by panel vote, listed here because the fix is small and self
contained. Raised by CNA, Design, Consumer, MITRE, CISA, Marketing. Axis 1 is source
corroboration (`indep_sources`, `single_origin`), which defines the headline. Axis 2 is
`owner_tier == "block-corroborated"`, meaning block inference and the product map agreed on
the same single row. `cna.html:143-145` renders axis 2 as a chip reading literally
"corroborated" under a column headed "Confidence", and neither CNA page carries
`indep_sources` at all. Seven named rows show that chip while resting on one origin, beside
a raw `sources` string reading `ghsa,osv`, where OSV is a GHSA mirror `_ORIGIN` correctly
collapses everywhere except on that page. Rename the tier value itself (not just the chip)
to `block-plus-product-map`, add an independent-sources column to both CNA pages, add an "of
which corroborated" column beside Outstanding on `/cnas`, and add a copy test pinning the
word to one axis. Note 190 of 223 named rows are single-origin.

**38. The named row cannot be recomputed by the party it names.** HIGH. Raised by CNA,
Design, MITRE, CISA, Consumer, Marketing. `cna.html:14-19` tells the reader the method
exactly and the row never says which three neighbours on each side produced the name.
`BlockInferencer._neighbours` and `_block_width` both compute the ids and both discard them.
Every one of those neighbours is a PUBLISHED record whose assigner is already public in the
CVE List, so publishing `owner_evidence` (the k ids each side plus the agreement width)
discloses nothing and converts every named row from an assertion into a check anyone can run
in a minute. This is the single change most likely to turn a legal response into an email.
Render it as an expandable cell, which is also the component item 39 needs. Address the
dual-use question on `/policy` head on rather than leaving it open: the capability requires
only the public CVE List, the redaction is already ~62% defeated by public data, and that is
an argument **for** the narrow unblinding ask, not against it.

**39. The primary table can never fit its container, and the columns that fall off are the
evidence.** HIGH. Raised by Design, CNA, Consumer, MITRE, CISA. The 1200px container cap
means `.tablewrap` is 1152px wide at every viewport at or above 1200, while the table's
min-content width is 1681px. Measured at 1280, 1440 and 2560 identically: Sources is 74% cut
and Advisory summary is 100% off-screen with no visual cue that it exists. The columns that
survive are CVE ID, days public, rule and inferred owner. So the default desktop rendering
shows the claim and hides the support, on a site whose entire defence is that every row is
already public and checkable. Make Advisory summary a per-row expandable rather than a
permanent column (which also reduces the republication surface item 24 is about and drops
`td.desc { min-width: 22rem }`, the declaration forcing the geometry), and give `/cves` and
`/cna` a wider container.

**40. The caveats are unreachable on mobile and the caption survives one wheel notch.**
HIGH. Raised by Design, CNA, MITRE, CISA, Marketing, Consumer. Correction from
cross-examination: the desktop claim in the original filing was wrong (the caveat block
enters view at 333px of page scroll, not 40,848px of inner scroll). The mobile half stands
and is severe: at 375x812 the document is 222,469px and the `.caveat` block sits at y
221,174, which is 272 screens down. And the sharper defect the original missed is that the
`<caption>`, deliberately placed inside the table so the hedge "travels with the table into a
copy, a print or a screen reader", is 73px tall inside a bounded scrollport and is entirely
out of view at 120px of inner scroll, that is, one wheel notch, while all 506 rows remain.
Move the three qualifying caveats **above** the table in DOM and reading order; move the
caption out of `.tablewrap` into a paragraph linked with `aria-describedby`; make `.filters`
sticky (note `--header-h` is defined nowhere, so the obvious fix is a silent no-op until the
token is added; the real header is 65px and `--rbp-thead-h` is a different thing used exactly
once); and paginate or virtualise.

**41. Six of eight `.rbp` tables have no `data-label`, so mobile renders unlabelled numbers
next to company names.** HIGH. Raised by Design, CNA, MITRE, CISA, Consumer, Marketing.
`rbp.css:424` hides `thead` below the breakpoint and supplies the replacement label only
from `td[data-label]`. Counts inside `table.rbp`: cnas 0 of 7, cna 0 of 11, changes 0 of 17,
data 5 of 21, method 0 of 2; only cves and backlog-at-launch are complete. Rendered at 375px
the first `/cnas` card reads `GitHub_M / 210 / 126d / 42d / 0 / 10,411 / no data yet` with
every label null. Two of those are day counts, two are row counts, and the `0` is Candidate
MUST. Add the attributes, and add a test asserting per table that `count(data-label) ==
count(td)` **and** that each value equals the corresponding `<th>` text, since count equality
alone survives a column reorder.

**42. Print blanks seven of eight column headers and drops the footer.** HIGH. Raised by
Design, CNA, MITRE, CISA, Marketing. `style.css:2145` hides a bare `button` with
`display: none !important`, and the accessibility fix moved every sortable column's text
inside `button.sortbtn`; `rbp.css`'s print block never re-shows it. `.footer` is hidden by
the same rule, and it is the only carrier of the snapshot date, the build timestamp, the four
source links, the withhold route, `rbp@rogolabs.net`, and the site's best sentence. Meanwhile
`.filters` still prints a live search box and three selects. A printed page is the artefact a
CNA circulates internally and attaches to an escalation; today it is an undated table of
named organisations with blank headers, no provenance and no correction path. Restore the
button and the footer, hide `.filters` and `#exports`, add `::after` labels for the five
chips that lack them, and add a print test: collect the selectors `style.css`'s print block
hides and assert none matches an element carrying visible text.

**43. The mobile card layout strips table semantics and the live region fires per
keystroke.** MEDIUM. Raised by Design. `display: block` on table/tbody/tr/td drops the
implicit roles in every engine and no ARIA is supplied. Separately `#count` is
`role="status" aria-live="polite"` and is rewritten inside `render()` on every `input` event,
so typing "openssl" queues seven polite announcements over the user's own typing, alongside
seven `history.replaceState` calls (which WebKit throttles at 100 per 30 seconds). Supply the
roles, debounce at ~150ms, and move both the count write and `replaceState` onto the debounced
tail. Correction: the original's 46.1ms render measurement did not reproduce (6.5ms); debounce
for the live region, not for the performance.

**44. No `og:image`, no `twitter:card`, and the title disagrees with the lead count.**
HIGH. Raised by Design, Marketing, MITRE, Consumer, CNA. `<title>` renders `summary.total`
(522), `.lead-count` renders `corroborated` (172), `og:description` renders 172, `og:title`
and `meta description` carry no number. In a Slack or Teams preview the tab title and the
description sit adjacent, so the mismatch is the most-seen thing about the site rather than
the least. And with no card of our own, the image that circulates with any coverage is
whatever someone screenshots, which today is the leaderboard from item 11. Compute one
`headline` value in `rbp/site.py` and render it into title, og:title, og:description, meta
description, `.lead-count` and a build-time card; keep the total as the explicit second
figure; gate the pre-launch card to carry no number, matching the existing `og:description`
branch. Add a test asserting the integer in `<title>` equals the integer in `.lead-count`
equals the integer in `og:description` on every built page in both postures.

**45. The About page ships the holding page verbatim.** HIGH. Raised by MITRE, Marketing,
Design, Consumer. `site.py:947` copies `placeholder.html` unconditionally, and
`base.html:69` links it in the nav as "About" only when launched. So the launched nav points
at a page carrying `noindex, nofollow`, `og:description` = "not yet published", a canonical
and `og:url` pointing at the **site root**, body copy in future tense, and a footer reading
"rbptracker.org, soon". That page carries the glossary provenance, the full 4.5.1.7
quotation and the narrow ask, which is to say it is the page a Board member or a journalist
gets sent, and it is de-indexed and canonicalised away to the front page. It also does not
extend `base.html`: no nav, no theme continuity, its own palette, no way back into the site.
Make it a Jinja template extending `base.html`, and add a copy test asserting no page in the
launched nav contains "being built", "not yet published" or "soon".

**46. The launch-day headline is zero, and nobody has decided that on purpose.** HIGH.
Raised by Marketing, CISA, MITRE, CNA, Consumer, Design. `cli.py:96` refuses any epoch later
than `today - min_age_days`, the reportable arrival rate is roughly 5-6 a day, and the lead
renders the corroborated subset, so a clean-slate epoch produces a single-digit or zero
headline at 104px on announcement day, with `backlog-at-launch.html` holding all 522 rows
including the 519-day-old one. `index.html:491-496` already renders the empty state. The
epoch is a dial with a demonstrated setting, not a cliff: the recorded rehearsal used epoch
2026-08-01 and counted 80. Decide the headline number first and derive the epoch from it
(`launch - 90d` retains ~495 of 522 and preserves the advisory-date stability property in
full), or keep the clean slate and lead the announcement with `/backlog-at-launch` while
relabelling the headline explicitly as a since-launch flow. Rehearse the exact value through
`dry_run` and **look at the rendered front page** at 1280 and 375 before the flip, because no
test catches this. Note the epoch also drives item 6's withhold ceiling, so choose it with
both consequences on the table, and note that publishing the pre-epoch backlog with the
`owner` column intact defeats the protection the epoch was meant to provide.

**47. The site never says who publishes it or what it gets out of it.** HIGH. Raised by
Marketing (r3). Zero hits across `templates/` and `placeholder.html` for "not affiliated",
"conflict of interest", "funded", "independent of" or "commercial". The only
self-identification is "Built by RogoLabs" in a footer and a mailto. The site publishes named
compliance claims about specific companies and offers those companies a correction channel
run by an unnamed "a person". The vacuum does not stay empty; the cheapest fill is "an
employee of a commercial security vendor is publishing a compliance scoreboard on other
vendors' CNAs", it is available for the cost of one search, and it attaches to Jerry
personally rather than to the method. Add a linked "Who publishes this" block on `/method`
and `/about-this-count`: who runs it by name, that it is an independent personal project
rather than a product, that it takes no funding from and has no commercial relationship with
any listed CNA, and what would end it (which is Condition 14). Name a human in the correction
channel copy. Ship it **before** the launch commit, not in it, because a disclosure that
appears in the launch commit reads as prepared for the launch.

**48. The "not a CNA scorecard" defence and the sibling CNA scorecard.** HIGH. Raised by
Marketing (r3). `index.html` asserts in bold "This is a Program-level transparency
measurement, not a CNA scorecard", and that sentence is load-bearing for the per-CNA pages
and for `PLAN.md` 2a. The same author operates cnascorecard.org, and the footer links
cve.icu, so the connection is one search from either. Portfolio context defeats the
disclaimer without disputing a single number, and the omission cuts both ways: not linking it
looks like concealment once found, linking it without explanation confirms the framing.
Pre-empt it in one paragraph that draws the distinction the project actually holds
(cnascorecard.org measures CNA performance by design; this measures a Program-level state
whose distribution across CNAs is an artefact of block width and feed coverage, which is why
there is no rate column). Take the leaderboard off the front page first, because the
paragraph is not survivable while the table is still there.

**49. The count rises with a CNA's advisory transparency and can be lowered by publishing
less.** HIGH. Raised by MITRE (r3). Membership requires a public reference, so a row exists
only where an advisory or tracker entry precedes the CVE record. A CNA that publishes nothing
until its record exists contributes structurally zero rows regardless of how long it holds
IDs. `grep` for "incentiv", "perverse", "gaming" across `templates/`, `rbp/` and `PLAN.md`
returns nothing. This is the CVE Board's first substantive response and it is correct as
stated. Say it plainly on `/` and `/method`, and use it as the bridge to the ask rather than
burying it as a caveat: the incentive inverts only for an outside measurement, which is
precisely why the Program publishing the number itself is the fix.

**50. There is no corrections record, and the only error artefact the site publishes names
the wronged party.** MEDIUM. Raised by Marketing, CNA, MITRE, CISA, Consumer. `/method`
publishes a permanent CVE-to-wrong-CNA misses table from `grader.misses`, retained
indefinitely on the public branch, while `PLAN.md` 8c de-identified the two known
misattributions on the express reasoning that naming them "would republish the pairing being
retracted, in the document that records it as false". Drop the `predicted` column (and per
item 9, the `actual` column too, since a transfer names the compliant party); null
`predicted` in the ledger once a verdict is folded into the score; keep count, composition,
tier and stratum, which is what makes the precision figure honest. Then add a `/corrections`
page linked from the nav and from every `/cna` page, and **ship it populated on day one**
with the two PLAN 8c misattributions and the retracted buffer claim already on it. A
corrections page that appears after the first dispute reads as damage control and is worth
less than nothing.

**51. The description field is a 400-character passthrough with no content policy.**
MEDIUM. Raised by CISA (r3). Every adapter truncates upstream text at 400 and publishes it
verbatim; there is no filter of any kind. The corpus is clean today (median 79, max 345, one
false-positive regex hit), but the tail already carries mechanism rather than a title: a live
row reads *"a 16-bit integer wrap: when sizeof(*pe) + lv->name_size exceeds UINT16_MAX, the
pe->size field (uint16_t) wraps, leading to memory corruption"*, on a RESERVED ID with no
published record. Nothing decided to publish that; the truncation constant did. `PLAN.md`
already records four rows that shipped Debian tracker annotations. Cut the cap to a title
length (~120) at a word boundary, add a build-time **refusal** on mechanism markers (commit
SHA, "Introduced with", patch URLs, "proof of concept"), report the redaction count on
`/method`, and land it before CSAF enters the profile, because ICS advisory titles routinely
carry the primitive and the interface. Lift `report.py:455-456`'s no-severity sentence, which
is well drafted and currently exists only in an artefact the public never sees, onto `/` and
`/method`.

**52. There is no versioned URL and no deprecation path.** MEDIUM. Raised by Consumer.
`/data` promises "pinning a major version keeps working" and there is nothing to pin: one
integer, one unversioned URL, no parallel serving, and a two-day archive as the only
fallback. This review has queued at least five changes that are bumps under the site's own
stated policy. On a static Pages site `/data/v1/` is a copy, not infrastructure. Land it
before the first bump; after it, the promise is already broken and cannot be un-broken. Add a
`deprecations` array to the envelope so a consumer learns about a break by parsing rather
than by breaking.

**53. There is no change feed and two clocks that disagree about what a build is.**
HIGH. Raised by Consumer, MITRE, Marketing, CISA. No RSS, no Atom, no `changes.json`;
`/changes` tells consumers to compute the diff themselves against a snapshot retention
deletes in two days. `generated_at` moves on every build even when no row changed (and item
30 means that is a dozen times a day), while `snapshot_date` is stable across three of every
four builds, so neither is a usable change key and there is no run id or content hash.
Publish `data/changes.json` from the `_changes` computation that already runs, tagged by
cause (`new-observation`, `feed-added`, `resolved-published`, `resolved-rejected`) since an
untagged delta is dangerous to alert on, plus an Atom rendering. Add `run_id` and a
`rows_digest`. Consider a per-CNA feed at `/cna/<slug>.atom`, which reframes the deliverable
from "let consumers diff" to "let the named party self-monitor" and is a strong line in the
Phase 6 email.

**54. Two roster tests can freeze the publication; the policy-currency tests never run on
it.** HIGH. Raised by GitHub Actions, MITRE, CISA, Marketing, Python. `build: needs: test`
gates a four-times-daily unattended publication on the default suite, which contains
`test_the_pinned_roster_is_not_stale` (hard-fails on **2026-12-20** by arithmetic, after
which Pages serves the last artefact indefinitely and the banner that would say so cannot
fire) and a **live network fetch** of `raw.githubusercontent.com` whose failure stops the
deploy. Meanwhile `RBP_LIVE_TESTS` appears once, in `ci.yml`, and never in `deploy.yml`, so
the tests verifying the site still quotes current policy text and section numbers never run
on the thing that publishes. The guards are inverted: the harmless one blocks and the harmful
one does not. Move both roster tests out of the gating suite, surface staleness as a `/method`
banner plus the issue channel, add a `schedule:` trigger to `ci.yml` so they still run
unattended somewhere a red check costs a notification rather than a publication, and add a
non-blocking policy-currency check to every scheduled build.

**55. Rows carried forward from a failed oracle lookup are published unmarked.** MEDIUM.
Raised by MITRE (r3). This is the one case where the site states an ID is still reserved and
unpublished **without having checked this run**, and it is published with no marker, no count
and no degraded flag; the count reaches only the run log. During an endpoint brownout the
affected fraction is unbounded while the run reports healthy. Add
`oracle["carried_forward"]` to `degraded_reasons` as a distinct reason, publish the count,
land `state_verified_this_run` on the published row so the rows are filterable, and cap it:
refuse to publish a row carried forward for more than N consecutive runs, past which the
reservation state is being asserted from a chain of snapshots rather than from the oracle.

**56. Three unhardened network operations and one very large one.** MEDIUM. Raised by
Python, GitHub Actions. `cvelist._releases` (`urlopen`), `download_baseline`
(`urlretrieve`, 583 MB, no ceiling, no redirect revalidation, no IP pinning) and
`_delta_rows` (`blob = r.read()`, unbounded into memory) bypass the hardened opener entirely,
as does `classify.py:182`, which is the highest-volume call in the pipeline (~700 requests
per run under a 24-worker pool). Move the opener to `rbp/net.py` behind a single
`_open(url, timeout)` that does the `_url_ok` check itself, and route all four through it.
While there: the "hardened" opener is not. `build_opener` starts from the defaults and only
replaces classes the caller subclasses, so `_OPENER.handle_open` is
`['data','file','ftp','http','https','unknown']` and `_OPENER.open('file:///...')` returns
file contents, three lines below a comment asserting those schemes "cannot be opened at all".
Build from `OpenerDirector` with an explicit handler list and pin it with a three-line test.
Ensure `_SafeRedirect` strips `Authorization` on a host change before moving the
token-carrying `_releases` call onto a redirect-following path. Also: `_url_ok` tests
`is_private` rather than `is_global`, so 100.64.0.0/10 passes; use `not ip.is_global`, but
filter per address rather than rejecting the whole host, since `is_global` is stricter than
the current disjunction for 6to4, Teredo and documentation ranges. And thread `force` into
`download_baseline` so `--reindex` can actually re-fetch a corrupt baseline, which today it
cannot, making the documented recovery instruction false on a developer machine.

**57. `run_coverage` describes a different population from the table above it.** HIGH.
Raised by Python, MITRE, CNA, CISA, Consumer, Marketing. `inference.py:597-598` computes it
over the whole backlog including within-buffer, undated and pre-epoch rows;
`index.html:93` renders it as a claim about "these rows". The gap is one point today only
because `epoch_excluded` is 0, and the recorded rehearsal (442 held back, 80 counted) is the
launch-day case where the same sentence would describe a population 6.5x the table it sits
above, in the sentence that carries the abstention caveat. `apply_to_backlog` already
receives `record_for`; restrict the count to it, publish both figures under distinct names,
and print both in the run log.

**58. The suppression key cannot be rotated without silently republishing every withheld
row.** HIGH. Raised by GitHub Actions, CNA, CISA. A **missing** key with a non-empty list
fails the build loudly by design; a **wrong** key fails silently, because `_committed_hit`
simply stops matching and nothing counts committed digests that matched nothing this run.
Since the plaintext IDs are deliberately not retained (which is the correct privacy call),
rotating the secret destroys the list in the direction of publishing. And because the CVE ID
input space is trivially enumerable, a leaked key yields the complete withheld list, which is
the embargo list. Add a key-id prefix (`k2:<digest>`) and refuse to run on a mismatch; report
per run how many committed digests matched a row in any retained snapshot; keep an encrypted
offline record of the plaintext IDs outside the repo so re-keying is a re-derivation; and
move suppression evaluation into its own step whose env carries only that secret, out of the
process that parses ten third-party feeds. The list is empty today, so this is free to fix
now and impossible to fix after the first durable suppression.

**59. The certainty chips have no legend, and the metric system has no absence state.**
MEDIUM. Raised by Design (r3 x2), CNA, Marketing, Consumer. Eight chips carry the entire
certainty vocabulary and no page defines one of them at the point of use; the `.caveat` block
explains owner inference in prose that never uses the words on the chips. That is the enabling
condition for item 37's collision. Ship a compact `<dl>` legend above `.tablewrap`, generated
from one dict in `rbp/site.py` keyed by chip class and rendered into both the legend and the
print `::after` labels, with a test asserting every `chip-*` class used in any template
appears in it. Separately, `.metric-value` has exactly one visual form, so a measured zero and
an unmeasured field are indistinguishable by construction, which is why templates defend the
distinction one card at a time and inconsistently (`index.html:82-90` guards on the value,
`index.html:251-252` uses `or 0`). Add a `.metric-value--absent` treatment and a Jinja macro
that branches internally, so a card cannot be written without the branch, and a test rendering
a fixture with every optional key omitted asserting no `.metric-value` contains a digit.

**60. The pinned roster is hand-built and strips the Root.** MEDIUM. Raised by MITRE (r3),
CISA. Every one of the 539 entries has exactly two keys; no committed script produces the
file; the drift test compares name sets only. So the launch gate's denominator rests on a file
no script can rebuild. More importantly, the site depends on the Root relationship in four
places and cannot act on it, which means the Phase 6 correction window (Condition 10) can be
addressed only to CNAs and misses the body the policy assigns the duty to. Commit the refresh
script, retain every upstream field, record the upstream sha beside `fetched`, and use the
scope information as an abstention signal: a block-inferred name contradicted by that CNA's
own published assignment scope should not be published.

**61. The Markdown report sends CNAs claims the site has publicly retracted.** MEDIUM.
Raised by CNA, MITRE, CISA, Marketing. `report.py:471` still says the buffer means "short
coordinated-disclosure windows are excluded"; `method.html:70-74` retracts exactly that in
bold ("It does not, and no buffer length could"). `report.py:562` emits a bare "100% precision
at 59.8% coverage", which `PLAN.md`'s own rule says may be quoted only with its composition
attached (213 of 224 cases were one CNA). `report.md` is the Phase 6 artefact that gets
**mailed to the CNA being named**, so it is the highest-stakes copy in the repository and the
one place a retraction has not reached. Fix both strings and add a copy test over generated
artefacts, not just templates, covering `launch.py`'s condition strings too, which are the
other place prose escapes template review.

**62. Keyboard users must pass 732 tab stops to reach the correction channel.** MEDIUM,
arguably higher: WCAG 2.4.1 Bypass Blocks is level A. Raised by Design (r2), CISA.
`/cves.html` has 760 focusable elements, 732 inside `.tablewrap`, and the only skip link
targets `#main`, which is **above** the table. Everything a keyboard or switch user needs
after the table (the three caveats, the Method link, the withhold link, the email address) is
behind those stops, and per item 15 they are also invisible. Add a second skip link before
`.tablewrap` targeting the caveat block, then paginate, which fixes this, the 41,520px
scrollport, the 366 KB innerHTML rebuild and the 272-screen mobile document together.

---

## Part 4: dropped, downgraded, or corrected

Recorded so they are not silently re-litigated. In each case the refutation was checkable and
the original was not.

**Dropped: "the lead count contradicts the rows" as an arithmetic bug.** Filed as a blocker;
refuted on the live branch by five reviewers. `origin/data` snapshots for 2026-08-22 and
2026-08-23 both show `corroborated: 172` against exactly 172 rows with `indep_sources >= 2`
and `single_origin: 350` against 350. Within one run `kpi_core` filters the same row objects
`_publishable` later copies, so they cannot disagree. The 172-vs-162 gap came from a torn
local snapshot written by three executions twenty-one hours apart. **Surviving
recommendation:** the `_assert_consistent` extension, folded into item 1 as the detector for
the torn-snapshot class.

**Dropped: "`unmeasurable_rows` and `candidate_rows` are never emitted".** Filed as a blocker
("the rule card renders 0 / 0 / 0"). `clock.py:553-558` emits both, and the live summary
carries `unmeasurable_rows: 521, candidate_rows: 1, min_sightings: 3`. The zeros were a stale
local build. **Surviving recommendations:** the presentation question (an all-zero "Candidate
MUST" column on `/cnas` and a zero tile on `/cna` read as findings about CNA behaviour when
`OWNER_FEEDS` holds three entries and MUST is structurally unassessable for 431 of 434 CNAs)
is folded into item 19; the `or 0` template pattern is folded into item 59; the invariant test
`unmeasurable + candidate == total` is worth keeping as a regression pin.

**Downgraded: "the envelope publishes nulls".** Both live examples refuted
(`coverage.min_sightings` is 3, `counts.unmeasurable_rule` is populated). The fail-open design
survives at low severity: `schema.envelope` builds every declared field with a bare `.get()`,
so the next key rename publishes a null with no test failure. Folded into item 22 as a
`_require()` helper, with the split behaviour item 17 needs so requiring a field on the
current snapshot does not make the build refuse an older archived one. The genuinely useful
residue is separate and is kept: four percentage-like coverage figures are published with no
statement of which one the launch gate reads.

**Corrected: "the cache saves failed runs".** The central mechanism is false.
`actions/cache@v4`'s `action.yml` declares `post-if: "success()"`, so the save step is skipped
when the job fails, and the described self-perpetuating loop cannot occur. **Surviving
recommendations,** kept in item 27: atomic parquet writes, the restore-time integrity gate
(validating both cached paths, not just the corpus), and the unbounded
`[ZipFile(BytesIO(outer.read(n))) for n in inner_zips]` memory ceiling in `_iter_records`.
The claim that the 583 MB baseline is cached is also wrong: the cached paths are `data/index`
(6.6 MB) and `data/.api_cache.json`.

**Corrected: "`state_verified_this_run` is a phantom column".** Present on 522 of 522 live
rows. Two of the three columns survive (item 23). The finding's own author corrected it.

**Corrected: "held-back rows are indistinguishable from countable rows".** They carry
`counted: False` and `held_back_reason` and zero of them carry an owner, which is the naming
gate working correctly and should be recorded as such. The surviving defect is narrower and
sharper: neither key is in `COLUMNS` or `FIELDS`, so a consumer that strips rows to the
declared `columns` (the documented, correct behaviour) destroys the only discriminator and
merges 84 within-buffer rows into the reportable set. Kept in item 23.

**Dropped: "delete the 'not comparable to that series' disclaimers".** Refuted by five
reviewers and the refutation is right. Those three bolded sentences are the site's best work
and the reason the removed-metrics section survives adversarial reading. What actually drifted
is the standing framing line, not the site. **Surviving recommendations:** strike the stale
"241 candidate 4.5.1.4 MUST" figure from the project fact list (live `must_rows` is 0, and the
figure only ever existed on the theory that GHSA was GitHub's own channel, which `clock.py`
has since reasoned its way out of); stop describing the product in MUST/SHOULD terms in any
launch material; and settle the launch sentence now so it is pressure-tested by the same
review loop as everything else. The panel converged on the redaction sentence
("The CVE Program's API will confirm that a CVE ID is reserved. It will not tell you who
reserved it.") as the lead and the footer's standing offer as the close.

**Downgraded: publish a KEV flag.** Amended by four reviewers. The publication half is
dropped: a KEV flag rendered on a row that also carries an inferred CNA name converts "this
CNA has an unpublished record" into "this CNA is sitting on a known-exploited vulnerability",
which is an accusation of a different order resting on the same inference, and `PLAN.md:226`'s
no-severity rule is the project's single clearest answer when challenged. **Surviving
recommendation, worth doing:** measure the intersection first (it may be empty by
construction), and if it is not, use `in_kev` internally to route a withhold request on a KEV
row to human review, since CISA has already published it and the embargo argument does not
apply. Report the overlap as an aggregate count on `/method` with no per-row flag. Amend
`PLAN.md:226` only as narrowly as that.

**Corrected: the data branch is 17.2 MB.** That is the sum of uncompressed blob sizes. The
entire 49-commit branch is 343 KB packed, about 7 KB per commit. Item 20 is a privacy finding,
not a quota finding, and the correction matters because the size argument would push toward a
force-push orphan for the wrong reason.

**Corrected: the desktop caveat measurement.** The 40,848px figure applies only to a wheel
whose pointer is over the table; the caveat block enters view at 333px of page scroll. Do not
put that number in a launch decision. The mobile measurement and the caption-in-scrollport
measurement both stand, and the caption one is sharper. See item 40.

**Corrected: `render()` costs 46ms per keystroke.** Measured at 6.5ms. Debounce for the live
region, not for the performance. See item 43.

**Corrected: `--reindex` cannot recover a corrupt baseline on CI.** True locally only; the
583 MB zip is deliberately not cached, so a fresh runner re-downloads it. Fix it anyway,
because `assert_corpus_current`'s recovery instruction says "Re-run with `--reindex`" and on a
developer machine that instruction provably cannot replace the file it names.

**Downgraded: the SSRF CGNAT gap.** Reaching it requires controlling DNS for a hard-coded feed
hostname or a redirect target, and CGNAT space is not routed on GitHub-hosted runners.
Low-to-medium, kept in item 56 alongside the much larger `file:`/`ftp:`/`data:` hole in the
same module.

---

## Part 5: chair additions

**C1. Nobody asked whether naming is ready, only whether the naming machinery is correct.**
This is the largest gap in ninety findings. Assemble the facts the panel established, which no
single finding puts in one place: production graded n is **1**; the per-CNA precision figure is
stratified on the wrong axis and excludes every error a CNA reported; 96.4% of named rows sit
on one CNA whose own advisory channel the pipeline does not read; two of the five named CNAs
hold exactly one inferred, single-origin, `unmeasurable`-ordering row apiece; coverage is 21.7%
against a gate that cannot clear; the correction channel is unreachable; and the named rows
have already circulated without the notice the project promised. Every one of those is
individually fixable, and the panel dutifully proposed a fix for each. **The option nobody
tabled is launching without the owner column at all:** publish the count, the clock, the
sources, the age distribution, the abstention rate and the coverage table, and add names later
when the accuracy ledger has real n and the correction channel has been exercised by someone
outside the repository. That version of the site is shippable in weeks rather than months, it
loses nothing the site's argument actually requires (the argument is about a redacted field and
an unpublished Program metric, not about which CNA is worst), and it removes every blocker in
items 2, 5, 7, 9, 11, 18, 37, 38 and 50 at a stroke. It also converts the naming work from a
launch dependency into a v2 with a real measurement behind it. I would take it.

**C2. There is no end-to-end test over the produced files.** Every test in this repository is
either a unit test over a function or a string match over source. Nothing runs the real
pipeline over a fixture corpus and asserts invariants on the artefacts it writes. That single
missing test is the common cause of the phantom columns, the run_coverage population, the scrub
desynchronisation, the sidecar counts, the torn snapshot and half the design findings, and it
is the Python-side twin of item 15's render harness. Build it: a fixture corpus, a fixture feed
set, one `cli.run` plus one `cli.build`, and then assertions over `site/` and `snapshots/`
(key-set equality against `COLUMNS` in both directions, `len(rows) == counts.total` on every
envelope, every internal href resolves, every archive URL resolves from its own location, no id
in `.suppressed.json` appears anywhere, ledger names match row names). Do this before working
through Part 3, or half of Part 3 will be re-found in round five.

**C3. Write down the standard for publishing a claim about a named party.** The panel found the
individual defamation vectors (the slug collision, the misses table, coordinator naming, the
transfer misattribution) one at a time, and each fix is local. Nobody wrote the rule they are
all instances of. One paragraph in `PLAN.md`, and one pre-publication checklist item: before any
artefact asserts something about a named organisation, it must be (a) derived from a stated
method the party can recompute from public data, (b) accompanied by the site's measured error
rate **conditioned on the prediction**, (c) reachable by a correction channel that party can
actually use, and (d) removable from every artefact the project controls, with the scope of
"controls" stated honestly. Every blocker in Part 1 is a violation of one of those four, and a
written rule is what stops the next one being found by a reviewer rather than by a lawyer.

**C4. The panel produced ninety findings and no sequencing contract.** That is why round three's
fixes were re-reviewed in round four against a build nobody could date. Adopt one convention:
each item in this document gets a line in `PLAN.md` with a state (open / landed / dropped) and
the commit that closed it, and `REVIEW.md` is regenerated rather than appended. Round five should
begin by verifying the closed items against `origin/data`, not by re-reading the code.

---

## What the panel disagreed about most, and why it matters

**Whether to trust the artefact in front of you.** This was the round's defining split and it
was not really about any finding. Four blocker- and high-severity items were filed against a
local build produced by an older revision, and four different reviewers independently caught it
by fetching `origin/data` and recomputing. Roughly a fifth of the round's blocker-grade output
was spent on defects that do not exist. It matters because the same failure will happen to a
journalist with a clone, to a CNA quoting a row, and to the maintainer at 2am on launch night,
and because it is fixed by item 1 in half a day. Until then, no verdict about this project
should be issued without naming the artefact it was measured against.

**Whether a gate that cannot clear is a control or an obstacle.** On the coverage threshold, one
reviewer argued for adding an ICS floor to condition 1 and another argued that a second
unreachable term converts a stalled gate into a permanently stalled one, which is how people end
up routing around the control. Both are right, and the resolution is not technical: publish the
sector figure as a hard requirement, re-derive the threshold in the open with the reasoning
recorded, and treat any lowering as a public decision rather than a config change. The reason
this matters more than it looks is reflexive. This project's entire thesis is that the CVE
Program replaced numeric thresholds with private discretion. If the tracker quietly moves its own
number when it becomes inconvenient, it has made the Program's argument for it, and there is no
retention policy that reaches that.

**Whether the site's disclaimers are its weakness or its strength.** One reviewer read the three
bolded "not comparable to that series" statements as positioning drift and proposed removing
them; five reviewers refuted it hard, and the refutation held. The disclaimers are the most
accurate sentences on the site and the reason the removed-metrics argument survives contact with
the Secretariat. What is actually misaligned is the *launch line*, which claims an equivalence
the site itself denies three times in bold. The lesson generalises past this one argument: on
every claim where the panel found a contradiction (the warrant, the Program's own metric, the
redaction scope, the covered-set guarantee, the ask), the weaker and more precise version was
already written somewhere on the site, and the stronger version was the one in the lead position.
The fix in every case is to promote the sentence the project already knows to be true.

**Severity of the correction channel, and who it is for.** The Python and Actions reviewers
tended to file the withhold defects as ordering and plumbing; the CNA and CISA reviewers filed
the same defects as the difference between a correction request and a letter from counsel. The
CNA reading is the one to act on, and it produced the single most important sentence in this
review, which no engineering finding would have reached on its own: **as built, the site's
published accuracy figure improves every time a named party catches it being wrong.** That is
not a bug in a function. It is a closed loop between three subsystems, each of which is
individually defensible, and it is the kind of thing only an adversarial panel finds.

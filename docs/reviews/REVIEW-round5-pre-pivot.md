# RBP Tracker: combined panel review, round 5

**Verdict.** The measurement is sound and the reasoning around it is better than anything
comparable in this space, but the project is not launchable today for one reason that has
now recurred in five separate artefacts: the site publishes CNA names through files that
its own leak guard is structurally incapable of inspecting, on pages that state in bold
that it names nobody. Everything else on this list is ordinary engineering work; that one
thing is a credibility failure that gets worse every six hours it stays live, and it is
the only class of defect here that cannot be repaired after discovery.

Round 5 panel: Python, Web Design and Layout, GitHub Actions, CNA Operator, CVE Program
Leader (MITRE), CISA Government Leader, CVE Consumer Working Group Leader, RogoLabs
Marketing. Prior round preserved at `docs/reviews/REVIEW-round4.md`; do not overwrite it
again, it is the only record of what was already adjudicated.

Note on the gate. The brief given to the panel says the launch gate is 50% CNA coverage.
That gate no longer exists in the code: `rbp/site.py:86` is `GATE_TOP_N_PCT = 80.0` on
top-50-by-volume, reading 41 of 50 with a margin of one. Several briefed figures are
likewise superseded (see item 21). Read numbers off the live site or `origin/data`, never
off a document and never off the gitignored local `site/` tree.

---

## Blocks launch

### 1. Stop the naming leaks, today, before any other work

Raised independently by: CNA Operator, MITRE, Consumer, CISA, Python. Five artefacts, four
discovery mechanisms, one root cause.

`site.NAMING_ENABLED = False` is enforced at the row boundary and nowhere else. Every one
of the following is publicly fetchable right now:

- **`/data/cnas.json`** (`rbp/site.py:1050`, `rbp/cli.py:428`): seven named CNAs sorted
  descending by outstanding count, with `oldest_days`, `median_days_public` and
  `past_expectation` per CNA. Linked from `/data` and on `ALLOWED_SNAPSHOT`
  (`rbp/publish.py:39`), so it is also on four dated snapshots on the public branch.
- **`/data/summary.json`** `inference.leave_one_out.by_cna`: a 40-CNA table of `decided`,
  `precision` and `coverage` for the block-inference method. This is a per-target
  operating table for de-anonymising the reserved space, published from the site that
  argues on `/policy` that exactly this capability makes a blanket unblinding unsafe.
  Also `largest_stratum: "GitHub_M"` and `inference.live.by_cna`.
- **`/data/resolved.json`, `origin/data:resolutions.json`**: 46 of 47 rows carry
  `published_assigner` joined to `first_public`, `published` and `days_to_publish`. That
  join is a dated per-CNA lateness table, and because the assigner is confirmed by the
  published record, the inference-precision caveat does not soften it at all. The comment
  at `rbp/publish.py:125` exempting `published_assigner` is wrong: the field is public,
  the join is not.
- **`/data/precision.json`**: `by_cna` keyed on CNA name, and `graded[].actual` naming the
  CNA, under a `_note` that says inferred names should not have been published.
- **Per-row owner-derived bits in `rbp.json` and `rbp.csv`**: `rule_basis`
  ('inferred-owner' on 246 of 642), `disclosure_order`, `veto_evaluated` (True on 203),
  `self_disclosed`, `rule`, `rule_strength`, `rule_certainty`. `rule_basis` alone
  partitions the rows into exactly the set `cnas.json` enumerates; the two files together
  are a solved system. `disclosure_order` non-'unmeasurable' narrows the owner to one of
  three CNAs by construction, and the one live instance (CVE-2026-32179, MsQuic, NuGet)
  names Microsoft to any reader.
- **`origin/data:snapshots/2026-08-22/backlog.csv`**: 223 of 522 rows carry an `owner`
  column with `owner_tier`, `owner_method` and `owner_contested`. Stale (schema v2 removed
  the columns on 08-23) but still served and still in the branch history.

**Do now, in this order:**

1. Gate the `cnas.json` writers (`rbp/site.py:1050`, `rbp/cli.py:428`) to write `[]` while
   `NAMING_ENABLED` is False, and remove `"cnas.json"` from `publish.ALLOWED_SNAPSHOT`.
   Remove or re-caption its `/data` link in the same commit so the page does not describe
   a file that is gone.
2. Drop `by_cna` and `largest_stratum` from `leave_one_out` and `live` in every published
   envelope. Keep `largest_stratum_share`, which carries the concentration argument
   de-identified. Drop `by_cna` from the served `precision.json` and `actual` from its
   graded entries.
3. Strip `published_assigner` from `resolved.json` and `resolutions.json` while naming is
   off, and rewrite the exemption comment at `publish.py:125` to the correct rule: a field
   is a naming field when the record it sits in joins it to a date or duration derived
   from this site's own observations, whether or not the value is independently public.
4. Force `counts.named` / `summary.named_cnas` to null (not zero) while naming is off, so
   a consumer can distinguish "none" from "not published".
5. Have `clock.annotate` emit `rule_basis` as a constant and `rule`/`rule_strength` as
   null when naming is off, rather than relying on downstream stripping. See item 6.

### 2. Rebuild `publish.check` as an allowlist with a floor, not a blocklist with a walk

Raised by: Python (twice), GitHub Actions (twice), Consumer, CNA, MITRE.

`publish.check` is the only control between the runner and the public data branch (the
persist step is `git add -A` plus a push), and it has now been proven blind on four
independent axes:

- **Field axis.** `_named_paths` keys on field names (`owner`, `predicted`,
  `predicted_owner`, plus `owner_tier`/`owner_method`/`product_map_owner`). A key called
  `cna` walks straight through. Verified: `publish._named_paths(live_cnas_json)` returns
  `[]`.
- **Format axis.** `rbp/publish.py:232` and `:373` are both
  `if not fn.endswith(".json"): continue`, while `ALLOWED_SNAPSHOT` permits `backlog.csv`.
  The two CONTENT arms at `:406` and `:409` glob `snapshots/*/*.json` and are equally
  blind. Three places, not two.
- **Path axis.** The allowlist arm uses `glob.glob(..., "**", "*")`, which never matches
  dotfiles. Reproduced: a tree containing `.github/workflows/deploy.yml` and a root
  `.hidden_secret` returns `[]`. The `.git` filter at `publish.py:358` is dead code, since
  glob never yields a path for it to test. This is the exact leak the module docstring
  says motivated the function.
- **Floor.** `publish.check(tempfile.mkdtemp())` returns `[]`. Every arm is a refusal arm;
  nothing asserts presence. `stage` calls `prune_snapshots` (`shutil.rmtree`) and
  `prune_ledger` on every run, and the persist step commits deletions as readily as
  additions. The docstring records that a green state commit already dropped every
  snapshot once.

**The fix is to change the shape of the guard, not to patch a fifth axis:**

- Build the set of paths that MAY exist (root allowlist plus
  `snapshots/<ISO-date>/<allowlisted name>`), walk the tree with `os.walk` (skipping only a
  literal top-level `.git`), diff, and refuse on any symmetric difference. A missing
  required path then becomes a violation for free, which is the floor arm.
- Add a **value guard**: refuse any value matching a pinned CNA roster short name at any
  key, any depth, any array position, in any allowlisted file. `rbp/roster.py` already
  holds the roster; this is a set-membership test over string leaves. That single arm
  catches every artefact in item 1 and the next one nobody anticipates.
- Add a **per-extension dispatch**: for CSV, refuse any header column in
  `site.NAME_FIELDS` and any non-empty value under one. Route staged CSVs through a
  de-namer as well.
- Add a **shrink refusal**: compare snapshot-directory count and newest-snapshot row count
  against `git show HEAD:` in the `.state` checkout (free, it is a real checkout), refuse a
  drop beyond tolerance, and require callers of a deliberate shrink (withhold, retention
  prune) to pass the expected delta so the assertion checks the number and not just the
  direction.
- Add the **mutation test** that replaces the hand-maintained `NAME_FIELDS` list: run
  `clock.annotate` and `report._publishable` twice over the same rows, once as inference
  left them and once with `owner`, `owner_tier`, `owner_method` and the three
  `product_map_*` keys removed, and assert every key in `schema.COLUMNS` is identical.
  Measured: seven published fields currently differ. This single assertion catches
  `rule_basis`, `disclosure_order`, `self_disclosed`, `rule`, `rule_strength`,
  `rule_certainty` and `veto_evaluated`, and catches the next one automatically.
- Feed `check()` a CSV fixture, a dotfile fixture and an empty tree. Today
  `grep -n csv tests/test_publish.py` returns nothing and all nine `check()` call sites are
  fed JSON.

**Launch condition change (chair):** condition 2 ("v1 publishes no attribution") is
currently discharged on the strength of this guard. Mark it UNMET in `rbp/launch.py` until
the value guard exists, and re-verify it against the rebuilt guard, not the old one.

### 3. Treat the exposure as an incident: history, decision, notification

Raised by: MITRE (r2), CNA, Marketing, Python.

Deleting a path from the branch tip does not unpublish it. The 08-22 CSV blob is reachable
from every commit that carried it, and the branch is public. Set against the project's own
standard in `PLAN.md` 8c, which reopened a notification decision over two names exposed for
50.8 hours across 43 commits, the present exposure is larger on every axis: five artefacts,
seven-plus named CNAs, three days and counting, plus live HTTP 200 endpoints. `robots.txt`
and `noindex` provide no containment on a public git branch.

- Re-root `origin/data`. This project already did it once on 2026-08-23 (commit `20f633f`),
  and `docs/github-support-request.md` records the GC request, so the procedure and its cost
  are known. The branch is four snapshot dates and about 20 commits old and nothing depends
  on it; it will never be cheaper.
- Record the decision in `PLAN.md` 8c against the real figures, using the same framework as
  the two-name decision. Resolve the block at `PLAN.md:648-649`, which still reads REOPENED
  and still argues from a 2h55m window that the correction sixteen lines above replaces with
  50.8 hours across 43 commits. `NEXT.md:181` says the same decision is settled. Two
  documents currently disagree about whether a live decision is open.
- Redact the Wordfence and WPScan pairings at `PLAN.md:616-617`, `:645` and `NEXT.md:182`.
  Section 8c opens by explaining that naming them would republish the pairing being retracted
  and then names them three times.
- **Notify once, covering everything.** One note covers Wordfence, WPScan and every CNA named
  by the leaked artefacts. Two notes, the second sent after someone else finds the rest, is a
  pattern rather than an accident.
- Add notification as **launch condition 10** with a `verified_on` and the same 30-day expiry
  every other commitment carries. Recipients are three classes with different payloads:
  **Roots and TL-Roots** get the rows attributed to CNAs in their scope (they hold the only
  operative lever under RBP Policy v2.0.0, and the site says so at `index.html:341`), the
  **Secretariat** gets the same plus the 4.5.1.7 and metrics asks, the **QWG** gets the method
  and the count. Commit the Root / TL-Root mapping as a pinned fixture beside the CNA roster.
  Sequence after condition 4's permissionless rehearsal, because the note names that channel.

### 4. Make the incident switch fail closed

Raised by: GitHub Actions, MITRE, CNA, CISA, Consumer, Marketing, Python.

`RBP_PAUSE` is enforced by two hand-typed YAML string comparisons
(`deploy.yml:336`, `:452`). `grep -rn RBP_PAUSE --include=*.py rbp/` returns nothing, so the
export at `deploy.yml:72` is dead and the comment at `:68-71` describes behaviour no code
implements. `true`, `yes`, `1 ` with a trailing space, or `True` all publish. Every other
posture lever parses strictly and refuses a non-boolean (`site.py:101`, `clock.py:85`,
`report.validate_min_age`); the one whose failure mode is "keep publishing during an
incident" got none of them. `gh api repos/RogoLabs/RBP/actions/variables` returns zero
variables, so it has never been exercised.

- Add `rbp/publish.py::paused()` parsing the variable the way `site._validated_launched`
  parses `RBP_LAUNCHED`, **failing closed** on an unrecognised value. Emit one step output
  and gate both `persist` and `deploy` on it. Test that both gates reference the same output.
- Make a paused run loud and distinguishable from a broken one: a `::warning::` annotation,
  a `$GITHUB_STEP_SUMMARY` line, and a `paused` field in `summary.json`. Today `notify` does
  not match a skipped job and `recover` requires `deploy.result == 'success'`, so a paused run
  looks identical to an outage in the Actions UI and in the issue tracker.
- Document the real emergency stop, which is disabling the workflow from the Actions UI, and
  document what pause means for already-published state: the last artefact stays live on
  Pages and on the data branch until someone removes it.

### 5. Make the withhold channel work the way the site says it does

Raised by: Python, CNA, CISA, MITRE, Consumer, Marketing. Three defects on one path.

- **`_scrub` matches by substring** (`rbp/publish.py:113`), justified at `:107` as "Crude and
  correct, because the id is the first column and appears nowhere else in a row". Both halves
  are false. On the live CSV, CVE-2026-5744 is a strict prefix of two siblings, and 328 of 642
  rows carry a `CVE-\d{4}-\d+` match in a non-id column. Reproduced: a three-row fixture
  scrubbed for one ID returns `removed 3` and leaves only the header. The JSON branch matches
  exactly, so the two artefacts desynchronise, and `_scrub` runs over all 90 retained snapshots
  on every withhold. Fix: parse with `csv`, match `row["cve_id"]` exactly, write back with
  `csv.writer`. Then assert, post-scrub, that the **set** of removed ids equals the requested
  set (not just the counts, which can hide a swap) and that
  `len(backlog.csv) == len(backlog.json) == summary.total` for every staged snapshot.
  Regression test with CVE-2026-5744 and a five-digit sibling.
- **The published caps do not exist.** `suppress.py:321` is `honoured = list(reqs)` under a
  comment stating there is no cap and no ordering, and `from_issues` re-reads every open issue
  every run so nothing persists and nothing needs review. Against that, `method.html:629-637`
  publishes a 25-per-run cap, a 5-per-author cap, oldest-first ordering, and "N need review to
  carry past this run". `persists_next_run` is published and consumed by nothing; `method.html:646`
  renders `sup.get('capped')`, a key no code emits. The operator log at `suppress.py:456-462`
  tells the operator a review is required when it is not. Pick one and ship code and copy in the
  same commit. The honest rule ("every open request is honoured every cycle until the issue is
  closed") is simpler and a stronger commitment than the one currently advertised. Move
  "Closing an issue revokes it" into `.github/ISSUE_TEMPLATE/withhold.yml`, since it is the one
  true sentence in that block and the requester never reads `/method`.
- **The embargo route is the slow one.** `security.txt` lists the public withhold issue as the
  first `Contact:`, and RFC 9116 orders Contact by preference, so automated consumers take it
  first. `/method:588-591` puts the private routes at five business days against six hours for
  the public one, while the issue template itself warns that a public issue is a permanent
  indexed record that someone wanted an ID delisted. Reorder so `mailto:` and the private
  advisory are first and second. Commit to a same-business-day target for embargo reports
  specifically, separate from general correspondence. Document the operator path (one append to
  `suppressions.txt` plus a `workflow_dispatch`) so the safe channel is also the fastest and the
  page can say so. If five days stands, say plainly that an embargoed row reported privately
  stays published for up to five business days.
- **Condition 4's rehearsal must span two builds**, from an account with no repository
  permissions. The first cycle is the only interval on which the code and the copy currently
  agree.

### 6. Emit `rule: null` when the rule is unmeasurable

Raised by: CNA, CISA, MITRE (twice), Design, Consumer. One change, five findings.

Live: `rule` is `4.5.1.6` on 642 of 642 rows, `rule_strength` `SHOULD` on 642,
`rule_certainty` `unmeasurable` on 641, `must_rows` 0. The front-page card counts 4.5.1.6 as
*observed* (1 row) while the column asserts it as a *default* (642 rows); both surfaces come
from one run and neither says which sense it uses. The `/cves` Rule filter offers a MUST option
that matches zero rows, and the empty state it lands on carries a `colspan="8"` on a
seven-column table.

Change `clock.annotate` to emit `rule: null` and `rule_strength: null` when
`rule_certainty == "unmeasurable"`, render "rule undetermined" rather than an empty cell, and
build the `<select id="rule">` options from the values present in the data. Then the card, the
column and the filter agree by construction, the Rule column stops being a constant, and the
72-hour publication expectation from RBP Policy v2.0.0, which is true of every row and needs no
view about who disclosed first, is the only thing asserted. Update `schema.FIELDS` to document
null; this is a meaning change and needs a `SCHEMA_VERSION` note.

Do **not** write copy asserting MUST is permanently unreachable. It is unreachable because
`clock.OWNER_FEEDS` is a three-entry literal, not because the evidence is absent (see item 13).
State the ceiling as what the site can currently read, with a date.

### 7. Decide the headline number, and what "independent" means, in one change

Raised by: Marketing (twice), Design, MITRE, CNA, Consumer, CISA. Four findings, one decision.

Live: `<title>` says 642, `.lead-count` says 181, `og:description` carries 181 beside a title
carrying 642, and `/cves` says 642 in both its header and its `<caption>`. Both figures are
described as "the CVE Program's own definition".

The panel's decisive finding is that the two are **not** a strong subset and a weak remainder,
they are near-disjoint populations selected by feed topology. `report._ORIGIN` correctly
collapses `osv` and `ghsa` to one origin because OSV re-publishes GHSA, so the 316 rows sourced
`ghsa,osv` (49% of the dataset) can never corroborate however long they stay unpublished, while
67 of the 181 corroborated rows carry no advisory-kind source at all and are distro trackers
agreeing with each other. `clock.py:230-240` says in terms that a tracker entry is not a
disclosure; `report.py:146-153` gives the same three feeds three independent origins.

- **Lead with `summary.total`** on `/`, in `<title>`, `og:title`, `og:description` and the
  `/cves` header, with identical phrasing on all five. It is the Program's own glossary
  definition ("referenced in one or more public sources") and it is the number `/cves` already
  shows. Delete "Which makes it the Program's own definition" from wherever it sits under a
  stricter test.
- **Redefine corroboration** to require at least one source with
  `clock.origin_kind(s) == "advisory"`, and relabel the tile and filter to what it measures.
  Extend `publisher.category` (item 13) into `report._indep` so coordinator-published CSAF does
  not supply a phantom independent origin; BSI is both the aggregator the site discovers
  providers from and an ingested peer publisher, so every provider it lists is currently
  re-counted through it. Two live rows already have this shape.
- **Publish the delta yourself**, once, with a stated reason. Corroboration redefinition, the
  epoch decision, `rule: null` and any coverage change all move published numbers. Batch them
  into one dated note (chair addition F).
- Add `"headline_metric": "total"` to the envelope so the published number and the published
  data cannot drift, and a test asserting the same integer appears in `<title>`, `.lead-count`,
  `og:description` and the `/cves` header.
- State the structural asymmetry once on `/method`: because OSV re-publishes GHSA, the largest
  group of rows can never corroborate, so a low corroborated figure is a property of feed
  topology and not of evidence quality.

### 8. Decide the epoch, and make the code and the three documents agree

Raised by: Marketing, Python, MITRE, CISA, Consumer.

`clock.py:112` reads `public_date` inside a function whose docstring, `PLAN.md` and
`deploy.yml` all say it keys on the advisory date, and the same module states that
`public_date` is the earliest date from any source including trackers. Twelve live rows have
`advisory_date` strictly later than `public_date`; 67 have no `advisory_date` at all.
`site._changes:937` applies the epoch filter with `public_date` independently, so changing one
without the other desynchronises `/changes` from the count in the same run. `before_epoch` has
two call sites on opposite sides of `clock.annotate`, and at the earlier one the row has no
`advisory_date` key at all, so `row.get('advisory_date')` there would silently make
`_published_ids` the unfiltered backlog.

On the epoch itself, the panel converged against setting one on launch day. `age_buckets` gives
about five rows a day of post-epoch inflow, so a launch-day epoch renders 0 for a week and low
single digits for a fortnight while a 642-row stock with a 570-day oldest row moves to a
secondary page. Anchoring at 2026-08-13 (Board approval of RBP Policy v2.0.0) yields 22 rows,
which is a slower version of the same mistake, and deletes the single most quotable fact the
dataset holds.

- **Recommended: do not set `RBP_EPOCH`.** Lead with the full reportable stock and keep
  `/backlog-at-launch.html` as an age archive.
- Whichever is chosen, make the code, the docstring, `PLAN.md` and `deploy.yml` agree, add
  `"epoch_field"` to the envelope so the partition is reproducible, and add the straddling-row
  test that does not exist today (`tests/test_epoch.py:94` sets only `public_date`, so both
  readings pass).
- Note that 80 rows are excluded as undated regardless of any epoch, so `epoch_excluded` will
  understate the removal. Disclose both together.

### 9. Fix the copy that says the site does something it does not

Raised by: MITRE, Marketing, CNA, Consumer, CISA, Design.

`NAMING_ENABLED` is enforced in the data path and consulted nowhere in the copy path. There is
no `naming_enabled` key in the template context at all (`rbp/site.py:800-835`).

- `index.html:88-97` renders "On this run 60% of these rows carry no owner at all" from
  `run_coverage`. The true figure is 100%, and the sentence implies 40% do carry one.
- `index.html:433` is a card headed "How accurate is the owner column", for a column that does
  not exist, and it is the last card on the page.
- `index.html:382` and `policy.html:140` say "roughly half the owners inferred".
- `method.html:509` is headed "Why one CNA holds most of the named rows"; `:252` has a tile
  "Rows named this run".
- `cves.html:95-101` says "Most named rows rest on a single source", 38 lines below
  "This site does not say which CNA reserved any of them", in the same `.caveat` block.
- `data.html:20` describes an `owner` column removed by schema v2; `:28` advertises
  `data/cna/<slug>.json`, which 404s; `:41` reproduces verbatim the absence-convention sentence
  that `schema.py:20-24` identifies as the defect it was written to correct; `:175` says the
  licence is MIT and `LICENSE` is Apache 2.0; and the file table omits `held-back.json`,
  `resolved.json`, `archive.json` and `rbp.csv.meta.json`.
- `rbp/site.py:1277` copies `placeholder.html` to `about-this-count.html` in both postures, and
  `base.html:69` links it in the nav only when launched, so the post-launch About page says
  "This tracker is being built and is not yet published", "will list" and "soon".
- `security.txt`'s header comment still reasons from "the site names organisations".

Fix: pass `naming_enabled` into the context and gate every dependent block; rewrite the
survivors inside the conditional and put the method-page naming discussion in the subjunctive;
template the four tense-bearing strings in `placeholder.html` so About is honest post-launch;
regenerate the `/data` file table from what `_write_data` actually writes; fix the licence to
Apache 2.0 and state the **data** licence separately from the code licence.

Then make it a build gate, not a habit: fail the build when any rendered page contains
"named rows", "owner column", "rows named" or a per-CNA route while `NAMING_ENABLED` is False,
and when `about-this-count.html` contains "is not yet published", "being built", "soon" or
"will list" while `launched` is true. Assert on rendered pages in both postures, not on
templates, because the failure mode is that the template is fine and the flag is not consulted.
Also assert that every path named on `/data` resolves in the built site.

### 10. Say who builds this

Raised by: Marketing, CISA, MITRE, CNA, Consumer, Design.

`grep` across `templates/` and `placeholder.html` for author, employer, affiliation, funding,
conflict or independence returns nothing. The entire attribution is `base.html:190`,
"Built by RogoLabs, CVE.ICU". The CISA panellist's answer to "would you cite this" was no, and
this was the reason.

Add a "Who builds this" block to `about-this-count.html`, linked from the footer: named author;
personal project of RogoLabs and sibling of cve.icu; employer named and stated as uninvolved,
unfunded and supplying no data; no CNA affiliation and no CVE Board or Root role (I confirmed
neither RogoLabs nor Empirical Security is on the 539-entry roster, so this is a positive fact
worth stating); Apache 2.0 for the code and a stated licence for the data; and one line saying
the site takes no position on any individual CNA and publishes no attribution in this version.

Two hundred words, written now in your framing. The same fact discovered by a critic is a story;
volunteered, it is a footnote.

While there: split the contact routes. One mailbox with a published five-business-day SLA,
framed entirely as a delisting channel, handles every inbound the launch generates. Add a route
for CNA questions that is explicitly not a withhold request, and a press line with a same-day
target for the launch window. Do not publish an SLA that has not been rehearsed.

### 11. Fix the footer ask and the policy page's three incompatible positions

Raised by: Marketing, CISA, MITRE, CNA, Design, Consumer.

`base.html:187-189`, on every page including the holding page: "Unredact `owning_cna` and
publish an RBP metric, and this site will point at yours instead." `placeholder.html:62-66` and
`policy.html:99-104` say a blanket unblinding would be unsafe and that this project is the
reason we know it. `rbp/inference.py` publishes the calibrated k-sweep in a public repo, and
until item 1 lands, `summary.json` publishes the per-CNA operating table. Three positions:
we publish the calibrated method, the capability is unsafe, please give us the change that
makes it unnecessary. They cannot all stand.

- Rewrite the footer to the narrow ask, metric first: "Publish an RBP metric again, and unblind
  `owning_cna` for reserved IDs Publicly Disclosed more than 24 hours ago, and this site will
  point at yours instead." Pin it against the About page qualifier with a copy test.
- **Key the ask on the right defined term.** 4.5.1.4, 4.5.1.6 and 4.5.1.7 all key on *Publicly
  Disclosed* (non-trivial information available), not on *referenced*, which is the RBP trigger.
  The site already gets this right at `method.html:115` ("A tracker entry is a public source,
  and is not a Public Disclosure") and enforces it in `clock.origin_kind`. As drafted the ask is
  **broader** than 4.5.1.7 contemplates, not narrower, which is the opposite of what makes it
  grantable. State the operational proxy (at least one advisory-kind source) in the same
  sentence, and acknowledge that the Program decides what meets the definition.
- **Withhold the k-sweep table** from `inference.py`'s docstring. The concept is obvious; the
  calibrated operating curve at four thresholds is the uplift. State the shipped k and that
  lower k was evaluated and rejected on precision grounds.
- **Add the asymmetry paragraph to `/policy`.** 4.5.1.7 is a confidentiality default with a
  narrow MAY carve-out: a case-by-case discretion informed by embargo status, multi-party
  coordination state and reference validity, none of which this site can see, and all of which
  block inference operates over categorically. Say that, say it is why v1 publishes no
  attribution, and say the ask is for the Program to exercise its discretion rather than for the
  site to substitute its own. That paragraph converts the project's largest vulnerability into
  its most credible sentence. It is only survivable once item 1 lands.
- **Exercise 4.5.1.7 on a handful of the oldest rows before launch and publish the outcome.**
  This was the panel's single strongest recommendation and it is nearly free. "We asked the
  Secretariat to name the reserving CNA under a rule that permits it, on five IDs public for over
  a year, and here is what happened" is unanswerable in a way that no amount of inference is, and
  it forecloses "they never came to us".
- **Correct the redaction framing.** The claim is accurate (verified: RESERVED returns
  `[REDACTED]`, PUBLISHED returns the assigner, and it is one branch in
  `cve-id.controller.js`), but the same branch is guarded by
  `isSecretariat || orgUUID === owning_cna`, so every CNA can already audit its own reserved
  backlog and the Secretariat can compute it across all 539. Amend "nobody can tell whether it
  ran" to "no one outside the Program can tell". That reframes the project as making public what
  only insiders can see, which is both true and much harder to argue with, and it makes the
  metrics ask the cheap one to grant.

### 12. Fix the dark-theme token leak and the contrast harness that certifies it

Raised by: Design (twice), CISA, Marketing, MITRE, CNA, Consumer.

`rbp.css:377` sets `--color-text-secondary: #5a6168` on bare `:root`; `style.css:91` sets
`#9ca3b4` on `[data-theme="dark"]`. Same specificity, `rbp.css` loads second, so the light value
wins in dark, which is the default theme (`base.html:46` goes light only on an explicit OS
preference). The dark block at `rbp.css:393-404` re-corrects eight of nine tokens and omits
exactly this one.

Measured on `/overview` at 1440x900: 63 elements fail WCAG AA and every one computes to
`rgb(90,97,104)`. The lead count renders at 104px / 14.81:1 and the bound strip that qualifies
it renders at 14.08px / 2.32-3.01:1 on the header gradient. On `/cves` the leak lands on
`span.chip-unmeasured` on 641 of 642 rows, at 2.54:1, beside a `.qualifier` line at 10.11:1, so
the site's abstention marker is the least legible cell on the page and its nameability bit is
the most legible. `rbp.css:66-73` records this exact semantic failure being fixed once already,
in light theme.

- Add `--color-text-secondary` to the `[data-theme="dark"]` block. One declaration.
- Fix `rbp/contrast.py:97-119`: `tokens()` returns `{**light, **dark}`, merging by block type
  and ignoring cross-file source order, so it reports 7.02 where the browser renders 2.54, a 2.9x
  overstatement across the whole suite. Resolve by (file order, source order, specificity).
- It also resolves `background-color` only and cannot see the `linear-gradient` on
  `.page-header`, which is where the bound strip sits. Composite the background stack.
- Extend `tests/test_a11y.py:55-71`, which already contains the check that would have caught
  this, to the inherited `--color-*` tokens rather than only the three `--rbp-*` forks, and fix
  `SURFACES` at `:345`: `#151821` appears nowhere in either stylesheet except a comment, while
  `#1e2130` (header, footer, card) and `#252838` (gradient end, hover) are real and omitted.
- Add `:root { color-scheme: light }` and `[data-theme="dark"] { color-scheme: dark }` plus
  `accent-color`, so scrollbars, `<select>` popups, the search clear control and `::selection`
  follow the theme. `getComputedStyle(document.documentElement).colorScheme` is currently
  `"normal"`, and the failure runs in both directions since the toggle sets light by removing
  the attribute.

### 13. Classify CSAF per document before expanding CSAF coverage

Raised by: CISA (five findings), CNA, Python, Consumer, MITRE. CSAF expansion is the named route
to gate margin, so every one of these gets worse as the plan executes.

- **VEX is ingested as advisory.** `feeds.py:906` iterates `vulnerabilities` with no check on
  `document.category`, `product_status` or tracking type. `_csaf_directories` sorts by URL length
  and neither `/vex` nor `/advisories` is a prefix of the other, so both survive; simulating the
  merge over live changes.csv gives about 15% VEX in the newest-120 window. A live Red Hat VEX has
  `known_not_affected: 989` against `known_affected: 321`. A vendor's "we are not affected"
  statement, the responsible act VEX exists for, currently becomes evidence that starts a 72-hour
  clock against a different CNA.
- **VEX backdates the clock.** `advisory_date` is a `min()` over advisory-kind sources and
  `_ORIGIN_KIND["csaf"]` is 'advisory' for every provider. A VEX `initial_release_date` is when the
  vendor opened its own tracking, systematically earlier than any advisory (one live document:
  2026-07-27 initial release, surfaced by a 2026-08-25 changes.csv entry), so it usually wins the
  min and deepens `past_expectation` on rows that already exist. The docstring's stated safety
  property, that an unknown source counts as a tracker, is a **per-adapter** guarantee sitting in
  front of a **fan-out** whose 17 providers are discovered at runtime from the BSI aggregator.
- **TLP is discarded.** `grep -rn tlp rbp/` returns nothing. Every conforming document carries
  `document.distribution.tlp.label`, and provider metadata carries `tlp_label` per ROLIE feed.
  Refuse anything absent or not WHITE/CLEAR. This is a class-1 guard by the project's own taxonomy
  and it is a string comparison.
- **`publisher.category` is discarded.** `feeds.py:901` keeps `.name` only. CISA declares
  `coordinator`, Red Hat and Schneider declare `vendor`. That field decides which rule a CSAF row
  is evidence for. A coordinator publishing about someone else's product can only ever support
  4.5.1.6; it must never yield `own-first`, and it must never count as an independent origin in
  `_indep` (item 7).
- **The same field is a capability, not just a guard.** Three live rows (CVE-2026-13336/13337/13348)
  are sourced from `csaf:Schneider Electric CPCERT` alone: `csaf_security_advisory`,
  `publisher.category: vendor`, TLP WHITE, `product_status` with both `fixed` and `known_affected`
  on Schneider's own product, public 14 days. `disclosure_order`'s own documented rule covers this
  exactly and returns 'unmeasurable', because `clock.py:194` looks up a three-entry `OWNER_FEEDS`
  literal keyed on an inferred owner that v1 does not compute. So `must_rows: 0` is a
  hardcoded-map artefact, not a data ceiling, and the site is understating what it can defensibly
  say on the rows a government reader cares about most.
- **Own-channel eligibility ignores feed completeness.** `disclosure_order` returns
  'third-party-first', an affirmative claim, from a feed *not* containing something, and nothing
  consults `FEED_HEALTH` first. Safe today only because all three mapped feeds read `ok`. Under
  `cap_per_provider=120` and `CSAF_MAX_DIRS=12`, every CSAF provider is partial by design, so
  adding a fourth CNA to `OWNER_FEEDS` from the fan-out begins asserting disclosure ordering from
  a feed read at 7% coverage. Make eligibility conditional on an `ok` health entry for the run,
  return 'unmeasurable' otherwise, write the rule down beside `OWNER_FEEDS`, and derive
  `cnas_own_channel` from feeds that actually reported `ok` rather than from dict membership.
- **The entry cap is unrecorded.** `feeds.py:891-892` slices to `cap_per_provider` with nothing
  recording the discard, while the directory cap is properly reported as "12/121 directories".
  CISA's OT ROLIE feed carries 1,739 entries dated 2025-2026, so the first successful CISA read
  drops about 93% of its advisories on a run that reports clean. Track `entries_available` before
  the slice and report "120/1,739 entries". `_csaf_directory_entries` caps again at `:770` with no
  record; same treatment. Prefer a date window over a count for coordinator feeds.
- **CISA is unreachable and the loss is recorded as permanent.** The 403 is most likely
  cloud-egress blocking of runner IPs rather than a UA block (the r1 diagnosis was corrected), but
  the provider metadata advertises two ROLIE feeds on `raw.githubusercontent.com/cisagov/CSAF`, a
  host the runner already reaches every run for GHSA. Pin them as a fallback. Separately, split the
  health taxonomy: `_record_csaf_health` only reaches FAILED when unreachable **and** no rows, so
  16 of 17 providers going dark reads as CAPPED with `degraded: false`. Add a per-provider `parts`
  dict so `compare_magnitudes` can see a single provider vanish. Add an operator contact URL to the
  UA at `feeds.py:24`.
- **The evidence link is a raw JSON blob.** CSAF rows point at the ROLIE `self` href
  (`raw.githubusercontent.com/...` for CISA, `se.com/.well-known/csaf/....json` for Schneider) while
  `document.references` carries the canonical human page. Prefer the human-readable `self`
  reference as `advisory_url`, keep the machine URL as a separate `advisory_doc_url`, and carry the
  tracking id (ICSA-26-232-01, SEVD-2026-223-01) as a displayed searchable field.
- **Remove the `|| r.vendor` fallback** at `cves.html:188` before any of this lands, or a
  coordinator name appears under a column headed Package on a critical-infrastructure row.

Sequence: document-category classification, TLP guard and `publisher.category` **first**, then the
CISA fetch, then the cap. Fixing the fetch first means the site's first ICS rows at volume are
filed under the wrong rule.

### 14. Read the KEV catalogue

Raised by: CISA (twice), Consumer, MITRE, Marketing, CNA.

CVE-2026-60004: on CISA's KEV catalogue, `dateAdded` 2026-08-25, `dueDate` 2026-08-28 under
BOD 26-04, and `GET /api/cve-id/CVE-2026-60004` returns `RESERVED` / `[REDACTED]`. It is in the
site's `held_back.json` on four consecutive snapshots with `held_back_reason: "undated"`, so it is
excluded permanently rather than pending. No dated feed carries it (OSV returns 404 for the
advisory and the ID), so this is structural and not a page-cap artefact. Meanwhile 0 of 642 counted
rows intersect KEV, which is the strongest reassurance the project can offer and is unpublished.

- Fetch KEV once per run. Treat a failed fetch as a class-3 report (omit, say so), never a build
  failure.
- Use `dateAdded` as an authoritative public date **and bypass the min-age buffer**. Dating alone
  does not work: `dateAdded` 2026-08-25 plus `DEFAULT_MIN_AGE_DAYS = 7` lands on 2026-09-01, four
  days after the federal deadline, so the row stays invisible for the entire window in which it
  matters. Both round-two proposals missed this.
- While there, write down what the buffer is now for. `report.py:100-125` justifies
  `MIN_AGE_FLOOR_DAYS` entirely from a naming hazard that `NAMING_ENABLED = False` removes, so
  under v1 its only remaining function is confidence in the date. Re-derive the floor from that
  rather than carrying 7 forward for a reason that no longer applies.
- Publish `counts.kev_backlog` and `counts.kev_held_back` in the envelope on **both** populations,
  every run, including when they are zero. A nonzero backlog figure then becomes an alarm rather
  than someone else's discovery.
- **Defer** the row-level flag and the `/cves` filter until naming and corrections are settled and
  the backlog figure is nonzero. A KEV badge beside an inferred CNA name is a severity claim wearing
  a citation, `PLAN.md` section 3 forbids exactly that, and a column false on 642 of 642 rows is a
  tenth constant column. State on `/method` that the flag is CISA's determination, that absence
  means nothing, and that the site publishes no severity view of its own.

### 15. Make the undated population reachable and honest

Raised by: CISA, Design, Consumer, Marketing.

80 of the known population are excluded **permanently**, not pending: their only sources are
dateless distro trackers whose state does not change with time. The bound strip describes this in
language that reads as a measurement gap that will close, and the single `undated_excluded` figure
conflates it with the 67 within-buffer rows that clear in a week.

Worse, there is no navigable surface. The nav has no "At launch" entry because `base.html:68`
gates it on `summary.epoch_excluded`, which is 0. `/backlog-at-launch.html` is still served
(HTTP 200, linked from nothing), renders no rows because its table is gated on `summary.epoch`, and
its lead paragraph reads "No launch epoch is set, so nothing is held back and the headline count
covers every reportable row", both clauses false on that build. The only link to `held-back.json`
anywhere on the site is on that orphan page, and `/data` does not list the file.

- Decouple the page from the epoch, gate the nav link on
  `undated_excluded or epoch_excluded`, group rows by `held_back_reason`, and state the permanence
  difference plainly.
- Rewrite the false sentence; publish the two-way split in the envelope counts.
- List `held-back.json` on `/data` with its two distinguishing fields, and give it kind-specific
  `counts` and `columns` (today it reports `rows: 147` with `counts.total: 642`, i.e. another
  file's population, and declares the 30-name backlog column list over rows carrying five
  undeclared keys).
- On a `first-observed` clock origin: only with the constraint the author himself added on
  reflection. A first-sighting date is a function of when a feed was added, which is the
  ambiguity `/changes` already has. If it ships, it must be usable only when the sighting feed was
  in the profile on the prior snapshot, marked `clock_origin: first-observed`, and excluded from
  `past_expectation`, from any rule determination and from the corroborated subset. With those four
  exclusions it supports a count and nothing else, which is all it should support.

---

## Wanted, not blocking

### 16. Workflow and supply-chain hardening

Raised by: GitHub Actions (six findings), Python, MITRE, Marketing, CISA.

- **Split `persist` into its own job** with `needs: [build, deploy]`. Today it is the last step of
  `build` while `deploy` is a separate job, so a deploy failure leaves the branch a day ahead of the
  site, with `prune_snapshots` (rmtree) and `prune_ledger` (drops open predictions) already applied
  against a snapshot the site never served. `deploy.yml:291-293` states the invariant the ordering
  violates. Note the platform already protects the reversible half: the `github-pages` environment
  has a branch policy allowing only `main`, so a branch dispatch cannot deploy but *can* push state.
  Fold the run-ledger append into the same job so one commit carries the snapshot and its delivered
  tick. Re-run `publish check` inside the job that holds `contents: write`.
- **Drop `pages: write` and `id-token: write` from `build`** (unused there; `upload-pages-artifact`
  needs neither). After the persist split, `build` needs only `contents: read, issues: read`. Add an
  explicit `permissions: contents: read` to `ci.yml`. Add `persist-credentials: false` to the main
  checkout: the live log shows the write-scoped token written to `.git/config` in two checkouts and
  resident for the whole 34-minute run beside third-party feed parsing.
- **Protect `main` and `data`.** `branches/main/protection` returns 404 and `rulesets` returns `[]`.
  With `contents: write` on the feed-parsing job and a six-hourly cron, that is a code-execution
  persistence path, not a defacement risk. Add rulesets blocking force-push and deletion on both,
  plus a weekly `state-YYYY-Www` tag pushed from the persist job as a restore point retention cannot
  reach.
- **Pin the supply chain.** Upper bounds are not pins: four resolutions a day of unpinned ranges
  plus their transitive closure, five mutable action major tags, and `sha_pinning_required: false`.
  SHA-pin the five actions first (one commit, closes the larger hole), add Dependabot for
  `github-actions`, then hash-lock pip. Note `test` and `build` resolve independently minutes apart,
  so the suite that gates publication can run against a different dependency set than the code that
  publishes.
- **Move `RBP_SUPPRESS_KEY` off the wide pipeline step.** It is an HMAC over a few hundred thousand
  enumerable CVE IDs, so a leaked key turns `suppressions.txt` into a plaintext list of IDs someone
  asked to have withheld. Emit digests from the pipeline and do the membership test in a minimal
  step. Write the rotation runbook now: rotating invalidates every committed digest and requires
  re-deriving from open issues, and it publishes a second digest set over the same domain.
- **Fix the ledger append.** `continue-on-error: true`, `-q` on every git command, and `|| true` on
  the fetch, whose failure path falls through to `git checkout -B data` in a fresh `git init` and
  builds a parentless orphan the push then rejects, silently, green. `git commit ... || exit 0`
  masks a failed commit as a clean no-op. Replace the hand-rolled init and token-in-URL with
  `actions/checkout@v4` at `ref: data`, drop `|| true`, add a fetch-rebase-retry loop, and emit a
  `::warning::` plus a step-summary line on final failure.
- **Add `paths-ignore` and a ref guard.** Five of the last twenty commits touched no code and each
  fired a full production run with a destructive state advance. And no step checks `github.ref`, so
  a `workflow_dispatch` from any branch runs that branch's `rbp/publish.py` against the real
  `.state` checkout and pushes to `data`. Mirror the existing "Refuse a rehearsal outside a dry run"
  step at `deploy.yml:153-159`.
- **Add `cancelled` to `notify`'s condition.** `timed_out` is not a value `needs.<job>.result` can
  take, so the three comparisons are dead expressions and the comment justifying them describes a
  guarantee the expression cannot provide. A job killed by `timeout-minutes` surfaces as
  `cancelled`, which is deliberately excluded. Safe to add: a run cancelled at queue time cancels
  `notify` too. Then exercise it, since the fire drill at `:161-166` uses `exit 1` and has only ever
  tested the `failure` path.
- **Move both roster tests out of the deploy-gating suite.** `test_the_pinned_roster_has_not_drifted`
  makes an ungated live fetch and hard-fails at 26 net CNA changes; `test_the_pinned_roster_is_not_stale`
  fails by calendar arithmetic on 2026-12-21. Both stop publication for reasons unrelated to the
  site. Mark them and add `-m 'not roster'` to `deploy.yml:110`, mirroring the render-directory
  precedent and its recorded reasoning. Surface roster age and drift as a `/method` banner and an
  auto-filed issue instead.
- **Add `schedule:` to `ci.yml`** so the live currency checks run unattended where a red check costs
  a notification rather than a publication. Today `RBP_LIVE_TESTS` is set in exactly one place and
  `ci.yml` has no schedule, so the policy-currency and RESERVED-redaction oracles run only when a
  human pushes. `PLAN.md:486` makes unredaction the project's kill criterion; as built, the good
  outcome could arrive and the site would keep asserting the redaction until somebody committed.
  Widen the 20-ID redaction sample and stratify it by year.
- **Add an external heartbeat.** `runs.jsonl` is read in exactly one place, inside a build. A
  dead-man's switch that only fires while the man is alive is not one. A Healthchecks-style ping from
  the deploy job on success is the only shape that survives an Actions outage. Then rewrite the claim
  at `deploy.yml:366-368` to name whatever actually ships. Cover the 60-day scheduled-workflow
  auto-disable with a keepalive.

### 17. Wall time, cadence and the corpus cache

Raised by: GitHub Actions.

- Build-job durations since 2026-08-22, oldest first: 5.9, 7.8, 7.1, 7.1, 8.3, 7.5, 5.0, 4.9, 11.3,
  11.4, 10.8, 15.9, 12.6, 13.3, 19.1, 22.4, 17.1, 17.9, **34.6, 33.1, 23.6** minutes, against a
  documented budget of "6.9 to 14.9 minutes" and `timeout-minutes: 45`. All three recent runs were
  warm. Single third-party providers have consumed 18.0 minutes (`open-xchange`, yielding +0) and
  28.2 minutes (`ubuntu` page cap) on consecutive runs. There is no per-provider, per-adapter or
  global deadline anywhere: `grep -rniE "deadline|time_budget|monotonic|elapsed"` over
  `feeds.py`/`cli.py` returns one comment and no code. Add a per-provider budget recording TRUNCATED
  on breach, a whole-pipeline deadline that degrades rather than being killed, drop `retries` to 2 on
  the fan-out adapters, publish `wall_seconds` per feed, and only then reset the timeout and rewrite
  the stale comment.
- The 2026-08-23 18:17 tick produced **no run of any kind**, leaving a 13h24m gap in a published
  six-hourly cadence, consistent with queue eviction under `concurrency: group: pages`. The minute-17
  change made lateness worse, not better: mean 41.5 minutes before, 67.6 after, max 100. Correct or
  delete the comment justifying minute 17, split the concurrency group so a push cannot evict a
  scheduled tick, and have `cadence()` compare delivered ticks against expected slots so a missed
  slot has a number instead of leaving no trace in the artefact that exists to prove cadence.
- The corpus cache key hashes `rbp/cvelist.py`, including the restore-key prefix, so any edit
  (including one that removed six lines of prose) forces a 583 MB re-download and full reindex on the
  push carrying the edit. At 34.6 minutes warm plus a ~15-minute cold path, that run now times out.
  Key on `cvelist.SCHEMA` plus a hand-bumped salt, split `data/.api_cache.json` onto its own key
  hashed on `classify.py` (its only writer), and add a monthly `force_reindex: true, dry_run: true`
  drill so the cold path is measured deliberately. Do **not** cache the 583 MB zip: `actions/cache`
  restores unconditionally and the baseline rotates daily, so it would make the common case worse.

### 18. Feed and corpus integrity

Raised by: Python (five findings), CISA, CNA, Consumer, Marketing.

- **`_get_text` truncates at `MAX_BYTES` and returns the fragment as complete** (`feeds.py:381`),
  and `_csaf_directory_advisories` wraps the parse in `except Exception: pass`, so a short read
  produces a short advisory list recorded as a healthy feed. The module header records this exact
  class costing the entire OSV npm ecosystem once. Read `MAX_BYTES + 1` and raise; narrow the bare
  except to the network exceptions it means (it currently swallows `_url_ok`'s ValueError and every
  HTTPError, and a provider that failed lands in `empty` rather than `unreachable`, which is a
  benign category). Do the narrowing first, or the ceiling check is inert.
- **A vanished feed is invisible to the shrink guard.** `compare_magnitudes` iterates the current
  run's feeds, so a feed present last run and absent this run is never visited: reproduced, returns
  `[]`. The route in is `cli.py:176-178`, where an unknown source name prints a warning and is
  dropped, and `cli.py:376` then writes the **post-filter** list into `summary.json` as `requested`.
  Iterate the union, make an unknown source fatal, and record the caller's original list. Note
  `site._changes` reads that same post-filter value for its comparability test, so it is a second
  consumer of the wrong number.
- **The corpus canary takes an unclamped `max()`** (`cvelist.py:407`), so one future-dated
  CNA-supplied `date_published` permanently disables the check the docstring calls "the only check
  that looks at the data itself" (reproduced: a 23-day-stale corpus reports -203 days behind). The
  poisoning is sticky, because `apply_deltas` only adds and the Actions cache restores by prefix.
  Replace with "at least N records carry a `date_published` within `max_lag_days`", which no single
  row can satisfy or defeat, and wrap `fromisoformat` (a 10-character garbage value currently raises
  an unhandled ValueError instead of the intended SystemExit).
- **The SSRF hardening stops at the `feeds.py` module boundary.** `cvelist.py:52`, `:124`, `:241`
  and `classify.py:183` use the process-default opener: http allowed, redirects unvalidated, no IP
  pinning, and `_SafeRedirect`'s credential stripping never runs, on the path that attaches
  `Authorization: Bearer $GITHUB_TOKEN` and downloads 583 MB from a URL read out of a network-fetched
  JSON document. `urlretrieve` has no ceiling and `_delta_rows` does an unbounded `r.read()` into
  `BytesIO`. Move the hardened opener into `rbp/http.py`, build it from a bare `OpenerDirector`
  (keeping `UnknownHandler` so an unhandled scheme raises rather than returning None), use it
  everywhere, mirror `_stream_zip`'s chunked temp-file copy in `download_baseline`, move `_url_ok`
  inside `_stream_zip`, and add an AST-walk test that no module in `rbp/` calls `urlopen` or
  `urlretrieve` directly. The comment at `feeds.py:313` asserting no http/file/ftp handlers is false
  by introspection (`_OPENER.open('file:///etc/hosts')` returns the file), which is what stopped
  anyone re-checking.
- **The inner zip is read fully into RAM** (`cvelist.py:139`) under a docstring claiming "no full
  read into RAM", and `MAX_TOTAL`, documented as the zip-bomb guard, is summed only over the inner
  entries, i.e. after the 646 MB outer decompression has already happened with no ceiling, on the
  one path an attacker could influence. Copy to a `NamedTemporaryFile` in chunks enforcing the
  ceiling during the copy, and wrap the generator in try/finally to close the ZipFiles. Do **not**
  chunk the DataFrame build; it buys nothing at this size and risks dtype drift.
- **`refs` is truncated at 250 characters as a display concern** and read by two stages as evidence:
  `_indep` (which produces the headline) and `_derive_meta` (which produces the only evidence link).
  Longest live value is 234 and a single BSI CSAF token is 154, so the margin is 16 characters
  against an input the project is actively widening. Drop the cap; 642 rows at ~234 bytes is 150 KB.
- Lower priority: guard `FETCH_BYTES` with a lock (racy read-modify-write from three thread pools,
  but read only by `feedlab`), and add `classify.reset()` clearing `RATE_LIMITED` in production,
  deleting the two `.clear()` calls in `tests/test_degraded.py` that currently substitute for a
  production reset that does not exist.

### 19. The published data contract

Raised by: Consumer (nine findings), Python, CNA, CISA, MITRE.

- **Rows do not obey the declared columns.** The envelope declares 30 columns; rows carry 31 keys,
  missing `own_feed_date` and `earliest_other_date` and adding `dates`, `disclosure_order` and
  `suppressed`. Only the CSV is projected, and only because `DictWriter`'s default `restval=''`
  manufactures the missing columns silently. Project in `schema.envelope` from the row list, set
  `restval` to a sentinel that fails the build, and add the `set(r) == set(COLUMNS)` test that no
  current test can fail. Drop `suppressed` via `report._INTERNAL` (false on 642 of 642, and its only
  informative value is about rows that are not there). **Keep `dates`**: it is the only field from
  which a consumer can reproduce `public_date`, `advisory_date` and the clock, and it is exactly the
  audit trail the two dead columns were supposed to provide. Promote it into `COLUMNS` as a
  documented JSON-only object with a stated CSV encoding.
- **`own_feed_date` and `earliest_other_date` are written by no code**, empty on every CSV row and
  absent as keys from every JSON row, while `/data` calls them "the entire input to the rule call"
  and "checkable without parsing nested JSON". `clock.disclosure_order` already computes exactly
  `mine[0]` and `theirs[0]` at `:206-211` and discards them. Populate them there.
- **Nine of thirty published columns are constant** across all 642 rows: `state`, `clock_known`,
  `rule`, `rule_strength`, `self_disclosed`, `own_feed_date`, `earliest_other_date`,
  `owner_nameable`, `state_verified_this_run`. `past_expectation` is a perfect function of
  `clock_origin` (575 advisory/True, 67 tracker/False, zero exceptions) because the 7-day buffer
  exceeds the 72-hour expectation by construction, so the field documented as the lateness test
  measures nothing a consumer does not already have. `clock_known` is true everywhere because the
  false rows are held back. Amend the FIELDS entries to state the constraint, and add the general
  test: every published field has at least two distinct values or a FIELDS entry saying in terms that
  it does not. That single assertion catches all nine at once.
- **`summary.json` has no schema version, no field dictionary and two fields named `truncated` that
  disagree.** It is the only machine-readable home for `limitations`, `feeds.detail` and `coverage`,
  and `/data` advertises it as feed health. `feeds.truncated` is `[]` on a run where `feeds.detail`
  reports ubuntu, ghsa and csaf all capped, because `cli.py:378-380` filters on
  `status == TRUNCATED` while `feeds.py:85` sets the per-feed flag to `status in (TRUNCATED, CAPPED)`
  under a comment arguing for the wider rule. Wrap it in the envelope, document `SUMMARY_FIELDS`,
  make the two agree, and promote `feeds: {name: status}` plus `limitations` into the `rbp.json`
  envelope so the primary artefact answers the completeness question without a second fetch. This
  also fixes `index.html:67`, whose feed caveat is gated on the empty list, so the front page rendered
  clean on the run where the only critical-infrastructure provider was unreachable.
- **The data branch carries no schema version at all.** Bare JSON arrays, an unversioned
  `summary.json`, a CSV with no marker, and no branch-side `rbp.csv.meta.json`. The header changed
  under consumers between 08-22 and 08-23 (31 columns with `owner` at position 15, then 30 without)
  with nothing to pin to. Add `snapshots/<date>/manifest.json` carrying `schema_version`, `columns`,
  `source_commit`, `generated_at` and per-file row counts, add it to `ALLOWED_SNAPSHOT`, and have the
  archive builder read the version from it rather than stamping today's constant. That fixes the
  archive-rewrap defect (five declared columns are absent as keys from the live
  `/data/archive/2026-08-22/rbp.json`, which nonetheless stamps `schema_version: 2` and includes
  `past_expectation: true`) in the same change. Rename one of the two files called `resolved.json`,
  which mean different things on the two surfaces.
- **`refs` is an undocumented three-level nested encoding.** Entries separated by `;`, each split at
  the *first* `:`, and CSAF values are themselves TAB-separated triples. Ten literal tabs are in the
  live CSV. `_indep` parses it and the front page leads with the result, so `indep_sources` cannot be
  reproduced from the published documentation. Publish `refs` in `rbp.json` as an array of objects
  plus a `csaf_providers` list; document the full grammar for the CSV; and add the test that
  recomputes `indep_sources` from published columns and asserts equality. That test fails today,
  which is the point.
- **`advisory_url` falls back to a cve.org record page on 65 of 642 rows**, all `samsung`, in a field
  documented "Always populated". For a RESERVED ID that page renders nothing, so a tenth of the
  dataset offers as its only evidence a link that appears to disprove the row. The code already knows
  (`report.py:76-79` records fixing exactly this for CSAF and did not generalise it). Add `samsung`
  and `arch` branches, refuse to publish a row whose only link is the CVE Record page, and assert
  that every `source` in the feed registry has a `_u` branch.
- **Publish `changes.json`.** `site._changes` already computes `new`, `published`, `rejected`,
  `no_longer_listed`, `dropped_by_epoch`, `comparable` and `incomparable_reason`, and none of it
  leaves HTML. A row leaving has six possible meanings (published, rejected, withheld, pre-epoch,
  no longer listed, endpoint brownout) and a set-differ sees one. Publish the diff with a documented
  reason enum, state that withheld rows are deliberately absent from it rather than given a reason
  code, and add a `comparability_key` hash over profile, `min_age_days`, epoch and the sorted feed
  set so a consumer can apply the same refusal the site applies to itself.
- **CSV hygiene:** 15 live cells begin with `@` (npm scoped names, verbatim upstream text). Do not
  mutate values. Add a build assertion refusing `=` or `+` as a first character (neither occurs
  today) and document on `/data` that `package` and `description` are verbatim upstream text and
  that `refs` may contain tabs. Put `generated_at`, `source_commit`, `snapshot_date` and the row
  count into `rbp.csv.meta.json`, which currently carries only `schema_version`, `columns` and
  `fields` and is therefore byte-identical between runs.
- **The archive index URL 404s for machines.** `site.py:1142` writes
  `"url": "data/archive/<date>/rbp.json"` into a document served at `/data/archive.json`, so a
  consumer resolving it against its own location gets `/data/data/archive/...` (verified: 404 vs 200
  for the root-relative form). Fix the URL, fix the test to resolve against the index's own location
  so it can fail, and keep pruned dates with `pruned: true` and a reason rather than dropping them.
  Write `rbp.csv` and `summary.json` into each archive date, or at minimum fold feeds and limitations
  into the envelope so an archived citation is self-describing.
- **`held-back.json` and `resolved.json` reuse the backlog envelope**, so their `counts` and
  `columns` describe a different file. Add a `KINDS` map in `schema.py` and compute counts from each
  payload's own rows. Add `known_population` (counted plus held back) to the backlog envelope.
- **The published population is defined three times** (`cli.py:244-249` before `annotate`,
  `cli.py:323-327` after it, `report.py:260-261` as a third writer whose `_age` is byte-identical to
  `clock.age_days`). They agree today by coincidence. Move `clock.annotate` to immediately **after
  inference** (not before it: `annotate` reads `owner` for `rule_basis` and `disclosure_order`, so
  moving it earlier zeroes both), compute the population once, pass it to all three consumers, and
  delete the gap-filler. Then assert in `site._assert_consistent` that
  `summary.corroborated == len([r for r in rows if r["indep_sources"] >= 2])` and
  `single_origin == total - corroborated` over the **published** list. That invariant currently holds
  by construction and nothing checks it; it stops holding the moment an epoch is set or a row is
  withheld.
- **Carry-forward reads the wrong file.** `cli._previous_reserved` reads `backlog.json`, which is the
  published subset, while its docstring says it deliberately reads the backlog rather than the ledger
  precisely so held-back rows are covered. 147 rows (18.6% of the known population) have no brownout
  protection. Union with `held_back.json`, both of which are on `ALLOWED_SNAPSHOT` and both restored
  to the runner. Note `backlog_full.json` is not on the branch by design, which is also why the
  week-over-week diff in `report.build` is permanently dead in CI and only ever populates locally.
- **`_derive_meta` splits OSV refs on every colon**, so 53 Maven rows publish only the groupId
  (`io.strimzi` for `io.strimzi:strimzi`) and 29 Android rows publish no package at all (the OSV name
  begins with a colon). Use `split(':', 2)`, strip leading and trailing colons, and better, stop
  re-parsing a delimiter-joined string the pipeline already had structured.
- Wanted, deferred: a `purl` column where the OSV/GHSA adapter has an ecosystem and a name (374 of
  642 rows are mechanically purl-able; it needs a small committed mapping table, not an f-string, and
  the 239 rows with no ecosystem need a documented refusal). Do **not** add affected version ranges:
  that turns a completeness tracker into an unvetted vulnerability feed for records no CNA has
  reviewed.

### 20. Correction path, and the precision figure that can only go up

Raised by: CNA (twice), MITRE, CISA, Consumer, Marketing. **This is the sharpest structural finding
on the table and it should be treated as a launch item once item 1 lands.**

The site offers exactly one remedy, withhold. A withheld row leaves the snapshot, and
`publish.prune_ledger` then deletes every **open** prediction whose id is not in the newest
`backlog.json`. A prediction is graded only when the CVE record publishes, and a row is on this site
precisely because it has not, so a disputed prediction is open by definition when the withhold lands.
`method.html:645` states the mechanism as though it were a privacy feature. Production graded n is 1
(`precision.json`: graded 1, correct 1, precision null, below_floor true), so the first few disputes
shape the figure entirely, and every CNA who tells you that you got them wrong makes your published
accuracy look better.

- Add a `correction` issue template read by the same `from_issues` walk. When a correction names a
  cve_id with an open prediction, record a DISPUTED verdict rather than deleting the entry, counted
  separately from wrong.
- Change `prune_ledger` to move dropped open predictions into a `withdrawn` list with a reason
  (`withheld` | `no-longer-listed`) rather than deleting them, so the sample behind the published
  figure is reconstructible. `prune_ledger` runs on every run, not only on a withhold, so this is
  needed for the ordinary case too.
- Publish `disputed` and `withdrawn` counts inside `precision.json` and beside the `/method` tiles,
  and state that the figure is computed over predictions that resolved, excluding N withdrawn and M
  disputed. A precision figure with its exclusions stated is defensible; one with silent exclusions
  is not.
- Publish an ID-free corrections ledger (error class and date) so the project can state its own
  accuracy on published rows, which is the number a journalist asks for.
- This must land **before the notification note goes out**, because the note invites exactly the
  disputes the current code discards.

### 21. Policy and history accuracy

Raised by: MITRE (five findings), Marketing, CISA, CNA.

- **The archived series is a stock, not a flow, and the site's central comparability disclaimer is
  wrong.** Three surfaces say the archived table "was a quarterly *flow* of newly identified RBPs"
  and that this site is "a live *stock*", concluding in bold that the two are not comparable. The
  February 2021 artefact decomposes each quarter into "Public before 2017" and "Public 2017 or
  later", and those two rows sum exactly to the later single-row figures for all sixteen quarters
  (3,623+703=4,326; 1,611+1,323=2,934; 5+548=553). A pre-2017 cohort persisting across sixteen
  quarters and decaying monotonically from 3,623 to 5 is a backlog draining, not a flow. So the
  archived series and this site measure the same thing in the same units on the same definition,
  including the same age dimension. Replace the paragraph, state what is comparable (same defined
  state, same glossary definition, same stock, both broken down by age of the public reference) and
  what is not (authoritative internal access versus feeds reaching 135 of 539 CNAs; a floor). This
  **reverses** the round-two conclusion that the "dashboard they should have published" stance had to
  be retired: fix the paragraph and the stance becomes defensible on the corrected footing.
- **Delete the N/A inference.** Three surfaces argue the series "had stopped being populated" from a
  cell reading N/A. The last content update (`2985abd60637`, 2021-10-25) populated Q3-2021 while
  Q4-2021 had not yet ended, so the N/A was correct for an unfinished quarter and is evidence of
  nothing. The probative version supports the same conclusion on better evidence: at the 2022-02-07
  release, Q4-2021 was complete, issue #842 item 1 populated Q4-2021 in two sibling tables, and item
  2 commented out the RBP table rather than populating it. Also fix "final column" and "last column
  Q3 2021": the columns are years, the final column is 2017, and the N/A is the Q4-2021 row cell.
- **Publish the exculpatory fact.** Across the table's whole public life (2021-09-07 to 2022-02-07)
  the RBP series received exactly one data update. That is strong evidence for the benign account,
  costs nothing, makes every other claim on the page more credible, and reframes the ask: the
  obstacle was producing the number, not willingness, so "publish the cadence and method of the RBP
  identification the v2.0.0 policy already names as a channel, and resume the series with it" is a
  request the Secretariat can act on.
- **Pin the evidence.** Every link supporting the history claims points at
  `blob/main/src/views/About/Metrics.vue`. Capture into `tests/fixtures/cve_metrics_history.json`
  with a captured date: `409582962878` (first RBP markup, 2021-02-15), `fa5cc54decc8` (restructure,
  2021-08-18), `2c702b11259b` (removal, 2022-02-07, which also **deleted** the sidebar nav entry
  outright rather than commenting it), plus the bodies of issues #835 and #842. Change `policy.html`'s
  "went live in February 2021" to `index.html`'s better construction with the correction folded into
  the same sentence. Drop `PLAN.md:179`'s "the public face of that channel has been switched off for
  four and a half years": what is evidenced is that one table stopped being published.
- **Fix the gate justification.** `site.py:82-85` states in a public file that the planned feed work
  "take[s] it to 40 of 50", immediately above `GATE_TOP_N_PCT = 80.0`, which requires exactly 40 of
  50. Delete the projection sentence, which records how the number was picked rather than why it is
  right. `method.html:404`'s "unreachable" defence does not hold as published (the withdrawn
  threshold was 50%, the stated ceiling 68.8%); the valid argument now exists in a Python comment
  (28.2% ceiling on the current feed set) and should be moved into the page with its date. Fix
  `base.html:32`, which pushes the weakest coverage figure into every unfurl while the gate reads a
  different basis.
- **Pin the roster denominator.** `PLAN.md` reasons throughout from 434 while production reports 539,
  so absolute coverage rose from 121 to 135 while the published percentage fell from 27.9% to 25.0%.
  The roster **is** pinned (`roster_pinned: true`, `roster_fetched: 2026-08-22`); the defect is that
  `PLAN.md` quotes `total_assigners_in_window` (434) as if it were `total_cnas` (539). Name the
  denominator and give the absolute numerator beside every published percentage.
- **Publish the concentration figure de-identified, on the lead screen.** `top_owner_share` is 0.90
  and is rendered only on `/method`, behind a correct anti-leaderboard decision that was implemented
  as suppression rather than disclosure. "Ninety per cent of the rows this site can attribute trace
  to a single CNA, which tells you about block widths and feed coverage rather than about behaviour"
  is the site's best defence against the leaderboard reading and it is three clicks from the lead.
  Put it and the single-origin share in the bound strip with no CNA named, after item 12 makes that
  strip legible. Do **not** gate on it.
- **Publish the source composition.** 5 of 642 rows are CSAF; the rest are OSS package and distro
  feeds. The bound strip should carry a one-line composition figure, and its feed caveat should key
  on `summary.limitations` as well as `summary.feeds.truncated`. Correct the round-one claim that
  zero rows are ICS: three Schneider rows exist, and `icscert`, `siemens`, `schneider`, `SICK`, `ABB`
  and `Nozomi` are all above the sighting floor.
- **Reconcile the briefing figures before anything is quoted.** Seven of seven figures in the panel
  brief are wrong against production, and two (241 candidate MUST, the 50% gate) describe mechanisms
  that no longer exist. Generate `FIGURES.md` from the live `summary.json` on every build, commit it
  to the data branch with its `generated_at` and `source_commit`, and make it the only place any
  number may be quoted from. Date-stamp or strip every inline figure in `PLAN.md` and `NEXT.md`.
  Before the QWG note goes out, read the numbers off the rendered site.
- **Publish lead time, once n supports it.** The site held CVE-2026-60004 for three days before CISA
  listed it, and `resolutions.json` already carries 47 resolved rows with `first_public`, `published`
  and `days_to_publish`. Publish the distribution with its n and date range, stated as a floor
  bounded below by feed-introduction dates, excluding rows whose first sighting coincides with a
  feed's introduction. Not on the front page until n survives a hostile reading, and not before the
  correction channel exists.

### 22. Design and accessibility remainder

Raised by: Design (eight findings), CNA, CISA, Consumer, Marketing.

- **The caveats are structurally unreachable on `/cves`.** `.tablewrap` holds 51,852px of internal
  scroll behind a 772px box with `overscroll-behavior: auto`, and the caption (the home of "This site
  does not say which CNA reserved any of them") is `position: static` and 51.5px tall, so it is
  visible for 0.098% of the scroll extent. `calc(100vh - 8rem)` reserves 128px for a 65px header,
  occluding the sticky `thead` by 14px at rest and losing it entirely past 555px of page scroll.
  Move the certainty statement and the two remaining hedges into a persistent strip under the filter
  bar, add `overscroll-behavior: contain`, promote the header height to a token, and make
  `.tablewrap` itself `position: sticky` with `100dvh` so the scrollport and its header stay in view.
  Add a render test that scrolls to document maximum and asserts the first `thead th` has
  `bottom > 0`.
- **Mobile is 265,257px tall** (326 screenfuls) with 642 unvirtualised cards, `.filters` static,
  `.tablewrap max-height: none`, and all six `.sortbtn` controls `display: none`'d along with the
  `thead`, so sorting is removed from the pointer, keyboard and accessibility trees at that
  breakpoint. Cap the initial render (50 to 100 rows) on **every** viewport with a "show the
  remaining N" control, make `.filters` sticky below 768px, and render a `<select id="sortby">` bound
  to the same sortKey/sortDir. The `display: block` pattern also drops implicit table semantics with
  no replacement: add explicit `role="table"/"rowgroup"/"row"/"cell"` in `render()`.
- **No `<noscript>` anywhere**, and `/cves` ships a server-rendered `<caption>` asserting 642 rows
  over an empty `<tbody>`, with 97.2% of the 626 KB page being an inline JSON payload. Server-render
  the first 50 rows as static markup and let JS take over: that fixes noscript, first paint and the
  initial-render cap in one change. Add a `<noscript>` pointing at `rbp.csv` and `rbp.json`. Fix the
  `colspan="8"` on a seven-column table.
- **Templates fail open on missing summary keys.** The Jinja environment uses the default permissive
  `Undefined`, `index.html:241-242` uses `or 0` (converting absence into a confident zero under a
  heading reading "4.5.1.4 MUST"), `:260` has no guard at all, and `method.html:336,365,378-384` have
  none, while `site._gate_status` fails **closed** on exactly the coverage keys the method template
  renders unguarded. Nothing published is currently wrong (all four branch snapshots carry the keys),
  which is precisely why two panellists filed the degraded local render as a live blocker. Pass
  `undefined=StrictUndefined`, guard on presence rather than truthiness, add a page arm to
  `assert_artefact` refusing the token `None` in a numeric context or an empty `.metric-value`, and
  add one fixture whose summary omits the four keys. Every current fixture supplies them.
- **Pin the CVE ID column** or, better, sequence after removing the constant Rule column: `.tablewrap`
  has 405px of horizontal overflow and `td.id` is `position: static`, so the identifying columns leave
  the viewport exactly when the description becomes legible. A working sticky-first-column recipe
  already exists in `style.css:1628-1636`, scoped to a selector this table never matches.
- **Add anchors to `/method`.** Fifteen links under seven labels, all bare filenames, into a 39 KB
  page whose eleven `<h2>` elements carry no ids (the only fragment link on the whole site is the
  skip link). Add ids, point the links, add a TOC card, set `scroll-margin-top: 5rem`, and test that
  every fragment resolves. This is also a citability fix: a claim that cannot be linked to a passage
  cannot be cited precisely.
- **Theme toggle state is not exposed.** `aria-label` is the constant "Toggle dark mode" in both
  states (wrong in the default theme), `aria-pressed` is never set, and the only state indicator is a
  glyph hidden from AT by the label and rendering at 2.54:1. Set `aria-pressed`, name the destination,
  mark the glyph `aria-hidden`, and add `id="nav-menu"` plus `aria-controls`.
- **Reduce the low-entropy columns.** `rule` is one value on 642 rows, `sources` is `ghsa,osv` on
  316, `indep_sources` is 1 on 461, `vendor` is empty on 463. State constants once above the table and
  render chips only on divergence. Keep both filter options with the empty one disabled and its zero
  count beside it, rather than building options only from present values, so a shared `?rule=` state
  keeps resolving and the schema's value space stays visible.
- **Rename or drop the `vendor` column.** It is the first downstream feed that mentioned the ID, so
  every populated value (Ubuntu 73, Red Hat 55, Amazon Linux 46, Microsoft 3, Debian 3, Alpine 2) is a
  CNA that, in the ordinary 4.5.1.6 case, did the right thing. `grep ',Red Hat,' rbp.csv` returns a
  55-row list from a file stamping `not_a_cna_scorecard: True`, and the same short name means opposite
  things in `cnas.json` and here with nothing distinguishing them. `sources` already carries the
  information without the implication; dropping it is better than renaming it.

### 23. Guard the MUST claim's evidentiary standard

Raised by: CNA.

A row whose only source is the owner's own feed is scored `own-first` and becomes a candidate
4.5.1.4 MUST with no corroboration test anywhere on that path, so a row can carry `rule_strength:
MUST` and `single_origin: true` simultaneously: the site's strongest accusation would meet a weaker
evidentiary bar than its headline count. Zero rows today, and zero only because `OWNER_FEEDS` was
emptied of GitHub_M. Require `indep_sources >= 2` before any row carries 4.5.1.4, encode it as an
assertion in `clock.annotate` rather than a downstream filter, add the invariant as a test in the
form it should be stated publicly, and say the standard on `/method` in one sentence.

### 24. The carry-forward republishes an unverified accusation with no ceiling

Raised by: CNA.

When an `/api/cve-id` lookup errors, the row is republished as RESERVED with
`state_verified_this_run: False`, and that row becomes the next run's `previous_reserved`, so the
carry is self-perpetuating with no counter and no ceiling. Nothing reads the flag: it appears in
zero templates, and `cli.py:413-416` passes `oracle["dropped"]` into `degraded_state` and **not**
`oracle["carried_forward"]`, so a row that is dropped degrades the run while a row that is
republished as an accusation does not. `tests/test_degraded.py:110` already builds the total-outage
case and asserts only that the rows are flagged. Pass `carried_forward` into `degraded_state`, add
`unverified_runs` with a small ceiling after which the row moves to held-back, mark such rows
visibly on `/cves` and exclude them from `past_expectation`, and add the missing assertion that the
total-outage fixture produces `degraded: True`.

### 25. OSV source names defeat the tracker guard

Raised by: CNA, Python, CISA.

`feed_osv` emits the constant `"source": "osv"` for all 11 ecosystems while recording health under
`osv:{eco}`, and `_ORIGIN_KIND["osv"]` is `advisory`, so any ecosystem added to the tuple inherits
advisory status without touching `clock.py` and the "unknown counts as a tracker" default cannot
fire. Current configuration is clean and deliberate (all 35 unread ecosystems were scored, and on
319 rows carrying both a ghsa and an osv date the two agree on all 319), but the tuple is a file
someone will edit under pressure to move a launch gate. Emit `osv:{eco}` as the source so the
existing fail-safe does the work it was written for. This is the same class as the CSAF fan-out in
item 13: **a fan-out adapter must key origin on the sub-source**, and after both fixes the origin map
has no fan-out adapters left in it and its docstring becomes true as written.

---

## Dropped, with reasons

These were argued and did not survive. Recording them so they are not re-filed next round.

1. **"The rule-split card renders 0 / 0 / 0 on the deployed page"** (Design). Refuted against
   production: `/overview.html` renders 641 / 1 / 0, and all four branch snapshots carry
   `unmeasurable_rows` and `candidate_rows`. The evidence was a gitignored local build from the
   2026-08-20 snapshot. The `or 0` guard defect is real and survives in item 22.
2. **"`/method` renders literal None and an empty launch-gate figure"** (MITRE). Same stale build.
   Live `/method` has zero occurrences of the token `None` and renders 41 / 50, "at least 3 times"
   and "instead of 3". The display-versus-decision asymmetry survives in item 22.
3. **"The headline is not reproducible from the published data (172 vs 162)"** (MITRE) as a
   **blocker**. Refuted on production: live `counts.corroborated` is 181 and recomputes to 181 from
   the rows; all four branch snapshots agree exactly. The 172/162 pair came from a local build at
   `source_commit 4c6bc3893a7d`, three commits stale. The invariant is still missing and survives in
   item 19; the "find which ten rows diverge" instruction is dropped, there are none.
4. **"Zero rows are ICS/OT"** (CISA, withdrawn by its author). Three Schneider Electric CPCERT rows
   are live, and six ICS-sector CNAs are above the sighting floor. The composition-disclosure half
   survives in item 21.
5. **`cnas_effective_ics` as launch condition 13** (CISA, contested by Marketing and MITRE). Gating
   launch on ICS coverage makes promotion contingent on feeds that may never be readable, and
   covering ICS is not this project's job. Disclosure is the remedy. Record the decision in `PLAN.md`
   rather than letting the proposal evaporate.
6. **Concentration as a gate condition** (Marketing, amended by its own author). Publish
   `top_owner_share` de-identified; do not gate on it. The gate already clears with a margin of one
   and moves overnight on a third party's publishing schedule; every extra numeric condition is one
   more thing that can take the site down.
7. **"`actions/cache` saves on job failure"** (Actions). Refuted: `actions/cache@v4`'s `action.yml`
   declares `post-if: "success()"`, and a prior round already corrected this. The proposed workflow
   change is a no-op. The temp-file-and-`os.replace` half survives at low priority in item 17.
8. **A per-row KEV column and `/cves` filter shipped now** (CISA, Consumer). Deferred, not dropped:
   a KEV badge beside an inferred CNA name is a severity claim, `PLAN.md` section 3 forbids it, and
   the column would be false on 642 of 642 rows. Ships after naming and corrections are settled and
   the backlog figure is nonzero.
9. **Affected version ranges in the published schema** (Consumer, refuted by Marketing). That turns a
   completeness tracker into an unvetted vulnerability feed for records no CNA has reviewed, under a
   RogoLabs byline, for IDs that are reserved precisely because the record is not ready. `purl`
   survives as a wanted item.
10. **`file:///etc/passwd` via `_OPENER` as a high-severity live hole** (Python). Amended to medium:
    the handler set really does include file/ftp/http/data, but every reachable call site guards with
    `_url_ok` and the one `_stream_zip` call site is a hardcoded ecosystem URL. The real high-severity
    version is the corpus path in item 18. Keep both fixes; do not keep the severity.
11. **"The February 2021 artefact was a different table"** (MITRE). Refuted: the 1999-2009 year-column
    tables in that commit are the Published CVE Records tables; the RBP artefact is a chart plus a
    2017Q1-2020Q4 cohort table, i.e. the same quarterly series. The "went live" verb fix survives in
    item 21.
12. **"CISA's 403 is refutable in ten seconds / the operator misdiagnosed it"** (CISA, corrected by
    its author). A 200 from a laptop does not disprove a WAF rule against GitHub Actions runner IP
    ranges. The commit message stands; the ROLIE fallback and the health-taxonomy split survive in
    item 13.
13. **"Retire the 'dashboard they should have published' stance"** (Marketing). Reversed by the
    stock-versus-flow finding: the stance is refuted only by a paragraph the site wrote about facts it
    had not checked. Fix the paragraph; then re-argue the stance on the corrected footing.
14. **`_previous_reserved` should read `backlog_full.json`** (Python, self-corrected). It is not on
    `ALLOWED_SNAPSHOT`, `publish.check` refuses it by path deliberately, and it never reaches the
    runner. Union `backlog.json` with `held_back.json` instead.
15. **Chunked DataFrame construction in `build_index`** (Python, refuted by Python). Buys nothing at
    381k rows and risks dtype drift across empty chunks, which `SCHEMA = 2` does not detect.
16. **`FETCH_BYTES` / `RATE_LIMITED` as medium** (Python, amended). Low. `FETCH_BYTES` is read only by
    `feedlab`; `RATE_LIMITED` is correct in production because every run is a fresh process. The
    valuable half (production has no reset and two tests substitute for one) survives in item 18.

---

## What the panel disagreed about most, and why it matters

**Which number leads the site.** Design and Marketing initially split in opposite directions on
whether to lead with `total` or `corroborated`, and both treated it as a matter of taste. The
disagreement was resolved by a measurement rather than an argument: the two figures are near-disjoint
populations selected by feed topology, not a strong subset and a weak remainder, because `_ORIGIN`
correctly collapses OSV into GHSA and roughly half the rows can therefore never corroborate, while
more than a third of the corroborated set is distro trackers agreeing with each other. That matters
beyond the headline, because it means `indep_sources`, the field `schema.FIELDS` nominates as "the
field to filter on for a defensible subset", does not measure evidence quality at all. Anyone who
downloads `rbp.json` and cross-tabulates reaches this in ten minutes. Fixing the number without
fixing the definition would leave the same trap set for a downstream tool.

**Whether the site should read KEV at all.** Marketing and MITRE argued that any exploitation signal
converts a completeness measurement into a severity claim and forfeits the one editorial constraint
that keeps this defensible. CISA and Consumer argued that a KEV-listed CVE with a federal remediation
deadline and no CVE record is the strongest exhibit the project will ever hold. Both are right, and
the resolution the panel converged on is the interesting one: read KEV as a **date source and an
aggregate**, publish the zero as well as the one, and hold the per-row flag until naming and
corrections are settled. The zero (0 of 642 counted rows are on KEV) is the site's best answer to
"are you handing attackers a target list", and it is currently unpublished because nobody fetches the
file.

**How much evidence a panellist owes before filing.** A fifth of round two's blocker-grade output was
measured against a gitignored local `site/` tree three commits and three days stale, producing two
false blockers that a third panellist then had to refute with live fetches. The project already
stamps `source_commit` and build time in every page footer and every envelope, which is what made the
refutations possible. That is a process finding as much as a technical one, and it is why item 21's
`FIGURES.md` recommendation matters beyond tidiness: this project's numbers move four times a day,
and every prose artefact in the repository is stale within about 36 hours of being written.

**Whether the launch gate is a quality bar or a way of never being wrong in public.** Nobody except
Marketing named the failure mode of never launching. Four hand-verified conditions expire on
2026-09-21 and 2026-09-22, the gate clears by one CNA and has already changed state overnight because
a third party published, and this round proposed five further conditions. The panel's own output has
to be partitioned or it becomes the reason the site never ships. That partition is the structure of
this document: items 1 to 15 make published claims true, items 16 to 25 make the site better.

---

## Chair additions

Marked as such because the panel did not raise them.

**A. Adopt a verification rule and give it a tool.** No finding may be filed against `site/` or
`snapshots/`, both of which are gitignored local build output. Facts come from `origin/data`, from
the live site, or from source. Add a `make review-facts` target that fetches the live `rbp.json`,
`summary.json` and `cnas.json`, prints `source_commit` and `generated_at`, and diffs them against
`origin/data`'s newest snapshot, so the first thing any reviewer does is establish what they are
looking at.

**B. Stop overwriting `REVIEW.md`.** Round four's 1,560 lines are the only record of what was already
adjudicated, and this round re-litigated at least three items that a prior round had already settled.
Round four is preserved at `docs/reviews/REVIEW-round4.md`; keep every future round as a dated file
and let `REVIEW.md` be the current one.

**C. Mark launch condition 2 UNMET until the guard is rebuilt.** "v1 publishes no attribution" is
currently discharged on the strength of `publish.check`, which returns `[]` on a tree naming seven
CNAs. A condition discharged by a control proven blind four times is not discharged. Change it in
`rbp/launch.py`, and re-verify it against the value guard rather than the walk.

**D. Build one posture matrix, not fifteen assertions.** At least eight findings each ask for one
render-time assertion (no `None` in a numeric slot, no empty `.metric-value`, no "owner column"
string while naming is off, no "not yet published" while launched, title integer equals lead integer,
every `/data` path resolves, every `method.html#fragment` resolves, no roster name in any artefact).
Build the site once per posture (launched x naming, plus the pre-launch holding page) into a temp
tree and run every one of those assertions over the rendered output. One harness, one fixture set,
and the next copy-versus-flag drift fails the build rather than shipping.

**E. Answer "why did the number go up" before launch day.** The count went 506 to 642 across the
panel's own window, and a build log reported 788 three ticks later. Nobody asked whether that growth
is CNAs getting worse or feeds getting wider. `/changes` cannot distinguish the two, which is a known
open item, but it stops being a curiosity the moment the launch headline is a number that has tripled
in a fortnight. At minimum, publish the per-run feed-set hash and the count attributable to feeds
added since the previous snapshot, so the first person to ask has an answer that is not "we do not
know".

**F. Land the number-moving fixes as one dated delta.** Corroboration redefinition (item 7), the
epoch decision (item 8), `rule: null` (item 6), the tracker and coordinator corroboration fixes (items
7 and 13), KEV dating (item 14) and any coverage change all move published figures. Shipped
separately over six weeks, the site appears to be revising its own numbers weekly, which is the worst
possible impression for an instrument. Batch them, publish one note stating each change, its reason
and its effect on the count, and put that note in the dated archive so the discontinuity is
explained rather than discovered.

**G. Two things this repository is missing outright.** There is no `SECURITY.md` and no disclosure
policy for the project's own code, on a site that asks other organisations to improve theirs. And
there is no stated licence for the **data**, which is the artefact people will actually redistribute;
`LICENSE` is Apache 2.0 for the code and `/data` currently claims MIT for both. Both are an
afternoon and both are the first things a careful reuser checks.

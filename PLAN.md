# rbptracker.org build plan

Public tracker for **RBP** CVE IDs: IDs in the `RESERVED` state that are referenced in
public advisories but have no published CVE Record. Lists the CVE, the owning CNA, and
how long it has been RBP. GitHub Pages + GitHub Actions only.

Drafted 2026-08-20. All figures below were measured against live sources on that date,
not estimated.

---

## 1. Why this exists

### The rule, and the hole where enforcement should be

**RBP Policy v2.0.0**, approved by the CVE Board on **2026-08-13**, is the policy in
force. It states the expectation plainly:

> A CVE Record should be published within 72 hours of either (a) disclosure by the CNA or
> (b) the CNA becoming aware of a third-party disclosure, as applicable.

and aligns itself explicitly to the CNA Operational Rules (v4.1.0, approved 2025-05-14):

- **§4.5.1.4**: CNAs **MUST** publish within 72 hours of *the CNA itself* publicly
  disclosing. Past that, the CNA's Root **MAY** direct a CNA-LR to publish.
- **§4.5.1.6**: CNAs **SHOULD** publish within 72 hours of becoming aware a third party
  disclosed. This is the usual distro/RBP case.
- **§4.5.1.7**, the Secretariat **MAY publicly identify the CNA who reserved the CVE ID
  24 hours after** public disclosure.
- **§4.5.3.5**: CNAs **MUST reject unused or unpublished CVE IDs**, so a long-lived
  reservation is not a neutral state under the rules.

Then enforcement. The entire mechanism is four discretionary levers, **Warning,
Reservation Caps, Intervention, Formal Review**, which the Program *"may take"* and
which *"may be applied individually or combined."* Remediation deadlines are whatever a
TL-Root or Root decides case by case. There is no condition that triggers anything by
itself.

**This is the change that motivates the site.** The previous policy (v1.0, *"CVE Program
Policy and Procedure for RBPs"*) had an automatic arithmetic trigger: RBP IDs above 5% of
the CVE IDs a CNA made public in the trailing 12 months and it stopped receiving new ID
blocks; above 50% for three months and it was cut to 25% of yearly output. Anyone with
the data could compute whether a CNA was over the line. **v2.0.0 removes every numeric
threshold.** There is now no line to be over.

Discretion is defensible. Discretion exercised entirely in private is not distinguishable
from no enforcement at all, and right now there is:

- no public list of RBPs,
- no public record that a CNA was notified,
- no public enforcement log,
- no public attribution: `owning_cna` is redacted for exactly the reserved population,
  despite §4.5.1.7 expressly permitting the Secretariat to name it after 24 hours,
- and no Program RBP metric at all. One existed: a quarterly RBP table went live on the
  CVE Metrics page in **February 2021** and was **commented out on 2022-02-07**, after
  about a year public. The block is still in `src/views/About/Metrics.vue` on `main`,
  frozen, its last column Q3 2021, and `metrics.json` carries no RBP series. The live page
  reports published records and reserved IDs and nothing on the overlap. Verified in the
  rendered DOM, not just the source: the string "Reserved but Public" does not appear on
  cve.org/About/Metrics.

The site publishes the observable half and reconstructs the redacted half with a graded
method.

> **Do not cite the 5%/50% thresholds.** They are withdrawn. The v1.0 PDF is still hosted
> by third-party CNAs and still ranks well in search. That is how this project picked them
> up in the first place. `tests/test_policy.py` pins the current text and fails the build
> if either canonical source moves.

## 2. Verified findings (2026-08-20)

### F1, the bulk CVE List contains zero RESERVED records
Full state census over the `all_CVEs` release, 365,232 records, 9.2s:

```
PUBLISHED  347,571
REJECTED    17,659
RESERVED         0
```

The policy's numerator is invisible in the bulk feed.

### F2, the git tree does not carry reserved stubs either (corrects VISION.md)
`cves/2026/26xxx` in `CVEProject/cvelistV5`: 487 files present in the 26000–26999 range,
**513 IDs absent**. The small stub files are `REJECTED`, not `RESERVED`. Cloning the
2.63 GB repo buys nothing. Drop that approach.

### F3: `/api/cve-id/` exposes the true state, unauthenticated  ← the unlock
Not `/api/cve/` (which 404s on reserved IDs, the reason the current engine mislabels
everything `DNE`). The reservation endpoint:

```
GET https://cveawg.mitre.org/api/cve-id/CVE-2026-2574
{"cve_id":"CVE-2026-2574","cve_year":"2026","state":"RESERVED","owning_cna":"[REDACTED]"}

GET https://cveawg.mitre.org/api/cve-id/CVE-2026-26100
{"state":"PUBLISHED","owning_cna":"Nozomi"}
```

Rate limit header: `ratelimit-policy: 25000;w=60`. Measured 94 req/s at 24 threads;
456 IDs resolved in 4.9s.

**Consequence:** every row the current engine calls `DNE` becomes `RESERVED`, the
policy's own literal definition of RBP. The "these might be typos" objection dies.

### F4: `owning_cna` is redacted on exactly the population the policy governs
Sampled 2023–2026. Every `PUBLISHED` ID returns a real `owning_cna`. Every `RESERVED` ID
returns `[REDACTED]`. No partial disclosure, no aged unblinding, despite CNA
Operational Rules §4.5.1.7 permitting the Secretariat to name the reserving CNA 24 hours
after public disclosure.

**This is the site's thesis.** The field is populated, served, and masked by choice.

### F5: block inference reconstructs the owner, 100% precision out-of-sample
CVE IDs are issued in runs. If published IDs bracketing a reserved ID agree on one
assigner, that assigner very likely owns the reserved one. Tested on the *real RBP
population*: predicted from the 2026-07-14 corpus, graded against IDs that published
after.

| gate | coverage | precision | verdict |
|---|---:|---:|---|
| k=1 | 86.2% | 99.5%  | aggressive |
| k=2 | 65.2% | 99.3%  |: |
| **k=3** | **59.8%** | **100.0%** | **ship this** |
| k=5 | 50.9% | 100.0% | costs coverage for nothing |

k = published IDs required on *each* side, all agreeing. n=224 ground-truth cases.
Leave-one-out across all 32,267 published 2026 IDs corroborates: k=3 → 60.6% / 99.37%.

Self-validating: every RBP that later publishes reveals its true owner, so precision is
re-measured on every build and printed on the site.

### F6: persistence is real; this is not publication lag
Re-queried all 456 IDs from the 2026-07-19 snapshot, 32 days later (already ≥14 days
public when captured):

```
still RESERVED   232   (~46+ days RBP minimum)
now  PUBLISHED   224   (self-healed, proves these were real)
```

Of the 224 resolved, **213 were GitHub_M** vs. the old engine's inference of 70, current
attribution under-calls by ~3x.

### F7, the policy's numeric thresholds no longer exist (correction)
An earlier draft of this plan built a per-CNA scoreboard around RBP% against a 5%
threshold, sourced from a PDF hosted by INCIBE. That document is **RBP Policy v1.0 and is
superseded.** The canonical policy at `cve.org/Resources/General/Policies/RBP-CVE-IDs-Policy.pdf`
is **v2.0.0, approved 2026-08-13**, and contains no percentage anywhere in its text -
verified by regex over the full document, and pinned in `tests/fixtures/rbp_policy_v2.json`.

Consequences, all of which are already applied below:

- There is no policy threshold for the site to test a CNA against. `/cnas` becomes
  **descriptive**, not judgmental: counts, ages, and a normalised rate labelled explicitly
  as *this site's own statistic*, never as a program limit. No "over the line" flags.
- The judgment moves to `/cves`, where it is properly anchored: **72 hours**, from a rule
  that is current and quoted verbatim.
- A normalised rate is still worth showing so a large CNA with 200 RBPs is not compared
  naively against a five-person CNA with two, but it carries no threshold and no verdict.

The CVE Program has no public RBP metric. It had one: a quarterly table (4,326 in 2017 Q1
falling to ~350-550 by 2021) that went live in February 2021 and was commented out of the
Metrics page on **2022-02-07**. The markup survives in `main`; the data file has no RBP
series; the rendered page contains no "Reserved but Public" string. Since v2.0.0 names
"Program metrics and audits" as an RBP identification channel, the public face of that
channel has been switched off for four and a half years.

Correction worth recording: an earlier draft of this claimed the page "still promises
figures from 2017 to present and stops at Q3 2021." That came from reading the repo source
rather than the live DOM, and the section is commented out. Read the rendered page before
asserting what a site says.

---

## 2a. Editorial stance

**The site leads with the count.** *"We are publishing the dashboard they should have
published."*

That is literally true, and it is a stronger position than criticism. The CVE Program
shipped a quarterly RBP table in February 2021 and commented it out on 2022-02-07. This
site resumes an abandoned Program artifact rather than attacking anyone, which keeps it
useful rather than merely critical and makes every CNA a potential ally instead of a
target.

Design consequences, binding on phase 4:

- Count above the fold, refreshed every six hours. It is the number people cite and the
  reason to come back.
- The `owning_cna` redaction is the immediate subhead. It explains why the count had to be
  assembled from outside rather than read off cve.org.
- The removed Program metric gets its own section lower down. Documented, dated, checkable.
- **Never lead with a per-CNA leaderboard.** `/cnas` exists and is reachable, but the front
  page is a measurement, not a ranking.
- Visual register is instrument panel, not exposé. Inherit cve.icu's system, which already
  reads that way.

## 3. What the site claims, precisely

| claim | basis | strength |
|---|---|---|
| This ID is Reserved and publicly referenced, for N days | API state + dated advisory, re-verified every run | fact |
| This is the CNA that reserved it | k=3 block inference, precision re-measured every build | inference, graded |
| This ID has been RBP for N days, past the 72-hour rule | dated advisory + confirmed RESERVED state | fact |
| This CNA has X RBPs outstanding, oldest N days | aggregation of the above over named rows | derived, floor |

Plus the front-page claim, which costs nothing and is unambiguous: **the policy's only
enforcement is discretionary and exercised in private, and the field required to audit it
is redacted.**

### Never say
- "This CNA violated the rules." Say: over the threshold the program itself set.
- Anything about severity, exploitability, or risk. Publishing completeness only
  (VISION.md principle 3 carries over).
- An inferred owner below the k=3 gate: publish the row with the owner blank, and say why.
- **No vulnerability detail beyond the advisory summary, and no pointer to code.** The
  published `description` is the advisory's own summary, sanitised by
  `classify.display_description` and cut at the first sentence boundary. Removed before
  publication: all URLs, and all vulnerability-tracker annotations (`NOTE:`,
  `DEBIANBUG`, `Introduced with:`, `Fixed by:`, `Bug:`, `References:`), from the first
  marker onward.

  The line this replaces said "beyond the verbatim advisory title already public
  downstream", which described neither the code nor the intent. The code was slicing 180
  raw characters, so four rows shipped Debian tracker annotations and two of those were
  `Introduced with: <commit URL>`. An introducing-commit pointer is not vulnerability
  detail, it is a pointer to the vulnerable code, republished inside a curated list of
  CVE IDs chosen precisely because no record has been published. "Debian publishes it
  first" is true and is the exact aggregation argument this site is built on, so it is
  not a defence available to us.

  The field itself stays: 52 of 96 named rows carried an empty package and CSAF rows
  carry none at all, so the summary is the only identifier a defender has. Deleting it
  would make the site less useful without making anyone safer.

  Enforced twice on purpose. Cleaned deterministically upstream, and asserted at publish
  time in `site.assert_artefact`, which refuses any published description containing a
  URL or an annotation. The assertion is a backstop that can only fire if the sanitiser
  breaks; unlike the `NOTE:` guard it replaced, the thing it catches is a disclosure
  harm rather than an ugly string, so blocking is the right direction (8b class 1).

---

## 4. Architecture

All in Actions; Pages serves static files. No server, no DB, no secrets beyond `GITHUB_TOKEN`.

| step | what | measured cost |
|---|---|---|
| **cache**     | restore corpus from Actions cache; cold-pull the 583 MB `all_CVEs` once; apply hourly `delta_CVEs` every run | 583 MB cold / 4.1 MB warm, 1,961 records per delta |
| **gather**    | port the 10 adapters from `rbp/feeds.py`; collect referenced IDs + earliest reference date | OSV all.zip 1.51 GB/20s, Debian 86 MB/1.5s, Arch 0.9 MB, Alpine 81 KB/branch |
| **resolve**   | for every referenced ID absent from corpus, call `/api/cve-id/` at 24 threads; partition RESERVED / PUBLISHED / REJECTED / UNKNOWN | 94 req/s, 456 IDs in 4.9s, limit 25,000/min |
| **attribute** | k=3 gate against corpus; re-grade last run's inferences against newly-published truth; emit live precision | local |
| **score**     | hours-since-public vs the 72h expectation; MUST/SHOULD split; per-CNA outstanding, oldest, time-to-publish | local |
| **render**    | Jinja2 → HTML + `rbp.json` / `rbp.csv` / per-CNA endpoints; client-side sort+filter on preloaded JSON | est. 3–8 MB payload |
| **deploy**    | `upload-pages-artifact` → `deploy-pages`; history to a `data` branch, never `main` | deploys >10 min time out |

Schedule: every 6 hours + `workflow_dispatch`. Fine-grained resolution makes the
self-healing story visible.

### Hard limits we live inside

| constraint | limit | our position |
|---|---|---|
| Pages published site | 1 GB | <1%, payload is a few MB |
| Pages deploy timeout | 10 min | deploy step only; build is separate |
| Pages bandwidth | 100 GB/mo soft | real risk at launch, see R7 |
| Source repo recommended max | 1 GB | corpus never committed: non-negotiable |
| Actions cache | 10 GB/repo, 7-day idle evict | ~600 MB, refreshed 6-hourly so never idles |
| Actions job timeout | 6 h | target <15 min warm |
| CVE Services rate limit | 25,000/min | peak ~5,600/min at 24 threads |

---

## 5. Pages

Visual system inherits cve.icu directly, port `web/static/css/style.css` and extend.
Same tokens, same dark-mode toggle, same card/stat-grid grammar. Do not redesign.

| route | purpose | must nail |
|---|---|---|
| `/`            | headline count, aging distribution, live precision, WoW movement | the redaction thesis in one sentence above the fold |
| `/cves`        | full table: ID, package, days RBP, sources, owner, advisory link | measures the **72h per-record rule**; sortable by days RBP, deep-linkable filters. The page people cite |
| `/cnas`        | descriptive: RBP count, oldest outstanding, time-to-publish distribution, normalised rate | **no threshold flags: v2.0.0 has no threshold.** Every rate labelled as this site's statistic, not a program limit; min-denominator guard visible |
| `/cna/<name>`  | per-CNA detail, full rows, time-to-publish history | the page a CNA lands on, make it fair and complete |
| `/method`      | definitions, k=3 gate, live precision, feed inventory, limits | every number on the site links here |
| `/policy`      | v2.0.0 quoted, the v1.0→v2.0.0 change shown side by side, the redaction demonstrated live | the withdrawal of the arithmetic trigger is the story; show the actual API response |
| `/data`        | JSON, CSV, per-CNA endpoints, schema, licence | stable URLs, others building on this is the win condition |
| `/changes`     | new / resolved / still-open since last run | resolutions as prominent as additions |

Resolved rows stay visible 30 days marked *Published, resolved in N days*. A tracker
that only accumulates looks like a grudge; one that visibly closes rows looks like an
instrument, and the closures prove the open rows are real.

---

## 6. Build sequence

- **Phase 0, port and re-found** (½ day). Lift `rbp/` into this repo. Strip snapshots,
  the 550 MB zip, PDF/email artefacts. `.gitignore` the corpus. MIT, CNAME, Pages→Actions.
  *Done when* `python -m rbp.cli run` reproduces the old snapshot in a clean checkout.
- **Phase 1: replace the oracle** (1 day). Rewrite `classify.py` against `/api/cve-id/`.
  Retire `DNE`; taxonomy becomes RESERVED / PUBLISHED / REJECTED / UNKNOWN. Thread-pooled
  with backoff and a circuit-breaker that fails the build rather than publishing a partial scan.
  *Done when* the 456 historical IDs reclassify to 232 / 224, matching today's probe.
- **Phase 2: inference + self-grading** (1 day). ✅ DONE. k-neighbour gate at k=3;
  grader scoring earlier runs against newly-published truth → `precision.json`;
  `run_coverage` reported separately from validation coverage. CI reproduces
  60.8%/99.35% (LOO) and 59.8%/100% (out-of-sample), 39 tests.
  **Correction found while building:** coverage is population-dependent, precision is
  not. A live run over alas+alpine named only **24% of reportable rows**, not the 59.8%
  the validation set suggests, live RBPs cluster in interleaved regions of the ID
  space where no CNA owns the neighbourhood. Loosening the gate does not fix it (k=2
  bought one extra row for 0.25pt of precision; k=1 bought five and dropped LOO
  precision to 97.75%, brushing the kill floor). The binding constraint is the shape of
  the ID space. **The site must show each run's actual naming coverage next to the
  method's validated precision, and never present the latter's coverage as the
  former's.** Also decided by measurement: the product→CNA map never names a CNA alone
  (85% precision as a fallback) and REJECTED records are not used as neighbours
  (too rare to matter).
- **Phase 2.5, prove the pipeline in CI** (half a day). DONE 2026-08-20. Cold run 16 min,
  warm run 9 min, both green. Warm run took the delta path (1 day, 2,100 records, corpus
  380,846 to 381,167) instead of the 583 MB baseline. Ledger round trip proven: restored
  360 outstanding, grew to 367, snapshots now persisting to the `data` branch.
  Four defects fixed, three of which only a real run would have surfaced:
  baseline freshness keyed on the hourly release tag rather than the daily asset date;
  no incremental path at all; the Actions cache pointed at a path nothing writes, which
  also reset the grader ledger every run; and OSV npm had never been ingested, because a
  220 MB archive read through a 100 MB in-memory cap truncates into an invalid zip while
  the build reports success. Streaming archives to disk recovered npm and Hex, worth
  ~1,650 referenced IDs. Feed health now prints a DEGRADED banner rather than letting a
  broken feed read as improvement.
  Two branch-hygiene bugs worth remembering: `rm -rf ./*` does not match dotfiles, so the
  orphan `data` branch was created carrying `.github/` and `.gitignore`, and the inherited
  ignore file listed `snapshots/`, so the first state commit silently dropped every
  snapshot while reporting success.
  *Outstanding:* a non-zero graded count. The ledger persists correctly, but nothing has
  been graded yet because no predicted ID published in the 15 minutes between the two
  runs. It resolves on its own within a day or two.
- **Phase 3, the 72-hour clock** (1 day). Per-row hours since first public reference
  against the 72h expectation; `self_disclosed` splitting 4.5.1.4 (MUST) from 4.5.1.6
  (SHOULD); per-CNA aggregation, outstanding count, oldest, time-to-publish distribution
  from resolved RBPs. Normalised rate for scale context only: min-denominator guard,
  Wilson interval, labelled as this site's statistic. **No threshold flags, v2.0.0 has
  no threshold.**
  *Done when* no page renders a percentage beside a pass/fail verdict, and the MUST/SHOULD
  split shows on every row.
- **Phase 4: site build** (2 days). Port cve.icu CSS + base template. Eight routes.
  Client-side sort/filter with deep-linkable query state. JSON/CSV with documented schema.
  *Done when* cold build <20 min and Lighthouse ≥95 perf + a11y.
- **Phase 5: harden the loop** (1 day). Feed-health surfacing, history to `data` branch
  with compaction, failure alerting, staleness banner past 24h.
  *Done when* killing a feed produces a degraded-coverage banner, not a smaller count.
- **Incident switch and rehearsal (round 3, items 1 and 2).** `RBP_PAUSE=1` as a
  repository variable holds publication: the pipeline still runs and still reports, but
  nothing is staged to the data branch and nothing deploys. The `dry_run` dispatch input
  does the same for one run, so a candidate epoch, a gate flip or a buffer change can be
  rehearsed against real data before it is published. There was previously no lever at
  all, so an unattended six-hourly tick could not be held while a fix landed.
  Every path leaving the runner is checked against an allowlist before the push, and the
  check refuses any file off the list and any row naming a CNA on an uncounted row.
  Verified against both historical leaks: it catches `backlog_full.json` by path and the
  `held_back.json` named row by content.
  Snapshot retention keeps the current snapshot, the previous one and one per month. An
  unbounded public log of every row ever named, including names later withdrawn, grew four
  times a day and no correction on the site could reach it.
- **Pre-launch posture (in force now).** `/` serves the holding page and the dashboard
  sits at `/overview.html`, noindexed, with the holding page carrying no link into it.
  The dashboard is still built and the data files are still served, because the repo is
  public either way: the gate is on what the front door presents, not on hiding anything.
  Flip with the `RBP_LAUNCHED` repository variable, so launching is a settings change
  rather than a commit.
- **Launch-day reset (decided 2026-08-20).** On launch the count starts from zero rather
  than carrying the backlog gathered while coverage was still changing. Implemented as
  `RBP_EPOCH`, a date set via repository variable, keyed on the **advisory date** and not
  on when this site first saw a row. That choice is load-bearing: keyed on first-seen, a
  newly added feed would inject hundreds of years-old RBPs into the headline count, which
  is exactly the instability the reset exists to avoid. Keyed on the advisory date the
  count means "went public since launch and still unpublished", and feed expansion cannot
  inflate it retroactively.
  Only the backlog resets. The grader ledger and the resolution ledger are explicitly NOT
  reset, because zeroing the grader would drop the measured precision to n=0 on launch day
  and turn the accuracy claim back into a promise. Held-back rows keep their real ages,
  stay in the raw data, and their count is disclosed on `/method` and `/cves`: a filter
  that removes the oldest and strongest evidence has to be visible.
- **LAUNCH GATE: 50% CNA coverage, on `cnas_effective`.** Nothing is shared or promoted
  publicly until feeds touch at least **half of all CNAs**, counting a CNA as touched
  only once at least `MIN_SIGHTINGS` (3) of its published CVEs have been seen. That is
  deliberately the same floor `inference.attribute` requires before it will attach a
  name, so the gate cannot clear on CNAs the site would then refuse to name.

  **Three coverage figures exist and only one is the gate.** They differ by a factor of
  sixty, so naming which one is being quoted matters more than the number:

  | figure | means | 2026-08-21 |
  |---|---|---|
  | `cnas_sighted` | any one of its CVEs was seen, even once | 159 / 434 = **36.6%** |
  | `cnas_effective` | seen >= 3 times. **This is the gate.** | 121 / 434 = **27.9%** |
  | `cnas_own_channel` | its own advisory feed is ingested | 2 / 434 = **0.5%** |

  Reaching the gate needs 217 effective, so roughly **96 more CNAs**.

  Earlier revisions of this line quoted 36.4% and 40.6%: those were `cnas_sighted`,
  where a single incidental reference credits a CNA. The gate was briefly *coded*
  against `cnas_own_channel`, which is bounded by the number of hand-written owner-feed
  parsers (three), giving a 0.7% ceiling against a 50% threshold: **the gate could never
  clear**, and because failing a gate and not yet meeting one produce the identical
  pre-launch site, nothing surfaced it. `test_gate_threshold_is_reachable` now asserts
  the gate figure can reach its own threshold.

  The site stays live throughout; the gate is on promotion, not deployment. Below half
  the landscape the backlog reads as a partial sample of whichever ecosystems happen to
  be instrumented, and a CNA absent from the site could fairly say the measurement never
  looked at it. Expansion targets are the Tier A and Tier B lists in VISION.md; a generic
  CSAF ingester is the highest value-per-effort item, since one fetch unlocks many
  vendor CNAs.
- **Phase 6: notify, then go loud**. Site is live throughout; before *promoting* it,
  send per-CNA row exports plus a note to the QWG and Secretariat. Not permission-seeking -
  a correction window that makes "you never told us" unavailable.

---

## 7. Risk register

- **R1 (high): MITRE removes or authenticates `/api/cve-id/`.** The whole RESERVED signal
  is one undocumented public endpoint. *Mitigate:* snapshot every observed state transition
  to the `data` branch from day one so the record survives independently; keep `/api/cve/`
  as a flagged fallback; state in `/method`, before it happens, that closing the endpoint
  in response to this site would itself be a transparency reduction. Do not scrape beyond
  candidate IDs; give no operational reason to close it.
- **R2 (high), a named CNA is named wrongly.** 100% on 134 cases is not infallible.
  *Mitigate:* k=3 never lower; publish measured precision beside every inferred name;
  one-click correction on every CNA page applied within one build cycle with a visible
  changelog; label the column *Inferred owner*, never *Assigner*; show prediction vs. truth
  side by side once revealed, including misses.
- **R3 (high), a row is under legitimate embargo.** *Mitigate:* keep the buffer (7 days by
  default, 2.3x the 72h expectation, and configurable);
  reproduce only advisory titles already public downstream, never detail; embargo-exception
  path that suppresses a row on request, with suppressions counted and disclosed in
  aggregate so the mechanism can't hide the problem.
- **R4 (medium), a feed dies quietly and the numbers shrink.** Most likely failure mode;
  silently corrupts the trend. *Mitigate:* per-feed counts asserted against a rolling median,
  build fails past tolerance; feed-health table with last-success timestamps; never publish
  a degraded run without a banner. Phase 5, not optional.
- **R5 (medium): "you're doing the Secretariat's job badly."** *Mitigate:* §4.5.1.7 permits
  the Secretariat to name; it doesn't prohibit anyone else from computing. But win on frame,
  not technicality: *we would rather not be doing this, unredact the field and we'll point
  at yours instead.* Footer of every page. It's a standing offer, and it's true.
- **R6 (medium): small-denominator CNAs pilloried by arithmetic.** A five-person CNA with
  4 RBPs against 14 published reads as 28.6% and tops a leaderboard above Microsoft. Worse
  now that no policy threshold exists to justify the ranking at all.
  *Mitigate:* rank by absolute count, not rate. Suppress the rate below a denominator floor
  (start at 20 published/12mo) and show the raw count instead; Wilson lower bound where a
  rate is shown; label every rate as this site's descriptive statistic. No verdict attaches
  to a rate anywhere on the site.
- **R7 (medium): launch traffic exceeds 100 GB/mo.** *Mitigate:* paginate JSON, small
  summary for first paint, detail lazy-loaded; gzip at build; content-hashed filenames;
  raw dumps as separate downloads, not page dependencies.
- **R8 (low): repo bloat.** *Mitigate:* corpus never committed; orphan `data` branch with
  compacted daily rollups; quarterly aggregation past 12 months. Set the rule in Phase 0.
- **R9 (low): 583 MB cold pull on cache miss.** *Mitigate:* 6-hourly runs mean the cache
  never idles; key on release tag with a restore-key prefix; cold path ~15 min, inside the
  6-hour job limit and never touching the 10-minute deploy step.

---

## 8. Kill criteria

- **Out-of-sample precision below ~97%** on a meaningful sample → pull the owner column,
  run counts-only until fixed. Naming is defensible only while measurably right.
- **The still-reserved population collapses** → the program is working and the premise is
  weaker than the snapshot suggested. Report that as prominently as bad news would have been.
- **MITRE unredacts `owning_cna`** → the site has won. Say so, then pivot to being the
  historical record and time-to-publish instrument.

**The one thing to get right:** lead with the redaction, not the leaderboard. It's the
finding nobody else has, it's unarguable, it implicates a process rather than a company,
and it makes every CNA reading the site a potential ally rather than a target. The
leaderboard is the evidence; the redaction is the story.

---

## 8a. Settled metric decisions (2026-08-20)

- **Headline column is descriptive: "N days public".** Not "N days overdue" and not hours
  past 72. The clock we can observe starts at the earliest downstream advisory we can see,
  which is a floor on how long the ID has been public, not the rule's CNA-awareness clock.
  A descriptive number stays true under that limitation; an "overdue" number asserts more
  than the evidence supports. Past-72h is shown as a separate marker, not baked into the
  number.
- **"Out of scope" means out of compliance, loosely.** It does NOT mean the CVE Program's
  sense of a CNA's declared assignment scope. Avoid the word "scope" in site copy
  entirely, because it collides with that term. Declared-scope violations are a different
  project and are noted only as possible future work.
- **Buffer defaults to 7 days and is configurable.** 2.3x the 72h expectation. Precedence
  is dispatch input, then the `RBP_MIN_AGE_DAYS` repository variable, then
  `report.DEFAULT_MIN_AGE_DAYS`, so widening it under CNA pushback is a settings change
  rather than a commit. Measured against the 716-row backlog of 2026-08-20:

  | buffer | multiple of 72h | reportable |
  |---:|---:|---:|
  | 3d | 1.0x | 572 |
  | **7d** | **2.3x** | **546** |
  | 14d | 4.7x | 485 |
  | 30d | 10.0x | 412 |

  85 rows come from undated feeds and can never be reportable at any buffer, which is its
  own honest limitation to state on `/method`.

## 8b. Guard taxonomy (review r3 item 10)

Every guard in this codebase answers one question: **what does it cost to be wrong in
each direction?** Getting that backwards has now caused more outages than the bugs the
guards were added for, so the rule is written down rather than re-derived each time.

**Three kinds of guard, and only the first may stop a publication.**

1. **Refuse: the data would make a false statement about a named third party.**
   Publishing is worse than not publishing, so raise and fail the build. A name on an
   uncounted row, a name absent from `cnas.json`, a name outside the covered set, an
   ungated `product_map_*` field, a ledger prediction for an unpublished row. These are
   `rbp.publish.check` and `site.assert_artefact`, and they must stay loud.

2. **Clean: the data is correct but ugly.** Fix it at the publishable boundary and
   continue. A description reading `NOTE: bookkeeping`, `[unknown]` or `security update`
   is poor display text, not a misattribution. `report._clean_description` falls back to
   the package name.

3. **Report: the run is degraded but honest.** Publish, and publish the degradation
   beside it. A failed feed, a truncated feed, an undated row, an unmeasurable disclosure
   ordering, a precision figure below `GRADER_MIN_N`. Never silently drop, never block.

**Never fail dark.** The deploy job is `needs: build` with no `if:`, so anything that
exits non-zero in `build` skips the deploy and Pages serves the previous artefact
indefinitely with no notification. A guard in class 1 is worth that cost. A guard in
class 2 or 3 is not: it freezes the site four times a day over cosmetics, and it looks
identical to a build problem.

### The two mistakes this section exists to prevent

Both happened on 2026-08-21, in opposite directions, and neither was caught by a test.

- **A class-2 problem written as a class-1 guard.** `assert_artefact` was made to refuse
  any description starting with `NOTE:`. Six such rows exist in live data, so the first
  real gated deploy went red on data that was entirely correct. Fixed by cleaning
  instead. *Tell: the guard's failure message could not name a third party who would be
  harmed by publishing.*

- **A guard that could never fire, and looked exactly like one that had not fired yet.**
  The launch gate was keyed to `cnas_own_channel`, bounded by three hand-written
  owner-feed parsers, so a 50% threshold had a 0.7% ceiling. Nothing failed: an
  unreachable gate and a distant gate produce the identical pre-launch site. Found by
  reading a summary artefact by hand. *Tell: no test asserted the guard's own threshold
  was satisfiable.* `test_gate_threshold_is_reachable` now does.

The second is the more dangerous shape, because the failure is silence. **A guard whose
threshold is a number needs a test that the number is reachable**, and a guard whose
"blocked" state is indistinguishable from its "not yet" state needs something that tells
them apart.

## 8c. Disclosure decisions (2026-08-22)

Deliberately de-identified. Naming the organisations here would republish the pairing
being retracted, in the document that records it as false, which is review finding C1.
The specifics stay recoverable from the archived mirror described in
`docs/github-support-request.md`.

### The two misattributed rows: decided not to notify

Two rows carried a **WordPress-plugin-ecosystem CNA named on a core Linux platform
vulnerability**, surfaced only through distro advisory feeds that such a CNA's scope
never touches. Item 3's covered-set gate and bulk-reporter rule were built to stop
exactly this. Both rows now read `unattributed` / `abstain` / `owner_nameable: false`,
and zero WordPress-ecosystem CNAs are named anywhere in production.

**Decision: do not notify the two CNAs. Jerry, 2026-08-22.**

Measured exposure, which is what the decision turns on:

| | |
|---|---|
| Window the names were public | **~2h55m**, across 7 commits |
| Served by rbptracker.org | **No.** Never a page; the ungated file was git-branch only |
| Repo reach in that window | 0 stars, 0 forks, repo under 3 hours old |
| Now | removed from branch history; reachable only by exact blob SHA |

**Why.** The notification principle in `report.py` exists so a CNA is never *publicly*
accused without a way to respond. It is the right principle and it is why the per-CNA
pages stay withheld pre-launch. It does not fit this case: there was no public
accusation surface, the window was under three hours, and there is no correction for
them to make, because the error was ours and it is fixed. Writing to them would mean
disclosing reserved-CVE analysis to two organisations not otherwise party to it, in
order to report a mistake they were never harmed by and cannot act on. Same reasoning
as the GitHub ticket in the same session: do not manufacture an incident.

**The counterargument, recorded because it is real.** The blobs stay fetchable by exact
SHA until GitHub garbage collects. The retraction is closed against discovery and open
against replay. If that residual is ever judged to outweigh the above, notifying becomes
defensible and this decision should be revisited rather than treated as settled.

**What this decision is not.** It is not a precedent for a named row after launch. Once
`/` is the dashboard and the per-CNA pages are live, a misattribution has a public
accusation surface by definition, the reasoning above inverts, and the notification
principle applies in full. Phase 6's correction channel is the mechanism for that and is
still unbuilt, which is the strongest argument for keeping the launch gate where it is.

## 8d. Launch go/no-go checklist (review Part 2)

**Promotion requires all nine. Coverage is condition 1, not the whole test.** The
adversarial review found that five of its own findings had assumed the coverage gate was
the only gate, which is why this exists as a list. It is published on `/method` as well as
recorded here, because the panel's ask was that the commitment be checkable from outside,
and a checklist only in this file is a promise to ourselves.

Live status is generated by `rbp/launch.py` and rendered on `/method`. Conditions 1, 2, 3
are derived from the run; the rest are declared in that module with the reason they are
not met. **3 of 9 met as of 2026-08-22.**

| # | Condition | State | Item |
|---|---|---|---|
| 1. | Coverage on `cnas_effective`, on the profile the cron actually runs, against a **pinned roster**, with top-50-by-volume alongside | **not yet.** 27.9% of 50%; roster is per-run, not pinned | 7 |
| 2. | No ungated name on any world-readable artefact, enforced at publish time and not by a test | **met.** `rbp.publish.check`, a workflow step | 2, 9 |
| 3. | Every named CNA inside the covered set for the run that named it, as a build invariant | **met.** `site.assert_artefact` plus a second check in `publish.check` | 3 |
| 4. | A monitored non-public correction channel, a suppression lever behind it, and a published aggregate withheld count | **not yet.** Nothing exists | 4 |
| 5. | The 24-hour naming warrant bound in code, with a floor that refuses to run below it | **met.** `report.validate_min_age`, 4-day floor | 8 |
| 6. | One precision figure, stratified, with its sample composition in the same sentence | **not yet.** Withholding below n=20 hides this rather than solving it | 21 |
| 7. | A dated immutable archive, so a pre-launch citation stays resolvable after the epoch flip | **not yet.** No durable target | 2, 14 |
| 8. | A failure notification exists, and has been exercised once | **not yet.** Nothing beyond the default Actions email | 10 |
| 9. | The launch state rehearsed via `dry_run` against real data, including the epoch flip | **not yet.** The lever exists and has never been pulled | 1 |

**Two things this checklist is deliberately not.**

It does **not** gate the build. `site._gate_status` still sets the posture on coverage
alone and `publish.gate` still fails a below-gate launch attempt. Making nine conditions
each capable of halting a publication that runs four times a day would freeze the site
over paperwork, which is precisely the class-2-guard-written-as-class-1 mistake in 8b, at
nine times the scale. It is advisory to a human, and that is the correct altitude.

It is **not** a coverage substitute. Condition 1 can be met while eight others are not,
and the reverse. The number everyone watches is one row of this table.

**Note on condition 1.** Three of its four requirements are about being able to trust the
percentage rather than about its value: the profile recorded, the denominator pinned, and
top-50 reported alongside. Only the profile is currently true. The denominator is
recounted from the corpus every run, so the percentage is trended over a moving base and
will shift overnight on 1 January when the year window rolls. A pinned roster is a
prerequisite for treating any coverage figure as progress rather than as weather.

## 9. Still open

- **"Days out of scope", confirm the metric.** Built here as *days in RBP state*: days
  since earliest downstream reference, for an ID still Reserved. A floor on the true clock,
  not the rule's CNA-awareness clock. If you meant something else, it changes the headline column.
- **Years in scope.** Engine currently scans 2025–2026. Backfilling to 2020 would surface
  long-tail reserved-hoarding at real API cost, do it once offline as a launch artefact.
- **REJECTED-but-public.** Publicly referenced then rejected is a different pathology and
  arguably worse for consumers. Out of scope for v1; note it.
- **Feed expansion before or after launch.** Tier-A list in VISION.md (GitLab, Wolfi, SUSE,
  Oracle, Rocky, Gentoo) raises the floor on every percentage. Instinct: launch at current
  coverage with the floor framing intact, then let each added feed be its own news beat.

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
- and no public Program RBP metric. The live Metrics page reports published records and
  reserved IDs and nothing on the overlap between them. Verified in the rendered DOM
  rather than the source: the string "Reserved but Public" does not appear on
  cve.org/About/Metrics.

> **The history of that metric came out on 2026-08-27**, here and from every page of the
> site. This section used to narrate when an earlier RBP table appeared, when it stopped
> being published, and why that was probably innocent. Even written charitably, raising
> the question plants it: a reader who arrives with no theory about it leaves with one.
> The measurement stands on the current fact alone, which is the bullet above.

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

> **The n=224 figure is lopsided, and this is where that is stated.** 213 of those 224
> cases were a single CNA (GitHub_M), so eleven cases informed every other CNA in the
> Program, and both rows this project is known to have got wrong were outside the 213.
> Quote it only with that composition attached.
>
> The **leave-one-out** figure is the broadly based one and is what the site publishes:
> measured 2026-08-22 at 99.39% over 29,614 decisions spread across 345 CNAs, with 56
> above the n=20 floor, the largest single CNA accounting for 24.3% of decisions, and the
> tail excluding that CNA at 99.19% over 22,413 decisions. Those two figures are not
> interchangeable and neither is a substitute for the live graded figure, which stays
> withheld below n=20.

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

The CVE Program has no public RBP metric. The Metrics page carries no "Reserved but
Public" string and `metrics.json` has no RBP series. v2.0.0 names "Program metrics and
audits" as an RBP identification channel, and nothing in public shows what that channel
reports.

Lesson worth keeping from an earlier draft of this section, which asserted what the
Metrics page "still promises" on the strength of the repo source and was wrong: **read the
rendered page before asserting what a site says.** The source and the DOM disagree, and
only one of them is what a reader sees.

---

## 2a. Editorial stance

**The site leads with the count.**

Publishing a measurement is a stronger position than criticising the absence of one. The
site states what is observable and stops there, which keeps it useful rather than merely
critical and makes every CNA a potential ally instead of a target.

> **The justification for this stance was rewritten on 2026-08-27.** It used to claim the
> site was supplying an instrument the Program itself ought to have been publishing,
> resting on the history of an earlier Program RBP table and when it stopped being
> published. The old wording is deliberately not quoted here. That framing came out of
> the site, the README and this file on the same day: it argues from what someone else
> failed to do, and the measurement does not need it. The stance itself is unchanged and
> the reasoning below still holds.

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
- **Launch-day reset: RETIRED 2026-08-27, unused.** Decided 2026-08-20, never fired, and
  the window for it has closed. The reasoning below is kept because the mechanism is still
  in the code and still correct; what changed is that it no longer has a moment to be
  used in.

  The site launched on 2026-08-26 without an epoch being set, and has been indexable at
  around 1,700 rows ever since. Setting `RBP_EPOCH` now would take a publicly indexed
  count to **zero**: measured on the 2026-08-27 snapshot, no row has an advisory date on
  or after today, and only 50 rows are on or after 2026-08-20. The reset existed to avoid
  launching on a backlog gathered while coverage was still changing; launching on that
  backlog is what happened, and zeroing a number the world has already seen is a larger
  instability than the one the reset was designed to prevent.

  **What stays.** `RBP_EPOCH` remains a working repository variable, `rbp/clock.py` still
  keys on the advisory date, the held-back archive is still published on every run, and
  the launch-day zero state is still rendered and still tested. That is deliberate
  insurance rather than dead weight: if this project ever needs to restart a count, the
  machinery is there and proven, and the reason it was not used is here rather than in
  someone's memory.

  Jerry's call, 2026-08-27. The original reasoning follows.

  Implemented as
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

## 8aa. Review Part 1: complete (2026-08-22)

All twenty Part 1 items are closed, with per-item notes in REVIEW.md. Item 15 carries
three named remainders rather than being marked done: `feed_csaf` calls `record_feed` on
no path at all, so "Huawei yields 0" and "Huawei was never reached" are
indistinguishable and CSAF is the only route to every ICS and enterprise vendor; `_get`
still launders a 404 into an empty page for adapters other than ubuntu; and the
comparability guard compares status names rather than window edges, so a moved page
boundary still renders as "No longer listed".

**What actually found the defects.** Five of this session's bugs were found by running
the thing rather than by the suite, and every one lived at a seam between stages: a guard
that blocked correct data, a launch gate with an unreachable ceiling, 521 rows published
under a headline of 522, a withheld row surviving in the accuracy ledger, and iterating
an object that cannot be enumerated by design. A sixth, fourteen mangled `<thead>` tags,
was found only by querying the parsed DOM; every string-level test passed.

The suite is thorough about what the data IS and thin about the seams between stages and
about what the data is SAID to mean. That is the gap to aim the next review at.

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
exactly this.

> ### CORRECTION, 2026-08-23. The exposure table below was wrong and the decision rests on it.
>
> The sentence that used to stand here, *"Both rows now read `unattributed` /
> `abstain` / `owner_nameable: false`, and zero WordPress-ecosystem CNAs are named
> anywhere in production"*, was true of the SITE and false of the DATA BRANCH.
> Measured directly on `origin/data`:
>
> ```
> resolutions.json  open.CVE-2026-9238.owner  = "Wordfence"   (package: qemu)
> resolutions.json  open.CVE-2026-16566.owner = "WPScan"      (package: ansible)
> ```
>
> | | recorded below | **actually measured** |
> |---|---|---|
> | Window the names were public | ~2h55m | **50.8 hours and counting** |
> | Commits carrying them | 7 | **43** |
> | Now | "removed from branch history" | **live at the branch tip** |
>
> First appearance `cb77d67`, 2026-08-20T22:29:37Z. Still present at `db1e017`,
> 2026-08-23T01:20:23Z. The names were never on a rendered page, which is the one
> line of the original table that holds.
>
> Cause: `ResolutionLedger.track` writes the owner under `if cid not in open`, so
> the FIRST name wins permanently. Both rows were recorded on 2026-08-20, the gate
> that now abstains on them was added afterwards, and nothing ever revisits an
> existing entry. `publish.check` could not see it: its content rule globs
> `snapshots/*/*.json`, so root-level files were exempt by construction.
>
> **The leak is closed** as of the de-naming commit: staging strips every
> attribution field from every staged file, and `publish.check` now walks the whole
> tree. That fixes the future. It does not un-publish 43 commits of git history.
>
> **The decision below is therefore reopened, and it is Jerry's to make.** Section
> 8c set its own trigger: *"If that residual is ever judged to outweigh the above,
> notifying becomes defensible and this decision should be revisited."* A 50.8-hour
> live window across 43 public commits is a different fact pattern from a 2h55m one
> that was described as already removed. Two things follow, neither of them mine to
> decide: whether to notify Wordfence and WPScan, and whether to re-root the data
> branch to drop the history. **No history has been rewritten.**

**Decision as originally recorded: do not notify the two CNAs. Jerry, 2026-08-22.**
**Status: REOPENED 2026-08-23 on the corrected exposure figures above.**

Exposure as originally recorded, retained so the correction has something to point at:

| | |
|---|---|
| Window the names were public | ~2h55m, across 7 commits |
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

**Promotion requires all eight. Coverage is condition 1, not the whole test.** The
adversarial review found that five of its own findings had assumed the coverage gate was
the only gate, which is why this exists as a list. It is published on `/method` as well as
recorded here, because the panel's ask was that the commitment be checkable from outside,
and a checklist only in this file is a promise to ourselves.

Live status is generated by `rbp/launch.py` and rendered on `/method`. Conditions 1, 2, 3
are derived from the run; the rest are declared in that module with the reason they are
not met. **8 of 8 met as of 2026-08-26.** Condition 4 was RETIRED that day with the withhold channel it described; the numbering is deliberately not closed up, because the numbers are how the review's items are cited elsewhere.

| # | Condition | State | Item |
|---|---|---|---|
| 1. | Coverage on `cnas_effective`, on the profile the cron actually runs, against a **pinned roster**, with top-50-by-volume alongside | **not yet.** 27.9% of 50%; roster is per-run, not pinned | 7 |
| 2. | No ungated name on any world-readable artefact, enforced at publish time and not by a test | **met.** `rbp.publish.check`, a workflow step | 2, 9 |
| 3. | Every named CNA inside the covered set for the run that named it, as a build invariant | **met.** `site.assert_artefact` plus a second check in `publish.check` | 3 |
| ~~4.~~ | ~~A monitored correction channel, a suppression lever behind it, and a published aggregate withheld count~~ | **RETIRED 2026-08-26** with the channel. It existed so a CNA could contest a row that NAMED it, and v1 names nobody; every listed row is a CVE ID already public in an advisory and held for the reportable buffer. ~1,470 lines, a repository secret and an `issues: read` permission on the publishing job, removed. An email address in `security.txt` remains, read by a person. **The cost:** no automatic route and no published withheld count, so a removal now has no audit trail. If the site ever names a party again this comes back with it | 4 |
| 5. | The 24-hour naming warrant bound in code, with a floor that refuses to run below it | **met.** `report.validate_min_age`, 4-day floor | 8 |
| 6. | One precision figure, stratified, with its sample composition in the same sentence | **met.** Floor moved into `inference.summarise_state`, so the two-answers bug is gone; LOO stratified by owner with the floor per stratum | 21 |
| 7. | A dated immutable archive, so a pre-launch citation stays resolvable after the epoch flip | **met.** `/data/archive/<date>/rbp.json` plus an index. Described as **stable, not immutable**: a withhold removes a row from it too | 2, 14 |
| 8. | A failure notification exists, and has been exercised once | **met.** One issue per failure episode, auto-closed on recovery. Exercised for real by a bug of mine, not by the drill | 10 |
| 9. | The launch state rehearsed via `dry_run` against real data, including the epoch flip | **met** on the third attempt. The first was impossible, the second was green and did not rehearse, the third broke the suite | 1 |

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

## 8e. Panel decision: rendering in CI (2026-08-23)

A four-persona panel was asked how CI should cover the half of accessibility that
genuinely needs layout: horizontal overflow at a given viewport, and the 768px
breakpoint collision. Recorded here because the decision is not implemented yet
and should not be lost.

**Decision: a browser on the COMMIT path only. Nothing new on the publish path.**

The panel's own investigation is the reason. A reviewer served the built site and
measured it, and found that the review's proposed assertion would not have caught
the review's own defect: at 375px the card layout IS correctly active and the
document still overflowed 926px, because `style.css` sets `white-space: nowrap`
at 768px and the card layout never reset it. And at exactly 768px, where the
collision is worst, `scrollWidth - clientWidth` is **0** and the check passes,
because `.tablewrap { overflow-x: auto }` absorbs the overflow before the
document sees it while hiding 74% of every row behind a nested scrollbar.

So `scrollWidth <= clientWidth` is necessary and not sufficient, and the check
that does catch 768 is a computed-style agreement check: at every width at or
below the mobile boundary, `thead` being `display: none` must agree with `td` not
being `nowrap`. Producing that value means running the cascade, specificity
resolution and media-query evaluation, which is the definition of a browser.
Option (b), a CSS parser, was rejected on measurement rather than on taste.

**The shape, so it cannot become a false-green or an outage:**

- a new `render` job, `needs: test`, on push and pull_request only, NOT in
  `deploy.needs`, so there is no skip cascade and the publish path is unchanged
- `render` added to `notify.needs`, so a failure is reported
- Playwright pinned in a separate `requirements-browser.txt`, never in
  `requirements-dev.txt`, so `pytest tests/ -q --ignore=tests/render` stays the
  offline default at about 11 seconds
- widths parsed from the `@media` preludes in both stylesheets as {b-1, b, b+1}
  plus 320/375/1280, never typed
- the served `?v=` hash asserted against the file on disk, because two reviewers
  silently measured the wrong document
- focus rings exercised by real Tab traversal, since `.focus()` does not arm
  `:focus-visible`

**Given up, explicitly:** per-tick browser coverage. Three experiments agreed
that after `overflow-wrap: anywhere` and `min-width: 0`, document overflow no
longer varies with feed data, so a scheduled tick has nothing new to render. If
that is wrong the failure is silent, and the fix is to move `render` into
`deploy.needs` with the notify wiring already in place.

**Also given up:** detecting the `render` job being deleted rather than failing.
Branch protection sees red, not absent. The panel refused the cross-branch hash
handshake proposed to close that, on the grounds that it puts a new false-green
surface on the publication path to guard against an edit only the maintainer can
make.

**Status: IMPLEMENTED, 2026-08-24.** `render` in `ci.yml`, `needs: test`, 29
tests in `tests/render/` against a headless Chromium, 4.3 seconds locally. The
offline default is unchanged at about 10 seconds and now passes
`--ignore=tests/render` explicitly, in `ci.yml` **and** in `deploy.yml`: the
render tests skip themselves without Playwright, but a collection-time error in
their conftest would still have failed the job that gates a four-times-daily
publication.

The shape shipped as specified, with one deviation and two corrections. All three
are recorded because each of them was a belief this document held that turned out
to be wrong when it was executed.

**Deviation: `render` is NOT in `notify.needs`.** It cannot be. `notify` is a job
in `deploy.yml` and a job cannot depend on a job in another workflow, and the
panel's other constraint, "push and pull_request only", is precisely `ci.yml`'s
trigger set. Living in a different workflow is a stronger version of "not in
`deploy.needs`" than the panel asked for: there is no skip cascade to reason
about at all. The notification is given up on the argument that it exists for
UNATTENDED publication, where "a silent stop looked exactly like a quiet week",
and a push or a pull request is attended by definition, with a red required check
reaching the person who caused it faster than a bot issue would. If `render` ever
moves onto the publish path it goes into `deploy.yml` and into `notify.needs`
together.

**Correction 1. The computed-style agreement check does not catch 768.** This
section says the check "that does catch 768 is a computed-style agreement check".
It is not, and `tests/render/test_mutations.py` proves it by executing the pre-fix
stylesheet: at 768px the thead is displayed AND the cells are `nowrap`, so both
halves report "not card layout", they agree, and an agreement check passes. What
catches 768 is a **card-mode assertion** (at or below the boundary the card layout
must be ON) together with the **nested-scrollbar measurement**, which is the
one that reproduces the panel's own finding of ~74% of every row hidden. The
agreement check earns its place on the OTHER defect, the 926px overflow at 375px,
where the card layout is correctly active and `nowrap` was never reset. Both
checks are needed and neither is redundant. Two mutation tests assert the
negative result directly, so if a future browser starts reporting document
overflow at 768 the reasoning here is revisited rather than the assertion quietly
deleted.

**Correction 2. `.focus()` does arm `:focus-visible`, sometimes.** This section
says focus rings need real Tab traversal "since `.focus()` does not arm
`:focus-visible`". Measured: Chromium matches `:focus-visible` on a scripted
`.focus()` when there has been **no user interaction yet**, because it treats
"nothing has happened" the same as "keyboard". The distinction only appears after
a real pointer press, which is the state most readers are in. The conclusion is
unchanged and the reason for it is different, which is exactly the kind of
half-true premise that makes a test confidently wrong. Traversal is still driven
by real key presses; the premise is now asserted rather than assumed.

**Two false-greens closed that the panel's shape did not name.** A browser job
that installs nothing, downloads no browser or collects zero tests exits green
and covers nothing, so `RBP_RENDER_TESTS=1` turns every skip in that directory
into a failure and a second step refuses a suite that collects fewer than 20
tests. And the width sweep's own parser is covered by the OFFLINE suite in
`tests/test_breakpoints.py`, because a parser that silently stops finding
breakpoints leaves three fixed widths, every render check still passes, and the
pixel that broke is the one nobody measured.

**The fixture is synthetic, and that is guarded rather than hoped.** CI has no
`snapshots/` on the commit path. `tests/render/test_mutations.py` strips the card
layout entirely and requires `/cves` to overflow at 320px and 375px: if the
fixture rows are ever too short or too few to exercise reflow, that test fails
rather than every overflow assertion in the package quietly becoming vacuous.
Three further guards in the conftest fail the build if `changes.html`,
`backlog-at-launch.html` or `method.html` render no table, because each was a
real way to leave five `.rbp` tables unmeasured while the suite stayed green.

The contrast half needs no browser, is done, and is still covered offline;
`tests/test_a11y.py` now says which half it is and where the other one lives.

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

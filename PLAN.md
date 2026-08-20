# rbptracker.org — build plan

Public tracker for **RBP** CVE IDs: IDs in the `RESERVED` state that are referenced in
public advisories but have no published CVE Record. Lists the CVE, the owning CNA, and
how long it has been RBP. GitHub Pages + GitHub Actions only.

Drafted 2026-08-20. All figures below were measured against live sources on that date,
not estimated.

---

## 1. Why this exists

The CVE Program's **Policy and Procedure for RBPs** is arithmetic, not vibes:

- RBP % > **5%** of the CVE IDs a CNA made public in the past 12 months → the CNA must
  publish RBP records before receiving new IDs; while over the line it gets one new
  reserved ID per RBP published.
- RBP % > **50% for more than three months** → limited to **25%** of normal yearly ID
  output for a year (or until the parent CNA is satisfied, whichever is longer).

Every input to those thresholds is invisible outside the Secretariat. The site makes the
observable half public and reconstructs the redacted half with a graded method.

---

## 2. Verified findings (2026-08-20)

### F1 — the bulk CVE List contains zero RESERVED records
Full state census over the `all_CVEs` release, 365,232 records, 9.2s:

```
PUBLISHED  347,571
REJECTED    17,659
RESERVED         0
```

The policy's numerator is invisible in the bulk feed.

### F2 — the git tree does not carry reserved stubs either (corrects VISION.md)
`cves/2026/26xxx` in `CVEProject/cvelistV5`: 487 files present in the 26000–26999 range,
**513 IDs absent**. The small stub files are `REJECTED`, not `RESERVED`. Cloning the
2.63 GB repo buys nothing. Drop that approach.

### F3 — `/api/cve-id/` exposes the true state, unauthenticated  ← the unlock
Not `/api/cve/` (which 404s on reserved IDs — this is why the current engine mislabels
everything `DNE`). The reservation endpoint:

```
GET https://cveawg.mitre.org/api/cve-id/CVE-2026-2574
{"cve_id":"CVE-2026-2574","cve_year":"2026","state":"RESERVED","owning_cna":"[REDACTED]"}

GET https://cveawg.mitre.org/api/cve-id/CVE-2026-26100
{"state":"PUBLISHED","owning_cna":"Nozomi"}
```

Rate limit header: `ratelimit-policy: 25000;w=60`. Measured 94 req/s at 24 threads;
456 IDs resolved in 4.9s.

**Consequence:** every row the current engine calls `DNE` becomes `RESERVED` — the
policy's own literal definition of RBP. The "these might be typos" objection dies.

### F4 — `owning_cna` is redacted on exactly the population the policy governs
Sampled 2023–2026. Every `PUBLISHED` ID returns a real `owning_cna`. Every `RESERVED` ID
returns `[REDACTED]`. No partial disclosure, no aged unblinding — despite CNA
Operational Rules §4.5.1.7 permitting the Secretariat to name the reserving CNA 24 hours
after public disclosure.

**This is the site's thesis.** The field is populated, served, and masked by choice.

### F5 — block inference reconstructs the owner, 100% precision out-of-sample
CVE IDs are issued in runs. If published IDs bracketing a reserved ID agree on one
assigner, that assigner very likely owns the reserved one. Tested on the *real RBP
population*: predicted from the 2026-07-14 corpus, graded against IDs that published
after.

| gate | coverage | precision | verdict |
|---|---:|---:|---|
| k=1 | 86.2% | 99.5%  | aggressive |
| k=2 | 65.2% | 99.3%  | — |
| **k=3** | **59.8%** | **100.0%** | **ship this** |
| k=5 | 50.9% | 100.0% | costs coverage for nothing |

k = published IDs required on *each* side, all agreeing. n=224 ground-truth cases.
Leave-one-out across all 32,267 published 2026 IDs corroborates: k=3 → 60.6% / 99.37%.

Self-validating: every RBP that later publishes reveals its true owner, so precision is
re-measured on every build and printed on the site.

### F6 — persistence is real; this is not publication lag
Re-queried all 456 IDs from the 2026-07-19 snapshot, 32 days later (already ≥14 days
public when captured):

```
still RESERVED   232   (~46+ days RBP minimum)
now  PUBLISHED   224   (self-healed — proves these were real)
```

Of the 224 resolved, **213 were GitHub_M** vs. the old engine's inference of 70 — current
attribution under-calls by ~3x.

### F7 — the policy's own 5% metric is computable, as a floor
Denominator from the corpus (384 CNAs published in the trailing 12 months). Sanity check
on the resolved-owner subset only:

| CNA | observed RBP | published 12mo | floor RBP% | |
|---|---:|---:|---:|---|
| OpenVPN  | 4   | 14    | 28.57% | **over 5%** |
| GitHub_M | 213 | 8,856 | 2.41%  | |
| Gitea    | 1   | 49    | 2.04%  | |
| redhat   | 3   | 523   | 0.57%  | |

Our numerator only counts feed-visible RBPs, so every percentage is a **lower bound**.
That is a strength: if a CNA's floor already exceeds 5%, the breach is unarguable.
Watch the small-N trap (OpenVPN is 4/14) — see R6.

---

## 3. What the site claims, precisely

| claim | basis | strength |
|---|---|---|
| This ID is Reserved and publicly referenced, for N days | API state + dated advisory, re-verified every run | fact |
| This is the CNA that reserved it | k=3 block inference, precision re-measured every build | inference, graded |
| This CNA is above the program's own 5% threshold | floor RBP% vs published-12mo, min-denominator guard | derived, floor |

Plus the front-page claim, which costs nothing and is unambiguous: **the public cannot
audit this policy because the program redacts the field required to audit it.**

### Never say
- "This CNA violated the rules." Say: over the threshold the program itself set.
- Anything about severity, exploitability, or risk. Publishing completeness only
  (VISION.md principle 3 carries over).
- An inferred owner below the k=3 gate — publish the row with the owner blank, and say why.
- Vulnerability detail beyond the verbatim advisory title already public downstream.

---

## 4. Architecture

All in Actions; Pages serves static files. No server, no DB, no secrets beyond `GITHUB_TOKEN`.

| step | what | measured cost |
|---|---|---|
| **cache**     | restore corpus from Actions cache; cold-pull the 583 MB `all_CVEs` once; apply hourly `delta_CVEs` every run | 583 MB cold / 4.1 MB warm, 1,961 records per delta |
| **gather**    | port the 10 adapters from `rbp/feeds.py`; collect referenced IDs + earliest reference date | OSV all.zip 1.51 GB/20s, Debian 86 MB/1.5s, Arch 0.9 MB, Alpine 81 KB/branch |
| **resolve**   | for every referenced ID absent from corpus, call `/api/cve-id/` at 24 threads; partition RESERVED / PUBLISHED / REJECTED / UNKNOWN | 94 req/s, 456 IDs in 4.9s, limit 25,000/min |
| **attribute** | k=3 gate against corpus; re-grade last run's inferences against newly-published truth; emit live precision | local |
| **score**     | trailing-12mo published per CNA; floor RBP%; 5%/50% flags; 3-month persistence | local |
| **render**    | Jinja2 → HTML + `rbp.json` / `rbp.csv` / per-CNA endpoints; client-side sort+filter on preloaded JSON | est. 3–8 MB payload |
| **deploy**    | `upload-pages-artifact` → `deploy-pages`; history to a `data` branch, never `main` | deploys >10 min time out |

Schedule: every 6 hours + `workflow_dispatch`. Fine-grained resolution makes the
self-healing story visible.

### Hard limits we live inside

| constraint | limit | our position |
|---|---|---|
| Pages published site | 1 GB | <1%, payload is a few MB |
| Pages deploy timeout | 10 min | deploy step only; build is separate |
| Pages bandwidth | 100 GB/mo soft | real risk at launch — see R7 |
| Source repo recommended max | 1 GB | corpus never committed — non-negotiable |
| Actions cache | 10 GB/repo, 7-day idle evict | ~600 MB, refreshed 6-hourly so never idles |
| Actions job timeout | 6 h | target <15 min warm |
| CVE Services rate limit | 25,000/min | peak ~5,600/min at 24 threads |

---

## 5. Pages

Visual system inherits cve.icu directly — port `web/static/css/style.css` and extend.
Same tokens, same dark-mode toggle, same card/stat-grid grammar. Do not redesign.

| route | purpose | must nail |
|---|---|---|
| `/`            | headline count, aging distribution, live precision, WoW movement | the redaction thesis in one sentence above the fold |
| `/cves`        | full table: ID, package, days RBP, sources, owner, advisory link | sortable by days RBP, deep-linkable filters — this is the page people cite |
| `/cnas`        | scoreboard: floor RBP%, count, oldest outstanding, threshold flags | "floor" labelled on every percentage; min-denominator guard visible |
| `/cna/<name>`  | per-CNA detail, full rows, time-to-publish history | the page a CNA lands on — make it fair and complete |
| `/method`      | definitions, k=3 gate, live precision, feed inventory, limits | every number on the site links here |
| `/policy`      | the RBP policy quoted + the redaction demonstrated live | show the actual API response |
| `/data`        | JSON, CSV, per-CNA endpoints, schema, licence | stable URLs — others building on this is the win condition |
| `/changes`     | new / resolved / still-open since last run | resolutions as prominent as additions |

Resolved rows stay visible 30 days marked *Published — resolved in N days*. A tracker
that only accumulates looks like a grudge; one that visibly closes rows looks like an
instrument, and the closures prove the open rows are real.

---

## 6. Build sequence

- **Phase 0 — port and re-found** (½ day). Lift `rbp/` into this repo. Strip snapshots,
  the 550 MB zip, PDF/email artefacts. `.gitignore` the corpus. MIT, CNAME, Pages→Actions.
  *Done when* `python -m rbp.cli run` reproduces the old snapshot in a clean checkout.
- **Phase 1 — replace the oracle** (1 day). Rewrite `classify.py` against `/api/cve-id/`.
  Retire `DNE`; taxonomy becomes RESERVED / PUBLISHED / REJECTED / UNKNOWN. Thread-pooled
  with backoff and a circuit-breaker that fails the build rather than publishing a partial scan.
  *Done when* the 456 historical IDs reclassify to 232 / 224, matching today's probe.
- **Phase 2 — inference + self-grading** (1 day). k-neighbour gate; grader scoring last
  run against newly-published truth → `precision.json`; wire into templates.
  *Done when* CI reproduces 60.6%/99.37% (LOO) and 59.8%/100% (out-of-sample).
- **Phase 3 — policy scoring** (1 day). Trailing-12mo denominators, floor RBP%, 5%/50%
  flags, 3-month persistence. Min-denominator guard + Wilson interval on every rate.
  *Done when* the scoreboard reproduces F7 and no sub-floor CNA shows a percentage.
- **Phase 4 — site build** (2 days). Port cve.icu CSS + base template. Eight routes.
  Client-side sort/filter with deep-linkable query state. JSON/CSV with documented schema.
  *Done when* cold build <20 min and Lighthouse ≥95 perf + a11y.
- **Phase 5 — harden the loop** (1 day). Feed-health surfacing, history to `data` branch
  with compaction, failure alerting, staleness banner past 24h.
  *Done when* killing a feed produces a degraded-coverage banner, not a smaller count.
- **Phase 6 — notify, then go loud**. Site is live throughout; before *promoting* it,
  send per-CNA row exports plus a note to the QWG and Secretariat. Not permission-seeking —
  a correction window that makes "you never told us" unavailable.

---

## 7. Risk register

- **R1 (high) — MITRE removes or authenticates `/api/cve-id/`.** The whole RESERVED signal
  is one undocumented public endpoint. *Mitigate:* snapshot every observed state transition
  to the `data` branch from day one so the record survives independently; keep `/api/cve/`
  as a flagged fallback; state in `/method` — before it happens — that closing the endpoint
  in response to this site would itself be a transparency reduction. Do not scrape beyond
  candidate IDs; give no operational reason to close it.
- **R2 (high) — a named CNA is named wrongly.** 100% on 134 cases is not infallible.
  *Mitigate:* k=3 never lower; publish measured precision beside every inferred name;
  one-click correction on every CNA page applied within one build cycle with a visible
  changelog; label the column *Inferred owner*, never *Assigner*; show prediction vs. truth
  side by side once revealed, including misses.
- **R3 (high) — a row is under legitimate embargo.** *Mitigate:* keep the 14-day buffer;
  reproduce only advisory titles already public downstream, never detail; embargo-exception
  path that suppresses a row on request, with suppressions counted and disclosed in
  aggregate so the mechanism can't hide the problem.
- **R4 (medium) — a feed dies quietly and the numbers shrink.** Most likely failure mode;
  silently corrupts the trend. *Mitigate:* per-feed counts asserted against a rolling median,
  build fails past tolerance; feed-health table with last-success timestamps; never publish
  a degraded run without a banner. Phase 5, not optional.
- **R5 (medium) — "you're doing the Secretariat's job badly."** *Mitigate:* §4.5.1.7 permits
  the Secretariat to name; it doesn't prohibit anyone else from computing. But win on frame,
  not technicality: *we would rather not be doing this — unredact the field and we'll point
  at yours instead.* Footer of every page. It's a standing offer, and it's true.
- **R6 (medium) — small-denominator CNAs pilloried by arithmetic.** OpenVPN 28.57% is 4/14.
  *Mitigate:* suppress the percentage below a denominator floor (start at 20 published/12mo)
  and show raw count; Wilson lower bound for ranking; default sort by absolute count.
- **R7 (medium) — launch traffic exceeds 100 GB/mo.** *Mitigate:* paginate JSON — small
  summary for first paint, detail lazy-loaded; gzip at build; content-hashed filenames;
  raw dumps as separate downloads, not page dependencies.
- **R8 (low) — repo bloat.** *Mitigate:* corpus never committed; orphan `data` branch with
  compacted daily rollups; quarterly aggregation past 12 months. Set the rule in Phase 0.
- **R9 (low) — 583 MB cold pull on cache miss.** *Mitigate:* 6-hourly runs mean the cache
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

## 9. Still open

- **"Days out of scope" — confirm the metric.** Built here as *days in RBP state*: days
  since earliest downstream reference, for an ID still Reserved. A floor on the true clock,
  not the rule's CNA-awareness clock. If you meant something else, it changes the headline column.
- **Years in scope.** Engine currently scans 2025–2026. Backfilling to 2020 would surface
  long-tail reserved-hoarding at real API cost — do it once offline as a launch artefact.
- **REJECTED-but-public.** Publicly referenced then rejected is a different pathology and
  arguably worse for consumers. Out of scope for v1; note it.
- **Feed expansion before or after launch.** Tier-A list in VISION.md (GitLab, Wolfi, SUSE,
  Oracle, Rocky, Gentoo) raises the floor on every percentage. Instinct: launch at current
  coverage with the floor framing intact, then let each added feed be its own news beat.

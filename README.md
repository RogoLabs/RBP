# RBP Tracker

[rbptracker.org](https://rbptracker.org) lists **Reserved but Public** CVE IDs: IDs
in the `RESERVED` state that are referenced in a public advisory while the CVE
Record itself is still unpublished. Anyone pulling the CVE List sees nothing. The
advisory is already out there.

The term is the CVE Program's own. Its
[glossary](https://www.cve.org/ResourcesSupport/Glossary?activeTerm=glossaryRBP)
defines it as *"A CVE ID in the 'Reserved' state that is referenced in one or more
public sources but for which a CVE Record has not been published."*

**This site names no CNA.** It publishes the identifier and the advisories it
appears in, and leaves attribution to the Program. See [Why there is no
attribution](#why-there-is-no-attribution).

---

## Why this exists

RBP Policy v2.0.0, approved by the CVE Board on 2026-08-13, expects a record
within 72 hours of disclosure. Enforcement is four discretionary levers the
Program *"may take"*. The previous policy had an automatic arithmetic trigger that
anyone with the data could compute; v2.0.0 removes every numeric threshold.

So there is no public list of RBPs, no public enforcement log, and `owning_cna` is
redacted for exactly the reserved population. This site publishes the observable
half.

**It is a count of a state, not a count of violations**, and it is a Program-level
transparency measurement rather than a CNA scorecard. Every number here is a
**floor**: only configured feeds are read.

---

## How it works

```
ensure corpus  ->  gather feeds  ->  classify  ->  report  ->  build site  ->  publish
```

1. **Corpus.** The full CVE List (`cvelistV5`, ~365k records) is downloaded and
   indexed to parquet. It contains zero `RESERVED` records, which is the whole
   problem: the reserved population is invisible in the bulk data.
2. **Feeds.** 14 public advisory sources are read for CVE IDs
   (`alas`, `alpine`, `arch`, `csaf`, `debian`, `ghsa`, `ghsa-repos`, `mozilla`,
   `msrc`, `osv`, `redhat`, `samsung`, `ubuntu`, `ubuntu-osv`). `ghsa-repos` polls
   repository security advisories one repo at a time, because an advisory with no
   package ecosystem never enters GitHub's advisory database and no page of the
   global endpoint can return it. `ubuntu-osv` reads Canonical's OSV tarball on
   the Ubuntu Security Team's own recommendation; it is year-sharded, so unlike
   the `ubuntu` tracker walk beside it there is no page cap and no reach caveat.
3. **Classify.** Every referenced ID is checked against the CVE Services
   reservation endpoint, which returns the true state for any ID. `RESERVED` plus
   a public reference is an RBP.
4. **Buffer.** A row is reportable only once it has been provably public for at
   least 7 days, which is 2.3x the 72-hour expectation. Configurable.
   The list defaults to the last 90 days, with the full count and a control to
   clear it stated above the rows.
5. **Publish.** A static site plus JSON, CSV and a dated archive, on GitHub Pages,
   four times a day. Five pages: the list at `/`, `/method.html`,
   `/policy.html`, `/status.html` and `/about-this-count.html`. Before launch `/`
   is the holding page instead and the list moves to `/overview.html`.

Whether the last run was complete, which feeds answered, how often the site has
actually published and what moved since the previous run are all on
**`/status.html`**, and nowhere else. The pages that carry the count carry no
banner about the state of the build that produced it. `degraded` in `rbp.json` is
the machine-readable answer, and the floor caveat is in the slide-over panel on
the list page rather than in prose above the rows: that hedge was removed on
2026-08-27, which is a real reduction in disclosure and is recorded in `NEXT.md`
rather than left to be noticed.

No server, no database, no runtime API calls. Every page is a file.

### Repository layout

| path | what it is |
|---|---|
| `rbp/` | the pipeline and the site builder |
| `templates/`, `static/` | the rendered pages, their CSS and the self-hosted font. `_about-copy.html` is the holding-page prose, wrapped by `about.html` for the site route and `holding.html` for the pre-launch front door. `static/fonts/` carries Inter and its licence: the site makes no third-party request |
| `tools/` | authoring scripts run by hand, output committed. Not on the publish path |
| `tests/` | the offline suite; `tests/render/` needs a browser |
| `rbp/verify.py` | invariants on the built artefact, run as a deploy step after the upload. Fails the build on a finding, which skips the deploy: Pages keeps serving the previous artefact. A shortfall the run already recorded as a failure or a truncation publishes instead, with `degraded: true` |
| `feedlab/` | per-feed scorecards, committed as evidence (see `FEEDS.md`) |
| `.github/workflows/` | `ci.yml` on the commit path, `deploy.yml` on the publish path |
| `PLAN.md` | the design record and the launch gate |
| `FEEDS.md` | the feed admissibility rules and how a new feed is scored |
| `NEXT.md` | what to pick up next |

The `data` branch holds durable state between runs: the grader ledger, the run
ledger, the resolution ledger and retained snapshots. `data/` and `site/` are
gitignored; the corpus is ~583 MB and must never enter the repo.

---

## Running it

```bash
pip install -r requirements-dev.txt
```

Build the site from an existing snapshot:

```bash
python -m rbp.cli build --out site
```

Run the whole pipeline (downloads the corpus, hits the reservation endpoint):

```bash
python -m rbp.cli run
```

Run the tests. The offline suite needs no network and takes about twelve seconds:

```bash
python -m pytest tests/ -q --ignore=tests/render
```

The browser suite needs Playwright, and is the commit path only:

```bash
pip install -r requirements-browser.txt && python -m playwright install chromium
RBP_RENDER_TESTS=1 python -m pytest tests/render -q
```

`RBP_RENDER_TESTS=1` turns every skip into a failure. A browser job that silently
skips itself is worse than no browser job, because it reads as coverage.

Lint:

```bash
python -m ruff check .
```

### Levers

All of these are repository variables, so changing one is a settings change rather
than a commit. The suite clears every one of them, so a value in your shell cannot
change a test result.

| variable | effect |
|---|---|
| `RBP_LAUNCHED` | `1` makes `/` the dashboard. Unset, `/` is the holding page and the dashboard is `/overview.html`, noindexed. |
| `RBP_EPOCH` | `YYYY-MM-DD`. Counts only IDs that went public on or after this date. **Retired unused 2026-08-27**: the launch-day reset it existed for passed without being used, and setting it now would take a publicly indexed count to zero. The lever works and is kept as insurance. See `PLAN.md`. |
| `RBP_PAUSE` | `1` runs the pipeline and publishes nothing. |
| `RBP_MIN_AGE_DAYS` | the reportable buffer, in days. |
| `RBP_WITHHOLD` | comma-separated CVE IDs to drop from every page and artefact. |

---

## Why there is no attribution

The state is observable and the CVE Services API confirms it. What it will not
tell you is who reserved the ID: `"owning_cna": "[REDACTED]"`.

Ownership *can* be estimated from public data, and this version does not publish
those estimates. `rbp/inference.py` still runs and the grader still records, so a
future naming release would start from real measured precision rather than from
nothing, but no name crosses the publication boundary.

That boundary is enforced rather than intended:

- `site.NAMING_ENABLED` is the single flag, applied at the writer;
- `schema.ROW_NAME_FIELDS` / `LEDGER_NAME_FIELDS` / `PER_CNA_KEYS` are the one
  definition of what counts as a name, so a new `owner_*` field cannot leak by
  being forgotten in one of several lists;
- `python -m rbp.publish check` refuses to stage any tree in which a certified CNA
  short name appears at all;
- `tests/test_no_attribution.py` asserts it as an import-graph property: importing
  `rbp.cli` must not load `rbp.inference` or `rbp.attribution`.

## There is no removal channel

Retired 2026-08-27. The site previously offered an email address and promised that
a person would apply a removal by hand.

The reasoning is the same one that retired the automated channel a day earlier. A
row appears only after the CVE Services reservation endpoint confirms the ID is
reserved and unpublished, so there is nothing to correct; and every row is a CVE
ID **already referenced in a public advisory**, held for the reportable buffer
before it is listed, on a site that names no CNA, so there is nothing to withhold
that is not already public.

**The cost, stated because it is real.** The case the channel answered was the
embargo rather than the error: a row that is entirely accurate and whose listing
still cuts across a live multi-party disclosure. Verification does not reach that
case, because the row being correct is its premise. That case has no route here.

`RBP_WITHHOLD` still exists, still drops rows from every published artefact and is
still tested. The capability is kept and simply not advertised.

To report a vulnerability in this site's own code, open a [private security
advisory](https://github.com/RogoLabs/RBP/security/advisories/new). That is the
only contact this site offers, and `.well-known/security.txt` says so.

---

## Contributing

Two conventions matter more than style here.

**No feed is merged without its scorecard in the diff.** Run
`python -m rbp.feedlab score <name>` and commit the result under `feedlab/`.
`FEEDS.md` section 2 sets the admissibility tests.

**Mutation-test the fix.** Reintroduce the defect and confirm a test fails. First
passes typically catch about half, and almost every survivor is *fixture
blindness* rather than a product bug: a check that reads a file nobody renders, or
a fixture that never produces the state the assertion is about. On this project,
*the test passes* and *the test works* are different claims, and the gap between
them has cost more time than anything else.

## Licence

Apache 2.0. See [LICENSE](LICENSE).

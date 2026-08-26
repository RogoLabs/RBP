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

The Program used to publish a count of these. A quarterly RBP table went live on
the CVE Metrics page in February 2021 and was commented out on 2022-02-07. The
block is still in `src/views/About/Metrics.vue` on `main`, frozen, its last column
Q3 2021, and `metrics.json` carries no RBP series.

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
2. **Feeds.** 12 public advisory sources are read for CVE IDs
   (`alas`, `alpine`, `arch`, `csaf`, `debian`, `ghsa`, `mozilla`, `msrc`, `osv`,
   `redhat`, `samsung`, `ubuntu`).
3. **Classify.** Every referenced ID is checked against the CVE Services
   reservation endpoint, which returns the true state for any ID. `RESERVED` plus
   a public reference is an RBP.
4. **Buffer.** A row is reportable only once it has been provably public for at
   least 7 days, which is 2.3x the 72-hour expectation. Configurable.
5. **Publish.** A static site plus JSON, CSV and a dated archive, on GitHub Pages,
   four times a day. Five pages: the list at `/`, `/method.html`,
   `/policy.html`, `/status.html` and `/about-this-count.html`. Before launch `/`
   is the holding page instead and the list moves to `/overview.html`.

Whether the last run was complete, which feeds answered, how often the site has
actually published and what moved since the previous run are all on
**`/status.html`**, and nowhere else. The pages that carry the count carry no
banner about the state of the build that produced it: the count's own hedge says
it is a floor on every run, and `degraded` in `rbp.json` is the machine-readable
answer.

No server, no database, no runtime API calls. Every page is a file.

### Repository layout

| path | what it is |
|---|---|
| `rbp/` | the pipeline and the site builder |
| `templates/`, `static/` | the rendered pages and their CSS. `_about-copy.html` is the holding-page prose, wrapped by `about.html` for the site route and `holding.html` for the pre-launch front door |
| `tests/` | the offline suite; `tests/render/` needs a browser |
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
| `RBP_EPOCH` | `YYYY-MM-DD`. Counts only IDs that went public on or after this date. |
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

## Asking for a row to be removed

Email **rbp@rogolabs.net** with the CVE ID and nothing else. No reason, no detail,
no confirmation that a vulnerability exists.

A person reads it and applies the removal by hand, so it takes effect on the next
build. No proof of affiliation is required. There is no automated route and no
published count of withheld rows, so a removal leaves no audit trail on the site;
that was a deliberate trade for a channel with nothing to fail silently.

To report a vulnerability in this site's own code, open a [private security
advisory](https://github.com/RogoLabs/RBP/security/advisories/new) instead.

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

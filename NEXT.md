# Where this stands, and what to pick up next

Rewritten 2026-08-24. Everything below is a fact checked against the repo or the
live feeds on that date, not a plan. The previous version of this file listed
three things waiting; two of them are done and the third is still yours.

---

## What shipped before this session

`main` was at the merge of `denaming-and-gate`, 648 tests. All eighteen blockers
from the eight-persona review were closed.

**v1 publishes no attribution.** No CNA is named as owning an RBP row.
`site.NAMING_ENABLED` is the single flag. Inference and the grader still run, so
a v2 naming release starts from real graded n rather than from one.

**The gate clears.** `GATE_TOP_N_PCT = 80.0` on top-50-CNAs-by-volume at the
3-sighting floor, at 40 of 50 on 2026-08-23 and **41 of 50 on 2026-08-24**. The
re-derivation is recorded in the constant's own comment in `rbp/site.py`.

**The data branch was re-rooted.** `refs/backup/data-pre-reroot` still holds the
old tip **locally only**; it is not on any remote and will be lost if this clone
is.

---

## What shipped in this session

736 tests, 707 of which run offline in about ten seconds.

### The render job, PLAN.md 8e. Implemented.

`render` in `ci.yml`, `needs: test`, 29 tests in `tests/render/` against a
headless Chromium, 4.4 seconds. Not in `deploy.yml` at all, so the publish path
cannot depend on it and there is no skip cascade to reason about. Both `test`
jobs now pass `--ignore=tests/render` explicitly, so a collection error in the
browser directory cannot stop a publication.

Three corrections came out of executing the panel's decision, and all three are
recorded in PLAN.md 8e:

- **The agreement check does not catch 768.** With the pre-fix stylesheets the
  thead is displayed AND the cells are `nowrap`, so both halves say "not card
  layout", they agree, and the check passes. What catches 768 is the card-mode
  assertion and the nested-scrollbar measurement. The agreement check catches the
  other defect, the 926px overflow at 375px. `tests/render/test_mutations.py`
  asserts both negatives directly.
- **`.focus()` does arm `:focus-visible`** when there has been no prior user
  interaction, because Chromium treats "nothing has happened" as "keyboard". The
  distinction only appears after a pointer press. Conclusion unchanged, reason
  different.
- **`notify.needs` could not be honoured.** `notify` is in `deploy.yml` and a job
  cannot depend on a job in another workflow. Deviation and reasoning are in the
  `ci.yml` comment.

Widths are parsed from the `@media` preludes of both stylesheets by
`rbp/breakpoints.py` and bracketed as {b-1, b, b+1}, never typed. That parser is
covered by the OFFLINE suite, because a parser that silently stops finding
breakpoints leaves three fixed widths and every render check still passes.

### The margin question, and what measures it. Answered with numbers.

`rbp/feedlab.py`, the scoring harness FEEDS.md section 3 asks for. Scorecards in
`feedlab/`, which is committed; the multi-megabyte baseline stays under `data/`,
which is not.

**The CSAF sweep buys nothing.** Probed all ten top-50 CNAs the gate cannot see.
One of ten serves CSAF at the well-known path, and it is unusable: Huawei
publishes 121 advisory directories and every one of them returns **401**. Six are
404, one is a WAF 403, one fails TLS verification. Margin has to come from Tier
2's national CERT feeds or from Tier 3, both parsers rather than config lines.

**Every merged feed is now scored against all the others.** 10 detecting, 1
corroborating (`mozilla`), 1 unmeasurable (`arch`). The detecting/corroborating
split, applied today, would exclude nothing and cost **zero** CNAs, against
FEEDS.md's estimate of "0 to 1". The full table is in FEEDS.md section 2.

**Two silent-shrink defects, found by building the harness and both fixed.**
`gather` erased every `CAPPED` state in the same call that recorded it, so
`stats["limitations"]` was permanently empty and the live snapshot reads
`ghsa ok 3321 ids` on a feed that had hit its page cap. And `feed_csaf` recorded
no health at all, on the one adapter that fans out to seventeen third parties, so
Huawei's 401s and Cisco's 403 read as a clean run. Both are mutation-tested.

---

## The three things waiting for you

### 1. Rehearse the withhold channel from a permissionless account

**Unchanged, and still nobody's job but yours.** Launch condition 4 is
deliberately UNMET. The channel is reachable in code and covered by tests, and
the original defect hid specifically in the configuration where the requester has
no repository permissions. No test written from inside the repo can prove it
works from outside, and this session did not change that.

    file a withhold request from a spare GitHub account that has no access
    to RogoLabs/RBP, using the template at
    https://github.com/RogoLabs/RBP/issues/new?template=withhold.yml
    then confirm the row leaves on the next build

If it works, set `verified_on` for condition 4 in `rbp/launch.py` to the date and
flip it to MET. If it does not, the failure is worth more than the fix.

### 2. Decide whether the margin is acceptable

Still yours to decide, but it is no longer a decision without numbers, and the
number moved while this file was being written.

**Corrected 2026-08-24 against origin/data.** The gate is at **41 of 50 (82.0%)**,
not 40, clearing by one CNA rather than by zero. `hpe` crossed the three-sighting
floor between the 08-23 and 08-24 snapshots. Nobody did anything: HPE published,
a feed saw it three times, and the site's launch gate changed state overnight.

That is the argument about margin, made by the thing itself rather than by
anybody's opinion of it. A gate that moves without a commit can move back.

The nine that would buy more headroom are WPScan, dell, TR-CERT, sap, huawei,
twcert, HCL, qnap, juniper.

**The cheap route is closed.** The CSAF sweep was the highest-leverage item in
FEEDS.md and it returns nothing usable for any of the ten. What remains is a
parser each, at FEEDS.md's own rate of 2 to 3 CNAs per working day including the
scorecard and the test.

So the decision is now between three real options, not two:

- **Launch at one CNA of margin** and accept that a quiet fortnight at two of
  them un-clears the gate. The gate demotes the site to the pre-launch posture
  rather than breaking it, and `publish.gate` makes the demotion a red check
  rather than a silent non-launch. The failure is loud and reversible.
- **Buy margin first**, which is now measured at roughly a day per CNA and
  targets TWCERT and TR-CERT, the two on the list that probed 200 on their own
  advisory sites. Two CNAs of headroom for two days.
- **Widen the gate's basis** so one CNA cannot decide it. Nothing in this session
  touched `GATE_TOP_N_PCT`, deliberately: the threshold was re-derived once
  already after two metric changes, and moving it again to solve a margin problem
  would be the third derivation and the least defensible.

A recommendation, since the measurement produced one and the decision is still
yours: **buy the two CNAs.** One CNA of margin on a figure that moves with
someone else's publishing schedule is not much better than none, and the 40-to-41
step is the evidence: it happened overnight, in the favourable direction this
time. Two days is cheap against explaining why the site un-launched itself in its
first week.

Whichever you pick, run `python -m rbp.feedlab score <name>` before merging any
new feed. No feed goes in without its scorecard in the diff.

### 3. FEEDS.md section 3's three remaining guards

Not started, and correctly so: they are "before feed 10, not after feed 30", and
no feed has been added. They become due the moment option 2 above is chosen.

- per-feed shrink baselines survive a profile change
- a failure budget expressed as a fraction, not a count
- `gather` parallelised, preserving per-feed health recording exactly

The second is the one not to defer past the first new feed. One measurement to
carry forward: the scorecard baseline fetched all 12 feeds in 784 seconds, and
`ubuntu` alone was 486 of them. That is a cold fetch through `feedlab` rather
than the pipeline's warm run, so it is not directly comparable to the 9-minute
figure in FEEDS.md, but the shape is: one feed is most of the wall clock, and
`gather` is a serial loop.

---

## What to be careful of

**Merging to `main` publishes.** `deploy.yml` fires on `push: branches: [main]`.
No repository variables are set, so `RBP_LAUNCHED` is unset and the site deploys
in its **pre-launch** posture: holding page at `/`, dashboard at
`/overview.html`, `robots.txt` disallowing everything. Promotion is a separate,
deliberate act.

**The render job has never executed in CI.** It runs clean locally, 29 tests in
4.4 seconds, and the first push is the first time GitHub's runner installs
Chromium for it. It cannot affect a publication if it fails, by construction.

**PLAN.md 8c is settled but worth re-reading.** The decision not to notify
Wordfence and WPScan was taken on 2026-08-23 against corrected exposure figures,
after the original figures turned out to be wrong by a factor of seventeen. The
correction block is still in 8c; do not let a future reader find only the
original table.

**The lesson that still costs the most time.** Every fix in these sessions was
mutation-tested by reintroducing the defect and confirming a test failed, and
first passes typically catch about half. Almost every survivor is **fixture
blindness rather than a product bug**. It happened twice more this session: two
existing tests asserted that GHSA records its page cap and both passed while
`gather` erased it, because both call the adapter directly and the pipeline never
does; and the feed scorecard's own classifier called `arch` a publication mirror
on 0 dated references out of 0, which is the "cannot read is not nothing to read"
error committed by the tool built to police it.

On this project, *the test passes* and *the test works* are different claims.

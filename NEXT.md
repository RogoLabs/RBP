# Where this stands, and what to pick up next

Written 2026-08-23 at the end of a long session. Everything below is a fact
checked against the repo or the live branches on that date, not a plan.

---

## What shipped

`main` is at the merge of `denaming-and-gate`, 19 commits, 648 tests. All
eighteen blockers from the eight-persona review are closed.

**v1 publishes no attribution.** No CNA is named as owning an RBP row. That was
the review chair's proposal and it removed nine of the eighteen blockers at once,
because nine existed only because the site named parties. `site.NAMING_ENABLED`
is the single flag. Inference and the grader still run, so a v2 naming release
starts from real graded n rather than from one.

**The gate clears.** `GATE_TOP_N_PCT = 80.0` on top-50-CNAs-by-volume at the
3-sighting floor, at **40 of 50**. The old 50%-of-roster threshold was a leftover
from two metric changes and was arithmetically unreachable; the re-derivation is
recorded in the constant's own comment in `rbp/site.py`.

**The data branch was re-rooted**, 52 commits to 1, dropping inferred names that
sat at a stable raw URL. `refs/backup/data-pre-reroot` still holds the old tip
**locally only**; it is not on any remote and will be lost if this clone is.

---

## The three things waiting for you

### 1. Rehearse the withhold channel from a permissionless account

Launch condition 4 is deliberately UNMET and will stay that way until you do
this. The channel is fixed and covered by tests, but the original defect hid
specifically in the configuration where the requester has no repository
permissions, and no test written from inside the repo can prove it works from
outside.

    file a withhold request from a spare GitHub account that has no access
    to RogoLabs/RBP, using the template at
    https://github.com/RogoLabs/RBP/issues/new?template=withhold.yml
    then confirm the row leaves on the next build

If it works, set `verified_on` for condition 4 in `rbp/launch.py` to the date and
flip it to MET. If it does not, the failure is worth more than the fix.

### 2. Decide whether the zero margin is acceptable

The gate clears at exactly 40 of 50. There is no second condition and no
headroom: one CNA dropping below three sightings un-clears it. Ten top-50 CNAs
remain under the floor and any one of them buys margin:

    WPScan, dell, TR-CERT, sap, huawei, twcert, HCL, qnap, juniper, hpe

`FEEDS.md` section 4 has the probes. Read section 2 first: a feed must be able to
surface an RBP, not merely raise coverage, and nothing yet measures the
difference.

### 3. The render job, PLAN.md 8e

Recorded, decided, **not implemented**. A browser on the commit path only, never
in `deploy.needs`. It is the only thing that can catch the 768px class of defect,
because at exactly 768px the collision is worst *and* `scrollWidth - clientWidth`
is 0, so the obvious assertion passes while three quarters of every row hides
behind a nested scrollbar. My recommendation was to land it after launch, because
it is a CI job nobody has watched execute.

---

## What to be careful of

**Merging to `main` publishes.** `deploy.yml` fires on `push: branches: [main]`.
No repository variables are set, so `RBP_LAUNCHED` is unset and the site deploys
in its **pre-launch** posture: holding page at `/`, dashboard at `/overview.html`,
`robots.txt` disallowing everything. Promotion is a separate, deliberate act.

**PLAN.md 8c is settled but worth re-reading.** The decision not to notify
Wordfence and WPScan was taken on 2026-08-23 against corrected exposure figures,
after the original figures turned out to be wrong by a factor of seventeen. The
correction block is still in 8c; do not let a future reader find only the
original table.

**The lesson that cost the most time.** Every fix in this session was
mutation-tested by reintroducing the defect and confirming a test failed. First
passes typically caught about half, and almost every survivor was **fixture
blindness rather than a product bug**: no fixture produced a degraded run, so
`False == False` passed; every suppression test mocked `subprocess` with a fixed
payload, so restoring the exact label filter that caused the bug passed all of
them; the end-to-end harness built only the pre-launch posture, so every writer
gated on `launched` was unreached.

On this project, *the test passes* and *the test works* are different claims. The
a11y fix had to be done twice for exactly this reason: the first pass
parametrised its contrast test over a hand-typed list of seven chips, inside the
commit fixing a review finding about hand-typed lists, and there are eight.

**Fix classes at the root.** The contrast work was repointed rule by rule twice
and missed things both times. Overriding the inherited tokens once fixed nine
live failures that rule-by-rule had not found.

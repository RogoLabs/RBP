export const meta = {
  name: 'review-panel',
  description: 'Seven-persona adversarial review of rbptracker.org, pressure-tested to consensus',
  whenToUse: 'Run at each build milestone before writing more code. Pass args.focus to bias the review, args.rounds to bound the loop.',
  phases: [
    { title: 'Review', detail: 'each persona reviews the repo independently' },
    { title: 'Challenge', detail: 'every persona tries to refute every finding' },
    { title: 'Converge', detail: 'further rounds until nothing new survives' },
    { title: 'Synthesise', detail: 'one agreed, ranked list' },
  ],
}

const REPO = '/Users/gamblin/Documents/Github/RBP'
const MAX_ROUNDS = (args && args.rounds) || 2
const FOCUS = (args && args.focus) || 'the whole project'

// WHY THIS BLOCK CARRIES NO CURRENT NUMBERS.
//
// The previous version pinned nineteen live figures: "~542-559 rows", "~51% of
// rows named", "179 corroborated", "241 candidate MUST", "coverage 158 of 434",
// "LAUNCH GATE: 50%", "currently PRE-LAUNCH". By 2026-08-28 every one of them
// was wrong. The site had 1,691 rows, named nobody, had deleted the
// corroboration count and the /cna and /changes pages, had moved the gate to
// 80% of the top 50 against a pinned roster of 539, and had launched.
//
// A panel briefed on that reviews a site that does not exist, and files findings
// asking for hedges on claims the site stopped making. NEXT.md opens with the
// same lesson about itself: "Its first action item told you to rehearse a
// withhold channel that had been deleted."
//
// So: only facts that do not move live here. Everything that moves is a POINTER
// to where the panel must read it. A stale pointer is a broken link, which is
// obvious. A stale number is a confident lie, which is not.
const CONTEXT = `
PROJECT: rbptracker.org, live and launched. Repo ${REPO}
(public: github.com/RogoLabs/RBP). Built by RogoLabs (Jerry Gamblin).

WHAT IT IS, IN ONE LINE: a list of CVE IDs that are in the RESERVED state, are
cited in a public advisory, and have no published CVE Record, plus the advisories
each one appears in. Here is the data and here are the links. That is the whole
product.

WHAT IT IS NOT, AND THESE ARE DELIBERATE, SETTLED DECISIONS. Do not file a
finding asking for any of them back without new evidence:
- It is NOT a CNA scorecard and it names NO CNA. \`site.NAMING_ENABLED = False\`
  is the single flag, enforced at the writer, and \`python -m rbp.publish check\`
  refuses to stage any tree in which a certified CNA short name appears at all.
  Inference still runs off the publish path so a future release starts from
  measured precision, but no name crosses the boundary.
- It does NOT argue about what the CVE Program did or failed to do. It leads with
  the count and leaves the argument to the reader.
- It publishes no independent-origin count, no per-CNA page, no changes feed and
  no removal channel. Each was built and then removed on purpose, and the
  reasoning for each is recorded in NEXT.md.
- Every number is a FLOOR: only configured feeds are read.

READ THESE BEFORE ASSERTING ANYTHING:
  NEXT.md          what is true now, what was decided and why, what is next.
                   Read this FIRST. It is maintained as part of every change.
  PLAN.md          the design record and the launch gate.
  FEEDS.md         feed admissibility rules; no feed merges without a scorecard.
  README.md        the levers and the repository layout.
  rbp/*.py, templates/*.html, static/css/rbp.css, tests/*.py,
  .github/workflows/deploy.yml

CURRENT NUMBERS ARE NOT LISTED HERE ON PURPOSE. Read them yourself:
  rows, coverage, feed health, degraded state:
      snapshots/<latest>/summary.json and snapshots/<latest>/backlog.json
  the launch gate and whether it clears:  GATE_TOP_N_PCT in rbp/site.py
  the published data contract:            SCHEMA_VERSION in rbp/schema.py
  what the pages actually say:            build it, do not guess:
      python -m rbp.cli build --out /tmp/rbp-review
A finding that quotes a figure you did not read out of the repo will be refuted.

ESTABLISHED EXTERNAL FACTS (verified; do not contradict without new evidence):
- "Reserved but Public" is the CVE Program's own glossary term.
- RBP Policy v2.0.0, CVE Board approved 2026-08-13. It sets a 72-hour
  publication expectation and has NO numeric threshold. Enforcement is four
  discretionary levers the Program "may" apply. v1.0's 5%/50% arithmetic
  thresholds are WITHDRAWN; third parties still host that PDF and it must not
  be cited.
- CNA Operational Rules v4.1.0 (2025-05-14). 4.5.1.4 = MUST publish within 72h
  when the CNA itself disclosed. 4.5.1.6 = SHOULD within 72h when a third party
  disclosed. 4.5.1.7 = the Secretariat MAY name the reserving CNA 24h after
  public disclosure; this site treats that as a self-imposed floor, NOT as
  permission, and says so on /policy.
- GET https://cveawg.mitre.org/api/cve-id/{id} returns the true state including
  RESERVED, unauthenticated. It returns owning_cna for PUBLISHED and REJECTED
  and "[REDACTED]" for RESERVED, i.e. exactly the population the policy governs.
  The bulk CVE List contains ZERO reserved records.
- Because ownership is always inferred for a reserved ID and this version
  infers nothing publicly, no published row can claim 4.5.1.4 MUST. /method
  says so explicitly.

THIS PROJECT'S OWN RECURRING FAILURE MODES, worth aiming at:
- A feed shrinking silently. It has happened twice. A row count that only ever
  goes down triggers a guard; a count held FLAT by a cap or a freeze does not.
- Fixture blindness. "The test passes" and "the test works" are different
  claims here, and the gap has cost more time than anything else. A test that
  reads a file nobody renders, or a fixture that never produces the state the
  assertion is about, is the usual shape.
- A disclosure computed on every run and rendered on no page.
- One stage reading a field another stage owns.
`

// SEVEN PERSONAS, AND THE MIX IS THE POINT.
//
// The previous panel ran eight, of which four were institutional-reputation
// voices: a CNA asking "would you accept your own /cna page" and "where could
// inferred ownership defame you"; MITRE asking about third-party naming; CISA
// asking "does this help defenders or mostly embarrass vendors"; and marketing
// asking "credible instrument or hit piece" and "what reputational risk does
// Jerry personally carry".
//
// Those were the right questions for a site that named CNAs and framed itself as
// the scorecard the Program should have published. This site names nobody and
// publishes an ID and its links. Half a panel asking reputation questions about
// a cancelled product answers them the only way it can: with another hedge,
// another caveat, another guard. That is an engine for overbuilding, and it ran.
//
// So the reputation block collapses to ONE voice, `fairness`, asking the only
// version of the question this site can still fail: is any published sentence an
// accusation rather than an observation. The seats freed go to the audience this
// version actually has, and to a voice whose entire job is to argue for
// deletion, which the old panel had no seat for at all.
const PERSONAS = [
  { key: 'data', label: 'Data Consumer', brief:
    `You build scanners, SBOM tooling and vuln management, and you want to ingest
     this. It is the primary audience: the product is the data and the links.
     Judge rbp.json, rbp.csv, the dated archive and their documentation. Is the
     schema versioned, stable and documented? Are the absence conventions one
     convention rather than three? Can a tool tell "not measured" from "measured
     zero"? Are floor-versus-actual semantics clear enough that nobody silently
     treats the count as complete? What is missing that stops you building on it
     today, and what would you have to hard-code around?` },

  { key: 'defender', label: 'Practitioner Who Arrived From a Link', brief:
    `You are on a security team. Someone sent you a link to this site claiming an
     unpublished CVE affects you. You have five minutes. Judge the site as a
     tool for answering ONE question fast: is this ID real, where is the
     advisory, and does it touch me. Can you filter to what you care about? Does
     the URL you land on still mean the same thing when you paste it into a
     ticket? Does every row's evidence link actually render something, or does it
     lead to a page that shows nothing for a RESERVED ID? What could you not find
     that you would obviously want to?` },

  { key: 'python', label: 'Staff Python Engineer', brief:
    `Judge rbp/*.py as production code someone else maintains: correctness, error
     handling, concurrency, the SSRF-hardened opener, resource leaks, pandas
     correctness and memory on a large corpus, idempotency, and cross-stage
     coupling. Three bugs in this project were one stage reading a field another
     stage owns (days_public, self_disclosed, feed health); look for more of that
     shape. Judge test QUALITY, not test count: find fixtures that cannot produce
     the state their assertion is about.` },

  { key: 'pipeline', label: 'Pipeline and Feed Integrity Lead', brief:
    `You own the run. Judge .github/workflows/*.yml, the data-branch state design
     and rbp/feeds.py health recording together, because the failure that matters
     here crosses them. Correctness under concurrency and partial failure, secret
     and permission scope, unpinned actions, whether state can be corrupted or
     lost, quota and cost. Then the harder half: can a feed degrade WITHOUT any
     guard firing? Caps, freezes, silent truncation, a provider going dark inside
     a fan-out, a health line that reports the aggregate and hides the part. This
     site's worst error is publishing a smaller floor and calling it news.` },

  { key: 'design', label: 'Design and Accessibility Lead', brief:
    `Judge templates/*.html and static/css/rbp.css as a public list people arrive
     at from a link. Information hierarchy, whether the lead number reads
     instantly, scannability of a list in the thousands, small-screen behaviour
     and reflow at 320px, dark and light themes, contrast, focus states, keyboard
     paths, and screen-reader semantics on a JS-rendered list. Judge whether the
     controls are honest: a filter that silently stops filtering, a label that
     reads the same for two different states, a blank cell where a dash belongs.
     Say plainly where copy is wallpaper people scroll past.` },

  { key: 'fairness', label: 'Fairness and Accuracy Reviewer', brief:
    `You have operated a CNA and you have been on the receiving end of a public
     dashboard. This site names no CNA, so the scorecard question is closed. Ask
     the question it CAN still fail: is any published sentence, label, chip,
     ordering or default an ACCUSATION rather than an OBSERVATION? Where does a
     neutral fact acquire a verdict on its way to the page? Does any evidence
     link disprove itself? Does the site distinguish a vendor's own advisory feed
     from an aggregator mirroring it, and does any wording imply the publisher of
     an advisory is the CNA that reserved the ID? Is the embargo case, where a
     row is entirely accurate and still cuts across a live disclosure, honestly
     handled or quietly dropped? What would make you send a lawyer rather than a
     correction.` },

  { key: 'subtract', label: 'Subtraction Advocate', brief:
    `YOUR ENTIRE JOB IS TO ARGUE FOR DELETION, and you have a seat because the
     previous panel had none and the project overbuilt as a result.
     Every finding you file must REMOVE something: a guard that has never fired
     and could not, a caveat that restates a caveat one paragraph up, a field no
     consumer reads, a config lever nobody has set, a test asserting a property
     that cannot vary, a page section that explains instead of showing, a comment
     longer than the code it guards, an abstraction with one caller.
     Weigh each against what it earns. A guard that fired once and prevented a
     real bad publication earns its keep; one written for a hypothetical does
     not. Be specific about what breaks if it goes, and say so honestly when
     something you dislike is load-bearing. Do NOT file findings that add
     anything. If you cannot find real subtractions, file fewer findings.` },
]

const FINDING = {
  type: 'object',
  required: ['findings'],
  properties: {
    findings: {
      type: 'array',
      items: {
        type: 'object',
        required: ['id', 'title', 'severity', 'area', 'evidence', 'why_it_matters',
                   'recommendation', 'net_effect'],
        properties: {
          id: { type: 'string', description: 'short slug, e.g. csv-schema-unversioned' },
          title: { type: 'string' },
          severity: { type: 'string', enum: ['blocker', 'high', 'medium', 'low'] },
          area: { type: 'string', description: 'file or page or subsystem' },
          evidence: { type: 'string', description: 'concrete: file:line, a quoted string, or a reproducible observation. No hand-waving.' },
          why_it_matters: { type: 'string' },
          recommendation: { type: 'string', description: 'the specific change to make' },
          // THE ANTI-OVERBUILD MEASUREMENT, and it is a required field so no
          // finding can dodge it. The old panel had no way to see that its
          // output was almost entirely additive, so nobody noticed it was.
          net_effect: { type: 'string', enum: ['adds', 'removes', 'neutral'],
            description: 'Does the recommended fix add code, copy, config or tests, remove them, or neither? Judge honestly: a new guard, a new caveat and a new field all count as adds.' },
          replaces: { type: 'string', description: 'If net_effect is "adds": what existing thing this makes unnecessary, or "nothing" if it is purely additive. Purely additive findings must clear a higher bar.' },
        },
      },
    },
  },
}

const VERDICTS = {
  type: 'object',
  required: ['verdicts'],
  properties: {
    verdicts: {
      type: 'array',
      items: {
        type: 'object',
        required: ['id', 'stance', 'reasoning'],
        properties: {
          id: { type: 'string' },
          stance: { type: 'string', enum: ['endorse', 'refute', 'amend', 'abstain'] },
          reasoning: { type: 'string', description: 'For refute: the specific reason it is wrong, already handled, or costs more than it fixes. For amend: what to change.' },
          revised_severity: { type: 'string', enum: ['blocker', 'high', 'medium', 'low', ''] },
        },
      },
    },
    new_findings: FINDING.properties.findings,
  },
}

// ---- round 1: independent review ----------------------------------------
phase('Review')
const first = await parallel(PERSONAS.map(p => () =>
  agent(`You are the ${p.label} on an adversarial review panel for a live public
security dashboard. ${p.brief}

${CONTEXT}

Focus of this review: ${FOCUS}.

Read the actual files before asserting anything. Cite file:line or quote exact
strings. A finding with vague evidence will be refuted by the other panellists
and wasted.

Report ONLY defects, risks and gaps that should change before more code is
written. No praise, no summary of what the project does.

THE BAR FOR A FINDING THAT ADDS SOMETHING IS HIGHER THAN FOR ONE THAT REMOVES
SOMETHING. This project's last review pushed it into building guards, caveats
and levers it did not need, because the panel had no way to see that nearly all
of its output was additive. If your fix adds, say what it makes unnecessary, or
say "nothing" and accept that it will be judged as pure addition.

Aim for your 4 to 8 highest-value findings; quality over volume. Prefix every id
with "${p.key}-".`,
    { label: `review:${p.key}`, phase: 'Review', schema: FINDING })
))

let pool = first.filter(Boolean).flatMap(r => r.findings || [])
log(`round 1: ${pool.length} findings from ${first.filter(Boolean).length} personas`)

// ---- rounds 2..N: everyone attacks everything ---------------------------
const refuted = new Map()
const seen = new Set(pool.map(f => f.id))
let round = 1

while (round < MAX_ROUNDS) {
  round += 1
  phase(round === 2 ? 'Challenge' : 'Converge')

  const table = pool.map(f =>
    `[${f.id}] (${f.severity}, ${f.net_effect}${f.replaces && f.replaces !== 'nothing' ? `, replaces: ${f.replaces}` : ''}) ${f.title}
   area: ${f.area}
   evidence: ${f.evidence}
   fix: ${f.recommendation}`).join('\n\n')

  const results = await parallel(PERSONAS.map(p => () =>
    agent(`You are the ${p.label} on the same review panel, now in the
cross-examination round. ${p.brief}

${CONTEXT}

Here is every finding on the table, from all seven panellists:

${table}

Your job is to PRESSURE TEST, not to agree. For each finding you have a real
view on, give a stance:
  refute  = wrong, already handled in the code, based on a misreading, asking
            for something this version deliberately removed, OR costing more
            than the defect it fixes. Check the code before refuting.
  amend   = right in substance but the severity or the fix is wrong.
  endorse = correct and important, and you would defend it. Add anything the
            author missed from your discipline.
  abstain = outside your competence. Use this freely rather than padding.

Refuting a weak finding is as valuable as endorsing a strong one. If a finding
in your own area is wrong, say so.

REFUTE ON COST, NOT ONLY ON CORRECTNESS. A finding can be perfectly accurate and
still be wrong to act on, because the guard, caveat or field it adds costs more
attention than the problem it solves. This project has a documented history of
exactly that. A purely additive finding whose "replaces" is "nothing" should be
refuted unless it prevents real harm.

Then, only if the other panellists' findings revealed something genuinely new to
you, add new_findings. Do not restate anything already on the table. Prefix new
ids with "${p.key}-r${round}-".`,
      { label: `challenge:${p.key}`, phase: round === 2 ? 'Challenge' : 'Converge', schema: VERDICTS })
  ))

  let added = 0
  for (const r of results.filter(Boolean)) {
    for (const v of (r.verdicts || [])) {
      if (!refuted.has(v.id)) refuted.set(v.id, [])
      refuted.get(v.id).push(v)
    }
    for (const f of (r.new_findings || [])) {
      if (!seen.has(f.id)) { seen.add(f.id); pool.push(f); added += 1 }
    }
  }

  // A finding dies when more panellists refute it than defend it. Dedup by
  // persona so one voice cannot outvote itself.
  const survivors = pool.filter(f => {
    const vs = refuted.get(f.id) || []
    const no = vs.filter(v => v.stance === 'refute').length
    const yes = vs.filter(v => v.stance === 'endorse' || v.stance === 'amend').length
    return !(no > 0 && no >= yes)
  })
  const killed = pool.length - survivors.length
  log(`round ${round}: ${added} new, ${killed} refuted out, ${survivors.length} standing`)
  pool = survivors

  if (added === 0) { log('converged: no panellist raised anything new'); break }
}

// ---- synthesis ----------------------------------------------------------
phase('Synthesise')
const adds = pool.filter(f => f.net_effect === 'adds').length
const removes = pool.filter(f => f.net_effect === 'removes').length
log(`standing: ${pool.length} (${adds} add, ${removes} remove, ${pool.length - adds - removes} neutral)`)

const detail = pool.map(f => {
  const vs = refuted.get(f.id) || []
  const votes = vs.map(v => `${v.stance}${v.revised_severity ? ` -> ${v.revised_severity}` : ''}: ${v.reasoning}`).join(' | ')
  return `[${f.id}] (${f.severity}, ${f.net_effect}, replaces: ${f.replaces || 'nothing'}) ${f.title}
   area: ${f.area}
   evidence: ${f.evidence}
   why: ${f.why_it_matters}
   fix: ${f.recommendation}
   panel: ${votes || 'no challenges recorded'}`
}).join('\n\n')

const agreed = await agent(`You are the chair of a seven-persona review panel for
rbptracker.org. The panel was: ${PERSONAS.map(p => p.label).join('; ')}.

${CONTEXT}

These findings survived ${round} rounds of cross-examination:

${detail}

Produce the single combined list the panel agrees needs doing before more code is
written. Rules:

1. Merge duplicates across personas into one item, naming which disciplines
   raised it. Overlap between disciplines is a signal of importance.
2. Rank by what should actually be done first, weighing severity and effort.
   Not by persona order.
3. Set severity from the panel's revised views, not the original claim.
4. Drop anything where the refutations were more convincing than the defence,
   and list those separately with the reason, so they are not silently lost.
5. SEPARATE "FIX THIS" FROM "DELETE THIS", as two lists. This site's product is
   the data and the links; its documented failure mode is accreting guards,
   caveats and levers around them. A review that only adds has failed, however
   correct each item is.
6. Report the balance plainly: how many surviving items add versus remove, and
   whether the net effect of doing everything on this list is a larger or a
   smaller codebase. Say whether that is the right direction here.
7. Be concrete. Each item must name the change and the file or page.
8. If the panel missed something obvious to you as chair, add it, marked as such.

The site is LIVE and LAUNCHED, so do not frame anything as a launch gate.
Frame it as: what is wrong for a reader or a consumer today, and what is
carrying weight it has not earned.

Write it as Markdown suitable for committing as docs/reviews/REVIEW-round9.md.
Use no em dashes anywhere. Start with a two-sentence verdict on whether the
project is on a sound footing, then FIX, then DELETE, then the dropped items,
then the add-versus-remove balance, then a short note on what the panel
disagreed about most and why it matters.`,
  { label: 'chair:synthesis', phase: 'Synthesise', effort: 'high' })

return {
  rounds: round,
  standing: pool.length,
  balance: { adds, removes, neutral: pool.length - adds - removes },
  agreed,
  findings: pool,
  votes: Object.fromEntries(refuted),
}

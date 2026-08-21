export const meta = {
  name: 'review-panel',
  description: 'Eight-persona adversarial review of rbptracker.org, pressure-tested to consensus',
  whenToUse: 'Run at each build milestone before writing more code. Pass args.focus to bias the review, args.rounds to bound the loop.',
  phases: [
    { title: 'Review', detail: 'each persona reviews the repo independently' },
    { title: 'Challenge', detail: 'every persona tries to refute every finding' },
    { title: 'Converge', detail: 'further rounds until nothing new survives' },
    { title: 'Synthesise', detail: 'one agreed, ranked list' },
  ],
}

const REPO = '/Users/gamblin/Documents/Github/RBP'
const MAX_ROUNDS = (args && args.rounds) || 3
const FOCUS = (args && args.focus) || 'the whole project'

// Facts the panel must not have to rediscover, and must not contradict without
// evidence. Keeping these in one place stops eight agents each burning context
// re-deriving them, and stops them inventing different numbers.
const CONTEXT = `
PROJECT: rbptracker.org, live. Repo ${REPO} (public: github.com/RogoLabs/RBP).
Tracks "Reserved but Public" CVE IDs: reserved, cited in a public advisory, no
published CVE Record. Built by RogoLabs (Jerry Gamblin), sibling of cve.icu.

READ THESE FIRST: PLAN.md (full design, findings, risk register, decisions),
rbp/*.py, templates/*.html, tests/*.py, .github/workflows/deploy.yml.

ESTABLISHED FACTS (verified; do not contradict without new evidence):
- RBP Policy v2.0.0, CVE Board approved 2026-08-13. It sets a 72-hour
  publication expectation and has NO numeric threshold. Enforcement is four
  discretionary levers (Warning, Reservation Caps, Intervention, Formal Review)
  that the Program "may" apply. v1.0's 5%/50% arithmetic thresholds are
  WITHDRAWN; third parties still host that PDF and it must not be cited.
- CNA Operational Rules v4.1.0 (2025-05-14). 4.5.1.4 = MUST publish within 72h
  when the CNA itself disclosed. 4.5.1.6 = SHOULD within 72h when a third party
  disclosed (the ordinary distro case). 4.5.1.7 = the Secretariat MAY name the
  reserving CNA 24h after public disclosure. 4.5.3.5 = CNAs MUST reject unused
  or unpublished IDs.
- GET https://cveawg.mitre.org/api/cve-id/{id} returns the true state including
  RESERVED, unauthenticated, 25k req/min. It returns owning_cna for PUBLISHED
  and REJECTED records and "[REDACTED]" for RESERVED ones, i.e. exactly the
  population the policy governs. The bulk CVE List contains ZERO reserved
  records and the git tree carries none either.
- Owner is reconstructed by block inference: name a CNA only when the 3
  published CVE IDs on each side share one assigner. Out-of-sample on the real
  RBP population (n=224): 59.8% coverage, 100% precision. Leave-one-out over
  31,815 published 2026 IDs: 60.8% at 99.35%. A grader marks every prediction
  once the record publishes; production n is currently tiny (1 graded).
- Live numbers: ~542-559 rows, 558/712 past 72h, oldest 519 days, median 38-42,
  ~51% of rows named, 241 candidate 4.5.1.4 MUST, 179 corroborated by 2+
  independent sources, 85 rows undated and unageable at any threshold.
- CNA coverage 158 of 434 (36.4%). LAUNCH GATE: no public promotion until 50%.
- Currently PRE-LAUNCH: / serves a holding page, dashboard at /overview.html,
  noindex. RBP_LAUNCHED flips it. RBP_EPOCH will zero the count on launch day,
  keyed on advisory date.
- Every MUST reading is labelled a candidate, because ownership is always
  inferred for a reserved ID.

KNOWN OPEN ITEMS (say something new, not just these): Ubuntu truncates at a
200-page cap every run; Huawei CSAF yields 0; Cisco CSAF metadata fetch fails;
/changes cannot distinguish "new because a feed was added" from "new because a
CNA missed a deadline"; grader production n is 1.
`

const PERSONAS = [
  { key: 'python', label: 'Python Expert', brief:
    `Staff Python engineer. Judge rbp/*.py as production code someone else must maintain: correctness, error handling, concurrency (ThreadPoolExecutor use, the free-threading story), the SSRF-hardened opener, resource leaks, pandas correctness and memory on a 380k-row corpus, idempotency of the delta upsert, test quality versus test theatre, and cross-stage coupling. Note that three bugs in this project were one stage reading a field another stage owns (days_public, self_disclosed, feed health); look for more of that shape.` },
  { key: 'design', label: 'Web Design and Layout Expert', brief:
    `Design lead. Judge templates/*.html and static/css/rbp.css as a public dashboard: information hierarchy, whether the lead number reads instantly, scannability of a 542-row table, mobile and small-screen behaviour, the inherited cve.icu system versus the additions, dark and light themes, accessibility (contrast, focus states, keyboard, screen-reader semantics on a JS-rendered table, sticky headers), and whether the caveats are legible or wallpaper people scroll past.` },
  { key: 'actions', label: 'GitHub Actions Leader', brief:
    `CI/CD platform lead. Judge .github/workflows/*.yml and the data-branch state design: correctness under concurrency and failure, the cache strategy, secret and permission scope (contents: write pushing to a data branch), supply-chain exposure of unpinned actions, what happens on partial failure or a mid-run cancellation, whether state can be corrupted or lost, quota and cost, and whether a six-hourly schedule with a 583 MB cold path is sound. Consider the blast radius if the token leaked.` },
  { key: 'cna', label: 'CNA Expert', brief:
    `Operates a CNA and has been on the receiving end of a scorecard. Judge fairness and accuracy: would you accept your own /cna page? Where could inferred ownership defame you? Is the MUST/SHOULD split honest given the site cannot observe who disclosed first? Are embargo and coordinated-disclosure cases handled? Is the correction path credible? Does the site distinguish your own advisory feed from an aggregator mirroring it? What would make you send a lawyer instead of a correction.` },
  { key: 'mitre', label: 'CVE Program Leader from MITRE', brief:
    `Runs Program operations. Judge this as the Secretariat would: is the redaction claim accurate and fairly characterised? Is the removed-metrics claim (a quarterly RBP table live Feb 2021, commented out 2022-02-07) fair, and are there innocent explanations the site ignores? Does third-party naming of reserving CNAs conflict with 4.5.1.7 reserving that to the Secretariat? Where does the site overstate, and what is the strongest legitimate objection you would raise publicly?` },
  { key: 'cisa', label: 'CISA Government Leader', brief:
    `Federal cyber leadership. Judge public-interest value and risk: does this help defenders or mostly embarrass vendors? Does surfacing reserved-but-public IDs create exploitation risk or aid attackers with a target list? Are ICS and critical-infrastructure implications handled (CISA is itself a CSAF provider here)? Is the disclosure posture responsible? Would you cite this site, and what would have to be true first?` },
  { key: 'consumer', label: 'CVE Consumer Working Group Leader', brief:
    `Represents downstream consumers: scanners, SBOM tools, vuln management. Judge usability as a data source: are the JSON and CSV schemas stable, documented, versioned? Is there a feed to ingest? Are floor-versus-actual semantics clear enough that a tool will not silently misuse them? Is the undated-rows and coverage-floor caveat prominent enough to stop someone treating the count as complete? What would you need to build on this?` },
  { key: 'marketing', label: 'RogoLabs Marketing Expert', brief:
    `Owns RogoLabs positioning across cve.icu, cnascorecard.org, cveforecast.org. Judge launch readiness and framing: is "the dashboard they should have published" the right stance, and does the site deliver it? Is the lead number the right lead? Will this read as a credible instrument or a hit piece? Is the 50% coverage gate right, too low, or too high? What is the one sentence a journalist quotes, and is it the sentence we want? What reputational risk does Jerry personally carry.` },
]

const FINDING = {
  type: 'object',
  required: ['findings'],
  properties: {
    findings: {
      type: 'array',
      items: {
        type: 'object',
        required: ['id', 'title', 'severity', 'area', 'evidence', 'why_it_matters', 'recommendation'],
        properties: {
          id: { type: 'string', description: 'short slug, e.g. csv-schema-unversioned' },
          title: { type: 'string' },
          severity: { type: 'string', enum: ['blocker', 'high', 'medium', 'low'] },
          area: { type: 'string', description: 'file or page or subsystem' },
          evidence: { type: 'string', description: 'concrete: file:line, a quoted string, or a reproducible observation. No hand-waving.' },
          why_it_matters: { type: 'string' },
          recommendation: { type: 'string', description: 'the specific change to make' },
          blocks_launch: { type: 'boolean' },
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
          reasoning: { type: 'string', description: 'For refute: the specific reason it is wrong or not worth doing. For amend: what to change.' },
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
written. No praise, no summary of what the project does. Be specific about the
fix. Aim for your 5 to 10 highest-value findings; quality over volume. Prefix
every id with "${p.key}-".`,
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
    `[${f.id}] (${f.severity}${f.blocks_launch ? ', claims launch blocker' : ''}) ${f.title}
   area: ${f.area}
   evidence: ${f.evidence}
   fix: ${f.recommendation}`).join('\n\n')

  const results = await parallel(PERSONAS.map(p => () =>
    agent(`You are the ${p.label} on the same review panel, now in the
cross-examination round. ${p.brief}

${CONTEXT}

Here is every finding on the table, from all eight panellists:

${table}

Your job is to PRESSURE TEST, not to agree. For each finding you have a real
view on, give a stance:
  refute  = wrong, already handled in the code, based on a misreading, or not
            worth doing. Say specifically why. Check the code before refuting.
  amend   = right in substance but the severity or the fix is wrong.
  endorse = correct and important, and you would defend it. Add anything the
            author missed from your discipline.
  abstain = outside your competence. Use this freely rather than padding.

Refuting a weak finding is as valuable as endorsing a strong one. If a finding
in your own area is wrong, say so.

Then, only if the other panellists' findings revealed something genuinely new
to you, add new_findings. Do not restate anything already on the table. Prefix
new ids with "${p.key}-r${round}-".`,
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
const detail = pool.map(f => {
  const vs = refuted.get(f.id) || []
  const votes = vs.map(v => `${v.stance}${v.revised_severity ? ` -> ${v.revised_severity}` : ''}: ${v.reasoning}`).join(' | ')
  return `[${f.id}] (${f.severity}${f.blocks_launch ? ', launch blocker' : ''}) ${f.title}
   area: ${f.area}
   evidence: ${f.evidence}
   why: ${f.why_it_matters}
   fix: ${f.recommendation}
   panel: ${votes || 'no challenges recorded'}`
}).join('\n\n')

const agreed = await agent(`You are the chair of an eight-persona review panel for
rbptracker.org. The panel was: ${PERSONAS.map(p => p.label).join('; ')}.

${CONTEXT}

These findings survived ${round} rounds of cross-examination:

${detail}

Produce the single combined list the panel agrees needs fixing before more code
is written. Rules:

1. Merge duplicates across personas into one item, naming which disciplines
   raised it. Overlap between disciplines is a signal of importance.
2. Rank by what actually should be done first, weighing severity, launch-blocking
   status, and effort. Not by persona order.
3. Set severity from the panel's revised views, not the original claim.
4. Drop anything where the refutations were more convincing than the defence,
   and list those separately with the reason, so they are not silently lost.
5. Separate what blocks launch from what is merely wanted. The launch gate is
   50% CNA coverage; note anything that should join it as a gate.
6. Be concrete. Each item must name the change to make and the file or page.
7. If the panel missed something obvious to you as chair, add it, marked as such.

Write it as Markdown suitable for committing as REVIEW.md. Use no em dashes
anywhere. Start with a two-sentence verdict on whether this project is on a
sound footing, then the ranked list, then the dropped items, then a short note
on what the panel disagreed about most and why it matters.`,
  { label: 'chair:synthesis', phase: 'Synthesise', effort: 'high' })

return {
  rounds: round,
  standing: pool.length,
  agreed,
  findings: pool,
  votes: Object.fromEntries(refuted),
}

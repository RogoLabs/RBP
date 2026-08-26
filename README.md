# RBP durable state

Working state for [rbptracker.org](https://rbptracker.org), written by the
pipeline in `RogoLabs/RBP`. Not documentation, and not a stable interface.

| | |
|---|---|
| `snapshots/<date>/` | one published run: `backlog.json`, `backlog.csv`, `summary.json`, `held_back.json`, `resolved.json`, `cnas.json` |
| `precision.json` | the grader ledger. Inference does not run under v1, so this is inert |
| `resolutions.json` | which listed IDs have since published or been rejected |
| `runs.jsonl` | one line per delivered publication, so `/method` can evidence its cadence |

**No file here attributes a reserved CVE ID to a CNA.** v1 publishes no
attribution, and `rbp.publish.check` refuses to stage any tree in which a
certified CNA short name appears as a key or a value, in any field, in any
format. Feed names, affected package names and aggregate coverage figures are
not attribution and are published deliberately.

**Re-rooted 2026-08-26.** The prior history is gone. Four snapshots plus both
ledgers carried CNA names through fields the leak guard did not inspect: a
per-CNA table in `cnas.json`, `published_assigner` in the resolution ledger,
`by_cna` inside `summary.json`, and 223 named rows in a pre-schema-v2
`backlog.csv`. Rewriting the tip alone would have left every one of them
reachable in history, so the branch was re-rooted rather than amended. Snapshot
contents are otherwise unchanged.

Retention: 90 days of dailies, then one snapshot per month. A withhold request
removes a row from these files too, so a dated figure can go down.

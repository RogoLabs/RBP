# rbptracker.org durable state

Machine-written. Do not edit by hand.

This branch is the site's memory. It holds what must survive between runs and
cannot live in an Actions cache, because caches are evictable and are not a
database:

- `precision.json`: the grader ledger. Every owner prediction the site has ever
  made, and the verdict once the CVE Record published and the CVE List revealed
  the real assigner. This is what makes the accuracy figure on the site earned
  rather than asserted, so losing it would quietly reset the central claim to zero.
- `snapshots/<date>/`: dated backlog snapshots, for the week-over-week diff and
  the historical record of which IDs were reserved when.

Kept off `main` so the source repo stays small (GitHub recommends under 1 GB)
and so a data commit every six hours does not bury the code history.

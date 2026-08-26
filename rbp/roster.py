"""
The pinned CNA roster, which is the coverage denominator (review Part 2, condition 1).

Coverage was measured against a denominator recounted from the corpus every run:
the number of distinct assigners with at least one published CVE in a rolling
three-year window. That number moves for reasons that have nothing to do with this
site's reach. It grows as CNAs publish, shrinks as the window rolls, and steps
overnight on 1 January. A percentage trended over a base like that is weather, not
progress, and the launch gate is a threshold on exactly that percentage.

So the denominator is now the CVE Program's own list of certified CNAs, pinned in
`roster_data/cna_roster.json` and refreshed deliberately rather than incidentally.

TWO CONSEQUENCES, BOTH WORTH STATING PLAINLY.

The roster is LARGER than the corpus-derived count: 539 certified CNAs against 434
distinct recent assigners. So coverage drops when measured honestly, from 27.9% to
about 22%. The 105 difference is CNAs that have published nothing in the window,
and a CNA that has published nothing is still a CNA whose advisories this site
cannot read and which may hold reserved IDs. Excluding them flattered the figure.

And the roster can go stale. A pinned file that silently drifts from the Program's
own list is a denominator nobody is measuring. `tests/test_roster.py` fetches the
live list and fails when the pinned copy has drifted beyond a tolerance, so the
refresh is a deliberate commit with a visible diff rather than a background number
that moved.
"""
from __future__ import annotations

import datetime as dt
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
ROSTER_PATH = os.path.join(HERE, "roster_data", "cna_roster.json")

# The Program's own published list. Not an API this project should poll on every
# run: it is a slowly-changing roster, and pinning it is the point.
SOURCE_URL = ("https://raw.githubusercontent.com/CVEProject/cve-website/dev/"
              "src/assets/data/CNAsList.json")

# How far the pinned roster may drift before the drift test fails. Certification
# adds a handful of CNAs a month, so a tolerance in the tens catches "this has not
# been refreshed in a year" without failing on "three were added last week".
MAX_DRIFT = 25

# How old the pinned roster may be before the drift test complains, in days.
MAX_AGE_DAYS = 120


def load(path=None):
    """The pinned roster. Raises if it is missing or unreadable.

    Deliberately strict. A missing roster silently falling back to the
    corpus-derived count would restore the moving denominator the gate exists to
    avoid, and it would do it invisibly.
    """
    path = path or ROSTER_PATH
    try:
        d = json.load(open(path))
    except Exception as e:
        raise SystemExit(
            f"cannot read the pinned CNA roster at {path}: {e}. The coverage "
            "denominator and therefore the launch gate depend on it. Refusing to "
            "fall back to a corpus-derived count, which is the moving base the "
            "pinned roster exists to replace.") from e
    names = {e["short_name"] for e in d.get("cnas") or [] if e.get("short_name")}
    if not names:
        raise SystemExit(f"the pinned CNA roster at {path} lists no CNAs")
    return {
        "names": names,
        "count": len(names),
        "fetched": d.get("fetched"),
        "source": d.get("source"),
    }


def age_days(roster, today=None):
    """How stale the pinned roster is, or None if it carries no date."""
    if not roster.get("fetched"):
        return None
    try:
        then = dt.date.fromisoformat(roster["fetched"])
        now = dt.date.fromisoformat(today) if today else dt.date.today()
    except ValueError:
        return None
    return (now - then).days


def normalise(name):
    """CNA short names vary in punctuation across sources (GitHub_M vs GitHub-M).

    The same normalisation clock._same_name uses. Matching the corpus's assigner
    strings against the roster's short names without it would undercount coverage
    for exactly the CNAs whose names contain punctuation.
    """
    return (name or "").lower().replace("_", "").replace("-", "").replace(" ", "")


def index(roster):
    """normalised short name -> canonical short name."""
    return {normalise(n): n for n in roster["names"]}

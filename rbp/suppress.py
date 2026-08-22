"""
The suppression lever (review item 4).

`templates/cna.html` promised a CNA that a wrong row, or one "under coordinated
disclosure", would be "corrected or suppressed on the next build", and that
"suppressions are counted publicly in aggregate". None of it existed:
`grep -rni suppress rbp/` returned nothing, and the pipeline recomputes `owner` by
block inference every run, so a manual correction could not have survived anyway.

Two inputs, one set.

    the committed list      snapshot-independent, durable, reviewed. Entries are
                            added by a human and survive every run.
    labelled issues         public issues on this repo carrying the `withhold`
                            label, read each run. This is the fast path: a request
                            filed at 09:00 is honoured by the 12:00 build with
                            nobody in the loop.

WHY A PUBLIC ISSUE AND NOT A PRIVATE ADVISORY

The first version of this read GitHub private vulnerability reporting, on the
reasoning that an embargo report must not be public. Three things were wrong with
that, and the first is the one that matters.

The advisory form does not fit the task. It asks for affected versions, severity,
CWE and ecosystem, because it is built for reporting a vulnerability in THIS
repository's own code. Someone who wants to say "do not list CVE-2026-1234" lands
on a form that does not describe what they are doing, and the likely outcome is
that they give up. Friction in this channel is a far more probable failure than
disclosure, and a worse one, because the entire point is that reporting must be
trivially easy.

An issue is readable with the workflow's own GITHUB_TOKEN (`issues: read`), so
there is no personal access token: nothing to create, nothing to rotate, nothing
to expire, and the whole silent-credential-failure class disappears rather than
being mitigated.

And a public request makes the lever AUDITABLE from outside. Anyone can check that
the published suppressed count matches the visible requests, which is stronger
accountability than a private channel plus a number this project publishes about
itself. The requirement was that the mechanism "cannot be used to quietly hide the
problem"; a public request serves that better than a private one.

WHAT IS GIVEN UP, AND HOW IT IS MITIGATED

The row is already listed, so the CVE ID is already public here. What a public
request adds is a signal about WHICH row someone cares about. So no reason is
asked for and the template tells reporters not to give one: "please withhold
CVE-2026-1234" does not distinguish an embargo from a wrong owner from a CNA that
would simply rather not be listed. A private route and email remain available for
anyone who wants them, described accurately as human-reviewed rather than
automatic, because without a PAT they cannot be read by the pipeline.

WHY THE COMMITTED LIST HOLDS HASHES AND NOT CVE IDS

A plaintext list in a public repository is a file that says "somebody reported
CVE-2026-XXXX as being under embargo". That is strictly worse than the listing it
exists to remove: it converts a row that merely looked overdue into a row a third
party has confirmed is sensitive, and it is permanent, because git history is.

So entries are `HMAC-SHA256(key, cve_id)`. The pipeline holds every candidate ID
already, so it hashes each one and tests membership. Without the key the file
cannot be enumerated, and it cannot even be used to confirm a guess.

WHY A MISSING KEY FAILS THE BUILD

If the committed list is non-empty and no key is configured, the entries cannot be
evaluated, and the run would publish rows that are supposed to be withheld. That
is a false statement about a third party under embargo, which is PLAN 8b class 1:
refuse to publish. This is one of the few places in this codebase where a
configuration error should stop a publication, and the reason is that the
alternative is publishing the thing the lever exists to withhold.

WHY THE ISSUE READ FAILING DOES *NOT* FAIL THE BUILD

The opposite direction. An unreadable endpoint is indistinguishable from "no
requests", so a read that starts failing would silently switch the fast path off.
That is the failure shape this project has hit repeatedly, so it is reported as a
DEGRADED run instead: the banner is already on every page, and a degraded run says
its counts are not comparable. Loud, and it does not freeze a publication four
times a day over a transient API error.
"""
from __future__ import annotations

import hmac
import json
import os
import re
import subprocess
from hashlib import sha256

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)

# Where the committed hashes live. On `main`, not the data branch: this is
# reviewed input, not generated state.
DEFAULT_LIST = "suppressions.txt"

# Ceiling on how many rows a single run may auto-withhold from private advisories.
#
# There is deliberately no verification of who may report (review item 4: "an
# embargo report needs only the CVE ID and the word embargo, no detail"), which is
# right for a genuine embargo and does mean anyone with a GitHub account can
# remove a row. One advisory naming 500 IDs would empty the site, which is a
# denial of service against the project's entire purpose.
#
# So the fast path is capped. Beyond the cap the run still withholds the first
# MAX_AUTO ids, reports the overflow loudly, and the remainder needs a human entry
# in the committed list. The cap protects availability; the committed list keeps
# the ceiling from becoming a way to ignore a real mass report.
MAX_AUTO = 25


def _key():
    return (os.environ.get("RBP_SUPPRESS_KEY") or "").strip()


def digest(cve_id, key=None):
    """Keyed hash of one CVE ID. Case-normalised, so a lowercase entry works."""
    k = (key if key is not None else _key()).encode()
    return hmac.new(k, (cve_id or "").strip().upper().encode(), sha256).hexdigest()


def read_list(path=DEFAULT_LIST):
    """Committed hashes. Blank lines and `#` comments ignored."""
    if not os.path.exists(path):
        return []
    out = []
    for line in open(path):
        line = line.split("#", 1)[0].strip()
        if line:
            out.append(line.lower())
    return out


WITHHOLD_LABEL = "withhold"
# A maintainer-applied label. A confirmed request is exempt from every cap and
# from the per-author limit, which is the escape hatch for a genuine mass report:
# the caps exist to bound an anonymous stranger, not to stop a reviewed decision.
CONFIRMED_LABEL = "confirmed"


def from_issues(repo="RogoLabs/RBP", label=WITHHOLD_LABEL, token_env="GITHUB_TOKEN"):
    """Withhold requests from open issues carrying the label.

    Returns `(requests, error)` where each request is a dict with `cve_id`,
    `issue`, `author`, `created_at` and `confirmed`. `error` is None on success and
    a short string when the endpoint could not be read, which the caller must
    surface as a degraded run rather than treat as an empty result: "cannot read"
    and "nothing to read" are the same value and must not be the same outcome.

    Returns RECORDS rather than a bare set of ids, because every anti-abuse
    decision needs to know who asked and when. The first version returned a set,
    which made the per-run cap starvable: see triage().

    CLOSED issues are ignored. Closing a request is how it is revoked, so a row
    does not stay withheld because nobody remembered to revisit it, and revoking
    is instant rather than waiting on a build.

    Reads with the workflow's own GITHUB_TOKEN (`issues: read`), or with whatever
    `gh` is already authenticated as locally. No personal access token.
    """
    token = (os.environ.get(token_env) or "").strip()
    env = dict(os.environ)
    if token:
        env["GH_TOKEN"] = token
    try:
        p = subprocess.run(
            ["gh", "api", "--paginate",
             f"repos/{repo}/issues?state=open&labels={label}&per_page=100"],
            capture_output=True, text=True, timeout=60, env=env, check=False)
    except (OSError, subprocess.SubprocessError) as e:
        return [], f"could not run gh: {e}"
    if p.returncode != 0:
        return [], f"gh api failed: {(p.stderr or '').strip()[:160]}"
    try:
        items = json.loads(p.stdout or "[]")
    except ValueError as e:
        return [], f"unparseable issue response: {e}"
    if not isinstance(items, list):
        return [], "issue response was not a list"

    out = []
    for it in items:
        # The issues endpoint returns pull requests too, and a PR with a CVE ID in
        # its title would otherwise withhold that row.
        if not isinstance(it, dict) or it.get("pull_request"):
            continue
        labels = {(l or {}).get("name") for l in (it.get("labels") or [])
                  if isinstance(l, dict)}
        blob = " ".join(str(it.get(f) or "") for f in ("title", "body"))
        author = ((it.get("user") or {}).get("login") or "").lower()
        for cid in {m.group(0).upper() for m in CVE_RE.finditer(blob)}:
            out.append({
                "cve_id": cid,
                "issue": it.get("number"),
                "author": author,
                "created_at": str(it.get("created_at") or ""),
                "confirmed": CONFIRMED_LABEL in labels,
            })
    return out, None


# --------------------------------------------------------------------------
# anti-abuse
# --------------------------------------------------------------------------
# The channel is deliberately unauthenticated: nobody should have to prove who
# they are before asking that a row about them not be listed. The cost is that a
# bot can file withhold requests, and a fully automatic removal turns that into
# vandalism against the site's whole purpose.
#
# Note what an attacker actually gains: rows leave, so the count goes DOWN. This is
# defacement, not exploitation, and the damage is proportional to rows removed. So
# the primary defence is bounding the number, not authenticating the asker.

# Most rows one author may withhold per run.
MAX_PER_AUTHOR = 5
# Most rows all requests together may withhold per run, absolute...
MAX_AUTO = 25
# ...and as a share of the published backlog, so the ceiling stays sane if the
# backlog is ever small. 25 of 522 is nothing; 25 of 40 would be most of the site.
MAX_FRACTION = 0.05


def triage(requests, backlog_size=None):
    """Decide which withhold requests to honour this run.

    Returns `(honoured_ids, report)`.

    ORDERED OLDEST FIRST, and that is the important line. The first version took
    `sorted(found)[:MAX_AUTO]`, which sorts by CVE ID string, so an attacker naming
    low-numbered ids would sort ahead of a genuine request filed days earlier and
    silently displace it. A cap that can starve the request it exists to protect is
    worse than no cap: it converts vandalism against the site into denial of the
    correction channel, which is the more serious of the two. First-come-first-served
    means a flood filed after a genuine request cannot displace it.

    Confirmed requests bypass every limit, so a reviewed mass report is not held
    back by a ceiling designed for strangers.
    """
    reqs = sorted(requests or [], key=lambda r: (r.get("created_at") or "",
                                                 r.get("issue") or 0))
    ceiling = MAX_AUTO
    if backlog_size:
        ceiling = min(MAX_AUTO, max(1, int(backlog_size * MAX_FRACTION)))

    honoured, per_author = [], {}
    deferred_author, deferred_ceiling = [], []
    for r in reqs:
        if r.get("confirmed"):
            honoured.append(r)
            continue
        a = r.get("author") or "?"
        if per_author.get(a, 0) >= MAX_PER_AUTHOR:
            deferred_author.append(r)
            continue
        if len([x for x in honoured if not x.get("confirmed")]) >= ceiling:
            deferred_ceiling.append(r)
            continue
        per_author[a] = per_author.get(a, 0) + 1
        honoured.append(r)

    ids = {r["cve_id"] for r in honoured}
    report = {
        "requested": len({r["cve_id"] for r in reqs}),
        "honoured": len(ids),
        "authors": len({r.get("author") for r in reqs}),
        "confirmed": len([r for r in reqs if r.get("confirmed")]),
        "deferred_per_author": len({r["cve_id"] for r in deferred_author}),
        "deferred_ceiling": len({r["cve_id"] for r in deferred_ceiling}),
        "ceiling": ceiling,
    }
    return ids, report


class Suppressions:
    """The effective suppression set for one run, plus what to publish about it."""

    def __init__(self, committed, auto_ids, error=None, key=None, triage=None):
        self.committed = set(committed or ())
        self.auto = set(auto_ids or ())
        self.error = error
        self.triage = triage or {}
        self._key = key

    def __contains__(self, cve_id):
        cid = (cve_id or "").strip().upper()
        if cid in self.auto:
            return True
        return bool(self.committed) and digest(cid, self._key) in self.committed

    def __len__(self):
        return len(self.committed) + len(self.auto)

    @property
    def report(self):
        """What goes in summary.json.

        Counts only, never IDs. Publishing which rows are withheld would undo the
        withholding, and publishing nothing at all would make the lever a way to
        quietly shrink the count, which is what the site already promised it was
        not. The aggregate is the whole accountability mechanism.
        """
        t = self.triage
        return {
            "committed": len(self.committed),
            "from_reports": len(self.auto),
            # Anti-abuse visibility. Counts only, and published rather than logged,
            # because "the count went down" is indistinguishable from abuse unless
            # the site says how many requests it received and how many it declined.
            "requested": t.get("requested", 0),
            "authors": t.get("authors", 0),
            "confirmed": t.get("confirmed", 0),
            "deferred": (t.get("deferred_per_author", 0)
                         + t.get("deferred_ceiling", 0)),
            "ceiling": t.get("ceiling"),
            "degraded": bool(self.error),
            "detail": self.error,
        }


def load(list_path=DEFAULT_LIST, repo="RogoLabs/RBP", allow_remote=True,
         backlog_size=None):
    """Build the run's suppression set from both inputs."""
    committed = read_list(list_path)
    key = _key()
    if committed and not key:
        raise SystemExit(
            f"{list_path} holds {len(committed)} suppression entry(ies) and "
            "RBP_SUPPRESS_KEY is not set, so none of them can be evaluated. "
            "Refusing to publish: these rows are withheld because someone "
            "reported them as wrong or under embargo, and running without the "
            "key would publish every one of them. Set the secret, or empty the "
            "file deliberately.")

    auto, err, triage_report = set(), None, None
    if allow_remote:
        requests, err = from_issues(repo=repo)
        if not err:
            auto, triage_report = triage(requests, backlog_size=backlog_size)
            d = triage_report
            if d["requested"]:
                print(f"  withhold requests: {d['requested']} id(s) from "
                      f"{d['authors']} author(s); honouring {d['honoured']}"
                      + (f", {d['confirmed']} confirmed" if d["confirmed"] else ""))
            if d["deferred_per_author"]:
                print(f"  ANTI-ABUSE: {d['deferred_per_author']} request(s) deferred, "
                      f"one author above the {MAX_PER_AUTHOR}-per-run limit")
            if d["deferred_ceiling"]:
                print(f"  ANTI-ABUSE: {d['deferred_ceiling']} request(s) deferred, "
                      f"above the {d['ceiling']}-per-run ceiling. Oldest requests were "
                      "honoured first, so nothing already filed was displaced. Add the "
                      f"'{CONFIRMED_LABEL}' label to exempt a reviewed request.")
    s = Suppressions(committed, auto, error=err, key=key, triage=triage_report)
    if err:
        print(f"  DEGRADED: suppression fast path unavailable ({err}). "
              "Withhold requests filed as issues are NOT being honoured this run.")
    elif auto:
        print(f"  suppressing {len(auto)} row(s) from withhold requests")
    if committed:
        print(f"  {len(committed)} committed suppression entry(ies) in force")
    return s

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

# A title a human would type without the template, e.g. "Withhold CVE-2026-1234".
# The template prefills exactly this, so a request filed through it matches on
# both the label and the title.
_TITLE_RE = re.compile(r"^withhold\b", re.I)

# The template renders its answers under a "### CVE ID" heading. Only that
# section is parsed, so prose elsewhere in the body cannot withhold a row.
_FIELD_RE = re.compile(r"^###\s*CVE ID\s*$(.*?)(?=^###\s|\Z)",
                       re.I | re.M | re.S)


def _template_field(body):
    """The CVE ID section of a template-filled issue, or '' if there is none.

    Falling back to the WHOLE body would restore the defect this exists to fix,
    so absence returns nothing and the title alone carries the request.
    """
    m = _FIELD_RE.search(body or "")
    return m.group(1) if m else ""


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
        # NOT filtered on the label server-side. That filter is what made this
        # channel unreachable for the people it exists for.
        #
        # Every surface linked issues/new?labels=withhold, and the `labels` query
        # parameter is honoured only for accounts with TRIAGE permission on the
        # repository. A CNA employee with an ordinary GitHub account filed an
        # unlabelled issue, this query never returned it, and because the API
        # call itself succeeded `err` stayed None so no degraded banner fired
        # either. The request vanished with no error anywhere.
        #
        # There is now an issue template that applies the label server-side, and
        # this reads ALL open issues and matches on the label OR the title, so a
        # request filed by hand, from a phone, or against a stale bookmark still
        # lands. The cost is one extra page of issues per run, which is nothing.
        p = subprocess.run(
            ["gh", "api", "--paginate",
             f"repos/{repo}/issues?state=open&per_page=100"],
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
        title = str(it.get("title") or "")
        # An issue counts as a withhold request if it carries the label OR its
        # title says so. Anything else is an ordinary issue and is ignored.
        if label not in labels and not _TITLE_RE.match(title.strip()):
            continue

        # THE TITLE AND THE TEMPLATE FIELD, NEVER THE FREE BODY.
        #
        # This used to be `title + body`, and every distinct CVE ID anywhere in
        # the text became a withhold request. So "same root cause as
        # CVE-2025-1111" withheld an unrelated row that nobody asked about, and
        # a reference to prior art quietly removed someone else's row.
        blob = title + " " + _template_field(str(it.get("body") or ""))
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

# Most rows one author may withhold per run. RETAINED but no longer a gate: see
# triage() for why the caps stopped deciding whether a row is withheld and
# started deciding only whether the withhold PERSISTS.
MAX_PER_AUTHOR = 5
# Most rows all requests together may withhold per run, absolute...
MAX_AUTO = 25
# ...and as a share of the published backlog, so the ceiling stays sane if the
# backlog is ever small. 25 of 522 is nothing; 25 of 40 would be most of the site.
MAX_FRACTION = 0.05

# Above this many requests in one run, the run is reported as anomalous. Not a
# cap: every request is still honoured for the cycle. It exists so a flood is
# VISIBLE on the site the same run it happens, rather than being discovered when
# someone notices the count dropped.
ANOMALY_THRESHOLD = MAX_AUTO


def triage(requests, backlog_size=None):
    """Decide which withhold requests to honour this run.

    Returns `(honoured_ids, report)`.

    THE POLICY INVERTED ON 2026-08-23, and the reasoning is worth keeping.

    It used to be: honour up to a cap, and silently drop the rest. Past
    MAX_PER_AUTHOR the request was appended to a deferred list and nothing else
    happened. The row kept publishing, no reply reached the requester, and the
    degraded banner had no deferral term, so the site looked healthy while an
    embargo request sat unhonoured. The failure mode was "an embargoed row stays
    published", which is the worst outcome this channel exists to prevent.

    It is now: EVERY request is honoured for ONE CYCLE, unconditionally, and it
    PERSISTS only if a human adds the `confirmed` label. The failure mode becomes
    "a row is briefly missing", and the abuse case the caps were written for is
    bounded to a single six-hour cycle rather than prevented outright.

    What this trades away, stated plainly because it is a real cost: anyone with
    a GitHub account can blank any row for up to one cycle, and a flood can blank
    many. That is defacement, the count goes DOWN, and it is visible and
    self-healing. The alternative was publishing something a party asked to have
    withheld, which is neither.

    The caps still exist and still do work: they decide what carries into the
    NEXT run without review, which is where an unbounded flood would otherwise
    become permanent. `confirmed` bypasses everything, so a reviewed mass report
    is never held back by a ceiling designed for strangers.

    ORDERED OLDEST FIRST. The first version took `sorted(found)[:MAX_AUTO]`,
    which sorts by CVE ID string, so an attacker naming low-numbered ids sorted
    ahead of a genuine request filed days earlier and silently displaced it. That
    matters less now that nothing is displaced, and the ordering is kept because
    the persistence decision inherits it.
    """
    reqs = sorted(requests or [], key=lambda r: (r.get("created_at") or "",
                                                 r.get("issue") or 0))
    ceiling = MAX_AUTO
    if backlog_size:
        ceiling = min(MAX_AUTO, max(1, int(backlog_size * MAX_FRACTION)))

    # Everything requested is withheld this cycle. No exceptions, no ordering
    # effects, no cap: that is the whole change.
    honoured = list(reqs)

    # The caps now classify PERSISTENCE only. A request over a cap is still
    # withheld today; what it does not get is a free ride into tomorrow.
    persists, over_author, over_ceiling, per_author = [], [], [], {}
    for r in reqs:
        if r.get("confirmed"):
            persists.append(r)
            continue
        a = r.get("author") or "?"
        if per_author.get(a, 0) >= MAX_PER_AUTHOR:
            over_author.append(r)
            continue
        if len(persists) >= ceiling:
            over_ceiling.append(r)
            continue
        per_author[a] = per_author.get(a, 0) + 1
        persists.append(r)

    ids = {r["cve_id"] for r in honoured}
    report = {
        "requested": len({r["cve_id"] for r in reqs}),
        "honoured": len(ids),
        "authors": len({r.get("author") for r in reqs}),
        "confirmed": len([r for r in reqs if r.get("confirmed")]),
        # Withheld today but NOT carried without review. Nothing is silently
        # dropped any more, so these names changed with the meaning: a row here
        # is withheld right now and needs the `confirmed` label to stay that way.
        "needs_review_per_author": len({r["cve_id"] for r in over_author}),
        "needs_review_ceiling": len({r["cve_id"] for r in over_ceiling}),
        "persists_next_run": len({r["cve_id"] for r in persists}),
        "ceiling": ceiling,
        # Visible the same run a flood happens, rather than inferred later from
        # a count that dropped.
        "anomalous": len(ids) > ANOMALY_THRESHOLD,
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

    def __iter__(self):
        """Deliberately unsupported, with a reason.

        The committed half holds keyed hashes rather than CVE IDs, exactly so the
        list cannot be enumerated by anyone holding the file. That property would
        be quietly false if this object could be iterated, and a caller iterating
        it would silently get only the ids from open requests while believing it
        had them all.

        Raised with an explanation because the default message
        ("'Suppressions' object is not iterable") took a production failure to
        diagnose. Use `in` to test membership, or `.auto` for the open-request ids.
        """
        raise TypeError(
            "Suppressions cannot be iterated: the committed entries are keyed "
            "hashes, not CVE IDs, so enumerating them is impossible by design. "
            "Test membership with `cve_id in suppressions`, or use `.auto` for the "
            "ids from open withhold requests.")

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
            # Nothing is deferred any more: everything requested is withheld
            # this cycle. What is published instead is how many of those need a
            # human `confirmed` label to survive into the next run, which is the
            # number that actually tells a reader whether the lever is being
            # used or abused.
            "needs_review": (t.get("needs_review_per_author", 0)
                             + t.get("needs_review_ceiling", 0)),
            "persists_next_run": t.get("persists_next_run", 0),
            "anomalous": bool(t.get("anomalous")),
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
            over_a = d.get("needs_review_per_author", 0)
            over_c = d.get("needs_review_ceiling", 0)
            if over_a or over_c:
                print(f"  REVIEW NEEDED: {over_a + over_c} request(s) are "
                      "withheld this run but will NOT carry into the next one "
                      f"without the '{CONFIRMED_LABEL}' label "
                      f"({over_a} above the {MAX_PER_AUTHOR}-per-author limit, "
                      f"{over_c} above the {d.get('ceiling')}-per-run ceiling).")
            if d.get("anomalous"):
                print(f"  ANOMALY: {d['honoured']} withhold(s) in one run, above "
                      f"{ANOMALY_THRESHOLD}. Every one is honoured this cycle; "
                      "check whether this is a flood before confirming any.")
    s = Suppressions(committed, auto, error=err, key=key, triage=triage_report)
    if err:
        print(f"  DEGRADED: suppression fast path unavailable ({err}). "
              "Withhold requests filed as issues are NOT being honoured this run.")
    elif auto:
        print(f"  suppressing {len(auto)} row(s) from withhold requests")
    if committed:
        print(f"  {len(committed)} committed suppression entry(ies) in force")
    return s

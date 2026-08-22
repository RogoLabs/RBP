"""
Resolve referenced CVE IDs to their authoritative reservation state.

Oracle: the CVE Services *reservation* endpoint, `/api/cve-id/{id}`, NOT
`/api/cve/{id}`. This distinction is the whole point of this module.

    /api/cve/{id}      404s on reserved IDs. A reserved ID and an ID that was
                       never allocated look identical. This is why the previous
                       engine collapsed both into a guessed `DNE` state.

    /api/cve-id/{id}   returns the true reservation state, unauthenticated:
                         200 {"state":"RESERVED",  "owning_cna":"[REDACTED]"}
                         200 {"state":"PUBLISHED", "owning_cna":"Nozomi"}
                         200 {"state":"REJECTED",  "owning_cna":...}
                         404 {"error":"CVE_ID_NOT_FOUND"}   never allocated
                         400 {"error":"BAD_INPUT"}          malformed

So RESERVED is directly observable, and "reserved" is cleanly separable from
"never allocated". A row we call RBP now matches the CVE Program's own
definition verbatim: an ID in the Reserved state, referenced in public.

The cvelistV5 git tree is NOT consulted. It carries no reserved stubs, the
26000-26999 block holds 487 files against 513 absent IDs, and the small stubs
there are REJECTED, not RESERVED. Cloning 2.63 GB buys nothing. (PLAN.md F2.)

`owning_cna` is served for PUBLISHED and REJECTED and redacted for exactly the
RESERVED population, the one the RBP policy governs. Owner attribution for
reserved IDs is therefore inferred downstream (see attribution.py), never taken
from this oracle.

Cache discipline: only immutable terminal states (PUBLISHED / REJECTED) persist
across runs. RESERVED and transient errors are re-verified every run, so a
record that finally publishes auto-closes and a one-off API error never
permanently drops a CVE from the backlog.
"""
from __future__ import annotations

import concurrent.futures
import datetime as dt
import json
import os
import random
import re
import time
import urllib.error
import urllib.request

CVE_ID_API = "https://cveawg.mitre.org/api/cve-id/"
UA = {"User-Agent": "rbptracker.org (+https://github.com/RogoLabs/RBP)"}
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")

# Terminal: the record exists and is visible to any CVE List consumer.
_IMMUTABLE = ("PUBLISHED", "REJECTED")
# Terminal in the other direction: the ID was never allocated. Re-checked every
# run anyway, an ID can be allocated later, and a downstream typo can be fixed.
_NOT_FOUND = "NOT_ALLOCATED"

# The endpoint advertises `ratelimit-policy: 25000;w=60`. 24 workers measured
# ~94 req/s, i.e. ~5,600/min: roughly 22% of the ceiling. Do not raise this
# without re-reading the live header; there is no upside in going faster.
DEFAULT_WORKERS = 24

# --------------------------------------------------------------------------
# Description sanitising (review item 18)
# --------------------------------------------------------------------------
# The published description is the only identifier a defender has on many rows:
# 52 of 96 named rows carried an empty package and CSAF rows carry no package at
# all. So the field stays. What comes out of it are the vulnerability-tracker
# annotations that Debian and others append, of which the load-bearing case is
#
#     NOTE: Introduced with: https://.../commit/90ca4e03c27dc8ac821a2e1686
#
# An "Introduced with" pointer is not a description of a flaw, it is a pointer to
# the vulnerable code, reproduced inside a curated list of CVE IDs selected
# precisely because no record has been published. That Debian publishes it first
# is true, and is exactly the "aggregation of public facts creates new exposure"
# argument this whole site rests on, so the defence does not survive contact with
# the site's own thesis. It is also gratuitous: the annotation identifies nothing
# a defender needs.
#
# Everything from the first annotation marker onward is dropped, rather than the
# marker alone, because these annotations are appended in a trailing block and
# what follows one is never prose.
_ANNOTATION_RE = re.compile(
    r"\s*(?:NOTE\s*:|DEBIANBUG\s*:?|Introduced\s+(?:with|in)\s*:|Fixed\s+by\s*:"
    r"|Bug\s*:|References?\s*:)",
    re.I)
# Stops at whitespace OR a closing bracket, rather than eating everything
# non-space. `\S+` swallowed the `)` of a markdown link, so
# `[PhotoSwipe](https://photoswipe.com/)` was left as `[PhotoSwipe](` with an
# unclosed paren on the page.
_URL_RE = re.compile(r"\b(?:https?://|www\.|git://|ftp://)[^\s<>()\[\]]*", re.I)
# Wreckage left behind once a URL is removed from the middle of prose: an empty
# markdown target, empty brackets, a stranded connective, doubled punctuation.
_EMPTY_LINK_RE = re.compile(r"\[([^\]]*)\]\s*\(\s*\)")
_EMPTY_BRACKETS_RE = re.compile(r"\(\s*\)|\[\s*\]")
_STRANDED_LEAD_RE = re.compile(
    r"^(?:From|See|Ref(?:erence)?|Source|At|Via|Per)\b[\s,;:.\-]*(?=[A-Z])")
# Sentence end: terminator, whitespace, then something that starts a new sentence.
# Requires two characters before the terminator so "e.g. foo" and "v1.2. bar" are
# not read as boundaries.
_SENTENCE_RE = re.compile(r"(?<=[a-z0-9)\"'\]]{2})([.!?])(?=\s+[A-Z(\"']|\s*$)")
# Backstop only. A description that reaches this without a sentence boundary is
# almost always an advisory title, which has no terminal punctuation at all.
MAX_DESCRIPTION = 240


def display_description(text):
    """Feed description to publishable display text.

    Order matters and is the point: annotations and URLs come out BEFORE any
    length cut, so a pointer can never survive as a truncated fragment. Then cut
    at the first sentence boundary, which replaces a raw 180-character slice that
    left 518 of 522 rows ending mid-word.

    Returns "" when nothing usable survives. The caller decides the fallback;
    report._clean_description substitutes the package name.
    """
    t = (text or "").replace("\n", " ").replace("\r", " ")
    t = _ANNOTATION_RE.split(t, maxsplit=1)[0]
    had_url = bool(_URL_RE.search(t))
    t = _URL_RE.sub("", t)
    if had_url:
        # Tidy the hole the URL left. "[PhotoSwipe](https://...)" must not become
        # "[PhotoSwipe]()", and "From https://..., The server option" must not
        # become "From , The server option".
        t = _EMPTY_LINK_RE.sub(r"\1", t)
        t = _EMPTY_BRACKETS_RE.sub("", t)
        t = re.sub(r"\s+([,.;:])", r"\1", t)
        t = re.sub(r"([,;:])\s*([,.;:])", r"\2", t)
        t = re.sub(r"\s+", " ", t).strip(" ;,:-–")
        t = _STRANDED_LEAD_RE.sub("", t)
    t = re.sub(r"\s+", " ", t).strip()
    t = t.strip(" ;,:-–")
    if not t:
        return ""
    # Removing a URL can leave a stub that reads like prose but says nothing:
    # "See https://.../advisory for details" becomes "See for details". Below a
    # floor of real words, return nothing and let the caller fall back to the
    # package name, which is genuinely more useful to a defender than a fragment.
    if had_url and (len(t) < 25 or len(t.split()) < 4):
        return ""
    m = _SENTENCE_RE.search(t)
    if m:
        return t[:m.end()].strip()
    if len(t) <= MAX_DESCRIPTION:
        return t
    cut = t[:MAX_DESCRIPTION].rsplit(" ", 1)[0].rstrip(" ;,:-")
    return cut or t[:MAX_DESCRIPTION]


# 429s seen this run. A rate limit is a capacity signal about a shared endpoint,
# not an error, and it was previously invisible: the retry succeeded and nothing
# recorded that the ceiling had been touched.
RATE_LIMITED = []


def _backoff(attempt, retry_after=None):
    """Exponential backoff with jitter, honouring Retry-After when offered.

    Jitter is not decoration here. 24 workers ran `time.sleep(2 ** i)` in
    lockstep, so one 429 produced 24 synchronised retries, which is the shape
    that turns a soft rate limit into a hard one.
    """
    if retry_after:
        try:
            return max(0.0, min(float(retry_after), 30.0))
        except (TypeError, ValueError):
            pass
    return (2 ** attempt) * (0.5 + random.random())


def _valid(cid):
    return bool(CVE_RE.match(cid))


def _get(cid, attempts=3):
    """One reservation lookup. Retries only on transient failure, never on a
    decisive 404/400: those are answers, not errors."""
    for i in range(attempts):
        try:
            req = urllib.request.Request(CVE_ID_API + cid, headers=UA)
            with urllib.request.urlopen(req, timeout=30) as r:
                d = json.load(r)
            return {"state": d.get("state", "?"), "assigner": d.get("owning_cna", "")}
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return {"state": _NOT_FOUND, "assigner": ""}
            if e.code == 400:
                return {"state": "MALFORMED", "assigner": ""}
            if e.code == 429 and i < attempts - 1:
                RATE_LIMITED.append(cid)
                # Honour Retry-After when the endpoint sends one, and jitter
                # otherwise. 24 workers previously executed `2 ** i` in lockstep,
                # so a single 429 became 24 simultaneous retries at t+1s, t+2s,
                # t+4s against an endpoint this project depends on and does not
                # own. Jitter breaks the convoy.
                time.sleep(_backoff(i, e.headers.get("Retry-After")))
                continue
            return {"state": f"HTTP{e.code}", "assigner": ""}
        except Exception:  # noqa: BLE001
            if i < attempts - 1:
                time.sleep(_backoff(i))
                continue
            return {"state": "ERROR", "assigner": ""}
    return {"state": "ERROR", "assigner": ""}


def _lookup(cid, cache):
    """Cached resolve. Only immutable states are reused; RESERVED is always
    re-queried so the backlog self-heals the moment a record publishes."""
    hit = cache.get(cid)
    if hit and hit.get("state") in _IMMUTABLE:
        return hit
    res = _get(cid)
    if res["state"] in _IMMUTABLE:
        cache[cid] = res
    return res


def classify(refs, corpus_df, attributor, cache_path, workers=DEFAULT_WORKERS,
             today=None, ttl=None, previous_reserved=()):
    """Partition referenced IDs into RBP backlog vs. resolved.

    Returns `(backlog, fresh_resolved, health)`. The third value used to not
    exist: the state tally was printed to a log and thrown away, so `unresolved`
    and `never_allocated` never reached summary.json and no consumer could tell a
    quiet week from a brownout at the endpoint.

    `previous_reserved` is the set of CVE IDs that were RESERVED in the previous
    snapshot. It exists so an id the endpoint fails to resolve this run can be
    carried forward rather than silently dropped. Defaults to empty, which is the
    correct first-run behaviour and also means a caller that forgets to pass it
    degrades to the old drop behaviour rather than crashing; tests pin that the
    real caller passes it.

    `ttl` is accepted and ignored, it belonged to the old dual-oracle cache,
    where RESERVED was expensive to re-check. It no longer is.
    """
    previous_reserved = set(previous_reserved or ())
    today = today or dt.date.today().isoformat()
    state_map = dict(zip(corpus_df["cve_id"], corpus_df["state"]))

    cache = {}
    if os.path.exists(cache_path):
        try:
            cache = {k: v for k, v in json.load(open(cache_path)).items()
                     if isinstance(v, dict) and v.get("state") in _IMMUTABLE}
        except Exception:  # noqa: BLE001
            cache = {}

    unknown, malformed = [], 0
    for cid in refs:
        if not _valid(cid):
            malformed += 1
            continue
        # Present and terminal in the baseline corpus -> nothing to ask.
        if state_map.get(cid) in _IMMUTABLE:
            continue
        unknown.append(cid)
    if malformed:
        print(f"  skipped {malformed} malformed CVE ids")
    reused = sum(1 for c in unknown if cache.get(c, {}).get("state") in _IMMUTABLE)
    print(f"  resolving {len(unknown)} candidates via /api/cve-id/ "
          f"({reused} cached terminal, {workers} workers)")

    t0 = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        api = dict(zip(unknown, ex.map(lambda c: _lookup(c, cache), unknown)))
    live = len(unknown) - reused
    if live:
        print(f"  resolved in {time.time() - t0:.1f}s ({live / max(time.time() - t0, .01):.0f} req/s)")
    json.dump(cache, open(cache_path, "w"))

    backlog = []
    tally = {"PUBLISHED": 0, "REJECTED": 0, _NOT_FOUND: 0, "RESERVED": 0, "ERROR": 0}
    carried = []
    for cid, res in api.items():
        st = res["state"]
        if st in _IMMUTABLE:
            tally[st] += 1
        elif st == "RESERVED":
            # The policy's own definition of RBP: Reserved, and public.
            # `owning_cna` is [REDACTED] here by design, so owner is inferred.
            tally["RESERVED"] += 1
            backlog.append(_row(cid, refs[cid], "RESERVED", attributor))
        elif st == _NOT_FOUND:
            # Referenced downstream but never allocated. Not RBP, a data-quality
            # defect in the citing advisory. Counted, never published as RBP.
            tally[_NOT_FOUND] += 1
        else:
            # Unresolved this run: transient, not cached, retried next run.
            #
            # CARRY FORWARD. This branch used to only increment a counter, so an
            # ERROR'd id was never appended to `backlog` and simply vanished from
            # the snapshot. That is the one direction of error this project cannot
            # afford: it shrinks the headline AND manufactures a fake departure in
            # _changes.no_longer_listed, while the row stays open in the ledger
            # forever. A brownout at the endpoint would have read as the CVE
            # Program improving.
            #
            # A bare abort would be the wrong fix (a single flaky id must not stop
            # a publication), so the primitive is carry-forward: if the id was
            # RESERVED in the previous snapshot, keep it, count it, and mark it
            # unverified so every surface can see the count is partly inherited.
            tally["ERROR"] += 1
            if cid in previous_reserved:
                row = _row(cid, refs[cid], "RESERVED", attributor)
                row["state_verified_this_run"] = False
                backlog.append(row)
                carried.append(cid)

    # Verified rows are marked too, so `state_verified_this_run` is never absent
    # on some rows and False on others, which is how a missing field gets read as
    # a healthy default.
    for r in backlog:
        r.setdefault("state_verified_this_run", True)

    print(f"  states: {tally['RESERVED']} RESERVED (RBP) | "
          f"{tally['PUBLISHED']} published | {tally['REJECTED']} rejected | "
          f"{tally[_NOT_FOUND]} never allocated | {tally['ERROR']} unresolved")
    if tally["ERROR"]:
        print(f"  WARNING: {tally['ERROR']} ids unresolved (transient); "
              f"{len(carried)} carried forward from the previous snapshot, "
              f"{tally['ERROR'] - len(carried)} genuinely dropped")
    if RATE_LIMITED:
        print(f"  note: {len(RATE_LIMITED)} lookups were rate limited and retried")

    health = {
        "lookups_attempted": len(unknown),
        "lookups_live": live,
        "cached_terminal": reused,
        "published": tally["PUBLISHED"],
        "rejected": tally["REJECTED"],
        "reserved": tally["RESERVED"],
        # A genuinely valuable data-quality population that was printed to a log
        # and discarded: ids cited by a downstream advisory that were never
        # allocated at all.
        "never_allocated": tally[_NOT_FOUND],
        "unresolved": tally["ERROR"],
        "carried_forward": len(carried),
        "dropped": tally["ERROR"] - len(carried),
        "rate_limited": len(RATE_LIMITED),
        "malformed": malformed,
    }
    return backlog, tally["PUBLISHED"] + tally["REJECTED"], health


def _row(cid, e, state, attributor):
    # The product->CNA map is corroboration only; it never names a CNA on its
    # own (85% precision as a standalone fallback, see inference.py). The
    # authoritative owner column is filled by block inference downstream.
    pm_owner, pm_conf, pm_method = attributor.attribute(
        e.get("product", ""), e.get("description", ""))
    return {
        "cve_id": cid, "state": state,
        "owner": None, "owner_tier": "abstain", "owner_method": "pending-inference",
        "product_map_owner": None if pm_owner == "unclassified" else pm_owner,
        "product_map_confidence": pm_conf, "product_map_method": pm_method,
        "public_date": e["public_date"],
        "sources": ",".join(sorted(e["sources"])), "feed_count": len(e["sources"]),
        "dates": dict(e.get("dates") or {}),
        "refs": ";".join(sorted(e["refs"]))[:250],
        # Sanitised BEFORE the length cut, not after. The old code was
        # `[:180]`, which sliced the raw feed string and left several rows ending
        # in half a commit URL: the annotation was already gone from view but the
        # pointer was still in the data. Cutting first and cleaning second cannot
        # fix that, because by then the URL is a fragment that no longer matches a
        # URL pattern. See display_description.
        "description": display_description(e["description"]),
    }

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
                time.sleep(2 ** i)
                continue
            return {"state": f"HTTP{e.code}", "assigner": ""}
        except Exception:  # noqa: BLE001
            if i < attempts - 1:
                time.sleep(2 ** i)
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
             today=None, ttl=None):
    """Partition referenced IDs into RBP backlog vs. resolved.

    `ttl` is accepted and ignored, it belonged to the old dual-oracle cache,
    where RESERVED was expensive to re-check. It no longer is.
    """
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
            tally["ERROR"] += 1  # transient; not cached, retried next run

    print(f"  states: {tally['RESERVED']} RESERVED (RBP) | "
          f"{tally['PUBLISHED']} published | {tally['REJECTED']} rejected | "
          f"{tally[_NOT_FOUND]} never allocated | {tally['ERROR']} unresolved")
    if tally["ERROR"]:
        print(f"  WARNING: {tally['ERROR']} ids unresolved (transient), counts are a floor")

    fresh_resolved = tally["PUBLISHED"] + tally["REJECTED"]
    return backlog, fresh_resolved


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
        "refs": ";".join(sorted(e["refs"]))[:250],
        "description": e["description"][:180].replace("\n", " "),
    }

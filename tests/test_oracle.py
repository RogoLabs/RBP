"""
Acceptance tests for the reservation oracle (PLAN.md phase 1).

The frozen tests run offline and gate CI. The live test is opt-in via
RBP_LIVE_TESTS=1. It hits the real endpoint and asserts the invariants that
must hold for all time, not the snapshot numbers, which drift as records
publish.
"""
from __future__ import annotations

import collections
import json
import os
import pathlib

import pytest

from rbp.classify import _NOT_FOUND, _get, _valid

FIX = pathlib.Path(__file__).parent / "fixtures"
BACKLOG = json.loads((FIX / "backlog_2026-07-19.json").read_text())
PROBE = json.loads((FIX / "probe_2026-08-20.json").read_text())

# Measured 2026-08-20, 32 days after the snapshot. Every one of these IDs was
# already >=14 days publicly referenced when captured.
EXPECT_RESERVED = 232
EXPECT_PUBLISHED = 224
TOTAL = 456

live_only = pytest.mark.skipif(
    os.environ.get("RBP_LIVE_TESTS") != "1",
    reason="live endpoint test; set RBP_LIVE_TESTS=1",
)


# --------------------------------------------------------------------------
# frozen: the phase 1 acceptance criterion
# --------------------------------------------------------------------------

def test_fixture_is_the_documented_snapshot():
    assert len(BACKLOG["cve_ids"]) == TOTAL
    assert len(PROBE["results"]) == TOTAL


def test_historical_backlog_reclassifies_as_documented():
    """The 456 IDs the old dual-oracle engine called `DNE` resolve to
    232 RESERVED / 224 PUBLISHED under the reservation endpoint."""
    tally = collections.Counter(r["state"] for r in PROBE["results"].values())
    assert tally["RESERVED"] == EXPECT_RESERVED
    assert tally["PUBLISHED"] == EXPECT_PUBLISHED
    assert sum(tally.values()) == TOTAL


def test_nothing_was_never_allocated():
    """None of the 456 were phantom IDs. The old `DNE` label conflated
    'reserved' with 'never existed'; here the population is entirely real."""
    states = {r["state"] for r in PROBE["results"].values()}
    assert _NOT_FOUND not in states
    assert states == {"RESERVED", "PUBLISHED"}


def test_owner_is_redacted_for_exactly_the_reserved_population():
    """The finding the site is built on: the assigner is served for published
    records and withheld for reserved ones."""
    for cve, r in PROBE["results"].items():
        if r["state"] == "RESERVED":
            assert r["owning_cna"] == "[REDACTED]", cve
        else:
            assert r["owning_cna"] not in ("", "[REDACTED]", None), cve


def test_resolved_records_prove_these_were_real_gaps():
    """224 of 456 self-healed, which is what makes the other 232 indefensible:
    the same pipeline that found them watched half of them get fixed."""
    owners = collections.Counter(
        r["owning_cna"] for r in PROBE["results"].values() if r["state"] == "PUBLISHED"
    )
    assert sum(owners.values()) == EXPECT_PUBLISHED
    # One CNA dominates; the old attributor inferred 70 of these, under by ~3x.
    assert owners.most_common(1)[0] == ("GitHub_M", 213)


@pytest.mark.parametrize("cid,ok", [
    ("CVE-2026-2574", True), ("CVE-1999-0001", True), ("CVE-2026-12345678", True),
    ("CVE-2026-123", False), ("NOT-A-CVE", False), ("cve-2026-2574", False), ("", False),
])
def test_id_validation(cid, ok):
    assert _valid(cid) is ok


# --------------------------------------------------------------------------
# live: invariants that survive drift
# --------------------------------------------------------------------------

@live_only
def test_live_endpoint_semantics():
    assert _get("CVE-1999-0001")["state"] == "PUBLISHED"
    assert _get("CVE-2026-9999999")["state"] == _NOT_FOUND
    assert _get("NOT-A-CVE")["state"] == "MALFORMED"


@live_only
def test_live_backlog_only_ever_shrinks():
    """RESERVED -> PUBLISHED is one-way. Today's reserved count must never
    exceed the 2026-08-20 measurement; if it does, the oracle is misreading."""
    import concurrent.futures as cf

    ids = BACKLOG["cve_ids"]
    with cf.ThreadPoolExecutor(24) as ex:
        states = list(ex.map(lambda c: _get(c)["state"], ids))
    tally = collections.Counter(states)
    assert tally["RESERVED"] <= EXPECT_RESERVED
    assert tally["PUBLISHED"] >= EXPECT_PUBLISHED
    assert tally["RESERVED"] + tally["PUBLISHED"] == TOTAL


@live_only
def test_live_reserved_owner_still_redacted():
    """If this fails, MITRE unredacted the field. See PLAN.md section 8.
    That is a win, not a regression. Update the site's framing."""
    reserved = [c for c, r in PROBE["results"].items() if r["state"] == "RESERVED"]
    sample = [c for c in reserved[:20] if _get(c)["state"] == "RESERVED"]
    assert sample, "no still-reserved IDs in sample; widen it"
    assert all(_get(c)["assigner"] == "[REDACTED]" for c in sample)

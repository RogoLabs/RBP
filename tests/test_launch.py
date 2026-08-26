"""
The launch go/no-go checklist (review Part 2).

The risk this file guards is specific. Six of the nine conditions are declared
literals rather than derived facts, so the checklist can lie in a way the coverage
gate cannot: someone edits a status to MET, the site publishes "9 of 9 are met",
and nothing contradicts it. These tests make an unjustified MET fail.
"""
from __future__ import annotations

import pathlib
import re

import pytest

from rbp import launch


def _summary(effective=121, total=434, sighted=159, own=2, profile="weekly"):
    return {"coverage": {
        "total_cnas": total, "cnas_effective": effective, "cnas_sighted": sighted,
        "cnas_own_channel": own, "min_sightings": 3, "pct_effective":
            round(100 * effective / total, 1), "pct_cnas": round(100 * sighted / total, 1),
        "profile": profile, "top_n": 50, "top_covered": 37}}


def _gate(pct=27.9, cleared=False):
    return {"cleared": cleared, "pct": pct, "required": 50.0}


def test_all_conditions_are_present_and_numbered_once():
    items = launch.checklist(_summary(), _gate())
    assert [c["n"] for c in items] == [1, 2, 3, 5, 6, 7, 8, 9], (
        "condition 4 was RETIRED with the withhold channel on 2026-08-26, "
        "not renumbered: the numbers are how the review's items are cited "
        "and shifting them would silently repoint every reference")
    assert all(c["title"] and c["detail"] for c in items)


def test_every_unmet_condition_states_what_blocks_it():
    """An unmet condition with no reason is indistinguishable from an oversight,
    and the whole point of publishing this list is that a reader can see why."""
    for c in launch.checklist(_summary(), _gate()):
        if c["status"] != launch.MET:
            assert c["blocks"], f"condition {c['n']} is unmet with no reason given"


def test_a_met_condition_never_carries_a_blocking_reason():
    for c in launch.checklist(_summary(), _gate()):
        if c["status"] == launch.MET:
            assert not c["blocks"], f"condition {c['n']} is met but claims to be blocked"


def test_status_is_only_cleared_when_every_condition_is_met():
    st = launch.status(_summary(), _gate())
    assert st["total"] == 8, "condition 4 retired 2026-08-26 with the withhold channel"
    assert st["met"] + st["unmet"] == st["total"]
    assert st["cleared"] is (st["unmet"] == 0)
    assert len(st["blocking"]) == st["unmet"]


def test_the_checklist_can_still_go_false():
    """The whole point of the list is that it is checkable, and it now clears on
    the fixture, so the guard against "cannot fail" has to be explicit. A
    condition below the gate must un-clear it."""
    st = launch.status(_summary(effective=10), _gate(pct=2.3, cleared=False))
    assert st["cleared"] is False and st["blocking"]


def test_coverage_condition_is_derived_not_declared():
    """Condition 1 must track the actual number. If it were a literal it would go
    stale the first time coverage moved, which is every run."""
    below = launch.checklist(_summary(effective=10), _gate(pct=2.3))[0]
    assert below["status"] == launch.UNMET
    assert "2.3%" in below["blocks"]
    # Clearing coverage alone is not enough: the roster is still unpinned.
    at_gate = launch.checklist(_summary(effective=300), _gate(pct=69.1, cleared=True))[0]
    assert at_gate["status"] == launch.UNMET
    assert "pinned roster" in at_gate["blocks"]
    assert "coverage is" not in (at_gate["blocks"] or "")


def test_coverage_condition_reports_the_profile_the_cron_actually_ran():
    """The review's wording: coverage "on the profile the cron actually runs". A
    deep-profile figure published without the profile beside it would overstate
    what the four-times-daily weekly run can see."""
    c = launch.checklist(_summary(profile="deep"), _gate())[0]
    assert "'deep'" in c["detail"]
    missing = launch.checklist(_summary(profile=None), _gate())[0]
    assert missing["status"] == launch.UNMET
    assert "profile is not recorded" in missing["blocks"]


def test_the_gate_and_the_checklist_are_not_the_same_question():
    """Conflating them is the specific error Part 2 was written about: five review
    findings had assumed coverage was the only gate.

    This used to assert that something OTHER than coverage was outstanding, which
    was true while five conditions were open and expired the moment they landed.
    Eight of nine are now met and coverage is the only one left, so the checklist
    legitimately coincides with the gate today. That is a fact about progress, not
    an invariant, and a test that pins it would fail on the next thing we fix.

    What IS invariant: `cleared` is true only when every condition is met, and the
    coverage condition is DERIVED, so a cleared gate cannot clear the checklist by
    itself while any other condition is unmet.
    """
    # A cleared gate, with the coverage condition's other requirements unmet
    # (the fixture has no pinned roster), must not clear the checklist.
    st = launch.status(_summary(effective=434), _gate(pct=100.0, cleared=True))
    assert st["cleared"] is False
    assert st["unmet"] >= 1
    assert 1 in {int(b.split(".")[0]) for b in st["blocking"]}, (
        "coverage is reported as met despite an unpinned roster")

    # And `cleared` tracks the count rather than being set independently.
    assert st["cleared"] is (st["unmet"] == 0)
    assert st["met"] + st["unmet"] == st["total"]


def test_cleared_requires_every_condition_not_just_most():
    """The roll-up must not round up. With one condition outstanding the answer is
    no, whatever the other eight say."""
    st = launch.status(_summary(), _gate())
    if st["unmet"]:
        assert st["cleared"] is False
    assert st["cleared"] == (st["unmet"] == 0)


def test_declared_conditions_carry_a_review_item_reference():
    """Each declared status has to be traceable to the finding that asked for it,
    or it is an assertion with no provenance."""
    for c in launch.checklist(_summary(), _gate()):
        assert c.get("item"), f"condition {c['n']} cites no review item"
        assert re.fullmatch(r"[0-9]+(, ?[0-9]+)*", c["item"]), c["item"]


def test_no_condition_claims_a_status_outside_the_two_allowed():
    """There is deliberately no "partial". A partially met launch condition is an
    unmet one, and the word invites rounding up."""
    for c in launch.checklist(_summary(), _gate()):
        assert c["status"] in (launch.MET, launch.UNMET), c


def test_the_module_forbids_a_third_status_word():
    """Grep-style, because the temptation to add "partial" arrives exactly when a
    condition is nearly done, which is when rounding up is most attractive."""
    body = (pathlib.Path(launch.__file__)).read_text()
    # Docstrings AND comments out: both explain why the word is banned, and the
    # explanation must not trip the rule. Exactly the trap the templates grep hit.
    code = re.sub(r'""".*?"""', "", body, flags=re.S)
    code = re.sub(r"#.*", "", code)
    for word in ("PARTIAL", '"partial"', "'partial'"):
        assert word not in code, f"{word} appeared in executable code in launch.py"


def test_plan_and_site_publish_the_same_number_of_conditions():
    """The review asked for this list in PLAN.md AND on /method. Two copies drift;
    this asserts the count at least stays in step."""
    plan = (pathlib.Path(__file__).parent.parent / "PLAN.md").read_text()
    section = plan.split("## 8d.")[1].split("\n## ")[0] if "## 8d." in plan else ""
    assert section, "PLAN.md has no 8d launch checklist section"
    numbered = re.findall(r"^\| ?\*?\*?([1-9])\.?\*?\*? ?\|", section, re.M)
    if not numbered:
        numbered = re.findall(r"^(?:- )?\*\*([1-9])\.", section, re.M)
    assert len(set(numbered)) == 8, (
        f"PLAN.md 8d lists {len(set(numbered))} conditions, launch.py has 9")


# 4 moved to UNMET on 2026-08-23; 7 was UNMET the same day and fixed the same
# day (retention 2 days -> 90 days plus monthly), so it is back to MET on a
# bounded promise. Originally, and this is that deliberate update.
# Both were declared MET and both were falsified by checking rather than by
# reasoning: condition 4's automatic route needs an issue label an ordinary
# GitHub account cannot apply, and condition 7's dated archive is deleted in
# about two days by prune_snapshots(keep=2). Condition 5 stays MET because its
# mechanism, the 4-day floor, is real; only its stated doctrine was wrong, and
# the title changed instead.
@pytest.mark.parametrize("n,expect_met", [(2, True), (3, True), (5, True),
                                          (6, True), (7, True),
                                          (8, True), (9, True)])
def test_declared_statuses_match_what_is_actually_built(n, expect_met):
    """Pins today's honest position so a status cannot drift silently. When one of
    these genuinely lands, this test is the thing that has to be updated
    deliberately, in the same commit, which is the point."""
    c = next(c for c in launch.checklist(_summary(), _gate()) if c["n"] == n)
    assert (c["status"] == launch.MET) is expect_met, (
        f"condition {n} changed status; update this test in the same commit that "
        "changed it, and say so in the message")


# --------------------------------------------------------------------------
# the rehearsal escape (Part 2 condition 9)
# --------------------------------------------------------------------------

def test_launched_alone_is_still_demoted_below_the_gate(tmp_path, monkeypatch):
    """The demotion is correct for a real run and must not weaken. Bypassing the
    coverage gate takes TWO deliberate levers, so no single setting can both request
    a launch and waive the check on it."""
    import importlib
    from rbp import site as site_mod
    monkeypatch.setenv("RBP_LAUNCHED", "1")
    monkeypatch.delenv("RBP_REHEARSE", raising=False)
    importlib.reload(site_mod)
    assert site_mod.REHEARSE is False
    monkeypatch.delenv("RBP_LAUNCHED", raising=False)
    importlib.reload(site_mod)


def test_the_rehearsal_flag_is_a_separate_lever(monkeypatch):
    """Not a mode of RBP_LAUNCHED. A single variable that both requests a launch and
    waives the gate is one typo away from launching below coverage."""
    import importlib
    from rbp import site as site_mod
    for val, expect in (("1", True), ("true", True), ("yes", True),
                        ("", False), ("0", False)):
        monkeypatch.setenv("RBP_REHEARSE", val)
        importlib.reload(site_mod)
        assert site_mod.REHEARSE is expect, val
    monkeypatch.delenv("RBP_REHEARSE", raising=False)
    importlib.reload(site_mod)


def test_the_workflow_only_sets_the_rehearsal_flag_on_a_dry_run():
    """The escape is safe because deploy is skipped on a dry run, so the artefact is
    built and discarded. If the flag could be set on a real run it would be a gate
    bypass rather than a rehearsal."""
    import pathlib
    wf = (pathlib.Path(__file__).parent.parent / ".github" / "workflows"
          / "deploy.yml").read_text()
    line = next(l for l in wf.splitlines() if l.strip().startswith("RBP_REHEARSE:"))
    assert "inputs.dry_run == true" in line, (
        "RBP_REHEARSE is not gated on dry_run, so it is a gate bypass")
    assert "rehearse_launch == true" in line


def test_the_rehearsal_escape_announces_itself_loudly():
    """A build that silently ignores the gate is indistinguishable from a gate that
    stopped working."""
    import inspect
    from rbp import site as site_mod
    src = inspect.getsource(site_mod.load)
    i = src.index("REHEARSE")
    assert "must not" in src[i:i + 900], "the rehearsal message does not warn"


# --------------------------------------------------------------------------
# the checklist has to be able to go false (review item 16)
# --------------------------------------------------------------------------

def test_a_hand_verified_condition_expires():
    """`_DECLARED` hard-coded six of nine conditions as MET, and four of the six
    were false on the day someone finally looked. The docstring says the
    checklist exists so the commitment is "checkable from outside", and a
    condition that cannot go false is not checkable.

    Deriving what the run can observe is the better fix and is done for
    conditions 1 to 4. For the rest, "met once in August" must stop reading as
    "met today"."""
    fresh = launch.status(_summary(), _gate(), today="2026-08-25")
    stale = launch.status(_summary(), _gate(), today="2026-12-01")
    assert stale["unmet"] > fresh["unmet"], (
        "no condition expired after three months; the checklist is still a claim")
    for c in stale["conditions"]:
        if c["n"] in (5, 6, 8, 9):
            assert c["status"] == launch.UNMET
            assert "verified" in (c["blocks"] or "")


def test_an_undated_declared_condition_cannot_claim_met():
    """An undated hand-verification is exactly the thing the expiry guards
    against, so absence must fail closed rather than never expire."""
    cond = {"n": 99, "title": "x", "detail": "", "status": launch.MET,
            "blocks": None, "verified_on": None}
    out = launch._expire(cond, today="2026-08-25")
    assert out["status"] == launch.UNMET
    assert "no usable verification date" in out["blocks"]


def test_every_declared_condition_carries_a_verification_date():
    """A new condition added without one would be permanently true, which is the
    defect this whole section exists to remove."""
    for c in launch._DECLARED:
        assert "verified_on" in c, f"condition {c['n']} has no verified_on"
        if c["status"] == launch.MET:
            assert c["verified_on"], f"condition {c['n']} claims met with no date"


def test_the_retired_condition_is_gone_rather_than_quietly_met():
    """Condition 4 asked for a monitored correction channel with a suppression
    lever behind it. The channel was removed on 2026-08-26, so the condition is
    RETIRED: absent from the list, with the reasoning kept in rbp/launch.py.

    Absent rather than met, because marking it met would be false: nothing
    monitors anything now. A checklist that can be satisfied by deleting the
    thing it asks about is not a checklist.
    """
    items = launch.checklist(_summary(), _gate(), today="2026-08-25")
    assert not [c for c in items if c["n"] == 4]
    import inspect
    src = inspect.getsource(launch)
    assert "CONDITION 4 IS RETIRED" in src, (
        "the retirement was deleted rather than recorded, so a reader cannot "
        "tell it was answered from it being quietly dropped")
    # Whitespace-normalised: the quote wraps across comment lines.
    flat = " ".join(src.replace("#", " ").split())
    assert "too much overhead for a side project" in flat, "the reason is not recorded"
    assert "WHAT THIS COSTS" in src, (
        "the retirement records the decision but not its cost, which is the half "
        "a future reader needs")


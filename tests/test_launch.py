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


def test_all_nine_conditions_are_present_and_numbered_once():
    items = launch.checklist(_summary(), _gate())
    assert [c["n"] for c in items] == list(range(1, 10))
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
    assert st["total"] == 9
    assert st["met"] + st["unmet"] == 9
    assert st["cleared"] is (st["unmet"] == 0)
    assert st["cleared"] is False, "not launch-ready today; if this flips, check why"
    assert len(st["blocking"]) == st["unmet"]


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
    findings had assumed coverage was the only gate. A cleared coverage gate must
    not clear the checklist."""
    st = launch.status(_summary(effective=434), _gate(pct=100.0, cleared=True))
    assert st["cleared"] is False
    assert st["unmet"] >= 5


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
    assert len(set(numbered)) == 9, (
        f"PLAN.md 8d lists {len(set(numbered))} conditions, launch.py has 9")


@pytest.mark.parametrize("n,expect_met", [(2, True), (3, True), (4, True), (5, True),
                                          (6, False), (7, False),
                                          (8, False), (9, False)])
def test_declared_statuses_match_what_is_actually_built(n, expect_met):
    """Pins today's honest position so a status cannot drift silently. When one of
    these genuinely lands, this test is the thing that has to be updated
    deliberately, in the same commit, which is the point."""
    c = next(c for c in launch.checklist(_summary(), _gate()) if c["n"] == n)
    assert (c["status"] == launch.MET) is expect_met, (
        f"condition {n} changed status; update this test in the same commit that "
        "changed it, and say so in the message")

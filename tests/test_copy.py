"""
The copy and citation pass (review item 11).

"Every item here is a place where the site's public surfaces contradict each other
or omit what cuts against them, on a project whose entire authority rests on
quoting accurately."

Every policy quotation was already pinned by tests/test_policy.py and none of the
historical claims were, which is backwards: the historical claims are the
contested ones. These pin the claims and the copy rules.

Asserted against RENDERED pages where possible, not templates, because a rule that
holds in the source and not in the output protects nothing.
"""
from __future__ import annotations

import html
import json
import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).parent.parent
TEMPLATES = ROOT / "templates"
PLACEHOLDER = ROOT / "placeholder.html"


def _live_pages(built):
    """The dashboard pages this build actually produced.

    Was a hardcoded list naming cves.html and changes.html. Those were deleted on
    2026-08-26 and the tests raised FileNotFoundError, which is the loud version
    of the failure; the quiet version is a list that stops covering a page nobody
    remembered to add. Globbed, minus the holding page, which is a standalone
    file that shares nothing with base.html by design.
    """
    return [p.name for p in sorted(built.glob("*.html"))
            if p.name not in ("about-this-count.html", "index.html")]


def _text(path):
    """Tags stripped, whitespace collapsed, entities resolved."""
    raw = pathlib.Path(path).read_text()
    return re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", raw)))


@pytest.fixture
def built(built_site):
    """The rendered site, built for this session from a fixture snapshot.

    Was `ROOT / "site"`, skipped when absent. `site/` is gitignored, so it is
    absent on every CI runner: all eighteen assertions in this file skipped in
    CI, including in the `test` job that gates the publication, and ran locally
    against whatever stale build happened to be in the working tree. See
    tests/_sitefixture.py.
    """
    return built_site


# --------------------------------------------------------------------------
# contradictions between one page and another
# --------------------------------------------------------------------------

def test_no_template_says_the_table_was_public_for_about_a_year():
    """index.html said "after about a year public" while policy.html, one click
    away, labelled that figure a correction: "closer to four months than a year"."""
    for tpl in list(TEMPLATES.glob("*.html")) + [PLACEHOLDER]:
        body = re.sub(r"\{#.*?#\}", "", tpl.read_text(), flags=re.S)
        assert "about a year" not in body, (
            f"{tpl.name} still claims the RBP table was public for about a year; "
            "policy.html corrects this to closer to four months")


def test_no_page_claims_to_fill_the_gap_left_by_the_archived_series():
    """index.html said the Metrics page reports "nothing on the overlap between
    them, which is the gap this site fills" while policy.html said "The two are not
    comparable and this site does not replace it". /policy is canonical."""
    for tpl in list(TEMPLATES.glob("*.html")) + [PLACEHOLDER]:
        body = tpl.read_text()
        assert "gap this site fills" not in body, tpl.name
        assert "this site fills" not in body, tpl.name


def test_the_advisory_title_column_is_gone_everywhere():
    """`<th>Advisory title</th>` shipped on three pages while data.html retracted
    exactly that word: the field is a summary, often a body rather than a title."""
    for tpl in TEMPLATES.glob("*.html"):
        assert ">Advisory title<" not in tpl.read_text(), tpl.name


def test_the_meta_description_makes_no_absolute_claim(built):
    """The one string search engines and link previews quote verbatim. It began
    "Every CVE ID that is reserved..." on a run at 27.9% effective CNA coverage.
    "Every" is the absolute the holding page was corrected to remove."""
    for page in _live_pages(built):
        raw = (built / page).read_text()
        m = re.search(r'<meta name="description" content="([^"]*)"', raw)
        assert m, page
        desc = m.group(1)
        assert not desc.lower().startswith("every"), desc
        assert "Program's own term" in desc or "own term" in desc, desc


# --------------------------------------------------------------------------
# quote the clauses that cut against the site
# --------------------------------------------------------------------------

COUNTER_QUOTES = [
    "incident response",
    "short delays",
    "resource constraints",
    "volume, complexity",
    "volume, history",
]


@pytest.mark.parametrize("phrase", COUNTER_QUOTES)
def test_the_front_page_quotes_the_clauses_that_cut_against_it(built, phrase):
    """The front page quoted the policy's "does not condone any unnecessary,
    intentional, or routine delay" and omitted, from the same paragraph, every
    clause that softens it. /policy already states this project's own standard:
    "quoting only the discretionary parts would be selective." It was broken on the
    section that governs the headline."""
    assert phrase in _text(built / "overview.html"), (
        f"the front page omits the policy's {phrase!r} clause")


def test_counter_quotes_are_filed_under_the_sections_they_occupy(built):
    """Two of the four are not in Timely Publication. Misfiling them would be the
    exact error tests/test_policy.py exists to prevent."""
    text = _text(built / "overview.html")
    for heading in ("Timely Publication", "Notification and Remediation", "Enforcement"):
        assert heading in text, heading
    # Ordering: the volume/complexity clause belongs to Notification and
    # Remediation, so that heading must precede it.
    assert text.index("Notification and Remediation") < text.index("volume, complexity")
    assert text.index("Enforcement") < text.index("volume, history")


def test_the_counter_quotes_are_verbatim_against_the_pinned_policy():
    """The site's authority rests on quoting accurately, so these are checked
    against the pinned document rather than against memory."""
    policy = json.loads(
        (ROOT / "tests" / "fixtures" / "rbp_policy_v2.json").read_text())["full_text"]
    flat = re.sub(r"\s+", " ", policy)
    for quote in [
        "recognizing that such publication may, at times, coincide with ongoing "
        "vulnerability or incident response activities",
        "internal processes may necessitate short delays",
        "no later than the deadline stated by their TL-Root or Root (which may "
        "account for factors such as volume, complexity, and resource constraints)",
        "may take further action depending on the",
    ]:
        assert quote in flat, f"not in RBP Policy v2.0.0: {quote!r}"


def test_the_front_page_answers_the_counter_quotes_rather_than_only_listing_them(built):
    """The review's ask was to quote them AND answer them in the same breath with
    the buffer, the median and the 180d+ bucket, then state the sentence they
    license."""
    text = _text(built / "overview.html")
    assert "only deadline that binds a specific row is one a Root set privately" in text
    assert "never calls a single row overdue" in text


# --------------------------------------------------------------------------
# historical claims: pinned, because these are the contested ones
# --------------------------------------------------------------------------

def test_the_issue_numbers_and_dates_are_pinned(built):
    """#835 withdrew the v1.0 PDF; #842 commented out the table thirteen days
    later. Both numbers and both dates appear on the site and neither was pinned."""
    text = _text(built / "overview.html") + _text(built / "policy.html")
    assert "842" in text and "835" in text
    assert "7 February 2022" in text
    assert "February 2021" in text
    assert "Q3" in text and "2021" in text


def test_the_three_item_restructuring_is_described_not_asserted(built):
    """"Item 2 of three" only exculpates if a reader can see what items 1 and 3
    were. The first draft of this asserted them from memory and was wrong; they
    come from cve-website#842 and are now named with the issue linked."""
    text = _text(built / "overview.html")
    assert "item 2 of a three-item" in text
    assert "issue" in text and "842" in text
    # Item 1 and item 3, from the issue body.
    assert "Reserved IDs tables" in text or "Published Records" in text
    assert "quarterly to annual" in text


def test_the_n_a_final_column_fact_is_on_both_front_doors(built):
    """The most exculpatory fact available: the series had stopped being populated
    before anyone commented it out. It was on /policy only, which nobody can reach
    pre-launch."""
    assert "N/A" in _text(built / "overview.html")
    assert "N/A" in _text(built / "policy.html")
    assert "N/A" in _text(built / "index.html"), "missing from the holding page"


def test_the_flow_versus_stock_distinction_is_on_the_holding_page():
    """The holding page is the only page anyone can reach pre-launch, so it is
    where good faith is cheapest to establish. It implied this site publishes the
    Program's archived metric, which /policy retracts on a page nobody can reach."""
    text = _text(PLACEHOLDER)
    assert "flow" in text and "stock" in text
    assert "not comparable" in text
    assert "minority of CNAs" in text, "the coverage bound is missing"


def test_the_ask_is_anchored_on_the_in_force_document(built):
    """Asking for the return of a v1.0-era quarterly table under a policy that
    withdrew the arithmetic that table scored is answerable with "that was v1.0".
    v2.0.0 names "Program metrics and audits" as its own identification channel.

    The `if not exists(): continue` this used to carry was a skip wearing a
    loop's clothing: it never raised, so it never reported, and on CI it checked
    the placeholder and silently walked past the built page. Both are asserted
    now, unconditionally.
    """
    for path in (PLACEHOLDER, built / "overview.html"):
        assert "metrics and audits" in _text(path), path


# --------------------------------------------------------------------------
# claims stated as completed facts
# --------------------------------------------------------------------------

def test_no_built_page_states_an_interval_as_a_completed_fact(built):
    """A grep guard for the class, not just the instance that was found."""
    banned = ["about a year", "for over a year", "for more than a year public"]
    for page in built.glob("*.html"):
        text = _text(page).lower()
        for phrase in banned:
            assert phrase not in text, f"{page.name}: {phrase!r}"


# --------------------------------------------------------------------------
# the framing assets must survive launch
# --------------------------------------------------------------------------

def test_the_holding_page_survives_launch_at_a_permanent_route(built):
    """placeholder.html was copied over index.html ONLY in the not-launched
    branch, so flipping RBP_LAUNCHED would have deleted it and with it the
    paragraphs doing the site's framing work.

    A grep of the built dashboard once returned zero occurrences of "glossary";
    the only surviving framing was one line of footer small print. Launch day
    would have quietly destroyed the most careful copy on the site.

    ASSERTED AS CLAIMS, not as sentences. This used to probe for the phrases
    "not our term" and "unblind". The first was a defensive framing and the
    second was a policy ask, and both were removed in the 2026-08-26 voice pass:
    the site describes what it measures rather than arguing for a change. What
    has to survive is the PROVENANCE, the naming warrant, and the reason
    ownership is not published. A test keyed to a sentence breaks on every edit
    and says nothing about whether the point is still made.
    """
    about = built / "about-this-count.html"
    assert about.exists(), "the holding page has no permanent route"
    text = _text(about)
    low = text.lower()
    assert "cve program's own" in low or "cve program&#39;s own" in low, (
        "the page no longer says the term belongs to the CVE Program")
    assert "glossary" in low, "the glossary is not cited as the source"
    assert "4.5.1.7" in text, "the naming-warrant quotation is missing"
    assert "secretariat may publicly identify" in low, (
        "4.5.1.7 is cited by number without being quoted")
    assert "reserved space" in low, (
        "the reason this site does not publish inferred ownership is missing")


def test_the_about_route_exists_in_both_postures(tmp_path, monkeypatch):
    """Asserted by building BOTH postures, because "it works pre-launch" is
    exactly what was true before and exactly what was not the problem."""
    import importlib
    from rbp import site as site_mod

    snaps = tmp_path / "snapshots" / "2026-08-20"
    snaps.mkdir(parents=True)
    (tmp_path / "data").mkdir()
    (snaps / "backlog.json").write_text("[]")
    (snaps / "cnas.json").write_text("[]")
    (snaps / "summary.json").write_text(json.dumps({
        "total": 0, "past_expectation": 0, "oldest_days": None, "median_days": None,
        "named_cnas": 0, "must_rows": 0, "should_rows": 0, "clock_unknown": 0,
        "unmeasurable_rows": 0, "candidate_rows": 0, "undated_excluded": 0,
        "min_age_days": 7, "age_buckets": {},
        "inference": {"k": 3, "run_coverage": 0.0,
                      "leave_one_out": {"precision": 0.99, "coverage": 0.6,
                                        "decided": 0},
                      "live": {"graded": 0, "correct": 0, "precision": None,
                               "outstanding": 0, "by_tier": {}}},
        "feeds": {"requested": [], "failures": [], "attempts": 0, "truncated": [],
                  "detail": {}},
        "coverage": {"total_cnas": 10, "cnas_effective": 6, "cnas_own_channel": 1,
                     "cnas_sighted": 8, "min_sightings": 3, "pct_cnas": 80.0,
                     "pct_effective": 60.0, "observed_pct": 1.0, "profile": "weekly"},
    }))

    for launched in (False, True):
        monkeypatch.setenv("RBP_LAUNCHED", "1" if launched else "")
        importlib.reload(site_mod)
        out = tmp_path / ("post" if launched else "pre")
        site_mod.build(str(out), str(tmp_path / "snapshots"), str(tmp_path / "data"))
        assert (out / "about-this-count.html").exists(), (
            f"about route missing with launched={launched}")
    monkeypatch.delenv("RBP_LAUNCHED", raising=False)
    importlib.reload(site_mod)


# --------------------------------------------------------------------------
# the lead screen (items 19 and 20)
# --------------------------------------------------------------------------

def test_the_lead_never_claims_corroboration_it_cannot_show(built):
    """The version-skew trap, and the third instance today of absence defaulting
    to the stronger reading.

    The first draft read `corroborated or total`, so a snapshot written before that
    key existed rendered "506 CVE IDs are referenced in two or more independent
    public advisories" when only ~172 were. On the lead sentence."""
    import re as _re
    from jinja2 import Environment, FileSystemLoader, select_autoescape
    env = Environment(loader=FileSystemLoader(str(TEMPLATES)),
                      autoescape=select_autoescape(["html"]),
                      trim_blocks=True, lstrip_blocks=True)
    src = (TEMPLATES / "index.html").read_text()
    # The guard must test the VALUE, not truthiness, and must not use `or`.
    lead = src[src.index("lead-count"):src.index("</p>", src.index("lead-unit"))]
    assert "is not none" in lead, (
        "the lead sentence does not guard on the value existing")
    assert "corroborated') or " not in lead, (
        "`or` in the lead figure silently upgrades a missing key to the total")


def test_the_bound_strip_guards_on_values_not_on_the_parent_dict(built):
    """`summary.coverage` existing does not mean cnas_effective does, and Jinja
    renders a missing key as empty, so the unguarded version produced "Feeds reach
    of 434 CNAs (%)": a sentence with holes where the numbers go."""
    src = (TEMPLATES / "index.html").read_text()
    strip = src[src.index("bound-strip"):src.index("</ul>")]
    assert "cnas_effective') is not none" in strip


def test_no_page_leads_with_a_single_cna_share(built):
    """A lead-screen tile reporting that one CNA holds the majority is a leaderboard
    with one entrant, which PLAN 2a forbids and which clock.per_cna deliberately
    refuses to build in the per-CNA view. It belongs on /method as an instrument
    reading."""
    front = _text(built / "overview.html")
    assert "Share of named rows held by the single largest" not in front
    assert "largest single holder accounts for" in _text(built / "method.html")


def test_the_headline_count_states_its_own_base(built):
    """Four lead tiles previously carried four different unstated denominators,
    and a reader takes them all as shares of the headline.

    The tiles went with the redesign on 2026-08-26: they were instrument
    readings about this site's own machinery, not about the CVEs, and the list
    is the front door now. The CLAIM survives them, because it is the one that
    mattered: a number on the lead screen has to say what it is a number OF.
    """
    front = _text(built / "overview.html")
    assert "reserved, public, unpublished" in front, (
        "the headline count no longer says what it is counting")
    # And the qualifier that makes it a floor rather than a census.
    assert "floor" in front, "the lead screen does not say the count is a floor"


def test_the_framing_sentence_is_on_the_lead_screen(built):
    """Item 19: said once, in the lead block, not buried on /method."""
    front = _text(built / "overview.html")
    assert "Program-level transparency measurement, not a CNA scorecard" in front
    assert "block" in front and "feed" in front


def test_the_delegation_caveat_reaches_every_page_that_names_a_cna(built):
    """A row may be an ID delegated TO a CNA rather than withheld BY it, and nothing
    observable distinguishes them."""
    for page in _live_pages(built):
        assert "CNA-LR" in _text(built / page), page


def test_the_hostile_question_is_answered_on_the_site(built):
    """"So is the largest holder the worst offender?" is the headline that writes
    itself. The answer has to already be on the page rather than in a maintainer's
    head."""
    m = _text(built / "method.html")
    assert "worst offender" in m
    assert "most visible holder" in m


def test_link_previews_do_not_carry_the_count_before_launch(built):
    """Unfurlers do not read robots.txt, so a noindex page pasted into Slack still
    renders og:description. The gate is on promotion, and an unfurl in someone
    else's channel is promotion."""
    import re as _re
    for page in _live_pages(built):
        raw = (built / page).read_text()
        m = _re.search(r'og:description" content="([^"]*)"', raw)
        assert m, page
        assert not _re.match(r"^\d", m.group(1)), (
            f"{page} unfurls with a bare count pre-launch: {m.group(1)[:60]}")


def test_every_page_has_its_own_og_url_and_canonical(built):
    """One hard-coded root og:url on all seven pages meant every paste unfurled as
    the front page regardless of what was shared."""
    for page in _live_pages(built):
        raw = (built / page).read_text()
        assert f'og:url" content="https://rbptracker.org/{page}"' in raw, page
        assert f'rel="canonical" href="https://rbptracker.org/{page}"' in raw, page


def test_the_holding_page_unfurls_as_more_than_a_bare_link():
    """It is the only page anyone can reach pre-launch."""
    body = PLACEHOLDER.read_text()
    for tag in ('name="description"', 'property="og:title"',
                'property="og:description"', 'rel="canonical"'):
        assert tag in body, tag
    assert "og:description" in body and "not yet published" in body


# --------------------------------------------------------------------------
# claims the site refutes elsewhere on the site (review item 8)
# --------------------------------------------------------------------------
#
# Five statements the site made about the Program or about itself, each refuted
# by another page of the same site. All were live, all in the launched nav, and
# all the sort of thing a reader falsifies by scrolling. Four of the five had
# already propagated from one original into several files, which is why these
# are asserted across every template rather than at the place each was found.

import pathlib as _pl

_TPL = _pl.Path(__file__).parent.parent / "templates"
_RBP = _pl.Path(__file__).parent.parent / "rbp"


def _all_templates():
    return {p.name: p.read_text() for p in _TPL.glob("*.html")}


def test_the_site_does_not_call_the_count_the_programs_own_metric():
    """It is the Program's own DEFINITION, measured from outside. Calling it the
    Program's own metric was contradicted three hundred lines below on the same
    rendered page, by "This site does not replace that series and is not
    comparable to it." The definition claim is both accurate and stronger."""
    for name, body in _all_templates().items():
        assert "Program's own metric" not in body, name
        assert "Program&rsquo;s own metric" not in body, name


def test_the_redaction_claim_states_its_true_scope():
    """"Redacted for exactly this population" was wrong and /policy already said
    so, labelling itself a precision correction: the redaction covers EVERY
    reserved ID, tens of thousands a year, of which the RBP set is a subset.

    The true version is a better argument for the ask, because it explains why
    the Program has not already solved this."""
    for name, body in _all_templates().items():
        assert "for exactly this population" not in body, (
            f"{name} claims the redaction is scoped to RBPs; it covers every "
            "reserved ID")


def test_nothing_calls_rule_4517_this_sites_warrant():
    """policy.html says in bold that 4.5.1.7 "is not this site's permission to
    name anyone, and the site does not claim it as one". Three other places
    called it exactly that. /policy is right, so the others moved."""
    sources = {**_all_templates(),
               **{p.name: p.read_text() for p in _RBP.glob("*.py")}}
    for name, body in sources.items():
        assert "entire warrant" not in body, (
            f"{name} calls 4.5.1.7 this site's warrant while /policy denies it")


def test_no_page_claims_the_site_names_cnas():
    """/method opened with "The site names CNAs, so the method has to be
    auditable". v1 names nobody, so the sentence describing why the method
    matters described a site that does not exist."""
    for name, body in _all_templates().items():
        low = body.lower()
        assert "the site names cnas" not in low, name
        assert "this site names cnas" not in low, name


def test_the_method_page_says_the_must_reading_is_switched_off(built):
    """/method describes when the site claims rule 4.5.1.4 MUST. Under v1 it can
    never claim it: that reading needs an owner and v1 attributes nothing, so
    every one of the published rows is 4.5.1.6 SHOULD and the ordering is
    recorded as unmeasurable.

    Measured on the live site 2026-08-26: 640 of 640 rows, every one of them.

    A page that describes a capability without saying it is switched off is a
    page claiming a distinction it does not draw.
    """
    text = _text(built / "method.html")
    assert "no row takes 4.5.1.4" in text, (
        "/method describes the MUST reading without saying v1 cannot reach it")


def test_a_must_row_never_ships_without_the_evidence_must_requires(built):
    """The other half, on the data rather than the copy.

    4.5.1.4 is claimed only where the owning CNA's own feed carried the advisory
    first. So a row may carry MUST only alongside a measured ordering; MUST on an
    unmeasurable ordering is the site asserting a breach it did not observe.

    Not "no row claims MUST": the fixture deliberately exercises that rendering
    branch, and asserting the absence would test the fixture rather than the
    rule. On the LIVE site today all 640 rows are SHOULD, which is what the
    /method paragraph above says and what makes it true.
    """
    import json
    rows = json.loads((built / "data" / "rbp.json").read_text())
    rows = rows.get("rows") if isinstance(rows, dict) else rows
    assert rows, "no rows, so this asserts nothing"
    bad = [r["cve_id"] for r in rows
           if r.get("rule_strength") == "MUST"
           and r.get("disclosure_order") in (None, "", "unmeasurable")]
    assert not bad, (
        f"{len(bad)} row(s) claim MUST on an ordering nobody measured: {bad[:3]}")

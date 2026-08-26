"""
Launch day (review item 6).

"Flipping RBP_LAUNCHED and RBP_EPOCH together produces a red cron four times a day
for about a week while Pages keeps serving the pre-launch holding page, with no
notification step anywhere in the workflow. The observable result of launching is
that nothing happens and nobody is told."

Three separate failures met on the same run:

  the epoch excludes 100% of reportable rows for the whole buffer window, and the
  guard that catches it sits AFTER the corpus download and 674 API lookups;

  the zero-state page collapses to a header and one yellow line, because the whole
  body including every disclosure sat inside {% if summary.total %};

  and /changes declares the pair comparable and renders the entire backlog as "No
  longer listed, cause unverified", because `epoch` is emitted as `EPOCH or None`
  and the None-to-date transition short-circuits a truthiness test.
"""
from __future__ import annotations

import importlib
import json



# --------------------------------------------------------------------------
# refuse an unusable epoch before spending the network
# --------------------------------------------------------------------------

def _validate(epoch, today="2026-08-22", buffer_days=7, monkeypatch=None):
    from rbp import clock, cli
    monkeypatch.setenv("RBP_EPOCH", epoch)
    importlib.reload(clock)
    importlib.reload(cli)
    try:
        cli._validate_epoch_against_data(today, buffer_days)
        return None
    except SystemExit as e:
        return str(e)
    finally:
        monkeypatch.delenv("RBP_EPOCH", raising=False)
        importlib.reload(clock)
        importlib.reload(cli)


def test_an_epoch_set_to_today_is_refused_with_the_arithmetic(monkeypatch):
    """The newest reportable advisory date is always at least min_age_days before
    today, by construction: that is what the buffer does. So an epoch of today
    excludes everything, and the message has to show why rather than leave it to be
    deduced."""
    msg = _validate("2026-08-22", monkeypatch=monkeypatch)
    assert msg, "an epoch of today was accepted"
    for part in ("2026-08-22", "buffer", "7", "newest reportable date",
                 "2026-08-15", "Refusing before spending"):
        assert part in msg, part


def test_the_refusal_names_a_working_epoch(monkeypatch):
    """A refusal that does not say what to do instead gets worked around rather
    than fixed."""
    msg = _validate("2026-08-20", monkeypatch=monkeypatch)
    assert msg and "Set the epoch to 2026-08-15 or earlier" in msg


def test_an_epoch_at_the_boundary_is_accepted(monkeypatch):
    """Exactly min_age_days back is the newest epoch that can ever match a row."""
    assert _validate("2026-08-15", monkeypatch=monkeypatch) is None


def test_a_comfortably_past_epoch_is_accepted(monkeypatch):
    assert _validate("2026-07-01", monkeypatch=monkeypatch) is None


def test_no_epoch_is_accepted(monkeypatch):
    assert _validate("", monkeypatch=monkeypatch) is None


# --------------------------------------------------------------------------
# the comparability guard, keyed on presence rather than truthiness
# --------------------------------------------------------------------------

def _snap(tmp_path, date, rows, summary):
    d = tmp_path / date
    d.mkdir(parents=True, exist_ok=True)
    (d / "backlog.json").write_text(json.dumps(rows))
    (d / "summary.json").write_text(json.dumps(summary))
    return str(d)


def _row(cid, public="2026-01-01"):
    return {"cve_id": cid, "public_date": public, "days_public": 200,
            "owner": None, "owner_nameable": False}


def test_starting_an_epoch_is_not_comparable(tmp_path):
    """The failure this replaces. `epoch` is emitted as `EPOCH or None`, so the
    None-to-date transition short-circuited `is not None` and the pair was declared
    comparable on exactly the run where it is least comparable. Reproduced by
    execution before the fix: comparable True, no_longer_listed 150 of 150, which
    at live scale is ~500 CVE IDs rendered as a comma-joined mono dump under "No
    longer listed, cause unverified" on the first day anyone reads the site."""
    from rbp import site
    base = {"min_age_days": 7, "feeds": {"requested": ["debian"]}}
    prev = _snap(tmp_path, "2026-08-21", [_row("CVE-2025-1")], {**base, "epoch": None})
    now = _snap(tmp_path, "2026-08-22", [], {**base, "epoch": "2026-08-15"})

    ch = site._changes([], prev, now)
    assert ch["comparable"] is False, "the epoch flip was declared comparable"
    assert ch["epoch_started"] is True
    assert ch["no_longer_listed"] == [], "the whole backlog rendered as departures"


def test_unsetting_an_epoch_is_also_not_comparable(tmp_path):
    """The direction the old guard DID catch. It must keep catching it."""
    from rbp import site
    base = {"min_age_days": 7, "feeds": {"requested": ["debian"]}}
    prev = _snap(tmp_path, "2026-08-21", [_row("CVE-2025-1")], {**base, "epoch": "2026-08-01"})
    now = _snap(tmp_path, "2026-08-22", [], {**base, "epoch": None})
    ch = site._changes([], prev, now)
    assert ch["comparable"] is False
    assert ch["epoch_started"] is False, "unsetting is not starting"


def test_a_missing_previous_backlog_is_not_a_diff(tmp_path):
    """The tolerant read turned a missing previous backlog into an empty set, which
    makes every current row new and every previous row gone while `comparable`
    stays True. A diff computed against nothing must never publish as a diff."""
    from rbp import site
    d = tmp_path / "2026-08-21"
    d.mkdir(parents=True)
    (d / "summary.json").write_text(json.dumps({"min_age_days": 7, "epoch": None}))
    now = _snap(tmp_path, "2026-08-22", [], {"min_age_days": 7, "epoch": None})
    ch = site._changes([_row("CVE-2026-9")], str(d), now)
    assert ch["comparable"] is False
    assert "nothing to diff against" in ch["incomparable_reason"]
    assert ch["new"] == []


def test_an_emptied_feed_set_is_caught(tmp_path):
    """`if a and b and a != b` skipped the check whenever either side was empty,
    which is precisely a run where every feed was dropped. Same truthiness hole a
    third time, after min_age_days and epoch."""
    from rbp import site
    prev = _snap(tmp_path, "2026-08-21", [_row("CVE-2026-1")],
                 {"min_age_days": 7, "epoch": None,
                  "feeds": {"requested": ["debian", "ubuntu"]}})
    now = _snap(tmp_path, "2026-08-22", [], {"min_age_days": 7, "epoch": None,
                                             "feeds": {"requested": []}})
    ch = site._changes([], prev, now)
    assert ch["comparable"] is False
    assert "feed set changed" in ch["incomparable_reason"]


def test_epoch_eligible_rows_are_what_gets_diffed(tmp_path):
    """Better than a flag: an epoch change moves rows into the archive rather than
    through the diff. A pre-epoch row that leaves is not a departure, it was never
    eligible."""
    from rbp import site
    base = {"min_age_days": 7, "epoch": "2026-06-01",
            "feeds": {"requested": ["debian"]}}
    prev = _snap(tmp_path, "2026-08-21",
                 [_row("CVE-2025-old", "2025-01-01"), _row("CVE-2026-new", "2026-07-01")],
                 base)
    now = _snap(tmp_path, "2026-08-22", [], base)
    ch = site._changes([], prev, now)
    assert ch["comparable"] is True, "same epoch on both sides is comparable"
    # The pre-epoch row is excluded from `before`, so it cannot be a departure.
    assert "CVE-2025-old" not in ch["no_longer_listed"]
    assert "CVE-2026-new" in ch["no_longer_listed"]
    assert ch["dropped_by_epoch"] == 1


# --------------------------------------------------------------------------
# the archive, and the zero state
# --------------------------------------------------------------------------

def test_the_held_back_rows_stay_reachable_whether_or_not_an_epoch_is_set(built_site):
    """The epoch removes rows from the count. They must not vanish with it.

    /backlog-at-launch was removed on 2026-08-26 with the other four pages, so
    the promise moved to where it is machine-checkable: held-back rows are
    published as data on every run, epoch or no epoch, so the count can always be
    reconciled against what it excludes.
    """
    data = {p.name for p in (built_site / "data").glob("*.json")}
    assert "held-back.json" in data, sorted(data)


def test_the_held_back_rows_are_never_named(built_site):
    """These rows are outside the reportable set, so they are outside the set this
    site is willing to attribute, at any age.

    Was asserted against templates/backlog-at-launch.html. That page went in the
    2026-08-26 pivot and the held-back rows kept shipping as JSON, so the test
    was reading a file nobody rendered while the artefact it was about went
    unchecked. Asserted on the PUBLISHED bytes now, which is the stronger claim
    and the one that survives the next page being deleted.
    """
    import json as _json
    hb = built_site / "data" / "held-back.json"
    assert hb.exists(), "no held-back.json; this assertion has nothing to check"
    payload = _json.loads(hb.read_text())
    rows = payload.get("rows") if isinstance(payload, dict) else payload
    assert rows, "held-back.json carries no rows, so this test proves nothing"
    for field in ("owner", "owner_tier", "owner_method", "predicted_owner"):
        named = [r for r in rows if r.get(field) is not None]
        assert not named, f"{len(named)} held-back row(s) carry {field}"


def test_the_zero_state_is_rendered_server_side_and_explains_itself():
    """With an epoch set, a zero-row page IS the launch page for the whole buffer
    window, and it has to say why it is empty.

    Two failures, one after the other. First the whole body including every
    disclosure sat inside `{% if summary.total %}`, so a zero-row page collapsed
    to a header and one yellow line. Then the pivot moved the front page to
    list.html and dropped the zero state entirely, leaving only the JS
    "your filter matched nothing" state, which is a different thing and does not
    render at all when there is nothing to filter. This test read
    templates/index.html across both and passed.

    Server-side, deliberately: with zero rows the JS has nothing to have an
    opinion about, and a reader with JS off must still get the explanation.
    """
    import pathlib
    src = (pathlib.Path(__file__).parent.parent / "templates" / "list.html").read_text()
    assert "{% if not summary.total %}" in src, (
        "the front page has no zero state; with an epoch set this is launch day")
    zero = src.index("{% if not summary.total %}")
    block = src[zero:src.index("{% endif %}", zero)]
    assert "empty-state" in block, "the zero state is not styled as an empty state"
    assert "caveat warn" not in block, "the zero state is styled as a warning"
    assert "not a fault" in block
    # It must be OUTSIDE the row island, which only the JS reads. A zero state
    # emitted into <script id="rows"> is not rendered at all.
    assert zero < src.index('<script id="rows"'), (
        "the zero state is emitted after the row island, so it is inside the JS")


def test_the_no_longer_listed_dump_is_capped():
    """An unbounded comma-joined ID paragraph ran to 7,000 characters at 150 rows
    and ~500 IDs at live scale, which defeats the caveat directly above it.

    Moved to status.html on 2026-08-26 with the rest of the per-run movement.
    `site._changes` had been computed into the render context and rendered by
    nothing since the pivot deleted /changes, so this test and four others in
    this file were guarding an output no reader could reach.
    """
    import pathlib
    src = (pathlib.Path(__file__).parent.parent / "templates" / "status.html").read_text()
    assert "no_longer_listed[:50]" in src
    assert "Showing 50 of" in src

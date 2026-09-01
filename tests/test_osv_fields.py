"""`feed_osv` reads CVE ids from `aliases`, and for distro publishers that is the
wrong field.

Measured 2026-09-01, in-scope CVE ids by field across the five distro ecosystems
that also have a dedicated feed in this project:

               aliases   upstream   related
  Red Hat            0      3,140         0
  SUSE               0      6,833     6,833
  Rocky Linux        0      2,120         3
  AlmaLinux          0          0     2,116
  Alpine             0        899         0

`upstream` is a ratified OSV field (ossf/osv-schema#249, PR #312) for an
ASYMMETRIC reference: the CVE covers more than the distro record does, so
`aliases`, which asserts equivalence, would be wrong for them. Canonical stated
in that thread that they do not expect to adopt `aliases`.

These tests do not make the adapter read those fields. Reading all three buys 313
ids and 8 RBP candidates across eight ecosystems and 180 MB, which the project
declines on its own bandwidth standard. They pin that the decline is LOUD: an
archive that yields nothing must not record as a healthy part, which is how the
`+0 CNAs for every distro ecosystem` measurement in FEEDS.md Tier 1 came to be an
artefact nobody could see.
"""
import io
import json
import zipfile

import pytest

from rbp import feeds


@pytest.fixture(autouse=True)
def _clean_health():
    feeds.reset_health()
    yield
    feeds.reset_health()


def _zip(records):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for i, rec in enumerate(records):
            zf.writestr(f"rec-{i}.json", json.dumps(rec))
    return buf.getvalue()


def _serve(monkeypatch, blob):
    """Patch the one seam `_stream_zip` reads bytes through, plus the SSRF guard,
    which rejects the fake host before any of this is reached."""
    class _Opener:
        def open(self, req, timeout=None):
            return io.BytesIO(blob)
    monkeypatch.setattr(feeds, "_OPENER", _Opener())
    monkeypatch.setattr(feeds, "_url_ok", lambda url: True)


def _lang(cid):
    """A language-ecosystem record: symmetric, so the CVE is in `aliases`."""
    return {"id": "GHSA-xxxx", "aliases": [cid], "published": "2026-02-03T00:00:00Z",
            "summary": "a thing", "affected": [{"package": {"name": "somepkg"}}]}


def _distro(cid, field="upstream"):
    """A distro record: asymmetric, so the CVE is in `upstream` (or `related`),
    and `aliases` is empty."""
    return {"id": f"DISTRO-{cid}", "aliases": [], field: [cid],
            "published": "2026-02-03T00:00:00Z", "details": "a thing",
            "affected": [{"package": {"name": "somepkg"}}]}


def test_a_language_ecosystem_still_reads_normally(monkeypatch):
    """PyPI measured 2026-09-01: 2,438 in-scope ids via `aliases`, 0 via
    `upstream`, 31 via `related` of which 3 were not already in `aliases`. The
    language ecosystems use the field correctly and nothing here changes for
    them."""
    _serve(monkeypatch, _zip([_lang("CVE-2026-1111"), _lang("CVE-2026-2222")]))
    rows = feeds.feed_osv((2025, 2026), ecosystems=("PyPI",))
    assert sorted(r["cve_id"] for r in rows) == ["CVE-2026-1111", "CVE-2026-2222"]
    h = feeds.FEED_HEALTH["osv:PyPI"]
    assert h["status"] == feeds.OK and h["rows"] == 2


def test_an_archive_with_no_readable_id_is_failed_not_ok(monkeypatch):
    """THE GUARD. Before 2026-09-01 this recorded `ok`, `0 ids`, and a green run.

    Reintroduce the defect by dropping the `if not found:` branch and this test
    reports OK with zero rows, which is what every distro ecosystem did for the
    whole life of the Tier 1 measurement.
    """
    _serve(monkeypatch, _zip([_distro("CVE-2026-1111"), _distro("CVE-2026-2222")]))
    rows = feeds.feed_osv((2025, 2026), ecosystems=("Red Hat",))
    assert rows == []
    h = feeds.FEED_HEALTH["osv:Red Hat"]
    assert h["status"] == feeds.FAILED, "an unreadable archive must not read as ok"
    assert "upstream" in h["detail"], "the detail must name the likely cause"
    assert h["rows"] == 0


def test_the_related_only_shape_is_caught_too(monkeypatch):
    """AlmaLinux is the reason this is a separate test: it uses `related`, not
    `upstream`, so a guard written only against `upstream` would still have to
    catch it. The guard keys on finding nothing, which is field-agnostic."""
    _serve(monkeypatch, _zip([_distro("CVE-2026-1111", field="related")]))
    assert feeds.feed_osv((2025, 2026), ecosystems=("AlmaLinux",)) == []
    assert feeds.FEED_HEALTH["osv:AlmaLinux"]["status"] == feeds.FAILED


def test_rows_counts_what_the_archive_held_not_what_it_contributed(monkeypatch):
    """`rows=` MOVED FROM `added` TO `found` ON 2026-09-01, and `osv:Pub` is why.

    `seen` is shared across the ecosystem loop, so `added` is order-dependent:
    Pub recorded **+1** on the 2026-08-31 baseline because npm, PyPI and Maven had
    already supplied nearly all of its ids, not because Pub holds one id. A guard
    or a magnitude comparison keyed on that number is comparing loop order.

    Here the second ecosystem's ids are entirely supplied by the first, so `added`
    is 0 and `found` is 2. The part must not report 0 and must not report FAILED.
    """
    blob = _zip([_lang("CVE-2026-1111"), _lang("CVE-2026-2222")])
    _serve(monkeypatch, blob)
    rows = feeds.feed_osv((2025, 2026), ecosystems=("npm", "Pub"))
    assert len(rows) == 2, "the second ecosystem is a full duplicate of the first"
    pub = feeds.FEED_HEALTH["osv:Pub"]
    assert pub["rows"] == 2, "rows is what Pub's archive held, not what it added"
    assert pub["status"] == feeds.OK, "full overlap is not a failure"
    assert "0 new of 2" in pub["detail"], pub["detail"]


def test_an_out_of_window_only_archive_is_failed(monkeypatch):
    """A configured ecosystem holding nothing in the gather window is the other
    way to reach zero, and it is equally not a healthy part: FEEDS.md's policy is
    that an ecosystem measured at zero is recorded and un-configured, never left
    in the tuple reading empty."""
    _serve(monkeypatch, _zip([_lang("CVE-2019-1111")]))
    assert feeds.feed_osv((2025, 2026), ecosystems=("Hackage",)) == []
    assert feeds.FEED_HEALTH["osv:Hackage"]["status"] == feeds.FAILED

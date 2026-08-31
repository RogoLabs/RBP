"""Canonical's OSV tarball, the feed the publisher asked us to read instead.

`feed_ubuntu` walks `cves.json` 200 pages deep and reaches 5.2% of the records
back 33 days. `feed_ubuntu_osv` reads one 42 MB tarball whose CVE directory is
sharded by year, so the reach question stops existing. FEEDS.md, "MERGED
2026-08-31", carries the measurements.

Three of the tests below are about traps rather than about behaviour, and each
one has already been paid for once in this repository:

  * the CVE id is in `upstream`, not `aliases`, which is the GIT trap
  * a `want` prefix that stops matching is an empty feed, which is the silent
    shrink
  * the format is OSV and the content is a tracker, which would start a 72-hour
    MUST clock on the wrong evidence
"""
import io
import json
import tarfile

import pytest

from rbp import clock, feeds


@pytest.fixture(autouse=True)
def _clean_health():
    feeds.reset_health()
    yield
    feeds.reset_health()


def _rec(cid, **over):
    """One Ubuntu OSV CVE record, shaped like the real ones.

    `aliases` is EMPTY and `upstream` carries the id, which is not this fixture
    being clever: verified 400/400 on a live 2026 sample, 2026-08-31.
    """
    r = {"schema_version": "1.7.0", "id": f"UBUNTU-{cid}", "aliases": [],
         "upstream": [cid], "related": [], "details": f"details for {cid}",
         "published": "2026-03-04T05:06:07Z", "modified": "2026-03-05T00:00:00Z",
         "affected": [{"package": {"ecosystem": "Ubuntu:24.04:LTS",
                                   "name": "somepkg"}}]}
    r.update(over)
    return r


def _tarxz(members):
    """A real tar.xz in memory. `members` maps archive path to a dict or bytes."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:xz") as tf:
        for name, body in members.items():
            raw = body if isinstance(body, bytes) else json.dumps(body).encode()
            info = tarfile.TarInfo(name)
            info.size = len(raw)
            tf.addfile(info, io.BytesIO(raw))
    return buf.getvalue()


def _serve(monkeypatch, blob):
    """Stand in for the network, at the one seam the helper reads bytes through."""
    class _Opener:
        def open(self, req, timeout=None):
            return io.BytesIO(blob)
    monkeypatch.setattr(feeds, "_OPENER", _Opener())


def _rows(monkeypatch, members, years=(2025, 2026)):
    _serve(monkeypatch, _tarxz(members))
    return feeds.feed_ubuntu_osv(years)


# --------------------------------------------------------------------------
# the year shard, which is the whole reason this feed has no cap
# --------------------------------------------------------------------------

def test_a_record_outside_the_window_is_never_read(monkeypatch):
    """The real tarball is 64,756 members and 9.77 GB decompressed, of which the
    2025-2026 window is 15,790 members and 4.77 GB. `want` is applied before any
    member body is read, so the other 49,000 cost their decompression and nothing
    else: no parse, no allocation, no row."""
    rows = _rows(monkeypatch, {
        "osv/cve/2026/UBUNTU-CVE-2026-1111.json": _rec("CVE-2026-1111"),
        "osv/cve/2025/UBUNTU-CVE-2025-2222.json": _rec("CVE-2025-2222"),
        "osv/cve/2013/UBUNTU-CVE-2013-3333.json": _rec("CVE-2013-3333"),
        "osv/cve/2024/UBUNTU-CVE-2024-4444.json": _rec("CVE-2024-4444"),
    })
    assert sorted(r["cve_id"] for r in rows) == ["CVE-2025-2222", "CVE-2026-1111"]


def test_the_usn_and_lsn_directories_are_not_read(monkeypatch):
    """The tarball also carries 7,907 USNs and 54 LSNs, 276 MB of it. Those are
    ADVISORIES and this feed is deliberately not reading them: `clock._ORIGIN_KIND`
    classifies `ubuntu-osv` as a tracker, and that classification is only honest
    while the adapter reads `osv/cve/` alone."""
    rows = _rows(monkeypatch, {
        "osv/cve/2026/UBUNTU-CVE-2026-1111.json": _rec("CVE-2026-1111"),
        "osv/usn/USN-9999-1.json": {"id": "USN-9999-1", "upstream": ["CVE-2026-5555"],
                                    "published": "2026-03-04T00:00:00Z"},
        "osv/lsn/LSN-0116-1.json": {"id": "LSN-0116-1", "upstream": ["CVE-2026-6666"],
                                    "published": "2026-03-04T00:00:00Z"},
    })
    assert [r["cve_id"] for r in rows] == ["CVE-2026-1111"]


def test_the_feed_records_no_cap_because_it_has_none(monkeypatch):
    """`ubuntu` records CAPPED on every single run and `_ubuntu_reach` states the
    cost in days. This feed reads the whole configured window, so a CAPPED here
    would be furniture of exactly the kind `record_feed`'s four states exist to
    avoid."""
    _rows(monkeypatch, {"osv/cve/2026/UBUNTU-CVE-2026-1111.json": _rec("CVE-2026-1111")})
    h = feeds.FEED_HEALTH["ubuntu-osv"]
    assert h["status"] == feeds.OK
    assert h["capped"] is False and h["truncated"] is False
    assert h["rows"] == 1, "rows= must be passed or compare_magnitudes cannot compare it"


# --------------------------------------------------------------------------
# the GIT trap
# --------------------------------------------------------------------------

def test_the_cve_is_read_from_upstream_and_not_from_aliases(monkeypatch):
    """THE GIT TRAP, AND THE REASON THIS FEED IS NOT ONE LINE OF `feed_osv` CONFIG.

    Ubuntu's OSV records leave `aliases` empty. `feed_osv` reads `aliases`, so
    adding "Ubuntu" to its ecosystem tuple returns zero rows and records a
    healthy feed, which is exactly how GIT was banked at +18 CNAs and delivered
    +0.

    Reintroduce the defect by reading `aliases` in `feed_ubuntu_osv` and this
    test returns nothing.
    """
    rows = _rows(monkeypatch, {
        "osv/cve/2026/UBUNTU-CVE-2026-1111.json": _rec("CVE-2026-1111"),
    })
    assert [r["cve_id"] for r in rows] == ["CVE-2026-1111"]


def test_an_alias_is_not_a_reference_even_when_one_is_present(monkeypatch):
    """The mirror of the test above, and the reason it is a separate test.

    Reading BOTH fields would pass the test above while attributing a second CVE
    to Ubuntu that Ubuntu did not track. `aliases` is empty in the live data, so
    a record carrying one is a shape change, and the safe reading of a shape
    change is to ignore the field this adapter was never told to read.
    """
    rows = _rows(monkeypatch, {
        "osv/cve/2026/UBUNTU-CVE-2026-1111.json": _rec(
            "CVE-2026-1111", aliases=["CVE-2026-7777"]),
    })
    assert [r["cve_id"] for r in rows] == ["CVE-2026-1111"]


def test_the_row_carries_the_ubuntu_record_id_as_its_ref(monkeypatch):
    """`gather` builds refs as `f"{source}:{source_ref}"`, and `report._u` needs
    the row to be openable. The ref is the UBUNTU-CVE id because that is the
    record actually parsed."""
    rows = _rows(monkeypatch, {
        "osv/cve/2026/UBUNTU-CVE-2026-1111.json": _rec("CVE-2026-1111"),
    })
    assert rows[0]["source"] == "ubuntu-osv"
    assert rows[0]["source_ref"] == "UBUNTU-CVE-2026-1111"
    assert rows[0]["public_date"] == "2026-03-04"
    assert rows[0]["product"] == "somepkg"


# --------------------------------------------------------------------------
# withdrawn
# --------------------------------------------------------------------------

def test_a_withdrawn_record_is_not_a_reference(monkeypatch):
    """290 of the 15,790 in-window records are withdrawn (1.8%, 2026-08-31).
    Publishing one puts an id on the site whose own publisher has retracted the
    record it is cited from."""
    rows = _rows(monkeypatch, {
        "osv/cve/2026/UBUNTU-CVE-2026-1111.json": _rec("CVE-2026-1111"),
        "osv/cve/2026/UBUNTU-CVE-2026-2222.json": _rec(
            "CVE-2026-2222", withdrawn="2026-04-01T00:00:00Z"),
    })
    assert [r["cve_id"] for r in rows] == ["CVE-2026-1111"]


def test_the_withdrawn_count_is_recorded_rather_than_dropped(monkeypatch):
    """A row count that moves for a reason nobody wrote down is the thing this
    module is most careful about."""
    _rows(monkeypatch, {
        "osv/cve/2026/UBUNTU-CVE-2026-1111.json": _rec("CVE-2026-1111"),
        "osv/cve/2026/UBUNTU-CVE-2026-2222.json": _rec(
            "CVE-2026-2222", withdrawn="2026-04-01T00:00:00Z"),
    })
    assert "1 withdrawn" in feeds.FEED_HEALTH["ubuntu-osv"]["detail"]


# --------------------------------------------------------------------------
# the silent shrink, in the one shape this adapter can take it
# --------------------------------------------------------------------------

def test_a_tarball_that_matches_nothing_is_a_failure_not_an_empty_feed(monkeypatch):
    """THE SILENT SHRINK, and `want` is where this feed can take it.

    `want` is a path prefix against a layout the PUBLISHER controls. If
    `osv/cve/<year>/` becomes `osv/cves/<year>/`, every member is skipped, the
    download succeeds, the parse succeeds, and the feed returns zero rows with
    nothing wrong anywhere. Recording that as `ok` is how a feed goes to zero
    while the build reports success, which this repository has shipped twice.
    """
    rows = _rows(monkeypatch, {
        "osv/cves/2026/UBUNTU-CVE-2026-1111.json": _rec("CVE-2026-1111"),
    })
    assert rows == []
    h = feeds.FEED_HEALTH["ubuntu-osv"]
    assert h["status"] == feeds.FAILED, "an unmatched layout must not read as ok"
    assert "layout may have changed" in h["detail"]


def test_the_bytes_are_reported_even_when_nothing_matched(monkeypatch):
    """`stats["bytes"]` is set BEFORE the first yield, and this is the contract
    that depends on it.

    The first version of the helper carried the byte count on each yielded tuple,
    so a run whose `want` matched nothing reported "0 ids from 0MB": the 42 MB it
    had just spent was invisible, and the failure above would have read as an
    archive that was simply empty. Asserted against the helper rather than
    through the health line, because a small fixture rounds to 0MB either way and
    the assertion would pass for the wrong reason.
    """
    blob = _tarxz({"osv/cves/2026/UBUNTU-CVE-2026-1111.json": _rec("CVE-2026-1111")})
    _serve(monkeypatch, blob)
    stats = {"bytes": 0}
    got = list(feeds._stream_tar_xz("https://example.invalid/osv-all.tar.xz",
                                    lambda n: n.startswith("osv/cve/2026/"), stats))
    assert got == [], "the prefix does not match, so no member is yielded"
    assert stats["bytes"] == len(blob), \
        "the download happened; its cost must be reported even with zero matches"


def test_an_unreadable_tarball_with_no_rows_is_failed(monkeypatch):
    _serve(monkeypatch, b"this is not an xz stream")
    assert feeds.feed_ubuntu_osv((2025, 2026)) == []
    assert feeds.FEED_HEALTH["ubuntu-osv"]["status"] == feeds.FAILED


def test_a_stream_that_dies_after_rows_is_truncated_not_capped(monkeypatch):
    """TRUNCATED degrades the run and CAPPED does not, so this is the difference
    between a warning and furniture. A half-read tarball returns a plausible
    number of plausible rows, and there is no configured limit here for it to
    hide behind."""
    good = _tarxz({"osv/cve/2026/UBUNTU-CVE-2026-1111.json": _rec("CVE-2026-1111"),
                   "osv/cve/2026/UBUNTU-CVE-2026-2222.json": _rec("CVE-2026-2222"),
                   "osv/cve/2026/UBUNTU-CVE-2026-3333.json": _rec("CVE-2026-3333")})
    real = feeds.tarfile.open

    class _Dies:
        """Yields the first member, then raises, as a torn stream does."""
        def __init__(self, tf):
            self._tf = tf
            self._n = 0

        def __iter__(self):
            return self

        def __next__(self):
            self._n += 1
            if self._n > 1:
                raise OSError("Compressed file ended before the end-of-stream marker")
            return next(iter(self._tf))

        def extractfile(self, m):
            return self._tf.extractfile(m)

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(feeds.tarfile, "open",
                        lambda *a, **k: _Dies(real(*a, **k)))
    _serve(monkeypatch, good)
    rows = feeds.feed_ubuntu_osv((2025, 2026))
    assert len(rows) == 1, "the rows already read are kept"
    h = feeds.FEED_HEALTH["ubuntu-osv"]
    assert h["status"] == feeds.TRUNCATED
    assert h["capped"] is False, "there is no configured cap here to blame"


def test_a_member_that_is_not_json_does_not_lose_the_archive(monkeypatch):
    rows = _rows(monkeypatch, {
        "osv/cve/2026/UBUNTU-CVE-2026-1111.json": _rec("CVE-2026-1111"),
        "osv/cve/2026/UBUNTU-CVE-2026-2222.json": b"{ truncated",
        "osv/cve/2026/UBUNTU-CVE-2026-3333.json": _rec("CVE-2026-3333"),
    })
    assert sorted(r["cve_id"] for r in rows) == ["CVE-2026-1111", "CVE-2026-3333"]
    assert feeds.FEED_HEALTH["ubuntu-osv"]["status"] == feeds.OK


def test_the_decompression_ceiling_refuses_rather_than_truncates(monkeypatch):
    """41.7 MB expands to 9.77 GB, a 234x ratio, and `MAX_ARCHIVE_BYTES` guards
    the download rather than the expansion. Reading half an archive as a whole
    one is the failure this ceiling exists to make loud."""
    monkeypatch.setattr(feeds, "MAX_UNPACKED_BYTES", 10)
    rows = _rows(monkeypatch, {
        "osv/cve/2026/UBUNTU-CVE-2026-1111.json": _rec("CVE-2026-1111"),
        "osv/cve/2026/UBUNTU-CVE-2026-2222.json": _rec("CVE-2026-2222"),
    })
    assert rows == [], "nothing under the ceiling here, so nothing survives"
    assert feeds.FEED_HEALTH["ubuntu-osv"]["status"] == feeds.FAILED


# --------------------------------------------------------------------------
# the format is OSV and the content is a tracker
# --------------------------------------------------------------------------

def test_ubuntu_osv_is_a_tracker_despite_the_osv_in_its_name():
    """`osv` is an ADVISORY feed and this is not, so the map reads as
    inconsistent until you know what each one fetches.

    `osv` reads OSV.dev's language ecosystems, whose records are published
    advisories served in OSV format. `ubuntu-osv` reads `osv/cve/`, which
    Canonical documents as mirroring the Ubuntu Security Tracker "even if
    security updates aren't yet available". Classifying it beside `osv` on the
    strength of the slug would start a 72-hour MUST clock on a row whose only
    evidence is that Ubuntu is aware of the id.
    """
    assert clock.origin_kind("ubuntu-osv") == "tracker"
    assert clock.origin_kind("ubuntu") == "tracker"
    assert clock.origin_kind("osv") == "advisory", "the contrast is the point"


def test_a_ubuntu_osv_row_alone_cannot_start_the_clock():
    """The consequence of the classification above, asserted through the function
    that consumes it rather than through the map."""
    row = {"dates": {"ubuntu-osv": "2026-01-01"}}
    assert clock.advisory_date(row) is None


def test_the_link_goes_to_the_publisher_not_to_osv_dev():
    """OSV.dev's Ubuntu mirror was stamped four days older than Canonical's
    tarball on the day both were fetched, so this feed can hold a record before
    osv.dev does, and the newest rows are exactly the RBP rows. A link that 404s
    on the freshest evidence is F3's dead chip with a delay fuse on it."""
    from rbp import report
    urls = report._derive_meta({"cve_id": "CVE-2026-1111", "sources": "ubuntu-osv",
                               "refs": "ubuntu-osv:UBUNTU-CVE-2026-1111"})[2]
    assert urls["ubuntu-osv"] == "https://ubuntu.com/security/CVE-2026-1111"
    assert "osv.dev" not in urls["ubuntu-osv"]

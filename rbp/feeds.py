"""
Downstream advisory feed adapters. Each returns a list of normalized dicts:
    {cve_id, source, source_ref, public_date, product, description}
and degrades gracefully (returns [] and warns) if unreachable.
"""
from __future__ import annotations

import concurrent.futures
import datetime as dt
import http.client
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import tarfile
import threading
import time
import zipfile
import urllib.error
import urllib.parse
import urllib.request
from urllib.parse import urlparse

# The parenthesised URL is not decoration and it is not a disguise.
#
# Cisco's edge (AkamaiGHost) answered 403 to this client on every run. The
# reflex is to send a browser string; that is the one thing that does NOT work.
# Measured against www.cisco.com/.well-known/csaf/provider-metadata.json, five
# runs each, the 403 cached at the edge:
#
#   rbp-cves/1.0 (CVE quality research)   403   what we used to send
#   Mozilla/5.0 ... Chrome/128 Safari     403   the browser string
#   foobar/1.0, rbp, rbptracker/1.0       403   any bare product token
#   rbp-cves/1.0 (see rbptracker.org)     403   a domain with no scheme
#   rbp-cves/1.0 (+https://rbptracker.org) 200  this
#
# The rule is self-identification: a scheme-qualified URL, an email address or a
# crawler keyword in the comment field. That is the ordinary robots convention,
# so the fix is to say who we are and how to reach us, which is MORE honest than
# the string it replaces, not less. We do not claim to be curl and we do not
# claim to be a browser. Disclosed on /method, because a reader deserves to know
# which doors we had to knock on differently.
UA = {"User-Agent": "rbp-cves/1.0 (+https://rbptracker.org)"}
MAX_BYTES = 100_000_000     # cap on a single _get body (Debian tracker ~30MB is the largest)

# Bulk archives are streamed to disk, not held in memory, so they get their own
# much larger ceiling. Reading a 220MB zip through the MAX_BYTES cap silently
# truncated it into an invalid archive, which is how the OSV npm ecosystem, one
# of the largest, was dropped from every run while the build reported success.
MAX_ARCHIVE_BYTES = 900_000_000
_CHUNK = 1 << 20

# Per-feed health for this process. A feed that fails must not simply yield
# fewer rows: counts are a floor, and a silent shrink reads as improvement.
FEED_HEALTH = {}

# FOUR states, not three. `capped` is the one this file was missing.
#
# A configured page cap fires on EVERY run by design: ubuntu's 200-page cap
# always fires, and ghsa's 40-page cap always fires. Recording those as
# `truncated` made `degraded` permanently true, so base.html rendered "This run
# is incomplete ... not comparable to the previous run" on every page of every
# run, three hundred lines above a card that compares this run to the previous
# one. A warning that is always on is not a warning; it is furniture, and it
# trains a reader to ignore the banner that matters.
#
#   capped     a known, configured limit was reached. Expected, standing,
#              disclosed on /method as a permanent caveat. NOT a degraded run.
#   truncated  the feed stopped for a reason that is not a configured cap.
#              Unexpected. Degrades the run.
OK, TRUNCATED, FAILED, CAPPED = "ok", "truncated", "failed", "capped"


def reset_health():
    """Clear per-run state. A module global that survives between runs in the
    same process reports a stale feed as healthy.

    FETCH_BYTES is per-run state for the same reason: a scorecard that adds one
    candidate's bytes to the previous candidate's is a scorecard that gets worse
    the more feeds you measure.
    """
    FEED_HEALTH.clear()
    FETCH_BYTES["total"] = 0


def record_feed(name, status, detail="", rows=None, counts_coverage=True,
                accounted=None):
    """Record one feed outcome in three states, not two.

    A feed that hit a page cap is neither a success nor a failure: it returned
    real rows AND silently dropped the rest. Recording it as ok made the method
    page assert "all N feed fetches succeeded" on every single run, because the
    Ubuntu 200-page cap fires every run. `status` accepts a bool for the old
    call sites, where True means ok.

    TWO MARKS THAT QUALIFY A ZERO. Added 2026-08-31, after a run where a zero
    meant neither of the things the shrink guards read it as and the site
    stopped publishing for it.

    `counts_coverage=False` says THIS ENTRY'S ROWS ARE NOT COVERAGE. `rows`
    normally counts ids a source evidences, so a fall means ids left the site
    and `compare_magnitudes` and `verify` are both right to be loud. For a resolver
    it counts work done over a population that some other feed is draining, so
    the same fall means the opposite, and a guard that fires on it is reporting
    good news as a regression. `resolve_dates_ubuntu` is the case that forced
    this: `ubuntu-osv` landed and the undated population it works over went 82
    to 3 in a day. Note the asymmetry that makes this safe -- a resolver can
    only fail to IMPROVE a row, never remove one, so nothing it does can be the
    silent shrink these guards exist for.

    `accounted` says THIS RUN ALREADY KNOWS WHY THIS IS ZERO, and carries the
    reason for the log. `verify` reads it and treats the shortfall the way it
    treats one behind a recorded failure: published as degraded rather than
    blocked. It deliberately does NOT touch `status`, because the status word is
    load-bearing elsewhere: an unreachable CSAF provider has to stay CAPPED or
    Cisco's every-run 403 makes `degraded` permanently true, which is the
    furniture problem `degraded_state` spends a paragraph rejecting. The status
    word governs the banner; this governs the gate.
    """
    if status is True:
        status = OK
    elif status is False:
        status = FAILED
    rec = {"status": status, "detail": detail, "rows": rows,
           "ok": status == OK,
           # Both incomplete-shaped states answer True here, so a
           # consumer asking "did this feed read everything" still
           # gets the right answer without knowing about caps.
           "truncated": status in (TRUNCATED, CAPPED),
           "capped": status == CAPPED}
    # Written only when they are not the default, so every existing entry in
    # summary.json keeps the shape it has today and a snapshot recorded before
    # this commit compares against one recorded after it with no special case.
    # Spelled out rather than `coverage`, which is already a top-level key in
    # summary.json meaning CNA coverage. Two unrelated senses of one word in one
    # artefact is how a reader ends up believing the wrong one.
    if not counts_coverage:
        rec["counts_coverage"] = False
    if accounted:
        rec["accounted"] = accounted
    FEED_HEALTH[name] = rec


def health_summary():
    """(failures, truncated, attempts) where an attempt is one FEED, not one
    sub-fetch.

    Returns truncation SEPARATELY rather than folding it into neither bucket.
    This used to return only FAILED entries, so `cli`'s `if failures:` could never
    fire on truncation. Ubuntu truncates on every single run, so the live snapshot
    published `failures: []` beside `truncated: ["ubuntu"]` on a run with known
    data loss and the DEGRADED warning never printed once. A truncated feed
    returned real rows AND silently dropped the rest, which is a floor on a floor
    and the one direction of error this project cannot afford.

    The unit used to be wrong as well as the states: OSV recorded per ecosystem
    and gather recorded again for `osv`, so "all 20 feed fetches succeeded"
    described 10 feeds and any consumer check of the form
    `failures == [] and attempts == len(requested)` was broken on arrival.
    """
    failures = [f"{k}: {v['detail']}" for k, v in FEED_HEALTH.items()
                if v["status"] == FAILED]
    truncated = [f"{k}: {v['detail']}" for k, v in FEED_HEALTH.items()
                 if v["status"] == TRUNCATED]
    capped = [f"{k}: {v['detail']}" for k, v in FEED_HEALTH.items()
              if v["status"] == CAPPED]
    top = [k for k in FEED_HEALTH if ":" not in k]
    return failures, truncated, len(top), capped


def rows_by_source(rows):
    """Per-feed contribution to the PUBLISHED rows: {feed: (touched, only)}.

    IDS FETCHED IS NOT ROWS PUBLISHED, and until this existed the site published
    only the first number and let a reader infer the second. `/status` rendered
    one line per feed reading "arch  OK  62 ids" beside "csaf  OK  2,695 ids",
    which are the same sentence about two feeds where one is the sole evidence
    for 22 published rows and the other is the sole evidence for none.

    Measured on the 2026-08-27 snapshot: `mozilla` (607 ids/run) and `arch` (62)
    appeared in ZERO of the 1,709 published rows, on every run since they were
    merged, and no surface on the site could say so. Meanwhile `ghsa-repos` was
    the only source for 1,015 of those rows, 59% of the headline, and no surface
    could say that either.

    `only` is the number that matters and it is the one nobody had. It answers
    "what disappears if this feed does", which is the question behind both feed
    retirement and concentration risk, and it cannot be derived from `touched`:
    four distro feeds touch 196 rows between them and are the sole source for
    132, because they mostly corroborate each other.

    Takes the published population, not the backlog, so it counts what a reader
    can actually see. Source strings are the comma-joined form `classify` writes.
    """
    touched, only = {}, {}
    for r in rows:
        srcs = [x for x in (r.get("sources") or "").split(",") if x]
        for s in srcs:
            touched[s] = touched.get(s, 0) + 1
        if len(srcs) == 1:
            only[srcs[0]] = only.get(srcs[0], 0) + 1
    return {s: (n, only.get(s, 0)) for s, n in touched.items()}


def merge_contribution(detail, rows):
    """Fold `rows_by_source` into a `health_detail()` dict, in place.

    Every requested feed gets both keys, including the ones that contributed
    nothing: a feed missing from the published rows must render as an explicit
    zero, not as a blank. A blank reads as "not measured", which is the state
    this function exists to end.
    """
    contrib = rows_by_source(rows)
    for name, v in detail.items():
        n, only = contrib.get(name, (0, 0))
        v["rows_published"] = n
        v["rows_only"] = only
        # PARTS GET None, NOT 0, AND THE DIFFERENCE IS THE WHOLE POINT OF THE
        # KEY. `rows_by_source` reads the `sources` string on each published
        # row, and that string names the FEED (`csaf`), never the provider
        # inside it, so no part can be looked up in it. Writing 0 would publish
        # "this provider accounts for no rows on this site", which is a claim
        # about the provider; None publishes "not measured", which is a claim
        # about us and is the true one.
        #
        # Set explicitly rather than left absent, because absent is not the same
        # as None to the template: `h.rows_published is not none` is TRUE for a
        # missing key in Jinja, so an unset part takes the "measured" branch and
        # renders a blank cell where a dash belongs.
        for part in (v.get("parts") or {}).values():
            part.setdefault("rows_published", None)
            part.setdefault("rows_only", None)
    return detail


# A feed returning far fewer ids than last run is the silent-shrink signature,
# and it is invisible to a status field. Ubuntu went 3,995 -> 1,079 ids overnight
# while its status went from `truncated` to `ok`, and the headline fell 558 -> 458
# with nothing marked degraded.
#
# 0.4 because normal day-to-day movement on these feeds is 1-3% (debian 17,115 ->
# 17,328, alas 11,369 -> 11,470 across the same two runs), so a 40% drop is not
# weather. Compared per feed rather than on the total, because one feed collapsing
# while others grow can leave the total looking merely flat.
MAGNITUDE_DROP = 0.4

# A single sub-fetch (one OSV ecosystem) is noisier than a whole feed, so it is
# reported only on a clear collapse. Still far below "invisible", which is what
# skipping parts entirely amounted to.
PART_DROP = 0.7


def compare_magnitudes(previous, current, threshold=MAGNITUDE_DROP):
    """Feeds whose id count fell sharply since the previous run.

    Takes two `health_detail()`-shaped dicts and returns a list of human-readable
    findings. Empty means no feed shrank beyond the threshold.

    This is the guard the review asked for and I deferred, on the reasoning that it
    needed per-feed id-set recording that did not exist. It did exist:
    `record_feed` has carried a `rows` count all along, and it reaches summary.json.
    The work was comparing two numbers.
    """
    def _cmp(name, was, now, thr):
        if not isinstance(was, int) or not isinstance(now, int) or was <= 0:
            return None
        if now < was * (1 - thr):
            pct = round(100 * (was - now) / was)
            return f"{name}: {was:,} -> {now:,} ids ({pct}% fewer)"
        return None

    # AN ENTRY WHOSE ROWS ARE NOT COVERAGE IS NOT COMPARED AT ALL. See
    # `record_feed`: for a resolver, `rows` is work done over a population
    # another feed is draining, so a fall is the drain working. `ubuntu:dates`
    # went 56 -> 0 the day `ubuntu-osv` landed and dated the population out from
    # under it, and this function called that a shrink and set `degraded`. Left
    # alone it would have set it on every run from then on, because the drained
    # population does not come back: a warning that is always on is the
    # furniture problem `degraded_state` rejects, reached from a third direction.
    def _is_coverage(rec):
        return (rec or {}).get("counts_coverage") is not False

    out = []
    for name, cur in sorted((current or {}).items()):
        if ":" in name:
            continue                      # raw-shape sub-fetch; handled below
        prev_feed = (previous or {}).get(name) or {}
        if _is_coverage(cur):
            hit = _cmp(name, prev_feed.get("rows"), cur.get("rows"), threshold)
            if hit:
                out.append(hit)

        # AND EACH PART, which this deliberately skipped.
        #
        # The rationale was that "osv:npm rolls up to osv, comparing both
        # double-counts one feed and lets a single ecosystem's normal variation
        # trip the guard". The first half is true and the second is the wrong
        # trade: osv:npm going 5,000 -> 100 while the osv TOTAL stays flat means
        # another ecosystem grew enough to mask it, which is precisely the
        # silent-shrink signature this function exists to catch, arriving in the
        # one shape it could not see. npm is about 25% of osv's ids.
        #
        # Compared at a LOOSER threshold than the parent, because a single
        # ecosystem genuinely is noisier than a whole feed, so the guard reports
        # a part only when it has clearly collapsed rather than merely dipped.
        for child, cv in sorted((cur.get("parts") or {}).items()):
            if not _is_coverage(cv):
                continue
            pv = ((prev_feed.get("parts") or {}).get(child) or {})
            hit = _cmp(f"{name}:{child}", pv.get("rows"), cv.get("rows"),
                       PART_DROP)
            if hit:
                out.append(hit)
    return out


# A feed frozen at a constant is invisible to `compare_magnitudes`, which only
# ever asks whether a number went DOWN. `mozilla` returned exactly 607 ids on six
# consecutive published snapshots, `arch` exactly 62, `samsung` exactly 420 on
# five. Had any of them silently stopped updating on day one, every guard on this
# site would still have been green.
#
# 45 DAYS, DERIVED FROM THE FEEDS' OWN CADENCES rather than picked. Measured over
# the 2026-08-27 baseline, newest advisory per feed against the run date:
#
#   csaf, ghsa, ghsa-repos, osv, redhat, ubuntu   0 days
#   alas                                          1
#   mozilla                                       9
#   msrc                                         16   (Patch Tuesday, monthly)
#   samsung                                      26   (SMR bulletin, monthly)
#   alpine, arch, debian                     undated
#
# The slowest genuine cadence in the set is monthly, whose newest advisory can
# legitimately be ~35 days old just before the next bulletin lands. 45 leaves ten
# days of slack past that and still catches a dead feed inside seven weeks.
FRESHNESS_FLOOR_DAYS = 45


def stale_feeds(detail, today=None, floor_days=FRESHNESS_FLOOR_DAYS):
    """Feeds whose newest advisory is old enough that the feed has likely stopped.

    Returns (stale, unmeasurable). `stale` is a degradation: a feed that has
    stopped updating makes this run's counts a lower floor than usual, and unlike
    a configured page cap it is not a standing limit fired by design, so it must
    stay loud until someone fixes it.

    `unmeasurable` is NOT a degradation and is reported separately. `alpine`,
    `arch` and `debian` return no dates at all, so their freshness cannot be
    checked by any threshold. Silently skipping them would let "cannot be
    checked" read as "checked and fine", which is the distinction this whole
    module keeps having to relearn.
    """
    base = dt.date.fromisoformat(today) if today else dt.date.today()
    stale, unmeasurable = [], []
    for name, v in sorted((detail or {}).items()):
        if ":" in name:
            continue                       # sub-fetch; the parent carries it
        if not v.get("dated_rows"):
            unmeasurable.append(f"{name}: returns no dated rows")
            continue
        newest = v.get("newest") or ""
        try:
            age = (base - dt.date.fromisoformat(newest[:10])).days
        except ValueError:
            unmeasurable.append(f"{name}: newest date {newest!r} did not parse")
            continue
        if age > floor_days:
            stale.append(f"{name}: newest advisory is {newest}, {age} days old "
                         f"(floor {floor_days}); the feed has likely stopped")
    return stale, unmeasurable


def health_detail():
    """Structured per-feed health for summary.json. Sub-fetches (osv:npm) are
    nested under their parent so the top-level count means what it says."""
    out = {}
    for name, v in FEED_HEALTH.items():
        parent, _, child = name.partition(":")
        if child:
            out.setdefault(parent, {}).setdefault("parts", {})[child] = v
        else:
            out.setdefault(parent, {}).update(v)
    for v in out.values():
        parts = v.get("parts") or {}
        if parts and any(p["status"] != OK for p in parts.values()):
            if any(p["status"] == FAILED for p in parts.values()):
                worst = FAILED
            elif any(p["status"] == TRUNCATED for p in parts.values()):
                worst = TRUNCATED
            else:
                worst = CAPPED
            # A parent whose sub-fetches degraded is itself degraded, or the
            # top-level number hides the hole.
            if v.get("status") == OK:
                v["status"] = worst
                v["ok"] = False
                v["truncated"] = worst == TRUNCATED
                v["detail"] = (v.get("detail") or "") + \
                    f" ({sum(1 for p in parts.values() if p['status'] != OK)} of "\
                    f"{len(parts)} parts degraded)"
    return out


def _stream_zip(url):
    """Download a bulk archive to a temp file and open it. Streaming keeps peak
    memory at one chunk while still enforcing a hard ceiling, so a large archive
    is handled rather than quietly mangled."""
    import tempfile
    total = 0
    tmp = tempfile.NamedTemporaryFile(suffix=".zip", delete=False)
    try:
        with _OPENER.open(urllib.request.Request(url, headers=UA), timeout=300) as r:
            while True:
                chunk = r.read(_CHUNK)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_ARCHIVE_BYTES:
                    raise RuntimeError(
                        f"archive exceeded {MAX_ARCHIVE_BYTES:,} byte ceiling; "
                        "refusing to truncate it into an invalid zip")
                tmp.write(chunk)
        tmp.close()
        FETCH_BYTES["total"] += total
        return zipfile.ZipFile(tmp.name), tmp.name, total
    except Exception:
        tmp.close()
        try:
            os.unlink(tmp.name)
        except OSError:
            pass
        raise


# A 234x compression ratio is not a hypothetical. Measured 2026-08-31, Canonical's
# `osv-all.tar.xz` is 41.7 MB on the wire and 9.77 GB decompressed across 64,756
# members, because every OSV record carries the full `versions` list for every
# affected Ubuntu release. `MAX_ARCHIVE_BYTES` guards the DOWNLOAD and would not
# have noticed: 41.7 MB passes it with two decimal orders to spare.
#
# So the ceiling that matters here is on decompressed bytes, and it is the reason
# this helper exists instead of a second call to `_stream_zip`. The in-window
# read is 4.77 GB of that 9.77 (2025 at 1.70 and 2026 at 3.07), so 8 GB leaves
# 68% headroom over the measured cost while still stopping an archive that has
# decided to be infinite. It is a REFUSAL, not a truncation, for the same reason
# the zip ceiling is: half an archive read as a whole one is the silent shrink.
MAX_UNPACKED_BYTES = 8_000_000_000


def _stream_tar_xz(url, want, stats):
    """Download a tar.xz and yield (name, bytes) for members `want` selects.

    STREAMED IN ONE SEQUENTIAL PASS (`r|xz`), which is what `want` is for. The
    tarfile module can seek inside an xz archive, but only by decompressing from
    the start every time, so random access over 64,756 members is quadratic and a
    filter applied by the CALLER after the fact would have to hold or re-read
    9.77 GB. `want(name)` is applied before any member body is read, so the 49,000
    out-of-window records cost their decompression and nothing else.

    Yields rather than returning a list because the list is the 4.77 GB.

    `stats["bytes"]` is set as soon as the download completes, BEFORE the first
    member is yielded, rather than being carried on each yielded tuple. A caller
    whose `want` matched nothing still spent the 42 MB, and a health line reading
    "0 ids from 0MB" would have hidden the one failure mode this shape has: a
    `want` prefix that stopped matching because the publisher reorganised the
    tarball. That reads as an empty archive instead of as a broken filter.
    """
    import tempfile
    total = 0
    tmp = tempfile.NamedTemporaryFile(suffix=".tar.xz", delete=False)
    try:
        with _OPENER.open(urllib.request.Request(url, headers=UA), timeout=300) as r:
            while True:
                chunk = r.read(_CHUNK)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_ARCHIVE_BYTES:
                    raise RuntimeError(
                        f"archive exceeded {MAX_ARCHIVE_BYTES:,} byte ceiling; "
                        "refusing to truncate it into an invalid tarball")
                tmp.write(chunk)
        tmp.close()
        FETCH_BYTES["total"] += total
        stats["bytes"] = total
        unpacked = 0
        with tarfile.open(tmp.name, "r|xz") as tf:
            for m in tf:
                if not m.isfile() or not want(m.name):
                    continue
                unpacked += m.size
                if unpacked > MAX_UNPACKED_BYTES:
                    raise RuntimeError(
                        f"decompressed {unpacked:,} bytes, past the "
                        f"{MAX_UNPACKED_BYTES:,} ceiling; refusing to read a "
                        "partial archive as a whole one")
                f = tf.extractfile(m)
                if f is None:
                    continue
                yield m.name, f.read()
    finally:
        # CLOSED as well as unlinked. A download that raised partway never
        # reached the `tmp.close()` above, and unlinking an open file leaves the
        # handle (and its blocks) until the object is collected. Harmless once;
        # this runs on a six-hour cadence in a process that reads thirteen other
        # feeds after it.
        try:
            tmp.close()
        except OSError:
            pass
        try:
            os.unlink(tmp.name)
        except OSError:
            pass


def _public_ips(host):
    """Resolve host; return its addresses IFF every one is public (else [], reject the
    whole host if ANY record is private/loopback/link-local/reserved)."""
    try:
        infos = socket.getaddrinfo(host, None)
    except Exception:
        return []
    ips = []
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
            return []
        ips.append(info[4][0])
    return ips


def _url_ok(url):
    """SSRF guard: https only, resolvable public host. Blocks file://, internal IPs."""
    p = urlparse(url)
    return p.scheme == "https" and bool(p.hostname) and bool(_public_ips(p.hostname))


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Connects to a pre-validated public IP (SNI/cert still against the hostname),
    closing the resolve-then-reconnect TOCTOU that a DNS-rebinding attacker could use
    to slip an internal address past the guard between validation and connection."""

    def __init__(self, host, *a, pinned_ips=None, **kw):
        super().__init__(host, *a, **kw)
        self._pinned_ips = pinned_ips or []

    def connect(self):
        last = None
        for ip in self._pinned_ips:
            try:
                self.sock = socket.create_connection((ip, self.port), self.timeout, self.source_address)
                break
            except OSError as e:
                last = e
        else:
            raise last or OSError("no reachable pinned IP")
        self.sock = self._context.wrap_socket(self.sock, server_hostname=self.host)


class _PinnedHTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, req):
        def factory(host, **kw):
            ips = _public_ips(host.split(":")[0])
            if not ips:
                raise urllib.error.URLError(f"blocked non-public/unresolvable host: {host}")
            return _PinnedHTTPSConnection(host, pinned_ips=ips, **kw)
        return self.do_open(factory, req, context=self._context)


class _SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not _url_ok(newurl):   # re-validate every redirect hop (https + public host)
            return None
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        # Strip credentials when the redirect crosses to a different host, so a GitHub
        # token (or cookie) is never forwarded off api.github.com to a redirect target.
        if new is not None and urlparse(newurl).hostname != urlparse(req.full_url).hostname:
            for h in ("Authorization", "Cookie"):
                new.remove_header(h)
        return new


# https-only opener: IP-pinned connections + redirect re-validation. No http/file/ftp
# handlers are added, so those schemes cannot be opened at all.
_OPENER = urllib.request.build_opener(_PinnedHTTPSHandler, _SafeRedirect)

# Bytes read through the three shared fetch helpers, counted at the read rather
# than estimated from the parsed result.
#
# FEEDS.md section 3 makes `bytes` a scorecard field, next to `wall_seconds`,
# because the feed count is going up roughly fourfold against a 15-minute warm-run
# target and "it felt quick" is how a plan acquires a feed that downloads 600 MB
# on a schedule. Reset by reset_health(), so a scorecard measures one run.
FETCH_BYTES = {"total": 0}


def _get(url, timeout=90, retries=3, headers=None):
    if not _url_ok(url):
        raise ValueError(f"blocked non-https/internal URL: {url}")
    h = dict(UA)
    if headers:
        h.update(headers)
    last = None
    for i in range(retries):
        try:
            with _OPENER.open(urllib.request.Request(url, headers=h), timeout=timeout) as r:
                raw = r.read(MAX_BYTES)
                FETCH_BYTES["total"] += len(raw)
                return json.loads(raw), getattr(r, "status", 200), dict(r.headers)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None, 404, {}
            last = e
        except Exception as e:
            last = e
        time.sleep(1.5 * (i + 1))
    raise last


def _year(cid):
    try:
        return int(cid.split("-")[1])
    except (IndexError, ValueError, AttributeError):
        return None


_MONTHS = {m: i for i, m in enumerate(
    ["january", "february", "march", "april", "may", "june", "july", "august",
     "september", "october", "november", "december"], 1)}


def _parse_month_day_year(s):
    """Parse 'January 7, 2025' locale-independently (LC_TIME-agnostic). '' on failure."""
    m = re.match(r"([A-Za-z]+)\s+(\d{1,2}),?\s+(\d{4})", s or "")
    if not m:
        return ""
    mon = _MONTHS.get(m.group(1).lower())
    if not mon:
        return ""
    try:
        return dt.date(int(m.group(3)), mon, int(m.group(2))).isoformat()
    except ValueError:
        return ""


def _get_text(url, timeout=30):
    """Fetch raw text (for non-JSON sources like Mozilla's YAML), SSRF-guarded."""
    if not _url_ok(url):
        raise ValueError(f"blocked non-https/internal URL: {url}")
    with _OPENER.open(urllib.request.Request(url, headers=UA), timeout=timeout) as r:
        raw = r.read(MAX_BYTES)
        FETCH_BYTES["total"] += len(raw)
        return raw.decode("utf-8", "replace")


def _gh_headers():
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if not token:
        try:
            token = subprocess.check_output(["gh", "auth", "token"], text=True).strip()
        except Exception:
            token = None
    h = {"Accept": "application/vnd.github+json"}
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


def _d(s):
    return str(s)[:10] if s else ""


def feed_alas(years):
    data, _, _ = _get("https://explore.alas.aws.amazon.com/index.json")
    return [
        {"cve_id": r.get("cve_id", ""), "source": "alas", "source_ref": r.get("cve_id", ""),
         "public_date": _d(r.get("public_date")), "product": "",
         "description": (r.get("description") or "")[:400]}
        for r in (data or []) if _year(r.get("cve_id", "")) in years
    ]


# How hard to try a single page of Ubuntu's paginated sweep before giving up, and
# how long the whole feed may spend retrying.
#
# `_get` ALREADY retries three times at 1.5s, 3s and 4.5s, and that is not what
# was failing: three consecutive scheduled runs truncated anyway, at offsets 0,
# 1280 and 3000, on 503s and a connection reset. The sweep is 200 requests to one
# host back to back, so what it hits is load shedding rather than a dead endpoint,
# and the answer to shedding is to wait longer than 4.5 seconds.
#
# These waits are at the PAGINATION level, on top of `_get`'s. A page that fails
# every attempt at 5s and 20s is not a blip and the feed truncates honestly.
#
# The budget is the important number. Ubuntu is already 486s of a 784s gather, and
# a run that retries every page would take longer than the six-hour cadence allows
# while producing a worse feed than one that gives up and says so. When the budget
# is spent the loop stops retrying and truncates, and the recorded reason says the
# budget was hit rather than pretending the page simply failed.
def _ubuntu_reach(page_cap, limit, total_results, rows, years, why=None):
    """The Ubuntu cap stated in days, because pages are not a unit a reader has.

    The line this replaces read, in full:

        ubuntu: hit the 200-page cap; rows beyond it were not read

    Every word true, and it would have read identically whether the cap cost one
    day or three years. Measured live 2026-08-27, it costs almost everything:
    `cves.json` is ordered newest-published-first, `limit` is hard-capped at 20,
    so 200 pages is 4,000 of 75,993 records, and offset 3,980 lands on a row
    published 2026-07-20. This feed sees **38 days** while `debian` beside it in
    the same table sees the whole 2024-2026 window, and the site published the
    two counts adjacently with nothing to distinguish them.

    Exactly the finding `8e3479d` fixed for `feed_ghsa` the previous day: newest
    first, a fixed row cap, a reach measured in weeks against a window measured in
    years, at a constant count that reads as healthy. GHSA could be fixed by
    sharding the walk by publication month. This endpoint offers no date filter,
    so the reach is what it is and the honest move is to say so.
    """
    read = page_cap * limit
    dates = sorted(r["public_date"] for r in rows if r.get("public_date"))
    bits = [(why or f"hit the {page_cap}-page cap") + f" at {read:,} records"]
    if total_results:
        bits[0] += f" of {total_results:,} ({100 * read / total_results:.1f}%)"
    if dates:
        span = _days_between(dates[0], dates[-1])
        bits.append(f"read back to {dates[0]}"
                    + (f", a {span}-day window" if span is not None else ""))
        bits.append(f"the configured window opens {min(years)}-01-01, so most of "
                    "it was not read")
    else:
        bits.append("rows beyond it were not read")
    return "; ".join(bits)


def _days_between(a, b):
    """Whole days between two ISO dates, or None if either will not parse."""
    try:
        return (dt.date.fromisoformat(b[:10]) - dt.date.fromisoformat(a[:10])).days
    except Exception:
        return None


UBUNTU_PAGE_RETRIES = 2
UBUNTU_RETRY_WAITS = (5, 20)
UBUNTU_RETRY_BUDGET_S = 120


UBUNTU_WORKERS = 6
UBUNTU_TIME_BUDGET_S = 900


def _ubuntu_page(offset, limit, retries, waits, budget_s, spent):
    """One page, with the pagination-level retries. Returns (rows, code, err, spent).

    Extracted from the walk so the walk can run pages CONCURRENTLY. Broad on
    purpose: a page that fails every attempt truncates the feed, which is
    recorded, rather than discarding every page already read.
    """
    url = f"https://ubuntu.com/security/cves.json?limit={limit}&offset={offset}"
    last_err = None
    for attempt in range(retries + 1):
        try:
            data, code, _ = _get(url, timeout=60)
            return data, code, None, spent, attempt > 0
        except Exception as e:
            last_err = e
            if attempt == retries:
                break
            wait = waits[min(attempt, len(waits) - 1)]
            if spent + wait > budget_s:
                last_err = RuntimeError(
                    f"{str(e)[:60]} (retry budget of {budget_s}s spent)")
                break
            time.sleep(wait)
            spent += wait
    return None, None, last_err, spent, False


def feed_ubuntu(years, page_cap=200, retry_budget_s=UBUNTU_RETRY_BUDGET_S,
                workers=UBUNTU_WORKERS, time_budget_s=UBUNTU_TIME_BUDGET_S):
    """Ubuntu's CVE tracker, read newest-first in concurrent batches.

    WHY BATCHES AND NOT A SEQUENTIAL WALK. Pages are offset-addressed and
    independent, and the ordering was verified strictly descending by publish
    date at fifteen sampled offsets spanning the whole 76,753-record endpoint,
    within pages and across them. Nothing about a sequential walk was load-bearing
    except the early stop, which a batch preserves: the batch is fetched
    concurrently and the STOP DECISION is still made in offset order.

    Measured 2026-08-28, cold offsets, 24 pages: 6 workers 56.1s, 10 workers
    44.6s. Ten buys 20% over six, so the bottleneck is server-side and widening
    the pool spends politeness for nothing. Six.

    WHY THE CAP DOES NOT SIMPLY GO AWAY, which is the question round 7 left open.
    The {2025, 2026} window is **22,548 records, 1,128 pages** (binary-searched
    2026-08-28: offset 22,547 is published 2025-01-02 and 22,548 is 2024-12-31).
    At the measured rate that is 35 to 44 minutes against a 45-minute job that
    already takes 21, so a full-window read is not available at any worker count
    this project is willing to use. The cap is a real limit on a real constraint,
    and the honest move is to say what it costs, which `_ubuntu_reach` does.

    A WALL-CLOCK BUDGET SITS BESIDE THE PAGE CAP because a page cap's cost in
    time is not stable: measured cold latency ranged 1.25s to 30s per page on the
    same endpoint within an hour, and the 2026-08-27 baseline spent 1,070s on the
    200 pages that a warm run does in a fraction of that. A cap denominated only
    in pages is a cap whose cost varies five-fold with the endpoint's mood, and
    the job timeout is denominated in time.
    """
    out, seen, offset, limit, capped = [], set(), 0, 20, False
    total_results = None
    retry_attempts, recovered_pages, retry_spent = 0, 0, 0.0
    ended = "exhausted"
    t0 = time.time()
    # Batch wide enough to keep every worker busy and narrow enough that the
    # early stop is not overshot by much: at most `batch` pages past the window
    # boundary are fetched and discarded.
    batch = workers * 4

    budget_spent = False
    while offset < page_cap * limit:
        if time.time() - t0 > time_budget_s:
            budget_spent = True
            break
        offsets = [offset + i * limit for i in range(batch)
                   if offset + i * limit < page_cap * limit]
        if not offsets:
            break
        results = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
            futs = {ex.submit(_ubuntu_page, o, limit, UBUNTU_PAGE_RETRIES,
                              UBUNTU_RETRY_WAITS, retry_budget_s, retry_spent): o
                    for o in offsets}
            for f in concurrent.futures.as_completed(futs):
                results[futs[f]] = f.result()

        # ONE stop reason, decided in OFFSET ORDER, and the loop breaks on the
        # first one rather than letting a later page overwrite an earlier one.
        #
        # The first version of this batch walk kept three separate variables and
        # assigned `stop` in two of the branches, so an empty page at offset 40
        # clobbered a year-heuristic stop at offset 20 and the run then took the
        # genuine-end-of-data exit: `ended` stayed "exhausted", nothing was
        # recorded, and `health_detail()` returned {} for a feed that had
        # truncated. Which is the exact class of defect this adapter's own
        # docstring is about, reintroduced by the change that was meant to speed
        # it up. Offsets ascend, so the lowest one wins and everything past it is
        # beyond the boundary anyway.
        stop_reason = None
        for o in offsets:
            data, code, err, spent, recovered = results[o]
            retry_spent = max(retry_spent, spent)
            if recovered:
                recovered_pages += 1
            elif err is not None:
                retry_attempts += 1
            if err is not None:
                stop_reason = ("error", o, err)
                break
            rows = (data or {}).get("cves", []) if isinstance(data, dict) else []
            if isinstance(data, dict) and total_results is None:
                total_results = data.get("total_results")
            if not rows:
                # An empty page is only the end of the data if the request
                # SUCCEEDED. `_get` returns (None, 404, {}) on a retired path or
                # a WAF block, and binding `code` without reading it is how a 404
                # once ended pagination and was recorded as a healthy feed.
                stop_reason = ("empty", o, code)
                break
            heuristic = False
            for r in rows:
                cid = r.get("id", "")
                if _year(cid) in years and cid not in seen:
                    seen.add(cid)
                    out.append({"cve_id": cid, "source": "ubuntu", "source_ref": cid,
                                "public_date": _d(r.get("published")), "product": "",
                                "description": (r.get("description") or "")[:400]})
                py = _date_year(r.get("published"))
                if py is not None and py < min(years):
                    heuristic = True
            if heuristic:
                # The year heuristic. It assumes the feed is ordered by publish
                # date descending, which was VERIFIED across the whole endpoint
                # on 2026-08-28 rather than assumed. The page's in-window rows
                # are kept: they were appended above before this fires. Still
                # recorded, because "we stopped" and "there was nothing left"
                # must never look the same from outside.
                stop_reason = ("year", o, None)
                break
        # DEDUPED, which a sequential walk did not have to be. Concurrent pages
        # are fetched against a live, growing table: if Ubuntu publishes while a
        # batch is in flight every later offset shifts by one and the same record
        # can appear in two pages. `gather` dedupes into `refs` and so the ids
        # were never wrong, but the ROW COUNT would have been inflated, and that
        # count is what `compare_magnitudes` compares.
        if stop_reason is not None:
            kind, o, extra = stop_reason
            if kind == "error":
                print(f"  [ubuntu] stopped at offset {o}: {extra}", file=sys.stderr)
                ended = f"error at offset {o}: {str(extra)[:80]}"
            elif kind == "empty" and extra and extra != 200:
                ended = f"HTTP {extra} at offset {o}, treated as end of data"
            elif kind == "year":
                ended = (f"year heuristic stopped pagination at offset {o}; rows "
                         "beyond it were not read")
            # kind == "empty" with a 200 is the genuine end of the data, and
            # `ended` stays "exhausted".
            break
        offset += len(offsets) * limit
    else:
        capped = True

    if recovered_pages:
        note = f"; recovered {recovered_pages} page(s) on retry"
    elif retry_attempts:
        note = f"; {retry_attempts} retry attempt(s) did not recover it"
    else:
        note = ""
    if budget_spent:
        # CAPPED, NOT TRUNCATED, and the difference decides whether the site
        # wears a degraded posture. A wall-clock budget is a CONFIGURED limit in
        # exactly the sense the page cap is, so it belongs in `limitations` beside
        # it rather than in `degraded`.
        #
        # It is not a fine distinction here, it is the whole reason the budget is
        # safe to add. The measured live cost of the 200-page cap is 553s against
        # a 900s budget, and cold page latency on this endpoint ranges 1.25s to
        # 30s, so a slow afternoon puts the two within reach of each other.
        # Classifying budget exhaustion as TRUNCATED would have marked the run
        # degraded on any slow day, which is the furniture problem
        # `degraded_state` spends a paragraph rejecting, arrived at from a third
        # direction. `compare_magnitudes` still catches a real collapse in rows,
        # which is the guard for "worse than usual".
        pages_read = offset // limit
        print(f"  [ubuntu] wall-clock budget ({time_budget_s}s) spent after "
              f"{pages_read} pages", file=sys.stderr)
        record_feed("ubuntu", CAPPED,
                    _ubuntu_reach(pages_read, limit, total_results, out, years,
                                  why=f"spent the {time_budget_s}s wall-clock budget")
                    + note)
    elif capped:
        print(f"  [ubuntu] hit page cap ({page_cap}), coverage may be truncated", file=sys.stderr)
        record_feed("ubuntu", CAPPED, _ubuntu_reach(page_cap, limit, total_results,
                                                    out, years) + note)
    elif ended != "exhausted":
        print(f"  [ubuntu] {ended}", file=sys.stderr)
        record_feed("ubuntu", TRUNCATED, ended + note)
    elif recovered_pages:
        record_feed("ubuntu", True, f"{len(out)} ids{note}")
    return out


# 82 undated rows on 2026-08-27 and the endpoint answers a `q=` in 1.2s to 30s
# with no pattern to it, so the pass is sized by measurement rather than by a
# per-row estimate: 4 workers dated 59 of 82 in 180s, which is ~3s a row, and a
# complete pass wants ~250s. 600 leaves room for a bad afternoon and still lands
# a 21-minute job inside a 45-minute timeout.
#
# Workers stay at 4. The 2026-08-28 walk measurement found this endpoint's
# bottleneck is server-side (10 workers bought 20% over 6), so a wider pool
# spends politeness for very little, and this pass is the one that runs AFTER
# the walk has already taken its share.
UBUNTU_RESOLVE_BUDGET_S = 600
UBUNTU_RESOLVE_WORKERS = 4

# HOW MANY LOOKUPS HAVE TO FAIL BEFORE "ALL OF THEM" MEANS UBUNTU IS DOWN,
# expressed in waves of `workers` rather than as a number, because the number
# that matters is how many times the endpoint was INDEPENDENTLY observed.
#
# `resolve_dates_ubuntu` runs `workers` lookups concurrently. At a population of
# `workers` or fewer, every request is in flight at the same instant, so they
# share fate: "all 3 failed" is one observation of the endpoint during one bad
# second, not three. Failures on this host are bursty rather than independent,
# which the caller's own comment says outright, so a temporally concentrated
# sample is exactly the one that cannot tell a blip from an outage.
#
# THIS WAS LIVE ON 2026-09-01, three days after the branch was written against a
# population of 82. `ubuntu-osv` drained the undated backlog to 3, all 3 lookups
# failed, and the pass reported FAILED: the loudest state this module has,
# reached on one second of evidence.
#
# Three waves, so the endpoint is observed over at least three separate round
# trips before the pass is willing to call it down.
UBUNTU_DATES_OUTAGE_WAVES = 3


def resolve_dates_ubuntu(cve_ids, budget_s=UBUNTU_RESOLVE_BUDGET_S,
                         workers=UBUNTU_RESOLVE_WORKERS, timeout=30):
    """Ubuntu publication dates for named IDs, asked for one at a time.

    THE ROWS THIS EXISTS FOR CANNOT BE WALKED TO. `feed_ubuntu` reads newest
    first and the cap stays at 200 pages, which is 4,000 of the window's 22,548
    records; offset 3,980 lands on 2026-07-25 and everything older is invisible
    to it. Moving the cap was measured on 2026-08-28 and rejected: the full
    window is 1,128 pages and 35 to 44 minutes against a job that takes 21.

    So the reach problem has no answer on the walk, and it did not need one.
    `cves.json?q=<id>` is an exact-match filter that answers in a single request,
    which means the rows that need a date can be asked for BY NAME instead of
    paged past. Depth stops mattering: a row published in April costs exactly
    what a row published yesterday costs.

    Measured over the 82 rows held back as `undated` in the 2026-08-27 snapshot,
    on a pass with no failed lookups: 64 have an Ubuntu date, every one of the 64
    clears the 7-day buffer, every one is beyond the walk's reach, and the oldest
    has been public 151 days. Those 64 are not marginal rows. They are the OLDEST
    evidence the site has, and they were invisible because the only feed that
    could date them is the one feed whose reach is measured in weeks.

    THIS DATES ROWS. IT DOES NOT SIGHT THEM, and the distinction is the whole
    reason `sources` and `feed_count` are left alone here.

    Every ID passed to this function is one another feed already found, because
    that is the only way it reaches the backlog. So the lookup can never add a
    row `ubuntu` alone would have seen, and crediting `ubuntu` with a sighting
    on the ones it does answer would raise corroboration out of a sample chosen
    by which rows were already undated. `feed_count` would climb on exactly the
    rows where independent corroboration is weakest. That is a biased probe
    reported as evidence, which is the shape of error this project spends most
    of its comments on.

    For the same reason the date does not enter `dates`, whose consumers all read
    it against `sources`: `clock.disclosure_order` filters it by `own`/`others`
    membership derived from `sources`, so a key with no matching source is
    silently dropped, and a key that DID gain a matching source would start
    feeding an ordering claim built out of this bias.

    It lands in `public_date`, which `clock.advisory_date` documents as the
    earliest date from any ingested source, tracker rows included, as against the
    advisory date that may start a 72-hour clock. That is exactly the right
    strength. It starts the 7-day buffer, so the row can be counted. It cannot
    start the expectation clock, because `ubuntu` is a tracker in
    `clock._ORIGIN_KIND` and this endpoint's `published` field is a tracker date
    whether it arrives by walk or by name.

    Health is recorded under `ubuntu:dates`, a sub-entry rather than a
    fourteenth feed, so a bad lookup pass shows up in `health_summary`'s
    truncation list without changing what `attempts` counts. A spent budget or a
    failed lookup is TRUNCATED and says how many, because a resolver that
    quietly returns fewer dates than it was asked for is the silent shrink this
    project has already been bitten by twice, arriving in a new place.
    """
    ids = list(dict.fromkeys(cve_ids))
    if not ids:
        record_feed("ubuntu:dates", OK, "no undated rows to date", rows=0,
                    counts_coverage=False)
        return {}

    started = time.monotonic()
    found, errors, asked = {}, 0, 0
    lock = threading.Lock()

    def one(cid):
        nonlocal errors, asked
        with lock:
            if time.monotonic() - started > budget_s:
                return
            asked += 1
        try:
            data, code, _ = _get(f"https://ubuntu.com/security/cves.json?q={cid}",
                                 timeout=timeout)
        except Exception:
            with lock:
                errors += 1
            return
        if not isinstance(data, dict):
            # `_get` returns (None, 404, {}) rather than raising, and a 404 on
            # this path is the endpoint moving, not the id being unknown: an
            # unknown id answers 200 with an empty `cves`. Counting it as "no
            # date" would turn a retired endpoint into a silently undated
            # backlog.
            with lock:
                errors += 1
            return
        for row in data.get("cves") or []:
            # `q` is a SEARCH, not a key lookup. It has matched on description
            # text in probing, so a row that is not the id we asked for is some
            # other CVE's date and must never be attached to this one.
            if row.get("id") != cid:
                continue
            d = _d(row.get("published"))
            if d:
                with lock:
                    found[cid] = d
            break

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        list(ex.map(one, ids))

    unasked = len(ids) - asked
    detail = f"dated {len(found)} of {len(ids)} undated row(s) by name"
    if errors:
        detail += f"; {errors} lookup(s) failed"
    if unasked:
        detail += (f"; the {budget_s}s budget was spent with {unasked} "
                   "row(s) never asked for")

    # THREE STATES, AND THE MIDDLE ONE IS THE POINT.
    #
    # Measured live over the real held-back population on 2026-08-28: 82 ids in
    # ~300s, and three passes returned 59, 62 and 64 dated. The whole spread is
    # transient lookup failures. A couple of them in eighty-two is this endpoint
    # on an ordinary afternoon, and reporting that as TRUNCATED
    # would mark the run degraded on most runs. That is the furniture problem
    # `degraded_state` rejects, reached from a fourth direction: a warning that
    # is always on is a warning nobody reads.
    #
    # It is safe to keep those runs green for a reason specific to this pass and
    # not true of a feed walk. A row this pass fails to date is not published
    # wrong and is not dropped from a count; it stays in `held_back.json` as
    # `undated`, exactly where it already was, and the NEXT run asks for it
    # again. The population is self-healing across runs, so a failed lookup
    # costs a day of latency on the floor rather than silently shrinking it. The
    # count still says so out loud in `detail`, which is where `feed_csaf`
    # already puts the same shape of partial result.
    #
    # A spent budget is CAPPED, not TRUNCATED, for the reason the walk's own
    # wall-clock budget is: a configured limit belongs in `limitations` rather
    # than in the degraded banner.
    #
    # But Ubuntu being DOWN is none of the above. If every lookup failed there
    # is no self-healing to appeal to, the pass learned nothing, and reporting
    # `ok, dated 0` would be the silent shrink wearing the excuse above as a
    # disguise. That one is loud.
    #
    # AND IT NEEDS ENOUGH EVIDENCE TO SAY SO. See `UBUNTU_DATES_OUTAGE_WAVES`:
    # under one wave of workers every request shares an instant, so "all failed"
    # is one observation and not a verdict. Below the floor this falls through to
    # the self-healing case above, which is the honest reading of it: the rows
    # stay `undated` in `held_back.json` and the next run asks again, which is
    # the same outcome a partial failure at a large population already gets, and
    # `detail` still names the count out loud either way.
    #
    # NOTHING IS LOST BY BEING CAUTIOUS HERE, and this is the part that makes the
    # floor safe rather than merely quieter. This pass is not the outage
    # detector for this host. `feed_ubuntu` walks ubuntu.com on every single run
    # and records its own health, so a real Ubuntu outage is caught there, by a
    # feed whose rows ARE coverage, whatever this resolver concludes.
    outage_floor = max(1, workers) * UBUNTU_DATES_OUTAGE_WAVES
    if ids and errors == len(ids) and len(ids) >= outage_floor:
        status = FAILED
    elif unasked:
        status = CAPPED
    else:
        status = OK
    record_feed("ubuntu:dates", status, detail, rows=len(found),
                counts_coverage=False)
    return found


UBUNTU_OSV_URL = "https://security-metadata.canonical.com/osv/osv-all.tar.xz"


# THE FEED CANONICAL ASKED US TO READ INSTEAD, and the measurements that say yes.
#
# Shafayat of the Ubuntu Security Team, replying 2026-08-31 to the pre-announcement
# outreach: rather than `cves.json`, "which can be subject to change", use the OSV
# data feed, a "more stable interface" that "should also help with the
# completeness/page-cap issue you mentioned". The page cap was disclosed to them in
# the outreach mail, so this is the publisher answering the exact defect the site
# was already wearing on /method.
#
# WHY IT IS A LARGE WIN, measured 2026-08-31 against the 2026-08-27 baseline:
#
#                            ids     RBP candidates   lead refs   cost
#   ubuntu   (cves.json)   3,994          102            20       1,070s, 5.2% read
#   ubuntu-osv (this)     15,790          191           222       ~25s, whole window
#
# The cost line is the headline. `_ubuntu_reach` exists to say, honestly and on
# every run, that the tracker reads 4,000 of 76,753 records and reaches back 33
# days against a window that opens 2025-01-01. This feed has NO cap, because
# `osv/cve/` is sharded by year: `want` selects `osv/cve/2025/` and
# `osv/cve/2026/` and the reach question stops existing. That is the whole reason
# a 42 MB download beats a 200-page walk, and it is why there is no
# `_ubuntu_osv_reach` below.
#
# THE TRAP, and it is the GIT trap again. Ubuntu's OSV records leave `aliases`
# EMPTY and carry the CVE id in `upstream` (verified 400/400 on a 2026 sample,
# 2026-08-31). So the one-line change that looks like the whole job here, adding
# "Ubuntu" to `feed_osv`'s ecosystem tuple, returns ZERO rows: `feed_osv` reads
# `aliases`. That is precisely how the GIT ecosystem was banked at +18 CNAs from a
# full-text probe and delivered +0 from the adapter. Same shape, caught this time
# by reading the publisher's documented example before writing the config.
#
# `id` is `UBUNTU-<CVE>` and matched `upstream` on all 400, so the id is a
# cross-check rather than a second source.
#
# WHY THIS DOES NOT DELETE `feed_ubuntu`, which was the assumption going in and
# the measurement refused it. 1,273 of the tracker's 3,994 ids (31.9%) have NO OSV
# record at all, because OSV covers supported releases and the tracker triages
# every CVE it sees. Those 1,273 carry 39 RBP candidates. So OSV is not a superset
# and a straight swap would have quietly dropped rows while every count on the
# page went up.
#
# What the measurement DID find is that all 39 are already sighted by another
# merged feed, so the tracker's unique contribution is sightings rather than rows,
# and sightings feed `cnas_effective`, which is the launch gate. That makes the
# tracker's 1,070s a gate question and not a rows question, and it is answered by
# `feedlab audit` rather than here. Both feeds run until it is answered.
def feed_ubuntu_osv(years):
    """Canonical's own OSV publication of the Ubuntu CVE records, whole window.

    One 42 MB tarball, year-sharded, so there is no pagination, no page cap, no
    wall-clock budget and no reach caveat. See the block comment above for the
    measurements and for why `feed_ubuntu` stays.

    WITHDRAWN RECORDS ARE SKIPPED. 290 of the 15,790 in-window records carry a
    `withdrawn` timestamp (1.8%, 2026-08-31), which is Ubuntu retracting the
    record. A retracted reference is not a reference, and counting one would put
    an id on a page whose own publisher has withdrawn it. The count goes in the
    health detail rather than being dropped silently, because a number that moves
    for a reason nobody recorded is the thing this module is most careful about.
    """
    want_dirs = tuple(f"osv/cve/{y}/" for y in sorted(years))

    def want(name):
        return name.startswith(want_dirs) and name.endswith(".json")

    out, seen, withdrawn, stats = [], set(), 0, {"bytes": 0}
    try:
        for _name, raw in _stream_tar_xz(UBUNTU_OSV_URL, want, stats):
            try:
                rec = json.loads(raw)
            except Exception:
                continue
            if rec.get("withdrawn"):
                withdrawn += 1
                continue
            rid = rec.get("id", "")
            # `upstream`, NOT `aliases`. See the block comment above.
            cves = [a for a in (rec.get("upstream") or [])
                    if a.startswith("CVE-") and _year(a) in years]
            aff = rec.get("affected") or []
            pkg = ""
            if aff:
                pkg = ((aff[0].get("package") or {}).get("name") or "")[:120]
            pub = _d(rec.get("published"))
            desc = (rec.get("details") or "")[:400]
            for cid in cves:
                if cid in seen:
                    continue
                seen.add(cid)
                out.append({"cve_id": cid, "source": "ubuntu-osv",
                            "source_ref": rid or cid, "public_date": pub,
                            "product": pkg, "description": desc})
    # Broad on purpose: keep the partial results. See feed_ubuntu.
    #
    # TWO STATES, and the split is the one `record_feed` was given four states
    # for. Unlike the tracker walk this feed has no configured cap for a short
    # read to hide behind, so:
    #
    #   nothing read    FAILED. The host is unreachable or the tarball is not a
    #                   tarball. There is no partial result to defend.
    #   something read  TRUNCATED, which degrades the run. A stream that died
    #                   halfway through 2026 returns a plausible number of
    #                   plausible rows, and that is precisely the shape a silent
    #                   shrink takes.
    #
    # Neither is CAPPED. CAPPED means a limit this project configured and
    # discloses, and the whole point of this adapter is that it has none.
    except Exception as e:
        print(f"  [ubuntu-osv] stream stopped: {e}", file=sys.stderr)
        record_feed("ubuntu-osv", FAILED if not out else TRUNCATED,
                    f"stream stopped after {len(out)} ids: {str(e)[:100]}",
                    rows=len(out))
        return out

    detail = f"{len(out)} ids from {stats['bytes'] / 1e6:.0f}MB"
    if withdrawn:
        detail += f"; skipped {withdrawn} withdrawn record(s)"
    # A read that downloaded the tarball and matched nothing is NOT ok. `want`
    # is a path prefix against a layout the publisher controls, so this is the
    # one place a reorganised tarball turns into a silently empty feed.
    if not out:
        record_feed("ubuntu-osv", FAILED,
                    f"{stats['bytes']:,} bytes read and no member matched "
                    f"{', '.join(want_dirs)}; the tarball layout may have changed",
                    rows=0)
        return out
    record_feed("ubuntu-osv", OK, detail, rows=len(out))
    return out


def feed_debian(years):
    data, _, _ = _get("https://security-tracker.debian.org/tracker/data/json", timeout=180)
    out, seen = [], set()
    for pkg, cves in (data or {}).items():
        for cid, meta in (cves or {}).items():
            if _year(cid) in years and cid not in seen:
                seen.add(cid)
                desc = meta.get("description", "") if isinstance(meta, dict) else ""
                out.append({"cve_id": cid, "source": "debian", "source_ref": pkg,
                            "public_date": "", "product": pkg, "description": desc[:400]})
    return out


def _gh_headers():
    """Auth for both GitHub feeds, resolved the same way for each.

    Unauthenticated is 60 requests an hour and neither feed fits inside that:
    `feed_ghsa` alone reads about a hundred pages of a year. The environment is
    consulted first so Actions supplies its token, with the local `gh` CLI as the
    fallback so a developer run behaves like a scheduled one.
    """
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if not token:
        try:
            token = subprocess.check_output(["gh", "auth", "token"], text=True).strip()
        except Exception:
            token = None
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _month_end(y, m):
    nxt = dt.date(y + (m == 12), (m % 12) + 1, 1)
    return nxt - dt.timedelta(days=1)


def _ghsa_window(start, end, headers, page_cap):
    """One publication-window shard. Returns (rows, "complete" | "capped")."""
    url = ("https://api.github.com/advisories?per_page=100&type=reviewed"
           f"&sort=published&direction=desc&published={start}..{end}")
    rows = []
    for _ in range(page_cap):
        data, _code, hdrs = _get(url, timeout=60, headers=headers)
        rows += data or []
        nxt = [p.split(";")[0].strip("<> ")
               for p in hdrs.get("Link", "").split(",") if 'rel="next"' in p]
        if not nxt:
            return rows, "complete"
        url = nxt[0]
    return rows, "capped"


# MEASURED 2026-08-26. Why this reads a month at a time instead of one scan.
#
# The single descending scan read the newest 4,000 advisories and stopped, which
# is 83 days (2026-05-18 to 2026-08-26) against distro trackers observed over
# years. The comment this replaces said exactly that and could not say the size
# of the miss: 9,512 reviewed advisories were published between 2026-01-01 and
# 08-26, so the scan covered 42% of the year it reported on. A fixed cap also
# returns a roughly CONSTANT count every run, so compare_magnitudes reads stable
# truncation as a healthy feed, and the one detector for the failure this project
# calls intolerable was blind to the likeliest instance of it.
#
# Sharding by publication month bounds each shard to a window the cap cannot
# swallow. Measured reviewed volume per month in 2026: Jan 491, Feb 765, Mar
# 1,639, Apr 1,583, May 1,701, Jun 1,494, Jul 1,278. The worst month is 18 pages
# against a 40-page shard cap, so the cap became headroom rather than a standing
# truncation, and a month that does exceed it is NAMED in the health record
# instead of vanishing into one whole-feed count.
#
# `type=reviewed` IS NOT OPTIONAL HERE, and it is not a filter the old scan
# needed. The endpoint's default population depends on whether `published` is
# present, which is not documented and was measured:
#
#     sort=published&direction=desc                     100% reviewed
#     sort=published&direction=desc&published=<range>    94% unreviewed
#
# Adding the shard window therefore widens the population by itself. Over the
# 83-day window the old scan covered: 3,323 reviewed rows against 22,571
# unreviewed, so omitting the parameter is a sevenfold read for advisories that
# cannot be RBP by construction. Unreviewed advisories are GitHub's imports of
# already-published CVE records, and all 371 rows this feed contributed to the
# 2026-08-20 snapshot are reviewed, none unreviewed.
#
# The shard walk starts at January of the EARLIEST requested year and runs to
# today, not to each year's December. A CVE-2025 id can be disclosed in 2026,
# and the old scan caught it by counting backwards from today; a per-year window
# would have quietly dropped exactly those rows on a backfill run.
def feed_ghsa(years, page_cap=40, today=None):
    headers = _gh_headers()
    today = today or dt.date.today()
    out, capped, stopped = [], [], None
    y, m = min(years), 1
    while dt.date(y, m, 1) <= today:
        start, end = dt.date(y, m, 1), min(_month_end(y, m), today)
        try:
            rows, ended = _ghsa_window(start, end, headers, page_cap)
        # Broad on purpose: keep the partial results. See feed_ubuntu.
        except Exception as e:
            print(f"  [ghsa] stopped at {y}-{m:02d}: {e}", file=sys.stderr)
            stopped = f"stopped at {y}-{m:02d} of the shard walk: {str(e)[:80]}"
            break
        if ended == "capped":
            capped.append(f"{y}-{m:02d}")
        for a in rows:
            cid = a.get("cve_id")
            if cid and _year(cid) in years:
                out.append({"cve_id": cid, "source": "ghsa",
                            "source_ref": a.get("ghsa_id", ""),
                            "public_date": _d(a.get("published_at")), "product": "",
                            "description": (a.get("summary") or "")[:400]})
        y, m = (y + 1, 1) if m == 12 else (y, m + 1)
    # A shard cap is a configured limit and stays CAPPED. A shard that died is
    # not, and degrades the run. See the four states at the top of this file.
    if stopped:
        print(f"  [ghsa] {stopped}", file=sys.stderr)
        record_feed("ghsa", TRUNCATED, stopped)
    elif capped:
        detail = (f"hit the {page_cap}-page cap in {len(capped)} month(s) "
                  f"({', '.join(capped)}); advisories beyond it were not read")
        print(f"  [ghsa] {detail}", file=sys.stderr)
        record_feed("ghsa", CAPPED, detail)
    return out


_HERE = os.path.dirname(os.path.abspath(__file__))
# The watchlist is COMMITTED and the state is not, so they cannot share a home:
# `data/` is gitignored wholesale ("must NEVER enter the repo", .gitignore) and
# the state file is full of CVE ids, which is the one thing that may not reach a
# public branch. See the cache step in deploy.yml.
GHSA_REPOS_LIST = os.path.join(_HERE, "feed_data", "ghsa_repos.txt")
GHSA_REPOS_STATE = os.path.join(os.path.dirname(_HERE), "data", "ghsa_repos_state.json")

_GHSA_ID_RE = re.compile(r"^GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}\Z")
_CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}\Z")
_REPO_RE = re.compile(r"^[A-Za-z0-9._-]{1,39}/[A-Za-z0-9._-]{1,100}\Z")
_GHSA_REPO_CHUNK = 64


def _get_cond(url, headers=None, timeout=60):
    """GET that REPORTS 304 rather than raising it.

    `_get` cannot express a conditional fetch: urllib treats everything outside
    2xx as an error, so the one response this feed depends on being cheap arrives
    as an exception and reads identically to a failure. Everything else is shared
    with `_get` on purpose (the SSRF guard, the pinned opener, byte accounting),
    so a second fetch path is not a second set of holes.

    Returns (status, parsed_or_None, lowercased_headers). 304 and 404 are
    answers, not errors, and are returned as such.
    """
    if not _url_ok(url):
        raise ValueError(f"blocked non-https/internal URL: {url}")
    h = dict(UA)
    if headers:
        h.update(headers)
    try:
        with _OPENER.open(urllib.request.Request(url, headers=h), timeout=timeout) as r:
            raw = r.read(MAX_BYTES)
            FETCH_BYTES["total"] += len(raw)
            return (getattr(r, "status", 200), json.loads(raw),
                    {k.lower(): v for k, v in r.headers.items()})
    except urllib.error.HTTPError as e:
        hdrs = {k.lower(): v for k, v in dict(e.headers or {}).items()}
        if e.code in (304, 404):
            return e.code, None, hdrs
        raise


def _repo_advisory_ok(a, owner, repo):
    """A repo advisory counts only if it is published, not withdrawn, carries a
    well-formed CVE id, and its html_url belongs to the repo that was polled.

    That last clause is not distrust of GitHub. The advisory AUTHOR controls the
    `cve_id` field, so without it a watchlisted repo could attach any id it liked
    and this site would publish the claim as a reserved-but-public finding
    against whichever CNA owns that id.
    """
    if a.get("state") != "published" or a.get("withdrawn_at"):
        return False
    if not _CVE_ID_RE.match(a.get("cve_id") or ""):
        return False
    if not _GHSA_ID_RE.match(a.get("ghsa_id") or ""):
        return False
    prefix = f"https://github.com/{owner}/{repo}/security/advisories/".lower()
    return (a.get("html_url") or "").lower().startswith(prefix)


def _read_repo_list(path):
    try:
        with open(path) as f:
            names = [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
    except OSError:
        return []
    return [n for n in names if _REPO_RE.match(n)]


_CURATED_RE = re.compile(r"^#\s*curated:\s*(\d{4}-\d{2}-\d{2})\s*$", re.M)


def _repo_list_age_days(path, today=None):
    """Days since the repo list was last curated, or None if it says nothing.

    THE LARGEST SOURCE ON THIS SITE DECAYS AND NO NUMBER TRACKED IT. The file's
    own header says so in words: "NOT SELF-REFRESHING. Discovering a repository
    that publishes its FIRST advisory is a mining problem and it is not solved
    here." Honest, and unmeasured, which is the combination that lets a decision
    quietly become a default.

    `compare_magnitudes` cannot see this. The repos on the list keep publishing,
    so the id count stays healthy while the share of the real population the feed
    can reach falls. On 2026-08-27 this feed was the sole source for 1,015 of
    1,709 published rows, 59% of the headline, off 1,875 repositories frozen on
    2026-08-26 and drawn from a 10,000-repo sweep.

    A date in a comment is asserted config, which this codebase prefers to avoid,
    and the alternative was a mining job nobody has scheduled. Asserted and
    reported beats derived and absent: the age reaches the health line every run,
    so the decision to leave the list alone has to keep being made rather than
    happening.
    """
    try:
        with open(path) as f:
            m = _CURATED_RE.search(f.read())
    except OSError:
        return None
    if not m:
        return None
    try:
        base = dt.date.fromisoformat(today) if today else dt.date.today()
        return (base - dt.date.fromisoformat(m.group(1))).days
    except ValueError:
        return None


def _load_repo_state(path):
    try:
        with open(path) as f:
            st = json.load(f)
    except Exception:
        st = {}
    if not isinstance(st, dict) or not isinstance(st.get("repos"), dict):
        return {"schema": "ghsa-repos/1", "cursor": None, "repos": {}}
    st.setdefault("cursor", None)
    return st


def _save_repo_state(path, st):
    """Atomic, because a torn state file is indistinguishable from a cold start
    and a cold start is the one condition that cannot be paid for in one run."""
    tmp = path + ".tmp"
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(tmp, "w") as f:
        json.dump(st, f, separators=(",", ":"), sort_keys=True)
    os.replace(tmp, path)


def _poll_repo(name, headers, entry, page_cap=20):
    """Conditionally fetch one repo's advisories.

    Returns (status, rows, last_modified) where status is one of "updated",
    "not_modified", "not_found", "capped" or "error". Only "updated" and
    "not_found" carry authority over the stored rows; see the caller.
    """
    owner, repo = name.split("/", 1)
    url = (f"https://api.github.com/repos/{owner}/{repo}"
           "/security-advisories?per_page=100&sort=published&direction=desc")
    req = dict(headers)
    if entry.get("last_modified"):
        req["If-Modified-Since"] = entry["last_modified"]
    rows, last_mod, pages = [], None, 0
    while url:
        pages += 1
        if pages > page_cap:
            return "capped", rows, last_mod
        status, data, hdrs = _get_cond(url, headers=req, timeout=45)
        if status == 304:
            return "not_modified", [], entry.get("last_modified")
        if status == 404:
            return "not_found", [], None
        if pages == 1:
            last_mod = hdrs.get("last-modified")
        for a in data or []:
            if _repo_advisory_ok(a, owner, repo):
                rows.append({"cve_id": a["cve_id"], "ghsa_id": a["ghsa_id"],
                             "published": _d(a.get("published_at"))})
        nxt = [p.split(";")[0].strip("<> ")
               for p in hdrs.get("link", "").split(",") if 'rel="next"' in p]
        url = nxt[0] if nxt else None
        # The conditional header belongs to the FIRST page only. Replaying it on
        # page 2 asks "has anything changed since?" of a URL that answered 200 a
        # moment ago, and a 304 there would silently return half a repo's rows.
        req = dict(headers)
    return "updated", rows, last_mod


# WHAT THIS FEED IS FOR, and why `ghsa` alone cannot do it.
#
# A repository advisory with no package ecosystem NEVER enters
# github/advisory-database, so GET /advisories cannot return it at any page cap,
# in any window, with any `type`. Raising ghsa's cap does not reach these rows;
# only the per-repo endpoint does.
#
# MEASURED 2026-08-26 against the 2026-08-20 snapshot. The repos in
# data/ghsa_repos.txt yielded 1,030 CVE ids absent from the RBP backlog
# entirely, of which 1,018 were RESERVED at the reservation oracle that same day
# (the other 12 had published since). A 150-id sample of those was probed against
# the global endpoint and 150 of 150 were absent from it. One example, so the
# claim is checkable rather than statistical: CVE-2026-12521 is public as
# zephyrproject-rtos/zephyr GHSA-g5v9-xmfp-7gxm with a full technical writeup,
# 404 on /advisories/GHSA-g5v9-xmfp-7gxm, and RESERVED at MITRE.
#
# A PARTIAL SWEEP MUST NOT SHRINK THE FEED, which is the whole reason the state
# file stores rows rather than only validators. `gather` rebuilds refs from
# scratch every run, so a feed that returned only what it polled this run would
# report a smaller count whenever the rate budget stopped the sweep early, and a
# feed shrinking quietly is the failure this project treats as intolerable. Every
# stored row is returned every run; polling only decides which entries get
# REFRESHED. That is the same reasoning as classify's `previous_reserved`.
#
# The three states that may mutate stored rows, and the two that may not:
#   200  authoritative, replaces the repo's rows wholesale
#   404  authoritative-absent (renamed, deleted, or made private), clears them
#   304  nothing changed, keep them, and costs no rate-limit quota (measured)
#   error / budget stop  UNKNOWN, never absent, keep them
#   page cap  a partial list is not a restatement, so it is not allowed to
#             replace a complete one either; the stored rows stand and the cap is
#             named in the health record
def feed_ghsa_repos(years, budget_buffer=150, page_cap=20,
                    list_path=None, state_path=None):
    list_path = list_path or GHSA_REPOS_LIST
    state_path = state_path or GHSA_REPOS_STATE
    headers = _gh_headers()
    repos = _read_repo_list(list_path)
    if not repos:
        record_feed("ghsa-repos", FAILED, f"no repo list at {os.path.basename(list_path)}")
        return []
    st = _load_repo_state(state_path)
    entries = st["repos"]

    # Round-robin from the saved cursor, so a budget stop resumes where it left
    # off instead of re-polling the head of the list every run and never reaching
    # the tail.
    start = repos.index(st["cursor"]) if st.get("cursor") in repos else 0
    order = repos[start:] + repos[:start]

    counts = {"updated": 0, "not_modified": 0, "not_found": 0, "capped": 0, "error": 0}
    polled, stopped_at = 0, None

    # Chunked rather than one big pool, for two reasons that are both about the
    # budget. The rate check costs a round trip per call, so it runs once per
    # chunk instead of once per repo (1,875 extra round trips was most of this
    # feed's wall clock). And a chunk boundary is the only place a CURSOR is
    # meaningful: results are applied in list order, so the resume point is the
    # head of the first chunk not yet applied, with nothing half-done behind it.
    for base in range(0, len(order), _GHSA_REPO_CHUNK):
        chunk = order[base:base + _GHSA_REPO_CHUNK]
        for name in chunk:
            entries.setdefault(name, {"last_modified": None, "rows": []})
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
            futures = [ex.submit(_poll_repo, n, headers, entries[n], page_cap)
                       for n in chunk]
            results = []
            for n, f in zip(chunk, futures):
                try:
                    results.append((n, f.result(), None))
                # Broad on purpose: one unreachable repo is not a feed failure,
                # and its stored rows survive it. See feed_ubuntu.
                except Exception as e:
                    results.append((n, None, e))
        for name, res, err in results:
            entry = entries[name]
            if err is not None:
                counts["error"] += 1
                entry["consecutive_errors"] = entry.get("consecutive_errors", 0) + 1
                print(f"  [ghsa-repos] {name}: {str(err)[:90]}", file=sys.stderr)
                continue
            status, rows, last_mod = res
            polled += 1
            counts[status] += 1
            entry.pop("consecutive_errors", None)
            if status == "updated":
                entry["rows"], entry["last_modified"] = rows, last_mod
            elif status == "not_found":
                entry["rows"], entry["last_modified"] = [], None
                entry["not_found_since"] = entry.get("not_found_since") or str(dt.date.today())
            if status != "not_found":
                entry.pop("not_found_since", None)
        nxt = base + _GHSA_REPO_CHUNK
        if nxt < len(order) and _rate_exhausted(budget_buffer):
            stopped_at = order[nxt]
            break
    st["cursor"] = stopped_at
    _save_repo_state(state_path, st)

    out, seen = [], set()
    for name, entry in entries.items():
        for r in entry.get("rows", []):
            cid = r.get("cve_id", "")
            if _year(cid) not in years or cid in seen:
                continue
            seen.add(cid)
            # "<owner/repo>\t<GHSA>", tab-separated for the same reason csaf
            # carries "<provider>\t<id>\t<url>": report._derive_meta has to
            # rebuild the advisory URL, and a repository advisory lives under the
            # repo's own path rather than at /advisories/<id>. Without the repo
            # name the row would fall through to the cve.org last resort, which
            # renders NOTHING for a RESERVED id, so the site would publish a row
            # whose only evidence link disproved it.
            out.append({"cve_id": cid, "source": "ghsa-repos",
                        "source_ref": f"{name}\t{r.get('ghsa_id', '')}",
                        "public_date": r.get("published", ""), "product": name,
                        "description": f"{name} repository advisory {r.get('ghsa_id', '')}"})

    detail = (f"{polled} of {len(repos)} repos polled "
              f"({counts['updated']} changed, {counts['not_modified']} unchanged, "
              f"{counts['not_found']} gone, {counts['error']} errored)")
    # The age rides on EVERY branch below, including the healthy one, because a
    # decaying list is not an error state and would otherwise be the one fact
    # about this feed that only surfaces when something else has already broken.
    # Same lesson as the CSAF disclosure that only survived on a degraded run.
    age = _repo_list_age_days(list_path)
    if age is not None:
        detail += f"; repo list curated {age}d ago and does not self-refresh"
    if counts["error"] > max(5, polled * 0.2):
        record_feed("ghsa-repos", TRUNCATED, f"{detail}; error rate above 20%")
    elif stopped_at:
        # A budget stop is a configured limit reached, exactly like a page cap,
        # and the sweep resumes next run. It is CAPPED, not a degradation.
        record_feed("ghsa-repos", CAPPED,
                    f"{detail}; the rate budget stopped the sweep, resuming at {stopped_at}")
    elif counts["capped"]:
        record_feed("ghsa-repos", CAPPED,
                    f"{detail}; {counts['capped']} repo(s) hit the {page_cap}-page cap")
    print(f"  [ghsa-repos] {detail}", file=sys.stderr)
    return out


def _rate_exhausted(buffer):
    """True when the GitHub core budget is down to its reserve.

    Read from the rate_limit endpoint rather than tracked from response headers
    because the 304s this feed depends on do not decrement anything, so a locally
    maintained counter drifts pessimistic and would stop a sweep that had budget
    left. The endpoint itself is not rate limited.
    """
    try:
        data, _code, _h = _get("https://api.github.com/rate_limit", timeout=15,
                               retries=1, headers=_gh_headers())
        return int(data["resources"]["core"]["remaining"]) < buffer
    # Unknown budget is not an exhausted budget: a failed check must not stop a
    # sweep that has quota, or a transient blip becomes a permanently short feed.
    except Exception:
        return False


def feed_redhat(years):
    """Red Hat security-data API: broad CNA coverage + severity + package."""
    out, seen = [], set()
    for y in sorted(years):
        page, per = 1, 1000
        while True:
            try:
                data, code, _ = _get(
                    f"https://access.redhat.com/hydra/rest/securitydata/cve.json"
                    f"?after={y}-01-01&before={y}-12-31&per_page={per}&page={page}", timeout=90)
            # Broad on purpose: keep the partial results. See feed_ubuntu.
            except Exception as e:
                print(f"  [redhat] stopped ({y} p{page}): {e}", file=sys.stderr)
                break
            rows = data or []
            if not rows:
                break
            for r in rows:
                cid = r.get("CVE", "")
                if _year(cid) in years and cid not in seen:
                    seen.add(cid)
                    pkg = (r.get("bugzilla_description") or "").split(":")[0].strip()
                    out.append({"cve_id": cid, "source": "redhat", "source_ref": cid,
                                "public_date": _d(r.get("public_date")), "product": pkg,
                                "description": (r.get("bugzilla_description") or "")[:400]})
            if len(rows) < per:
                break
            page += 1
    return out


def feed_alpine(years, branches=("v3.21", "v3.20", "edge"), repos=("main", "community")):
    """Alpine secdb: per-branch package -> secfixes -> CVE ids."""
    out, seen = [], set()
    for br in branches:
        for repo in repos:
            try:
                data, code, _ = _get(f"https://secdb.alpinelinux.org/{br}/{repo}.json", timeout=60)
            # One branch failure must not drop the whole feed.
            except Exception as e:
                print(f"  [alpine] skip {br}/{repo}: {e}", file=sys.stderr)
                continue
            for pkg in (data or {}).get("packages", []):
                p = pkg.get("pkg", {})
                name = p.get("name", "")
                for _ver, cves in (p.get("secfixes") or {}).items():
                    for cid in cves or []:
                        cid = cid.split()[0]  # some entries append notes
                        if _year(cid) in years and cid not in seen:
                            seen.add(cid)
                            out.append({"cve_id": cid, "source": "alpine", "source_ref": name,
                                        "public_date": "", "product": name, "description": ""})
    return out


# OSV publishes 46 ecosystems; this reads 11. The other 35 were scored against the
# corpus on 2026-08-23 and the result is why the list is not longer: every distro
# ecosystem (Red Hat, SUSE, Rocky, AlmaLinux, Chainguard, Wolfi, openEuler, Mageia,
# TuxCare, Azure Linux, Bitnami) contributes ZERO new CNAs at the 3-sighting floor,
# because the distros are exactly what the other nine feeds already read.
#
# `Android` is the one that earned its place: +7 CNAs (Arm, Google_Devices,
# MediaTek, Unisoc, google_android, imaginationtech, qualcomm) for 620 rows in
# 0.5s. It also made a hand-written Android Security Bulletin scraper unnecessary,
# which was the top item on the expansion list until this was measured.
#
# `GIT` is deliberately ABSENT despite looking like the biggest win available. A
# full-text regex over its archive finds 31,366 in-scope CVE IDs and suggested
# +18 CNAs; the ADAPTER returns 450 rows and +0, because it reads CVE aliases and
# GIT records carry their CVE references elsewhere. The estimate and the adapter
# were measuring different things. Anything added here needs the adapter's own
# number, not a probe's.
# OSV ECOSYSTEMS, 15 OF 46. The four added on 2026-08-27 are the measured half of
# FEEDS.md Tier 1's standing "merge the remaining 27" instruction, which treated 35
# ecosystems as one decision called "bandwidth" and therefore never got made.
#
# Sizes fetched 2026-08-27. They are not one decision:
#
#   the small eight   GitHub Actions 99KB, SwiftURL 107KB, Hackage 51KB,
#                     opam 49KB, VSCode 21KB, CRAN 12KB, GSD 6KB, UVI 1KB
#                     = 346KB total, against osv's existing 305MB per run
#   the large six     MinimOS 67MB, Linux 55MB, Chainguard 30MB, Wolfi 19MB,
#                     Root 14MB, Bitnami 9MB = 195MB, a 64% increase, for six
#                     distro-rebuild channels that are exactly the category
#                     measured at +0 CNAs. NOT merged on this evidence.
#
# Scored as their own candidate before merging, against the 2026-08-27 baseline:
#
#   58 ids, 6 not already seen, 0 marginal CNAs, 7 unpublished now,
#   disclosure lead on 24 of 51 dated references (median 13d, max 97d),
#   1.1s and 0.3 MB.  VERDICT: corroborating.
#
# Merged on the strength of test 2, which FEEDS.md section 2 explicitly permits:
# "corroborating is not a soft rejection. It means the feed may be merged." Zero
# marginal CNAs means this buys NO coverage and no gate movement, and it is not
# counted as progress toward either. What it buys is seven currently-unpublished
# ids, which is the thing the site is actually about, for a tenth of a percent of
# this adapter's existing bandwidth.
#
# MEASURED AT ZERO AND DELIBERATELY NOT MERGED: VSCode, CRAN, GSD, UVI. All four
# returned 0 in-scope ids for 2025-2026 on 2026-08-27, at 41KB combined. Recorded
# here rather than merged-and-empty so the next person does not re-probe them,
# and dated so revisiting is a decision rather than an oversight.
#
# `Pub` REMOVED 2026-09-01, and it is the same policy applied one id later.
#
# Pub holds **1** in-scope id: 13 records in the whole archive, one of them
# aliasing an in-window CVE. It was configured when the rule above was written and
# it sits one id from being the case that rule already decided.
#
# What forced the decision is the guard added below on the same day. A configured
# ecosystem yielding nothing in scope now records FAILED, and `health_summary`
# collects FAILED sub-entries into `failures` without filtering on the colon, so
# `cli.degraded_state` would mark the whole run degraded. Pub's single id ageing
# out of the window is therefore one id away from putting "This run is incomplete"
# across every page of the site, on behalf of a 13-record ecosystem.
#
# That is precisely the furniture problem `record_feed`'s four states exist to
# avoid, reached from a new direction: a warning that fires for a non-reason
# trains a reader to ignore the banner that matters. Between losing 1 id of 45,895
# and arming that, the id loses. Recorded, dated, and reversible: if Pub is ever
# wanted back, the guard needs a shape that can tell "too small to matter" from
# "could not be read", which this one deliberately cannot.
def feed_osv(years, ecosystems=("PyPI", "npm", "Go", "crates.io", "RubyGems",
                                "Maven", "Packagist", "NuGet", "Hex",
                                "Android",
                                "GitHub Actions", "SwiftURL", "Hackage", "opam")):
    """OSV.dev bulk per-ecosystem dumps: language-ecosystem breadth. Each record's
    CVE aliases are the referenced IDs; package name is the attribution product."""
    out, seen = [], set()
    for eco in ecosystems:
        # QUOTED. The ecosystem name goes into a URL path and five of OSV's 46
        # names contain a space: "GitHub Actions", "Red Hat", "Rocky Linux",
        # "Azure Linux" and "BellSoft Hardened Containers". Unquoted, urllib
        # raises `URL can't contain control characters` before any request is
        # made, so this adapter could not fetch any of them at all and would have
        # recorded each as a hard FAILED.
        #
        # Latent until 2026-08-27 because none of the five was configured, and
        # found by trying to merge the small ecosystems rather than by reading
        # the code. It matters more than it looks: FEEDS.md's standing
        # instruction to "merge the remaining 27" includes three of these, and
        # the 2026-08-22 measurement that scored them at +0 CNAs was a full-text
        # probe over the archives, NOT this adapter. That is the same
        # probe-and-adapter-measure-different-things gap that made the GIT
        # estimate wrong by its entire value, sitting unnoticed in the same table.
        url = ("https://osv-vulnerabilities.storage.googleapis.com/"
               f"{urllib.parse.quote(eco)}/all.zip")
        if not _url_ok(url):
            record_feed(f"osv:{eco}", False, "url rejected by the SSRF guard")
            continue
        tmp_path = None
        try:
            zf, tmp_path, nbytes = _stream_zip(url)
        except Exception as e:
            record_feed(f"osv:{eco}", False, str(e)[:120])
            print(f"  [osv:{eco}] FAILED: {e}", file=sys.stderr)
            continue
        n0 = len(out)
        found = set()
        for info in zf.infolist():
            name = info.filename
            if not name.endswith(".json") or info.file_size > 2_000_000:
                continue
            try:
                rec = json.loads(zf.read(name))
            except Exception:
                continue
            cves = [a for a in (rec.get("aliases") or []) if a.startswith("CVE-") and _year(a) in years]
            found.update(cves)
            if not cves:
                continue
            aff = rec.get("affected") or []
            pkg = ""
            if aff:
                pkg = ((aff[0].get("package") or {}).get("name") or "")[:120]
            pub = _d(rec.get("published"))
            summ = (rec.get("summary") or rec.get("details") or "")[:400]
            for cid in cves:
                if cid in seen:
                    continue
                seen.add(cid)
                out.append({"cve_id": cid, "source": "osv", "source_ref": f"{eco}:{pkg}",
                            "public_date": pub, "product": pkg, "description": summ})
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        added = len(out) - n0
        # TWO NUMBERS, BECAUSE `added` CANNOT ANSWER "DID THIS ARCHIVE GIVE US
        # ANYTHING", AND THAT IS THE QUESTION THE GUARD BELOW ASKS.
        #
        # `seen` is shared across the whole ecosystem loop, so `added` is what an
        # ecosystem contributed THAT NO EARLIER ONE HAD: it is order-dependent and
        # it understates every ecosystem after the first. Measured, `added` from the
        # 2026-08-31 baseline against `found` re-measured 2026-09-01:
        #
        #   SwiftURL   16 credited of 22 held      Hex   186 of 211
        #   crates.io  366 of 384                  NuGet 376 of 386
        #   RubyGems   206 of 219                  GitHub Actions 20 of 23
        #
        # (A day apart, so a few of those ids are drift rather than dedup. SwiftURL
        # at 27% understated in a 62-record archive is not drift.)
        #
        # `found` is the ids this ecosystem's own archive contained, deduped within
        # the ecosystem and independent of loop order, which is both the honest
        # thing to compare and the thing that goes to zero when something is
        # actually wrong.
        #
        # A FIRST VERSION OF THIS COMMENT SAID `osv:Pub` RECORDED +1 BECAUSE
        # EARLIER ECOSYSTEMS HAD SUPPLIED ITS IDS. That was wrong, and it was
        # wrong in the direction that flatters this change. Pub holds **1**
        # in-scope id, measured directly: 13 records in the whole archive, one of
        # them aliasing an in-window CVE. `added` and `found` agree there. See the
        # tuple below, where that measurement had a consequence.
        #
        # `rows=` MOVES FROM `added` TO `found` for the same reason: an
        # order-dependent row count means reordering the tuple below would fire
        # spurious `compare_magnitudes` drops on several parts with no change in
        # any data. The transition is safe in one direction only, which is the
        # right one: `found >= added` always, so every part's recorded count rises
        # or holds, and `compare_magnitudes` only ever fires on a fall.
        detail = f"{added} new of {len(found)} in-scope ids from {nbytes / 1e6:.0f}MB"
        if not found:
            # AN ARCHIVE THAT YIELDED NOTHING IS NOT A HEALTHY FEED PART, and
            # until 2026-09-01 it recorded as `ok` with "0 ids".
            #
            # This is the third appearance of one bug in this file. `feed_osv`
            # reads CVE ids from `aliases`, and that is the WRONG FIELD for an
            # entire class of publisher. Measured 2026-09-01 across the five
            # distro ecosystems with a dedicated feed here, in-scope CVE ids by
            # field:
            #
            #                aliases   upstream   related
            #   Red Hat            0      3,140         0
            #   SUSE               0      6,833     6,833
            #   Rocky Linux        0      2,120         3
            #   AlmaLinux          0          0     2,116
            #   Alpine             0        899         0
            #
            # ZERO through `aliases`, every one of them. `upstream` is a ratified
            # OSV field (ossf/osv-schema#249, merged as PR #312) meaning an
            # ASYMMETRIC reference: the CVE covers more than the distro record
            # does, so `aliases`, which asserts equivalence, would be wrong for
            # them to use. Canonical said in that thread they do not expect to
            # move to `aliases`; SUSE and Red Hat agreed the field suits them.
            # This is settled schema behaviour, not a quirk to wait out.
            #
            # It is why `feed_ubuntu_osv` reads `upstream` rather than being one
            # line of config in the tuple below, and it is why FEEDS.md Tier 1's
            # "+0 CNAs for every distro ecosystem" was an artefact: the adapter
            # could not read a single id from any of them. Corrected measurement
            # is in FEEDS.md under "MEASURED 2026-09-01"; the conclusion survives,
            # so nothing here is merged on the strength of it.
            #
            # The guard, not the fix. Reading three fields buys 313 ids and 8 RBP
            # candidates across eight ecosystems and 180 MB, which this project
            # declines. What it must not do is decline SILENTLY, so a configured
            # ecosystem that returns nothing is now loud, and the next one added
            # cannot sit in the tuple reading zero and reporting health.
            record_feed(f"osv:{eco}", FAILED,
                        f"{nbytes / 1e6:.0f}MB read and no in-scope CVE id found; "
                        "if this is a distro ecosystem its ids are in `upstream` "
                        "or `related`, which this adapter does not read",
                        rows=0)
            print(f"  [osv:{eco}] FAILED: 0 in-scope ids from "
                  f"{nbytes / 1e6:.0f}MB", file=sys.stderr)
        else:
            record_feed(f"osv:{eco}", True, detail, rows=len(found))
            print(f"  [osv:{eco}] +{added} (of {len(found)} in scope)", file=sys.stderr)
    return out


def _date_year(s):
    try:
        return int(str(s)[:4])
    except (ValueError, TypeError):
        return None


def feed_msrc(years):
    """Microsoft MSRC CVRF API: monthly Patch-Tuesday docs. Microsoft is its own
    CNA, so an RBP here is self-disclosure (the stronger §4.5.1.4 MUST). Also bundles
    Azure Linux/Mariner CVEs, adding breadth."""
    try:
        idx, _, _ = _get("https://api.msrc.microsoft.com/cvrf/v3.0/updates",
                         timeout=40, headers={"Accept": "application/json"})
    except Exception as e:
        print(f"  [msrc] index skip: {e}", file=sys.stderr)
        return []
    months = [(u["ID"], u["CvrfUrl"], _d(u.get("InitialReleaseDate")))
              for u in (idx or {}).get("value", [])
              if len(u.get("ID", "")) == 8 and _date_year(u.get("InitialReleaseDate")) in years
              and u.get("CvrfUrl")]

    def _month(item):
        mid, url, mdate = item
        try:
            doc, _, _ = _get(url, timeout=90, headers={"Accept": "application/json"})
        except Exception as e:
            print(f"  [msrc] skip {mid}: {e}", file=sys.stderr)
            return []
        rows = []
        for v in (doc or {}).get("Vulnerability", []):
            cid = v.get("CVE", "")
            if not cid or _year(cid) not in years:
                continue
            title = v.get("Title")
            title = title.get("Value", "") if isinstance(title, dict) else (title or "")
            vdate = _d(v.get("ReleaseDate"))
            pub = vdate if _date_year(vdate) and _date_year(vdate) >= 2000 else mdate  # skip 0001 placeholder
            rows.append({"cve_id": cid, "source": "msrc", "source_ref": f"msrc:{mid}",
                         "public_date": pub, "product": "", "description": title[:400]})
        return rows

    out, seen = [], set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as ex:
        for rows in ex.map(_month, months):
            for r in rows:
                if r["cve_id"] not in seen:
                    seen.add(r["cve_id"])
                    out.append(r)
    return out


CSAF_PROVIDERS = (
    "https://cert-portal.siemens.com/productcert/csaf/provider-metadata.json",   # Siemens (ICS CNA)
    "https://www.cisa.gov/sites/default/files/csaf/provider-metadata.json",       # CISA (ICS)
    # SICK IS DELETED FROM HERE, NOT MISSING. The BSI aggregator supplies
    # `www.sick.com` and this line configured `sick.com`; `_expand_csaf_providers`
    # dedupes on the exact URL string, so both were read and the same publisher
    # occupied two provider slots.
    #
    # It cost two rows on a public page with contradictory numbers, 120 duplicate
    # advisory fetches every run, and a "17 providers" count for sixteen
    # publishers. The site still reads SICK, through the aggregator.
    #
    # This also retires the host-canonicalisation idea, which would have renamed
    # every parts key at once and given the shrink guard a one-run blind spot
    # across all seventeen providers to fix one duplicate.
    #
    # RECORDED DISSENT, because it is a fair point: deleting a deliberate config
    # line moves a chosen provider onto the aggregator path, which no scorecard
    # has assessed. That is an argument for reviewing the aggregator-discovered
    # providers, not for keeping a duplicate.
    # Not listed by any aggregator we read, found by probing .well-known. Both
    # are high-volume CNAs in their own right.
    "https://www.cisco.com/.well-known/csaf/provider-metadata.json",              # Cisco PSIRT
    "https://www.suse.com/.well-known/csaf/provider-metadata.json",               # SUSE
)

# CLOSED, DO NOT RE-PROBE: Huawei. It is reachable and unreadable, which is not
# the same as absent and reads exactly like a provider nobody has tried yet.
#
# `www.huawei.com` serves valid provider metadata at the well-known path, listing
# 121 distributions, one directory per advisory. Every one of those directories
# answers 401 Unauthorized, `changes.csv` and `index.txt` alike; the `/clear` root
# exists and is empty. So Huawei publishes a CSAF catalogue no unauthenticated
# client can read. Measured twice: `feedlab probe-csaf` on 2026-08-24 (recorded in
# feedlab/_csaf_probe.json) and live at +0 on the same run.
#
# It is the single largest CNA the gate cannot see that serves CSAF at all
# (444 published CVEs in the window), so it will keep looking like the obvious
# next win to anyone reading the top-50 miss list. It is not one. The cost of
# rediscovering this is a `probe-csaf` run and an afternoon.
#
# The related warning was ALSO wrong and is fixed: "capped: www.huawei.com
# 12/121 directories" asserted a loss of 109 directories of advisories that do
# not exist. The cap is now claimed only where the provider had readable
# advisories, which is why that line disappeared from the health string on
# 2026-08-27 while Huawei stayed in "no advisories in scope". That is the fix
# landing, not a regression.

# CSAF aggregators list many vendors' provider-metadata URLs in one file, one fetch
# unlocks N vendors (Red Hat, Nozomi, Stackable, KUNBUS, ...).
CSAF_AGGREGATORS = (
    "https://wid.cert-bund.de/.well-known/csaf-aggregator/aggregator.json",       # BSI CERT-Bund
)

# Provider metadata we can still act on when the canonical host refuses us.
#
# www.cisa.gov answers 403 to the GitHub Actions runners and 200 to a developer
# laptop, with the SAME User-Agent, from the same code. That is the hosting edge
# filtering cloud egress, not anything we send, so no header change reaches it
# and the Cisco fix above does nothing here. Two 403s on one health line, two
# unrelated causes.
#
# These feed URLs are not invented and they are not a third-party mirror. They
# are the ROLIE feeds CISA's own provider-metadata.json designates, read from
# the canonical document on 2026-08-26, served from CISA's own GitHub
# organisation, which the runners do reach. The canonical URL is still fetched
# first on EVERY run, so the day CISA stops blocking the runners this pinned
# copy stops being consulted, without a commit.
#
# Pinning is asserted config in a codebase that prefers derived, so the fallback
# announces itself in the health detail every time it fires. Silent is the only
# unacceptable option; asserted-and-named is a trade we can defend.
CSAF_METADATA_FALLBACK = {
    "https://www.cisa.gov/sites/default/files/csaf/provider-metadata.json": {
        "canonical_url": "https://www.cisa.gov/sites/default/files/csaf/provider-metadata.json",
        "publisher": {"category": "coordinator", "name": "CISA",
                      "namespace": "https://www.cisa.gov/"},
        "role": "csaf_trusted_provider",
        "distributions": [{"rolie": {"feeds": [
            {"summary": "TLP:WHITE CISA OT Advisories", "tlp_label": "WHITE",
             "url": "https://raw.githubusercontent.com/cisagov/CSAF/develop/"
                    "csaf_files/OT/white/cisa-csaf-ot-feed-tlp-white.json"},
            {"summary": "TLP:WHITE CISA IT Advisories", "tlp_label": "WHITE",
             "url": "https://raw.githubusercontent.com/cisagov/CSAF/develop/"
                    "csaf_files/IT/white/cisa-csaf-it-feed-tlp-white.json"},
        ]}}],
    },
}

# Cap on directory distributions consulted per provider. Some providers list one
# directory per advisory rather than one root (Huawei lists 117), and without a
# cap a single provider dominates the run.
CSAF_MAX_DIRS = 12

# How long one CSAF provider may hold the run, in seconds.
#
# THE 2026-08-29 OUTAGE, and it is the reason this exists. The scheduled build
# was cancelled at the 45-minute ceiling, and the log names the cause exactly:
#
#   17:11:23  [csaf] www.huawei.com: +0 new (0 in scope)
#   17:29:24  [csaf] www.open-xchange.com: +0 new (0 in scope)
#   17:29:43  ##[error]The operation was canceled.
#
# Eighteen minutes inside ONE provider, which then returned nothing. Every other
# provider that run finished in about eleven seconds, the slowest legitimate one
# (wid.cert-bund.de) in twenty. The same host answers in under a second from a
# laptop and yields 15 advisories, so this is the host stalling GitHub's egress,
# the same shape as CISA's 403 to the runners, arriving as latency instead of a
# status code. `_get` retries three times at a 90-second timeout, so a handful of
# stalled URLs is a quarter of an hour with nothing to show.
#
# SET TO 300s ON 2026-08-29, when the COUNT cap was removed and the read cursor
# replaced it. Sized against the real job rather than picked:
#
#   measured cold run, 45s budget:  10,838 ids in 332s, 13 of 17 caught up
#   at 300s the four large providers read ~6.7x that each, and csaf costs
#   4 x 300s + ~60s for the other thirteen = ~21 min
#   `ubuntu-osv` joined on 2026-08-31 and adds ~35s to that ~60s, measured
#   the rest of the pipeline measured 31.3 min on the 2026-08-29 build
#   total ~52 min, which is why timeout-minutes goes 45 -> 60 in deploy.yml
#
# CATCH-UP TIME, which is the number this budget actually buys, at four runs
# a day from the cold state measured above:
#
#   www.cisa.gov                 caught up in under a day
#   security.access.redhat.com   ~1 day
#   wid.cert-bund.de             ~2 days
#   www.suse.com                 ~8 days
#
# After that the budget never fires again: a caught-up provider reads only what
# changed, which on SUSE was six advisories in 24 hours against 83,111 listed.
# This is a limit on how fast the backlog drains, not on what the site can see. Those are one
# change: the budget is now the only thing bounding a provider, so it has to be
# large enough to be worth reading and small enough that seventeen of them fit.
#
# Measured, not guessed. Read rates per provider, 10 workers: siemens 65/s,
# cisa 51/s, redhat 32/s, cisco 22/s, cert-bund 16/s, suse 10/s. At 600s that
# is roughly 19,000 advisories from Red Hat, 9,600 from CERT-Bund and 6,000
# from SUSE, against 120 from each of them before.
#
# What that buys, measured against the 358 rows an uncapped sweep found on
# 2026-08-29 that the site does not have:
#
#   cap    120 ->  42 rows (12%)     what the site did
#   cap  1,000 -> 117 rows (33%)
#   cap  5,000 -> 247 rows (69%)
#   cap 10,000 -> 342 rows (96%)
#
# Only three providers are big enough to spend the whole budget; the other
# fourteen finish in seconds and are read IN FULL, which is what removing the
# count cap means for them.
#
# THE BUDGET GUARDS THE LISTING PHASE TOO, which is where those minutes went.
# A budget that only wrapped the advisory fetch would not have caught this at
# all: open-xchange never reached the advisory fetch.
#
# This is a configured limit in exactly the sense the Ubuntu wall-clock budget
# and the advisory cap are, so it is reported the same way: CAPPED, named, with
# the number, and not a degradation.
CSAF_PROVIDER_BUDGET_S = 300

# What each provider has seen, and where it got to.
#
# WHY THIS EXISTS: the reader was stateless and re-fetched every provider's whole
# catalogue every six hours, so something had to cap it. Measured on SUSE
# 2026-08-29: 83,111 in-window advisories, of which SIX changed in 24 hours and
# ZERO in 6. Re-reading 83,105 unchanged documents to find six is the problem a
# cap was papering over.
#
# THREE THINGS PER PROVIDER, and the third is the one that matters most:
#
#   newest_read   everything at or below this has been read at least once
#   oldest_read   ... down to here. The window between them is CONTIGUOUS.
#   refs          every CVE reference this provider has EVER given us.
#
# `refs` is not an optimisation, it is a correctness requirement, and leaving it
# out shipped a silent shrink to the live site on 2026-08-29. `gather` builds the
# reference set from what each adapter RETURNS on the current run and keeps no
# memory of its own, so a provider that correctly reads nothing because it is
# caught up also contributes nothing. Within one run of the cache restoring,
# twelve of seventeen providers reported "+0 new (0 in scope)", every word true,
# and the list fell 1,769 -> 1,760 while all eight CISA rows, SUSE's and
# Schneider's vanished and CERT-Bund's fell 112 -> 59. /status published
# "csaf:www.cisa.gov  OK  0 ids  caught up across all 1,833 advisories", an
# accurate sentence about a provider whose rows had just been erased.
#
# So: FETCHING is incremental, RETURNING never is. A provider emits everything it
# knows on every run whether it fetched anything or not, and `refs` is pruned to
# the year window so it cannot grow without bound as that window rolls.
#
# Fresh advisories are read oldest-first and backfill newest-first, so both marks
# advance contiguously and a budget stop truncates the walk rather than leaving a
# hole. Nothing is skipped, only deferred, and /status says how far behind each
# provider still is.
#
# Same shape as data/ghsa_repos_state.json, cached by deploy.yml.
#
# THIS IS WHAT MAKES THE CAPS UNNECESSARY, and it is the answer to "why is there
# a time box at all". There was a time box because the reader was stateless: it
# threw away everything it learned and re-fetched the whole catalogue every six
# hours, so something had to stop it. Measured on SUSE 2026-08-29: 83,111
# in-window advisories, of which SIX changed in the last 24 hours and ZERO in the
# last 6. Re-reading 83,105 unchanged documents to find 6 is the entire problem.
#
# Two marks per provider, and the pair is what makes a budget stop safe:
#
#   newest_read   everything at or below this has been read at least once
#   oldest_read   ... down to here. The window [oldest_read, newest_read] is
#                 CONTIGUOUS, which is the whole invariant.
#
# Fresh advisories (ts > newest_read) are read OLDEST-FIRST so newest_read walks
# up without leaving a hole. Backfill (ts < oldest_read) is read NEWEST-FIRST so
# oldest_read walks down without leaving one. A budget stop in either direction
# truncates the walk and the mark simply stops where the reading stopped, so the
# next run resumes exactly there. Nothing is ever skipped, only deferred, and
# /status says how far behind each provider still is.
#
# A revised advisory gets a NEWER timestamp, so it rises above newest_read and is
# re-read on the next run. That is correct and free.
#
# Same shape as data/ghsa_repos_state.json, which has done this for the repo
# poller since it was written, cached by .github/workflows/deploy.yml.
CSAF_STATE = os.path.join(os.path.dirname(_HERE), "data", "csaf_state.json")


# 1: read marks only.
# 2: adds `refs`, the references each provider has seen.
# 3: forced discard. Version 2 was written by a run that had itself restored a
#    version-1 cache, so it saved marks claiming "caught up" beside a `refs` that
#    was nearly empty. The per-provider "no refs key means cold start" guard
#    could not see that: the key was present, it was just wrong. The damaged
#    state then re-saved itself every run and CISA sat at 3 rows instead of 13
#    across two deploys.
CSAF_STATE_VERSION = 3


def _csaf_state_load(path=None):
    """Per-provider read marks. A missing or corrupt file is a cold start, not
    an error: cold start means read from the top and backfill from there."""
    try:
        d = json.load(open(path or CSAF_STATE))
        if not isinstance(d, dict):
            return {}
        # THE STAMP IS CHECKED, NOT JUST WRITTEN, and not checking it is what
        # let a damaged cache outlive the fix for it.
        #
        # A version stamp nothing reads is decoration. The previous change wrote
        # this field and then loaded the file regardless, so a state saved by a
        # broken run was restored by the run that fixed the bug, re-saved, and
        # carried forward again. Two deploys with CISA at 3 rows instead of 13
        # while cisagov/CSAF#466 was open and pointing at them.
        #
        # Discarding the whole file costs one cold start, which is a few minutes
        # of re-reading and no lost rows, because a provider always RETURNS
        # everything it knows and a cold provider simply knows it from this run.
        # Trusting an unrecognised state costs a silent shrink.
        if d.get("_version") != CSAF_STATE_VERSION:
            print(f"  [csaf] read marks are version {d.get('_version')!r}, "
                  f"expected {CSAF_STATE_VERSION}; starting cold",
                  file=sys.stderr)
            return {}
        return {k: v for k, v in d.items() if not k.startswith("_")}
    except (OSError, ValueError):
        return {}


def _csaf_state_save(state, path=None):
    # Stamped, so the NEXT shape change is a discard rather than a shrink. The
    # per-provider `refs` check above is the actual guard; this makes a future
    # migration visible to anyone reading the file.
    path = path or CSAF_STATE
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as fh:
            json.dump(dict(state, _version=CSAF_STATE_VERSION), fh,
                      indent=1, sort_keys=True)
    except OSError as e:
        # Never fail a run over the cursor. A lost cursor costs re-reading, which
        # is exactly the behaviour that existed before it.
        print(f"  [csaf] could not save read marks: {e}", file=sys.stderr)


def _csaf_plan(entries, newest_read, oldest_read):
    """What to read this run, in the order that keeps both marks contiguous.

    `entries` is [(ts, url)], any order. Returns (todo, fresh_n, backfill_n).

    Cold start reads newest-first, because on a provider nobody has read the
    recent advisories are the ones most likely to hold a reserved id.
    """
    if not newest_read:
        return sorted(entries, reverse=True), len(entries), 0
    fresh = sorted((e for e in entries if e[0] > newest_read))          # ascending
    older = sorted((e for e in entries if e[0] < oldest_read), reverse=True)
    return fresh + older, len(fresh), len(older)


_CSAF_YEAR_SEG = re.compile(r"^(19|20)\d{2}$")


def _csaf_path_year_in_scope(path, years):
    """False only when the advisory's own path names a year older than the window.

    `changes.csv` timestamps are LAST-MODIFIED, not published, and directory
    listings file an advisory under the year it was published. Cisco's most
    recently touched advisory sits in its **2021** directory: a routine revision
    to a five-year-old advisory, carrying five-year-old CVE ids.

    Sorting on the timestamp alone therefore spends the whole per-provider cap on
    revisions of old advisories. Measured against the live providers, same cap of
    120: Cisco yields 73 in-scope CVEs on timestamp order and **194** once the
    path year is honoured, Red Hat 242 and **261**. The cap is the scarce
    resource here, and this decides what it is spent on.

    A path carrying no year segment is kept. This narrows a selection that is
    already too broad; it never invents a reason to drop something.
    """
    segs = [s for s in path.split("/") if _CSAF_YEAR_SEG.match(s)]
    # Same rule as the timestamp filter above it: older than the window is out,
    # anything else stays, so the two cannot disagree about the same advisory.
    return not segs or any(int(s) >= min(years) for s in segs)


def _csaf_directory_entries(directory_url, years):
    """Recent advisory URLs from a CSAF *directory* distribution.

    The spec allows two distribution shapes and this adapter originally handled
    only one. ROLIE feeds are JSON and were supported; directory distributions
    are a plain listing and were not, so every provider using them yielded
    nothing. Red Hat, Huawei and Schneider Electric are all directory-only, which
    is why Red Hat, one of the largest publishers, contributed zero.

    `changes.csv` is preferred: it carries timestamps, so a recency cap is
    meaningful. `index.txt` is the fallback, and carries no dates, so it is
    filtered on the year in the file path instead.

    THERE IS NO CAP HERE. This returns every in-scope entry the listing holds.

    It used to take one, defaulted to None, and no production caller ever passed
    it. The docstring justified keeping it on the grounds that "another caller"
    might want it and that "the tests that pin its behaviour are pinning real
    behaviour", which was circular: those tests were the only thing exercising
    it. Deleted once `feed_csaf`'s own cap gained a test that drives it end to
    end and asserts which advisories were actually requested.

    A per-directory cap here would be invisible to the caller anyway: it returns
    N entries whether the provider listed N or 83,091, so the one number needed
    to say how much of a provider was read is destroyed before anything can
    report it. The listing is downloaded and parsed either way, so returning all
    of it costs a list rather than a fetch, and `feed_csaf` caps ONCE, where it
    knows what it is cutting and publishes the cut.

    DO NOT reintroduce an early `break` here. This loop used to stop at the
    first out-of-window row, on the assumption that changes.csv is newest-first.
    SUSE's is not: its first row is dated 2024-08-21, so the loop exited on line
    ONE of 41,038 and the provider returned nothing. 14,486 in-scope advisories
    were dropped, and the health line reported it as "no advisories in scope",
    which is the silent shrink this adapter exists to prevent, dressed up as a
    fact about SUSE. The file is not reliably sorted in either direction either:
    SUSE's LAST row is dated 2014. So every row is read, filtered, and sorted.

    The break also saved nothing. `_get_text` has already downloaded the whole
    listing by the time the first line is parsed, so stopping early spared some
    string splitting and no bytes at all.
    """
    base = directory_url.rstrip("/")
    try:
        raw = _get_text(f"{base}/changes.csv", timeout=90)
        out = []
        for line in raw.splitlines():
            parts = [x.strip().strip('"') for x in line.split(",", 1)]
            if len(parts) != 2:
                continue
            path, ts = parts
            year = _date_year(ts)
            if year is not None and year < min(years):
                continue
            if not _csaf_path_year_in_scope(path, years):
                continue
            out.append((ts, f"{base}/{path.lstrip('/')}"))
        if out:
            # Newest first whatever order the provider wrote the file in, so
            # `feed_csaf`'s cap keeps the most recent when it cuts.
            out.sort(reverse=True)
            return out
    except Exception:
        pass
    try:
        raw = _get_text(f"{base}/index.txt", timeout=90)
    except Exception:
        return []
    wanted = {str(y) for y in years}
    paths = [p.strip() for p in raw.splitlines() if p.strip()]
    # No timestamps here, so select on the year segment of the path and take the
    # tail, which these listings order oldest-first.
    keep = [p for p in paths if any(seg in wanted for seg in p.split("/"))]
    # UNDATED, and that matters once the caller sorts. index.txt carries no
    # timestamps, so these tuples sort below every dated entry and would be cut
    # first by a cap claiming to keep the newest. The listing order is the only
    # recency signal there is here, and it is preserved rather than relied upon:
    # no configured provider is index.txt-only today, and one that appeared
    # would need its own handling rather than an implicit tail slice.
    return [("", f"{base}/{p.lstrip('/')}") for p in keep]


def _csaf_directories(meta, max_dirs):
    """Directory URLs from provider metadata, de-duplicated and de-noised.

    Some providers list a directory per advisory rather than one root. Huawei
    publishes 117, half of them `/zh` language duplicates of the `/en` ones, so
    the language variants are dropped and the shortest paths are preferred on
    the assumption that a root listing covers its children.
    """
    urls = []
    for dist in (meta or {}).get("distributions", []):
        u = dist.get("directory_url")
        if u:
            urls.append(u.rstrip("/"))
    urls = [u for u in urls if not u.endswith("/zh")]
    urls.sort(key=len)
    out, seen = [], []
    for u in urls:
        if any(u.startswith(prefix + "/") for prefix in seen):
            continue           # already covered by a shorter root
        seen.append(u)
        out.append(u)
        if len(out) >= max_dirs:
            break
    return out


def _expand_csaf_providers(providers, aggregators, max_providers):
    """Return a de-duped, capped list of provider-metadata URLs, expanding any
    aggregator.json into its csaf_providers[].metadata.url entries."""
    urls, seen = list(providers), set(providers)
    for agg in aggregators:
        try:
            data, _, _ = _get(agg, timeout=40)
        except Exception as e:
            print(f"  [csaf] aggregator skip {agg}: {e}", file=sys.stderr)
            continue
        for p in (data or {}).get("csaf_providers", []):
            u = (p.get("metadata") or {}).get("url")
            if u and u not in seen:
                seen.add(u)
                urls.append(u)
    if len(urls) > max_providers:
        print(f"  [csaf] {len(urls)} providers discovered; capping at {max_providers}",
              file=sys.stderr)
    return urls[:max_providers]


def feed_csaf(years, providers=CSAF_PROVIDERS, aggregators=CSAF_AGGREGATORS,
              cap_per_provider=None, max_providers=40, workers=8,
              per_provider_budget_s=CSAF_PROVIDER_BUDGET_S,
              state_path=None, incremental=True):
    """Generic CSAF/ROLIE ingester: unlocks vendor/enterprise/ICS CNAs. Expands
    aggregators into providers, then for each provider: metadata -> ROLIE feed(s)
    -> recent advisory docs -> CVEs in scope.

    THERE IS NO COUNT CAP. `cap_per_provider` defaults to None and the only bound
    on a provider is CSAF_PROVIDER_BUDGET_S, its share of the run's wall clock.

    The count cap was 120 and it was the wrong unit. A fixed count reads 100% of
    a small provider and 0.1% of a large one while reporting both identically,
    and its cost in TIME swings with the host: the same 120 advisories took 0.4s
    from Siemens and 12s from SUSE. Time is what the job actually runs out of, so
    time is what a provider is now given, and a provider that spends it says so
    on /status with the numbers.

    Fourteen of the seventeen configured providers are small enough to be read in
    full inside the budget. Three are not, and SUSE at 83,111 in-window advisories
    cannot be read in full by any schedule this project can run: at a measured
    10/s that is 138 minutes for one provider. Reading it whole needs an
    incremental cursor, not a bigger number, which is what CSAF_STATE is."""
    out, seen = [], set()
    # Per-provider outcomes, so the aggregate this adapter reports is derived
    # rather than asserted. `feed_csaf` recorded NO health at all: `gather` filled
    # in `ok, N ids` whatever happened underneath, so a provider answering 401 on
    # every advisory, a provider behind a WAF returning 403, and a provider whose
    # 120 directories were cut to 12 all reported identically to a clean read.
    # That is the silent-shrink signature on the one adapter that fans out to
    # more than a dozen third parties.
    unreachable, empty, capped_dirs, fell_back = [], [], [], []
    # Providers that ran out of wall clock. See CSAF_PROVIDER_BUDGET_S.
    over_budget = []
    # How far behind each provider still is, in advisories. This is the
    # number the cap never had: not 'we read 120' but 'N remain unread, and
    # they will be read on subsequent runs'.
    behind = []
    state = _csaf_state_load(state_path) if incremental else {}
    # The ADVISORY cap, which is a different loss from `capped_dirs` and was
    # the one nothing measured. `capped_dirs` counts directories we declined to
    # consult; this counts advisories we listed, could have read, and cut.
    capped_reads = []
    all_providers = _expand_csaf_providers(providers, aggregators, max_providers)
    print(f"  [csaf] {len(all_providers)} providers (incl. aggregator-discovered)", file=sys.stderr)
    for meta_url in all_providers:
        host = meta_url.split("/")[2]
        # ONE CLOCK PER PROVIDER, started before the first byte is requested,
        # because the 18 minutes that killed the 2026-08-29 run were spent in
        # the LISTING phase, not the advisory phase.
        t_provider = time.time()

        def _out_of_budget():
            return time.time() - t_provider > per_provider_budget_s
        try:
            meta, _, _ = _get(meta_url, timeout=40)
        except Exception as e:
            meta = CSAF_METADATA_FALLBACK.get(meta_url)
            if meta is None:
                print(f"  [csaf] {meta_url}: metadata skip ({e})", file=sys.stderr)
                unreachable.append(f"{host} ({str(e)[:40]})")
                # RECORDED HERE, NOT ONLY AT THE BOTTOM OF THE LOOP. This branch
                # `continue`s, so the first version of the per-provider records
                # gave no part at all to the one provider worth tracking most.
                # `compare_magnitudes` iterates the CURRENT parts, so a provider
                # that vanishes from the dict is not compared against anything:
                # a provider going from 500 rows to unreachable would have been
                # invisible to the guard this change exists to feed. Caught by
                # `test_an_unreachable_csaf_provider_never_escalates_the_parent`,
                # which was written for the status coupling and found this
                # instead. CAPPED for the reason given at the other call site,
                # and `accounted` for the reason given there too: CAPPED keeps
                # the banner quiet, and the mark is what stops `verify` reading
                # this zero as a silent shrink and blocking the deploy.
                record_feed(f"csaf:{host}", CAPPED,
                            f"provider unreachable: {str(e)[:60]}", rows=0,
                            accounted="provider unreachable this run")
                continue
            # Reached, just not by the front door. The provider is NOT recorded
            # as unreachable, because we are about to read every advisory it
            # publishes; recording it as lost would be as wrong as staying quiet.
            print(f"  [csaf] {meta_url}: metadata unreachable ({e}); "
                  f"using pinned feeds", file=sys.stderr)
            fell_back.append(host)
        feed_urls = []
        for dist in (meta or {}).get("distributions", []):
            for f in (dist.get("rolie", {}) or {}).get("feeds", []):
                if f.get("url"):
                    feed_urls.append(f["url"])
        entries = []
        # Directory distributions, the half of the spec this adapter used to skip.
        available = _csaf_directory_count(meta)
        chosen = _csaf_directories(meta, max_dirs=CSAF_MAX_DIRS)
        # The cap is NOT reported here. Huawei publishes 121 directories and
        # every one of them answers 204 No Content, so "capped 12/121" asserted a
        # loss of 109 directories' worth of advisories that do not exist. A
        # standing warning naming a loss nobody can find is the furniture problem
        # again. The claim is deferred to after the fetch, where we know whether
        # the directories we DID read had anything in them.
        for durl in chosen:
            if _out_of_budget():
                break
            entries.extend(_csaf_directory_entries(durl, years))
        for furl in feed_urls:
            if _out_of_budget():
                break
            try:
                fd, _, _ = _get(furl, timeout=90)
            except Exception:
                continue
            for e in (fd or {}).get("feed", {}).get("entry", []):
                upd = e.get("updated", "") or e.get("published", "")
                if _date_year(upd) is not None and _date_year(upd) < min(years):
                    continue
                href = next((ln["href"] for ln in e.get("link", [])
                             if ln.get("rel") == "self"), None)
                if href:
                    entries.append((upd, href))
        # WHAT TO READ THIS RUN, which since 2026-08-29 is "what changed"
        # rather than "the newest 120". See CSAF_STATE.
        st = (state.get(host) or {}) if incremental else {}
        # A STATE FROM AN OLDER SHAPE IS A COLD START, NOT A CAUGHT-UP PROVIDER.
        #
        # THE SECOND SHRINK, 2026-08-30. The first version of this cursor stored
        # only the read marks. When `refs` was added, the deploy cache still held
        # the old shape, so every provider restored marks that said "caught up"
        # beside a `refs` that did not exist. `known` came back empty, the plan
        # fetched almost nothing because the marks said there was nothing new,
        # and the provider emitted almost nothing.
        #
        # Live effect within one run: CISA fell 13 rows -> 3, and the three ids
        # cited in cisagov/CSAF#466 came off the site while that issue was open
        # and linking to them.
        #
        # The marks are only meaningful ALONGSIDE the refs they were advanced
        # over. A state carrying one without the other is not a partial state, it
        # is a false one, and the safe reading is that this provider has never
        # been read.
        if incremental and "refs" not in st:
            st = {}
        listed = len(entries)
        if incremental:
            entries, n_fresh, n_older = _csaf_plan(
                entries, st.get("newest_read") or "", st.get("oldest_read") or "")
        else:
            entries, n_fresh, n_older = sorted(entries, reverse=True), listed, 0
        # BEFORE THE CUT, because after it the number is gone, and that is the
        # only part of this that does not go stale: a flat cap is invisible to a
        # guard that only ever asks whether a number went DOWN, so the loss has
        # to be measured here or it cannot be reported at all.
        #
        # The six-provider table that used to sit here was a one-day measurement
        # against a cap that no longer exists, restated verbatim in NEXT.md and
        # in the commit that removed the cap. Those are dated; a comment is not.
        # `planned` is what the cursor decided to read; `entries` after this
        # slice is what a count cap (if a caller set one) allows.
        #
        # THE COUNT CAP MUST BE MEASURED AGAINST THE PLAN, NOT THE LISTING. It
        # was measured against the listing, and the moment the cursor landed a
        # fully caught-up provider with nothing to do reported CAPPED, "read the
        # newest 0 of 20 advisories", because the plan was legitimately empty.
        # A provider that is up to date is the healthiest state there is and it
        # was publishing the loudest warning on the page.
        planned = len(entries)
        entries = entries[:cap_per_provider]
        cap_cut = planned - len(entries)

        def _fetch(item):
            upd, href = item
            # Checked per item rather than once: the pool has up to
            # `cap_per_provider` items queued and a stalling host makes each one
            # slow, so the budget has to be able to stop the queue draining.
            if _out_of_budget():
                return None          # NOT [], see below
            try:
                d, _, _ = _get(href, timeout=40)
            except Exception:
                return []
            doc = (d or {}).get("document", {})
            pub = (doc.get("publisher", {}) or {}).get("name", "")
            tr = doc.get("tracking", {}) or {}
            tid = tr.get("id", "")
            rows = []
            for v in (d or {}).get("vulnerabilities", []):
                cid = v.get("cve", "")
                # PER ID, not per advisory. See csaf_id_date.
                rel = csaf_id_date(cid, tr, upd)
                if cid and _year(cid) in years:
                    # source_ref carries publisher, tracking id AND the advisory
                    # URL. Without the URL, report._u had no csaf branch to write
                    # and every CSAF row fell through to
                    # cve.org/CVERecord?id=<id>, which renders NOTHING for a
                    # RESERVED ID: the row's only evidence link disproved it.
                    # The publisher is separated by a tab so a name containing a
                    # colon ("Foo Inc.: PSIRT") cannot corrupt the split.
                    rows.append({"cve_id": cid, "source": "csaf",
                                 "source_ref": f"{pub}\t{tid}\t{href}",
                                 "public_date": _d(rel),
                                 "product": "", "description": (v.get("title") or doc.get("title") or "")[:400]})
            return rows

        n0, fetched_n, done_n = len(out), 0, 0
        # THE STATE CARRIES THE REFERENCES, NOT JUST THE POSITION, and that is
        # the whole difference between this and the version that shrank the site.
        #
        # `gather` builds the reference set from what each adapter RETURNS on the
        # current run. It keeps no memory of its own. So a cursor that remembers
        # only where it got to makes a caught-up provider return nothing, and
        # every id whose only evidence was that provider drops off the site.
        # That shipped on 2026-08-29 and took CISA, SUSE and Schneider off the
        # list within one run, each reporting "0 ids in scope, caught up", every
        # word of it true.
        #
        # So a provider accumulates what it has seen, and returns ALL of it every
        # run whether it fetched anything or not. Fetching is incremental;
        # returning never is.
        known = dict(st.get("refs") or {})
        # `None` means the budget stopped us before the fetch; `[]` means we read
        # the advisory and it carried no in-scope CVE. Collapsing the two would
        # advance the read marks over documents nobody looked at, which is the
        # one way this cursor could silently lose an advisory forever.
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
            for item, rows in zip(entries, ex.map(_fetch, entries)):
                if rows is None:
                    continue
                done_n += 1
                ts = item[0]
                if ts:
                    # Both marks move only over what was actually read, and the
                    # plan's ordering (fresh ascending, backfill descending)
                    # keeps the window contiguous when the budget truncates.
                    if not st.get("newest_read") or ts > st["newest_read"]:
                        st["newest_read"] = ts
                    if not st.get("oldest_read") or ts < st["oldest_read"]:
                        st["oldest_read"] = ts
                fetched_n += len(rows)
                for r in rows:
                    known[r["cve_id"]] = [r["source_ref"], r["public_date"],
                                          r["description"]]
        # PRUNED TO THE WINDOW, so the state cannot grow without bound as the
        # year window rolls. An id that leaves the window leaves the state.
        known = {k: v for k, v in known.items() if _year(k) in years}

        # Emitted from what the provider KNOWS, not from what it just fetched.
        # The cross-provider `seen` dedupe still applies here, so a shared id is
        # still credited once, but each provider carries its own copy and a
        # provider losing a race no longer loses the id from its own state.
        for cid, ref in sorted(known.items()):
            if cid not in seen:
                seen.add(cid)
                out.append({"cve_id": cid, "source": "csaf", "source_ref": ref[0],
                            "public_date": ref[1], "product": "",
                            "description": ref[2]})
        read = len(known)
        gained = len(out) - n0
        unread = max(0, len(entries) - done_n)
        if incremental:
            st["refs"] = known
            st["listed"] = listed
            st["behind"] = unread
            state[host] = st
            if unread:
                behind.append(f"{host} {unread:,}")
        spent = time.time() - t_provider
        print(f"  [csaf] {host}: +{gained} new ({read} in scope)", file=sys.stderr)
        # ONE RECORD PER PROVIDER, so `compare_magnitudes` can see a provider go
        # dark. Until this landed, 17 providers shared a single `rows` number and
        # this adapter's own docstring pointed at the shrink guard as the
        # mechanism for "a provider that was working and stops", which that guard
        # could not do: it compares whole feeds, and csaf's whole-feed total swung
        # 3,296 -> 3,202 -> 3,938 -> 2,213 -> 2,695 across five published runs, so
        # any provider holding under 40% of the total could stop forever inside
        # the noise. `feed_osv` has recorded per-ecosystem parts all along; this is
        # the same shape for the adapter that fans out to more third parties than
        # any other. SUSE is the worked example: 14,486 in-scope advisories lost,
        # absorbed by the aggregate, published as a fact about SUSE.
        #
        # `read`, NOT `gained`, for the reason the comment below already gives:
        # `gained` is measured against a `seen` set shared across providers, so it
        # depends on the order providers are visited and would fire this guard
        # every time an earlier provider happened to carry the same advisory.
        #
        # STATUS IS OK FOR EVERY REACHABLE PROVIDER WE READ IN FULL, including
        # one with nothing to say, and it is CAPPED for one we did not.
        #
        # The rule used to be "OK for every reachable provider" without the second
        # half, and the second half is the entire disclosure: a provider read at
        # 0.1% published the same `ok` as a provider read whole.
        #
        # The banner argument that produced the original rule still holds, and it
        # is why this is CAPPED rather than TRUNCATED. `health_detail` escalates a
        # still-OK parent to the worst of its parts, and the worst a cap can make
        # it is CAPPED; `degraded_state` folds TRUNCATED into "this run is
        # incomplete" and deliberately does not fold CAPPED, because a standing
        # limit fires every run by design. So naming the cap costs no banner.
        #
        # A QUIET VENDOR IS STILL OK. `read == 0` is not a cap and must not
        # borrow the word: it means the provider had nothing in the window, which
        # is a fact about the provider, where a cap is a fact about us.
        #
        # An unreachable provider is recorded CAPPED, NOT FAILED, and the
        # difference is the whole banner argument. `health_summary` collects
        # FAILED across every entry INCLUDING parts, `degraded_state` turns any
        # failure into a degradation, and Cisco's edge 403s on every single run.
        # Recording it FAILED would have made `degraded` permanently true, which
        # is the exact furniture problem `degraded_state`'s docstring spends a
        # paragraph rejecting, arrived at from a new direction. CAPPED is this
        # project's existing word for a standing limit that is real, permanent,
        # and not news, and it routes to `limitations` where the parent already
        # publishes the same fact. The part is strictly better than the parent's
        # line there: it names the provider instead of truncating a list at six.
        #
        # WHAT CAPPED COSTS, AND THE MARK THAT PAYS IT. 2026-08-31: SUSE's
        # provider metadata answered with something that was not JSON for one
        # run, this branch recorded 2,732 -> 0 as CAPPED, and `verify` failed the
        # build because CAPPED is deliberately not in its `EXPLAINS_A_SHORTFALL`.
        # SUSE was serving valid JSON again within the hour. The status was
        # right and the gate was right; what was missing was any way to say "this
        # zero has a known cause" without saying it in the one word that also
        # drives the banner. That is `accounted`, and it is why both unreachable
        # branches pass it. A cap that is a CONFIGURED limit still excuses
        # nothing, which is the distinction `verify`'s comment protects.
        #
        # It also cannot escalate the parent: `_record_csaf_health` sets csaf to
        # FAILED or CAPPED whenever `unreachable` is non-empty, and
        # `health_detail`'s escalation only fires on a parent that is still OK.
        # `test_an_unreachable_csaf_provider_never_escalates_the_parent` pins that
        # coupling, because it is invisible from either function alone.
        if host in _csaf_hosts(unreachable):
            record_feed(f"csaf:{host}", CAPPED, "provider unreachable", rows=0,
                        accounted="provider unreachable this run")
        elif spent > per_provider_budget_s:
            # NAMED, because this is the failure that took the site off the air
            # for a scheduled run and nothing in the artefact said which provider
            # did it. The log had it; no page did.
            over_budget.append(f"{host} {spent:.0f}s")
            record_feed(f"csaf:{host}", CAPPED,
                        f"{read} ids in scope; read {done_n:,} advisories then "
                        f"stopped after {spent:.0f}s, over this provider's "
                        f"{per_provider_budget_s}s share of the run; "
                        f"{unread:,} still to read on later runs", rows=read)
        elif cap_cut > 0:
            capped_reads.append(f"{host} {len(entries)}/{planned:,} advisories")
            record_feed(f"csaf:{host}", CAPPED,
                        f"{read} ids in scope; read the newest {len(entries)} "
                        f"of {planned:,} advisories this run planned to read",
                        rows=read)
        else:
            # SAY WHICH KIND OF WORK THIS WAS. "12 ids in scope" is the same
            # sentence whether the provider is fully caught up and had nothing
            # new, or is 70,000 advisories behind and chewing through history.
            # Those are opposite states and a reader has to be able to tell.
            if incremental and unread:
                record_feed(f"csaf:{host}", CAPPED,
                            f"{read} ids in scope; read {done_n:,} of "
                            f"{listed:,} advisories ({n_fresh:,} new, "
                            f"{n_older:,} older); {unread:,} still to read on "
                            f"later runs", rows=read)
            else:
                # THE PINNED-FALLBACK DISCLOSURE LIVES HERE NOW. It used to be a
                # vendor name in the parent string, and moving the naming to the
                # parts would have dropped it entirely. "Pinned config that does
                # not announce itself is how a stale URL rots unnoticed" is the
                # reason it exists, and that reason is unchanged.
                via = (" via pinned feeds, its canonical metadata refused us"
                       if host in _csaf_hosts_plain(fell_back) else "")
                record_feed(f"csaf:{host}", OK,
                            f"{read} ids in scope; caught up across all "
                            f"{listed:,} advisories this provider lists{via}",
                            rows=read)
        # `gained` IS NOT PUBLISHED ANYWHERE, and the reason is twelve lines up:
        # it is measured against a `seen` set shared across every provider in the
        # run, so it depends on the ORDER providers are visited. The health
        # strings published it anyway and contradicted themselves in adjacent
        # rows on the live page: `sick.com` "114 ids in scope, 102 new" above
        # `www.sick.com` "114 ids in scope, 0 new", the same publisher reached
        # twice through a 301, the same 114 ids, two different claims about how
        # many were new. It keeps its stderr line, where a build log reader can
        # see the ordering effect for what it is.
        #
        # `read`, not `gained`. A provider contributing nothing is not an error
        # and is not nothing, but `gained` measures against a `seen` set shared
        # across every provider in the run, so a provider whose advisories an
        # EARLIER provider already contributed scored zero and was published as
        # "no advisories in scope". www.sick.com is sick.com after a 301, the
        # same host reached twice, and the second pass was reported as a vendor
        # with nothing to say. Corroboration is not emptiness.
        # CAUGHT UP IS NOT EMPTY, and this line said it was.
        #
        # `empty` was keyed on `read == 0`, which meant "this run got nothing".
        # Before the cursor that was a fair proxy for "this provider has nothing
        # in the window". After it, it is the signature of the HEALTHIEST state
        # there is: we have already read everything this provider published and
        # nothing has changed since.
        #
        # Measured immediately after the cursor landed: the parent line read
        # "no advisories in scope: advisories.stackable.tech,
        # cert-portal.siemens.com, ..." about providers whose 457 advisories had
        # all been read, and listed wid.cert-bund.de as having nothing in scope
        # on the same line that said it was 20,285 advisories behind.
        #
        # This is the sick.com lesson again, in a new form. That one is already
        # written down twenty lines up: a provider whose advisories an earlier
        # provider had supplied "was reported to readers as a vendor with nothing
        # to say. Corroboration is not emptiness." Neither is being up to date.
        #
        # So it keys on the LISTING, which is a fact about the provider, rather
        # than on this run's reading, which is a fact about us.
        if listed == 0:
            empty.append(host)
        elif available > len(chosen):
            # Now it means something: this provider had readable advisories AND
            # we consulted only some of its directories.
            capped_dirs.append(f"{host} {len(chosen)}/{available} directories")
    if incremental:
        _csaf_state_save(state, state_path)
    _record_csaf_health(all_providers, unreachable, empty, capped_dirs, fell_back,
                        len(out), capped_reads, over_budget, behind)
    return out


def csaf_id_date(cid, tracking, fallback=""):
    """When THIS id became public in THIS advisory, not when the advisory did.

    An advisory is revised, and a revision can ADD a CVE id. Dating every id in
    it from `initial_release_date` overstates the age of every id added later,
    by the whole gap.

    LIVE ON THE SITE, 2026-08-29, which is how this was found. ICSA-24-345-06
    was first published 2024-12-10 and its own revision history reads:

        rev 1  2024-12-10  Initial Publication
        rev 4  2026-06-23  Update C - Added CVE-2026-6071

    The site published CVE-2026-6071 at 627 days public. The advisory says 67.
    An overstated age on a public row about a named vendor's advisory, checkable
    by anyone in thirty seconds, is the worst error this site can make, and the
    120-advisory cap had been hiding it by never reading advisories this old.

    Two signals, both conservative, because every number here is a floor and the
    safe direction to be wrong in is younger:

    1. THE EARLIEST REVISION WHOSE SUMMARY NAMES THE ID. Publishers write "Update
       C - Added CVE-2026-6071", so the id's first appearance is at latest that
       revision. Earliest such revision, since a later one may merely be a CVSS
       correction.

    2. A CVE ID CANNOT PREDATE ITS OWN YEAR. CVE-2026-6071 cannot have been
       public in 2024 whatever any date field says. When the chosen date falls
       before the id's year, the earliest revision in or after that year is used
       instead. This catches the case where a revision added ids without listing
       them, which no summary-matching can reach.

    Falls back to `initial_release_date`, which is right for the v1 advisories
    that are most of them.
    """
    tr = tracking or {}
    revs = [r for r in (tr.get("revision_history") or []) if r.get("date")]
    initial = (tr.get("initial_release_date") or fallback or "")[:10]

    named = sorted(r["date"][:10] for r in revs
                   if cid and cid in (r.get("summary") or ""))
    if named:
        return named[0]

    year = _year(cid)
    if year is not None and initial and len(initial) >= 4:
        try:
            if int(initial[:4]) < year:
                after = sorted(r["date"][:10] for r in revs
                               if len(r["date"]) >= 4 and int(r["date"][:4]) >= year)
                if after:
                    return after[0]
                cur = (tr.get("current_release_date") or "")[:10]
                if cur:
                    return cur
        except ValueError:
            pass
    return initial


def _csaf_directory_count(meta):
    """How many directory distributions the provider actually offers.

    Counted before the cap and before the language filter, so the health line can
    say "12 of 121" rather than "12", which is the difference between a limit and
    a loss.
    """
    return len({(d.get("directory_url") or "").rstrip("/")
                for d in (meta or {}).get("distributions", [])
                if d.get("directory_url")})


def _csaf_hosts_plain(entries):
    """`fell_back` holds bare hosts, unlike `unreachable` which holds
    "host (error detail)". Separate reader so neither format has two."""
    return set(entries or ())


def _csaf_hosts(entries):
    """Bare hosts from `unreachable`, whose entries are "host (error detail)".

    Kept as a function rather than a set comprehension at the call site so the
    format of that list has exactly one reader.
    """
    return {e.split(" ", 1)[0] for e in entries}


def _record_csaf_health(providers, unreachable, empty, capped_dirs, fell_back,
                        rows, capped_reads=(), over_budget=(), behind=()):
    """One health record for the fan-out adapter, as COUNTS.

    THE VENDOR NAMES ARE GONE FROM HERE, deliberately, and the parts records are
    now the only place a provider is named.

    This used to assemble five accumulator lists of hostnames into one string,
    truncated at six and eight names. Three things were wrong with it, and the
    parts table on the same page fixed all three by existing:

    IT PUBLISHED FALSE CLAIMS ABOUT NAMED VENDORS. The parent said "no advisories
    in scope: www.huawei.com, www.innomic.com" while those same hosts' own parts
    said "ok, 0 ids in scope". Two renderings of one fact on one page, and only
    the string version was wrong.

    THE DENOMINATOR CERTIFIED ITSELF. `n = len(providers)` with numerator
    `n - len(unreachable)` publishes `n/n` on any run where nothing was
    unreachable, which is most runs, and the 17 counted one publisher twice
    because sick.com and www.sick.com are the same host after a 301.

    IT WAS THE WIDEST CELL ON /status, wide enough to force the overflow-wrap
    rule that stopped the table pushing the page sideways, and it was the route
    by which vendor names reached `limitations` through `health_summary`.

    Counts only. A reader who wants to know WHICH provider looks at the rows
    underneath, where the claim is per provider and cannot disagree with itself.
    """
    n = len(providers)
    bits = [f"{n} providers", f"{rows} ids"]
    for label, items in (("unreachable", unreachable), ("read via pinned feeds", fell_back),
                         ("directory cap", capped_dirs), ("advisory cap", capped_reads),
                         ("stopped on time budget", over_budget),
                         ("still catching up", behind),
                         ("no advisories in scope", empty)):
        if items:
            bits.append(f"{len(items)} {label}")
    detail = "; ".join(bits) + "; see the provider rows below"
    if unreachable and not rows:
        # Nothing was read from anywhere. That is an outage, not a limit.
        record_feed("csaf", FAILED, detail, rows=rows)
    elif unreachable or capped_dirs or capped_reads or over_budget or behind:
        # CAPPED, NOT TRUNCATED. `degraded_state` folds TRUNCATED into "this run
        # is incomplete" and deliberately does not fold CAPPED, because a
        # standing limit fires on every run by design: "A warning that is always
        # on is not a warning, it is furniture, and it teaches a reader to ignore
        # the banner on the day it means something."
        record_feed("csaf", CAPPED, detail, rows=rows)
    else:
        record_feed("csaf", OK, detail, rows=rows)

def feed_mozilla(years):
    """Mozilla Foundation Security Advisories (Firefox/Thunderbird) from the FSA git
    repo (YAML). Mozilla is its own CNA -> self-disclosure. Dependency-free: regex the
    CVE ids and parse the `announced:` date, no YAML lib."""
    hdrs = _gh_headers()
    out, seen = [], set()
    for y in sorted(years):
        try:
            listing, _, _ = _get(
                f"https://api.github.com/repos/mozilla/foundation-security-advisories/"
                f"contents/announce/{y}", timeout=40, headers=hdrs)
        except Exception as e:
            print(f"  [mozilla] {y} listing skip: {e}", file=sys.stderr)
            continue
        files = [f for f in (listing or []) if f.get("name", "").endswith(".yml") and f.get("download_url")]

        def _one(f):
            try:
                text = _get_text(f["download_url"])
            except Exception:
                return []
            cves = {c for c in re.findall(r"CVE-\d{4}-\d+", text) if _year(c) in years}
            if not cves:
                return []
            pub = ""
            m = re.search(r"announced:\s*(.+)", text)
            if m:
                pub = _parse_month_day_year(m.group(1).strip().strip("'\""))
            low = text.lower()
            prod = "thunderbird" if "thunderbird" in low else "firefox"
            tm = re.search(r"title:\s*(.+)", text)
            desc = (tm.group(1).strip() if tm else "")[:400]
            mid = f["name"].replace(".yml", "")
            return [{"cve_id": c, "source": "mozilla", "source_ref": mid, "public_date": pub,
                     "product": prod, "description": desc} for c in cves]

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
            for rows in ex.map(_one, files):
                for r in rows:
                    if r["cve_id"] not in seen:
                        seen.add(r["cve_id"])
                        out.append(r)
    return out


def feed_arch(years):
    """Arch Linux security tracker: one JSON of AVGs (group -> CVE issues + packages).
    Rolling-distro breadth; not a CNA (owner stays product-inferred). Undated."""
    data, _, _ = _get("https://security.archlinux.org/issues/all.json", timeout=60,
                      headers={"Accept": "application/json"})
    out, seen = [], set()
    for avg in data or []:
        pkgs = avg.get("packages") or []
        pkg = pkgs[0] if pkgs else ""
        for cid in avg.get("issues") or []:
            if _year(cid) in years and cid not in seen:
                seen.add(cid)
                out.append({"cve_id": cid, "source": "arch", "source_ref": pkg,
                            "public_date": "", "product": pkg,
                            "description": (avg.get("type") or "")[:400]})
    return out


_SMR_RE = re.compile(r"SMR[\s-]+(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[\s-]+(20\d\d)",
                     re.I)
_SMR_MONTHS = {m: i + 1 for i, m in enumerate(
    ["jan", "feb", "mar", "apr", "may", "jun",
     "jul", "aug", "sep", "oct", "nov", "dec"])}


def feed_samsung(years, url="https://security.samsungmobile.com/securityUpdate.smsb"):
    """Samsung Mobile Security Maintenance Release bulletins.

    Added to close the launch gate: SamsungMobile is a top-50 CNA by volume and
    was the last one under the 3-sighting floor. Measured before writing a line
    of it, which is the rule this project learned the hard way: a full-text probe
    of OSV's GIT ecosystem predicted +18 CNAs and the adapter delivered +0,
    because the probe and the adapter were reading different fields. This page
    yields 72 SamsungMobile sightings and takes top-50 coverage from 39 to 40.

    ONE PAGE, MANY MONTHS. The bulletin index carries every SMR back several
    years in one document, split by "SMR <Mon>-<Year>" headings, so the whole
    feed is a single fetch and the date has to come from the heading a CVE sits
    under rather than from the response.

    Most of the CVEs here are Google's, applied from the Android Security
    Bulletin, and those already arrive through OSV's Android ecosystem. That is
    not a reason to skip them: Samsung publishing a fix is a different public
    event from Google publishing one, and the row's `sources` should say so.
    (This used to read "a second independent origin is what moves a row into the
    corroborated headline". There is no corroborated headline as of 2026-08-27;
    the reason for reading the feed is unchanged.)
    """
    try:
        html = _get_text(url, timeout=60)
    except Exception as e:
        record_feed("samsung", False, str(e)[:120])
        print(f"  [samsung] FAILED: {e}", file=sys.stderr)
        return []

    # Split on the SMR headings so each CVE inherits the date of its own
    # release. Falling back to one date for the whole page would put a 2019
    # bulletin's CVEs on today, which is the clock error this project spent a
    # whole review item on.
    marks = [(m.start(), m.group(1).lower(), int(m.group(2)))
             for m in _SMR_RE.finditer(html)]
    out, seen = [], set()
    if not marks:
        record_feed("samsung", TRUNCATED, "no SMR headings found; page shape changed")
        print("  [samsung] no SMR headings; page shape changed", file=sys.stderr)
        return []

    for i, (pos, mon, yr) in enumerate(marks):
        end = marks[i + 1][0] if i + 1 < len(marks) else len(html)
        month = _SMR_MONTHS.get(mon)
        if not month:
            continue
        # Samsung publishes an SMR in the first week of its month. Day 1 is the
        # conservative choice: it can only make a row look OLDER, and every
        # other date on this site is a floor for the same reason.
        date = f"{yr:04d}-{month:02d}-01"
        for cid in set(re.findall(r"CVE-20\d\d-\d{4,7}", html[pos:end])):
            if _year(cid) not in years or cid in seen:
                continue
            seen.add(cid)
            out.append({"cve_id": cid, "source": "samsung",
                        "source_ref": f"SMR-{mon.title()}-{yr}",
                        "public_date": date, "product": "Galaxy",
                        "description": f"Samsung SMR {mon.title()} {yr}"})
    return out


ADAPTERS = {"alas": feed_alas, "ubuntu": feed_ubuntu, "debian": feed_debian,
            "ghsa": feed_ghsa, "ghsa-repos": feed_ghsa_repos,
            "redhat": feed_redhat, "alpine": feed_alpine,
            "osv": feed_osv, "csaf": feed_csaf, "msrc": feed_msrc, "mozilla": feed_mozilla,
            "arch": feed_arch, "samsung": feed_samsung,
            "ubuntu-osv": feed_ubuntu_osv}


def gather(sources, years):
    """Collect referenced CVE IDs from every configured feed.

    Health is recorded here rather than inside each adapter, so instrumentation
    cannot drift out of step with the adapter list. A feed that raises is
    recorded as a failure and the run reports degraded coverage; a feed that
    returns nothing is recorded as a success with zero rows, which is a
    materially different thing and must not read the same way.
    """
    reset_health()
    refs = {}
    for s in sources:
        try:
            rows = ADAPTERS[s](years)
        except Exception as e:
            record_feed(s, False, str(e)[:120])
            print(f"  [{s}] FAILED: {e}", file=sys.stderr)
            continue
        # Do not overwrite an incomplete state an adapter already recorded for
        # itself.
        #
        # CAPPED was MISSING from this tuple, and the omission erased the state
        # in the same call that recorded it. `feed_ghsa` records CAPPED when it
        # runs out of pages rather than out of data, and this branch then
        # overwrote it with OK on every single run, so `health_summary`'s
        # `capped` list could never be non-empty and `stats["limitations"]`, the
        # field the site publishes to say which feeds are read over a shorter
        # window than the trackers, was permanently empty. The live snapshot for
        # 2026-08-20 reads `ghsa ok 3321 ids` for exactly this reason.
        #
        # Same shape as the bug that made this branch necessary in the first
        # place: a state recorded by an adapter and discarded by the caller. The
        # fix is the membership test, and the test that catches it is a mutation
        # test, because every assertion about ghsa's row count passes either way.
        #
        # AND THE SAME BUG SURVIVED IN THE `ok` HALF OF IT, found 2026-08-26 by
        # reading the published artefact of a green run instead of the log.
        # Testing the STATUS keeps an adapter's account of itself only when that
        # account is bad news. `feed_csaf` records OK with a detail naming which
        # of its 17 providers were read, which had nothing to say, and which were
        # reached by a route other than the one in the config; every word of that
        # was overwritten with "2732 ids" on any run where nothing went wrong.
        #
        # So CISA being read through pinned feeds rather than www.cisa.gov, the
        # one fact on that line a reader most needs and the one the site promised
        # to disclose, appeared in the build log and reached no page. A
        # disclosure that only survives when a run is ALSO degraded is not a
        # disclosure. Test for a detail, not for bad news.
        h = FEED_HEALTH.get(s) or {}
        if h.get("status") in (TRUNCATED, FAILED, CAPPED) or h.get("detail"):
            FEED_HEALTH[s]["rows"] = len(rows)
        else:
            record_feed(s, OK, f"{len(rows)} ids", rows=len(rows))
        # HOW FAR BACK, AND HOW RECENT, recorded here rather than per adapter so
        # thirteen adapters cannot drift out of step on it, which is the same
        # reasoning that put health recording in this function.
        #
        # `newest` is the one that catches the failure a row count cannot see. A
        # feed frozen at a constant reads as perfectly healthy to
        # `compare_magnitudes`, which only ever asks whether a number went DOWN:
        # `mozilla` returned exactly 607 on six consecutive published snapshots,
        # `arch` exactly 62, `samsung` exactly 420 on five. If any of those had
        # stopped updating on day one, every guard on this site would still have
        # been green. `tests/test_ghsa_feeds.py` already named this shape for
        # ghsa and called it a standing truncation that reads as a healthy feed.
        #
        # `oldest` is how the Ubuntu cap gets stated in days instead of pages.
        dates = sorted(r["public_date"] for r in rows if r.get("public_date"))
        FEED_HEALTH[s]["newest"] = dates[-1] if dates else ""
        FEED_HEALTH[s]["oldest"] = dates[0] if dates else ""
        FEED_HEALTH[s]["dated_rows"] = len(dates)
        print(f"  [{s}] {len(rows)} referenced IDs in scope"
              + (f", {dates[0]} to {dates[-1]}" if dates else ", undated"))
        for r in rows:
            cid = r["cve_id"]
            e = refs.setdefault(cid, {"sources": set(), "refs": set(), "public_date": "",
                                      "product": "", "description": "",
                                      # Per-source dates, kept so the MUST clock
                                      # can ask who published FIRST rather than
                                      # only who published. Collapsing to the
                                      # minimum discarded exactly that.
                                      "dates": {}})
            e["sources"].add(s)
            if r["source_ref"]:
                e["refs"].add(f'{s}:{r["source_ref"]}')
            if r["public_date"]:
                if not e["public_date"] or r["public_date"] < e["public_date"]:
                    e["public_date"] = r["public_date"]
                prev = e["dates"].get(s)
                if not prev or r["public_date"] < prev:
                    e["dates"][s] = r["public_date"]
            if r["product"] and not e["product"]:
                e["product"] = r["product"]
            if r["description"] and not e["description"]:
                e["description"] = r["description"]
    return refs

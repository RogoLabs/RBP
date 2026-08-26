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
import time
import zipfile
import urllib.error
import urllib.request
from urllib.parse import urlparse

UA = {"User-Agent": "rbp-cves/1.0 (CVE quality research)"}
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


def record_feed(name, status, detail="", rows=None):
    """Record one feed outcome in three states, not two.

    A feed that hit a page cap is neither a success nor a failure: it returned
    real rows AND silently dropped the rest. Recording it as ok made the method
    page assert "all N feed fetches succeeded" on every single run, because the
    Ubuntu 200-page cap fires every run. `status` accepts a bool for the old
    call sites, where True means ok.
    """
    if status is True:
        status = OK
    elif status is False:
        status = FAILED
    FEED_HEALTH[name] = {"status": status, "detail": detail, "rows": rows,
                         "ok": status == OK,
                         # Both incomplete-shaped states answer True here, so a
                         # consumer asking "did this feed read everything" still
                         # gets the right answer without knowing about caps.
                         "truncated": status in (TRUNCATED, CAPPED),
                         "capped": status == CAPPED}


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

    out = []
    for name, cur in sorted((current or {}).items()):
        if ":" in name:
            continue                      # raw-shape sub-fetch; handled below
        prev_feed = (previous or {}).get(name) or {}
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
            pv = ((prev_feed.get("parts") or {}).get(child) or {})
            hit = _cmp(f"{name}:{child}", pv.get("rows"), cv.get("rows"),
                       PART_DROP)
            if hit:
                out.append(hit)
    return out


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


def feed_ubuntu(years, page_cap=200):
    out, offset, limit, capped = [], 0, 20, False  # Ubuntu API caps limit at 20
    # WHY the loop ended, not just that it ended. Three different exits used to
    # look identical from outside: the natural end of the data, an error response
    # laundered into an empty page, and the year heuristic firing early. Only the
    # page cap recorded anything, so the other two published a short feed as `ok`.
    # Measured consequence: ubuntu returned 3,995 ids on 2026-08-21 and 1,079 the
    # next day, the status went from `truncated` to `ok`, and the site's headline
    # fell from 558 to 458 with every health surface green. The health signal
    # improved while the data got worse.
    ended = "exhausted"
    while offset < page_cap * limit:
        try:
            data, code, _ = _get(f"https://ubuntu.com/security/cves.json?limit={limit}&offset={offset}", timeout=60)
        # Broad on purpose: keep the partial results. A page that fails mid-sweep
        # truncates the feed, which is recorded, rather than discarding every page
        # already read.
        except Exception as e:
            print(f"  [ubuntu] stopped at offset {offset}: {e}", file=sys.stderr)
            ended = f"error at offset {offset}: {str(e)[:80]}"
            break
        rows = (data or {}).get("cves", []) if isinstance(data, dict) else []
        if not rows:
            # An empty page is only the end of the data if the request SUCCEEDED.
            # `_get` returns (None, 404, {}) on a retired path or a WAF block, and
            # every caller bound `code` and never read it, so a 404 ended
            # pagination through this branch and was recorded as a healthy feed.
            if code and code != 200:
                ended = f"HTTP {code} at offset {offset}, treated as end of data"
            break
        stop = False
        for r in rows:
            cid = r.get("id", "")
            if _year(cid) in years:
                out.append({"cve_id": cid, "source": "ubuntu", "source_ref": cid,
                            "public_date": _d(r.get("published")), "product": "",
                            "description": (r.get("description") or "")[:400]})
            # stop on PUBLISH-date year, not CVE-ID year (a fresh advisory can cite an old CVE)
            py = _date_year(r.get("published"))
            if py is not None and py < min(years):
                stop = True
        if stop:
            # The year heuristic assumes the feed is ordered by publish date
            # descending. When it fires, rows beyond this page were NOT read, which
            # is truncation whether or not the assumption held.
            ended = (f"year heuristic stopped pagination at offset {offset}; rows "
                     "beyond it were not read")
            break
        offset += limit
    else:
        capped = True
    if capped:
        print(f"  [ubuntu] hit page cap ({page_cap}), coverage may be truncated", file=sys.stderr)
        record_feed("ubuntu", CAPPED, f"hit the {page_cap}-page cap; rows beyond it were not read")
    elif ended != "exhausted":
        print(f"  [ubuntu] {ended}", file=sys.stderr)
        record_feed("ubuntu", TRUNCATED, ended)
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


def feed_ghsa(years, page_cap=40):
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if not token:
        try:
            token = subprocess.check_output(["gh", "auth", "token"], text=True).strip()
        except Exception:
            token = None
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    out, url = [], "https://api.github.com/advisories?per_page=100&sort=published&direction=desc"
    # Three outcomes, tracked explicitly. This loop reported ONE of them.
    #
    # `for _ in range(page_cap)` exhausting is a truncation, twelve lines below
    # feed_ubuntu which records exactly that, and it recorded nothing. `gather`
    # then stamped ghsa `ok` with the truncated count, so the live summary read
    # {status: "ok", detail: "3321 ids"} on a feed that had silently stopped
    # reading. Worse, a fixed cap returns a roughly CONSTANT count every run, so
    # compare_magnitudes reads stable truncation as a healthy feed: the one
    # detector for the failure this project calls intolerable is blind to the
    # most likely instance of it.
    #
    # GHSA sources roughly 300 of 522 rows and the cap bounds that population's
    # observation window to about 83 days, while distro trackers are observed
    # over years. That is not merely incomplete, it silently invalidates
    # cross-CNA comparison, so it has to be visible rather than inferred.
    ended, pages = "exhausted", 0
    for _ in range(page_cap):
        pages += 1
        try:
            data, _, hdrs = _get(url, timeout=60, headers=headers)
        except Exception as e:
            print(f"  [ghsa] stopped: {e}", file=sys.stderr)
            ended = f"stopped after {pages} page(s): {str(e)[:80]}"
            break
        stop = False
        for a in data or []:
            cid = a.get("cve_id")
            y = _year(cid) if cid else None
            if y in years:
                out.append({"cve_id": cid, "source": "ghsa", "source_ref": a.get("ghsa_id", ""),
                            "public_date": _d(a.get("published_at")), "product": "",
                            "description": (a.get("summary") or "")[:400]})
            # stop on PUBLISH-date year, not CVE-ID year
            py = _date_year(a.get("published_at"))
            if py is not None and py < min(years):
                stop = True
        nxt = [p.split(";")[0].strip("<> ") for p in hdrs.get("Link", "").split(",") if 'rel="next"' in p]
        if stop or not nxt:
            ended = "reached the requested window"
            break
        url = nxt[0]
    else:
        # The loop ran out of iterations rather than out of data, which is
        # exactly the truncation nothing was reporting.
        ended = f"hit the {page_cap}-page cap; advisories beyond it were not read"
    if ended != "reached the requested window":
        print(f"  [ghsa] {ended}", file=sys.stderr)
        record_feed("ghsa", CAPPED if "page cap" in ended else TRUNCATED, ended)
    return out


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
def feed_osv(years, ecosystems=("PyPI", "npm", "Go", "crates.io", "RubyGems",
                                "Maven", "Packagist", "NuGet", "Pub", "Hex",
                                "Android")):
    """OSV.dev bulk per-ecosystem dumps: language-ecosystem breadth. Each record's
    CVE aliases are the referenced IDs; package name is the attribution product."""
    out, seen = [], set()
    for eco in ecosystems:
        url = f"https://osv-vulnerabilities.storage.googleapis.com/{eco}/all.zip"
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
        for info in zf.infolist():
            name = info.filename
            if not name.endswith(".json") or info.file_size > 2_000_000:
                continue
            try:
                rec = json.loads(zf.read(name))
            except Exception:
                continue
            cves = [a for a in (rec.get("aliases") or []) if a.startswith("CVE-") and _year(a) in years]
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
        # rows= was never passed here, so every OSV part carried rows: null and
        # compare_magnitudes could not compare it even after it learned to look.
        record_feed(f"osv:{eco}", True, f"{added} ids from {nbytes / 1e6:.0f}MB",
                    rows=added)
        print(f"  [osv:{eco}] +{added}", file=sys.stderr)
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
    "https://sick.com/.well-known/csaf/provider-metadata.json",                   # SICK (ICS CNA)
    # Not listed by any aggregator we read, found by probing .well-known. Both
    # are high-volume CNAs in their own right.
    "https://www.cisco.com/.well-known/csaf/provider-metadata.json",              # Cisco PSIRT
    "https://www.suse.com/.well-known/csaf/provider-metadata.json",               # SUSE
)

# CSAF aggregators list many vendors' provider-metadata URLs in one file, one fetch
# unlocks N vendors (Red Hat, Nozomi, Stackable, KUNBUS, ...).
CSAF_AGGREGATORS = (
    "https://wid.cert-bund.de/.well-known/csaf-aggregator/aggregator.json",       # BSI CERT-Bund
)

# Cap on directory distributions consulted per provider. Some providers list one
# directory per advisory rather than one root (Huawei lists 117), and without a
# cap a single provider dominates the run.
CSAF_MAX_DIRS = 12


def _csaf_directory_entries(directory_url, years, cap):
    """Recent advisory URLs from a CSAF *directory* distribution.

    The spec allows two distribution shapes and this adapter originally handled
    only one. ROLIE feeds are JSON and were supported; directory distributions
    are a plain listing and were not, so every provider using them yielded
    nothing. Red Hat, Huawei and Schneider Electric are all directory-only, which
    is why Red Hat, one of the largest publishers, contributed zero.

    `changes.csv` is preferred: it is newest-first with timestamps, so a recency
    cap is meaningful. `index.txt` is the fallback, and carries no dates, so it
    is filtered on the year in the file path instead.
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
                # changes.csv is newest-first, so the first out-of-window entry
                # means everything after it is older too.
                break
            out.append((ts, f"{base}/{path.lstrip('/')}"))
            if len(out) >= cap:
                break
        if out:
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
    return [("", f"{base}/{p.lstrip('/')}") for p in keep[-cap:]]


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
              cap_per_provider=120, max_providers=40, workers=8):
    """Generic CSAF/ROLIE ingester: unlocks vendor/enterprise/ICS CNAs. Expands
    aggregators into providers, then for each provider: metadata -> ROLIE feed(s)
    -> recent advisory docs -> CVEs in scope."""
    out, seen = [], set()
    # Per-provider outcomes, so the aggregate this adapter reports is derived
    # rather than asserted. `feed_csaf` recorded NO health at all: `gather` filled
    # in `ok, N ids` whatever happened underneath, so a provider answering 401 on
    # every advisory, a provider behind a WAF returning 403, and a provider whose
    # 120 directories were cut to 12 all reported identically to a clean read.
    # That is the silent-shrink signature on the one adapter that fans out to
    # more than a dozen third parties.
    unreachable, empty, capped_dirs = [], [], []
    all_providers = _expand_csaf_providers(providers, aggregators, max_providers)
    print(f"  [csaf] {len(all_providers)} providers (incl. aggregator-discovered)", file=sys.stderr)
    for meta_url in all_providers:
        host = meta_url.split("/")[2]
        try:
            meta, _, _ = _get(meta_url, timeout=40)
        except Exception as e:
            print(f"  [csaf] {meta_url}: metadata skip ({e})", file=sys.stderr)
            unreachable.append(f"{host} ({str(e)[:40]})")
            continue
        feed_urls = []
        for dist in (meta or {}).get("distributions", []):
            for f in (dist.get("rolie", {}) or {}).get("feeds", []):
                if f.get("url"):
                    feed_urls.append(f["url"])
        entries = []
        # Directory distributions, the half of the spec this adapter used to skip.
        available = _csaf_directory_count(meta)
        chosen = _csaf_directories(meta, max_dirs=CSAF_MAX_DIRS)
        if available > len(chosen):
            # Huawei publishes 121 distributions, one directory per advisory, so
            # the cap selects an arbitrary handful and the rest are never read.
            # Reported rather than merely capped: an arbitrary 12 of 121 is a
            # feed that has quietly shrunk to a tenth of itself, and the site
            # cannot tell the difference between that and a quiet vendor.
            capped_dirs.append(f"{host} {len(chosen)}/{available} directories")
        for durl in chosen:
            entries.extend(_csaf_directory_entries(durl, years, cap_per_provider))
        for furl in feed_urls:
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
        entries.sort(reverse=True)
        entries = entries[:cap_per_provider]

        def _fetch(item):
            upd, href = item
            try:
                d, _, _ = _get(href, timeout=40)
            except Exception:
                return []
            doc = (d or {}).get("document", {})
            pub = (doc.get("publisher", {}) or {}).get("name", "")
            tr = doc.get("tracking", {}) or {}
            rel = tr.get("initial_release_date", "") or upd
            tid = tr.get("id", "")
            rows = []
            for v in (d or {}).get("vulnerabilities", []):
                cid = v.get("cve", "")
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

        n0 = len(out)
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
            for rows in ex.map(_fetch, entries):
                for r in rows:
                    if r["cve_id"] not in seen:
                        seen.add(r["cve_id"])
                        out.append(r)
        gained = len(out) - n0
        print(f"  [csaf] {host}: +{gained}", file=sys.stderr)
        if gained == 0:
            # A provider contributing nothing is not an error and is not
            # nothing. FEEDS.md recorded that SUSE, Huawei and www.sick.com each
            # returned zero advisories in scope and that "the provider list has
            # never been validated against what it actually yields". This is that
            # validation, on every run, rather than once in a document.
            empty.append(host)
    _record_csaf_health(all_providers, unreachable, empty, capped_dirs, len(out))
    return out


def _csaf_directory_count(meta):
    """How many directory distributions the provider actually offers.

    Counted before the cap and before the language filter, so the health line can
    say "12 of 121" rather than "12", which is the difference between a limit and
    a loss.
    """
    return len({(d.get("directory_url") or "").rstrip("/")
                for d in (meta or {}).get("distributions", [])
                if d.get("directory_url")})


def _record_csaf_health(providers, unreachable, empty, capped_dirs, rows):
    """One health record for the fan-out adapter, derived from its providers.

    Ordered worst-first, because a single status has to mean the worst thing that
    happened: a provider that could not be reached at all is a bigger claim than
    a provider that was capped, and a cap is a bigger claim than a provider that
    genuinely had nothing to say.
    """
    n = len(providers)
    bits = [f"{n - len(unreachable)}/{n} providers read", f"{rows} ids"]
    if unreachable:
        bits.append(f"unreachable: {', '.join(sorted(unreachable)[:6])}")
    if capped_dirs:
        bits.append(f"capped: {', '.join(sorted(capped_dirs)[:6])}")
    if empty:
        bits.append(f"no advisories in scope: {', '.join(sorted(empty)[:8])}")
    detail = "; ".join(bits)
    if unreachable and not rows:
        # Nothing was read from anywhere. That is an outage, not a limit.
        record_feed("csaf", FAILED, detail, rows=rows)
    elif unreachable or capped_dirs:
        # CAPPED, NOT TRUNCATED, and the distinction decides whether the site
        # wears a banner.
        #
        # `degraded_state` folds TRUNCATED into "this run is incomplete" and
        # deliberately does not fold CAPPED, because a standing limit fires on
        # every run by design: "A warning that is always on is not a warning, it
        # is furniture, and it teaches a reader to ignore the banner on the day
        # it means something."
        #
        # An unreachable CSAF provider is a standing limit. Cisco's WAF returns
        # 403 to a non-browser agent on every single run, and this was written as
        # TRUNCATED first, which would have put "This run is incomplete ... not
        # comparable to the previous run" on every page of every run from the
        # moment it merged. Caught by simulating the live provider set before
        # merging rather than by reading the banner on the published site.
        #
        # It is still NAMED and still published as a limitation, so the loss is
        # visible; it is just not called a degradation. A provider that was
        # working and stops is caught by `compare_magnitudes`, which compares
        # this feed's row count to its own previous run and IS a degradation.
        # That is the mechanism for "worse than usual", and it already exists.
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
    not a reason to skip them: a second independent origin is what moves a row
    into the corroborated headline, and Samsung publishing a fix is a different
    public event from Google publishing one.
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
            "ghsa": feed_ghsa, "redhat": feed_redhat, "alpine": feed_alpine,
            "osv": feed_osv, "csaf": feed_csaf, "msrc": feed_msrc, "mozilla": feed_mozilla,
            "arch": feed_arch, "samsung": feed_samsung}


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
        if FEED_HEALTH.get(s, {}).get("status") in (TRUNCATED, FAILED, CAPPED):
            FEED_HEALTH[s]["rows"] = len(rows)
        else:
            record_feed(s, OK, f"{len(rows)} ids", rows=len(rows))
        print(f"  [{s}] {len(rows)} referenced IDs in scope")
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

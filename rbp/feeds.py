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
            "ghsa": feed_ghsa, "ghsa-repos": feed_ghsa_repos,
            "redhat": feed_redhat, "alpine": feed_alpine,
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

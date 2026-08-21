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

OK, TRUNCATED, FAILED = "ok", "truncated", "failed"


def reset_health():
    """Clear per-run state. A module global that survives between runs in the
    same process reports a stale feed as healthy."""
    FEED_HEALTH.clear()


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
                         "ok": status == OK, "truncated": status == TRUNCATED}


def health_summary():
    """(failures, attempts) where an attempt is one FEED, not one sub-fetch.

    The unit used to be wrong as well as the states: OSV recorded per ecosystem
    and gather recorded again for `osv`, so "all 20 feed fetches succeeded"
    described 10 feeds and any consumer check of the form
    `failures == [] and attempts == len(requested)` was broken on arrival.
    """
    failures = [f"{k}: {v['detail']}" for k, v in FEED_HEALTH.items()
                if v["status"] == FAILED]
    top = [k for k in FEED_HEALTH if ":" not in k]
    return failures, len(top)


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
    for parent, v in out.items():
        parts = v.get("parts") or {}
        if parts and any(p["status"] != OK for p in parts.values()):
            worst = FAILED if any(p["status"] == FAILED for p in parts.values()) else TRUNCATED
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
    except Exception:  # noqa: BLE001
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
                return json.loads(r.read(MAX_BYTES)), getattr(r, "status", 200), dict(r.headers)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None, 404, {}
            last = e
        except Exception as e:  # noqa: BLE001
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
        return r.read(MAX_BYTES).decode("utf-8", "replace")


def _gh_headers():
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if not token:
        try:
            token = subprocess.check_output(["gh", "auth", "token"], text=True).strip()
        except Exception:  # noqa: BLE001
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
    while offset < page_cap * limit:
        try:
            data, code, _ = _get(f"https://ubuntu.com/security/cves.json?limit={limit}&offset={offset}", timeout=60)
        except Exception as e:  # noqa: BLE001, keep partial results
            print(f"  [ubuntu] stopped at offset {offset}: {e}", file=sys.stderr)
            break
        rows = (data or {}).get("cves", []) if isinstance(data, dict) else []
        if not rows:
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
            break
        offset += limit
    else:
        capped = True
    if capped:
        print(f"  [ubuntu] hit page cap ({page_cap}), coverage may be truncated", file=sys.stderr)
        record_feed("ubuntu", TRUNCATED, f"hit the {page_cap}-page cap; rows beyond it were not read")
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
        except Exception:  # noqa: BLE001
            token = None
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    out, url = [], "https://api.github.com/advisories?per_page=100&sort=published&direction=desc"
    for _ in range(page_cap):
        try:
            data, _, hdrs = _get(url, timeout=60, headers=headers)
        except Exception as e:  # noqa: BLE001
            print(f"  [ghsa] stopped: {e}", file=sys.stderr)
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
            break
        url = nxt[0]
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
            except Exception as e:  # noqa: BLE001, keep partial results
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
            except Exception as e:  # noqa: BLE001: one branch failure shouldn't drop the feed
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


def feed_osv(years, ecosystems=("PyPI", "npm", "Go", "crates.io", "RubyGems",
                                "Maven", "Packagist", "NuGet", "Pub", "Hex")):
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
        except Exception as e:  # noqa: BLE001
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
            except Exception:  # noqa: BLE001
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
        record_feed(f"osv:{eco}", True, f"{added} ids from {nbytes / 1e6:.0f}MB")
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
    except Exception as e:  # noqa: BLE001
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
        except Exception as e:  # noqa: BLE001
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
    except Exception:  # noqa: BLE001
        pass
    try:
        raw = _get_text(f"{base}/index.txt", timeout=90)
    except Exception:  # noqa: BLE001
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
        except Exception as e:  # noqa: BLE001
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
    all_providers = _expand_csaf_providers(providers, aggregators, max_providers)
    print(f"  [csaf] {len(all_providers)} providers (incl. aggregator-discovered)", file=sys.stderr)
    for meta_url in all_providers:
        try:
            meta, _, _ = _get(meta_url, timeout=40)
        except Exception as e:  # noqa: BLE001
            print(f"  [csaf] {meta_url}: metadata skip ({e})", file=sys.stderr)
            continue
        feed_urls = []
        for dist in (meta or {}).get("distributions", []):
            for f in (dist.get("rolie", {}) or {}).get("feeds", []):
                if f.get("url"):
                    feed_urls.append(f["url"])
        entries = []
        # Directory distributions, the half of the spec this adapter used to skip.
        for durl in _csaf_directories(meta, max_dirs=CSAF_MAX_DIRS):
            entries.extend(_csaf_directory_entries(durl, years, cap_per_provider))
        for furl in feed_urls:
            try:
                fd, _, _ = _get(furl, timeout=90)
            except Exception:  # noqa: BLE001
                continue
            for e in (fd or {}).get("feed", {}).get("entry", []):
                upd = e.get("updated", "") or e.get("published", "")
                if _date_year(upd) is not None and _date_year(upd) < min(years):
                    continue
                href = next((l["href"] for l in e.get("link", []) if l.get("rel") == "self"), None)
                if href:
                    entries.append((upd, href))
        entries.sort(reverse=True)
        entries = entries[:cap_per_provider]

        def _fetch(item):
            upd, href = item
            try:
                d, _, _ = _get(href, timeout=40)
            except Exception:  # noqa: BLE001
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
                    rows.append({"cve_id": cid, "source": "csaf",
                                 "source_ref": f"{pub}:{tid}", "public_date": _d(rel),
                                 "product": "", "description": (v.get("title") or doc.get("title") or "")[:400]})
            return rows

        n0 = len(out)
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
            for rows in ex.map(_fetch, entries):
                for r in rows:
                    if r["cve_id"] not in seen:
                        seen.add(r["cve_id"])
                        out.append(r)
        print(f"  [csaf] {meta_url.split('/')[2]}: +{len(out) - n0}", file=sys.stderr)
    return out


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
        except Exception as e:  # noqa: BLE001
            print(f"  [mozilla] {y} listing skip: {e}", file=sys.stderr)
            continue
        files = [f for f in (listing or []) if f.get("name", "").endswith(".yml") and f.get("download_url")]

        def _one(f):
            try:
                text = _get_text(f["download_url"])
            except Exception:  # noqa: BLE001
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


ADAPTERS = {"alas": feed_alas, "ubuntu": feed_ubuntu, "debian": feed_debian,
            "ghsa": feed_ghsa, "redhat": feed_redhat, "alpine": feed_alpine,
            "osv": feed_osv, "csaf": feed_csaf, "msrc": feed_msrc, "mozilla": feed_mozilla,
            "arch": feed_arch}


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
        except Exception as e:  # noqa: BLE001
            record_feed(s, False, str(e)[:120])
            print(f"  [{s}] FAILED: {e}", file=sys.stderr)
            continue
        # Do not overwrite a truncation an adapter already recorded for itself.
        if FEED_HEALTH.get(s, {}).get("status") in (TRUNCATED, FAILED):
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

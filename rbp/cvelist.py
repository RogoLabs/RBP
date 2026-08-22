"""
Standalone CVE List v5 corpus, the source of truth.

Downloads the official daily baseline release (github.com/CVEProject/cvelistV5)
and indexes every record into a compact parquet. No dependency on any sibling
repo or snapshot. Two products fall out of one pass over the corpus:

    corpus.parquet       cve_id, state, assigner, date_published, vendor, product
    product_cna.parquet  product -> dominant assigner + confidence   (corroboration only)
"""
from __future__ import annotations

import datetime as dt
import io
import json
import os
import urllib.request
import zipfile
from collections import Counter, defaultdict

import pandas as pd

RELEASES_API = "https://api.github.com/repos/CVEProject/cvelistV5/releases"
UA = {"User-Agent": "rbptracker.org (+https://github.com/RogoLabs/RBP)"}

# Re-download the 583 MB baseline rather than chaining more deltas than this.
MAX_DELTA_GAP_DAYS = 10


def _auth_headers():
    """Authenticated headers when a token is present.

    Anonymous api.github.com is 60 requests per hour per IP, shared across every
    job on a GitHub-hosted runner, and a 403 here propagates through
    ensure_corpus and kills the run before any feed is read.
    """
    h = dict(UA)
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    if token:
        h["Authorization"] = f"Bearer {token}"
        h["X-GitHub-Api-Version"] = "2022-11-28"
    return h


def _releases(pages=3):
    """Recent releases, newest first. cvelistV5 cuts one per hour, so three
    pages is roughly twelve days of history."""
    out = []
    for page in range(1, pages + 1):
        req = urllib.request.Request(f"{RELEASES_API}?per_page=100&page={page}",
                                     headers=_auth_headers())
        with urllib.request.urlopen(req, timeout=60) as r:
            batch = json.load(r)
        if not batch:
            break
        out.extend(batch)
    return out


def _asset(rel, match):
    """First asset whose name satisfies `match`. Note that the baseline is named
    `..._all_CVEs_at_midnight.zip.zip`, so a bare `.zip` suffix test matches it
    as well as the delta; callers must discriminate on the name, not the
    extension."""
    for a in rel.get("assets", []):
        if match(a["name"]):
            return a
    return None


def survey_releases():
    """Map the release feed into what the corpus refresh actually needs.

    Two facts about this feed drive the whole design, both measured 2026-08-20:

      * The `all_CVEs_at_midnight` asset is ONE file per day. Every hourly
        release re-attaches the identical 583 MB object (same name, same size);
        only the tag rotates. Keying freshness on the tag, as this module used
        to, re-downloads the same half-gigabyte up to 24 times a day.

      * The delta zip is CUMULATIVE FROM MIDNIGHT, not hour-on-hour. It grew
        1.2 MB at 1300Z to 4.3 MB at 2000Z on a single day. So one fetch of the
        newest delta carries every change so far that day, and applying a day's
        final delta carries that whole day.

    Returns (baseline_date, baseline_url, {date: delta_url}) where the delta for
    each date is that date's LATEST release, i.e. the full day for past dates
    and everything-so-far for today.
    """
    rels = _releases()
    baseline_date = baseline_url = None
    deltas = {}
    for rel in rels:                      # newest first
        base = _asset(rel, lambda n: n.endswith("all_CVEs_at_midnight.zip.zip"))
        if base and baseline_url is None:
            baseline_date = base["name"][:10]          # 2026-08-20_all_CVEs...
            baseline_url = base["browser_download_url"]
        delta = _asset(rel, lambda n: "delta_CVEs" in n and n.endswith(".zip"))
        if delta:
            day = delta["name"][:10]
            deltas.setdefault(day, delta["browser_download_url"])   # first seen = latest
    if not baseline_url:
        raise RuntimeError("no all_CVEs baseline asset in recent releases")
    return baseline_date, baseline_url, deltas


def download_baseline(dest, url=None, date=None):
    """Fetch the daily baseline, skipping the download when we already hold that
    day's file. Freshness is keyed on the asset DATE, never the release tag.

    Callers that already surveyed the feed must pass `date` alongside `url`,
    otherwise the freshness stamp is never written and the next cold-ish run
    re-downloads 583 MB it already has.
    """
    if url is None:
        date, url, _ = survey_releases()
    stamp = dest + ".date"
    have = open(stamp).read().strip() if os.path.exists(stamp) else None
    if (os.path.exists(dest) and os.path.getsize(dest) > 100_000_000
            and date and have == date):
        print(f"baseline current ({date})")
        return dest
    print(f"downloading baseline {date} ({url.rsplit('/', 1)[-1]})")
    urllib.request.urlretrieve(url, dest)
    if date:
        open(stamp, "w").write(date)
    return dest


MAX_ENTRY = 8_000_000          # per-record decompressed ceiling (a CVE JSON is < ~1MB)
MAX_TOTAL = 6_000_000_000      # total decompressed ceiling (zip-bomb guard)


def _iter_records(zip_path):
    """Yield parsed CVE record dicts from the (possibly double-zipped) baseline.
    Opens the file on disk (no full read into RAM) and enforces size ceilings."""
    outer = zipfile.ZipFile(zip_path)
    inner_zips = [n for n in outer.namelist() if n.endswith(".zip")]
    containers = [zipfile.ZipFile(io.BytesIO(outer.read(n))) for n in inner_zips] or [outer]
    total = 0
    for z in containers:
        for info in z.infolist():
            name = info.filename
            if not (name.endswith(".json") and os.path.basename(name).startswith("CVE-")):
                continue
            if info.file_size > MAX_ENTRY:
                continue
            total += info.file_size
            if total > MAX_TOTAL:
                raise RuntimeError("baseline decompressed size exceeded ceiling, aborting")
            try:
                yield json.loads(z.read(name))
            except Exception:  # noqa: BLE001
                continue


def build_index(zip_path, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    rows = []
    prod_cna = defaultdict(Counter)   # product(lower) -> Counter(assigner)
    n = 0
    for rec in _iter_records(zip_path):
        meta = rec.get("cveMetadata", {})
        cid = meta.get("cveId")
        if not cid:
            continue
        state = meta.get("state", "")
        assigner = meta.get("assignerShortName", "")
        # Authoritative publication date. Needed for two things the clock module
        # cannot approximate: exact time-to-publish for resolved RBPs, and each
        # CNA's trailing-12-month volume for scale context.
        published = (meta.get("datePublished") or "")[:10]
        cna = (rec.get("containers", {}) or {}).get("cna", {}) or {}
        vendor = product = ""
        aff = cna.get("affected") or []
        if aff:
            vendor = (aff[0].get("vendor") or "")[:120]
            product = (aff[0].get("product") or "")[:120]
        rows.append((cid, state, assigner, published, vendor, product))
        # attribution signal: only trust PUBLISHED records with a real product
        if state == "PUBLISHED" and assigner:
            for a in aff:
                p = (a.get("product") or "").strip().lower()
                if p and p not in ("n/a", "unspecified", ""):
                    prod_cna[p][assigner] += 1
        n += 1
        if n % 50000 == 0:
            print(f"  indexed {n:,} records")
    corpus = pd.DataFrame(rows, columns=COLUMNS)
    corpus.to_parquet(os.path.join(out_dir, "corpus.parquet"), index=False)

    prows = []
    for p, c in prod_cna.items():
        top, cnt = c.most_common(1)[0]
        prows.append((p, top, cnt, sum(c.values()), round(cnt / sum(c.values()), 3)))
    prod = pd.DataFrame(prows, columns=["product", "cna", "cna_cves", "total_cves", "confidence"])
    prod.to_parquet(os.path.join(out_dir, "product_cna.parquet"), index=False)
    print(f"corpus: {len(corpus):,} records | product->CNA map: {len(prod):,} products")
    return corpus, prod


def load_index(out_dir):
    return (
        pd.read_parquet(os.path.join(out_dir, "corpus.parquet")),
        pd.read_parquet(os.path.join(out_dir, "product_cna.parquet")),
    )


# --------------------------------------------------------------------------
# incremental refresh
# --------------------------------------------------------------------------

STATE_FILE = "corpus_state.json"

# Bump when the corpus columns change. A cached index written under an older
# schema is unusable, so a mismatch forces a full rebuild rather than silently
# producing a corpus missing a column the pipeline now depends on.
SCHEMA = 2

COLUMNS = ["cve_id", "state", "assigner", "date_published", "vendor", "product"]


def _read_state(index_dir):
    path = os.path.join(index_dir, STATE_FILE)
    if os.path.exists(path):
        try:
            return json.load(open(path))
        except Exception:  # noqa: BLE001
            pass
    return {}


def _write_state(index_dir, **kw):
    state = _read_state(index_dir)
    state.update(kw)
    json.dump(state, open(os.path.join(index_dir, STATE_FILE), "w"), indent=1)


def _delta_rows(url):
    """Parse one cumulative delta zip into corpus rows."""
    with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=180) as r:
        blob = r.read()
    rows = []
    z = zipfile.ZipFile(io.BytesIO(blob))
    for info in z.infolist():
        name = info.filename
        if not (name.endswith(".json") and os.path.basename(name).startswith("CVE-")):
            continue
        if info.file_size > MAX_ENTRY:
            continue
        try:
            rec = json.loads(z.read(name))
        except Exception:  # noqa: BLE001
            continue
        meta = rec.get("cveMetadata", {})
        cid = meta.get("cveId")
        if not cid:
            continue
        aff = ((rec.get("containers", {}) or {}).get("cna", {}) or {}).get("affected") or []
        rows.append((cid, meta.get("state", ""), meta.get("assignerShortName", ""),
                     (meta.get("datePublished") or "")[:10],
                     (aff[0].get("vendor") or "")[:120] if aff else "",
                     (aff[0].get("product") or "")[:120] if aff else ""))
    return rows


def apply_deltas(index_dir, dates_to_urls):
    """Upsert delta records into corpus.parquet, oldest day first.

    A record only ever moves forward (RESERVED -> PUBLISHED -> REJECTED), so a
    later row always wins on cve_id. product_cna.parquet is deliberately NOT
    rebuilt here: it is a slowly-changing map used only for corroboration, and
    rebuilding it from corpus.parquet would degrade it, since corpus keeps just
    the first affected product per record while the full index walks all of them.
    It refreshes on the next full baseline instead.
    """
    corpus_path = os.path.join(index_dir, "corpus.parquet")
    corpus = pd.read_parquet(corpus_path)
    before = len(corpus)
    applied = []
    for day in sorted(dates_to_urls):
        rows = _delta_rows(dates_to_urls[day])
        if not rows:
            print(f"  delta {day}: empty, skipped")
            continue
        delta = pd.DataFrame(rows, columns=corpus.columns)
        corpus = (pd.concat([corpus, delta], ignore_index=True)
                    .drop_duplicates(subset="cve_id", keep="last"))
        applied.append(day)
        print(f"  delta {day}: {len(rows):,} records")
    corpus.to_parquet(corpus_path, index=False)
    print(f"corpus {before:,} -> {len(corpus):,} records "
          f"({len(applied)} delta day(s) applied)")
    return corpus, applied


def refresh_corpus(baseline_path, index_dir, force=False):
    """Bring the corpus up to date as cheaply as correctness allows.

    Cold, or a gap wider than MAX_DELTA_GAP_DAYS, or `force`: pull the 583 MB
    baseline and rebuild the index. Otherwise apply the cumulative delta for
    every day from the indexed date through today, which is a few MB.

    Returns (corpus_df, product_cna_df).
    """
    os.makedirs(index_dir, exist_ok=True)
    baseline_date, baseline_url, deltas = survey_releases()
    state = _read_state(index_dir)
    have = state.get("corpus_date")
    indexed = os.path.exists(os.path.join(index_dir, "corpus.parquet"))

    schema = state.get("schema")

    gap = None
    if have and indexed:
        gap = (dt.date.fromisoformat(baseline_date) - dt.date.fromisoformat(have)).days

    stale_schema = indexed and schema != SCHEMA
    if (force or not indexed or stale_schema or gap is None
            or gap > MAX_DELTA_GAP_DAYS or gap < 0):
        why = ("forced" if force else "no index" if not indexed
               else f"schema {schema} != {SCHEMA}" if stale_schema
               else f"gap {gap}d > {MAX_DELTA_GAP_DAYS}d" if gap and gap > MAX_DELTA_GAP_DAYS
               else "clock moved backwards" if gap is not None and gap < 0 else "no state")
        print(f"full baseline rebuild ({why})")
        download_baseline(baseline_path, url=baseline_url, date=baseline_date)
        corpus, prod = build_index(baseline_path, index_dir)
        _write_state(index_dir, corpus_date=baseline_date, last_full=baseline_date,
                     schema=SCHEMA)
        return corpus, prod

    # Warm path. Today's delta is re-applied on every run within the day; it is
    # cumulative and the upsert is idempotent, so that is correct, not wasteful.
    wanted = {d: u for d, u in deltas.items() if d >= have}
    missing = [d for d in _days_between(have, baseline_date) if d not in deltas]
    if missing:
        print(f"full baseline rebuild (delta unavailable for {missing})")
        download_baseline(baseline_path, url=baseline_url, date=baseline_date)
        corpus, prod = build_index(baseline_path, index_dir)
        _write_state(index_dir, corpus_date=baseline_date, last_full=baseline_date,
                     schema=SCHEMA)
        return corpus, prod

    print(f"incremental refresh: indexed {have}, latest {baseline_date}, "
          f"{len(wanted)} delta day(s)")
    corpus, applied = apply_deltas(index_dir, wanted)

    # `applied` used to be discarded and corpus_date advanced to baseline_date
    # unconditionally, so a delta day that yielded zero rows was stepped over
    # permanently: `wanted` then selected `d >= have` from the new date, `missing`
    # only covers days absent from the release feed, so `gap` stayed 0 forever and
    # no health surface went red.
    #
    # That matters more than it sounds. The corpus is ground truth for reconcile,
    # Grader.grade, published_last_12mo and coverage, so a frozen corpus stops
    # detecting closures entirely: already-published records keep accruing
    # days_public against named CNAs while the site reports itself healthy.
    #
    # Deliberately NOT a hard failure here. The obvious guard, "raise when
    # `wanted` was non-empty and `applied` is empty", was written first and
    # false-positived immediately: `_delta_rows` returns [] both when the archive
    # layout changed AND when a day genuinely carried no records, and this
    # function cannot tell those apart. Blocking a publication on an ambiguous
    # plumbing signal is the class-2-as-class-1 mistake in PLAN 8b.
    #
    # The real protection is assert_corpus_current, which asks the data whether it
    # is current rather than asking the fetch loop whether it felt successful. It
    # cannot be fooled by a layout change, and it fires with an actionable
    # message. So: warn loudly here, block there.
    skipped = sorted(set(wanted) - set(applied))
    if skipped:
        print(f"  WARNING: {len(skipped)} delta day(s) contributed no records: "
              f"{skipped[:5]}. If the corpus is stale the freshness canary will "
              "fail the run; if it passes, those days were genuinely empty.")
    _write_state(index_dir, corpus_date=baseline_date, schema=SCHEMA)
    prod = pd.read_parquet(os.path.join(index_dir, "product_cna.parquet"))
    return corpus, prod


# How far behind today's date the newest record in the corpus may be before the
# corpus is treated as frozen. The CVE List publishes continuously, so a corpus
# whose newest record is older than this is not a quiet week, it is a stuck
# pipeline. Three days rather than one, to absorb a weekend plus a slow release.
MAX_CORPUS_LAG_DAYS = 3


def assert_corpus_current(corpus, today=None, max_lag_days=MAX_CORPUS_LAG_DAYS):
    """The one-line canary that catches the whole frozen-corpus class.

    Every other health surface can read green while the corpus is stale, because
    they all describe the feeds or the reservation endpoint and none of them
    describe the corpus. This is the only check that looks at the data itself and
    asks whether it is current.

    Returns the lag in days. Raises only when the newest record is beyond the
    tolerance, and says what to do about it.
    """
    today = today or dt.date.today().isoformat()
    if "date_published" not in getattr(corpus, "columns", []):
        return None
    dates = corpus["date_published"].dropna()
    dates = dates[dates.astype(str).str.len() >= 10]
    if dates.empty:
        raise SystemExit(
            "the corpus carries no usable date_published values, so its freshness "
            "cannot be established. Re-run with --reindex.")
    newest = max(str(d)[:10] for d in dates)
    lag = (dt.date.fromisoformat(today) - dt.date.fromisoformat(newest)).days
    if lag > max_lag_days:
        raise SystemExit(
            f"the newest CVE record in the corpus is dated {newest}, {lag} days "
            f"before {today}. The CVE List publishes continuously, so this is a "
            "frozen corpus rather than a quiet period. Because the corpus is "
            "ground truth for closure detection, publishing now would keep "
            "accruing days_public against named CNAs for records that have "
            "already published. Re-run with --reindex.")
    print(f"corpus freshness: newest record {newest}, {lag}d behind {today}")
    return lag


def _days_between(start, end):
    """Dates from `start` through `end` inclusive."""
    a, b = dt.date.fromisoformat(start), dt.date.fromisoformat(end)
    return [(a + dt.timedelta(days=i)).isoformat() for i in range((b - a).days + 1)]

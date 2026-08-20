"""
Standalone CVE List v5 corpus — the source of truth.

Downloads the official daily baseline release (github.com/CVEProject/cvelistV5)
and indexes every record into a compact parquet. No dependency on any sibling
repo or snapshot. Two products fall out of one pass over the corpus:

    corpus.parquet       cve_id, state, assigner, vendor, product   (membership + state)
    product_cna.parquet  product -> dominant assigner + confidence   (corroboration only)
"""
from __future__ import annotations

import io
import json
import os
import urllib.request
import zipfile
from collections import Counter, defaultdict

import pandas as pd

RELEASE_API = "https://api.github.com/repos/CVEProject/cvelistV5/releases/latest"
UA = {"User-Agent": "rbp-cves/1.0"}


def latest_baseline_url():
    with urllib.request.urlopen(urllib.request.Request(RELEASE_API, headers=UA), timeout=60) as r:
        rel = json.load(r)
    for a in rel["assets"]:
        if a["name"].endswith("all_CVEs_at_midnight.zip.zip"):
            return a["browser_download_url"], rel["tag_name"]
    raise RuntimeError("baseline asset not found in latest release")


def download_baseline(dest, url=None):
    """Download the latest baseline, refreshing when a NEWER release exists.

    Freshness is keyed on the release tag (stored in a sidecar), NOT merely file
    presence — otherwise the weekly job would re-use a frozen zip forever and the
    'source of truth' would silently go stale.
    """
    tag = None
    if url is None:
        url, tag = latest_baseline_url()
    tag_file = dest + ".tag"
    have_tag = open(tag_file).read().strip() if os.path.exists(tag_file) else None
    fresh = os.path.exists(dest) and os.path.getsize(dest) > 100_000_000 and have_tag == tag and tag is not None
    if fresh:
        print(f"baseline current (release {tag})")
        return dest
    print(f"downloading baseline (release {tag}) -> {dest}")
    urllib.request.urlretrieve(url, dest)
    if tag:
        open(tag_file, "w").write(tag)
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
                raise RuntimeError("baseline decompressed size exceeded ceiling — aborting")
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
        cna = (rec.get("containers", {}) or {}).get("cna", {}) or {}
        vendor = product = ""
        aff = cna.get("affected") or []
        if aff:
            vendor = (aff[0].get("vendor") or "")[:120]
            product = (aff[0].get("product") or "")[:120]
        rows.append((cid, state, assigner, vendor, product))
        # attribution signal: only trust PUBLISHED records with a real product
        if state == "PUBLISHED" and assigner:
            for a in aff:
                p = (a.get("product") or "").strip().lower()
                if p and p not in ("n/a", "unspecified", ""):
                    prod_cna[p][assigner] += 1
        n += 1
        if n % 50000 == 0:
            print(f"  indexed {n:,} records")
    corpus = pd.DataFrame(rows, columns=["cve_id", "state", "assigner", "vendor", "product"])
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

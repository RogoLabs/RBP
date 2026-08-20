"""
Owner attribution for RBP-hard (`DNE`) CVEs — hardened, v2.

Fixes from adversarial review:
  - Curated keywords are matched against the PRODUCT field only, on whole-token /
    whole-phrase boundaries — never as a substring of the free-text description
    (which produced glibc->"glib"->Red Hat @0.9). No description matching at all.
  - Bulk-reporter exclusion is case-normalized and the @huntrdev short name fixed
    (the old set had the wrong "@huntr_ai").
  - Corpus-derived owner requires a MAJORITY (share >= MIN_SHARE) with a margin
    over second place, not a plurality — a 3/20 top CNA is `unclassified`, not named.

Confidence is a match-quality signal; the report applies a further min-confidence
gate before any CNA is publicly named.
"""
from __future__ import annotations

import re
from collections import Counter, defaultdict

# CNAs that frequently report/reserve CVEs for third-party products but are rarely
# the canonical owner of a distro-shipped OSS component. Compared case-insensitively.
BULK_REPORTERS = {s.lower() for s in {
    "mitre", "VulDB", "ZDI", "VulnCheck", "Fluid Attacks", "DIVD", "securin", "SSD",
    "cisa", "Patchstack", "Wordfence", "@huntrdev", "huntr", "Zero Day Initiative",
    "Fortinet", "CERT-PL", "cert@ncsc.nl", "Wordfence",
}}

# Hand-verified project keyword -> owning CNA short name. Matched on product tokens.
CURATED = {
    "qemu": "redhat", "virtio": "redhat", "hw/uefi": "redhat", "hcd-ohci": "redhat",
    "spice": "redhat", "util-linux": "redhat", "libblkid": "redhat", "libmount": "redhat",
    "gimp": "redhat", "glib-networking": "redhat",
    "dnf": "redhat", "dnf5": "redhat", "libsolv": "redhat", "libdnf": "redhat",
    "rpm": "redhat", "rsyslog": "redhat", "graphicsmagick": "redhat",
    "libheif": "GitHub_M", "libde265": "GitHub_M", "freerdp": "GitHub_M",
    "c-ares": "GitHub_M", "vim": "GitHub_M", "netrw": "GitHub_M", "libvnc": "GitHub_M",
    "squid": "GitHub_M", "openvpn": "OpenVPN", "tls-crypt": "OpenVPN",
    # enterprise vendors (own CNAs) — corroborated only by their own feed at display time
    "windows": "microsoft", "office": "microsoft", "sharepoint": "microsoft",
    "exchange": "microsoft", "edge": "microsoft", ".net": "microsoft",
    "firefox": "mozilla", "thunderbird": "mozilla",
}

MIN_EVIDENCE = 3      # need at least this many corpus records for a product
MIN_SHARE = 0.60      # winning CNA must hold a clear majority, not a plurality
MIN_MARGIN = 2        # ... and lead second place by this many records
_GENERIC = {"core", "server", "client", "library", "tools", "common", "linux",
            "manager", "agent", "networking", "framework", "service", "utils"}


def _norm(s):
    return re.sub(r"[^a-z0-9]+", " ", (s or "").lower()).strip()


def _phrase_in(phrase, text):
    """True if `phrase` occurs in `text` on whole-token boundaries."""
    return re.search(r"(?:^| )" + re.escape(phrase) + r"(?:$| )", text) is not None


class Attributor:
    def __init__(self, corpus_df):
        counts = defaultdict(Counter)
        pub = corpus_df[corpus_df["state"] == "PUBLISHED"]
        for prod, cna in zip(pub["product"], pub["assigner"]):
            p = _norm(prod)
            if not p or p in ("n a", "unspecified") or (cna or "").lower() in BULK_REPORTERS:
                continue
            counts[p][cna] += 1
        self.map = {}
        for p, c in counts.items():
            if p in _GENERIC or len(p) < 4:
                continue
            # deterministic tiebreak (count desc, then name) so rebuilds are stable
            ranked = sorted(c.items(), key=lambda kv: (-kv[1], kv[0]))
            cna, n = ranked[0]
            tot = sum(c.values())
            second = ranked[1][1] if len(ranked) > 1 else 0
            share = n / tot
            if n >= MIN_EVIDENCE and share >= MIN_SHARE and (n - second) >= MIN_MARGIN:
                self.map[p] = (cna, round(share, 2))

    def attribute(self, product, description):
        pnorm = _norm(product)             # PRODUCT only — never the description
        if pnorm:
            ptokens = set(pnorm.split())
            for kw, cna in CURATED.items():
                kwn = _norm(kw)
                hit = (kwn in ptokens) if " " not in kwn else _phrase_in(kwn, pnorm)
                if hit:
                    return cna, 0.9, "curated"
            if pnorm in self.map:
                cna, share = self.map[pnorm]
                return cna, min(share, 0.85), "corpus-exact"
        return "unclassified", 0.0, "none"

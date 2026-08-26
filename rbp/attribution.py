"""
Product -> CNA map. CORROBORATION ONLY, this never names a CNA on its own.

Measured as a standalone fallback where block inference abstains: 20 decisions
at 85% precision, well under the ~97% floor in PLAN.md section 8. Naming is done
by inference.py; a match here only promotes an already-named row to the
corroborated tier (where both fired, they agreed 14/14).

Fixes from adversarial review:
  - Curated keywords are matched against the PRODUCT field only, on whole-token /
    whole-phrase boundaries, never as a substring of the free-text description
    (which produced glibc->"glib"->Red Hat @0.9). No description matching at all.
  - Bulk-reporter exclusion is case-normalized and the @huntrdev short name fixed
    (the old set had the wrong "@huntr_ai").
  - Corpus-derived owner requires a MAJORITY (share >= MIN_SHARE) with a margin
    over second place, not a plurality, a 3/20 top CNA is `unclassified`, not named.

Confidence is a match-quality signal only. It no longer gates naming, the
k-neighbour block gate does, so a high-confidence match here still yields no
name unless block inference independently reached the same CNA.
"""
from __future__ import annotations

import re
from collections import Counter, defaultdict

# CNAs that frequently report/reserve CVEs for third-party products but are rarely
# the canonical owner of a distro-shipped OSS component. Compared case-insensitively.
# One definition, imported by both the product map and block inference. It used
# to be private to this module, so the product map excluded these CNAs on the
# grounds that they are rarely the canonical owner of a distro-shipped component
# while block inference named them freely on the same rows.
#
# The WordPress-ecosystem CNAs are listed explicitly. Two of the worst rows this
# project produced named one of them on a Linux distribution vulnerability, and
# their scope is a plugin ecosystem that distro feeds never carry.
BULK_REPORTER_NAMES = {
    "mitre", "VulDB", "ZDI", "VulnCheck", "Fluid Attacks", "DIVD", "securin", "SSD",
    "cisa", "Patchstack", "Wordfence", "WPScan", "@huntrdev", "huntr",
    "Zero Day Initiative", "Fortinet", "CERT-PL", "cert@ncsc.nl",
}
BULK_REPORTERS = {s.lower() for s in BULK_REPORTER_NAMES}


def is_bulk_reporter(name):
    """Case and punctuation insensitive, because CNA short names vary by source."""
    return (name or "").strip().lower().replace("_", "").replace("-", "") in {
        b.replace("_", "").replace("-", "") for b in BULK_REPORTERS}

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
    # enterprise vendors (own CNAs): corroborated only by their own feed at display time
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
        pnorm = _norm(product)             # PRODUCT only, never the description
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


class NullAttributor:
    """Attributes nothing, for the posture where the site names nobody.

    A drop-in for Attributor with the same one method. classify._row calls
    `attribute()` for every row and stores the result as product_map_owner /
    _confidence / _method, all three of which are in publish.NAME_FIELDS and are
    therefore stripped before anything is published.

    So under v1 the real Attributor loads a 1.4 MB product-to-CNA parquet, scores
    every row against it, and hands back three fields whose entire journey ends
    in a de-namer. Not computing them is both faster and one fewer place a name
    can escape from. `abstain` is the same answer the real one gives when it does
    not know, so nothing downstream needs a branch.
    """

    def attribute(self, product, description):
        return None, 0.0, "abstain"

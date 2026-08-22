"""
The suppression lever (review item 4).

`templates/cna.html` promised a CNA that a wrong row, or one "under coordinated
disclosure", would be "corrected or suppressed on the next build", and that
"suppressions are counted publicly in aggregate". None of it existed:
`grep -rni suppress rbp/` returned nothing, and the pipeline recomputes `owner` by
block inference every run, so a manual correction could not have survived anyway.

Two inputs, one set.

    the committed list      snapshot-independent, durable, reviewed. Entries are
                            added by a human and survive every run.
    private advisories      GitHub private vulnerability reporting on this repo,
                            read each run. This is the fast path: a report filed
                            at 09:00 is honoured by the 12:00 build with nobody
                            in the loop.

WHY THE COMMITTED LIST HOLDS HASHES AND NOT CVE IDS

A plaintext list in a public repository is a file that says "somebody reported
CVE-2026-XXXX as being under embargo". That is strictly worse than the listing it
exists to remove: it converts a row that merely looked overdue into a row a third
party has confirmed is sensitive, and it is permanent, because git history is.

So entries are `HMAC-SHA256(key, cve_id)`. The pipeline holds every candidate ID
already, so it hashes each one and tests membership. Without the key the file
cannot be enumerated, and it cannot even be used to confirm a guess.

WHY A MISSING KEY FAILS THE BUILD

If the committed list is non-empty and no key is configured, the entries cannot be
evaluated, and the run would publish rows that are supposed to be withheld. That
is a false statement about a third party under embargo, which is PLAN 8b class 1:
refuse to publish. This is one of the few places in this codebase where a
configuration error should stop a publication, and the reason is that the
alternative is publishing the thing the lever exists to withhold.

WHY THE ADVISORY READ FAILING DOES *NOT* FAIL THE BUILD

The opposite direction. An unreadable endpoint is indistinguishable from "no
reports", and a token that quietly expires would silently switch the fast path off
forever. That is the failure shape this project has hit repeatedly, so it is
reported as a DEGRADED run instead: the banner is already on every page, and a
degraded run says its counts are not comparable. Loud, and it does not freeze a
publication four times a day over a credential.
"""
from __future__ import annotations

import hmac
import json
import os
import re
import subprocess
from hashlib import sha256

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)

# Where the committed hashes live. On `main`, not the data branch: this is
# reviewed input, not generated state.
DEFAULT_LIST = "suppressions.txt"

# Ceiling on how many rows a single run may auto-withhold from private advisories.
#
# There is deliberately no verification of who may report (review item 4: "an
# embargo report needs only the CVE ID and the word embargo, no detail"), which is
# right for a genuine embargo and does mean anyone with a GitHub account can
# remove a row. One advisory naming 500 IDs would empty the site, which is a
# denial of service against the project's entire purpose.
#
# So the fast path is capped. Beyond the cap the run still withholds the first
# MAX_AUTO ids, reports the overflow loudly, and the remainder needs a human entry
# in the committed list. The cap protects availability; the committed list keeps
# the ceiling from becoming a way to ignore a real mass report.
MAX_AUTO = 25


def _key():
    return (os.environ.get("RBP_SUPPRESS_KEY") or "").strip()


def digest(cve_id, key=None):
    """Keyed hash of one CVE ID. Case-normalised, so a lowercase entry works."""
    k = (key if key is not None else _key()).encode()
    return hmac.new(k, (cve_id or "").strip().upper().encode(), sha256).hexdigest()


def read_list(path=DEFAULT_LIST):
    """Committed hashes. Blank lines and `#` comments ignored."""
    if not os.path.exists(path):
        return []
    out = []
    for line in open(path):
        line = line.split("#", 1)[0].strip()
        if line:
            out.append(line.lower())
    return out


def from_advisories(repo="RogoLabs/RBP", token_env="RBP_ADVISORY_TOKEN"):
    """CVE IDs named in this repo's private security advisories.

    Returns `(ids, error)`. `error` is None on success and a short string when the
    endpoint could not be read, which the caller must surface as a degraded run
    rather than treat as an empty result.

    Uses the `gh` CLI so the token never passes through a URL or a shell argument.
    """
    token = (os.environ.get(token_env) or "").strip()
    if not token:
        return set(), f"{token_env} is not set; the fast path is off"
    env = dict(os.environ, GH_TOKEN=token)
    try:
        p = subprocess.run(
            ["gh", "api", "--paginate", f"repos/{repo}/security-advisories"],
            capture_output=True, text=True, timeout=60, env=env, check=False)
    except (OSError, subprocess.SubprocessError) as e:
        return set(), f"could not run gh: {e}"
    if p.returncode != 0:
        return set(), f"gh api failed: {(p.stderr or '').strip()[:160]}"
    try:
        items = json.loads(p.stdout or "[]")
    except ValueError as e:
        return set(), f"unparseable advisory response: {e}"
    if not isinstance(items, list):
        return set(), "advisory response was not a list"

    ids = set()
    for a in items:
        if not isinstance(a, dict):
            continue
        # Withdrawn advisories are retracted reports and must not keep a row
        # suppressed, or a withdrawn claim becomes permanent by accident.
        if a.get("withdrawn_at"):
            continue
        blob = " ".join(str(a.get(f) or "") for f in ("summary", "description"))
        ids |= {m.group(0).upper() for m in CVE_RE.finditer(blob)}
    return ids, None


# Warn this many days before the advisory token expires.
#
# The failure this exists to prevent: a fine-grained PAT expires, the advisory
# read starts failing, the run is marked degraded, and the degraded banner says
# reports are not being honoured. That is already far better than silence, but it
# is still an outage of the correction channel discovered after it began. GitHub
# returns the expiry date on every authenticated response, so the run can say
# "this stops working in nine days" while it still works.
EXPIRY_WARN_DAYS = 14


def token_expiry_days(token_env="RBP_ADVISORY_TOKEN", today=None):
    """Days until the advisory token expires, or None if unknown.

    Fine-grained PATs return `github-authentication-token-expiration` on every
    authenticated response. Classic tokens with no expiry omit it, in which case
    there is nothing to warn about and None is the honest answer.
    """
    token = (os.environ.get(token_env) or "").strip()
    if not token:
        return None
    env = dict(os.environ, GH_TOKEN=token)
    try:
        p = subprocess.run(["gh", "api", "-i", "/rate_limit"],
                           capture_output=True, text=True, timeout=30,
                           env=env, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    if p.returncode != 0:
        return None
    m = re.search(r"^github-authentication-token-expiration:\s*(\S+)",
                  p.stdout or "", re.I | re.M)
    if not m:
        return None
    import datetime as _dt
    try:
        exp = _dt.date.fromisoformat(m.group(1)[:10])
    except ValueError:
        return None
    ref = _dt.date.fromisoformat(today) if today else _dt.date.today()
    return (exp - ref).days


class Suppressions:
    """The effective suppression set for one run, plus what to publish about it."""

    def __init__(self, committed, auto_ids, error=None, key=None, capped=0,
                 expires_in=None):
        self.committed = set(committed or ())
        self.auto = set(auto_ids or ())
        self.error = error
        self.capped = capped
        self.expires_in = expires_in
        self._key = key

    def __contains__(self, cve_id):
        cid = (cve_id or "").strip().upper()
        if cid in self.auto:
            return True
        return bool(self.committed) and digest(cid, self._key) in self.committed

    def __len__(self):
        return len(self.committed) + len(self.auto)

    @property
    def report(self):
        """What goes in summary.json.

        Counts only, never IDs. Publishing which rows are withheld would undo the
        withholding, and publishing nothing at all would make the lever a way to
        quietly shrink the count, which is what the site already promised it was
        not. The aggregate is the whole accountability mechanism.
        """
        return {
            "committed": len(self.committed),
            "from_reports": len(self.auto),
            "capped": self.capped,
            "degraded": bool(self.error),
            "detail": self.error,
            # Days until the token that reads reports expires, when knowable.
            # Published so an impending outage of the correction channel is
            # visible before it happens rather than after.
            "token_expires_in_days": self.expires_in,
            "token_expiring": (self.expires_in is not None
                               and self.expires_in <= EXPIRY_WARN_DAYS),
        }


def load(list_path=DEFAULT_LIST, repo="RogoLabs/RBP", allow_remote=True):
    """Build the run's suppression set from both inputs."""
    committed = read_list(list_path)
    key = _key()
    if committed and not key:
        raise SystemExit(
            f"{list_path} holds {len(committed)} suppression entry(ies) and "
            "RBP_SUPPRESS_KEY is not set, so none of them can be evaluated. "
            "Refusing to publish: these rows are withheld because someone "
            "reported them as wrong or under embargo, and running without the "
            "key would publish every one of them. Set the secret, or empty the "
            "file deliberately.")

    auto, err, capped = set(), None, 0
    if allow_remote:
        found, err = from_advisories(repo=repo)
        if len(found) > MAX_AUTO:
            capped = len(found) - MAX_AUTO
            auto = set(sorted(found)[:MAX_AUTO])
            print(f"  SUPPRESSION CAP HIT: private advisories named "
                  f"{len(found)} CVE IDs, above the {MAX_AUTO} per-run ceiling. "
                  f"Withholding {MAX_AUTO}; {capped} not withheld and needing a "
                  f"reviewed entry in {list_path}.")
        else:
            auto = found
    expires_in = None if err else token_expiry_days()
    if expires_in is not None and expires_in <= EXPIRY_WARN_DAYS:
        print(f"  WARNING: the advisory token expires in {expires_in} day(s). "
              "When it does, embargo reports stop being honoured automatically. "
              "Rotate it before then.")
    s = Suppressions(committed, auto, error=err, key=key, capped=capped,
                     expires_in=expires_in)
    if err:
        print(f"  DEGRADED: suppression fast path unavailable ({err}). "
              "Reports filed through private advisories are NOT being honoured "
              "this run.")
    elif auto:
        print(f"  suppressing {len(auto)} row(s) from private advisory reports")
    if committed:
        print(f"  {len(committed)} committed suppression entry(ies) in force")
    return s

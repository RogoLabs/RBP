"""
Shared test setup: make the suite hermetic against the environment.

Every posture lever in this project is an environment variable, because they are
wired to repository variables so that changing one is a settings change rather than
a commit. That is right for operating the site and wrong for testing it: a test
whose result depends on an ambient variable is not a test.

This was not theoretical. `RBP_REHEARSE` was added to the workflow's top-level env
block, so it reached the `test` job and switched off the gate demotion that
`test_launching_below_gate_fails_closed_and_still_publishes` exists to assert. The
suite failed with "LAUNCHED, / is the dashboard" printed from a pytest temp
directory: the test being told by its environment to expect the opposite of its own
point. Scoping the variable to the build job fixed that instance; this fixes the
class.

Tests that need a lever set it themselves with monkeypatch and reload the module,
which several already do. This only guarantees the starting state.
"""
from __future__ import annotations

import os

import pytest

import _sitefixture

# Every environment variable that changes what the site publishes or how it decides
# to publish it. Cleared for the whole session so no test inherits an operator's
# shell or a workflow's env block.
POSTURE_VARS = (
    "RBP_LAUNCHED",     # front door: holding page or dashboard
    "RBP_REHEARSE",     # skips the coverage-gate demotion
    "RBP_EPOCH",        # zeroes the count from a date
    "RBP_PAUSE",        # incident switch
    "RBP_MIN_AGE_DAYS",  # the reportable buffer
    "RBP_SUPPRESS_KEY",  # keys the committed suppression list
    "RBP_ADVISORY_TOKEN",  # withdrawn, kept here so a stale value cannot resurface
    "GITHUB_TOKEN",     # the suppression lever's issue read
)


@pytest.fixture(autouse=True, scope="session")
def _hermetic_environment():
    """Clear every posture lever before the suite runs, and restore afterwards.

    Session-scoped rather than per-test, because the modules that read these do so
    at import time and a per-test clear would fight every monkeypatch.setenv the
    suite already relies on.
    """
    saved = {k: os.environ.get(k) for k in POSTURE_VARS}
    for k in POSTURE_VARS:
        os.environ.pop(k, None)
    # Reload the modules that capture these at import, so the cleared state is the
    # one under test rather than whatever was captured first.
    import importlib
    for mod in ("rbp.clock", "rbp.site"):
        try:
            importlib.reload(importlib.import_module(mod))
        except Exception:  # noqa: BLE001
            pass
    yield
    for k, v in saved.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v


# --------------------------------------------------------------------------
# the built site, for the tests that assert on OUTPUT
# --------------------------------------------------------------------------
#
# Session-scoped and hermetic. See tests/_sitefixture.py for why these exist:
# three modules used to find the site by looking for `./site` on disk and skip
# when it was absent, which is always, on every CI runner, including the job that
# gates the publication.
#
# In the top-level conftest rather than in a helper each module imports, so the
# fixtures are inherited by tests/render/ too and there is one build per posture
# per session rather than one per module.


@pytest.fixture(scope="session")
def built_site(tmp_path_factory):
    """The PRE-LAUNCH build: / is the holding page, the dashboard is
    /overview.html, robots.txt disallows everything.

    The default because it is the posture the site is actually in today, and
    because it is the one the copy and suppression assertions were written
    against: they glob the dashboard pages excluding index.html, which only means
    what they intend when index.html is the holding page.
    """
    return _sitefixture.build(tmp_path_factory.mktemp("prelaunch"), launched=False)


@pytest.fixture(scope="session")
def built_site_launched(tmp_path_factory):
    """The LAUNCHED build: / is the dashboard.

    Not a variant to check later. Several writers are gated on `launched`, so a
    pre-launch-only fixture cannot reach them at all.
    """
    return _sitefixture.build(tmp_path_factory.mktemp("launched"), launched=True)

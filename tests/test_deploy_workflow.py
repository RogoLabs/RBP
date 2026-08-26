"""
The publish workflow, asserted as configuration.

WHY THIS FILE EXISTS. `.github/workflows/deploy.yml` decides what reaches the
public site, and almost none of it is reachable from Python. The pipeline it runs
is tested to death; the twenty lines of YAML that take the pipeline's output and
put it on the internet were tested by running them.

That is survivable for most of the file, because most of it fails loudly. It is
not survivable for the parts that fail SILENTLY, and there is at least one: an
action input whose default drops files from the artefact. A build that publishes
less than it produced is green, fast, and wrong, which is the exact shape this
project treats as its worst failure.

So this file asserts the handful of workflow properties whose failure mode is a
missing file rather than a red check. It is deliberately not a schema check on the
whole workflow: a test that breaks every time someone edits a comment in YAML gets
deleted, and then the two assertions worth having go with it.
"""
from __future__ import annotations

import pathlib
import re

import pytest
import yaml

ROOT = pathlib.Path(__file__).parent.parent
WORKFLOWS = ROOT / ".github" / "workflows"
DEPLOY = WORKFLOWS / "deploy.yml"


def _steps(workflow, job):
    return yaml.safe_load(workflow.read_text())["jobs"][job]["steps"]


def _step_using(workflow, job, action):
    for s in _steps(workflow, job):
        if str(s.get("uses", "")).startswith(action):
            return s
    return None


# --------------------------------------------------------------------------
# the one that drops files
# --------------------------------------------------------------------------

def test_the_pages_artefact_includes_dotfiles():
    """/.well-known/security.txt is a dotfile directory, and the action excludes
    those by default.

    `actions/upload-pages-artifact@v4` added "hidden files (specifically dotfiles)
    will not be included in the artifact" and archives with `--exclude=.[^/]*`.
    The input that turns it back on is `include-hidden-files`, and it defaults to
    false. So bumping v3 to v4 or later without it removes
    /.well-known/security.txt from the published site: green build, no warning,
    and the only machine-readable contact route this site offers stops resolving.

    Nothing would have caught it. No test asserted security.txt is built either,
    until the one below.

    Version-aware rather than unconditional, because v3 has no such input and
    setting one it does not declare is itself an error.
    """
    step = _step_using(DEPLOY, "build", "actions/upload-pages-artifact@")
    assert step, "the build job no longer uploads a Pages artefact"
    major = int(re.search(r"@v(\d+)", step["uses"]).group(1))
    if major < 4:
        pytest.skip(f"upload-pages-artifact@v{major} predates the dotfile exclusion")
    assert step.get("with", {}).get("include-hidden-files") is True, (
        f"upload-pages-artifact@v{major} excludes dotfiles by default, so "
        "/.well-known/security.txt will not be published. Set "
        "`include-hidden-files: true`.")


def test_the_build_actually_writes_security_txt(built_site, built_site_launched):
    """The other half. The workflow can be told to ship dotfiles and still ship
    nothing if the build stopped producing one, and this file had no coverage at
    all before the bump that nearly deleted it.

    RFC 9116 requires Expires; a security.txt without it is not one. Contact is
    the entire point of the file.
    """
    for out in (built_site, built_site_launched):
        f = out / ".well-known" / "security.txt"
        assert f.exists(), f"{out.name} published no .well-known/security.txt"
        body = f.read_text()
        assert "Contact:" in body, "security.txt names no contact"
        assert "Expires:" in body, "security.txt has no Expires, required by RFC 9116"
        assert "rbp@rogolabs.net" in body


# --------------------------------------------------------------------------
# the levers that must not become defaults
# --------------------------------------------------------------------------

def test_the_deploy_job_is_held_by_the_pause_switch_and_the_dry_run():
    """Both are the difference between rehearsing a change and shipping it. An
    `if:` that stops matching is not a syntax error and the run goes green while
    publishing something a dry run was supposed to withhold."""
    deploy = yaml.safe_load(DEPLOY.read_text())["jobs"]["deploy"]
    cond = deploy.get("if", "")
    assert "RBP_PAUSE" in cond, "the incident switch no longer holds the deploy"
    assert "dry_run" in cond, "a dry run would now publish"


def test_persisting_state_is_gated_the_same_way_as_publishing():
    """State advancing on a run that published nothing makes the next run's
    week-over-week diff compare against a snapshot no reader ever saw."""
    step = next(s for s in _steps(DEPLOY, "build")
                if "Persist durable state" in str(s.get("name", "")))
    cond = step.get("if", "")
    assert "RBP_PAUSE" in cond and "dry_run" in cond, (
        "durable state advances on a paused or rehearsed run")


def test_the_publish_path_does_not_run_the_browser_or_the_linter():
    """PLAN.md 8e: "a browser on the COMMIT path only. Nothing new on the publish
    path." A layout suite or a lint rule must not be able to stop the site
    publishing, and the guarantee is that deploy.yml does not mention them."""
    # THE PARSED STEPS, not the file text. deploy.yml explains at length why the
    # browser and the linter are absent, so grepping the raw YAML matches the
    # comment that documents the guarantee and fails on a correct file. The
    # commands and the actions are what run.
    wf = yaml.safe_load(DEPLOY.read_text())
    executable = []
    for job in wf["jobs"].values():
        for step in job.get("steps", []):
            executable.append(str(step.get("run", "")))
            executable.append(str(step.get("uses", "")))
    body = "\n".join(executable).lower()
    assert "playwright" not in body, "the publish path installs or runs a browser"
    assert "ruff" not in body, "a lint failure can now stop a publication"
    assert any("--ignore=tests/render" in c for c in executable), (
        "the publish path collects tests/render, so a collection error there can "
        "stop a publication")


# --------------------------------------------------------------------------
# node 20 is deprecated on GitHub-hosted runners
# --------------------------------------------------------------------------

# The first major of each action that runs on the Node 24 runtime, checked
# against the published action.yml on 2026-08-26. Hand-maintained, and honestly
# so: the tests are offline, so this cannot be derived, and the thing that tells
# you a NEW deprecation has landed is the runner's own annotation rather than a
# unit test. What this catches is a DOWNGRADE, or a new step added at whatever
# major someone copied out of a stale example.
_MIN_MAJOR = {
    "actions/checkout": 5,
    "actions/setup-python": 6,
    "actions/cache": 5,
    "actions/deploy-pages": 5,
    # upload-pages-artifact is a composite action with no runtime of its own; it
    # is pinned at v5 for the nested upload-artifact, and its dotfile behaviour is
    # asserted separately above because that is the part that loses data.
    "actions/upload-pages-artifact": 5,
}


@pytest.mark.parametrize("workflow", sorted(WORKFLOWS.glob("*.yml")),
                         ids=lambda p: p.name)
def test_no_action_is_pinned_below_the_node_24_runtime(workflow):
    """Node 20 is deprecated and GitHub already forces those actions onto Node 24,
    which is a warning today and a failure later.

    Discovered from the file rather than listed, so a step added tomorrow is
    covered without anyone remembering to add it here.
    """
    found = re.findall(r"uses:\s*(actions/[\w-]+)@v(\d+)", workflow.read_text())
    assert found, f"{workflow.name} pins no actions; has this test stopped reading?"
    stale = [f"{name}@v{major} (needs v{_MIN_MAJOR[name]}+)"
             for name, major in ((n, int(m)) for n, m in found)
             if name in _MIN_MAJOR and major < _MIN_MAJOR[name]]
    assert not stale, f"{workflow.name} pins actions on the Node 20 runtime: {stale}"


@pytest.mark.parametrize("workflow", sorted(WORKFLOWS.glob("*.yml")),
                         ids=lambda p: p.name)
def test_every_action_used_has_a_known_minimum(workflow):
    """The guard on the guard above: it only checks actions it knows about, so an
    action absent from _MIN_MAJOR is silently exempt, which is how a list like
    this stops covering anything."""
    used = {n for n, _ in re.findall(r"uses:\s*(actions/[\w-]+)@v(\d+)",
                                     workflow.read_text())}
    unknown = sorted(used - set(_MIN_MAJOR))
    assert not unknown, (
        f"{workflow.name} uses {unknown}, which no entry in _MIN_MAJOR covers, so "
        "the Node runtime check above skips them silently")


# --------------------------------------------------------------------------
# the runner has to be able to run the suite at all
# --------------------------------------------------------------------------
#
# This section is here rather than somewhere about packaging because its failure
# mode is the same as everything else in this file: deploy.yml's `test` job runs
# `pip install -r requirements-dev.txt` and then the suite, and that suite gates
# the publication. An import nobody declared is not a failing test, it is a
# COLLECTION error, which stops the whole run and therefore the publish.
#
# That happened. tests/test_deploy_workflow.py was written against a PyYAML that
# was installed on one machine as a transitive dependency of jupyter-events. 762
# tests passed locally and the runner reported "1 error in 1.66s".

_REQUIREMENTS = ("requirements.txt", "requirements-dev.txt", "requirements-browser.txt")

def _first_party():
    """Modules that live in this repo, so importing one proves nothing about
    packaging. Derived from the tree rather than listed: the hand-written version
    missed `test_focus`, which tests/render imports as a sibling, and a list that
    needs updating whenever a test module is added is a list that will report a
    false failure and then get deleted."""
    names = {"rbp", "tests"}
    for path in list((ROOT / "rbp").rglob("*.py")) + list((ROOT / "tests").rglob("*.py")):
        names.add(path.stem)
    return names


def _declared():
    """Distribution names named in any requirements file, lowercased."""
    names = set()
    for f in _REQUIREMENTS:
        for line in (ROOT / f).read_text().splitlines():
            line = line.split("#")[0].strip()
            if not line or line.startswith("-"):
                continue
            names.add(re.split(r"[<>=!\[;]", line)[0].strip().lower())
    return names


def _third_party_imports():
    """Top-level modules imported anywhere in rbp/ or tests/, minus stdlib."""
    import ast
    import sys
    mods = set()
    for path in list((ROOT / "rbp").rglob("*.py")) + list((ROOT / "tests").rglob("*.py")):
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.Import):
                mods |= {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom) and not node.level and node.module:
                mods.add(node.module.split(".")[0])
    return {m for m in mods
            if m not in sys.stdlib_module_names and m not in _first_party()}


def test_every_imported_package_is_declared_in_a_requirements_file():
    """An import that resolves only because something else pulled it in.

    Mapped import name to distribution with importlib.metadata, because the two
    differ often enough to matter here: `yaml` is PyYAML and `jinja2` is Jinja2,
    so a check on the import name alone would report both as undeclared and get
    switched off.
    """
    from importlib.metadata import packages_distributions
    dists = packages_distributions()
    declared = _declared()
    undeclared = []
    for mod in sorted(_third_party_imports()):
        # The distribution that provides it, as installed here. Unknown means the
        # module is not importable in this environment at all, which the suite
        # would already be failing on.
        for dist in dists.get(mod, [mod]):
            if dist.lower() in declared:
                break
        else:
            undeclared.append(f"{mod} (provided by {dists.get(mod, ['?'])})")
    assert not undeclared, (
        "these are imported by the suite and named in no requirements file, so "
        "they work here and fail on a clean runner as a COLLECTION error, which "
        f"stops the publish rather than one test: {undeclared}")

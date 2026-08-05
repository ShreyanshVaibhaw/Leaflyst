"""Properties of the CI workflow itself (plansecurity SP-8).

The pipeline is the thing that enforces every other gate, so a bad edit to it
disables checks silently: the run still goes green, and nothing says a scanner
stopped being blocking.

GitHub enforces SHA pinning at dispatch through the repository's allowed-actions
policy, so a tag-pinned action is already refused before any job starts. That
refusal arrives as `startup_failure` with no diff context. These assertions fail
in review instead, on the line that caused it - and they cover the properties the
platform policy does not check at all, like whether a job quietly granted itself
write access or made a scanner non-blocking.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

WORKFLOW_DIR = Path(__file__).resolve().parents[3] / ".github" / "workflows"
WORKFLOWS = sorted(WORKFLOW_DIR.glob("*.yml"))

#: A full 40-character commit SHA. Anything shorter is a tag or a branch.
PINNED = re.compile(r"^[^@]+@[0-9a-f]{40}$")

#: The release a pin corresponds to, e.g. `# v7.0.1`. Any comment at all would
#: satisfy a bare "has a comment" check - `# temporary` tells a reviewer nothing
#: about which release the SHA is, which is the entire point of the comment.
VERSION_COMMENT = re.compile(r"#\s*v?\d+(\.\d+)*")


def _steps(workflow: dict) -> list[tuple[str, dict]]:
    return [
        (job_name, step)
        for job_name, job in workflow.get("jobs", {}).items()
        for step in job.get("steps", [])
    ]


def _external_uses(workflow: dict) -> list[tuple[str, str]]:
    """Every third-party reference, from steps AND from job-level `uses`.

    A job can call a reusable workflow with `jobs.<id>.uses`, which has no
    `steps` at all - so a check that only walks steps would let a tag-pinned
    reusable workflow through while reporting everything as pinned. Local calls
    (`./.github/workflows/...`) are excluded: they are this repository's own
    code at this repository's own commit.
    """
    found = [
        (job, str(step["uses"]))
        for job, step in _steps(workflow)
        if "uses" in step
    ]
    found += [
        (job, str(spec["uses"]))
        for job, spec in workflow.get("jobs", {}).items()
        if "uses" in spec
    ]
    return [(job, uses) for job, uses in found if not uses.startswith("./")]


@pytest.fixture(scope="module")
def workflows() -> dict[Path, dict]:
    assert WORKFLOWS, f"no workflows found under {WORKFLOW_DIR}"
    return {p: yaml.safe_load(p.read_text(encoding="utf-8")) for p in WORKFLOWS}


def test_every_action_is_pinned_to_a_commit(workflows) -> None:
    """A tag is a mutable pointer: whoever can move it runs their code with this
    workflow's token. That is the whole shape of the tj-actions/changed-files
    compromise."""
    unpinned = [
        f"{path.name}:{job} -> {uses}"
        for path, workflow in workflows.items()
        for job, uses in _external_uses(workflow)
        if not PINNED.match(uses)
    ]
    assert not unpinned, f"actions not pinned to a full commit SHA: {unpinned}"


def test_every_pin_carries_a_readable_version(workflows) -> None:
    """A bare SHA is unreviewable. The comment is what lets a human see that a
    pin moved from v7.0.1 to something else - so it has to name a release, not
    merely exist."""
    missing = [
        line.strip()
        for path in workflows
        for line in path.read_text(encoding="utf-8").splitlines()
        if "uses:" in line
        and "@" in line
        and not line.strip().startswith("#")
        and not VERSION_COMMENT.search(line)
    ]
    assert not missing, f"pinned actions without a version comment: {missing}"


def test_the_default_token_is_read_only(workflows) -> None:
    """A workflow token that can write to the repository is a supply-chain
    credential."""
    for path, workflow in workflows.items():
        assert workflow.get("permissions") == {"contents": "read"}, (
            f"{path.name} does not declare least-privilege default permissions"
        )


def test_no_job_grants_itself_write_access(workflows) -> None:
    """A job-level block silently overrides the workflow default, so the header
    above is not evidence on its own."""
    widened = [
        f"{path.name}:{job} -> {perms}"
        for path, workflow in workflows.items()
        for job, spec in workflow.get("jobs", {}).items()
        if (perms := spec.get("permissions")) is not None
        and perms != {"contents": "read"}
    ]
    assert not widened, f"jobs widening the default token: {widened}"


def test_no_workflow_reads_a_secret(workflows) -> None:
    """These workflows run on pull requests, including from forks eventually.

    Nothing here needs a secret, so nothing here should be able to leak one. The
    check is on the raw text rather than the parsed tree because a secret can be
    referenced from any expression position.
    """
    # Both spellings: `secrets.NAME` and `secrets['NAME']`. Matching only the
    # dotted form leaves the index form as a way in.
    reference = re.compile(r"secrets\s*(\.|\[)")
    users = [
        f"{path.name}:{line.strip()}"
        for path in workflows
        for line in path.read_text(encoding="utf-8").splitlines()
        if reference.search(line)
    ]
    assert not users, f"workflow reads a secret: {users}"


def test_the_checkout_token_is_not_persisted(workflows) -> None:
    """checkout leaves the token in .git/config by default, and every job here
    then executes checked-out code."""
    persisted = [
        f"{path.name}:{job}"
        for path, workflow in workflows.items()
        for job, step in _steps(workflow)
        if "actions/checkout" in str(step.get("uses", ""))
        and (step.get("with") or {}).get("persist-credentials") is not False
    ]
    assert not persisted, f"checkout persists credentials in: {persisted}"


def test_no_security_step_is_made_non_blocking(workflows) -> None:
    """`continue-on-error` turns a gate into a report.

    A scanner that runs, finds something, and does not stop the merge is worse
    than no scanner: it produces the paperwork of a control without the control,
    and the run is green either way.
    """
    soft = [
        f"{path.name}:{job} -> {step.get('name', step.get('uses'))}"
        for path, workflow in workflows.items()
        for job, step in _steps(workflow)
        if step.get("continue-on-error")
    ]
    # A job-level flag makes EVERY step in it advisory at once, so checking only
    # steps would miss the broader version of the same mistake.
    soft += [
        f"{path.name}:{job} (whole job)"
        for path, workflow in workflows.items()
        for job, spec in workflow.get("jobs", {}).items()
        if spec.get("continue-on-error")
    ]
    assert not soft, f"steps that cannot fail the run: {soft}"

    swallowed = [
        f"{path.name}:{line.strip()}"
        for path in workflows
        for line in path.read_text(encoding="utf-8").splitlines()
        # `|| { ...; exit 1; }` is the negative-control idiom and does the
        # opposite - it turns a missing signal INTO a failure.
        if "|| true" in line or line.rstrip().endswith("|| :")
    ]
    assert not swallowed, f"commands whose failure is discarded: {swallowed}"


def test_the_negative_control_job_still_covers_every_gate(workflows) -> None:
    """The job proving each gate fires is itself worth pinning.

    Deleting a probe is a one-line change that leaves CI green, and the thing it
    was proving goes back to being an unverified assumption.
    """
    for _path, workflow in workflows.items():
        job = workflow.get("jobs", {}).get("gate-negative-controls")
        if job is None:
            continue
        names = " ".join(step.get("name", "") for step in job["steps"]).lower()
        for gate in ("vulnerable dependency", "leaked credential",
                     "misconfigured container", "schema drift", "skipped"):
            assert gate in names, f"the negative-control job no longer probes: {gate}"
        return
    pytest.fail("no workflow defines gate-negative-controls")

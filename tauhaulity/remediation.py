"""Hardening actions: what to do next, in priority order, from measured evidence.

A finding without an action is a complaint. This module derives the actionable
next step from the evidence each pillar actually produced, so the dossier closes
with a short ordered list: what to do now, what can be automated, and what a
human has to decide. Actions come from measured state, never from a static
checklist, and a clean context yields an empty tuple because silence is a valid
answer.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from tauhaulity.core.contracts import ScanContext, status_severity
from tauhaulity.core.scorecard import Scorecard

PRIORITY_NOW: Final[int] = 1
PRIORITY_SOON: Final[int] = 2
PRIORITY_LATER: Final[int] = 3


@dataclass(frozen=True, slots=True)
class Action:
    """One recommended hardening step.

    Attributes:
        id: Stable kebab-case identifier so a later diff can track the action.
        title: Short imperative summary.
        detail: What the action does and why it matters here.
        command: Runnable command, or an empty string when none exists.
        manual: True when the step needs a human decision or platform work.
        priority: 1 do now, 2 do soon, 3 when convenient.
        pillar: Pillar number the action came from.
        effort: minutes, hour or session.
        reference: Framework identifier when the mapping module is available.
    """

    id: str
    title: str
    detail: str
    command: str
    manual: bool
    priority: int
    pillar: int
    effort: str
    reference: str = ""


def _ref(pillar: int, status: str) -> str:
    """Return the first framework identifier for a pillar, or an empty string.

    The mapping module is optional: a checkout without it must still produce
    actions, just without the framework column.
    """

    try:
        from tauhaulity.standards import refs_for
    except ImportError:
        return ""
    refs = refs_for(pillar, status)
    return refs[0].identifier if refs else ""


def _evidence(ctx: ScanContext, pillar: int) -> str:
    """Return the lowercase evidence string of a pillar, or an empty string."""

    finding = ctx.findings.get(pillar)
    return finding.detail.lower() if finding is not None else ""


def actions_for(ctx: ScanContext, scorecard: Scorecard | None = None) -> tuple[Action, ...]:
    """Derive the ordered hardening actions for a finished scan.

    Parameters:
        ctx: Scan context holding the pillar findings.
        scorecard: Optional scorecard used to order actions by the points a
            pillar actually cost, so a project fixes what is expensive first.

    Returns:
        Actions ordered by priority, then by the points the pillar lost, then by
        pillar number, which keeps the order stable for the same input.
    """

    actions: list[Action] = []
    for finding in ctx.findings.values():
        number = finding.pillar
        status = finding.status
        severity = status_severity(status)
        evidence = _evidence(ctx, number)
        priority = PRIORITY_NOW if severity == 2 else PRIORITY_SOON if severity == 1 and finding.risk >= 3.0 else PRIORITY_LATER
        reference = _ref(number, status)

        if number == 11 and "hook gate missing" in evidence:
            actions.append(
                Action(
                    id="install-git-gate",
                    title="Install the pre-commit credential gate",
                    detail="The scanner found no gate, so a credential can still be committed and pushed.",
                    command="tauhaulity hook install",
                    manual=False,
                    priority=PRIORITY_NOW,
                    pillar=11,
                    effort="minutes",
                    reference=reference,
                )
            )
        if number == 11 and ("candidate" in evidence and "0 credential candidate" not in evidence):
            actions.append(
                Action(
                    id="rotate-exposed-credential",
                    title="Rotate every exposed credential",
                    detail=(
                        "A credential is present in the tree or in git history. Rotating it at the issuer is the only "
                        "remedy that matters; deleting the file does not remove it from the object database."
                    ),
                    command="",
                    manual=True,
                    priority=PRIORITY_NOW,
                    pillar=11,
                    effort="hour",
                    reference=reference,
                )
            )
            actions.append(
                Action(
                    id="record-fixture-baseline",
                    title="Record reviewed fixtures in the baseline",
                    detail="After rotation, accept only the findings that are known test fixtures so new leaks stand out.",
                    command="tauhaulity baseline .",
                    manual=False,
                    priority=PRIORITY_SOON,
                    pillar=11,
                    effort="minutes",
                    reference=reference,
                )
            )
        if number == 6 and ("dangerous_api" in evidence or "pickle" in evidence or "pyc" in evidence):
            actions.append(
                Action(
                    id="review-unsafe-call-site",
                    title="Review the unsafe call sites the scanner named",
                    detail=(
                        "Each site is a deserialization, shell, eval or extraction call. Fix the ones that take "
                        "untrusted input; for the ones that are guarded by design, record the review so the finding "
                        "stops failing the gate: tauhaulity suppress list ."
                    ),
                    command="tauhaulity suppress list .",
                    manual=True,
                    priority=PRIORITY_NOW if severity == 2 else PRIORITY_SOON,
                    pillar=6,
                    effort="hour",
                    reference=reference,
                )
            )
        if number == 10 and (".pth" in evidence or "record" in evidence or "startup" in evidence):
            actions.append(
                Action(
                    id="rebuild-virtualenv",
                    title="Rebuild the virtual environment from a reviewed lock file",
                    detail=(
                        "An installed file does not match its recorded digest, or a startup hook executes code. "
                        "Recreating the environment from a pinned lock file is safer than repairing it in place."
                    ),
                    command="tauhaulity venv-check .",
                    manual=True,
                    priority=PRIORITY_NOW,
                    pillar=10,
                    effort="hour",
                    reference=reference,
                )
            )
        if number == 9 and "0.0.0.0" in evidence:
            actions.append(
                Action(
                    id="bind-loopback",
                    title="Bind development services to the loopback address",
                    detail=(
                        "A listening socket is bound to every interface. On a shared or untrusted network that "
                        "exposes the service beyond this machine."
                    ),
                    command="tauhaulity ports --json",
                    manual=True,
                    priority=PRIORITY_SOON,
                    pillar=9,
                    effort="minutes",
                    reference=reference,
                )
            )
        if number == 1 and ("no baseline recorded" in evidence or "not escalated" in evidence):
            actions.append(
                Action(
                    id="capture-memory-baseline",
                    title="Capture a known-good memory baseline",
                    detail=(
                        "Without a baseline the pillar can only describe the current map. A baseline lets a later "
                        "scan prove that a loaded module image changed after startup."
                    ),
                    command="tauhaulity baseline --memory",
                    manual=False,
                    priority=PRIORITY_SOON,
                    pillar=1,
                    effort="minutes",
                    reference=reference,
                )
            )
        if number == 8 and "0 canary" in evidence:
            actions.append(
                Action(
                    id="arm-decoy-traps",
                    title="Arm decoy traps and watch the tree",
                    detail=(
                        "Deploy honeytokens so the first read of a decoy credential is recorded, and run the watcher "
                        "on a kernel notification backend to catch a destructive burst early."
                    ),
                    command="tauhaulity honeytoken deploy .",
                    manual=False,
                    priority=PRIORITY_SOON,
                    pillar=8,
                    effort="minutes",
                    reference=reference,
                )
            )
        if number == 5 and status == "EXPOSED":
            actions.append(
                Action(
                    id="pin-secret-memory",
                    title="Pin secret buffers or move keys out of the process",
                    detail=(
                        "Page locking is unavailable on this host, so a resident secret can reach swap or a crash "
                        "dump. Prefer a platform keyring or an external secret store."
                    ),
                    command="",
                    manual=True,
                    priority=PRIORITY_SOON,
                    pillar=5,
                    effort="session",
                    reference=reference,
                )
            )
        if number == 2 and severity >= 1:
            actions.append(
                Action(
                    id="harden-syscall-boundary",
                    title="Tighten the syscall boundary for your own services",
                    detail=(
                        "The host reports a weak syscall policy. A seccomp profile on Linux or an Exploit Protection "
                        "mitigation policy on Windows is platform work outside a scanner's reach."
                    ),
                    command="",
                    manual=True,
                    priority=PRIORITY_LATER,
                    pillar=2,
                    effort="session",
                    reference=reference,
                )
            )
        if number == 7 and "capture=yes" in evidence:
            actions.append(
                Action(
                    id="opt-in-egress-enforcement",
                    title="Decide whether outbound inspection should block, not only record",
                    detail=(
                        "The pre-TLS hook observes cleartext and never blocks. Enforcement is an explicit policy "
                        "decision, opt in with TAUHAULITY_ENFORCE=1 once you accept the false positives."
                    ),
                    command="",
                    manual=True,
                    priority=PRIORITY_LATER,
                    pillar=7,
                    effort="hour",
                    reference=reference,
                )
            )

    lost: dict[int, float] = {}
    if scorecard is not None:
        lost = {pillar.number: pillar.points_lost for pillar in scorecard.pillars}
    ordered = sorted(actions, key=lambda item: (item.priority, -lost.get(item.pillar, 0.0), item.pillar, item.id))
    seen: set[str] = set()
    unique: list[Action] = []
    for action in ordered:
        if action.id in seen:
            continue
        seen.add(action.id)
        unique.append(action)
    return tuple(unique)


def render_actions(actions: tuple[Action, ...], *, width: int = 100) -> list[str]:
    """Render actions as plain text lines.

    Parameters:
        actions: Actions to render.
        width: Maximum line width; the detail wraps to it.

    Returns:
        Renderable lines, empty when there is nothing to do.
    """

    if not actions:
        return ["no hardening action required by the current findings"]
    lines: list[str] = []
    for index, action in enumerate(actions, start=1):
        automation = action.command if action.command else "manual step"
        lines.append(f"{index}. [{action.effort}] {action.title}  ({automation})")
        detail = action.detail
        while len(detail) > width:
            cut = detail[:width].rsplit(" ", 1)[0]
            lines.append(f"   {cut}")
            detail = detail[len(cut) :].strip()
        if detail:
            lines.append(f"   {detail}")
    return lines


def summarize(actions: tuple[Action, ...]) -> str:
    """Return one line describing the action list."""

    if not actions:
        return "0 action(s): nothing to harden from the current findings"
    now = sum(1 for action in actions if action.priority == PRIORITY_NOW)
    automated = sum(1 for action in actions if not action.manual)
    return f"{len(actions)} action(s): {now} to do now, {automated} automated"

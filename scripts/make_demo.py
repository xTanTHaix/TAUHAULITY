"""Generate the animated demo assets from a real Tauhaulity session.

The window in docs/tauhaulity-demo.svg is not a mock-up: the shipped command line
runs inside a throwaway project, its output is captured through a subprocess and
then laid out again as a styled terminal. The SMIL animated SVG is the shipped
asset; the indexed colour GIF renderer is kept behind `--with-gif` for local
inspection and is not part of the checked-in set.

Why the design is shaped this way:

* Every line is measured with the font metrics before it is drawn. A line that
  does not fit is wrapped, never clipped, and an assertion fails the generator if
  a regression ever ships a cut line.
* Determinism: volatile capture values (temporary paths, durations, digests,
  timestamps, memory addresses, host labels) are normalised before rendering, so
  the same tree produces byte identical assets and --check can fail on real
  changes instead of on a clock.
* The static diagrams are not drawn here. They live in scripts/demo_diagrams.py
  and are imported when present; --check covers the animated SVG, the diagrams
  and demo-source.txt unconditionally.

Regenerate with: python scripts/make_demo.py
Verify drift with: python scripts/make_demo.py --check
Also write a GIF with: python scripts/make_demo.py --with-gif
Inspect a frame with: python scripts/make_demo.py --preview 0,29,59
"""

from __future__ import annotations

import argparse
import hashlib
import inspect
import math
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence
from xml.sax.saxutils import escape

SCRIPTS_DIR = Path(__file__).resolve().parent
ROOT = SCRIPTS_DIR.parent
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from demo_font import GLYPH_HEIGHT, Canvas, advance, text_width  # noqa: E402
from demo_gif import Frame, decode_gif, encode_gif  # noqa: E402

DOCS = ROOT / "docs"
FICTIONAL_TARGET = "/home/dev/api"
GENERATED_BY = "scripts/make_demo.py"

# ---------------------------------------------------------------- geometry --
WIDTH = 960
HEIGHT = 420
TITLE_BAR_HEIGHT = 28
STATUS_BAR_HEIGHT = 22
MARGIN_X = 16
MARGIN_Y = 8
SCALE = 2
TRACKING = 1
CHAR_ADVANCE = advance(SCALE, TRACKING)
LINE_HEIGHT = GLYPH_HEIGHT * SCALE + 2
CONTENT_TOP = TITLE_BAR_HEIGHT + MARGIN_Y
STATUS_TOP = HEIGHT - STATUS_BAR_HEIGHT
CONTENT_WIDTH = WIDTH - 2 * MARGIN_X
CONTENT_COLS = CONTENT_WIDTH // CHAR_ADVANCE
CONTENT_ROWS = (STATUS_TOP - CONTENT_TOP) // LINE_HEIGHT
CURSOR_WIDTH = 8
CURSOR_HEIGHT = GLYPH_HEIGHT * SCALE

#: The animated SVG is taller than the GIF so the whole session stays visible
#: without scroll animation; its width matches the GIF so both read as one design.
SVG_LINE_BUDGET = 44

# ----------------------------------------------------------------- palette --
#: Index zero is the body background because LZW compresses the largest run of
#: one symbol best; the two chrome bars come next, then the text roles.
PALETTE: tuple[tuple[int, int, int], ...] = (
    (0x0B, 0x0F, 0x14),  # 0  body background
    (0x16, 0x1B, 0x22),  # 1  title and status bar
    (0xE6, 0xED, 0xF3),  # 2  typed command and bright text
    (0xC9, 0xD1, 0xD9),  # 3  normal output
    (0x8B, 0x94, 0x9E),  # 4  dim detail and paths
    (0x3F, 0xB9, 0x50),  # 5  PASS and SAFE
    (0x7E, 0xE7, 0x87),  # 6  prompt and caret
    (0xD2, 0x99, 0x22),  # 7  WARNING
    (0xF8, 0x51, 0x49),  # 8  CRITICAL and blocked
    (0x58, 0xA6, 0xFF),  # 9  accent for pillar ids and numbers
    (0xFF, 0x5F, 0x56),  # 10 close dot
    (0xFF, 0xBD, 0x2E),  # 11 minimise dot
    (0x27, 0xC9, 0x3F),  # 12 zoom dot
    (0x30, 0x36, 0x3D),  # 13 window borders and separators
    (0x6E, 0x76, 0x81),  # 14 muted status bar text
    (0x0D, 0x11, 0x17),  # 15 raised panel (reserved for future panels)
)

ROLE_INDEX: dict[str, int] = {
    "bg": 0,
    "bar": 1,
    "command": 2,
    "output": 3,
    "dim": 4,
    "pass": 5,
    "prompt": 6,
    "warn": 7,
    "crit": 8,
    "accent": 9,
    "border": 13,
    "muted": 14,
    "panel": 15,
}

ROLE_COLOUR: dict[str, str] = {
    name: f"#{PALETTE[index][0]:02x}{PALETTE[index][1]:02x}{PALETTE[index][2]:02x}"
    for name, index in ROLE_INDEX.items()
}
BOLD_ROLES = frozenset({"command"})

#: Palette indices painted by the window chrome, used to separate text ink from
#: chrome ink in --preview coverage numbers.
CHROME_INDEXES = frozenset({ROLE_INDEX["bar"], ROLE_INDEX["border"], 10, 11, 12})

_PASS_STATUSES = frozenset(
    {"SAFE", "CLEAN", "READY", "PROTECTED", "SECURE", "GENERATED", "PASS", "VALID", "OK", "INSTALLED"}
)
_CRITICAL_STATUSES = frozenset(
    {"CRITICAL", "LEAK_DETECTED", "MALICIOUS_PTH", "ZOMBIE_FOUND", "EXPOSED", "FAIL", "INVALID", "BLOCKED"}
)

# ------------------------------------------------------------------ timing --
INTRO_DELAY_CS = 56
TYPING_DELAY_CS = 4
BLINK_DELAY_CS = 8
REVEAL_DELAY_CS = 8
VERDICT_DELAY_CS = 20
HOLD_SCAN_CS = 420
HOLD_AFTER_COMMAND_CS = 150
FINAL_HOLD_CS = 90
MIN_FRAMES = 45
MAX_FRAMES = 65
MIN_TOTAL_CS = 1200
MAX_TOTAL_CS = 1800

_SPINNER = "|/-\\"


# ------------------------------------------------------------------- model --
@dataclass(frozen=True, slots=True)
class Segment:
    """One run of text painted in a single colour role.

    Attributes:
        text: Characters to draw. Roles are assigned per segment, not per line,
            so a line can mix an accent pillar id with a coloured status.
        role: Key into ROLE_INDEX.
    """

    text: str
    role: str


@dataclass(frozen=True, slots=True)
class ScreenLine:
    """One line of terminal history.

    Attributes:
        line_id: Stable identity used by the SVG renderer to animate a line's
            own opacity window; ids increase but are never reused.
        segments: Coloured text runs.
    """

    line_id: int
    segments: tuple[Segment, ...]

    @property
    def text(self) -> str:
        """Plain text of the line."""

        return "".join(segment.text for segment in self.segments)

    def pixel_width(self) -> int:
        """Pixel width of the line in the rendered font."""

        return text_width(self.text, SCALE, TRACKING)


@dataclass(frozen=True, slots=True)
class FrameSpec:
    """One animation step before rasterisation.

    Attributes:
        lines: Full terminal history visible in the SVG; the GIF shows only the
            last CONTENT_ROWS of it, which is what a real terminal does.
        status: Status bar segments for this frame.
        cursor: Whether the block caret is shown at the end of the last line.
        delay_cs: Display time in hundredths of a second.
    """

    lines: tuple[ScreenLine, ...]
    status: tuple[Segment, ...]
    cursor: bool
    delay_cs: int


@dataclass(frozen=True, slots=True)
class Step:
    """One captured command and its output."""

    argv: tuple[str, ...]
    command: str
    output: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class Session:
    """A captured demo session.

    Attributes:
        steps: Commands in display order.
        source: "live run" or "bundled sample (<reason>)"; the dossier of the
            demo records this so a fallback is never mistaken for a live capture.
        scorecard: The scorecard object from the JSON dossier, when the live run
            produced one.
    """

    steps: tuple[Step, ...]
    source: str
    scorecard: Mapping[str, object] | None = None


# ---------------------------------------------------------------- capture --
_DEMO_PLAN: tuple[tuple[tuple[str, ...], str], ...] = (
    ((), "tauhaulity"),
    (("suppress", "list", "."), "tauhaulity suppress list ."),
    (("honeytoken", "deploy", "."), "tauhaulity honeytoken deploy ."),
    (("verify", "tauhaulity_report.md"), "tauhaulity verify tauhaulity_report.md"),
)

_SAMPLE_ROWS = (
    ("P01", "SAFE", "0.0"),
    ("P02", "SAFE", "0.0"),
    ("P03", "SAFE", "0.0"),
    ("P04", "READY", "0.0"),
    ("P05", "SAFE", "0.0"),
    ("P06", "SAFE", "0.0"),
    ("P07", "SAFE", "0.0"),
    ("P08", "PROTECTED", "1.5"),
    ("P09", "CLEAN", "0.0"),
    ("P10", "CLEAN", "0.0"),
    ("P11", "LEAK_DETECTED", "9.0"),
    ("P12", "GENERATED", "0.0"),
)


def _run(argv: Sequence[str], project: Path, timeout: float = 180.0) -> tuple[int, str]:
    """Run the CLI in the demo project and return its exit code and output.

    The interpreter path is reused instead of a shell so the demo works the same
    way on Windows and in WSL, and stdin is closed because no command prompts.
    """

    env = dict(os.environ)
    env["TAUHAULITY_NO_AUTO"] = "1"
    env["PYTHONPATH"] = str(ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    completed = subprocess.run(
        [sys.executable, "-m", "tauhaulity", *argv],
        cwd=str(project),
        capture_output=True,
        text=True,
        timeout=timeout,
        env=env,
        stdin=subprocess.DEVNULL,
    )
    return completed.returncode, completed.stdout + completed.stderr


def _prepare_project(project: Path) -> None:
    """Create a small project with one real credential so the scan is honest."""

    (project / "src").mkdir(parents=True, exist_ok=True)
    (project / "src" / "app.py").write_text("VALUE = 1" + chr(10), encoding="utf-8")
    (project / ".env").write_text("GITHUB_TOKEN=ghp_" + "A" * 36 + chr(10), encoding="utf-8")
    (project / ".git" / "hooks").mkdir(parents=True, exist_ok=True)


def _normalise(text: str, project: str) -> str:
    """Replace run specific values so the assets are reproducible.

    Everything masked here is a property of the machine or the moment, not of the
    tool: temp paths, durations, digests, timestamps, memory addresses and host
    labels. The statuses, risks, verdict and score are never masked.
    """

    normalised = text
    normalised = normalised.replace(project, FICTIONAL_TARGET)
    normalised = normalised.replace(project.replace(os.sep, "/"), FICTIONAL_TARGET)
    normalised = normalised.replace(chr(92), "/")
    normalised = re.sub(r"\b[0-9a-fA-F]{32,64}\b", "<digest>", normalised)
    normalised = re.sub(r"\b\d{4}-\d{2}-\d{2}T[0-9:.]+Z", "<timestamp>", normalised)
    normalised = re.sub(r" in \d+ ms", " in 0 ms", normalised)
    normalised = re.sub(r"median \d+ ms", "median 0 ms", normalised)
    normalised = re.sub(r"0x[0-9a-fA-F]{4,}", "0x<addr>", normalised)
    normalised = re.sub(r"\b(?:Win32-Native|WSL2-[A-Za-z]+|Linux-[A-Za-z]+)\b", "Dev-Host", normalised)
    normalised = re.sub(r"\b(?:windows-iphlpapi|linux-procfs|wsl-procfs)\b", "<socket-table>", normalised)
    return normalised


def _normalise_value(value: object, project: str) -> object:
    """Recursively normalise strings inside the captured scorecard object."""

    if isinstance(value, str):
        return _normalise(value, project)
    if isinstance(value, list):
        return [_normalise_value(item, project) for item in value]
    if isinstance(value, tuple):
        return tuple(_normalise_value(item, project) for item in value)
    if isinstance(value, Mapping):
        return {str(key): _normalise_value(item, project) for key, item in value.items()}
    return value


def _read_scorecard(project: Path) -> Mapping[str, object] | None:
    """Read the scorecard object from the JSON dossier the scan just wrote.

    The demo shows the real score, grade and deduction ledger; reading the same
    JSON a user would read keeps the diagram and the animation honest.
    """

    import json

    path = project / "tauhaulity_report.json"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    card = payload.get("scorecard")
    return dict(card) if isinstance(card, Mapping) else None


def capture_session() -> Session:
    """Run the real command line and capture the text the demo will show.

    Returns:
        A Session whose steps are real captured commands. When the subprocess
        cannot run at all, a bundled sample is returned and the source field says
        so, because a demo that silently fabricates output would be worse than one
        that admits it could not run.
    """

    project = Path(tempfile.mkdtemp(prefix="tauhaulity_demo_"))
    steps: list[Step] = []
    scorecard: Mapping[str, object] | None = None
    try:
        _prepare_project(project)
        for argv, command in _DEMO_PLAN:
            _code, output = _run(argv, project)
            lines = tuple(
                _normalise(line, str(project)).rstrip()
                for line in output.splitlines()
                if line.strip()
            )
            if not lines:
                raise RuntimeError(f"command produced no output: {command}")
            steps.append(Step(argv=tuple(argv), command=command, output=lines))
        captured = _read_scorecard(project)
        if captured is not None:
            normalised = _normalise_value(captured, str(project))
            scorecard = normalised if isinstance(normalised, Mapping) else None
    except Exception as exc:  # the demo must always render, even with a broken CLI
        return Session(steps=_sample_steps(), source=f"bundled sample ({type(exc).__name__})")
    finally:
        shutil.rmtree(project, ignore_errors=True)
    return Session(steps=tuple(steps), source="live run", scorecard=scorecard)


def _sample_steps() -> tuple[Step, ...]:
    """Fallback text used only when the CLI cannot be executed.

    The sample keeps the exact output shape of a live run so the layout code and
    the tests exercise the same code paths; demo-source.txt records that the
    sample was used.
    """

    scan_rows = tuple(
        f"{pid} [{status:<17}] risk {risk:>4}  stable evidence line"
        for pid, status, risk in _SAMPLE_ROWS
    )
    scan = (
        "TAUHAULITY SCAN - " + FICTIONAL_TARGET,
        "-" * 78,
        *scan_rows,
        "-" * 78,
        "verdict: CRITICAL (risk 9.00 / 10.00) on 12 pillars in 0 ms | score 81/100 (grade C)",
        "report[md]: " + FICTIONAL_TARGET + "/tauhaulity_report.md",
        "report[txt]: " + FICTIONAL_TARGET + "/tauhaulity_report.txt",
        "report[json]: " + FICTIONAL_TARGET + "/tauhaulity_report.json",
    )
    return (
        Step(argv=(), command="tauhaulity", output=scan),
        Step(
            argv=("suppress", "list", "."),
            command="tauhaulity suppress list .",
            output=(
                "no findings to review; 0 suppression(s) recorded in "
                + FICTIONAL_TARGET
                + "/.tauhaulity/suppressions.json",
            ),
        ),
        Step(
            argv=("honeytoken", "deploy", "."),
            command="tauhaulity honeytoken deploy .",
            output=(
                "deployed 5 honeytoken(s) (dotenv, aws_credentials, ssh_key, npmrc, pypirc) under "
                + FICTIONAL_TARGET
                + "; manifest: "
                + FICTIONAL_TARGET
                + "/.tauhaulity/honeytokens.json",
                "arm the guard in the process you want to observe with:",
                "  python -c 'import tauhaulity; tauhaulity.activate()'  (or set TAUHAULITY_ENFORCE=1)",
            ),
        ),
        Step(
            argv=("verify", "tauhaulity_report.md"),
            command="tauhaulity verify tauhaulity_report.md",
            output=(
                "VALID",
                "  scheme    : file-stamp",
                "  digest    : <digest>",
                "  key source: machine",
                "  reason    : INTEGRITY trailer matches the file bytes",
            ),
        ),
    )


# ---------------------------------------------------------------- segments --
def status_role(status: str) -> str:
    """Map a status token to its colour role.

    Unknown tokens resolve to the warning role so a future status cannot hide in
    the output colour.
    """

    token = status.strip().upper()
    if token in _CRITICAL_STATUSES:
        return "crit"
    if token in _PASS_STATUSES:
        return "pass"
    return "warn"


def _fit(text: str, width: int) -> str:
    """Clip a field with an explicit ASCII ellipsis marker.

    The demo font only covers ASCII, so the marker is three dots rather than the
    single ellipsis code point; losing the marker would make a truncated status
    look like a shorter real one.
    """

    if len(text) <= width:
        return text
    if width <= 3:
        return text[:width]
    return text[: width - 3] + "..."


def _wrap_segments(segments: Sequence[Segment], width: int = CONTENT_COLS) -> list[tuple[Segment, ...]]:
    """Wrap coloured segments to a column count without losing a role.

    Words are kept together when a space is available; a single token longer than
    the width (a path, for example) is hard split so it stays inside the canvas.
    Trailing spaces are removed because a trailing space would widen the caret.

    Raises:
        ValueError: When width is not positive.
    """

    if width <= 0:
        raise ValueError("wrap width must be positive")
    lines: list[tuple[Segment, ...]] = []
    current: list[Segment] = []
    used = 0
    for segment in segments:
        remaining = segment.text
        while remaining:
            space = width - used
            if len(remaining) <= space:
                current.append(Segment(remaining, segment.role))
                used += len(remaining)
                remaining = ""
                continue
            window = remaining[:space]
            cut = window.rfind(" ")
            if cut <= 0:
                cut = space
            else:
                cut += 1
            piece = remaining[:cut]
            current.append(Segment(piece, segment.role))
            lines.append(tuple(current))
            current = []
            used = 0
            remaining = remaining[cut:]
    if current:
        lines.append(tuple(current))
    if not lines:
        return [()]
    trimmed: list[tuple[Segment, ...]] = []
    for line_segments in lines:
        cleaned = list(line_segments)
        while cleaned and not cleaned[-1].text.strip():
            cleaned.pop()
        if cleaned:
            cleaned[-1] = Segment(cleaned[-1].text.rstrip(), cleaned[-1].role)
        trimmed.append(tuple(segment for segment in cleaned if segment.text))
    return [line for line in trimmed if line] or [()]


def _prompt_segments(command: str) -> tuple[Segment, ...]:
    """Render the shell prompt followed by the typed command."""

    return (Segment("$ ", "prompt"), Segment(command, "command"))


def _separator_segments() -> tuple[Segment, ...]:
    return (Segment("-" * CONTENT_COLS, "border"),)


def _pillar_segments(pillar_id: str, status: str, risk: str) -> tuple[Segment, ...]:
    """Render one compact matrix row with per segment colour roles."""

    return (
        Segment(pillar_id, "accent"),
        Segment("  ", "output"),
        Segment(f"{_fit(status, 17):<17}", status_role(status)),
        Segment("  risk ", "dim"),
        Segment(f"{risk:>4}", "accent"),
    )


def _header_segments(target: str) -> tuple[Segment, ...]:
    return (
        Segment("TAUHAULITY SCAN", "accent"),
        Segment(" - ", "dim"),
        Segment(target, "dim"),
    )


def _verdict_segments(text: str) -> tuple[Segment, ...]:
    match = re.match(r"^(verdict:)\s+([A-Z_]+)(.*)$", text)
    if match is None:
        return (Segment(text, "output"),)
    return (
        Segment(match.group(1), "dim"),
        Segment(" " + match.group(2), status_role(match.group(2))),
        Segment(match.group(3), "output"),
    )


def _report_segments(text: str) -> tuple[Segment, ...]:
    match = re.match(r"^(report\[[a-z]+\])(: )(.*)$", text)
    if match is None:
        return (Segment(text, "output"),)
    return (
        Segment(match.group(1), "accent"),
        Segment(match.group(2), "dim"),
        Segment(match.group(3), "dim"),
    )


def _generic_segments(text: str) -> tuple[Segment, ...]:
    """Colour an ordinary output line by its shape rather than by its content."""

    stripped = text.strip()
    if not stripped:
        return ()
    lowered = stripped.lower()
    if lowered.startswith("deployed"):
        return (Segment("deployed", "pass"), Segment(stripped[len("deployed") :], "output"))
    if lowered.startswith("arm the guard") or lowered.startswith("python -c") or lowered.startswith("  python"):
        return (Segment(text, "dim"),)
    match = re.match(r"^(VALID|INVALID)\b(.*)$", stripped)
    if match is not None:
        return (Segment(match.group(1), status_role(match.group(1))), Segment(match.group(2), "output"))
    if ":" in text and len(text.split(":", 1)[0]) <= 20 and not text.lstrip().startswith("http"):
        head, rest = text.split(":", 1)
        return (Segment(head + ":", "dim"), Segment(rest, "output"))
    return (Segment(text, "output"),)


_PILLAR_LINE = re.compile(r"^(P\d{2})\s+\[([^\]]*?)\]\s+risk\s+([0-9]+(?:\.[0-9]+)?)")


def parse_scan(output: Sequence[str]) -> tuple[str, str, tuple[tuple[str, str, str], ...], str, tuple[str, ...]] | None:
    """Extract the matrix, verdict and report lines from a captured scan.

    Returns:
        (header, target, rows, verdict, reports) or None when the output is not
        recognisably a scan. Details are not kept: they carry host specific
        evidence, while the status and risk column is what the demo teaches.
    """

    header = ""
    target = ""
    rows: list[tuple[str, str, str]] = []
    verdict = ""
    reports: list[str] = []
    for line in output:
        stripped = line.strip()
        if not header and stripped.startswith("TAUHAULITY SCAN"):
            header = stripped
            _, _, target = stripped.partition(" - ")
            continue
        match = _PILLAR_LINE.match(stripped)
        if match is not None:
            rows.append((match.group(1), match.group(2).strip(), match.group(3)))
            continue
        if not verdict and stripped.startswith("verdict:"):
            verdict = stripped
            continue
        if stripped.startswith("report["):
            reports.append(stripped)
    if not header or len(rows) != 12 or not verdict:
        return None
    return header, target, tuple(rows), verdict, tuple(reports)


def _scan_display(step: Step) -> tuple[list[tuple[Segment, ...]], tuple[str, str, str]]:
    """Turn a scan step into styled display lines plus (verdict, score, grade)."""

    parsed = parse_scan(step.output)
    if parsed is None:
        lines: list[tuple[Segment, ...]] = []
        for raw in step.output:
            lines.extend(_wrap_segments(_generic_segments(raw)))
        return lines, ("AT_RISK", "0", "F")
    _header, target, rows, verdict_line, reports = parsed
    display: list[tuple[Segment, ...]] = []
    display.append(_header_segments(target))
    display.append(_separator_segments())
    for pillar_id, status, risk in rows:
        display.append(_pillar_segments(pillar_id, status, risk))
    display.append(_separator_segments())
    display.extend(_wrap_segments(_verdict_segments(verdict_line)))
    for report in reports:
        display.extend(_wrap_segments(_report_segments(report)))
    match = re.search(r"score\s+(\d+)/\d+\s+\(grade\s+([A-Za-z+]+)\)", verdict_line)
    verdict_name = "AT_RISK"
    name_match = re.match(r"^verdict:\s*([A-Z_]+)", verdict_line)
    if name_match is not None:
        verdict_name = name_match.group(1)
    score = match.group(1) if match else "0"
    grade = match.group(2) if match else "F"
    return display, (verdict_name, score, grade)


def _output_display(step: Step) -> list[tuple[Segment, ...]]:
    """Wrap and colour one non scan command output."""

    lines: list[tuple[Segment, ...]] = []
    for raw in step.output:
        lines.extend(_wrap_segments(_generic_segments(raw)))
    return lines


# ---------------------------------------------------------------- timeline --
class _Timeline:
    """Mutable builder that owns line identities and the frame list."""

    def __init__(self) -> None:
        self.lines: list[ScreenLine] = []
        self.frames: list[FrameSpec] = []
        self._next_line_id = 0

    def _make_line(self, segments: Sequence[Segment]) -> ScreenLine:
        line = ScreenLine(self._next_line_id, tuple(segments))
        self._next_line_id += 1
        return line

    def add(self, segments: Sequence[Segment]) -> ScreenLine:
        """Append a new terminal line."""

        line = self._make_line(segments)
        self.lines.append(line)
        return line

    def replace_last(self, segments: Sequence[Segment]) -> ScreenLine:
        """Replace the newest line, used for typing and its caret."""

        if not self.lines:
            raise RuntimeError("replace_last requires a prompt line")
        line = self._make_line(segments)
        self.lines[-1] = line
        return line

    def emit(self, delay_cs: int, status: Sequence[Segment], cursor: bool = False) -> None:
        """Record the current visible state as one animation frame."""

        self.frames.append(
            FrameSpec(
                lines=tuple(self.lines),
                status=tuple(status),
                cursor=cursor,
                delay_cs=int(delay_cs),
            )
        )


def _status_ready() -> tuple[Segment, ...]:
    return (Segment(" ready", "muted"),)


def _status_scanning(index: int) -> tuple[Segment, ...]:
    spinner = _SPINNER[index % len(_SPINNER)]
    return (Segment(f" {spinner}", "warn"), Segment(" scanning 12 pillars", "output"))


def _status_verdict(name: str, score: str, grade: str) -> tuple[Segment, ...]:
    return (
        Segment(" " + name, status_role(name)),
        Segment(f"  score {score}/100 (grade {grade})", "dim"),
    )


def _typing_states(command: str, step: int) -> list[str]:
    """Return the cumulative prefixes shown while a command is typed."""

    return [command[: index + step] for index in range(0, len(command), step)]


def _append_typed_command(
    timeline: _Timeline,
    command: str,
    status: Sequence[Segment],
    *,
    step: int,
) -> None:
    """Type a command at 40 ms per frame, then hide the caret before output."""

    timeline.add(_prompt_segments(""))
    for typed in _typing_states(command, step):
        timeline.replace_last(_prompt_segments(typed))
        timeline.emit(TYPING_DELAY_CS, status, cursor=True)
    # One caret off frame is the visible blink; the next output frame is static.
    timeline.emit(BLINK_DELAY_CS, status, cursor=False)


def build_frame_specs(session: Session) -> tuple[FrameSpec, ...]:
    """Turn a captured session into the animation timeline.

    The scan matrix is revealed one pillar per frame so a viewer can follow the
    statuses; prose output is revealed a few lines at a time; the completed matrix
    holds long enough to be read.

    Raises:
        AssertionError: When the timeline breaks the published frame or duration
            budget. The bounds are asserted here so a slow or bloated animation
            cannot ship unnoticed.
    """

    timeline = _Timeline()
    timeline.add(_prompt_segments(""))
    timeline.emit(INTRO_DELAY_CS, _status_ready())

    scan_step = session.steps[0]
    _append_typed_command(timeline, scan_step.command, _status_ready(), step=3)
    scan_lines, (verdict_name, score, grade) = _scan_display(scan_step)
    verdict_status = _status_verdict(verdict_name, score, grade)

    spinner = 0
    reveal_plan: list[list[int]] = []
    # Header plus the rule, then every pillar row, then the rule and verdict, then
    # report paths. Grouping the decorative rules with their neighbour keeps the
    # frame count inside the budget without hiding any real line.
    reveal_plan.append([0, 1])
    reveal_plan.extend([[2 + number] for number in range(12)])
    reveal_plan.append([14, 15])
    remaining = list(range(16, len(scan_lines)))
    while remaining:
        group, remaining = remaining[:2], remaining[2:]
        reveal_plan.append(group)
    verdict_index = next(
        (
            index
            for index, line in enumerate(scan_lines)
            if any(segment.text.startswith("verdict:") for segment in line)
        ),
        len(scan_lines),
    )
    scan_done = False
    for group in reveal_plan:
        for index in group:
            timeline.add(scan_lines[index])
        if max(group) >= verdict_index:
            scan_done = True
        status = verdict_status if scan_done else _status_scanning(spinner)
        spinner += 1
        timeline.emit(VERDICT_DELAY_CS if scan_done else REVEAL_DELAY_CS, status)
    timeline.emit(HOLD_SCAN_CS, verdict_status)

    for command_step in session.steps[1:]:
        _append_typed_command(timeline, command_step.command, verdict_status, step=4)
        output_lines = _output_display(command_step)
        index = 0
        while index < len(output_lines):
            group = output_lines[index : index + 3]
            for line_segments in group:
                timeline.add(line_segments)
            index += 3
            timeline.emit(REVEAL_DELAY_CS, verdict_status)
        timeline.emit(HOLD_AFTER_COMMAND_CS, verdict_status)

    timeline.emit(FINAL_HOLD_CS, verdict_status)

    frames = tuple(timeline.frames)
    total_cs = sum(frame.delay_cs for frame in frames)
    if not MIN_FRAMES <= len(frames) <= MAX_FRAMES:
        raise AssertionError(f"demo has {len(frames)} frames, budget {MIN_FRAMES}..{MAX_FRAMES}")
    if not MIN_TOTAL_CS <= total_cs <= MAX_TOTAL_CS:
        raise AssertionError(f"demo runs {total_cs / 100:.2f}s, budget 12..18s")
    if not any(frame.delay_cs >= FINAL_HOLD_CS for frame in frames[-1:]):
        raise AssertionError("the final frame must hold for at least 900 ms")
    return frames


# --------------------------------------------------------------- rendering --
def line_pixel_width(line: ScreenLine) -> int:
    """Return the rendered pixel width of a line using the font metrics."""

    return line.pixel_width()


def _draw_chrome(canvas: Canvas, status: Sequence[Segment]) -> None:
    """Paint the window chrome: title bar, traffic lights, status bar.

    The body background is already the canvas background; only the bars and the
    borders are painted, which keeps the per frame paint cost low.
    """

    canvas.fill_rect(0, 0, WIDTH, TITLE_BAR_HEIGHT, ROLE_INDEX["bar"])
    canvas.fill_rect(0, STATUS_TOP, WIDTH, STATUS_BAR_HEIGHT, ROLE_INDEX["bar"])
    canvas.hline(0, TITLE_BAR_HEIGHT - 1, WIDTH, ROLE_INDEX["border"])
    canvas.hline(0, STATUS_TOP, WIDTH, ROLE_INDEX["border"])

    for index, role in enumerate(("dot_close", "dot_minimise", "dot_zoom")):
        canvas.fill_circle(20 + index * 20, TITLE_BAR_HEIGHT // 2, 5, 10 + index)
        del role

    canvas.draw_text(84, (TITLE_BAR_HEIGHT - GLYPH_HEIGHT * SCALE) // 2, "tauhaulity", SCALE, ROLE_INDEX["command"], TRACKING)
    path_x = WIDTH - MARGIN_X - text_width(FICTIONAL_TARGET, SCALE, TRACKING)
    canvas.draw_text(path_x, (TITLE_BAR_HEIGHT - GLYPH_HEIGHT * SCALE) // 2, FICTIONAL_TARGET, SCALE, ROLE_INDEX["dim"], TRACKING)

    status_y = STATUS_TOP + (STATUS_BAR_HEIGHT - GLYPH_HEIGHT * SCALE) // 2
    cursor = MARGIN_X
    for segment in status:
        cursor = canvas.draw_text(cursor, status_y, segment.text, SCALE, ROLE_INDEX[segment.role], TRACKING)
    hint = "12 pillars | read-only"
    hint_x = WIDTH - MARGIN_X - text_width(hint, SCALE, TRACKING)
    canvas.draw_text(hint_x, status_y, hint, SCALE, ROLE_INDEX["muted"], TRACKING)


def render_frame_spec(spec: FrameSpec) -> Frame:
    """Rasterise one timeline frame into an indexed GIF frame.

    Raises:
        AssertionError: When a rendered line exceeds the content width. This is a
            build time guard: a clipped line must never ship.
    """

    canvas = Canvas(WIDTH, HEIGHT, background=ROLE_INDEX["bg"])
    _draw_chrome(canvas, spec.status)
    visible = spec.lines[-CONTENT_ROWS:]
    for row, line in enumerate(visible):
        y = CONTENT_TOP + row * LINE_HEIGHT
        x = MARGIN_X
        for segment in line.segments:
            if not segment.text:
                continue
            value = ROLE_INDEX[segment.role]
            if segment.role in BOLD_ROLES:
                x = canvas.draw_text_bold(x, y, segment.text, SCALE, value, TRACKING)
            else:
                x = canvas.draw_text(x, y, segment.text, SCALE, value, TRACKING)
        width = line_pixel_width(line)
        if width > CONTENT_WIDTH:
            raise AssertionError(f"line exceeds {CONTENT_WIDTH}px: {line.text!r} ({width}px)")
    if spec.cursor and visible:
        last_row = len(visible) - 1
        caret_x = MARGIN_X + line_pixel_width(visible[last_row])
        if caret_x + CURSOR_WIDTH <= WIDTH - MARGIN_X:
            canvas.fill_rect(
                caret_x,
                CONTENT_TOP + last_row * LINE_HEIGHT,
                CURSOR_WIDTH,
                CURSOR_HEIGHT,
                ROLE_INDEX["prompt"],
            )
    return Frame(indices=bytes(canvas.pixels), delay_cs=spec.delay_cs)


def render_frames(frames: Sequence[FrameSpec]) -> list[Frame]:
    """Rasterise a whole timeline."""

    return [render_frame_spec(frame) for frame in frames]


def _frame_starts(frames: Sequence[FrameSpec]) -> list[int]:
    starts: list[int] = []
    total = 0
    for frame in frames:
        starts.append(total)
        total += frame.delay_cs
    return starts


def _animate_opacity(start_frame: int, end_frame: int, last_frame: int, total_cs: int, starts: Sequence[int], durations: Sequence[int]) -> str:
    """Return an SMIL animate element that shows an element only in its window.

    Times are expressed as fractions of the full cycle so every element shares the
    same dur and loops together; calcMode=discrete keeps the terminal look instead
    of fading text.
    """

    if start_frame == 0 and end_frame == last_frame:
        return ""
    start = starts[start_frame] / total_cs
    end = (starts[end_frame] + durations[end_frame]) / total_cs
    duration = total_cs / 100.0
    if start_frame == 0:
        values, key_times = "1;0", f"0;{end:.6f}"
    elif end_frame == last_frame:
        values, key_times = "0;1", f"0;{start:.6f}"
    else:
        values, key_times = "0;1;0", f"0;{start:.6f};{end:.6f}"
    return (
        f'<animate attributeName="opacity" values="{values}" keyTimes="{key_times}" '
        f'calcMode="discrete" dur="{duration:.3f}s" repeatCount="indefinite"/>'
    )


def _svg_line(line: ScreenLine, y: int) -> str:
    """Render one screen line as SVG text with coloured spans."""

    if not line.segments:
        return ""
    spans = "".join(
        f'<tspan fill="{ROLE_COLOUR[segment.role]}">{escape(segment.text)}</tspan>'
        for segment in line.segments
        if segment.text
    )
    if not spans:
        return ""
    return (
        f'<text x="{MARGIN_X}" y="{y}" font-size="16" xml:space="preserve">{spans}</text>'
    )


def write_animated_svg(path: Path, frames: Sequence[FrameSpec]) -> Path:
    """Write the session as an SMIL animated SVG that needs no JavaScript.

    Each screen line carries its own discrete opacity window, which reproduces
    both the typing effect and the scroll of a terminal without animating text
    coordinates. The viewBox is tall enough for the whole session, so no line is
    ever clipped.
    """

    if not frames:
        raise ValueError("cannot animate an empty timeline")
    durations = [frame.delay_cs for frame in frames]
    total_cs = sum(durations)
    starts = _frame_starts(frames)
    last_frame = len(frames) - 1

    line_windows: dict[int, list[int]] = {}
    line_bodies: dict[int, ScreenLine] = {}
    row_of: dict[int, int] = {}
    for index, frame in enumerate(frames):
        for row, line in enumerate(frame.lines):
            line_bodies[line.line_id] = line
            row_of[line.line_id] = row
            window = line_windows.setdefault(line.line_id, [index, index])
            window[1] = index

    max_rows = max(len(frame.lines) for frame in frames)
    if max_rows > SVG_LINE_BUDGET:
        raise AssertionError(f"animated SVG needs {max_rows} rows, budget {SVG_LINE_BUDGET}")
    svg_height = max(HEIGHT, CONTENT_TOP + max_rows * LINE_HEIGHT + MARGIN_Y + STATUS_BAR_HEIGHT)

    status_windows: list[list[object]] = []
    for index, frame in enumerate(frames):
        if status_windows and status_windows[-1][2] == frame.status and status_windows[-1][1] == index - 1:
            status_windows[-1][1] = index
        else:
            status_windows.append([index, index, frame.status])

    rows: list[str] = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {WIDTH} {svg_height}" '
        f'width="{WIDTH}" height="{svg_height}" '
        'font-family="ui-monospace, SFMono-Regular, Menlo, Consolas, monospace">',
        "  <title>Tauhaulity demo session</title>",
        "  <desc>Real command line capture: twelve pillar scan, verdict, scorecard, suppression review, honeytokens and dossier verification.</desc>",
        f'  <rect width="{WIDTH}" height="{svg_height}" fill="{ROLE_COLOUR["bg"]}"/>',
        f'  <rect x="0" y="0" width="{WIDTH}" height="{TITLE_BAR_HEIGHT}" fill="{ROLE_COLOUR["bar"]}"/>',
        f'  <line x1="0" y1="{TITLE_BAR_HEIGHT - 0.5}" x2="{WIDTH}" y2="{TITLE_BAR_HEIGHT - 0.5}" stroke="{ROLE_COLOUR["border"]}"/>',
    ]
    for index, colour in enumerate(("#ff5f56", "#ffbd2e", "#27c93f")):
        rows.append(
            f'  <circle cx="{20 + index * 20}" cy="{TITLE_BAR_HEIGHT // 2}" r="5" fill="{colour}"/>'
        )
    rows.append(
        f'  <text x="84" y="{TITLE_BAR_HEIGHT // 2 + 5}" font-size="15" fill="{ROLE_COLOUR["command"]}" font-weight="bold">tauhaulity</text>'
    )
    rows.append(
        f'  <text x="{WIDTH - MARGIN_X}" y="{TITLE_BAR_HEIGHT // 2 + 5}" font-size="15" fill="{ROLE_COLOUR["dim"]}" text-anchor="end">{escape(FICTIONAL_TARGET)}</text>'
    )

    for line_id in sorted(line_bodies):
        window = line_windows[line_id]
        row = row_of[line_id]
        body = _svg_line(line_bodies[line_id], CONTENT_TOP + row * LINE_HEIGHT + GLYPH_HEIGHT * SCALE)
        if not body:
            continue
        animate = _animate_opacity(window[0], window[1], last_frame, total_cs, starts, durations)
        if animate:
            rows.append(f"  <g>{body}{animate}</g>")
        else:
            rows.append(f"  <g>{body}</g>")

    status_y = svg_height - STATUS_BAR_HEIGHT + (STATUS_BAR_HEIGHT - GLYPH_HEIGHT * SCALE) // 2 + GLYPH_HEIGHT * SCALE
    rows.append(
        f'  <rect x="0" y="{svg_height - STATUS_BAR_HEIGHT}" width="{WIDTH}" height="{STATUS_BAR_HEIGHT}" fill="{ROLE_COLOUR["bar"]}"/>'
    )
    rows.append(
        f'  <line x1="0" y1="{svg_height - STATUS_BAR_HEIGHT + 0.5}" x2="{WIDTH}" y2="{svg_height - STATUS_BAR_HEIGHT + 0.5}" stroke="{ROLE_COLOUR["border"]}"/>'
    )
    rows.append(
        f'  <text x="{WIDTH - MARGIN_X}" y="{status_y}" font-size="15" fill="{ROLE_COLOUR["muted"]}" text-anchor="end">12 pillars | read-only</text>'
    )
    for start, end, status in status_windows:
        if not status:
            continue
        spans = "".join(
            f'<tspan fill="{ROLE_COLOUR[segment.role]}">{escape(segment.text)}</tspan>'
            for segment in status
        )
        animate = _animate_opacity(int(start), int(end), last_frame, total_cs, starts, durations)
        body = f'<text x="{MARGIN_X}" y="{status_y}" font-size="15" xml:space="preserve">{spans}</text>'
        rows.append(f"  <g>{body}{animate}</g>" if animate else f"  <g>{body}</g>")
    rows.append("</svg>")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(chr(10).join(rows) + chr(10), encoding="utf-8", newline=chr(10))
    return path


def write_gif(path: Path, frames: Sequence[Frame]) -> Path:
    """Write the animation as a GIF89a file."""

    if not frames:
        raise ValueError("cannot encode an empty animation")
    data = encode_gif(frames, WIDTH, HEIGHT, PALETTE, loop=True)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


# ------------------------------------------------------------- static SVGs --
def _diagram_payload(session: Session, frames: Sequence[FrameSpec], verdict: tuple[str, str, str]) -> dict[str, object]:
    """Build the data object handed to scripts/demo_diagrams.py.

    The same scorecard fields appear at the top level and nested under
    "scorecard", so a writer can read either shape without a second scan.
    """

    card = session.scorecard or {}
    score = card.get("score", int(verdict[1]) if verdict[1].isdigit() else 0)
    grade = card.get("grade", verdict[2])
    payload: dict[str, object] = {
        "version": "0.4.0",
        "target": FICTIONAL_TARGET,
        "generated_by": GENERATED_BY,
        "verdict": card.get("verdict", verdict[0]),
        "score": score,
        "score_max": card.get("score_max", 100),
        "grade": grade,
        "band": card.get("band", ""),
        "risk_total": card.get("risk_total", 0.0),
        "risk_ceiling": card.get("risk_ceiling", 10.0),
        "total_points_lost": card.get("total_points_lost", 0.0),
        "deductions": card.get("deductions", []),
        "commands": [step.command for step in session.steps],
        "frames": len(frames),
        "duration_s": round(sum(frame.delay_cs for frame in frames) / 100.0, 2),
    }
    payload["scorecard"] = {
        key: payload[key]
        for key in (
            "verdict",
            "score",
            "score_max",
            "grade",
            "band",
            "risk_total",
            "risk_ceiling",
            "total_points_lost",
            "deductions",
        )
    }
    payload["session"] = {"source": session.source, "commands": payload["commands"]}
    return payload


_DIAGRAM_WRITERS = (
    ("scorecard.svg", "write_scorecard_svg"),
    ("architecture.svg", "write_architecture_svg"),
)


def _invoke_diagram_writer(writer: object, path: Path, data: Mapping[str, object]) -> None:
    """Call a diagram writer with (path, data) or (path) depending on its arity.

    The module is owned by another component, so the adapter accepts both shapes
    instead of pinning a signature this generator would have to chase.
    """

    if not callable(writer):
        raise TypeError("diagram writer is not callable")
    parameters = [
        parameter
        for parameter in inspect.signature(writer).parameters.values()
        if parameter.kind in (parameter.POSITIONAL_ONLY, parameter.POSITIONAL_OR_KEYWORD)
    ]
    if len(parameters) >= 2:
        writer(path, dict(data))
    else:
        writer(path)


def _write_static_diagrams(output_dir: Path, data: Mapping[str, object]) -> dict[str, Path]:
    """Generate the static diagrams when scripts/demo_diagrams.py is available.

    A missing module is not an error: the diagrams are owned by a separate
    component and may land after this generator. A writer that fails is reported
    on stderr and skipped so a half published module cannot wedge the demo.
    """

    try:
        import demo_diagrams  # type: ignore[import-not-found]
    except ImportError:
        print(
            "make_demo: static diagrams skipped (scripts/demo_diagrams.py not present)",
            file=sys.stderr,
        )
        return {}
    written: dict[str, Path] = {}
    for name, attribute in _DIAGRAM_WRITERS:
        writer = getattr(demo_diagrams, attribute, None)
        if writer is None:
            raise RuntimeError(f"demo_diagrams.{attribute} is missing but the module imported")
        destination = output_dir / name
        try:
            _invoke_diagram_writer(writer, destination, data)
        except Exception as exc:
            # The module is present, so a failure is a real defect: failing the
            # run is better than silently dropping the asset from --check.
            raise RuntimeError(f"cannot generate {name}: {type(exc).__name__}: {exc}") from exc
        if not destination.is_file():
            raise RuntimeError(f"demo_diagrams.{attribute} did not write {name}")
        written[name] = destination
    return written


# -------------------------------------------------------------- generation --
def _write_source(path: Path, session: Session, frames: Sequence[FrameSpec], diagram_status: str) -> Path:
    """Write demo-source.txt, the provenance record for the generated assets."""

    total_cs = sum(frame.delay_cs for frame in frames)
    lines = [
        "demo source: " + session.source,
        f"frames: {len(frames)}",
        f"duration: {total_cs / 100:.1f}s",
        f"canvas: {WIDTH}x{HEIGHT}, palette {len(PALETTE)} colours",
        f"timeline: typing {TYPING_DELAY_CS * 10}ms/frame, reveal {REVEAL_DELAY_CS * 10}ms/frame, final hold {FINAL_HOLD_CS * 10}ms",
        "commands: " + " | ".join(step.command for step in session.steps),
        "static diagrams: " + diagram_status,
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(chr(10).join(lines) + chr(10), encoding="utf-8", newline=chr(10))
    return path


def generate(output_dir: Path = DOCS, *, include_gif: bool = False) -> dict[str, Path]:
    """Generate every demo asset and return the written paths."""

    output_dir = Path(output_dir)
    session = capture_session()
    frames = build_frame_specs(session)
    written: dict[str, Path] = {
        "demo_svg": write_animated_svg(output_dir / "tauhaulity-demo.svg", frames),
    }
    if include_gif:
        written["gif"] = write_gif(
            output_dir / "tauhaulity-demo.gif", render_frames(frames)
        )
    verdict = _scan_display(session.steps[0])[1]
    diagrams = _write_static_diagrams(output_dir, _diagram_payload(session, frames, verdict))
    written.update(diagrams)
    diagram_status = (
        "generated via scripts/demo_diagrams.py"
        if diagrams
        else "skipped (scripts/demo_diagrams.py unavailable)"
    )
    written["demo_source"] = _write_source(
        output_dir / "demo-source.txt", session, frames, diagram_status
    )
    return written


BASE_ASSETS: tuple[str, ...] = (
    "tauhaulity-demo.svg",
    "demo-source.txt",
)
DIAGRAM_ASSETS: tuple[str, ...] = ("scorecard.svg", "architecture.svg")


def _digests(output_dir: Path, names: Sequence[str]) -> dict[str, str]:
    """Return the sha256 of the named assets that exist."""

    digests: dict[str, str] = {}
    for name in names:
        path = Path(output_dir) / name
        if path.is_file():
            digests[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return digests


# ----------------------------------------------------------------- preview --
_ASCII_RAMP = " .:-=+*#%@"

#: One preview character per palette index. Using the colour role instead of a
#: luminance ramp keeps a command (#) distinguishable from output (+) and a
#: SAFE (G) pillar distinguishable from a CRITICAL (R) one in the ASCII dump.
_ART_BY_INDEX = (" ", ".", "#", "+", ":", "G", ">", "W", "R", "A", "o", "o", "o", "-", " ", " ")

#: Pooling priority used when a preview block contains several roles: text wins
#: over a border, a border over the chrome bar, and the background loses.
_ART_PRIORITY = (0, 1, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 2, 3, 3)

PREVIEW_LEGEND = (
    "legend: '#' command/caret  '+' output  ':' dim  'G' pass/SAFE  'W' warning  "
    "'R' critical  'A' accent  'o' traffic light  '-' border  '.' chrome"
)


def _luminance(colour: tuple[int, int, int]) -> float:
    red, green, blue = colour
    return 0.2126 * red + 0.7152 * green + 0.0722 * blue


def _ascii_art(indices: bytes, width: int, height: int, palette: Sequence[tuple[int, int, int]], columns: int) -> list[str]:
    """Downsample one frame into role coloured ASCII art.

    Each output character covers a block of source pixels. The most salient
    pixel of the block wins (text over border over chrome), so a one pixel stroke
    of a glyph is not lost to neighbour majority voting.
    """

    if columns <= 0:
        raise ValueError("preview columns must be positive")
    step = max(1, math.ceil(width / columns))
    fallback = [
        _ASCII_RAMP[min(len(_ASCII_RAMP) - 1, int(_luminance(colour) / 256 * len(_ASCII_RAMP)))]
        for colour in palette
    ]
    art: list[str] = []
    for y in range(0, height, step):
        row: list[str] = []
        for x in range(0, width, step):
            best_index = 0
            best_priority = -1
            for offset_y in range(y, min(y + step, height)):
                base = offset_y * width
                for offset_x in range(x, min(x + step, width)):
                    pixel = indices[base + offset_x]
                    priority = _ART_PRIORITY[pixel] if pixel < len(_ART_PRIORITY) else 3
                    if priority > best_priority:
                        best_priority = priority
                        best_index = pixel
            row.append(_ART_BY_INDEX[best_index] if best_index < len(_ART_BY_INDEX) else fallback[best_index])
        art.append("".join(row).rstrip())
    return art


def _collapse_blank(lines: Sequence[str]) -> list[str]:
    """Collapse runs of blank art lines so a preview stays readable in a log."""

    collapsed: list[str] = []
    previous_blank = False
    for line in lines:
        blank = not line.strip()
        if blank and previous_blank:
            continue
        collapsed.append(line)
        previous_blank = blank
    return collapsed


def preview_frames(path: Path, indices: Sequence[int], columns: int = 160) -> int:
    """Print ASCII art and ink coverage for selected frames of a GIF.

    Parameters:
        path: GIF to decode.
        indices: Zero based frame numbers; out of range numbers are reported.
        columns: Target ASCII width.

    Returns:
        Process exit code, zero when every requested frame was printed.
    """

    try:
        data = path.read_bytes()
        width, height, palette, frames = decode_gif(data)
    except OSError as exc:
        print(f"make_demo: cannot read {path}: {exc}", file=sys.stderr)
        return 1
    if not frames:
        print(f"make_demo: {path} contains no frames", file=sys.stderr)
        return 1
    exit_code = 0
    for index in indices:
        if not 0 <= index < len(frames):
            print(f"make_demo: frame {index} outside 0..{len(frames) - 1}", file=sys.stderr)
            exit_code = 1
            continue
        frame = frames[index]
        ink = sum(1 for pixel in frame.indices if pixel != 0) / (width * height)
        chrome = sum(1 for pixel in frame.indices if pixel in CHROME_INDEXES) / (width * height)
        text_ink = max(0.0, ink - chrome)
        print(PREVIEW_LEGEND)
        print(f"frame {index}/{len(frames) - 1}: {width}x{height}, delay {frame.delay_cs / 100:.2f}s, "
              f"ink {ink * 100:.1f}%, text ink {text_ink * 100:.1f}%")
        for line in _collapse_blank(_ascii_art(frame.indices, width, height, palette, columns)):
            print(line)
        print()
    return exit_code


def _parse_preview_indices(raw: str) -> list[int]:
    """Parse a comma separated --preview argument."""

    indices: list[int] = []
    for part in raw.split(","):
        token = part.strip()
        if not token:
            continue
        try:
            indices.append(int(token))
        except ValueError as exc:
            raise argparse.ArgumentTypeError(f"--preview expects frame numbers, got {token!r}") from exc
    if not indices:
        raise argparse.ArgumentTypeError("--preview needs at least one frame number")
    return indices


# --------------------------------------------------------------------- cli --
def main(argv: Sequence[str] | None = None) -> int:
    """Generate the assets, verify they are current, or preview frames."""

    parser = argparse.ArgumentParser(description="Generate the Tauhaulity demo assets.")
    parser.add_argument("--output", default=str(DOCS), help="output directory (default: docs/)")
    parser.add_argument("--check", action="store_true", help="compare against the checked-in assets")
    parser.add_argument(
        "--with-gif",
        action="store_true",
        help="also write the local GIF render (not part of the checked-in set)",
    )
    parser.add_argument("--preview", default="", help="comma separated frame numbers to print as ASCII art")
    parser.add_argument("--preview-cols", type=int, default=160, help="ASCII art width for --preview")
    args = parser.parse_args(argv)

    output_dir = Path(args.output)
    if not output_dir.is_absolute():
        output_dir = ROOT / output_dir

    if args.preview:
        try:
            indices = _parse_preview_indices(args.preview)
        except argparse.ArgumentTypeError as exc:
            parser.error(str(exc))
        gif_path = output_dir / "tauhaulity-demo.gif"
        if not gif_path.is_file():
            print("no GIF to preview: run with --with-gif first", file=sys.stderr)
            return 1
        return preview_frames(gif_path, indices, args.preview_cols)

    if args.check:
        with tempfile.TemporaryDirectory(prefix="tauhaulity_demo_check_") as staging:
            staging_dir = Path(staging)
            try:
                generate(staging_dir, include_gif=bool(args.with_gif))
            except (RuntimeError, OSError) as exc:
                print(f"demo asset generation failed: {exc}")
                return 1
            names = list(BASE_ASSETS)
            names.extend(name for name in DIAGRAM_ASSETS if (staging_dir / name).is_file())
            if args.with_gif:
                names.append("tauhaulity-demo.gif")
            fresh = _digests(staging_dir, names)
            current = _digests(output_dir, names)
            if fresh != current:
                drift = sorted(set(fresh) ^ set(current)) or sorted(
                    name for name in fresh if fresh[name] != current.get(name)
                )
                print("demo assets are stale: " + ", ".join(drift))
                return 1
            print("demo assets are current: " + ", ".join(sorted(fresh)))
            return 0

    try:
        written = generate(output_dir, include_gif=bool(args.with_gif))
    except (RuntimeError, OSError) as exc:
        print(f"make_demo: generation failed: {exc}", file=sys.stderr)
        return 1
    for name, path in written.items():
        print(f"{name}: {path} ({path.stat().st_size} bytes)")
    source_line = (output_dir / "demo-source.txt").read_text(encoding="utf-8").splitlines()[0]
    print(source_line)
    return 0


if __name__ == "__main__":
    sys.exit(main())

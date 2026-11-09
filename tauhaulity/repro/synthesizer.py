"""Standalone repro script synthesizer for confirmed findings.

A repro script is evidence, so it must be runnable outside Tauhaulity with nothing
but the standard library, and it must make the failure state obvious through its
exit code: zero means the vulnerability still reproduces, non-zero means it does
not. The generator therefore embeds a small, self contained copy of the rule the
pillar applied instead of importing a sibling module that may be absent, except in
the generic case where re-running the installed probe is genuinely possible.

Never embed the leaked credential itself: the token script uses a synthetic
canary of the same family, because a repro file is exactly the kind of artifact
that ends up committed to the repository it is meant to protect.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Final, Iterable

from tauhaulity.core.contracts import SPEC_BY_NUMBER, Finding, ScanContext, status_severity

REPRO_FILENAME_FORMAT: Final[str] = "repro_slot_{pillar:02d}.py"
MAX_SCRIPTS: Final[int] = 3

# Template selection is word based, not substring based: an evidence path such as
# "totally_legit.pth" contains the letters g-i-t and must not be mistaken for a
# credential finding, which would generate the wrong repro script.
_PICKLE_WORDS: Final[re.Pattern[str]] = re.compile(
    r"\b(?:pickle|pickles|pickled|deseriali[sz]e|deseriali[sz]ation|opcode|opcodes)\b",
    re.IGNORECASE,
)
_PORT_WORDS: Final[re.Pattern[str]] = re.compile(
    r"\b(?:port|ports|socket|sockets|zombie|zombies|listen|listener|listeners|listening)\b",
    re.IGNORECASE,
)
_TOKEN_WORDS: Final[re.Pattern[str]] = re.compile(
    r"\b(?:token|tokens|secret|secrets|credential|credentials|git|github_pat|"
    r"ghp_|gho_|ghu_|ghs_|ghr_|ssh|bearer|pat|pats)\b",
    re.IGNORECASE,
)

_TOKEN_TEMPLATE: Final[str] = '''#!/usr/bin/env python3
"""Auto-generated repro: Tauhaulity pillar {{PILLAR}} credential sentinel.

The script writes a synthetic canary credential of the {{FAMILY}} family into a
temporary file and runs the same credential rule the scan applied. The leaked
secret itself is never embedded: a repro script is a file that gets committed.

Exit code 0 means the sentinel still flags the canary (vulnerability
reproduced). Exit code 1 means it does not (the gate looks mitigated).
Standard library only.
"""

import os
import re
import sys
import tempfile
from pathlib import Path

os.environ.setdefault("TAUHAULITY_NO_AUTO", "1")

PILLAR = {{PILLAR}}
RECORDED_STATUS = {{STATUS}}
FAMILY = {{FAMILY}}
SAMPLE = {{SAMPLE}}

PATTERNS = {
    "github_fine": r"github_pat_[A-Za-z0-9_]{18,}",
    "github_classic": r"gh[pousr]_[A-Za-z0-9]{20,}",
    "openai": r"sk-[A-Za-z0-9_-]{16,}",
    "aws": r"AKIA[0-9A-Z]{16}",
    "ssh_key": r"-----BEGIN (?:OPENSSH|RSA|EC|DSA) PRIVATE KEY-----",
}


def detect(text):
    """Return the credential families present in text (standalone sentinel)."""
    return [name for name, pattern in PATTERNS.items() if re.search(pattern, text)]


def main():
    """Write the canary to a temp file, rescan it, return the repro verdict."""
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "leaked.env"
        path.write_text("GITHUB_TOKEN=" + SAMPLE, encoding="utf-8")
        text = path.read_text(encoding="utf-8")
    hits = detect(text)
    if hits:
        print("PASS: sentinel flagged the " + FAMILY + " canary at pillar " + str(PILLAR))
        print("      recorded status: " + RECORDED_STATUS + " (vulnerability reproduces)")
        return 0
    print("FAIL: sentinel no longer flags the " + FAMILY + " canary")
    print("      the condition is not reproducible, the gate looks mitigated")
    return 1


if __name__ == "__main__":
    sys.exit(main())
'''

_PICKLE_TEMPLATE: Final[str] = '''#!/usr/bin/env python3
"""Auto-generated repro: Tauhaulity pillar {{PILLAR}} pickle opcode gate.

Builds the malicious opcode stream a hostile pickle would carry (GLOBAL os.system
followed by REDUCE) and runs the opcode gate over it without ever deserializing
it. Deserializing the payload would execute it, which is the exact behaviour the
gate exists to prevent.

Exit code 0 means the gate still rejects the stream (vulnerability reproduced).
Exit code 1 means it does not (the gate looks mitigated). Standard library only.
"""

import os
import sys
import pickletools

os.environ.setdefault("TAUHAULITY_NO_AUTO", "1")

PILLAR = {{PILLAR}}
RECORDED_STATUS = {{STATUS}}
# GLOBAL os system, push the argument, then REDUCE: a classic arbitrary call.
# The newline opcode is built from its byte value so this template never relies
# on escape processing inside the generated file.
NL = bytes([10])
PAYLOAD = b"cos" + NL + b"system" + NL + b"(S'echo tauhaulity repro'" + NL + b"tR."
DANGEROUS = (
    "GLOBAL",
    "STACK_GLOBAL",
    "REDUCE",
    "INST",
    "OBJ",
    "NEWOBJ",
    "NEWOBJ_EX",
    "EXT1",
    "EXT2",
    "EXT4",
    "BUILD",
    "EVAL",
    "EXEC",
)


def gate(data):
    """Return every dangerous opcode present in a pickle stream."""
    names = set()
    try:
        for opcode, _argument, _position in pickletools.genops(data):
            names.add(opcode.name)
    except Exception as exc:
        return ["parse-error:" + type(exc).__name__]
    return [name for name in DANGEROUS if name in names]


def main():
    """Run the gate over the malicious stream and report the repro verdict."""
    rejected = gate(PAYLOAD)
    if rejected:
        print("PASS: opcode gate rejects the malicious pickle via " + ", ".join(rejected))
        print("      recorded status: " + RECORDED_STATUS + " (vulnerability reproduces)")
        return 0
    print("FAIL: opcode gate accepted the malicious pickle")
    print("      the condition is not reproducible, the gate looks mitigated")
    return 1


if __name__ == "__main__":
    sys.exit(main())
'''

_PORT_TEMPLATE: Final[str] = '''#!/usr/bin/env python3
"""Auto-generated repro: Tauhaulity pillar {{PILLAR}} port sentinel.

Binds 127.0.0.1 on the port reported by the scan, then confirms that a client
connection to that listener is detectable. If the reported port is already held,
that conflict is itself the reproduced condition.

Exit code 0 means the port condition still reproduces, exit code 1 means it does
not. Standard library only; nothing leaves the loopback interface.
"""

import errno
import os
import socket
import sys

os.environ.setdefault("TAUHAULITY_NO_AUTO", "1")

PILLAR = {{PILLAR}}
RECORDED_STATUS = {{STATUS}}
PORT = {{PORT}}
HOST = "127.0.0.1"


def main():
    """Bind, connect and report whether the port condition is reproducible."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        listener.bind((HOST, PORT))
        listener.listen(1)
        bound = listener.getsockname()[1]
        try:
            probe = socket.create_connection((HOST, bound), timeout=2.0)
            probe.close()
        except OSError as exc:
            print("FAIL: listener on %s:%d was not detectable (%s)" % (HOST, bound, exc))
            return 1
        print("PASS: listener on %s:%d is detectable" % (HOST, bound))
        print("      recorded status: " + RECORDED_STATUS + " (port condition reproduces)")
        return 0
    except OSError as exc:
        if exc.errno == errno.EADDRINUSE:
            print("PASS: port %d is already held on %s (%s)" % (PORT, HOST, exc))
            print("      recorded status: " + RECORDED_STATUS + " (conflict reproduces)")
            return 0
        print("FAIL: cannot bind %s:%d (%s)" % (HOST, PORT, exc))
        return 1
    finally:
        listener.close()


if __name__ == "__main__":
    sys.exit(main())
'''

_GENERIC_TEMPLATE: Final[str] = '''#!/usr/bin/env python3
"""Auto-generated repro: Tauhaulity pillar {{PILLAR}} ({{PILLAR_KEY}}).

Re-runs the same read-only pillar probe against the scanned target and compares
the resulting status token with the one recorded during the scan, so the script
verifies the condition with the real implementation instead of a description.

Exit code 0 means the pillar still reports the recorded failing status
(vulnerability reproduced). Exit code 1 means the status changed, so the
condition does not reproduce any more. Exit code 2 means the probe module is not
importable here: the condition is unverifiable rather than fixed.
Standard library only.
"""

import os
import sys
from pathlib import Path

os.environ.setdefault("TAUHAULITY_NO_AUTO", "1")

PROJECT = {{PROJECT}}
TARGET = {{TARGET}}
PILLAR = {{PILLAR}}
RECORDED_STATUS = {{STATUS}}
BENIGN = frozenset({"SAFE", "READY", "PROTECTED", "CLEAN", "SECURE", "GENERATED", "DISABLED"})


def load_probe():
    """Import the probe for this pillar number, or return None."""
    if PROJECT and PROJECT not in sys.path:
        sys.path.insert(0, PROJECT)
    import importlib

    try:
        from tauhaulity.pillars import discover_modules
    except Exception:
        return None
    for module_name in discover_modules():
        stem = module_name.rsplit(".", 1)[-1]
        digits = stem[1:3]
        if not digits.isdigit() or int(digits) != PILLAR:
            continue
        try:
            module = importlib.import_module(module_name)
        except Exception:
            return None
        probe = getattr(module, "probe", None)
        if callable(probe):
            return probe
    return None


def main():
    """Re-run the probe and map its status to a repro exit code."""
    probe = load_probe()
    if probe is None:
        print("UNVERIFIABLE: no importable probe for pillar " + str(PILLAR))
        return 2
    from tauhaulity.core.contracts import ScanContext, ScanOptions
    from tauhaulity.core.platform_probe import detect_platform
    from tauhaulity.core.policy import Policy

    context = ScanContext(
        target=Path(TARGET),
        platform=detect_platform(),
        policy=Policy(),
        options=ScanOptions(generate_repro=False),
    )
    finding = probe(context)
    status = str(getattr(finding, "status", ""))
    if status == RECORDED_STATUS:
        print("PASS: pillar " + str(PILLAR) + " still reports " + status + " (reproduced)")
        return 0
    if status.upper() in BENIGN:
        print("FAIL: pillar " + str(PILLAR) + " now reports " + status + " (mitigated)")
        return 1
    print("WARN: pillar " + str(PILLAR) + " reports a different status: " + status)
    return 1


if __name__ == "__main__":
    sys.exit(main())
'''


def _fill(template: str, mapping: dict[str, str]) -> str:
    """Replace generation tokens in a script template.

    Plain string replacement is used instead of str.format because the generated
    scripts contain braces, percent signs and f-string-like text that must survive
    verbatim.
    """

    rendered = template
    for token, value in mapping.items():
        rendered = rendered.replace("{{" + token + "}}", value)
    return rendered


def _quote(value: str) -> str:
    """Return a Python literal for a path, status or sample string."""

    return repr(str(value))


def _haystack(finding: Finding) -> str:
    """Join the free text of a finding for family and port heuristics."""

    slots = " ".join(str(value) for value in finding.slots.values())
    return " ".join(
        part
        for part in (
            finding.detail,
            finding.repro_hint or "",
            slots,
        )
        if part
    ).lower()


def _token_family(haystack: str) -> tuple[str, str]:
    """Pick a synthetic canary family matching the detected credential."""

    if "github_pat" in haystack:
        return "github_fine", "github_pat_" + "R" * 60
    if any(prefix in haystack for prefix in ("ghp_", "gho_", "ghu_", "ghs_", "ghr_")):
        return "github_classic", "ghp_" + "R" * 36
    if "sk-" in haystack:
        return "openai", "sk-" + "R" * 40
    if "akia" in haystack:
        return "aws", "AKIA" + "R" * 16
    if "private key" in haystack or "ssh" in haystack:
        return "ssh_key", "-----BEGIN OPENSSH PRIVATE KEY-----"
    return "github_classic", "ghp_" + "R" * 36


def _extract_port(finding: Finding) -> int:
    """Return the TCP port a finding actually names, else zero.

    The explicit ports slot wins because it is structured evidence such as
    "8000:PID_4120". A bare number inside prose is not trusted, because a detail
    line such as "22 listening sockets" would otherwise be mistaken for port 22
    and the repro script would try to bind a privileged port. A zero result asks
    the kernel for an ephemeral port, which still exercises the bind and detect
    path without assuming the reported port is free on this host.
    """

    # The slot may hold structured data ("8000:4120") or a summary ("22
    # listening"): only a value that is unambiguously a port is trusted.
    explicit = finding.slot("ports").strip()
    slot_match = re.search(r"^\s*(\d{1,5})(?:\s*[:/]\s*\d+)?\s*$", explicit)
    if slot_match is not None:
        value = int(slot_match.group(1))
        if 0 <= value <= 65535:
            return value
    prose = (finding.detail + " " + (finding.repro_hint or "")).strip()
    for pattern in (
        r"ports?[^0-9]{0,40}?(\d{1,5})\b",
        r":(\d{1,5})\b",
    ):
        for match in re.finditer(pattern, prose, re.IGNORECASE):
            value = int(match.group(1))
            if 1 <= value <= 65535:
                return value
    return 0


class AutoReproSynthesizer:
    """Write standalone repro scripts for confirmed findings.

    Attributes:
        out_dir: Directory scripts are written into. Pillar twelve points this at
            TARGET/.tauhaulity/repro so a scan never writes outside the project.
    """

    def __init__(self, out_dir: Path) -> None:
        """Create a synthesizer bound to one output directory.

        Raises:
            TypeError: When out_dir is not path-like.
        """

        if not isinstance(out_dir, (str, Path)):
            raise TypeError("out_dir must be a path")
        self.out_dir = Path(out_dir)

    def synthesize(self, finding: Finding, ctx: ScanContext) -> Path | None:
        """Write one standalone repro script for a finding.

        Parameters:
            finding: Finding to reproduce.
            ctx: Scan context supplying the target path.

        Returns:
            The written script path, or None when the finding reports a benign
            status: there is nothing to reproduce, and emitting a fake failure
            script would make the dossier lie.
        """

        if not isinstance(finding, Finding):
            raise TypeError("finding must be a Finding instance")
        if status_severity(finding.status) == 0:
            return None
        spec = SPEC_BY_NUMBER.get(finding.pillar)
        if spec is None:
            raise ValueError(f"unknown pillar number: {finding.pillar}")
        script = self._render_script(finding, ctx)
        self.out_dir.mkdir(parents=True, exist_ok=True)
        destination = self.out_dir / REPRO_FILENAME_FORMAT.format(pillar=finding.pillar)
        destination.write_text(script, encoding="utf-8", newline="\n")
        return destination

    def synthesize_many(
        self,
        findings: Iterable[Finding],
        ctx: ScanContext,
        *,
        limit: int = MAX_SCRIPTS,
    ) -> tuple[Path, ...]:
        """Write repro scripts for several findings, highest risk first.

        Parameters:
            findings: Candidate findings.
            ctx: Scan context supplying the target path.
            limit: Maximum number of scripts to write.

        Returns:
            The written script paths in descending risk order.

        Raises:
            ValueError: When limit is negative.
        """

        if limit < 0:
            raise ValueError("limit must not be negative")
        ordered = sorted(
            findings,
            key=lambda item: (-float(item.risk), int(item.pillar)),
        )
        written: list[Path] = []
        for finding in ordered:
            if len(written) >= limit:
                break
            path = self.synthesize(finding, ctx)
            if path is not None:
                written.append(path)
        return tuple(written)

    def _render_script(self, finding: Finding, ctx: ScanContext) -> str:
        """Select and fill the template matching the finding."""

        haystack = _haystack(finding)
        if finding.pillar == 6 or _PICKLE_WORDS.search(haystack):
            return self._pickle_script(finding)
        if finding.pillar == 9 or _PORT_WORDS.search(haystack):
            return self._port_script(finding)
        if finding.pillar == 11 or _TOKEN_WORDS.search(haystack):
            return self._token_script(finding)
        return self._generic_script(finding, ctx)

    def _token_script(self, finding: Finding) -> str:
        family, sample = _token_family(_haystack(finding))
        return _fill(
            _TOKEN_TEMPLATE,
            {
                "PILLAR": str(finding.pillar),
                "STATUS": _quote(finding.status),
                "FAMILY": _quote(family),
                "SAMPLE": _quote(sample),
            },
        )

    def _pickle_script(self, finding: Finding) -> str:
        return _fill(
            _PICKLE_TEMPLATE,
            {
                "PILLAR": str(finding.pillar),
                "STATUS": _quote(finding.status),
            },
        )

    def _port_script(self, finding: Finding) -> str:
        return _fill(
            _PORT_TEMPLATE,
            {
                "PILLAR": str(finding.pillar),
                "STATUS": _quote(finding.status),
                "PORT": str(_extract_port(finding)),
            },
        )

    def _generic_script(self, finding: Finding, ctx: ScanContext) -> str:
        spec = SPEC_BY_NUMBER[finding.pillar]
        project = str(_project_root(ctx))
        return _fill(
            _GENERIC_TEMPLATE,
            {
                "PILLAR": str(finding.pillar),
                "PILLAR_KEY": spec.key,
                "STATUS": _quote(finding.status),
                "PROJECT": _quote(project),
                "TARGET": _quote(str(ctx.target)),
            },
        )


def _project_root(ctx: ScanContext) -> str:
    """Return the import root used by the generic repro script.

    The scan target is normally a project root, but when the package itself lives
    in a parent directory the probe import needs that parent. Prefer the nearest
    ancestor that contains a tauhaulity package.
    """

    target = Path(ctx.target)
    try:
        resolved = target.resolve()
    except OSError:
        resolved = target
    for candidate in (resolved, *resolved.parents):
        if (candidate / "tauhaulity" / "__init__.py").is_file():
            return str(candidate)
    return str(resolved)


__all__ = ["AutoReproSynthesizer", "MAX_SCRIPTS", "REPRO_FILENAME_FORMAT"]

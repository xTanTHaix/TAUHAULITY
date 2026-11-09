"""Build the release artifacts: wheel, single-file zipapp and checksums.

The wheel is assembled with zipfile instead of a build backend so that a release
needs nothing but a CPython interpreter: no network, no setuptools, no build
frontend. That keeps the zero-dependency promise true for the release process as
well as for the runtime, and it makes the artifact byte-for-byte reproducible
from the source tree.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import shutil
import sys
import tempfile
import zipapp
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"
PACKAGE_DIR = "tauhaulity"
WHEEL_TAG = "py3-none-any"
ENTRY_POINT = "tauhaulity = tauhaulity.cli:main"
ZIPAPP_MAIN = "import sys\n\nfrom tauhaulity.cli import main\n\nsys.exit(main())\n"

METADATA_TEMPLATE = """Metadata-Version: 2.1
Name: tauhaulity
Version: {version}
Summary: 12-pillar project safety scan with containment, OSV advisories, quarantine, undo net and dossier exporter
License: MIT
Requires-Python: >=3.12
Classifier: Programming Language :: Python :: 3.12
Classifier: Programming Language :: Python :: 3.13
Classifier: Programming Language :: Python :: 3.14
Classifier: Programming Language :: Python :: 3.15
Classifier: Programming Language :: Rust
Classifier: License :: OSI Approved :: MIT License
Classifier: Operating System :: Microsoft :: Windows
Classifier: Operating System :: POSIX :: Linux
Description-Content-Type: text/markdown

{description}
"""

WHEEL_TEMPLATE = """Wheel-Version: 1.0
Generator: tauhaulity.build_release
Root-Is-Purelib: true
Tag: {tag}
"""


def project_version() -> str:
    """Read the version from the package without importing it.

    Reading the module metadata keeps a single source of truth: bumping
    tauhaulity/__init__.py is enough for both artifacts.
    """

    import re

    text = (ROOT / PACKAGE_DIR / "__init__.py").read_text(encoding="utf-8")
    match = re.search(r'^__version__\s*=\s*"([^"]+)"', text, flags=re.MULTILINE)
    if match is None:
        raise SystemExit("cannot find __version__ in tauhaulity/__init__.py")
    return match.group(1)


def _iter_package_files() -> list[Path]:
    """Return every shippable file of the package, sorted for reproducibility."""

    files = [
        path
        for path in (ROOT / PACKAGE_DIR).rglob("*")
        if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc"
    ]
    return sorted(files, key=lambda path: path.as_posix())


def _record_line(archive_path: str, data: bytes) -> str:
    """Return one RECORD row with the urlsafe base64 digest PEP 427 requires."""

    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode("ascii")
    return f"{archive_path},sha256={digest},{len(data)}"


def build_wheel(output_dir: Path, version: str) -> Path:
    """Assemble a pure-Python wheel and return its path.

    Parameters:
        output_dir: Directory the wheel is written into.
        version: Distribution version, used in the file name and METADATA.

    Returns:
        The written wheel path.

    Raises:
        OSError: When the archive cannot be written.
    """

    dist_info = f"tauhaulity-{version}.dist-info"
    description = (ROOT / "README.md").read_text(encoding="utf-8")
    metadata = METADATA_TEMPLATE.format(version=version, description=description).encode("utf-8")
    wheel_meta = WHEEL_TEMPLATE.format(tag=WHEEL_TAG).encode("utf-8")
    entry_points = ("[console_scripts]\n" + ENTRY_POINT + "\n").encode("utf-8")

    members: list[tuple[str, bytes]] = []
    for path in _iter_package_files():
        members.append((path.relative_to(ROOT).as_posix(), path.read_bytes()))
    members.append((f"{dist_info}/METADATA", metadata))
    members.append((f"{dist_info}/WHEEL", wheel_meta))
    members.append((f"{dist_info}/entry_points.txt", entry_points))

    output_dir.mkdir(parents=True, exist_ok=True)
    wheel_path = output_dir / f"tauhaulity-{version}-{WHEEL_TAG}.whl"
    with zipfile.ZipFile(wheel_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in members:
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            archive.writestr(info, data)
        record = [_record_line(name, data) for name, data in members]
        record.append(f"{dist_info}/RECORD,,")
        archive.writestr(f"{dist_info}/RECORD", "\n".join(record) + "\n")
    return wheel_path


def build_zipapp(output_dir: Path) -> Path:
    """Assemble the single-file zipapp and return its path."""

    output_dir.mkdir(parents=True, exist_ok=True)
    target = output_dir / "tauhaulity.pyz"
    with tempfile.TemporaryDirectory(prefix="tauhaulity_release_") as staging:
        staging_root = Path(staging)
        shutil.copytree(
            ROOT / PACKAGE_DIR,
            staging_root / PACKAGE_DIR,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )
        (staging_root / "__main__.py").write_text(ZIPAPP_MAIN, encoding="utf-8", newline=chr(10))
        zipapp.create_archive(staging_root, target=target, interpreter="/usr/bin/env python3", compressed=True)
    return target


def write_checksums(paths: list[Path], output_dir: Path) -> Path:
    """Write a SHA256SUMS file covering every artifact."""

    manifest = output_dir / "SHA256SUMS"
    lines = []
    for path in paths:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        lines.append(f"{digest}  {path.name}")
    manifest.write_text("\n".join(lines) + "\n", encoding="utf-8", newline=chr(10))
    return manifest


def main(argv: list[str] | None = None) -> int:
    """Build every artifact and print a JSON summary."""

    parser = argparse.ArgumentParser(description="Build the Tauhaulity release artifacts.")
    parser.add_argument("--output", default=str(DIST), help="output directory (default: dist/)")
    args = parser.parse_args(argv)

    output_dir = Path(args.output)
    if not output_dir.is_absolute():
        output_dir = ROOT / output_dir
    version = project_version()
    for stale in output_dir.glob("tauhaulity-*.whl"):
        stale.unlink()
    wheel = build_wheel(output_dir, version)
    zipapp_path = build_zipapp(output_dir)
    manifest = write_checksums([wheel, zipapp_path], output_dir)
    summary = {
        "version": version,
        "wheel": str(wheel),
        "zipapp": str(zipapp_path),
        "checksums": str(manifest),
        "wheel_bytes": wheel.stat().st_size,
        "zipapp_bytes": zipapp_path.stat().st_size,
        "packaged_files": len(_iter_package_files()),
    }
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())

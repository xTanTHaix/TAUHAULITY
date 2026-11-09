"""Build a single-file zipapp distribution of Tauhaulity.

A developer who wants to try the tool should not have to install a package
manager, a virtual environment and a console script first. This builder packs
the pure Python package and a tiny entry point into one .pyz archive that runs
with any CPython 3.12+ interpreter on Windows, macOS or Linux.
"""

from __future__ import annotations

import argparse
import shutil
import sys
import tempfile
import zipapp
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "tauhaulity"
DEFAULT_OUTPUT = ROOT / "dist" / "tauhaulity.pyz"
MAIN_TEMPLATE = """import sys

from tauhaulity.cli import main

sys.exit(main())
"""


def build(output: Path = DEFAULT_OUTPUT, *, root: Path = ROOT) -> Path:
    """Assemble the zipapp and return its path.

    Parameters:
        output: Destination .pyz file; its parent directory is created.
        root: Repository root containing the tauhaulity package.

    Returns:
        The written archive path.

    Raises:
        FileNotFoundError: When the package directory is missing.
        OSError: When the archive cannot be written.
    """

    package = root / "tauhaulity"
    if not package.is_dir():
        raise FileNotFoundError(f"package directory not found: {package}")
    destination = Path(output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="tauhaulity_pyz_") as staging:
        staging_root = Path(staging)
        shutil.copytree(package, staging_root / "tauhaulity", ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        (staging_root / "__main__.py").write_text(MAIN_TEMPLATE, encoding="utf-8", newline=chr(10))
        zipapp.create_archive(
            staging_root,
            target=destination,
            interpreter="/usr/bin/env python3",
            compressed=True,
        )
    return destination


def main(argv: list[str] | None = None) -> int:
    """Build the zipapp from the command line and report its size."""

    parser = argparse.ArgumentParser(description="Build the single-file Tauhaulity zipapp.")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT), help="destination .pyz path")
    args = parser.parse_args(argv)
    path = build(Path(args.output))
    print(f"built {path} ({path.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Entrypoint for python -m tauhaulity."""

from __future__ import annotations

import sys

from tauhaulity.cli import main

if __name__ == "__main__":
    sys.exit(main())

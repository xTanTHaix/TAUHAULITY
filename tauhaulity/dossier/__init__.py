"""Dossier exporter: report model, three renderers, redactor and form parser.

Nothing is imported at package import time. The renderers pull in the width
engine and the form parser, and a broken optional import must never stop the CLI
from reaching the rest of the package, so the public names are resolved lazily on
first attribute access.
"""

from __future__ import annotations

import importlib
from typing import Any

_LAZY: dict[str, tuple[str, str]] = {
    "DossierReport": ("tauhaulity.dossier.model", "DossierReport"),
    "DOSSIER_SCHEMA": ("tauhaulity.dossier.model", "DOSSIER_SCHEMA"),
    "REPORT_FILENAMES": ("tauhaulity.dossier.model", "REPORT_FILENAMES"),
    "build_report": ("tauhaulity.dossier.report", "build_report"),
    "write_reports": ("tauhaulity.dossier.report", "write_reports"),
    "render_reports": ("tauhaulity.dossier.report", "render_reports"),
    "render_markdown": ("tauhaulity.dossier.report", "render_markdown"),
    "render_text": ("tauhaulity.dossier.report", "render_text"),
    "render_json": ("tauhaulity.dossier.report", "render_json"),
    "report_hmac_payload": ("tauhaulity.dossier.report", "report_hmac_payload"),
    "verify_report": ("tauhaulity.dossier.report", "verify_report"),
    "verify_dossier_file": ("tauhaulity.dossier.verify", "verify_dossier_file"),
    "VerificationResult": ("tauhaulity.dossier.verify", "VerificationResult"),
    "build_file_stamp": ("tauhaulity.dossier.integrity", "build_file_stamp"),
    "split_file_stamp": ("tauhaulity.dossier.integrity", "split_file_stamp"),
    "FormError": ("tauhaulity.dossier.form_parser", "FormError"),
    "parse_form": ("tauhaulity.dossier.form_parser", "parse_form"),
    "render_form_lines": ("tauhaulity.dossier.form_parser", "render_form_lines"),
    "render_form_updates": ("tauhaulity.dossier.form_parser", "render_form_updates"),
    "redact_text": ("tauhaulity.dossier.redactor", "redact_text"),
    "mask_secret": ("tauhaulity.dossier.redactor", "mask_secret"),
    "hmac_sha256_hex": ("tauhaulity.dossier.redactor", "hmac_sha256_hex"),
    "machine_key": ("tauhaulity.dossier.redactor", "machine_key"),
    "verify_hmac": ("tauhaulity.dossier.redactor", "verify_hmac"),
    "resolve_signing_key": ("tauhaulity.dossier.redactor", "resolve_signing_key"),
    "SIGNING_KEY_ENV": ("tauhaulity.dossier.redactor", "SIGNING_KEY_ENV"),
}

__all__ = list(_LAZY)


def __getattr__(name: str) -> Any:
    """Resolve one public name from its defining module on first use."""

    target = _LAZY.get(name)
    if target is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module_name, attribute = target
    module = importlib.import_module(module_name)
    value = getattr(module, attribute)
    globals()[name] = value
    return value

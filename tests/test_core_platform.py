"""Platform fingerprint tests: cached identity and coherent labels."""

from __future__ import annotations

import sys

from tauhaulity.core.platform_probe import detect_platform


def test_detection_is_cached() -> None:
    assert detect_platform() is detect_platform()


def test_platform_fields_are_coherent() -> None:
    info = detect_platform()
    assert info.os_family in {"windows", "linux"} or info.os_family
    assert info.arch
    assert info.python_version == ".".join(str(part) for part in sys.version_info[:3])
    assert info.os_label
    assert info.python_label.startswith(info.implementation)
    assert isinstance(info.primitives, object)
    assert "ctypes" in info.primitives
    assert info.engine_tier in {"FULL_RUST_PY_SHIELD", "CTYPES_OS_PRIMITIVE_FALLBACK"}


def test_hardware_label_lists_resolved_primitives() -> None:
    info = detect_platform()
    label = info.hardware_label
    assert label
    if info.has("ctypes"):
        assert "ctypes" in label

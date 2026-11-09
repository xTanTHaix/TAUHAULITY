"""Tests for pillar four: PhantomFS lifecycle and mirage capability reporting.

PhantomFS is a real filesystem API over dictionaries, so the tests exercise it the
way an attacker's redirected I/O would: create, write, read, stat, list, delete.
The no-disk-writes test runs with the process cwd pointed at a temporary directory
and proves the directory stays empty.
"""

from __future__ import annotations

import os
import stat as stat_module
from pathlib import Path

import pytest

from tauhaulity.core.contracts import ScanContext, ScanOptions
from tauhaulity.pillars import p04_deception as pillar


def _make_ctx(target: Path, platform_info, policy) -> ScanContext:
    return ScanContext(target=Path(target), platform=platform_info, policy=policy, options=ScanOptions())


def test_normalize_path_forms() -> None:
    assert pillar.normalize_path("/a/b/c") == "/a/b/c"
    assert pillar.normalize_path("a//b/./c/../d") == "/a/b/d"
    assert pillar.normalize_path("..//..") == "/"
    assert pillar.normalize_path("C:\\Windows\\..\\Temp\\x.txt") == "/drive/c/Temp/x.txt"
    assert pillar.normalize_path("/a/b/") == "/a/b"
    with pytest.raises(pillar.PhantomFSError):
        pillar.normalize_path("")
    with pytest.raises(pillar.PhantomFSError):
        pillar.normalize_path("/a\x00b")


def test_file_lifecycle() -> None:
    fs = pillar.PhantomFS()
    assert fs.isdir("/")
    fs.mkdir("/mirage/payloads", mode=0o700)
    assert fs.isdir("/mirage")
    assert fs.isdir("/mirage/payloads")
    written = fs.write_text("/mirage/payloads/note.txt", "captured payload\n")
    assert written == len("captured payload\n")
    assert fs.isfile("/mirage/payloads/note.txt")
    assert fs.read_text("/mirage/payloads/note.txt") == "captured payload\n"
    assert fs.read_bytes("/mirage/payloads/note.txt") == b"captured payload\n"
    assert fs.listdir("/mirage/payloads") == ["note.txt"]
    info = fs.stat("/mirage/payloads/note.txt")
    assert stat_module.S_ISREG(info.st_mode)
    assert info.st_size == written
    assert info.st_ino > 0
    directory_info = fs.stat("/mirage/payloads")
    assert stat_module.S_ISDIR(directory_info.st_mode)
    fs.unlink("/mirage/payloads/note.txt")
    assert not fs.exists("/mirage/payloads/note.txt")
    assert fs.listdir("/mirage/payloads") == []
    fs.rmdir("/mirage/payloads")
    assert not fs.exists("/mirage/payloads")
    assert fs.stats()["unlinks"] == 1
    assert fs.snapshot()["/"]["kind"] == "dir"


def test_append_seek_and_modes() -> None:
    fs = pillar.PhantomFS()
    fs.mkdir("/jail")
    fs.write_bytes("/jail/blob.bin", b"abc")
    with fs.open("/jail/blob.bin", "ab") as handle:
        handle.write(b"def")
    assert fs.read_bytes("/jail/blob.bin") == b"abcdef"
    with fs.open("/jail/blob.bin", "rb") as handle:
        handle.seek(2)
        assert handle.tell() == 2
        assert handle.read(2) == b"cd"
        handle.seek(-1, os.SEEK_END)
        assert handle.read() == b"f"
    with fs.open("/jail/blob.bin", "r") as handle:
        assert handle.read() == "abcdef"
    with fs.open("/jail/blob.bin", "w") as handle:
        handle.write("reset")
    assert fs.read_bytes("/jail/blob.bin") == b"reset"
    with pytest.raises(TypeError):
        with fs.open("/jail/blob.bin", "wb") as handle:
            handle.write("text is not bytes")
    with pytest.raises(ValueError):
        fs.open("/jail/blob.bin", "rw")


def test_path_errors_are_filesystem_semantics() -> None:
    fs = pillar.PhantomFS()
    fs.mkdir("/dir")
    fs.write_bytes("/dir/file.bin", b"x")
    with pytest.raises(FileNotFoundError):
        fs.open("/missing.txt", "r")
    with pytest.raises(FileNotFoundError):
        fs.open("/missing/deep.txt", "w")
    with pytest.raises(FileExistsError):
        fs.mkdir("/dir")
    with pytest.raises(FileNotFoundError):
        fs.mkdir("/parent/child", parents=False)
    with pytest.raises(IsADirectoryError):
        fs.unlink("/dir")
    with pytest.raises(NotADirectoryError):
        fs.listdir("/dir/file.bin")
    with pytest.raises(FileNotFoundError):
        fs.stat("/nope")
    with pytest.raises(OSError):
        fs.rmdir("/dir")
    with pytest.raises(PermissionError):
        fs.rmdir("/")
    with pytest.raises(IsADirectoryError):
        fs.open("/dir", "r")


def test_phantomfs_never_touches_disk(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    fs = pillar.PhantomFS()
    fs.mkdir("/jail/evidence")
    fs.write_text("/jail/evidence/loot.txt", "stay in ram")
    fs.unlink("/jail/evidence/loot.txt")
    assert fs.total_bytes() == 0
    assert list(tmp_path.iterdir()) == []


def test_mirage_capability_is_consistent() -> None:
    capability = pillar.MirageCapabilityProbe().probe(phantomfs=True)
    assert capability.platform in {"win32", "linux", capability.platform}
    assert "phantomfs" in capability.primitives
    assert capability.detail
    if os.name == "nt":
        assert capability.namespaces == ()
        assert capability.unshare_symbol is False
        assert isinstance(capability.job_objects, bool)
        assert capability.in_job is None or isinstance(capability.in_job, bool)
    else:
        assert isinstance(capability.namespaces, tuple)
        assert isinstance(capability.unshare_symbol, bool)
        assert capability.partial == ((capability.namespace_view or capability.unshare_symbol) and not capability.unshare_usable)


def test_probe_returns_legal_finding(sample_project: Path, platform_info, default_policy) -> None:
    ctx = _make_ctx(sample_project, platform_info, default_policy)
    finding = pillar.probe(ctx)
    assert finding.pillar == 4
    assert finding.status in pillar.SPEC.statuses
    assert 0.0 <= finding.risk <= pillar.SPEC.risk_scale
    assert finding.slot("detail")
    assert finding.slot("mirage")
    ctx.record(finding)

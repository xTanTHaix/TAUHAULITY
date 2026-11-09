"""Loader tests: tier selection, primitive parity and total failure behaviour.

The suite runs on Windows (rust tier through the MinGW-w64 GNU target, or the
ctypes tier when the cdylib was never built) and on WSL Ubuntu (rust tier once
the .so is built). Native-only assertions skip when the shared library is
absent, because a missing build is an environment fact, not a defect.
"""

from __future__ import annotations

import hashlib
import os
import random
from pathlib import Path

import pytest

from tauhaulity.core.entropy import shannon_entropy
from tauhaulity.core.telemetry import crc64
from tauhaulity.primitives import loader

BACKENDS = {"rust", "ctypes", "python"}

#: Deterministic payloads that exercise the digest padding boundaries.
PAYLOADS = (
    b"",
    b"a",
    b"abc",
    bytes(range(256)),
    bytes(range(256)) * 16,
    b"x" * 55,
    b"x" * 56,
    b"x" * 63,
    b"x" * 64,
    b"x" * 65,
    b"x" * 1000,
    b"tauhaulity-silicon-shield",
)


@pytest.fixture()
def engine():
    """Return a freshly constructed engine and drop the cache afterwards."""

    loader._reset_engine()
    built = loader.get_engine()
    try:
        yield built
    finally:
        loader._reset_engine()


def _require_native() -> None:
    """Skip a native-only assertion when the crate was not built for this host."""

    if loader.find_native_library() is None:
        pytest.skip("tauhaulity_silicon_shield is not built for this platform")


def test_get_engine_returns_cached_singleton() -> None:
    loader._reset_engine()
    try:
        first = loader.get_engine()
        second = loader.get_engine()
        assert first is second
        assert first is not None
    finally:
        loader._reset_engine()


def test_engine_contract_fields_are_well_formed(engine) -> None:
    assert isinstance(engine.available, bool)
    assert engine.backend in BACKENDS
    assert isinstance(engine.version, str) and engine.version
    assert isinstance(engine.detail, str) and engine.detail
    assert engine.available is (engine.backend == "rust")


def test_sha256_matches_hashlib_for_every_padding_boundary(engine) -> None:
    for payload in PAYLOADS:
        digest = engine.sha256(payload)
        assert isinstance(digest, bytes)
        assert len(digest) == 32
        assert digest == hashlib.sha256(payload).digest()


def test_crc64_matches_the_telemetry_table(engine) -> None:
    for payload in PAYLOADS:
        measured = engine.crc64(payload)
        assert isinstance(measured, int)
        assert 0 <= measured <= 0xFFFFFFFFFFFFFFFF
        assert measured == crc64(payload)


def test_shannon_matches_the_core_entropy_implementation(engine) -> None:
    for payload in PAYLOADS:
        measured = engine.shannon(payload)
        assert isinstance(measured, float)
        assert 0.0 <= measured <= 8.0
        assert abs(measured - shannon_entropy(payload)) <= 1e-9
    assert engine.shannon(b"") == 0.0
    assert abs(engine.shannon(bytes(range(256))) - 8.0) <= 1e-9


def test_primitives_accept_other_buffer_types(engine) -> None:
    payload = b"buffer protocol parity"
    expected_sha = hashlib.sha256(payload).digest()
    for view in (bytearray(payload), memoryview(payload), memoryview(bytearray(payload))):
        assert engine.sha256(view) == expected_sha
        assert engine.crc64(view) == crc64(payload)
        assert abs(engine.shannon(view) - shannon_entropy(payload)) <= 1e-9


def test_string_input_is_rejected_instead_of_reencoded(engine) -> None:
    with pytest.raises(TypeError):
        engine.sha256("text is not bytes")  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        engine.crc64(1234)  # type: ignore[arg-type]


def test_random_payloads_stay_in_parity(engine) -> None:
    generator = random.Random(20261108)
    for length in (0, 1, 2, 15, 16, 17, 127, 128, 129, 1024, 4097):
        payload = bytes(generator.getrandbits(8) for _ in range(length))
        assert engine.sha256(payload) == hashlib.sha256(payload).digest()
        assert engine.crc64(payload) == crc64(payload)
        assert abs(engine.shannon(payload) - shannon_entropy(payload)) <= 1e-9


def test_forced_python_backend(monkeypatch) -> None:
    monkeypatch.setenv(loader.DISABLE_NATIVE_ENV, "1")
    loader._reset_engine()
    try:
        engine = loader.get_engine()
        assert engine.backend == "python"
        assert engine.available is False
        assert "pure Python" in engine.detail
        assert engine.sha256(b"abc") == hashlib.sha256(b"abc").digest()
        assert engine.crc64(b"123456789") == crc64(b"123456789")
        assert engine.lock_pages(bytearray(4096)) is False
        assert engine.dirty_pages(os.getpid()) == -1
        status = engine.page_seal_status()
        assert all(isinstance(value, str) for value in status.values())
        assert status["lock_pages"].startswith("disabled")
    finally:
        loader._reset_engine()


def test_explicit_override_with_unloadable_file_degrades_quietly(tmp_path, monkeypatch) -> None:
    fake = tmp_path / "not_a_library.bin"
    fake.write_bytes(b"this is not a dynamic library")
    monkeypatch.setenv(loader.LIBRARY_ENV, str(fake))
    loader._reset_engine()
    try:
        engine = loader.get_engine()
        assert engine.backend in {"ctypes", "python"}
        assert engine.available is False
        assert engine.detail
        assert engine.sha256(b"abc") == hashlib.sha256(b"abc").digest()
        assert loader.find_native_library() == fake
    finally:
        loader._reset_engine()


def test_explicit_override_selects_the_built_library(monkeypatch) -> None:
    native = loader.find_native_library()
    if native is None:
        pytest.skip("tauhaulity_silicon_shield is not built for this platform")
    # DISABLE_NATIVE_ENV is authoritative by design, so a suite running with the
    # tier-verification override exported must clear it before asserting that an
    # explicit library path selects the native backend.
    monkeypatch.delenv(loader.DISABLE_NATIVE_ENV, raising=False)
    monkeypatch.setenv(loader.LIBRARY_ENV, str(native))
    loader._reset_engine()
    try:
        engine = loader.get_engine()
        assert engine.backend == "rust"
        assert engine.available is True
        assert engine.version
    finally:
        loader._reset_engine()


def test_native_backend_is_selected_when_the_library_exists(monkeypatch) -> None:
    # The suite may run with TAUHAULITY_NO_NATIVE=1 exported (tier verification
    # pass); this test asserts native selection, so the ambient override must be
    # cleared explicitly instead of depending on the caller's environment.
    monkeypatch.delenv(loader.DISABLE_NATIVE_ENV, raising=False)
    _require_native()
    loader._reset_engine()
    try:
        engine = loader.get_engine()
        assert engine.backend == "rust"
        assert engine.available is True
        assert engine.detail.startswith("verified native cdylib")
    finally:
        loader._reset_engine()


def test_native_library_is_cross_verified_against_python() -> None:
    _require_native()
    loader._reset_engine()
    try:
        engine = loader.get_engine()
        generator = random.Random(424242)
        for length in (0, 3, 64, 65, 1024, 65536):
            payload = bytes(generator.getrandbits(8) for _ in range(length))
            assert engine.sha256(payload) == hashlib.sha256(payload).digest()
            assert engine.crc64(payload) == crc64(payload)
            assert abs(engine.shannon(payload) - shannon_entropy(payload)) <= 1e-9
    finally:
        loader._reset_engine()


def test_singleton_survives_a_failing_constructor(monkeypatch) -> None:
    def broken_init(self) -> None:
        raise MemoryError("simulated constructor failure")

    monkeypatch.setattr(loader.ShieldEngine, "__init__", broken_init)
    loader._reset_engine()
    try:
        engine = loader.get_engine()
        assert engine is not None
        assert engine.backend == "python"
        assert engine.available is False
        assert "construction failed" in engine.detail
        assert engine.sha256(b"abc") == hashlib.sha256(b"abc").digest()
        assert loader.get_engine() is engine
    finally:
        loader._reset_engine()


def test_bootstrap_failure_degrades_to_a_usable_engine(monkeypatch) -> None:
    def broken_bootstrap(self) -> None:
        raise RuntimeError("simulated bootstrap failure")

    monkeypatch.setattr(loader.ShieldEngine, "_bootstrap", broken_bootstrap)
    loader._reset_engine()
    try:
        engine = loader.get_engine()
        assert "downgraded" in engine.detail or "bootstrap failed" in engine.detail
        assert engine.available is False
        assert engine.crc64(b"abc") == crc64(b"abc")
    finally:
        loader._reset_engine()


def test_close_is_idempotent_and_keeps_the_engine_usable(engine) -> None:
    engine.close()
    engine.close()
    assert engine.closed is True
    assert engine.available is False
    assert engine.backend in {"ctypes", "python"}
    assert engine.sha256(b"abc") == hashlib.sha256(b"abc").digest()


def test_context_manager_closes_the_engine() -> None:
    loader._reset_engine()
    try:
        with loader.get_engine() as engine:
            assert engine.sha256(b"abc") == hashlib.sha256(b"abc").digest()
        assert engine.closed is True
    finally:
        loader._reset_engine()


# --------------------------------------------------------------------------- #
# Cross-compilation target directories
# --------------------------------------------------------------------------- #

#: A Windows GNU triple, the layout produced by build_windows_gnu.ps1.
GNU_TRIPLE = "x86_64-pc-windows-gnu"
#: A second triple used only to prove the ordering is deterministic.
SECOND_TRIPLE = "x86_64-pc-windows-msvc"


def _make_target_tree(root: Path) -> Path:
    """Create a minimal cargo target tree under a temporary checkout root.

    Returns:
        The rust_silicon_shield/target directory. The tree contains a plain
        release directory, two triple release directories, a triple directory
        without a release build, a documentation directory and a debug build.
    """

    crate = root / "rust_silicon_shield"
    crate.mkdir(parents=True)
    (crate / "Cargo.toml").write_text(
        '[package]\nname = "tauhaulity_silicon_shield"\nversion = "0.2.0"\n',
        encoding="utf-8",
    )
    target = crate / "target"
    for relative in (
        Path("release"),
        Path(GNU_TRIPLE) / "release",
        Path(SECOND_TRIPLE) / "release",
        Path("aarch64-unknown-linux-gnu"),
        Path("doc"),
        Path("debug"),
    ):
        (target / relative).mkdir(parents=True, exist_ok=True)
    return target


def test_triple_release_directories_are_discovered(tmp_path, monkeypatch) -> None:
    target = _make_target_tree(tmp_path)
    monkeypatch.setattr(loader, "_project_root", lambda: tmp_path)
    directories = loader._candidate_directories()
    plain = target / "release"
    gnu = target / GNU_TRIPLE / "release"
    msvc = target / SECOND_TRIPLE / "release"
    debug = target / "debug"

    assert plain in directories
    assert gnu in directories
    assert msvc in directories
    assert debug in directories
    # The plain build is preferred, then triples in a stable alphabetical order,
    # then the debug build, so two runs on the same tree agree.
    assert directories.index(plain) < directories.index(gnu)
    assert directories.index(gnu) < directories.index(msvc)
    assert directories.index(msvc) < directories.index(debug)


def test_target_directories_without_a_release_build_are_ignored(tmp_path, monkeypatch) -> None:
    target = _make_target_tree(tmp_path)
    monkeypatch.setattr(loader, "_project_root", lambda: tmp_path)
    directories = loader._candidate_directories()

    assert target / "aarch64-unknown-linux-gnu" not in directories
    assert target / "aarch64-unknown-linux-gnu" / "release" not in directories
    assert target / "doc" not in directories
    assert target / "release" in directories


def test_triple_build_is_selected_as_the_native_candidate(tmp_path, monkeypatch) -> None:
    target = _make_target_tree(tmp_path)
    filename = loader._library_filenames()[0]
    built = target / GNU_TRIPLE / "release" / filename
    built.write_bytes(b"placeholder handled by the loader verification")
    monkeypatch.setattr(loader, "_project_root", lambda: tmp_path)

    candidates = loader.native_candidates()
    assert built in candidates
    assert loader.find_native_library() == built


@pytest.mark.parametrize(
    "payload",
    [
        b"MZ" + b"\x00" * 62 + bytes(range(64)),
        b"\x7fELF\x02\x01\x01" + b"\x00" * 57,
        b"this file is not a shared library",
    ],
    ids=["truncated-pe", "foreign-elf-header", "plain-text"],
)
def test_unloadable_triple_build_degrades_to_the_platform_tier(tmp_path, monkeypatch, payload) -> None:
    filename = loader._library_filenames()[0]
    triple_release = tmp_path / "rust_silicon_shield" / "target" / GNU_TRIPLE / "release"
    triple_release.mkdir(parents=True)
    broken = triple_release / filename
    broken.write_bytes(payload)

    monkeypatch.setattr(loader, "_candidate_directories", lambda: (triple_release,))
    monkeypatch.delenv(loader.DISABLE_NATIVE_ENV, raising=False)
    monkeypatch.delenv(loader.LIBRARY_ENV, raising=False)
    loader._reset_engine()
    try:
        engine = loader.get_engine()
        assert engine.backend in {"ctypes", "python"}
        assert engine.available is False
        assert engine.version != "0.2.0"
        assert filename in engine.detail
        assert "load failed" in engine.detail
        # The primitives still have to be correct: a corrupt binary must never
        # poison a digest, it must only cost speed.
        assert engine.sha256(b"abc") == hashlib.sha256(b"abc").digest()
        assert engine.crc64(b"123456789") == crc64(b"123456789")
        assert abs(engine.shannon(b"abcd") - 2.0) <= 1e-9
        assert loader.native_candidates() == [broken]
    finally:
        loader._reset_engine()


def test_candidate_directories_tolerate_a_missing_target_tree(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(loader, "_project_root", lambda: tmp_path)
    directories = loader._candidate_directories()

    assert isinstance(directories, tuple)
    # A checkout that was never built still has to answer with the default
    # locations instead of raising during engine bootstrap.
    assert tmp_path / "rust_silicon_shield" / "target" / "release" in directories
    assert tmp_path / "rust_silicon_shield" / "target" / "debug" in directories


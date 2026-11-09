"""Tests for the real-time watch backends and the bounded watch loop.

Every timing test is bounded by a deadline instead of a fixed sleep, and the loop
runs on a worker thread while the test mutates the tree, because that is the only
way to exercise the event cycle without making the suite slow or flaky.

Kernel backend tests skip when the host has no notification primitive, so the
same file runs on Windows (ReadDirectoryChangesW), Linux (inotify) and any
platform that only has the polling fallback. The freeze tests never signal a real
process: prickly pids are either protected values (which must be refused) or are
replaced with recording stubs, so the assertions prove the gating logic and
nothing else.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
from pathlib import Path

import pytest

import tauhaulity.daemon.watch as watch
from tauhaulity.daemon.watch import (
    FileChange,
    WatchEvent,
    watch_backend_name,
    watch_loop,
)


def _project(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "canary.txt").write_text("do not touch" + chr(10), encoding="utf-8")
    (root / "notes.txt").write_text("plain notes" + chr(10), encoding="utf-8")
    return root


def _wait_until(predicate, timeout: float = 8.0, interval: float = 0.02) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return False


def _run_in_thread(root: Path, **kwargs):
    events: list[WatchEvent] = []
    results: list[int] = []
    errors: list[BaseException] = []
    backends: list[str] = []
    stop = kwargs.pop("stop", None) or threading.Event()

    def emit(event: WatchEvent) -> None:
        events.append(event)

    def run() -> None:
        try:
            results.append(
                watch_loop(
                    root,
                    stop=stop,
                    on_event=emit,
                    on_backend=backends.append,
                    **kwargs,
                )
            )
        except BaseException as exc:  # surface a loop crash instead of hiding it
            errors.append(exc)

    thread = threading.Thread(target=run, name="tauhaulity-watch-test")
    thread.start()
    return thread, events, results, errors, stop, backends


# ------------------------------------------------------------- existing loop


def test_canary_modification_produces_an_event(tmp_path: Path) -> None:
    root = _project(tmp_path / "project")
    thread, events, results, errors, stop, backends = _run_in_thread(root, interval_s=0.05)
    try:
        deadline = time.monotonic() + 8.0
        while time.monotonic() < deadline and not events:
            (root / "canary.txt").write_text(
                "tampered " + str(time.monotonic()), encoding="utf-8"
            )
            time.sleep(0.05)
    finally:
        stop.set()
        thread.join(10)
    assert not thread.is_alive()
    assert errors == []
    assert events
    canary_events = [event for event in events if event.kind == watch.CANARY_KIND]
    assert canary_events
    assert canary_events[0].path == "canary.txt"
    assert results == [len(events)]
    assert results[0] >= 1
    assert "T" in canary_events[0].at
    assert canary_events[0].at.endswith("+00:00")
    assert backends == [watch.watch_backend_name("auto")]


def test_clean_tree_yields_zero_events(tmp_path: Path) -> None:
    root = _project(tmp_path / "project")
    events: list[WatchEvent] = []
    count = watch_loop(root, interval_s=0.05, duration_s=0.3, on_event=events.append)
    assert count == 0
    assert events == []


def test_stop_event_ends_the_loop(tmp_path: Path) -> None:
    root = _project(tmp_path / "project")
    stop = threading.Event()
    stop.set()
    started = time.perf_counter()
    assert watch_loop(root, interval_s=0.05, stop=stop) == 0
    assert time.perf_counter() - started < 2.0


def test_duration_is_honoured(tmp_path: Path) -> None:
    root = _project(tmp_path / "project")
    started = time.perf_counter()
    assert watch_loop(root, interval_s=0.05, duration_s=0.25) == 0
    elapsed = time.perf_counter() - started
    assert 0.2 <= elapsed < 5.0


def test_zero_duration_returns_immediately(tmp_path: Path) -> None:
    root = _project(tmp_path / "project")
    started = time.perf_counter()
    assert watch_loop(root, interval_s=0.05, duration_s=0) == 0
    assert time.perf_counter() - started < 1.0


def test_vanished_canary_is_reported_without_raising(tmp_path: Path) -> None:
    root = _project(tmp_path / "project")
    thread, events, results, errors, stop, backends = _run_in_thread(root, interval_s=0.05)
    try:
        time.sleep(0.2)
        (root / "canary.txt").unlink()
        assert _wait_until(lambda: any("deleted" in event.detail for event in events))
    finally:
        stop.set()
        thread.join(10)
    assert errors == []
    deleted = [event for event in events if "deleted" in event.detail]
    assert deleted
    assert deleted[0].kind == watch.CANARY_KIND
    assert deleted[0].path == "canary.txt"


def test_entropy_alert_produces_an_event(tmp_path: Path) -> None:
    root = _project(tmp_path / "project")
    (root / "cipher.dat2").write_bytes(os.urandom(8192))
    events: list[WatchEvent] = []
    count = watch_loop(root, interval_s=0.05, duration_s=0.3, on_event=events.append)
    entropy = [event for event in events if event.kind == watch.ENTROPY_KIND]
    assert entropy
    assert entropy[0].path == "cipher.dat2"
    assert count == len(events)


def test_entropy_alert_is_reported_once(tmp_path: Path) -> None:
    root = _project(tmp_path / "project")
    (root / "cipher.dat2").write_bytes(os.urandom(8192))
    events: list[WatchEvent] = []
    watch_loop(root, interval_s=0.03, duration_s=0.4, on_event=events.append)
    entropy = [
        event
        for event in events
        if event.kind == watch.ENTROPY_KIND and event.path == "cipher.dat2"
    ]
    assert len(entropy) == 1


def test_invalid_arguments_raise(tmp_path: Path) -> None:
    root = _project(tmp_path / "project")
    for interval in (0, -1, True, "fast", float("nan")):
        with pytest.raises(ValueError):
            watch_loop(root, interval_s=interval)
    for duration in (-1, "long"):
        with pytest.raises(ValueError):
            watch_loop(root, interval_s=0.05, duration_s=duration)
    with pytest.raises(ValueError):
        watch_loop(root, interval_s=0.05, on_event=42)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        watch_loop(root, interval_s=0.05, stop=object())
    with pytest.raises(ValueError):
        watch_loop(root, interval_s=0.05, backend="bsd")
    with pytest.raises(ValueError):
        watch_loop(root, interval_s=0.05, on_backend=42)  # type: ignore[arg-type]


def test_callback_failure_does_not_stop_the_loop(tmp_path: Path) -> None:
    root = _project(tmp_path / "project")
    calls: list[WatchEvent] = []

    def explode(event: WatchEvent) -> None:
        calls.append(event)
        raise RuntimeError("consumer exploded")

    stop = threading.Event()
    results: list[int] = []

    def run() -> None:
        results.append(watch_loop(root, interval_s=0.05, stop=stop, on_event=explode))

    thread = threading.Thread(target=run, name="tauhaulity-watch-callback")
    thread.start()
    try:
        deadline = time.monotonic() + 8.0
        while time.monotonic() < deadline and not calls:
            (root / "canary.txt").write_text(
                "tampered " + str(time.monotonic()), encoding="utf-8"
            )
            time.sleep(0.05)
        thread.join(0.5)
        assert thread.is_alive(), "a failing callback must not end the loop"
    finally:
        stop.set()
        thread.join(10)
    assert calls
    assert results == [len(calls)]
    assert results[0] >= 1


# ----------------------------------------------------------- backend selection


def test_backend_name_reports_the_kernel_primitive() -> None:
    name = watch_backend_name("auto")
    assert name in {
        watch.LINUX_BACKEND_NAME,
        watch.WINDOWS_BACKEND_NAME,
        watch.POLLING_BACKEND_NAME,
    }
    if os.name == "nt":
        assert name != watch.LINUX_BACKEND_NAME
    elif sys.platform.startswith("linux"):
        assert name != watch.WINDOWS_BACKEND_NAME
    assert watch_backend_name("polling") == watch.POLLING_BACKEND_NAME


def test_create_backend_returns_the_selected_type(tmp_path: Path) -> None:
    backend = watch.create_backend(tmp_path, backend="auto")
    assert isinstance(backend, watch.WatchBackend)
    assert backend.name == watch_backend_name("auto")
    if backend.name == watch.WINDOWS_BACKEND_NAME:
        assert isinstance(backend, watch.WindowsBackend)
    elif backend.name == watch.LINUX_BACKEND_NAME:
        assert isinstance(backend, watch.LinuxBackend)
    else:
        assert isinstance(backend, watch.PollingBackend)


def test_unavailable_kernel_backend_reports_the_polling_fallback(tmp_path: Path) -> None:
    if os.name == "nt":
        selector, other = "linux", watch.LINUX_BACKEND_NAME
    elif sys.platform.startswith("linux"):
        selector, other = "windows", watch.WINDOWS_BACKEND_NAME
    else:
        pytest.skip("only one kernel backend family exists on this host platform")
    assert watch.watch_backend_name(selector) == watch.POLLING_BACKEND_NAME
    backend = watch.create_backend(tmp_path, backend=selector)
    assert backend.name == watch.POLLING_BACKEND_NAME
    assert getattr(backend, "reason", "")
    assert "not available" in backend.reason
    assert other  # documented name of the backend that was refused


def test_invalid_backend_selector_raises(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        watch_backend_name("bsd")
    with pytest.raises(ValueError):
        watch.create_backend(tmp_path, backend="bsd")


def test_polling_backend_is_always_available(tmp_path: Path) -> None:
    assert watch_backend_name("polling") == watch.POLLING_BACKEND_NAME
    backend = watch.create_backend(tmp_path, backend="polling")
    assert isinstance(backend, watch.PollingBackend)
    assert backend.name == watch.POLLING_BACKEND_NAME
    assert "polling" in backend.reason


# ------------------------------------------------------------- backend protocol


def test_backend_delivers_a_real_filesystem_event(tmp_path: Path) -> None:
    root = _project(tmp_path / "project")
    backend = watch.create_backend(root, backend="auto", interval_s=0.05)
    if backend.name == watch.POLLING_BACKEND_NAME:
        pytest.skip("no kernel notification backend on this host: " + backend.reason)
    backend.start()
    try:
        target = root / "watched.txt"
        target.write_text("first change", encoding="utf-8")
        deadline = time.monotonic() + 3.0
        changes: list[FileChange] = []
        while time.monotonic() < deadline and not changes:
            backend.wait(0.05)
            changes = backend.events()
        assert changes, "kernel backend delivered no event within 3 s"
        assert all(isinstance(change, FileChange) for change in changes)
        assert any("watched.txt" in change.rel_path for change in changes)
        start = time.perf_counter()
        assert backend.events() == []
        assert time.perf_counter() - start < 0.5
    finally:
        backend.stop()
    backend.stop()  # idempotent teardown must not raise


def test_backend_double_start_is_refused(tmp_path: Path) -> None:
    root = _project(tmp_path / "project")
    backend = watch.create_backend(root, backend="polling", interval_s=0.05)
    backend.start()
    try:
        with pytest.raises(RuntimeError):
            backend.start()
    finally:
        backend.stop()


def test_backend_wait_is_bounded(tmp_path: Path) -> None:
    root = _project(tmp_path / "project")
    backend = watch.create_backend(root, backend="polling", interval_s=0.05)
    backend.start()
    try:
        started = time.perf_counter()
        backend.wait(0.1)
        assert time.perf_counter() - started < 1.0
        # The polling backend may legitimately have queued nothing on a quiet tree.
        assert isinstance(backend.events(), list)
    finally:
        backend.stop()


def test_watch_loop_reports_the_backend_in_every_event(tmp_path: Path) -> None:
    root = _project(tmp_path / "project")
    thread, events, results, errors, stop, backends = _run_in_thread(
        root, interval_s=0.05, backend="polling"
    )
    try:
        deadline = time.monotonic() + 8.0
        while time.monotonic() < deadline and not events:
            (root / "canary.txt").write_text(
                "tampered " + str(time.monotonic()), encoding="utf-8"
            )
            time.sleep(0.05)
    finally:
        stop.set()
        thread.join(10)
    assert errors == []
    assert events
    assert backends == [watch.POLLING_BACKEND_NAME]
    assert all("backend=polling" in event.detail for event in events)


def test_watch_loop_reports_the_auto_backend_name(tmp_path: Path) -> None:
    root = _project(tmp_path / "project")
    names: list[str] = []
    watch_loop(root, interval_s=0.05, duration_s=0.2, on_backend=names.append)
    assert names == [watch_backend_name("auto")]


# ----------------------------------------------------------------- freeze gates


def test_freeze_disabled_by_flag_never_suspends(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _project(tmp_path / "project")
    state = root / ".tauhaulity"
    state.mkdir()
    (state / "policy.json").write_text(json.dumps({"canary_freeze": True}), encoding="utf-8")
    calls: list[int] = []
    monkeypatch.setattr(
        watch, "_suspend_process", lambda pid: calls.append(pid) or True
    )
    thread, events, results, errors, stop, backends = _run_in_thread(
        root, interval_s=0.05, freeze=False
    )
    try:
        deadline = time.monotonic() + 8.0
        while time.monotonic() < deadline and not events:
            (root / "canary.txt").write_text(
                "tampered " + str(time.monotonic()), encoding="utf-8"
            )
            time.sleep(0.05)
    finally:
        stop.set()
        thread.join(10)
    assert calls == []
    assert [event for event in events if event.kind == watch.FREEZE_KIND] == []


def test_freeze_without_policy_is_reported_but_not_attempted(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _project(tmp_path / "project")

    def forbidden(pid: int) -> bool:
        raise AssertionError("the policy gate must be checked before suspending")

    monkeypatch.setattr(watch, "_suspend_process", forbidden)
    thread, events, results, errors, stop, backends = _run_in_thread(
        root, interval_s=0.05, freeze=True
    )
    try:
        deadline = time.monotonic() + 8.0
        while time.monotonic() < deadline and not any(
            event.kind == watch.FREEZE_KIND for event in events
        ):
            (root / "canary.txt").write_text(
                "tampered " + str(time.monotonic()), encoding="utf-8"
            )
            time.sleep(0.05)
    finally:
        stop.set()
        thread.join(10)
    assert errors == []
    freeze_events = [event for event in events if event.kind == watch.FREEZE_KIND]
    assert freeze_events
    assert "not frozen" in freeze_events[0].detail
    assert "canary_freeze" in freeze_events[0].detail


def test_freeze_suspends_the_writer_when_policy_allows(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _project(tmp_path / "project")
    state = root / ".tauhaulity"
    state.mkdir()
    (state / "policy.json").write_text(
        json.dumps({"canary_freeze": True}), encoding="utf-8"
    )
    monkeypatch.setattr(watch, "_writer_pids", lambda root_path, paths: ([4242], ""))
    monkeypatch.setattr(watch, "_suspend_process", lambda pid: pid == 4242)
    thread, events, results, errors, stop, backends = _run_in_thread(
        root, interval_s=0.05, freeze=True
    )
    try:
        deadline = time.monotonic() + 8.0
        while time.monotonic() < deadline and not any(
            event.kind == watch.FREEZE_KIND for event in events
        ):
            (root / "canary.txt").write_text(
                "tampered " + str(time.monotonic()), encoding="utf-8"
            )
            time.sleep(0.05)
    finally:
        stop.set()
        thread.join(10)
    assert errors == []
    freeze_events = [event for event in events if event.kind == watch.FREEZE_KIND]
    assert freeze_events
    assert "suspended pid(s) 4242" in freeze_events[0].detail
    assert "canary.txt" in freeze_events[0].detail
    assert "resume with resume_process(pid)" in freeze_events[0].detail


def test_freeze_reports_when_no_writer_is_found(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _project(tmp_path / "project")
    state = root / ".tauhaulity"
    state.mkdir()
    (state / "policy.json").write_text(
        json.dumps({"canary_freeze": True}), encoding="utf-8"
    )
    monkeypatch.setattr(
        watch,
        "_writer_pids",
        lambda root_path, paths: ([], "no live process holds the canary open"),
    )
    thread, events, results, errors, stop, backends = _run_in_thread(
        root, interval_s=0.05, freeze=True
    )
    try:
        deadline = time.monotonic() + 8.0
        while time.monotonic() < deadline and not any(
            event.kind == watch.FREEZE_KIND for event in events
        ):
            (root / "canary.txt").write_text(
                "tampered " + str(time.monotonic()), encoding="utf-8"
            )
            time.sleep(0.05)
    finally:
        stop.set()
        thread.join(10)
    assert errors == []
    freeze_events = [event for event in events if event.kind == watch.FREEZE_KIND]
    assert freeze_events
    assert "not frozen: no live process holds the canary open" in freeze_events[0].detail


def test_unattributable_writer_is_reported_without_guessing_a_pid(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _project(tmp_path / "project")
    state = root / ".tauhaulity"
    state.mkdir()
    (state / "policy.json").write_text(
        json.dumps({"canary_freeze": True}), encoding="utf-8"
    )
    reason = "the Windows handle table is not enumerable from the standard library"
    monkeypatch.setattr(watch, "_writer_pids", lambda root_path, paths: ([], reason))
    suspended: list[int] = []
    monkeypatch.setattr(watch, "_suspend_process", lambda pid: suspended.append(pid) or True)
    thread, events, results, errors, stop, backends = _run_in_thread(
        root, interval_s=0.05, freeze=True
    )
    try:
        deadline = time.monotonic() + 8.0
        while time.monotonic() < deadline and not any(
            event.kind == watch.FREEZE_KIND for event in events
        ):
            (root / "canary.txt").write_text(
                "tampered " + str(time.monotonic()), encoding="utf-8"
            )
            time.sleep(0.05)
    finally:
        stop.set()
        thread.join(10)
    assert errors == []
    freeze_events = [event for event in events if event.kind == watch.FREEZE_KIND]
    assert freeze_events
    detail = freeze_events[0].detail
    assert "not frozen" in detail
    assert "handle table" in detail
    assert "suspended pid(s)" not in detail
    assert suspended == []


def test_suspend_and_resume_are_exposed() -> None:
    assert callable(watch.suspend_process)
    assert callable(watch.resume_process)
    assert watch._suspend_process is watch.suspend_process  # backwards compatible hook


def test_protected_pids_are_refused() -> None:
    protected = {0, 4, os.getpid()}
    parent = os.getppid()
    if parent > 0:
        protected.add(parent)
    for pid in sorted(protected):
        assert watch.suspend_process(pid) is False, "suspend must refuse " + str(pid)
        assert watch.resume_process(pid) is False, "resume must refuse " + str(pid)
    assert watch.suspend_process(-1) is False
    assert watch.suspend_process(True) is False
    assert watch.resume_process(0) is False


# --------------------------------------------------------- stop and duration


def _available_selectors() -> list[str]:
    selectors = [watch.BACKEND_POLLING]
    if watch_backend_name("auto") != watch.POLLING_BACKEND_NAME:
        selectors.append(watch.BACKEND_AUTO)
    return selectors


def test_stop_ends_every_backend_promptly(tmp_path: Path) -> None:
    for index, selector in enumerate(_available_selectors()):
        root = _project(tmp_path / ("stop" + str(index)))
        stop = threading.Event()
        results: list[int] = []

        def run(loop_root: Path = root, loop_selector: str = selector) -> None:
            results.append(
                watch_loop(loop_root, interval_s=1.0, stop=stop, backend=loop_selector)
            )

        thread = threading.Thread(target=run, name="tauhaulity-stop-" + selector)
        thread.start()
        time.sleep(0.25)
        started = time.perf_counter()
        stop.set()
        thread.join(3.0)
        elapsed = time.perf_counter() - started
        assert not thread.is_alive(), selector + " did not stop"
        assert elapsed < 1.0, selector + " took " + format(elapsed, ".3f") + "s to stop"
        assert results == [0]


def test_duration_ends_every_backend_promptly(tmp_path: Path) -> None:
    for index, selector in enumerate(_available_selectors()):
        root = _project(tmp_path / ("duration" + str(index)))
        started = time.perf_counter()
        count = watch_loop(root, interval_s=0.05, duration_s=0.2, backend=selector)
        elapsed = time.perf_counter() - started
        assert count == 0
        assert 0.15 <= elapsed < 2.0, selector + " elapsed " + format(elapsed, ".3f")


# --------------------------------------------------------------- idle cost


def test_idle_watch_does_not_spin(tmp_path: Path) -> None:
    root = _project(tmp_path / "project")
    stop = threading.Event()
    events: list[WatchEvent] = []

    def run() -> None:
        watch_loop(root, interval_s=0.2, stop=stop, on_event=events.append)

    thread = threading.Thread(target=run, name="tauhaulity-idle")
    thread.start()
    try:
        time.sleep(0.3)  # let startup cost settle before measuring idle
        cpu_before = time.process_time()
        wall_before = time.monotonic()
        time.sleep(1.0)
        cpu_delta = time.process_time() - cpu_before
        wall_delta = time.monotonic() - wall_before
    finally:
        stop.set()
        thread.join(5)
    assert not thread.is_alive()
    assert events == []
    assert cpu_delta < 0.2, (
        "idle watch burned " + format(cpu_delta, ".3f") + "s CPU over "
        + format(wall_delta, ".2f") + "s wall"
    )


# ---------------------------------------------------- entropy burst classifier


def test_entropy_burst_tracker_classifies_three_writes() -> None:
    tracker = watch.EntropyBurstTracker(window_s=2.0, hits=3)
    assert tracker.add(0.0, "a.bin", 7.9) == []
    assert tracker.add(0.5, "b.bin", 7.8) == []
    members = tracker.add(1.0, "c.bin", 7.7)
    assert {path for path, _value in members} == {"a.bin", "b.bin", "c.bin"}
    tracker.reset()
    assert tracker.add(10.0, "later.bin", 7.9) == []


def test_entropy_burst_tracker_expires_the_window() -> None:
    tracker = watch.EntropyBurstTracker(window_s=1.0, hits=3)
    assert tracker.add(0.0, "a.bin", 7.9) == []
    assert tracker.add(0.2, "b.bin", 7.9) == []
    # More than a second later the first two writes have expired.
    assert tracker.add(5.0, "c.bin", 7.9) == []


def test_entropy_burst_tracker_validates_arguments() -> None:
    with pytest.raises(ValueError):
        watch.EntropyBurstTracker(window_s=0)
    with pytest.raises(ValueError):
        watch.EntropyBurstTracker(hits=0)
    with pytest.raises(ValueError):
        watch.EntropyBurstTracker(window_s=True)  # type: ignore[arg-type]


# ------------------------------------------------ detection latency (bounded)


def test_auto_backend_detects_a_canary_write_within_three_seconds(tmp_path: Path) -> None:
    root = _project(tmp_path / "project")
    events: list[WatchEvent] = []
    stop = threading.Event()

    def run() -> None:
        watch_loop(root, interval_s=0.05, stop=stop, on_event=events.append)

    thread = threading.Thread(target=run, name="tauhaulity-latency")
    thread.start()
    try:
        time.sleep(0.2)  # arm the baseline and start the backend reader
        started = time.perf_counter()
        (root / "canary.txt").write_text(
            "tampered " + str(time.monotonic()), encoding="utf-8"
        )
        while time.monotonic() < started + 3.0 and not events:
            time.sleep(0.01)
        latency = time.perf_counter() - started
    finally:
        stop.set()
        thread.join(5)
    assert events, "auto backend delivered no canary event within 3 s"
    assert any(event.kind == watch.CANARY_KIND for event in events)
    assert "backend=" in events[0].detail
    assert latency < 3.0


def test_watch_event_shape() -> None:
    event = WatchEvent(
        "canary",
        "canary.txt",
        "modified: content changed",
        "2026-01-01T00:00:00+00:00",
    )
    assert event.kind == "canary"
    assert event.path == "canary.txt"
    assert "modified" in event.detail
    assert event.at.endswith("+00:00")

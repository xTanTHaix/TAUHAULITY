"""PEP-669 sys.monitoring tracer with bounded bookkeeping and honest availability.

sys.monitoring (Python 3.12+) lets an observer subscribe to interpreter events
without the per-line overhead of sys.settrace. This module exposes the smallest
useful wrapper: start/stop/available plus a self-test that the pillars use to
report the capability in the dossier.

Design limits that keep it safe inside a scanning process:
* The tracer reserves one tool id (3, then 4) and frees it on stop. If another
  debugger, coverage tool or profiler owns every candidate id, start() returns
  False instead of fighting over it, and availability is reported honestly.
* Only PY_START and PY_RETURN are observed. Line level tracing would multiply the
  callback rate by orders of magnitude for no diagnostic benefit here.
* Callback bookkeeping is deliberately bounded: a dict capped at 256 qualified
  names keeps a pathological program from growing memory without limit.
* Callbacks swallow every exception. An exception escaping a PEP-669 callback
  would surface inside unrelated user code, which is worse than losing a count.
"""

from __future__ import annotations

import sys
import threading
from typing import Any, Callable, Final

__all__ = ["MonitoringTracer", "available", "tracer"]

TOOL_NAME: Final[str] = "tauhaulity"
PREFERRED_TOOL_IDS: Final[tuple[int, ...]] = (3, 4)
MAX_TRACKED_FUNCTIONS: Final[int] = 256


class MonitoringTracer:
    """Thin PEP-669 tracer with bounded counters.

    Attributes:
        tool_id: Reserved sys.monitoring tool id, or None when stopped.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._tool_id: int | None = None
        self._started = False
        self._python_calls = 0
        self._returns = 0
        self._functions: dict[str, int] = {}
        self._overflow = 0
        self._observer: Callable[[Any, int], None] | None = None

    @property
    def tool_id(self) -> int | None:
        """Reserved tool id, or None when the tracer is stopped."""

        return self._tool_id

    def available(self) -> bool:
        """True when sys.monitoring exists and a tool id is free."""

        monitoring = getattr(sys, "monitoring", None)
        if monitoring is None:
            return False
        try:
            events = monitoring.events
            if not hasattr(events, "PY_START") or not hasattr(events, "PY_RETURN"):
                return False
            for tool_id in PREFERRED_TOOL_IDS:
                if monitoring.get_tool(tool_id) is None:
                    return True
        except (AttributeError, ValueError, TypeError):
            return False
        return False

    def active(self) -> bool:
        """True while the tracer is subscribed to interpreter events."""

        return self._started

    def start(self, *, callback: Callable[[Any, int], None] | None = None) -> bool:
        """Reserve a tool id, register callbacks and enable the events.

        Parameters:
            callback: Optional observer called with (code, instruction_offset) on
                every Python function entry. Its exceptions are swallowed.

        Returns:
            True when the tracer is running after the call.
        """

        with self._lock:
            if self._started:
                return True
            monitoring = getattr(sys, "monitoring", None)
            if monitoring is None:
                return False
            tool_id: int | None = None
            for candidate in PREFERRED_TOOL_IDS:
                try:
                    if monitoring.get_tool(candidate) is not None:
                        continue
                    monitoring.use_tool_id(candidate, TOOL_NAME)
                except (ValueError, TypeError, RuntimeError):
                    continue
                tool_id = candidate
                break
            if tool_id is None:
                return False
            try:
                events = monitoring.events
                monitoring.register_callback(tool_id, events.PY_START, self._on_py_start)
                monitoring.register_callback(tool_id, events.PY_RETURN, self._on_py_return)
                monitoring.set_events(tool_id, events.PY_START | events.PY_RETURN)
            except (ValueError, TypeError, RuntimeError, AttributeError):
                try:
                    monitoring.set_events(tool_id, 0)
                    monitoring.register_callback(tool_id, monitoring.events.PY_START, None)
                    monitoring.register_callback(tool_id, monitoring.events.PY_RETURN, None)
                except (ValueError, TypeError, RuntimeError, AttributeError):
                    pass
                try:
                    monitoring.free_tool_id(tool_id)
                except (ValueError, TypeError, RuntimeError):
                    pass
                return False
            self._tool_id = tool_id
            self._observer = callback
            self._started = True
            return True

    def stop(self) -> None:
        """Disable the events, unregister the callbacks and free the tool id."""

        with self._lock:
            tool_id = self._tool_id
            self._started = False
            self._tool_id = None
            self._observer = None
            monitoring = getattr(sys, "monitoring", None)
            if monitoring is None or tool_id is None:
                return
            try:
                monitoring.set_events(tool_id, 0)
            except (ValueError, TypeError, RuntimeError):
                pass
            try:
                events = monitoring.events
                monitoring.register_callback(tool_id, events.PY_START, None)
                monitoring.register_callback(tool_id, events.PY_RETURN, None)
            except (ValueError, TypeError, RuntimeError, AttributeError):
                pass
            try:
                monitoring.free_tool_id(tool_id)
            except (ValueError, TypeError, RuntimeError):
                pass

    def reset(self) -> None:
        """Zero the counters without changing the subscription state."""

        with self._lock:
            self._python_calls = 0
            self._returns = 0
            self._functions.clear()
            self._overflow = 0

    def stats(self) -> dict[str, Any]:
        """Return a snapshot of the tracer state and counters."""

        with self._lock:
            return {
                "available": self.available(),
                "active": self._started,
                "tool_id": self._tool_id,
                "python_calls": self._python_calls,
                "returns": self._returns,
                "functions": len(self._functions),
                "overflow": self._overflow,
            }

    def functions(self, limit: int = 16) -> list[tuple[str, int]]:
        """Return the busiest qualified names, highest count first."""

        with self._lock:
            material = sorted(self._functions.items(), key=lambda item: item[1], reverse=True)
        return material[: max(0, limit)]

    def self_test(self) -> dict[str, Any]:
        """Start the tracer, observe a few calls, stop it and report the result.

        Pillar six uses this to report PEP-669 capability without leaving a tracer
        installed on the host process.
        """

        result: dict[str, Any] = {
            "available": self.available(),
            "started": False,
            "callbacks": 0,
            "tool_id": None,
            "reason": "",
        }
        if not result["available"]:
            result["reason"] = "sys.monitoring is unavailable or every tool id is taken"
            return result
        was_active = self._started
        if not was_active and not self.start():
            result["reason"] = "could not reserve a sys.monitoring tool id"
            return result
        try:
            before = self._python_calls
            for _ in range(3):
                _tauhaulity_monitoring_probe(1, 2)
            result["callbacks"] = self._python_calls - before
            result["started"] = True
            result["tool_id"] = self._tool_id
        finally:
            if not was_active:
                self.stop()
        return result

    def _on_py_start(self, code: Any, instruction_offset: int) -> None:
        """Count a Python function entry; never raises."""

        try:
            self._python_calls += 1
            name = getattr(code, "co_qualname", None) or getattr(code, "co_name", "<code>")
            if name in self._functions:
                self._functions[name] += 1
            elif len(self._functions) < MAX_TRACKED_FUNCTIONS:
                self._functions[name] = 1
            else:
                self._overflow += 1
            observer = self._observer
            if observer is not None:
                observer(code, instruction_offset)
        except BaseException:
            return None
        return None

    def _on_py_return(self, code: Any, instruction_offset: int, retval: Any) -> None:
        """Count a Python function return; never raises."""

        try:
            self._returns += 1
        except BaseException:
            return None
        return None


def _tauhaulity_monitoring_probe(left: int, right: int) -> int:
    """Tiny function the self-test enters to prove the callback fires."""

    return left + right


tracer = MonitoringTracer()


def available() -> bool:
    """True when PEP-669 monitoring can be used on this interpreter."""

    return tracer.available()

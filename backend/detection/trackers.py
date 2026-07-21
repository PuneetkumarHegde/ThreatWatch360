"""
AlertIQ 2.0 - Phase 1 Sliding-Window Trackers
-------------------------------------------------
Small, dependency-free helper structures that give the rule engine memory
across packets/flows without needing a database. Every tracker is a plain
in-memory structure keyed by some entity (usually source IP), storing
(timestamp, value) pairs and pruning anything older than a window.

These are intentionally simple - Phase 2's ML layer will handle the more
subtle, statistical patterns. The rule engine's job is fast, cheap,
*explainable* first-pass detection.
"""
from __future__ import annotations

import threading
import time
from collections import defaultdict, deque


class TimedMultiSet:
    """Tracks distinct values seen per key within a rolling time window.

    Example: distinct destination ports contacted per source IP in the
    last N seconds -> used for Port Scan / Service Enumeration detection.
    """

    def __init__(self, window_seconds: float):
        self.window_seconds = window_seconds
        self._data: dict[str, deque] = defaultdict(deque)  # key -> deque[(ts, value)]
        self._lock = threading.Lock()

    def add(self, key: str, value) -> None:
        now = time.time()
        with self._lock:
            dq = self._data[key]
            dq.append((now, value))
            self._prune(dq, now)

    def distinct_count(self, key: str) -> int:
        now = time.time()
        with self._lock:
            dq = self._data.get(key)
            if not dq:
                return 0
            self._prune(dq, now)
            return len({v for _, v in dq})

    def distinct_values(self, key: str) -> set:
        now = time.time()
        with self._lock:
            dq = self._data.get(key)
            if not dq:
                return set()
            self._prune(dq, now)
            return {v for _, v in dq}

    def _prune(self, dq: deque, now: float) -> None:
        while dq and (now - dq[0][0]) > self.window_seconds:
            dq.popleft()


class TimedCounter:
    """Counts events per key within a rolling time window.

    Example: number of ICMP echo requests per source IP in the last
    10 seconds -> used for Host Discovery / SYN Flood rate checks.
    """

    def __init__(self, window_seconds: float):
        self.window_seconds = window_seconds
        self._data: dict[str, deque] = defaultdict(deque)  # key -> deque[timestamp]
        self._lock = threading.Lock()

    def increment(self, key: str) -> int:
        now = time.time()
        with self._lock:
            dq = self._data[key]
            dq.append(now)
            self._prune(dq, now)
            return len(dq)

    def count(self, key: str) -> int:
        now = time.time()
        with self._lock:
            dq = self._data.get(key)
            if not dq:
                return 0
            self._prune(dq, now)
            return len(dq)

    def _prune(self, dq: deque, now: float) -> None:
        while dq and (now - dq[0]) > self.window_seconds:
            dq.popleft()


class LastSeenMap:
    """Tracks the most recent value(s) associated with a key.

    Example: IP -> set of MAC addresses claimed for it recently
    -> used for ARP Spoofing detection (gateway MAC flapping).
    """

    def __init__(self, window_seconds: float):
        self.window_seconds = window_seconds
        self._data: dict[str, deque] = defaultdict(deque)  # key -> deque[(ts, value)]
        self._lock = threading.Lock()

    def record(self, key: str, value) -> set:
        """Record a (key -> value) observation and return the distinct
        set of values seen for that key within the window."""
        now = time.time()
        with self._lock:
            dq = self._data[key]
            dq.append((now, value))
            self._prune(dq, now)
            return {v for _, v in dq}

    def _prune(self, dq: deque, now: float) -> None:
        while dq and (now - dq[0][0]) > self.window_seconds:
            dq.popleft()


class Deduplicator:
    """Suppresses repeat Detection emissions for the same (rule, source,
    destination) tuple within a cooldown window, so one ongoing scan
    doesn't spam thousands of near-identical incidents."""

    def __init__(self, cooldown_seconds: float = 30.0):
        self.cooldown_seconds = cooldown_seconds
        self._last_emitted: dict[str, float] = {}
        self._lock = threading.Lock()

    def should_emit(self, dedup_key: str) -> bool:
        now = time.time()
        with self._lock:
            last = self._last_emitted.get(dedup_key)
            if last is not None and (now - last) < self.cooldown_seconds:
                return False
            self._last_emitted[dedup_key] = now
            return True

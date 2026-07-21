"""
AlertIQ 2.0 - Phase 2 Beacon / Fan-Out Tracker
---------------------------------------------------
Malware Beaconing and Botnet Communication are NOT single-flow phenomena
-- a single flow to a C2 server looks just like any other short TCP
connection. What makes it suspicious is the PATTERN across many flows
over time: low jitter (highly regular check-in interval) and, for botnet
communication specifically, the same source doing this against several
distinct destinations (fan-out).

This tracker sits between the FlowManager and the ML pipeline: every time
a flow is flushed, we record (src, dst, dst_port, start_time, fwd_bytes)
into a bounded rolling history, then compute statistics used as ML
features (beacon_observation_count, beacon_interval_jitter,
beacon_mean_bytes, dst_fanout_count_for_src).
"""
from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from statistics import mean, pstdev


class BeaconTracker:
    def __init__(self, max_observations: int = 60, history_window_seconds: float = 1800.0):
        self.max_observations = max_observations
        self.history_window_seconds = history_window_seconds
        # (src_ip, dst_ip, dst_port) -> deque[(start_time, fwd_bytes)]
        self._history: dict[tuple, deque] = defaultdict(lambda: deque(maxlen=max_observations))
        # src_ip -> {dst_ip: last_seen_low_jitter_time} for fan-out tracking
        self._beacon_like_dsts: dict[str, dict[str, float]] = defaultdict(dict)
        self._lock = threading.Lock()

    def record_flow(self, src_ip: str, dst_ip: str, dst_port: int | None, start_time: float, fwd_bytes: int) -> None:
        key = (src_ip, dst_ip, dst_port)
        with self._lock:
            dq = self._history[key]
            dq.append((start_time, fwd_bytes))
            self._prune(dq)

    def _prune(self, dq: deque) -> None:
        now = time.time()
        while dq and (now - dq[0][0]) > self.history_window_seconds:
            dq.popleft()

    def stats(self, src_ip: str, dst_ip: str, dst_port: int | None) -> dict | None:
        """Return beacon statistics for this (src, dst, port) tuple, or
        None if there isn't enough history yet."""
        key = (src_ip, dst_ip, dst_port)
        with self._lock:
            dq = self._history.get(key)
            if dq is None or len(dq) < 3:
                return None
            self._prune(dq)
            observations = list(dq)

        timestamps = [t for t, _ in observations]
        byte_sizes = [b for _, b in observations]
        intervals = [timestamps[i] - timestamps[i - 1] for i in range(1, len(timestamps))]
        if not intervals:
            return None

        mean_interval = mean(intervals)
        stdev_interval = pstdev(intervals) if len(intervals) > 1 else 0.0
        jitter_ratio = (stdev_interval / mean_interval) if mean_interval > 0 else 1.0

        return {
            "observation_count": len(observations),
            "mean_interval_seconds": round(mean_interval, 3),
            "interval_jitter_ratio": round(jitter_ratio, 4),
            "mean_bytes": round(mean(byte_sizes), 1),
            "stdev_bytes": round(pstdev(byte_sizes), 1) if len(byte_sizes) > 1 else 0.0,
        }

    def mark_beacon_like(self, src_ip: str, dst_ip: str) -> int:
        """Record that (src_ip -> dst_ip) currently looks beacon-like
        (low jitter), and return the current fan-out count: how many
        DISTINCT destinations this source is beaconing to right now.
        Used to distinguish single-C2 Malware Beaconing from
        multi-destination Botnet Communication.
        """
        now = time.time()
        with self._lock:
            self._beacon_like_dsts[src_ip][dst_ip] = now
            # prune stale entries (no longer beacon-like within the window)
            stale = [
                d for d, ts in self._beacon_like_dsts[src_ip].items()
                if (now - ts) > self.history_window_seconds
            ]
            for d in stale:
                del self._beacon_like_dsts[src_ip][d]
            return len(self._beacon_like_dsts[src_ip])

    def fanout_count(self, src_ip: str) -> int:
        with self._lock:
            return len(self._beacon_like_dsts.get(src_ip, {}))

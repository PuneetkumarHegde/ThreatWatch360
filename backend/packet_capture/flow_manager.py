"""
AlertIQ 2.0 - Phase 1 Flow Manager
-------------------------------------
Consumes normalized PacketRecords and aggregates them into bidirectional
Flows (5-tuple + protocol). Flows are flushed (handed to the caller for
feature extraction + rule evaluation) when they go idle or exceed the
max lifetime, so long-lived connections still get periodically re-checked.

This module is transport-agnostic with respect to *how* packets arrive -
it only needs an iterable/queue of PacketRecord objects, which makes it
trivially unit-testable without Scapy or root privileges.
"""
from __future__ import annotations

import logging
import threading
import time
from typing import Callable

from config import settings
from packet_capture.models import Flow, PacketRecord

logger = logging.getLogger("alertiq.flow_manager")

FlowFlushCallback = Callable[[Flow], None]


class FlowManager:
    def __init__(self, on_flow_flush: FlowFlushCallback):
        """
        Args:
            on_flow_flush: called with a completed/expired Flow so the
                caller (main loop) can run feature extraction + rules on it.
        """
        self._flows: dict[tuple, Flow] = {}
        self._lock = threading.Lock()
        self._on_flow_flush = on_flow_flush
        self.total_packets_processed = 0

    def ingest(self, pkt: PacketRecord) -> None:
        key = pkt.flow_key()
        with self._lock:
            flow = self._flows.get(key)
            if flow is None:
                flow = Flow(
                    key=key,
                    protocol=pkt.protocol,
                    src_ip=pkt.src_ip,
                    dst_ip=pkt.dst_ip,
                    src_port=pkt.src_port,
                    dst_port=pkt.dst_port,
                    start_time=pkt.timestamp,
                    last_seen=pkt.timestamp,
                )
                self._flows[key] = flow
            flow.update(pkt)
        self.total_packets_processed += 1

    def sweep(self) -> int:
        """Flush idle/expired flows. Returns number of flows flushed.

        Should be called periodically (see config.CaptureSettings.flow_sweep_interval)
        from the main loop's scheduler / background thread.
        """
        now = time.time()
        flushed = 0
        with self._lock:
            expired_keys = [
                key
                for key, flow in self._flows.items()
                if flow.is_idle(now, settings.capture.flow_idle_timeout)
                or flow.is_expired(now, settings.capture.flow_max_lifetime)
            ]
            for key in expired_keys:
                flow = self._flows.pop(key)
                flushed += 1
                try:
                    self._on_flow_flush(flow)
                except Exception:  # noqa: BLE001 - one bad flow must not kill the sweep
                    logger.exception("Error while flushing flow %s", flow.flow_id)
        return flushed

    def active_flow_count(self) -> int:
        with self._lock:
            return len(self._flows)

    def snapshot(self) -> list[Flow]:
        """Read-only snapshot of currently active flows, e.g. for a live dashboard."""
        with self._lock:
            return list(self._flows.values())

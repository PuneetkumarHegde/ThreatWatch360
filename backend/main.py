"""
AlertIQ 2.0 - Phase 1 Entrypoint
------------------------------------
Standalone runner that wires together:

    Sniffer -> Queue -> FlowManager -> RuleEngine -> Detections

This is deliberately runnable WITHOUT the FastAPI/DB/React layers
(those arrive in Phases 2-4), so the core detection engine can be
validated end-to-end on its own first.

Run (Linux/macOS, needs root for raw sockets):
    sudo python3 main.py --interface eth0

Run (Windows, needs Npcap + Administrator):
    python main.py --interface "Ethernet"

If --interface is omitted, Scapy will attempt to use the default route
interface.
"""
from __future__ import annotations

import argparse
import json
import logging
import queue
import signal
import sys
import threading
import time

from config import settings
from detection.rule_engine import RuleEngine
from packet_capture.flow_manager import FlowManager
from packet_capture.models import Detection, PacketRecord
from packet_capture.sniffer import PacketSniffer

logger = logging.getLogger("alertiq.main")


class AlertIQEngine:
    """Ties the capture -> flow -> rule pipeline together and exposes
    simple stats + a detection callback, so a future FastAPI layer
    (Phase 3) can simply instantiate this class and subscribe to it."""

    def __init__(self, interface: str | None = None, on_detection=None, on_packet=None):
        self.packet_queue: "queue.Queue[PacketRecord]" = queue.Queue(maxsize=50_000)
        self.rule_engine = RuleEngine()
        self.flow_manager = FlowManager(on_flow_flush=self._on_flow_flush)
        self.sniffer = PacketSniffer(self.packet_queue, interface=interface)
        self._on_detection = on_detection or self._default_on_detection
        self._on_packet = on_packet  # optional hook, e.g. for device discovery

        self.ml_pipeline = None
        if settings.enable_ml or settings.enable_anomaly_detection:
            try:
                from ai_engine.pipeline import MLPipeline

                self.ml_pipeline = MLPipeline()
            except FileNotFoundError as e:
                logger.warning(
                    "ML pipeline disabled - models not trained yet (%s). "
                    "Run: python3 -m ai_engine.train && python3 -m ai_engine.anomaly",
                    e,
                )

        self._stop_event = threading.Event()
        self._consumer_thread: threading.Thread | None = None
        self._sweeper_thread: threading.Thread | None = None

        self.detections_total = 0

    # -- lifecycle -----------------------------------------------------
    def start(self) -> None:
        logger.info("Starting AlertIQ detection engine")
        self.sniffer.start()
        self._stop_event.clear()
        self._consumer_thread = threading.Thread(target=self._consume_loop, daemon=True)
        self._sweeper_thread = threading.Thread(target=self._sweep_loop, daemon=True)
        self._consumer_thread.start()
        self._sweeper_thread.start()

    def stop(self) -> None:
        logger.info("Stopping AlertIQ detection engine")
        self._stop_event.set()
        self.sniffer.stop()
        if self._consumer_thread:
            self._consumer_thread.join(timeout=2)
        if self._sweeper_thread:
            self._sweeper_thread.join(timeout=2)

    # -- internal loops --------------------------------------------------
    def _consume_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                pkt = self.packet_queue.get(timeout=0.5)
            except queue.Empty:
                continue
            self.flow_manager.ingest(pkt)
            if self._on_packet:
                try:
                    self._on_packet(pkt)
                except Exception:  # noqa: BLE001
                    logger.exception("on_packet hook raised")
            if settings.enable_rule_engine:
                for detection in self.rule_engine.process_packet(pkt):
                    self._emit(detection)

    def _sweep_loop(self) -> None:
        while not self._stop_event.is_set():
            time.sleep(settings.capture.flow_sweep_interval)
            self.flow_manager.sweep()

    def _on_flow_flush(self, flow) -> None:
        rule_detections = []
        if settings.enable_rule_engine:
            rule_detections = self.rule_engine.process_flow(flow)
            for detection in rule_detections:
                self._emit(detection)

        # Only run the (heavier) ML pipeline if the rule engine found
        # nothing on this flow - it already has a confident, explainable
        # answer, so there's no need for a second opinion.
        if self.ml_pipeline and not rule_detections:
            dns_stats = self.rule_engine.dns_features(flow.src_ip)
            for detection in self.ml_pipeline.evaluate_flow(flow, dns_stats=dns_stats):
                self._emit(detection)

    def _emit(self, detection: Detection) -> None:
        self.detections_total += 1
        self._on_detection(detection)

    @staticmethod
    def _default_on_detection(detection: Detection) -> None:
        print(json.dumps(detection.to_dict(), indent=2))

    # -- stats, for a future /api/stats endpoint --------------------------
    def stats(self) -> dict:
        return {
            "packets_captured": self.sniffer.packets_captured,
            "packets_dropped": self.sniffer.packets_dropped,
            "active_flows": self.flow_manager.active_flow_count(),
            "total_flows_processed": self.flow_manager.total_packets_processed,
            "detections_total": self.detections_total,
        }


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="AlertIQ 2.0 - Phase 1 Detection Engine")
    parser.add_argument("--interface", "-i", default=None, help="Network interface to sniff on")
    parser.add_argument("--log-level", default=settings.log_level)
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    engine = AlertIQEngine(interface=args.interface)

    def _handle_sigint(*_):
        engine.stop()
        logger.info("Final stats: %s", engine.stats())
        sys.exit(0)

    signal.signal(signal.SIGINT, _handle_sigint)

    engine.start()
    logger.info("AlertIQ is monitoring traffic. Press Ctrl+C to stop.")

    try:
        while True:
            time.sleep(10)
            logger.info("Stats: %s", engine.stats())
    except KeyboardInterrupt:
        _handle_sigint()


if __name__ == "__main__":
    main()

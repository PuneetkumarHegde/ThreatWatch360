"""
AlertIQ 2.0 - Phase 3 Engine Manager
------------------------------------------
Owns the single running `AlertIQEngine` instance for the API process,
persists every `Detection` as an `Incident`, and updates the `Device`
table from observed ARP traffic. This is the bridge between the
standalone Phase 1/2 engine (main.py) and the Phase 3 REST API.
"""
from __future__ import annotations

import logging

from config import settings
from database.crud import create_incident_from_detection, upsert_device
from database.db import SessionLocal
from detection.demo_simulator import ALL_SCENARIO_NAMES, ML_SCENARIOS, RULE_SCENARIOS
from detection.rule_engine import RuleEngine
from main import AlertIQEngine
from packet_capture.models import PacketRecord, Protocol
from response.ip_blocker import block_ip
from response.notifier import send_incident_email

logger = logging.getLogger("alertiq.engine_manager")


class EngineManager:
    def __init__(self):
        self._engine: AlertIQEngine | None = None
        self._interface: str | None = None
        # A standalone RuleEngine (independent of the live capture engine)
        # so Demo Mode works even when live capture is stopped - this is
        # the whole point of Demo Mode (safe simulation without needing
        # real traffic/a real attacker).
        self._demo_rule_engine = RuleEngine()
        self._demo_ml_pipeline = None

    def start(self, interface: str | None = None) -> None:
        if self._engine is not None and self._engine.sniffer.is_running():
            logger.info("Engine already running")
            return
        self._interface = interface
        self._engine = AlertIQEngine(
            interface=interface,
            on_detection=self._persist_detection,
            on_packet=self._observe_packet,
        )
        self._engine.start()

    def stop(self) -> None:
        if self._engine is not None:
            self._engine.stop()

    def is_running(self) -> bool:
        return self._engine is not None and self._engine.sniffer.is_running()

    # -- Demo Simulation Mode ---------------------------------------------
    def run_demo(self, attack_type: str) -> list[dict]:
        if attack_type not in ALL_SCENARIO_NAMES:
            raise ValueError(f"Unknown demo scenario '{attack_type}'. Valid: {ALL_SCENARIO_NAMES}")

        if attack_type in RULE_SCENARIOS:
            detections = RULE_SCENARIOS[attack_type](self._demo_rule_engine)
        else:
            if self._demo_ml_pipeline is None:
                from ai_engine.pipeline import MLPipeline

                self._demo_ml_pipeline = MLPipeline()
            detections = ML_SCENARIOS[attack_type](self._demo_ml_pipeline)

        persisted = []
        db = SessionLocal()
        try:
            for detection in detections:
                incident = create_incident_from_detection(db, detection)
                persisted.append({"id": incident.id, "attack_type": incident.attack_type, "severity": incident.severity})
        finally:
            db.close()

        logger.info("Demo scenario '%s' produced %d incident(s)", attack_type, len(persisted))
        return persisted

    def stats(self) -> dict:
        if self._engine is None:
            return {
                "running": False,
                "interface": None,
                "packets_captured": 0,
                "packets_dropped": 0,
                "active_flows": 0,
                "detections_total": 0,
            }
        s = self._engine.stats()
        return {"running": self.is_running(), "interface": self._interface, **s}

    # -- callbacks (run on the engine's background threads - each opens
    #    its own short-lived DB session, since sessions aren't thread-safe
    #    to share) ---------------------------------------------------------
    def _persist_detection(self, detection) -> None:
        db = SessionLocal()
        try:
            incident = create_incident_from_detection(db, detection)
            logger.info(
                "Incident recorded: %s from %s (risk=%s)",
                detection.attack_type,
                detection.source_ip,
                detection.evidence.get("risk_score"),
            )
        except Exception:  # noqa: BLE001
            logger.exception("Failed to persist incident")
            return
        finally:
            db.close()

        if settings.enable_notifications:
            try:
                send_incident_email(
                    attack_type=incident.attack_type,
                    severity=incident.severity,
                    source_ip=incident.source_ip,
                    destination_ip=incident.destination_ip,
                    risk_score=incident.risk_score,
                    explanation=incident.explanation,
                )
            except Exception:  # noqa: BLE001
                logger.exception("Failed to send incident notification")

        # Automatic IP blocking is intentionally the most conservative
        # action here: OFF by default, and even when enabled only fires
        # for CRITICAL severity (SYN Flood, ARP Spoofing, Botnet C2,
        # Data Exfiltration) - never for reconnaissance-level findings,
        # which are common and often benign (e.g. legitimate vuln scans).
        if settings.enable_automatic_response and incident.severity == "CRITICAL":
            try:
                result = block_ip(incident.source_ip)
                logger.info("Automatic response block_ip(%s): %s", incident.source_ip, result.message)
            except Exception:  # noqa: BLE001
                logger.exception("Automatic response IP block failed")

    def _observe_packet(self, pkt: PacketRecord) -> None:
        if pkt.protocol != Protocol.ARP or not pkt.arp_sender_mac or not pkt.arp_sender_ip:
            return
        db = SessionLocal()
        try:
            upsert_device(db, mac_address=pkt.arp_sender_mac, ip_address=pkt.arp_sender_ip)
        except Exception:  # noqa: BLE001
            logger.exception("Failed to upsert device")
        finally:
            db.close()


# Module-level singleton, imported by the API routers.
engine_manager = EngineManager()

"""
AlertIQ 2.0 - Phase 1 Data Models
----------------------------------
Lightweight, dependency-free dataclasses shared across the capture,
flow-generation, feature-extraction, and rule-engine modules.

These are intentionally framework-agnostic (no SQLAlchemy / Pydantic here)
so Phase 1 can be unit-tested and run standalone before the API/DB layers
(Phase 3) exist. Phase 3 will map these onto ORM models.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum


class Protocol(str, Enum):
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    ARP = "ARP"
    DNS = "DNS"
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    OTHER = "OTHER"


@dataclass
class PacketRecord:
    """A single normalized packet, extracted from a raw Scapy packet."""

    timestamp: float
    protocol: Protocol
    src_ip: str
    dst_ip: str
    src_port: int | None = None
    dst_port: int | None = None
    length: int = 0
    ttl: int | None = None

    # TCP flag booleans (all False for non-TCP packets)
    flag_syn: bool = False
    flag_ack: bool = False
    flag_fin: bool = False
    flag_rst: bool = False
    flag_psh: bool = False
    flag_urg: bool = False

    # ARP-specific
    arp_sender_mac: str | None = None
    arp_sender_ip: str | None = None

    # DNS-specific
    dns_qname: str | None = None
    dns_is_query: bool | None = None

    def flow_key(self) -> tuple:
        """5-tuple identifying the bidirectional flow this packet belongs to.

        We normalize direction by sorting the (ip, port) endpoints so that
        packets in both directions of the same connection map to the same key.
        """
        a = (self.src_ip, self.src_port or 0)
        b = (self.dst_ip, self.dst_port or 0)
        endpoints = tuple(sorted([a, b]))
        return (endpoints[0], endpoints[1], self.protocol.value)


@dataclass
class Flow:
    """An aggregated bidirectional flow built up from PacketRecords."""

    flow_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    key: tuple = None
    protocol: Protocol = Protocol.OTHER

    src_ip: str = ""
    dst_ip: str = ""
    src_port: int | None = None
    dst_port: int | None = None

    start_time: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)

    packet_count: int = 0
    byte_count: int = 0

    fwd_packets: int = 0   # src -> dst
    bwd_packets: int = 0   # dst -> src
    fwd_bytes: int = 0
    bwd_bytes: int = 0

    syn_count: int = 0
    ack_count: int = 0
    fin_count: int = 0
    rst_count: int = 0

    ttl_values: list[int] = field(default_factory=list)
    dst_ports_seen: set[int] = field(default_factory=set)

    def duration(self) -> float:
        return max(self.last_seen - self.start_time, 0.0)

    def packet_rate(self) -> float:
        d = self.duration()
        return self.packet_count / d if d > 0 else float(self.packet_count)

    def is_idle(self, now: float, idle_timeout: float) -> bool:
        return (now - self.last_seen) >= idle_timeout

    def is_expired(self, now: float, max_lifetime: float) -> bool:
        return (now - self.start_time) >= max_lifetime

    def update(self, pkt: PacketRecord) -> None:
        self.last_seen = pkt.timestamp
        self.packet_count += 1
        self.byte_count += pkt.length

        if pkt.src_ip == self.src_ip:
            self.fwd_packets += 1
            self.fwd_bytes += pkt.length
        else:
            self.bwd_packets += 1
            self.bwd_bytes += pkt.length

        if pkt.flag_syn:
            self.syn_count += 1
        if pkt.flag_ack:
            self.ack_count += 1
        if pkt.flag_fin:
            self.fin_count += 1
        if pkt.flag_rst:
            self.rst_count += 1

        if pkt.ttl is not None:
            self.ttl_values.append(pkt.ttl)
        if pkt.dst_port is not None:
            self.dst_ports_seen.add(pkt.dst_port)


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AttackCategory(str, Enum):
    RECONNAISSANCE = "Reconnaissance"
    CREDENTIAL_ATTACKS = "Credential Attacks"
    NETWORK_ATTACKS = "Network Attacks"
    MALWARE_BEHAVIORS = "Malware Behaviors"
    DATA_THEFT = "Data Theft"
    UNKNOWN_THREATS = "Unknown Threats"


@dataclass
class Detection:
    """A rule-engine (or, later, ML) detection event.

    This is the precursor to a full "Incident" record (Phase 3 adds
    persistence, MITRE mapping, and investigation workflow on top).
    """

    detection_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = field(default_factory=time.time)
    attack_type: str = ""
    category: AttackCategory = AttackCategory.UNKNOWN_THREATS
    severity: Severity = Severity.LOW
    confidence: float = 0.0  # 0.0 - 1.0, rule-engine confidence

    source_ip: str = ""
    destination_ip: str | None = None
    destination_port: int | None = None

    evidence: dict = field(default_factory=dict)
    explanation: str = ""

    def to_dict(self) -> dict:
        d = {
            "detection_id": self.detection_id,
            "timestamp": self.timestamp,
            "attack_type": self.attack_type,
            "category": self.category.value,
            "severity": self.severity.value,
            "confidence": round(self.confidence, 3),
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "destination_port": self.destination_port,
            "evidence": self.evidence,
            "explanation": self.explanation,
        }
        return d

"""
AlertIQ 2.0 - Phase 1 Rule Engine
------------------------------------
Fast, explainable, signature/heuristic detection that runs BEFORE the
ML pipeline (Phase 2). Every rule below maps directly to one of the
project's 12 attack categories and produces a Detection with a plain
-English `explanation` field - this is the non-ML analogue of the SHAP
explanations that Phase 2 will add for the ML-driven detections.

Design:
  - `process_packet(pkt)`   -> called for every normalized packet (used by
                                rules that need per-packet visibility: ARP,
                                ICMP, DNS, TCP SYN).
  - `process_flow(flow)`    -> called when a flow is flushed by the
                                FlowManager (used by rules that need
                                completed-connection stats: SYN flood
                                completion ratio, exfiltration byte counts).

Both return a list[Detection] (usually empty).
"""
from __future__ import annotations

import logging
import math
from collections import Counter

from config import settings
from packet_capture.feature_extractor import extract_features
from packet_capture.models import (
    AttackCategory,
    Detection,
    Flow,
    PacketRecord,
    Protocol,
    Severity,
)
from detection.trackers import Deduplicator, LastSeenMap, TimedCounter, TimedMultiSet

logger = logging.getLogger("alertiq.rule_engine")

# Common ports associated with authentication services, used by the
# credential-attack rules (SSH brute force / password spraying).
_AUTH_PORTS = {22, 3389, 21, 23, 3306, 5432}


def _shannon_entropy(s: str) -> float:
    """Bits of entropy per character. Real words/hostnames ('cdn-prod-us-east')
    sit around 3.5-4.0; base32/hex/base64-encoded tunneling payloads sit
    around 4.5-6.0. This is what separates "long CDN hostname" (false
    positive in the wild) from "long random-looking encoded payload"
    (the actual DNS tunneling signature)."""
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _leaf_label(qname: str) -> str:
    """The first (leftmost) DNS label is where tunneling payloads are
    encoded, e.g. `<encoded-data>.tunnel.attacker.com`. Measuring entropy
    on just this label - not the whole qname, which includes normal,
    low-entropy domain suffixes - avoids diluting the signal."""
    return qname.split(".")[0] if qname else ""


class RuleEngine:
    def __init__(self):
        r = settings.rules

        # --- Reconnaissance ---
        self._port_scan_tracker = TimedMultiSet(r.port_scan_window_seconds)
        self._host_discovery_tracker = TimedMultiSet(r.host_discovery_window_seconds)
        self._service_enum_tracker = TimedMultiSet(r.service_enum_window_seconds)

        # --- Credential Attacks ---
        self._ssh_bruteforce_tracker = TimedCounter(r.ssh_bruteforce_window_seconds)
        self._password_spray_tracker = TimedMultiSet(r.password_spray_window_seconds)

        # --- Network Attacks ---
        self._syn_rate_tracker = TimedCounter(r.syn_flood_window_seconds)
        self._arp_mac_tracker = LastSeenMap(r.arp_spoof_window_seconds)

        # --- Malware Behaviors ---
        self._dns_query_tracker = TimedCounter(60.0)
        self._dns_subdomain_tracker = TimedMultiSet(60.0)
        self._last_dns_qname_len: dict[str, int] = {}

        # Known gateway MAC, learned from the first ARP reply we see for
        # each IP. In Phase 3 this will instead be seeded from the
        # discovered default gateway via the Devices module.
        self._known_ip_mac: dict[str, str] = {}

        self._dedup = Deduplicator(cooldown_seconds=20.0)

    # ------------------------------------------------------------------
    # Packet-level rules
    # ------------------------------------------------------------------
    def process_packet(self, pkt: PacketRecord) -> list[Detection]:
        detections: list[Detection] = []
        r = settings.rules

        if pkt.protocol == Protocol.ARP:
            d = self._check_arp_spoof(pkt)
            if d:
                detections.append(d)
            return detections  # ARP packets carry no other signal we use

        if pkt.protocol == Protocol.ICMP:
            d = self._check_host_discovery(pkt)
            if d:
                detections.append(d)

        if pkt.dst_port is not None:
            self._port_scan_tracker.add(pkt.src_ip, pkt.dst_port)
            self._service_enum_tracker.add(f"{pkt.src_ip}->{pkt.dst_ip}", pkt.dst_port)

            d = self._check_port_scan(pkt)
            if d:
                detections.append(d)
            d = self._check_service_enumeration(pkt)
            if d:
                detections.append(d)

        if pkt.protocol == Protocol.TCP and pkt.flag_syn and not pkt.flag_ack:
            if pkt.dst_port == r.ssh_bruteforce_port:
                d = self._check_ssh_bruteforce(pkt)
                if d:
                    detections.append(d)
            if pkt.dst_port in _AUTH_PORTS:
                d = self._check_password_spray(pkt)
                if d:
                    detections.append(d)

            self._syn_rate_tracker.increment(pkt.dst_ip)
            d = self._check_syn_flood_rate(pkt)
            if d:
                detections.append(d)

        if pkt.protocol == Protocol.DNS and pkt.dns_qname:
            d = self._check_dns_tunneling(pkt)
            if d:
                detections.append(d)

        return detections

    # ------------------------------------------------------------------
    # Flow-level rules (evaluated once a flow closes / times out)
    # ------------------------------------------------------------------
    def process_flow(self, flow: Flow) -> list[Detection]:
        detections: list[Detection] = []
        features = extract_features(flow)

        d = self._check_exfiltration(flow, features)
        if d:
            detections.append(d)

        d = self._check_syn_flood_completion(flow, features)
        if d:
            detections.append(d)

        return detections

    # ------------------------------------------------------------------
    # Individual rule implementations
    # ------------------------------------------------------------------
    def _emit(self, key: str, **kwargs) -> Detection | None:
        if not self._dedup.should_emit(key):
            return None
        return Detection(**kwargs)

    def _check_port_scan(self, pkt: PacketRecord) -> Detection | None:
        r = settings.rules
        count = self._port_scan_tracker.distinct_count(pkt.src_ip)
        if count < r.port_scan_distinct_ports:
            return None
        return self._emit(
            f"port_scan:{pkt.src_ip}",
            attack_type="Port Scan",
            category=AttackCategory.RECONNAISSANCE,
            severity=Severity.MEDIUM,
            confidence=min(0.5 + count / (r.port_scan_distinct_ports * 4), 0.95),
            source_ip=pkt.src_ip,
            evidence={
                "distinct_destination_ports": count,
                "window_seconds": r.port_scan_window_seconds,
                "threshold": r.port_scan_distinct_ports,
            },
            explanation=(
                f"Source {pkt.src_ip} contacted {count} distinct destination ports "
                f"within {r.port_scan_window_seconds:.0f}s, exceeding the port-scan "
                f"threshold of {r.port_scan_distinct_ports}."
            ),
        )

    def _check_host_discovery(self, pkt: PacketRecord) -> Detection | None:
        r = settings.rules
        self._host_discovery_tracker.add(pkt.src_ip, pkt.dst_ip)
        count = self._host_discovery_tracker.distinct_count(pkt.src_ip)
        if count < r.host_discovery_distinct_hosts:
            return None
        return self._emit(
            f"host_discovery:{pkt.src_ip}",
            attack_type="Host Discovery (Ping Sweep)",
            category=AttackCategory.RECONNAISSANCE,
            severity=Severity.LOW,
            confidence=min(0.5 + count / (r.host_discovery_distinct_hosts * 4), 0.9),
            source_ip=pkt.src_ip,
            evidence={
                "distinct_hosts_pinged": count,
                "window_seconds": r.host_discovery_window_seconds,
                "threshold": r.host_discovery_distinct_hosts,
            },
            explanation=(
                f"Source {pkt.src_ip} sent ICMP echo requests to {count} distinct "
                f"hosts within {r.host_discovery_window_seconds:.0f}s, consistent with "
                f"network host discovery (ping sweep)."
            ),
        )

    def _check_service_enumeration(self, pkt: PacketRecord) -> Detection | None:
        r = settings.rules
        pair_key = f"{pkt.src_ip}->{pkt.dst_ip}"
        count = self._service_enum_tracker.distinct_count(pair_key)
        if count < r.service_enum_distinct_ports_per_host:
            return None
        return self._emit(
            f"service_enum:{pair_key}",
            attack_type="Service Enumeration",
            category=AttackCategory.RECONNAISSANCE,
            severity=Severity.MEDIUM,
            confidence=min(0.5 + count / (r.service_enum_distinct_ports_per_host * 4), 0.9),
            source_ip=pkt.src_ip,
            destination_ip=pkt.dst_ip,
            evidence={
                "distinct_ports_on_target": count,
                "window_seconds": r.service_enum_window_seconds,
                "threshold": r.service_enum_distinct_ports_per_host,
            },
            explanation=(
                f"Source {pkt.src_ip} probed {count} distinct ports on a single host "
                f"({pkt.dst_ip}) within {r.service_enum_window_seconds:.0f}s, consistent "
                f"with service/banner enumeration."
            ),
        )

    def _check_ssh_bruteforce(self, pkt: PacketRecord) -> Detection | None:
        r = settings.rules
        pair_key = f"{pkt.src_ip}->{pkt.dst_ip}:{pkt.dst_port}"
        count = self._ssh_bruteforce_tracker.increment(pair_key)
        if count < r.ssh_bruteforce_attempts:
            return None
        return self._emit(
            f"ssh_bruteforce:{pair_key}",
            attack_type="SSH Brute Force",
            category=AttackCategory.CREDENTIAL_ATTACKS,
            severity=Severity.HIGH,
            confidence=min(0.6 + count / (r.ssh_bruteforce_attempts * 4), 0.95),
            source_ip=pkt.src_ip,
            destination_ip=pkt.dst_ip,
            destination_port=pkt.dst_port,
            evidence={
                "connection_attempts": count,
                "window_seconds": r.ssh_bruteforce_window_seconds,
                "threshold": r.ssh_bruteforce_attempts,
            },
            explanation=(
                f"Source {pkt.src_ip} opened {count} new SSH connections to "
                f"{pkt.dst_ip}:22 within {r.ssh_bruteforce_window_seconds:.0f}s, "
                f"consistent with an SSH brute-force attempt."
            ),
        )

    def _check_password_spray(self, pkt: PacketRecord) -> Detection | None:
        r = settings.rules
        # Track distinct destination HOSTS only - spraying means "same
        # credentials against many different targets". Hitting several
        # auth ports (22, 3389, 3306...) on a SINGLE host is service
        # enumeration, not spraying, and must not be conflated with it.
        self._password_spray_tracker.add(pkt.src_ip, pkt.dst_ip)
        count = self._password_spray_tracker.distinct_count(pkt.src_ip)
        if count < r.password_spray_distinct_hosts:
            return None
        return self._emit(
            f"password_spray:{pkt.src_ip}",
            attack_type="Password Spraying",
            category=AttackCategory.CREDENTIAL_ATTACKS,
            severity=Severity.HIGH,
            confidence=min(0.6 + count / (r.password_spray_distinct_hosts * 4), 0.95),
            source_ip=pkt.src_ip,
            evidence={
                "distinct_target_hosts": count,
                "window_seconds": r.password_spray_window_seconds,
                "threshold": r.password_spray_distinct_hosts,
            },
            explanation=(
                f"Source {pkt.src_ip} attempted authentication against {count} distinct "
                f"target hosts within {r.password_spray_window_seconds:.0f}s - a "
                f"low-and-slow pattern consistent with password spraying rather than a "
                f"single-target brute force."
            ),
        )

    def _check_syn_flood_rate(self, pkt: PacketRecord) -> Detection | None:
        r = settings.rules
        count = self._syn_rate_tracker.count(pkt.dst_ip)
        rate_per_sec = count / r.syn_flood_window_seconds
        if rate_per_sec < r.syn_flood_syn_per_second:
            return None
        return self._emit(
            f"syn_flood:{pkt.dst_ip}",
            attack_type="SYN Flood",
            category=AttackCategory.NETWORK_ATTACKS,
            severity=Severity.CRITICAL,
            confidence=min(0.6 + rate_per_sec / (r.syn_flood_syn_per_second * 4), 0.97),
            source_ip=pkt.src_ip,
            destination_ip=pkt.dst_ip,
            evidence={
                "syn_packets_per_second": round(rate_per_sec, 1),
                "window_seconds": r.syn_flood_window_seconds,
                "threshold_per_second": r.syn_flood_syn_per_second,
            },
            explanation=(
                f"Destination {pkt.dst_ip} received {round(rate_per_sec, 1)} SYN "
                f"packets/sec, exceeding the {r.syn_flood_syn_per_second}/sec SYN flood "
                f"threshold."
            ),
        )

    def _check_syn_flood_completion(self, flow: Flow, features: dict) -> Detection | None:
        r = settings.rules
        if flow.syn_count < 10:
            return None
        completion_ratio = flow.ack_count / flow.syn_count if flow.syn_count else 1.0
        if completion_ratio > r.syn_flood_completion_ratio:
            return None
        return self._emit(
            f"syn_flood_incomplete:{flow.dst_ip}:{flow.flow_id}",
            attack_type="SYN Flood",
            category=AttackCategory.NETWORK_ATTACKS,
            severity=Severity.HIGH,
            confidence=0.7,
            source_ip=flow.src_ip,
            destination_ip=flow.dst_ip,
            destination_port=flow.dst_port,
            evidence={
                "syn_count": flow.syn_count,
                "ack_count": flow.ack_count,
                "completion_ratio": round(completion_ratio, 3),
                "features": features,
            },
            explanation=(
                f"Flow to {flow.dst_ip} saw {flow.syn_count} SYNs but only "
                f"{flow.ack_count} completed handshakes (ratio "
                f"{round(completion_ratio, 2)}), indicating unanswered/half-open "
                f"connections typical of a SYN flood."
            ),
        )

    def _check_arp_spoof(self, pkt: PacketRecord) -> Detection | None:
        r = settings.rules
        if not pkt.arp_sender_ip or not pkt.arp_sender_mac:
            return None
        macs_seen = self._arp_mac_tracker.record(pkt.arp_sender_ip, pkt.arp_sender_mac)
        if len(macs_seen) < r.arp_spoof_mac_changes:
            return None
        return self._emit(
            f"arp_spoof:{pkt.arp_sender_ip}",
            attack_type="ARP Spoofing",
            category=AttackCategory.NETWORK_ATTACKS,
            severity=Severity.CRITICAL,
            confidence=0.85,
            source_ip=pkt.arp_sender_ip,
            evidence={
                "mac_addresses_claimed": sorted(macs_seen),
                "window_seconds": r.arp_spoof_window_seconds,
            },
            explanation=(
                f"IP address {pkt.arp_sender_ip} was claimed by {len(macs_seen)} different "
                f"MAC addresses ({', '.join(sorted(macs_seen))}) within "
                f"{r.arp_spoof_window_seconds:.0f}s. This is the classic signature of ARP "
                f"cache poisoning / spoofing, especially concerning if this IP is your "
                f"default gateway."
            ),
        )

    def _check_dns_tunneling(self, pkt: PacketRecord) -> Detection | None:
        r = settings.rules
        qname = (pkt.dns_qname or "").rstrip(".")
        if not qname:
            return None

        self._dns_query_tracker.increment(pkt.src_ip)
        self._dns_subdomain_tracker.add(pkt.src_ip, qname)
        self._last_dns_qname_len[pkt.src_ip] = len(qname)

        queries_last_min = self._dns_query_tracker.count(pkt.src_ip)
        unique_names = self._dns_subdomain_tracker.distinct_values(pkt.src_ip)
        uniqueness_ratio = len(unique_names) / queries_last_min if queries_last_min else 0.0

        leaf = _leaf_label(qname)
        entropy = _shannon_entropy(leaf)

        # A long qname alone is common and benign (CDN/analytics/ad-tech
        # hostnames are frequently 60-100+ chars of readable words). What
        # actually distinguishes tunneling is a long, HIGH-ENTROPY leaf
        # label - i.e. it looks like encoded data, not a hostname humans
        # or CDNs would generate.
        long_and_random = len(qname) >= r.dns_tunnel_query_len_threshold and entropy >= r.dns_tunnel_min_entropy
        high_volume_and_unique = (
            queries_last_min >= r.dns_tunnel_queries_per_minute
            and uniqueness_ratio >= r.dns_tunnel_unique_subdomain_ratio
            and entropy >= r.dns_tunnel_min_entropy
        )

        if not (long_and_random or high_volume_and_unique):
            return None

        return self._emit(
            f"dns_tunnel:{pkt.src_ip}",
            attack_type="DNS Tunneling",
            category=AttackCategory.MALWARE_BEHAVIORS,
            severity=Severity.HIGH,
            confidence=0.8 if long_and_random and high_volume_and_unique else 0.65,
            source_ip=pkt.src_ip,
            evidence={
                "sample_qname": qname[:80],
                "qname_length": len(qname),
                "leaf_label_entropy_bits": round(entropy, 2),
                "queries_last_60s": queries_last_min,
                "unique_query_ratio": round(uniqueness_ratio, 2),
            },
            explanation=(
                f"Source {pkt.src_ip} issued a DNS query with a high-entropy "
                f"({round(entropy, 1)} bits/char) leaf label ({len(qname)} chars total), "
                f"{queries_last_min} total queries in the last minute, and a "
                f"{round(uniqueness_ratio * 100)}% unique-subdomain ratio - consistent with "
                f"(DNS tunneling)."
            ),
        )

    def dns_features(self, src_ip: str) -> dict:
        """Expose current DNS activity for a source IP, consumed by the
        Phase 2 ML pipeline as `dns_qname_len_mean` / `dns_query_rate`
        features without re-parsing DNS packets."""
        return {
            "dns_qname_len_mean": float(self._last_dns_qname_len.get(src_ip, 0)),
            "dns_query_rate": float(self._dns_query_tracker.count(src_ip)),
        }

    def _check_exfiltration(self, flow: Flow, features: dict) -> Detection | None:
        r = settings.rules
        if flow.duration() < 1.0:
            return None
        outbound_bytes = flow.fwd_bytes
        if outbound_bytes < r.exfil_bytes_out_threshold:
            return None
        return self._emit(
            f"exfil:{flow.src_ip}->{flow.dst_ip}:{flow.flow_id}",
            attack_type="Data Exfiltration",
            category=AttackCategory.DATA_THEFT,
            severity=Severity.CRITICAL,
            confidence=0.7,
            source_ip=flow.src_ip,
            destination_ip=flow.dst_ip,
            destination_port=flow.dst_port,
            evidence={
                "outbound_bytes": outbound_bytes,
                "duration_seconds": round(flow.duration(), 1),
                "threshold_bytes": r.exfil_bytes_out_threshold,
                "features": features,
            },
            explanation=(
                f"{outbound_bytes / 1_000_000:.1f}MB was sent from {flow.src_ip} to "
                f"{flow.dst_ip} in a single flow lasting {flow.duration():.0f}s, "
                f"exceeding the {r.exfil_bytes_out_threshold / 1_000_000:.0f}MB outbound "
                f"data-exfiltration threshold."
            ),
        )

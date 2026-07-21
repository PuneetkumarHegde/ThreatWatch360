"""
AlertIQ 2.0 - Phase 1 Configuration
------------------------------------
Central configuration for packet capture and the rule engine.
Values here are tuned for a typical home/small-office network and are
meant to be overridden via environment variables or Settings page (Phase 3+).
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


@dataclass
class CaptureSettings:
    # Network interface to sniff on. None = scapy default route interface.
    # On Windows this is something like "Ethernet" / "Wi-Fi" (use `scapy.arch.windows.get_windows_if_list()`).
    # On Linux/macOS this is "eth0", "wlan0", "en0", etc.
    interface: str | None = os.environ.get("ALERTIQ_INTERFACE") or None

    # Berkeley Packet Filter applied at capture time to reduce load.
    # We capture IP + ARP traffic only; adjust if you need IPv6.
    bpf_filter: str = "ip or arp"

    # How often (seconds) the flow table is swept for expired / stale flows.
    flow_sweep_interval: float = 1.0

    # A flow with no packets for this many seconds is considered "closed"
    # and is flushed to feature extraction + rule evaluation.
    flow_idle_timeout: float = 15.0

    # Hard cap on flow lifetime even if still active, to bound memory
    # and guarantee periodic re-evaluation of long-lived connections.
    flow_max_lifetime: float = 120.0


@dataclass
class RuleThresholds:
    """Thresholds for the signature/heuristic rule engine (Phase 1).

    These are intentionally simple, explainable, and independent of the
    ML pipeline (added in Phase 2). Every rule below maps to one of the
    12 attack categories in the project spec.
    """

    # --- Reconnaissance: Port Scan ---
    # A single source touching this many distinct destination ports
    # (on one or more hosts) within the detection window is a scan.
    # NOTE: raised from 20->30 and window 10->15s after real-world Wi-Fi
    # testing showed P2P/torrent/gaming traffic can legitimately touch
    # many distinct remote ports in a short window; nmap-style scans are
    # still orders of magnitude above this.
    port_scan_distinct_ports: int = 30
    port_scan_window_seconds: float = 15.0

    # --- Reconnaissance: Host Discovery (Ping Sweep) ---
    # A single source ICMP-echoing this many distinct destination hosts
    # within the window is a sweep.
    host_discovery_distinct_hosts: int = 10
    host_discovery_window_seconds: float = 10.0

    # --- Reconnaissance: Service Enumeration ---
    # A single source hitting this many distinct ports on a *single*
    # destination host within the window is service/banner enumeration.
    # Raised from 15->25 / 15s->20s - legitimate game/streaming clients
    # occasionally touch a handful of ports on one server; real scans
    # (nmap default) hit hundreds of ports in seconds, well above this.
    service_enum_distinct_ports_per_host: int = 25
    service_enum_window_seconds: float = 20.0

    # --- Credential Attacks: SSH Brute Force ---
    ssh_bruteforce_port: int = 22
    ssh_bruteforce_attempts: int = 8
    ssh_bruteforce_window_seconds: float = 30.0

    # --- Credential Attacks: Password Spraying ---
    # Similar signature to brute force but spread across many destination
    # hosts on the same auth port within a wider window (low-and-slow).
    password_spray_distinct_hosts: int = 5
    password_spray_window_seconds: float = 120.0

    # --- Network Attacks: SYN Flood ---
    # Raised from 100->200/sec - bursty legitimate traffic (CDN prefetch,
    # download managers) can spike well above 100/sec briefly; real SYN
    # floods run into the thousands/sec, so this still catches them with
    # margin while cutting false positives on normal home networks.
    syn_flood_syn_per_second: int = 200
    syn_flood_window_seconds: float = 5.0
    # Ratio of SYN sent vs SYN-ACK received below which we suspect a flood
    # (i.e. lots of SYNs, few completed handshakes).
    syn_flood_completion_ratio: float = 0.1

    # --- Network Attacks: ARP Spoofing ---
    # Trigger if the MAC address claiming to own an IP (especially the
    # gateway IP) changes more than this many times within the window.
    # Raised from 2->3 changes / 30s->45s - a bare "2" is tripped by
    # ordinary Wi-Fi roaming or gateway failover; sustained spoofing
    # still triggers this easily since the attacker keeps re-poisoning.
    arp_spoof_mac_changes: int = 3
    arp_spoof_window_seconds: float = 45.0

    # --- Malware Behaviors: DNS Tunneling ---
    # Length alone is NOT sufficient - real CDN/analytics/ad-tech
    # subdomains are routinely 60-90+ readable characters. What actually
    # distinguishes tunneling is a long AND high-entropy leaf label (i.e.
    # it looks like base32/hex/base64-encoded data, not a hostname).
    # See detection/rule_engine.py `_shannon_entropy` / `_leaf_label`.
    dns_tunnel_query_len_threshold: int = 90       # unusually long QNAME
    dns_tunnel_min_entropy: float = 4.0             # bits/char; English/hostnames ~3.0-3.5, encoded data ~4.5-6.0
    dns_tunnel_queries_per_minute: int = 100
    dns_tunnel_unique_subdomain_ratio: float = 0.8  # high uniqueness

    # --- Malware Behaviors: Beaconing (heuristic placeholder for Phase 2 ML) ---
    beacon_min_observations: int = 6
    beacon_interval_jitter_ratio: float = 0.15  # low jitter => periodic beacon

    # --- Data Theft: Data Exfiltration ---
    exfil_bytes_out_threshold: int = 50_000_000   # 50MB outbound in window
    exfil_window_seconds: float = 60.0


@dataclass
class Settings:
    capture: CaptureSettings = field(default_factory=CaptureSettings)
    rules: RuleThresholds = field(default_factory=RuleThresholds)

    # Feature toggles (mirrors the Settings page in the SOC portal spec)
    enable_rule_engine: bool = True
    enable_ml: bool = True                   # Phase 2 - classifier (Beaconing/Botnet/SYN/DNS/Exfil confirmation)
    enable_anomaly_detection: bool = True     # Phase 2 - Isolation Forest (Unknown Attack)
    enable_notifications: bool = False        # Phase 3+
    enable_automatic_response: bool = False   # Phase 5 - IP blocking + email, OFF by default for safety

    log_level: str = os.environ.get("ALERTIQ_LOG_LEVEL", "INFO")


settings = Settings()

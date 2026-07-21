"""
AlertIQ 2.0 - MITRE ATT&CK Mapping
--------------------------------------
Maps each of the 12 supported attack types to its closest MITRE ATT&CK
(Enterprise) technique, for display on the Investigation page.
"""
from __future__ import annotations

MITRE_MAP: dict[str, tuple[str, str]] = {
    "Port Scan": ("T1046", "Network Service Discovery"),
    "Host Discovery (Ping Sweep)": ("T1018", "Remote System Discovery"),
    "Service Enumeration": ("T1046", "Network Service Discovery"),
    "SSH Brute Force": ("T1110.001", "Brute Force: Password Guessing"),
    "Password Spraying": ("T1110.003", "Brute Force: Password Spraying"),
    "SYN Flood": ("T1498.001", "Network Denial of Service: Direct Network Flood"),
    "ARP Spoofing": ("T1557.002", "Adversary-in-the-Middle: ARP Cache Poisoning"),
    "DNS Tunneling": ("T1071.004", "Application Layer Protocol: DNS"),
    "Malware Beaconing": ("T1071", "Application Layer Protocol (C2)"),
    "Botnet Communication": ("T1071", "Application Layer Protocol (C2)"),
    "Data Exfiltration": ("T1041", "Exfiltration Over C2 Channel"),
    "Unknown Attack": ("TA0000", "Unclassified / Requires Analyst Review"),
}


def lookup(attack_type: str) -> tuple[str | None, str | None]:
    return MITRE_MAP.get(attack_type, (None, None))

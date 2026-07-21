"""
AlertIQ 2.0 - Phase 5 Demo Simulation Mode
------------------------------------------------
Lets a user safely demonstrate every supported attack type WITHOUT
attacking a real device. Each simulator function builds a realistic
sequence of synthetic PacketRecord/Flow objects matching the exact
pattern the corresponding detector looks for, then feeds them through
the SAME rule engine / ML pipeline used for live traffic.

This is important: Demo Mode is not a set of canned/fake "Detection"
objects with pre-written text. It genuinely exercises the detection
code path, so a successful demo is real evidence the engine works -
not just a scripted UI animation.

All simulated traffic uses IPs from documentation/reserved ranges
(TEST-NET-1 through 3: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)
so demo runs can never be confused with real internal hosts, and
every resulting Detection/Incident is tagged `evidence["demo"] = True`
so the SOC portal can visually flag it.
"""
from __future__ import annotations

import random
import time

from detection.rule_engine import RuleEngine
from packet_capture.models import Detection, Flow, PacketRecord, Protocol

# Demo source = "the infected/attacking host" for every scenario.
DEMO_ATTACKER_IP = "203.0.113.66"
DEMO_VICTIM_IP = "198.51.100.10"
DEMO_GATEWAY_IP = "192.0.2.1"


def _tag_demo(detections: list[Detection]) -> list[Detection]:
    for d in detections:
        d.evidence = {**d.evidence, "demo": True}
    return detections


def _tcp_packet(src, dst, dport, syn=True, ack=False, sport=None) -> PacketRecord:
    return PacketRecord(
        timestamp=time.time(),
        protocol=Protocol.TCP,
        src_ip=src,
        dst_ip=dst,
        src_port=sport or random.randint(40000, 60000),
        dst_port=dport,
        length=60,
        ttl=64,
        flag_syn=syn,
        flag_ack=ack,
    )


def simulate_port_scan(engine: RuleEngine) -> list[Detection]:
    detections = []
    for port in random.sample(range(20, 9000), 40):
        detections += engine.process_packet(_tcp_packet(DEMO_ATTACKER_IP, DEMO_VICTIM_IP, port))
    return _tag_demo(detections)


def simulate_host_discovery(engine: RuleEngine) -> list[Detection]:
    detections = []
    for i in range(1, 13):
        pkt = PacketRecord(
            timestamp=time.time(), protocol=Protocol.ICMP,
            src_ip=DEMO_ATTACKER_IP, dst_ip=f"198.51.100.{i}", length=60, ttl=64,
        )
        detections += engine.process_packet(pkt)
    return _tag_demo(detections)


def simulate_service_enumeration(engine: RuleEngine) -> list[Detection]:
    detections = []
    common_ports = [
        21, 22, 23, 25, 53, 80, 88, 110, 111, 135, 139, 143, 161, 389, 443, 445,
        587, 636, 993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379, 8080, 8443,
    ]
    for port in common_ports:
        detections += engine.process_packet(_tcp_packet(DEMO_ATTACKER_IP, DEMO_VICTIM_IP, port))
    return _tag_demo(detections)


def simulate_ssh_bruteforce(engine: RuleEngine) -> list[Detection]:
    detections = []
    for _ in range(10):
        detections += engine.process_packet(_tcp_packet(DEMO_ATTACKER_IP, DEMO_VICTIM_IP, 22))
    return _tag_demo(detections)


def simulate_password_spray(engine: RuleEngine) -> list[Detection]:
    detections = []
    for i in range(1, 8):
        detections += engine.process_packet(_tcp_packet(DEMO_ATTACKER_IP, f"198.51.100.{i}", 22))
    return _tag_demo(detections)


def simulate_syn_flood(engine: RuleEngine) -> list[Detection]:
    detections = []
    for _ in range(150):
        detections += engine.process_packet(_tcp_packet(DEMO_ATTACKER_IP, DEMO_VICTIM_IP, 443, syn=True, ack=False))

    # Also exercise the flow-level completion-ratio rule.
    flow = Flow(
        key=((DEMO_ATTACKER_IP, 40000), (DEMO_VICTIM_IP, 443), "TCP"),
        protocol=Protocol.TCP, src_ip=DEMO_ATTACKER_IP, dst_ip=DEMO_VICTIM_IP,
        src_port=40000, dst_port=443,
    )
    flow.start_time = time.time() - 2
    flow.last_seen = time.time()
    flow.syn_count, flow.ack_count = 150, 3
    flow.packet_count = 153
    flow.ttl_values = [64]
    detections += engine.process_flow(flow)
    return _tag_demo(detections)


def simulate_arp_spoofing(engine: RuleEngine) -> list[Detection]:
    detections = []
    legit_mac = "AA:BB:CC:00:11:22"
    attacker_mac_1 = "DE:AD:BE:EF:00:01"
    attacker_mac_2 = "DE:AD:BE:EF:00:02"
    for mac in (legit_mac, attacker_mac_1, attacker_mac_2, legit_mac, attacker_mac_1):
        pkt = PacketRecord(
            timestamp=time.time(), protocol=Protocol.ARP,
            src_ip=DEMO_GATEWAY_IP, dst_ip="0.0.0.0", length=42,
            arp_sender_ip=DEMO_GATEWAY_IP, arp_sender_mac=mac,
        )
        detections += engine.process_packet(pkt)
    return _tag_demo(detections)


def simulate_dns_tunneling(engine: RuleEngine) -> list[Detection]:
    detections = []
    # 36-symbol alphabet (a-z0-9) gives ~5.0 bits/char entropy for a random
    # string - comfortably above the 4.0 bits/char threshold that separates
    # encoded-payload-looking labels from ordinary long hostnames.
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    for _ in range(110):
        random_label = "".join(random.choices(alphabet, k=80))
        pkt = PacketRecord(
            timestamp=time.time(), protocol=Protocol.DNS,
            src_ip=DEMO_ATTACKER_IP, dst_ip="8.8.8.8", src_port=53000, dst_port=53,
            length=90, dns_qname=f"{random_label}.exfil.demo-c2.example", dns_is_query=True,
        )
        detections += engine.process_packet(pkt)
    return _tag_demo(detections)


def simulate_data_exfiltration(engine: RuleEngine) -> list[Detection]:
    flow = Flow(
        key=((DEMO_ATTACKER_IP, 40000), ("203.0.113.200", 443), "TCP"),
        protocol=Protocol.TCP, src_ip=DEMO_ATTACKER_IP, dst_ip="203.0.113.200",
        src_port=40000, dst_port=443,
    )
    flow.start_time = time.time() - 30
    flow.last_seen = time.time()
    flow.fwd_bytes = 120_000_000
    flow.byte_count = 122_000_000
    flow.packet_count = 90_000
    flow.ttl_values = [64]
    return _tag_demo(engine.process_flow(flow))


def simulate_malware_beaconing(ml_pipeline) -> list[Detection]:
    detections: list[Detection] = []
    base = time.time()
    for i in range(15):
        flow = _make_beacon_flow(DEMO_ATTACKER_IP, "203.0.113.50", 8443, base + i * 60)
        detections += ml_pipeline.evaluate_flow(flow)
    return _tag_demo(detections)


def simulate_botnet_communication(ml_pipeline) -> list[Detection]:
    detections: list[Detection] = []
    base = time.time()
    destinations = [f"198.51.100.{n}" for n in range(20, 26)]
    for dst in destinations:
        for i in range(12):
            flow = _make_beacon_flow(DEMO_ATTACKER_IP, dst, 443, base + i * 45)
            detections += ml_pipeline.evaluate_flow(flow)
    return _tag_demo(detections)


def simulate_unknown_attack(ml_pipeline) -> list[Detection]:
    flow = _make_beacon_flow(DEMO_ATTACKER_IP, "203.0.113.250", 31337, time.time(), fwd_bytes=17, packet_count=1)
    flow.ttl_values = [1, 255, 3, 250, 5, 240]
    flow.syn_count = 0
    flow.ack_count = 0
    return _tag_demo(ml_pipeline.evaluate_flow(flow))


def _make_beacon_flow(src, dst, port, start_time, fwd_bytes=480, packet_count=6) -> Flow:
    flow = Flow(
        key=((src, 40000), (dst, port), "TCP"), protocol=Protocol.TCP,
        src_ip=src, dst_ip=dst, src_port=40000, dst_port=port,
    )
    flow.start_time = start_time
    flow.last_seen = start_time + 0.3
    flow.fwd_bytes = fwd_bytes
    flow.bwd_bytes = fwd_bytes // 4
    flow.byte_count = flow.fwd_bytes + flow.bwd_bytes
    flow.packet_count = packet_count
    flow.fwd_packets = packet_count // 2
    flow.bwd_packets = packet_count - flow.fwd_packets
    flow.syn_count = 1
    flow.ack_count = 1
    flow.ttl_values = [64]
    flow.dst_ports_seen = {port}
    return flow


# Registry consumed by the API layer. Rule-only scenarios take a
# RuleEngine; ML-only scenarios take an MLPipeline.
RULE_SCENARIOS = {
    "Port Scan": simulate_port_scan,
    "Host Discovery (Ping Sweep)": simulate_host_discovery,
    "Service Enumeration": simulate_service_enumeration,
    "SSH Brute Force": simulate_ssh_bruteforce,
    "Password Spraying": simulate_password_spray,
    "SYN Flood": simulate_syn_flood,
    "ARP Spoofing": simulate_arp_spoofing,
    "DNS Tunneling": simulate_dns_tunneling,
    "Data Exfiltration": simulate_data_exfiltration,
}

ML_SCENARIOS = {
    "Malware Beaconing": simulate_malware_beaconing,
    "Botnet Communication": simulate_botnet_communication,
    "Unknown Attack": simulate_unknown_attack,
}

ALL_SCENARIO_NAMES = list(RULE_SCENARIOS.keys()) + list(ML_SCENARIOS.keys())

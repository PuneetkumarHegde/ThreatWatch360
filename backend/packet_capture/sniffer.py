"""
AlertIQ 2.0 - Phase 1 Packet Sniffer
--------------------------------------
Wraps Scapy's AsyncSniffer to capture live traffic and normalize every
packet into a PacketRecord, which is then pushed onto a thread-safe queue
for the FlowManager to consume.

Requires elevated privileges to run:
  - Linux/macOS: run with sudo, or grant cap_net_raw to the python binary
  - Windows: install Npcap (https://npcap.com) and run as Administrator

This module has ZERO knowledge of "attacks" - it only normalizes packets.
All detection logic lives in detection/rule_engine.py.
"""
from __future__ import annotations

import logging
import queue
import threading
import time
from typing import Optional

from scapy.all import AsyncSniffer  # type: ignore
from scapy.layers.inet import IP, TCP, UDP, ICMP  # type: ignore
from scapy.layers.l2 import ARP  # type: ignore
from scapy.layers.dns import DNS, DNSQR  # type: ignore

from config import settings
from packet_capture.models import PacketRecord, Protocol

logger = logging.getLogger("alertiq.sniffer")


def _classify_transport(pkt) -> Protocol:
    if pkt.haslayer(TCP):
        dport = int(pkt[TCP].dport)
        sport = int(pkt[TCP].sport)
        if pkt.haslayer(DNS):
            return Protocol.DNS
        if dport == 443 or sport == 443:
            return Protocol.HTTPS
        if dport == 80 or sport == 80:
            return Protocol.HTTP
        return Protocol.TCP
    if pkt.haslayer(UDP):
        if pkt.haslayer(DNS):
            return Protocol.DNS
        return Protocol.UDP
    if pkt.haslayer(ICMP):
        return Protocol.ICMP
    if pkt.haslayer(ARP):
        return Protocol.ARP
    return Protocol.OTHER


def normalize_packet(pkt) -> Optional[PacketRecord]:
    """Convert a raw Scapy packet into a PacketRecord, or None if unsupported."""
    try:
        ts = float(getattr(pkt, "time", time.time()))
        length = len(pkt)

        if pkt.haslayer(ARP):
            arp = pkt[ARP]
            return PacketRecord(
                timestamp=ts,
                protocol=Protocol.ARP,
                src_ip=arp.psrc,
                dst_ip=arp.pdst,
                length=length,
                arp_sender_mac=arp.hwsrc,
                arp_sender_ip=arp.psrc,
            )

        if not pkt.haslayer(IP):
            return None  # Phase 1 focuses on IPv4 + ARP; IPv6 is a future extension

        ip = pkt[IP]
        proto = _classify_transport(pkt)

        record = PacketRecord(
            timestamp=ts,
            protocol=proto,
            src_ip=ip.src,
            dst_ip=ip.dst,
            length=length,
            ttl=int(ip.ttl),
        )

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            record.src_port = int(tcp.sport)
            record.dst_port = int(tcp.dport)
            flags = tcp.flags
            record.flag_syn = bool(flags & 0x02)
            record.flag_ack = bool(flags & 0x10)
            record.flag_fin = bool(flags & 0x01)
            record.flag_rst = bool(flags & 0x04)
            record.flag_psh = bool(flags & 0x08)
            record.flag_urg = bool(flags & 0x20)
        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            record.src_port = int(udp.sport)
            record.dst_port = int(udp.dport)

        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            try:
                qname = pkt[DNSQR].qname
                record.dns_qname = qname.decode(errors="ignore") if isinstance(qname, bytes) else str(qname)
                record.dns_is_query = (pkt[DNS].qr == 0)
            except Exception:  # noqa: BLE001 - malformed DNS should never crash capture
                pass

        return record
    except Exception:  # noqa: BLE001
        logger.exception("Failed to normalize packet; dropping it")
        return None


class PacketSniffer:
    """Thin, restartable wrapper around scapy.AsyncSniffer.

    Usage:
        sniffer = PacketSniffer(out_queue)
        sniffer.start()
        ...
        sniffer.stop()
    """

    def __init__(self, out_queue: "queue.Queue[PacketRecord]", interface: str | None = None):
        self.out_queue = out_queue
        self.interface = interface or settings.capture.interface
        self._sniffer: AsyncSniffer | None = None
        self._lock = threading.Lock()
        self.packets_captured = 0
        self.packets_dropped = 0

    def _on_packet(self, pkt) -> None:
        record = normalize_packet(pkt)
        if record is None:
            self.packets_dropped += 1
            return
        try:
            self.out_queue.put_nowait(record)
            self.packets_captured += 1
        except queue.Full:
            self.packets_dropped += 1
            logger.warning("Packet queue full; dropping packet to avoid unbounded memory growth")

    def start(self) -> None:
        with self._lock:
            if self._sniffer is not None:
                logger.info("Sniffer already running")
                return
            logger.info(
                "Starting packet capture on interface=%s filter=%r",
                self.interface or "<default>",
                settings.capture.bpf_filter,
            )
            self._sniffer = AsyncSniffer(
                iface=self.interface,
                filter=settings.capture.bpf_filter,
                prn=self._on_packet,
                store=False,
            )
            self._sniffer.start()

    def stop(self) -> None:
        with self._lock:
            if self._sniffer is None:
                return
            logger.info(
                "Stopping packet capture (captured=%d, dropped=%d)",
                self.packets_captured,
                self.packets_dropped,
            )
            self._sniffer.stop()
            self._sniffer = None

    def is_running(self) -> bool:
        return self._sniffer is not None and getattr(self._sniffer, "running", False)

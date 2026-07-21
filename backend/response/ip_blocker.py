"""
AlertIQ 2.0 - Phase 5 Automatic Response: IP Blocking
------------------------------------------------------------
Blocks a malicious source IP at the host firewall. This is a legitimate
defensive SOC feature (comparable to Wazuh's active-response or
CrowdStrike's network containment) that acts ONLY on the local machine's
own firewall to protect itself/its network - it does not attack, exploit,
or affect any other system.

Safety design:
  - Never runs automatically without the operator having explicitly
    enabled `enable_automatic_response` in Settings (default OFF).
  - Manual block via the API is always Admin-only.
  - Every block is logged with the exact command executed, and can be
    reversed with unblock_ip().
  - Refuses to block private/loopback/reserved ranges by default (you
    do not want a false positive auto-blocking your own gateway).
"""
from __future__ import annotations

import ipaddress
import logging
import platform
import subprocess

logger = logging.getLogger("alertiq.response.ip_blocker")

_RULE_PREFIX = "AlertIQ_Block_"


class BlockResult:
    def __init__(self, success: bool, message: str, command: str | None = None):
        self.success = success
        self.message = message
        self.command = command

    def to_dict(self) -> dict:
        return {"success": self.success, "message": self.message, "command": self.command}


def _is_safe_to_block(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved or addr.is_multicast)


def block_ip(ip: str, *, allow_private: bool = False) -> BlockResult:
    """Block outbound/inbound traffic to/from `ip` at the host firewall.

    Args:
        ip: the IP address to block.
        allow_private: set True only if you deliberately want to block an
            RFC1918 address (e.g. a compromised internal host) - off by
            default to avoid accidentally blocking your own gateway/DNS.
    """
    if not allow_private and not _is_safe_to_block(ip):
        return BlockResult(False, f"Refusing to block {ip}: private/loopback/reserved address. Pass allow_private=True to override.")

    system = platform.system()
    rule_name = f"{_RULE_PREFIX}{ip.replace('.', '_').replace(':', '_')}"

    try:
        if system == "Windows":
            cmd = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}", "dir=in", "action=block", f"remoteip={ip}",
            ]
            subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=10)
            cmd_out = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}_out", "dir=out", "action=block", f"remoteip={ip}",
            ]
            subprocess.run(cmd_out, check=True, capture_output=True, text=True, timeout=10)
            return BlockResult(True, f"Blocked {ip} via Windows Firewall", " ".join(cmd))

        elif system == "Linux":
            cmd_in = ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"]
            cmd_out = ["iptables", "-I", "OUTPUT", "-d", ip, "-j", "DROP"]
            subprocess.run(cmd_in, check=True, capture_output=True, text=True, timeout=10)
            subprocess.run(cmd_out, check=True, capture_output=True, text=True, timeout=10)
            return BlockResult(True, f"Blocked {ip} via iptables", " ".join(cmd_in))

        elif system == "Darwin":
            # macOS: pf requires an anchor file edit + reload, which is
            # more involved than a single command. We surface this as an
            # unsupported-but-documented case rather than silently no-op.
            return BlockResult(False, "Automatic blocking on macOS (pf) is not implemented - block manually via pfctl.")

        else:
            return BlockResult(False, f"Unsupported platform for automatic blocking: {system}")

    except subprocess.CalledProcessError as e:
        logger.error("Failed to block %s: %s", ip, e.stderr)
        return BlockResult(False, f"Firewall command failed: {e.stderr.strip() if e.stderr else e}")
    except FileNotFoundError:
        return BlockResult(False, f"Firewall tool not found for platform {system} (are you running with sufficient privileges / is it installed?)")
    except subprocess.TimeoutExpired:
        return BlockResult(False, "Firewall command timed out")


def unblock_ip(ip: str) -> BlockResult:
    system = platform.system()
    rule_name = f"{_RULE_PREFIX}{ip.replace('.', '_').replace(':', '_')}"

    try:
        if system == "Windows":
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"],
                check=False, capture_output=True, text=True, timeout=10,
            )
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}_out"],
                check=False, capture_output=True, text=True, timeout=10,
            )
            return BlockResult(True, f"Unblocked {ip}")

        elif system == "Linux":
            subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=False, capture_output=True, timeout=10)
            subprocess.run(["iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP"], check=False, capture_output=True, timeout=10)
            return BlockResult(True, f"Unblocked {ip}")

        else:
            return BlockResult(False, f"Unsupported platform for unblocking: {system}")

    except Exception as e:  # noqa: BLE001
        return BlockResult(False, f"Failed to unblock {ip}: {e}")

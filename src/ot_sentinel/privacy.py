from __future__ import annotations

import hashlib
import ipaddress
from copy import deepcopy
from typing import Any


def pseudonymize_ip(ip: str, salt: str) -> str:
    """Return a stable, non-reversible label for publication."""
    return "src-" + hashlib.sha256(f"{salt}|{ip}".encode()).hexdigest()[:12]


def network_prefix(ip: str) -> str:
    address = ipaddress.ip_address(ip)
    prefix = 24 if address.version == 4 else 48
    return str(ipaddress.ip_network(f"{address}/{prefix}", strict=False))


def sanitize_event(event: dict[str, Any], salt: str) -> dict[str, Any]:
    clean = deepcopy(event)
    source_ip = str(clean.pop("source_ip", "0.0.0.0"))
    clean["source_id"] = pseudonymize_ip(source_ip, salt)
    clean["source_network"] = network_prefix(source_ip)
    clean.pop("raw_payload_hex", None)
    decoded = clean.get("decoded", {})
    for key in ("username", "password", "token", "credential"):
        decoded.pop(key, None)
    clean["decoded"] = decoded
    clean["sanitized"] = True
    return clean


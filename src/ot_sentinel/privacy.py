from __future__ import annotations

import hashlib
import ipaddress
from copy import deepcopy
from typing import Any

from .publication import MIN_PSEUDONYM_SALT_LENGTH, strip_credential_fields


def pseudonymize_ip(ip: str, salt: str) -> str:
    """Return a stable, non-reversible label for publication."""
    if len(salt) < MIN_PSEUDONYM_SALT_LENGTH:
        raise ValueError(
            f"pseudonymization salt must contain at least {MIN_PSEUDONYM_SALT_LENGTH} characters"
        )
    ipaddress.ip_address(ip)
    return "src-" + hashlib.sha256(f"{salt}|{ip}".encode()).hexdigest()[:12]


def network_prefix(ip: str) -> str:
    address = ipaddress.ip_address(ip)
    prefix = 24 if address.version == 4 else 48
    return str(ipaddress.ip_network(f"{address}/{prefix}", strict=False))


def sanitize_event(event: dict[str, Any], salt: str) -> dict[str, Any]:
    clean = deepcopy(event)
    source_ip = str(clean.pop("source_ip", "")).strip()
    if not source_ip:
        raise ValueError("source_ip is required for strict public sanitization")
    clean["source_id"] = pseudonymize_ip(source_ip, salt)
    clean.pop("source_network", None)
    clean.pop("raw_payload_hex", None)
    clean = strip_credential_fields(clean)
    clean["sanitized"] = True
    return clean

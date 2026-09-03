from __future__ import annotations

import socket
import struct
from hashlib import sha256
from pathlib import Path

PCAP_GLOBAL = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)


def archive_previous_output(output: Path) -> Path | None:
    """Move a prior ignored EVE file aside so repeated native runs stay exact."""
    if not output.exists():
        return None

    digest = sha256(output.read_bytes()).hexdigest()[:12]
    archive_dir = output.parent / "archive"
    archive_dir.mkdir(parents=True, exist_ok=True)
    counter = 1
    while True:
        destination = archive_dir / f"eve-{digest}-{counter}.json"
        if not destination.exists():
            output.replace(destination)
            return destination
        counter += 1


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def packet(
    src: str,
    dst: str,
    sport: int,
    dport: int,
    seq: int,
    ack: int,
    flags: int,
    data: bytes = b"",
) -> bytes:
    src_bytes = socket.inet_aton(src)
    dst_bytes = socket.inet_aton(dst)
    tcp = struct.pack("!HHIIHHHH", sport, dport, seq, ack, (5 << 12) | flags, 64240, 0, 0)
    pseudo = src_bytes + dst_bytes + struct.pack("!BBH", 0, 6, len(tcp) + len(data))
    tcp_checksum = checksum(pseudo + tcp + data)
    tcp = struct.pack(
        "!HHIIHHHH", sport, dport, seq, ack, (5 << 12) | flags, 64240, tcp_checksum, 0
    )
    total_length = 20 + len(tcp) + len(data)
    ip = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, total_length, 1, 0, 64, 6, 0, src_bytes, dst_bytes
    )
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    ethernet = bytes.fromhex("0200000000020200000000010800")
    return ethernet + ip + tcp + data


def flow(sport: int, payload: bytes, base_time: int) -> list[tuple[int, bytes]]:
    client, server = "198.51.100.10", "10.20.0.5"
    client_seq, server_seq = 1000, 5000
    return [
        (base_time, packet(client, server, sport, 502, client_seq, 0, 0x02)),
        (base_time + 1, packet(server, client, 502, sport, server_seq, client_seq + 1, 0x12)),
        (base_time + 2, packet(client, server, sport, 502, client_seq + 1, server_seq + 1, 0x10)),
        (
            base_time + 3,
            packet(
                client,
                server,
                sport,
                502,
                client_seq + 1,
                server_seq + 1,
                0x18,
                payload,
            ),
        ),
    ]


def write_pcap(path: Path) -> None:
    write_request = bytes.fromhex("000100000006010600010001")
    read_request = bytes.fromhex("000200000006010300000001")
    packets = flow(41000, write_request, 1) + flow(42000, read_request, 10)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as handle:
        handle.write(PCAP_GLOBAL)
        for timestamp, raw in packets:
            handle.write(struct.pack("<IIII", timestamp, 0, len(raw), len(raw)))
            handle.write(raw)


if __name__ == "__main__":
    soc_dir = Path(__file__).resolve().parent
    archived = archive_previous_output(soc_dir / "output" / "eve.json")
    write_pcap(soc_dir / "fixtures" / "modbus-write-read.pcap")
    if archived is not None:
        print(f"Archived prior ignored Suricata output as {archived.name}.")
    print("Created deterministic synthetic Modbus PCAP fixture.")

#!/usr/bin/env python3
"""Create deterministic, checksum-correct test captures; never send traffic.

Only Python's standard library is required. Timestamps and traffic are synthetic.
These labels describe generated scenarios and expected rule behavior, not a
measurement of attack detection accuracy on real network traffic.
"""
# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import argparse
import csv
import json
import socket
import struct
from pathlib import Path

BASE_NS = 1_793_923_200_000_000_000
DEFAULT_SRC = "10.0.0.10"
DEFAULT_DST = "10.0.0.20"


def checksum(data: bytes) -> int:
    if len(data) & 1:
        data += b"\x00"
    value = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while value >> 16:
        value = (value & 0xFFFF) + (value >> 16)
    return (~value) & 0xFFFF


def ipv4_packet(
    payload: bytes,
    protocol: int,
    src: str = DEFAULT_SRC,
    dst: str = DEFAULT_DST,
    *,
    identification: int = 1,
    flags_offset: int = 0,
    options: bytes = b"",
) -> bytes:
    if len(options) % 4 or len(options) > 40:
        raise ValueError("IPv4 options must be a multiple of 4 bytes, at most 40")
    header = struct.pack(
        "!BBHHHBBH4s4s", 0x45 + len(options) // 4, 0,
        20 + len(options) + len(payload), identification & 0xFFFF,
        flags_offset, 64, protocol, 0, socket.inet_aton(src), socket.inet_aton(dst),
    ) + options
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    return header + payload


def ethernet(ip_packet: bytes, padding: bytes = b"") -> bytes:
    return bytes.fromhex("0200000000200200000000100800") + ip_packet + padding


def icmp_frame(
    payload_len: int = 900,
    *,
    src: str = DEFAULT_SRC,
    dst: str = DEFAULT_DST,
    icmp_type: int = 8,
    icmp_code: int = 0,
    sequence: int = 1,
    flags_offset: int = 0,
    ip_options: bytes = b"",
    padding: bytes = b"",
) -> bytes:
    payload = bytes((i + sequence) % 251 for i in range(payload_len))
    message = struct.pack("!BBHHH", icmp_type, icmp_code, 0, 0x1234,
                          sequence & 0xFFFF) + payload
    message = message[:2] + struct.pack("!H", checksum(message)) + message[4:]
    return ethernet(ipv4_packet(message, 1, src, dst, identification=sequence,
                               flags_offset=flags_offset, options=ip_options), padding)


def transport_checksum(payload: bytes, protocol: int, src: str, dst: str) -> int:
    pseudo = socket.inet_aton(src) + socket.inet_aton(dst)
    pseudo += struct.pack("!BBH", 0, protocol, len(payload))
    return checksum(pseudo + payload)


def tcp_frame(
    payload: bytes = b"test",
    *,
    src: str = DEFAULT_SRC,
    dst: str = DEFAULT_DST,
    src_port: int = 12345,
    dst_port: int = 80,
    flags: int = 0x18,
    tcp_options: bytes = b"",
    ip_options: bytes = b"",
) -> bytes:
    if len(tcp_options) % 4 or len(tcp_options) > 40:
        raise ValueError("TCP options must be a multiple of 4 bytes, at most 40")
    segment = struct.pack(
        "!HHIIBBHHH", src_port, dst_port, 1000, 2000,
        (5 + len(tcp_options) // 4) << 4, flags, 4096, 0, 0,
    ) + tcp_options + payload
    segment = segment[:16] + struct.pack("!H", transport_checksum(
        segment, 6, src, dst)) + segment[18:]
    return ethernet(ipv4_packet(segment, 6, src, dst, options=ip_options))


def udp_frame(
    payload: bytes = b"test",
    *,
    src: str = DEFAULT_SRC,
    dst: str = DEFAULT_DST,
    src_port: int = 12345,
    dst_port: int = 53,
    ip_options: bytes = b"",
    trailing_ip_bytes: bytes = b"",
) -> bytes:
    segment = struct.pack("!HHHH", src_port, dst_port, 8 + len(payload), 0) + payload
    value = transport_checksum(segment, 17, src, dst) or 0xFFFF
    segment = segment[:6] + struct.pack("!H", value) + segment[8:]
    return ethernet(ipv4_packet(segment + trailing_ip_bytes, 17, src, dst,
                               options=ip_options))


def pcap_bytes(
    records: list[tuple[int, bytes]],
    *,
    endian: str = "<",
    nanoseconds: bool = False,
    linktype: int = 1,
    snaplen: int = 262144,
    wire_lengths: list[int] | None = None,
) -> bytes:
    if endian not in ("<", ">"):
        raise ValueError("endian must be '<' or '>'")
    magic = 0xA1B23C4D if nanoseconds else 0xA1B2C3D4
    result = bytearray(struct.pack(endian + "IHHIIII", magic, 2, 4,
                                   0, 0, snaplen, linktype))
    for index, (timestamp_ns, frame) in enumerate(records):
        seconds, fraction_ns = divmod(timestamp_ns, 1_000_000_000)
        fraction = fraction_ns if nanoseconds else fraction_ns // 1000
        wire_len = len(frame) if wire_lengths is None else wire_lengths[index]
        result.extend(struct.pack(endian + "IIII", seconds, fraction,
                                  len(frame), wire_len))
        result.extend(frame)
    return bytes(result)


def write_pcap(path: Path | str, records: list[tuple[int, bytes]], **options) -> None:
    Path(path).write_bytes(pcap_bytes(records, **options))


def create_demo(destination: Path) -> dict:
    destination.mkdir(parents=True, exist_ok=True)
    records: list[tuple[int, bytes]] = []
    labels: list[dict] = []

    def append(offset_ns: int, size: int, scenario: str, *, src=DEFAULT_SRC,
               dst=DEFAULT_DST, icmp_type=8, alerts=False) -> None:
        index = len(records) + 1
        stamp = BASE_NS + offset_ns
        records.append((stamp, icmp_frame(size, src=src, dst=dst,
                                         icmp_type=icmp_type, sequence=index)))
        labels.append({
            "packet_index": index, "timestamp_ns": stamp,
            "scenario": scenario, "src_ip": src, "dst_ip": dst,
            "icmp_type": icmp_type, "payload_bytes": size,
            "expected_alert_sid": "1000001" if alerts else "",
        })

    for index in range(8):
        append(index * 100_000_000, 56, "small_echo")
    for index in range(4):
        append((2 + index * 2) * 1_000_000_000, 900, "large_sparse_echo")
    for index in range(15):
        append(10_000_000_000 + index * 50_000_000, 900,
               "large_frequent_echo", alerts=index >= 10)
    for index in range(4):
        append(10_750_000_000 + index * 50_000_000, 900,
               "large_echo_reply", src=DEFAULT_DST, dst=DEFAULT_SRC, icmp_type=0)
    for index in range(3):
        append(10_950_000_000 + index * 50_000_000, 900,
               "large_echo_other_source", src="10.0.0.30")

    write_pcap(destination / "demo.pcap", records)
    with (destination / "demo-labels.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(labels[0]))
        writer.writeheader()
        writer.writerows(labels)
    expected = {
        "synthetic_fixture": True,
        "description": "Generated packets; expected rule alerts, not measured detection accuracy.",
        "total_packets": 34,
        "decoded_packets": 34,
        "skipped_packets": 0,
        "matching_packets": 22,
        "alerts": 5,
        "alert_packet_indices": [23, 24, 25, 26, 27],
        "sid": 1000001,
        "rule": "alert icmp any any -> any any (msg:\"Large frequent ICMP echo\"; itype:8; dsize:>800; detection_filter:track by_src, count 10, seconds 1; sid:1000001; rev:1;)",
        "semantics": "Only matching requests count. The 11th and later in the inclusive fixed 1s window alert.",
    }
    (destination / "expected.json").write_text(json.dumps(expected, indent=2) + "\n", encoding="utf-8")
    return expected


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path,
                        default=Path(__file__).resolve().parents[1] / "samples")
    args = parser.parse_args()
    result = create_demo(args.output)
    print(f"Created {args.output / 'demo.pcap'}: {result['total_packets']} packets, "
          f"{result['alerts']} expected alerts (packets 23-27). No traffic was sent.")

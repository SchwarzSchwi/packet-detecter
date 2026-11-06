#!/usr/bin/env python3
"""Observable-behavior regression tests for the extracted packet detector."""
# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import argparse
import csv
import json
import os
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from make_sample import (BASE_NS, create_demo, icmp_frame, pcap_bytes,
                         tcp_frame, udp_frame)  # noqa: E402

BINARY = Path(os.environ.get("DETECTOR_BINARY", ROOT / "bin" / "packet-detector"))
DEFAULT_RULE = ('alert icmp any any -> any any (msg:"Large frequent ICMP echo"; '
                'itype:8; dsize:>800; detection_filter:track by_src, count 10, '
                'seconds 1; sid:1000001; rev:1;)')


class DetectorTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="packet-detector-test-")
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name)
        self.run_index = 0

    def run_command(self, arguments):
        return subprocess.run([str(BINARY), *map(str, arguments)],
                              capture_output=True, text=True, timeout=20,
                              cwd=self.path)

    def capture(self, records, rules, *, extra=(), **pcap_options):
        self.run_index += 1
        base = self.path / str(self.run_index)
        capture_path = base.with_suffix(".pcap")
        rules_path = base.with_suffix(".rules")
        output = self.path / f"out-{self.run_index}"
        capture_path.write_bytes(records if isinstance(records, bytes)
                                 else pcap_bytes(records, **pcap_options))
        rules_path.write_text(rules + "\n", encoding="utf-8")
        completed = self.run_command(["-r", capture_path, "-S", rules_path,
                                      "-l", output, *extra])
        self.assertEqual(completed.returncode, 0,
                         f"Command failed:\n{completed.stdout}\n{completed.stderr}")
        with (output / "alerts.csv").open(newline="", encoding="utf-8") as stream:
            alerts = list(csv.DictReader(stream))
        with (output / "packets.csv").open(newline="", encoding="utf-8") as stream:
            packets = list(csv.DictReader(stream))
        summary = json.loads((output / "summary.json").read_text(encoding="utf-8"))
        return alerts, packets, summary

    def check_invalid_rule(self, rule):
        path = self.path / "invalid.rules"
        path.write_text(rule + "\n", encoding="utf-8")
        result = self.run_command(["-T", "-S", path])
        self.assertNotEqual(result.returncode, 0, f"Rule was accepted: {rule}")
        self.assertTrue(result.stderr.strip(), "Invalid rule must have a diagnostic")

    def check_invalid_capture(self, contents):
        capture_path = self.path / "invalid.pcap"
        rules_path = self.path / "valid.rules"
        capture_path.write_bytes(contents)
        rules_path.write_text(DEFAULT_RULE + "\n", encoding="utf-8")
        self.run_index += 1
        result = self.run_command(["-r", capture_path, "-S", rules_path, "-l",
                                   self.path / f"bad-out-{self.run_index}"])
        self.assertNotEqual(result.returncode, 0, "Malformed capture was accepted")
        self.assertTrue(result.stderr.strip(), "Malformed capture must have a diagnostic")

    @staticmethod
    def indices(alerts, sid=None):
        return [int(row["packet_index"]) for row in alerts
                if sid is None or int(row["sid"]) == sid]

    def test_01_demo_exact_packets(self):
        create_demo(self.path / "sample")
        data = (self.path / "sample" / "demo.pcap").read_bytes()
        alerts, packets, summary = self.capture(data, DEFAULT_RULE)
        self.assertEqual(self.indices(alerts), [23, 24, 25, 26, 27])
        self.assertEqual([int(a["window_count"]) for a in alerts], [11, 12, 13, 14, 15])
        self.assertEqual(len(packets), 34)
        self.assertEqual(summary["total_packets"], 34)
        self.assertEqual(summary["decoded_packets"], 34)
        self.assertEqual(summary["skipped_packets"], 0)
        self.assertEqual(summary["alerts"], 5)
        self.assertEqual(summary["rules"][0]["matched_packets"], 22)

    def test_02_payload_comparison_boundaries(self):
        records = [(BASE_NS + n * 1000, icmp_frame(size))
                   for n, size in enumerate([799, 800, 801, 802])]
        terms = [(1, ">800"), (2, "800"), (3, "800<>802"),
                 (4, "!800"), (5, ">=800"), (6, "<=800")]
        rules = "\n".join(f'alert icmp any any -> any any (dsize:{term}; sid:{sid};)'
                          for sid, term in terms)
        alerts, _, _ = self.capture(records, rules)
        expected = {1: [3, 4], 2: [2], 3: [3], 4: [1, 3, 4], 5: [2, 3, 4], 6: [1, 2]}
        for sid, indices in expected.items():
            self.assertEqual(self.indices(alerts, sid), indices, f"sid={sid}")

    def test_03_filter_count_plus_one_and_exact_time_boundary(self):
        offsets = [0, 500_000_000, 1_000_000_000, 1_000_000_001,
                   1_500_000_000, 2_000_000_001, 2_000_000_002]
        records = [(BASE_NS + value, icmp_frame()) for value in offsets]
        rule = ('alert icmp any any -> any any (dsize:>800; '
                'detection_filter:track by_src, count 2, seconds 1; sid:1;)')
        alerts, _, _ = self.capture(records, rule, nanoseconds=True)
        self.assertEqual(self.indices(alerts), [3, 6])
        self.assertEqual([int(a["window_count"]) for a in alerts], [3, 3])

    def test_04_nonmatching_packets_do_not_advance_count(self):
        frames = [icmp_frame(900), icmp_frame(56), icmp_frame(900),
                  icmp_frame(900, icmp_type=0), icmp_frame(900)]
        records = [(BASE_NS + n * 1_000_000, frame) for n, frame in enumerate(frames)]
        rule = ('alert icmp any any -> any any (itype:8; dsize:>800; '
                'detection_filter:track by_src, count 2, seconds 1; sid:1;)')
        alerts, _, summary = self.capture(records, rule)
        self.assertEqual(self.indices(alerts), [5])
        self.assertEqual(summary["rules"][0]["matched_packets"], 3)

    def test_05_tracking_keys_and_rule_isolation(self):
        addresses = [("10.0.0.1", "10.0.0.10"), ("10.0.0.2", "10.0.0.10"),
                     ("10.0.0.1", "10.0.0.20"), ("10.0.0.2", "10.0.0.10"),
                     ("10.0.0.1", "10.0.0.10")]
        records = [(BASE_NS + n * 100_000_000, icmp_frame(src=src, dst=dst))
                   for n, (src, dst) in enumerate(addresses)]
        rules = "\n".join(
            f'alert icmp any any -> any any (detection_filter:track {track}, '
            f'count {count}, seconds 1; sid:{sid};)'
            for sid, track, count in [(1, "by_src", 1), (2, "by_dst", 1),
                                      (3, "by_src", 2)])
        alerts, _, _ = self.capture(records, rules)
        expected = {1: [3, 4, 5], 2: [2, 4, 5], 3: [5]}
        for sid, indices in expected.items():
            self.assertEqual(self.indices(alerts, sid), indices, f"sid={sid}")

    def test_06_tcp_udp_lengths_exclude_options_headers_and_padding(self):
        frames = [
            tcp_frame(b"ABCD", dst_port=443, tcp_options=b"\x01\x01\x00\x00",
                      ip_options=b"\x01\x01\x00\x00"),
            udp_frame(b"abc", trailing_ip_bytes=b"ignored"),
            icmp_frame(5, ip_options=b"\x01\x01\x00\x00", padding=b"pad" * 6),
        ]
        records = [(BASE_NS + n * 1000, frame) for n, frame in enumerate(frames)]
        rules = ('alert tcp any any -> any 443 (dsize:4; sid:1;)\n'
                 'alert udp any any -> any 53 (dsize:3; sid:2;)\n'
                 'alert icmp any any -> any any (dsize:5; sid:3;)')
        alerts, packets, _ = self.capture(records, rules)
        self.assertEqual([(int(a["packet_index"]), int(a["sid"])) for a in alerts],
                         [(1, 1), (2, 2), (3, 3)])
        self.assertEqual([int(p["payload_bytes"]) for p in packets], [4, 3, 5])

    def test_07_cidr_port_ranges_and_bidirectional_rule(self):
        frames = [
            udp_frame(b"abc", src="10.1.2.3", dst="192.0.2.9", src_port=1500, dst_port=53),
            udp_frame(b"abc", src="192.0.2.9", dst="10.1.2.3", src_port=53, dst_port=1500),
            udp_frame(b"abc", src="10.2.2.3", dst="192.0.2.9", src_port=1500, dst_port=53),
            udp_frame(b"abc", src="10.1.2.3", dst="192.0.2.9", src_port=1500, dst_port=54),
            udp_frame(b"abc", src="10.1.2.3", dst="192.0.2.9", src_port=2001, dst_port=53),
        ]
        records = [(BASE_NS + n * 1000, frame) for n, frame in enumerate(frames)]
        rule = 'alert udp 10.1.0.0/16 1000:2000 <> 192.0.2.9 53 (dsize:3; sid:1;)'
        alerts, _, _ = self.capture(records, rule)
        self.assertEqual(self.indices(alerts), [1, 2])

    def test_08_icmp_type_and_code(self):
        frames = [icmp_frame(8), icmp_frame(8, icmp_type=0),
                  icmp_frame(8, icmp_type=3, icmp_code=1),
                  icmp_frame(8, icmp_type=3, icmp_code=3)]
        records = [(BASE_NS + n * 1000, frame) for n, frame in enumerate(frames)]
        rule = 'alert icmp any any -> any any (itype:3; icode:1; sid:1;)'
        alerts, _, _ = self.capture(records, rule)
        self.assertEqual(self.indices(alerts), [3])

    def test_09_endianness_and_timestamp_resolution(self):
        records = [(BASE_NS, icmp_frame()), (BASE_NS + 500_000_000, icmp_frame())]
        rule = ('alert icmp any any -> any any (detection_filter:track by_src, '
                'count 1, seconds 1; sid:1;)')
        for endian in ("<", ">"):
            for nanoseconds in (False, True):
                with self.subTest(endian=endian, nanoseconds=nanoseconds):
                    alerts, _, _ = self.capture(records, rule, endian=endian,
                                                 nanoseconds=nanoseconds)
                    self.assertEqual(self.indices(alerts), [2])

    def test_10_supported_link_layers(self):
        frame = icmp_frame(5)
        ip = frame[14:]
        variants = [
            (1, frame),
            (1, frame[:12] + bytes.fromhex("810000010800") + ip),
            (1, frame[:12] + bytes.fromhex("88a80001810000020800") + ip),
            (113, struct.pack("!HHH8sH", 0, 1, 6, b"\x02\x00\x00\x00\x00\x10\x00\x00", 0x0800) + ip),
            (276, struct.pack("!HHIHBB8s", 0x0800, 0, 1, 1, 0, 6,
                              b"\x02\x00\x00\x00\x00\x10\x00\x00") + ip),
            (101, ip),
            (0, struct.pack("<I", 2) + ip),
            (0, struct.pack(">I", 2) + ip),
        ]
        rule = 'alert icmp any any -> any any (dsize:5; sid:1;)'
        for linktype, packet in variants:
            with self.subTest(linktype=linktype, length=len(packet)):
                alerts, _, summary = self.capture([(BASE_NS, packet)], rule, linktype=linktype)
                self.assertEqual(self.indices(alerts), [1])
                self.assertEqual(summary["decoded_packets"], 1)

    def test_11_fragments_unsupported_and_truncated_packets_are_skipped(self):
        valid = icmp_frame(900)
        ipv6 = bytes.fromhex("02000000002002000000001086dd") + bytes.fromhex("6000000000083a40") + bytes(32) + bytes(8)
        frames = [valid, icmp_frame(900, flags_offset=0x2000),
                  icmp_frame(900, flags_offset=1), valid[:30], ipv6,
                  icmp_frame(20, icmp_type=13)]
        records = [(BASE_NS + n * 1000, frame) for n, frame in enumerate(frames)]
        alerts, packets, summary = self.capture(records, 'alert ip any any -> any any (sid:1;)')
        self.assertEqual(self.indices(alerts), [1])
        self.assertEqual(summary["total_packets"], 6)
        self.assertEqual(summary["decoded_packets"], 1)
        self.assertEqual(summary["skipped_packets"], 5)
        self.assertTrue(all(row["reason"] for row in packets[1:]))

    def test_12_rule_errors_are_rejected(self):
        invalid_rules = [
            'alert icmp any any -> any any (content:"abc"; sid:1;)',
            'alert icmp any any -> any any (dsize:>800; unknown_word:1; sid:1;)',
            'alert icmp any any -> any any (sid:1;)\nalert icmp any any -> any any (sid:1;)',
            'alert udp any any -> any 65536 (sid:1;)',
            'alert udp 10.0.0.1/33 any -> any any (sid:1;)',
            'alert icmp any 80 -> any any (sid:1;)',
            'alert icmp any any -> any any (dsize:65536; sid:1;)',
            'alert icmp any any -> any any (itype:256; sid:1;)',
            'alert icmp any any -> any any (dsize:800<>800; sid:1;)',
            'alert icmp any any -> any any (detection_filter:track by_src, count 0, seconds 1; sid:1;)',
            'alert icmp any any -> any any (detection_filter:track by_src, count 1, seconds 0; sid:1;)',
            'drop icmp any any -> any any (sid:1;)',
            'alert icmp any any -> any any (dsize:800;)',
        ]
        for rule in invalid_rules:
            with self.subTest(rule=rule):
                self.check_invalid_rule(rule)

    def test_13_rule_validation_and_metadata(self):
        path = self.path / "valid.rules"
        path.write_text('# comment\nalert icmp any any -> any any (msg:"semi; colon"; '
                        'itype:8; dsize:>800; classtype:bad-unknown; '
                        'reference:arachnids,246; priority:2; sid:499; rev:4;)\n', encoding="utf-8")
        result = self.run_command(["-T", "-S", path])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.path / "alerts.csv").exists())

    def test_14_structurally_corrupt_capture_is_rejected(self):
        normal = pcap_bytes([(BASE_NS, icmp_frame(5))])
        bad_incl = normal[:32] + struct.pack("<I", 300000) + normal[36:]
        bad_wire = normal[:36] + struct.pack("<I", 1) + normal[40:]
        bad_fraction = normal[:28] + struct.pack("<I", 1_000_000) + normal[32:]
        bad_linktype = normal[:20] + struct.pack("<I", 999) + normal[24:]
        for contents in [b"", normal[:12], normal[:-1], normal[:30],
                         bad_incl, bad_wire, bad_fraction, bad_linktype,
                         bytes.fromhex("0a0d0d0a") + bytes(24)]:
            with self.subTest(length=len(contents), prefix=contents[:4].hex()):
                self.check_invalid_capture(contents)

    def test_15_packet_limit_and_no_alert_input(self):
        records = [(BASE_NS + n * 1000, icmp_frame(56)) for n in range(5)]
        alerts, packets, summary = self.capture(records, DEFAULT_RULE, extra=("-c", "2"))
        self.assertEqual(alerts, [])
        self.assertEqual(len(packets), 2)
        self.assertEqual(summary["total_packets"], 2)
        self.assertEqual(summary["alerts"], 0)

    def test_16_empty_capture_is_valid(self):
        alerts, packets, summary = self.capture([], DEFAULT_RULE)
        self.assertEqual(alerts, [])
        self.assertEqual(packets, [])
        self.assertEqual(summary["total_packets"], 0)

    def test_17_ipv4_and_transport_truncation_do_not_alert(self):
        tcp = tcp_frame(b"ABCD")
        udp = udp_frame(b"ABCD")
        frames = [tcp[:40], udp[:38], icmp_frame(1)[:40],
                  bytes.fromhex("0200000000200200000000100800") + b"\x45" + bytes(5)]
        records = [(BASE_NS + n * 1000, frame) for n, frame in enumerate(frames)]
        alerts, _, summary = self.capture(records, 'alert ip any any -> any any (sid:1;)')
        self.assertEqual(alerts, [])
        self.assertEqual(summary["skipped_packets"], 4)

    def test_18_quoted_message_is_valid_csv_and_json(self):
        message = 'large, "quoted" packet; test'
        rule = 'alert icmp any any -> any any (msg:"large, \\"quoted\\" packet; test"; sid:1;)'
        alerts, _, summary = self.capture([(BASE_NS, icmp_frame())], rule)
        self.assertEqual(alerts[0]["msg"], message)
        self.assertEqual(summary["rules"][0]["msg"], message)

    def test_19_unsupported_tracking_and_distinct_counting_are_rejected(self):
        # The uploaded detection_filter parser does not accept by_rule/by_both.
        # by_flow and unique_on need state absent from this extracted subset.
        for track in ["by_rule", "by_both", "by_flow"]:
            with self.subTest(track=track):
                self.check_invalid_rule(
                    f'alert icmp any any -> any any (detection_filter:track {track}, '
                    'count 1, seconds 1; sid:1;)')
        self.check_invalid_rule(
            'alert udp any any -> any any (detection_filter:track by_src, '
            'count 1, seconds 1, unique_on dst_port; sid:1;)')

    def test_20_regressing_capture_time_is_rejected(self):
        data = pcap_bytes([(BASE_NS + 1_000_000_000, icmp_frame()),
                           (BASE_NS, icmp_frame())])
        self.check_invalid_capture(data)

    def test_21_rate_capacity_error_preserves_already_emitted_alerts(self):
        # The bounded table holds 65,536 active rule/source states. The last
        # packet alerts through rule 1 before rule 2 exhausts that table.
        # Every persisted count and the last packet row must still agree.
        count = 65537
        records = [
            (BASE_NS, icmp_frame(0, src=f"10.{n >> 16}.{(n >> 8) & 255}.{n & 255}"))
            for n in range(count)
        ]
        capture_path = self.path / "capacity.pcap"
        rules_path = self.path / "capacity.rules"
        output = self.path / "capacity-out"
        capture_path.write_bytes(pcap_bytes(records))
        rules_path.write_text(
            'alert icmp any any -> any any (sid:1;)\n'
            'alert icmp any any -> any any (detection_filter:track by_src, '
            'count 1, seconds 60; sid:2;)\n', encoding="utf-8")
        result = self.run_command(["-r", capture_path, "-S", rules_path, "-l", output])
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(result.stderr.strip())
        summary = json.loads((output / "summary.json").read_text(encoding="utf-8"))
        self.assertEqual(summary["status"], "error")
        for key in ["total_packets", "decoded_packets", "alerts", "alerted_packets"]:
            self.assertEqual(summary[key], count, key)
        self.assertEqual(summary["skipped_packets"], 0)

        def count_and_last(path):
            row_count, last = 0, None
            with path.open(newline="", encoding="utf-8") as stream:
                for last in csv.DictReader(stream):
                    row_count += 1
            return row_count, last

        packet_count, last_packet = count_and_last(output / "packets.csv")
        alert_count, last_alert = count_and_last(output / "alerts.csv")
        self.assertEqual(packet_count, count)
        self.assertEqual(alert_count, count)
        self.assertEqual(int(last_packet["packet_index"]), count)
        self.assertEqual(last_packet["status"], "error")
        self.assertEqual(last_packet["reason"], "rate_state_capacity")
        self.assertEqual(int(last_packet["alerts"]), 1)
        self.assertEqual(int(last_alert["packet_index"]), count)
        self.assertEqual(int(last_alert["sid"]), 1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=BINARY)
    args, remaining = parser.parse_known_args()
    BINARY = args.binary.resolve()
    if not BINARY.is_file():
        parser.error(f"Build the detector first; executable not found: {BINARY}")
    unittest.main(argv=[sys.argv[0], *remaining], verbosity=2)

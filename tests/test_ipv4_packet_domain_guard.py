#!/usr/bin/env python3
"""Dataplane regression test for the IPv4 packet-domain fail-open guard.

It verifies that the offline classifier and the installed BMv2 pipeline agree:
selective table candidate/no-match decisions are made only in the supported
packet domain, while IPv4 options, fragments, and parser errors are counted as
conservative packet-domain fallback.
"""

from __future__ import annotations

import ipaddress
import json
import socket
import sys
import time
from pathlib import Path

import grpc
from google.protobuf import text_format
from scapy.all import Ether, ICMP, IP, Raw, TCP

from p4.v1 import p4runtime_pb2, p4runtime_pb2_grpc
from p4.config.v1 import p4info_pb2

from analyze_prefilter_selectivity import (
    compile_entry,
    compiled_entry_matches_packet,
)
from p4_packet_domain import classify_frame_for_prefilter
from send_prefilter_test_packets import (
    build_miss_packet,
    build_packet_from_entry,
    find_miss_descriptor,
    find_protocol_entry,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
ENTRIES_FILE = PROJECT_ROOT / "output" / "p4_install_entries.json"
P4INFO_FILE = PROJECT_ROOT / "output" / "ids_prefilter.p4info.txt"
OUTPUT_FILE = PROJECT_ROOT / "output" / "analysis" / "ipv4_packet_domain_guard_test.json"
INTERFACE = "veth1"
GRPC_ADDRESS = "127.0.0.1:9559"
DEVICE_ID = 0
COUNTER_NAME = "MyIngress.prefilter_counter"


def load_entries():
    return json.loads(ENTRIES_FILE.read_text(encoding="utf-8"))["entries"]


def load_p4info():
    p4info = p4info_pb2.P4Info()
    text_format.Merge(P4INFO_FILE.read_text(encoding="utf-8"), p4info)
    return p4info


def find_counter_id(p4info):
    for counter in p4info.counters:
        if counter.preamble.name == COUNTER_NAME:
            return counter.preamble.id
    raise RuntimeError("MyIngress.prefilter_counter not found in P4Info")


def read_counter(stub, counter_id, index):
    request = p4runtime_pb2.ReadRequest(device_id=DEVICE_ID)
    request.entities.add().counter_entry.counter_id = counter_id
    request.entities[-1].counter_entry.index.index = index
    for response in stub.Read(request):
        for entity in response.entities:
            if entity.HasField("counter_entry"):
                return int(entity.counter_entry.data.packet_count)
    return 0


def read_counters(stub, counter_id):
    return {
        "p4_candidate": read_counter(stub, counter_id, 0),
        "p4_no_match": read_counter(stub, counter_id, 1),
        "packet_domain_fallback": read_counter(stub, counter_id, 2),
    }


def send_raw(frame: bytes):
    raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    try:
        raw_socket.bind((INTERFACE, 0))
        raw_socket.send(frame)
    finally:
        raw_socket.close()


def choose_flag_entry(entries, predicate):
    for entry in entries:
        flag_match = entry.get("match", {}).get("tcp_flags")
        if flag_match and predicate(int(flag_match["mask"])):
            return entry
    return None


def expected_classification(compiled_entries, frame):
    packet, reason = classify_frame_for_prefilter(frame)
    if packet is None:
        return "packet_domain_fallback", reason
    if any(compiled_entry_matches_packet(entry, packet) for entry in compiled_entries):
        return "p4_candidate", reason
    return "p4_no_match", reason


def main():
    for path in (ENTRIES_FILE, P4INFO_FILE):
        if not path.exists():
            raise SystemExit(f"ERROR: missing required file: {path}")

    entries = load_entries()
    compiled_entries = [compile_entry(entry, index) for index, entry in enumerate(entries)]

    tcp_entry = find_protocol_entry(entries, 6, avoid_flags=True)
    udp_entry = find_protocol_entry(entries, 17)
    icmp_entry = find_protocol_entry(entries, 1)
    exact_flags_entry = choose_flag_entry(entries, lambda mask: mask == 0xFF)
    masked_flags_entry = choose_flag_entry(entries, lambda mask: 0 < mask < 0xFF)
    miss_descriptor = find_miss_descriptor(entries)
    required = {
        "tcp_candidate": tcp_entry,
        "udp_candidate": udp_entry,
        "icmp_candidate": icmp_entry,
        "tcp_exact_flags_candidate": exact_flags_entry,
        "tcp_masked_flags_candidate": masked_flags_entry,
        "guaranteed_no_match": miss_descriptor,
    }
    absent = [name for name, value in required.items() if value is None]
    if absent:
        raise SystemExit(f"ERROR: required test predicates absent: {', '.join(absent)}")

    ordinary_tcp = bytes(build_packet_from_entry(tcp_entry))
    cases = [
        ("tcp_candidate", ordinary_tcp),
        ("udp_candidate", bytes(build_packet_from_entry(udp_entry))),
        ("icmp_candidate", bytes(build_packet_from_entry(icmp_entry))),
        ("guaranteed_no_match", bytes(build_miss_packet(miss_descriptor))),
        ("tcp_exact_flags_candidate", bytes(build_packet_from_entry(exact_flags_entry))),
        ("tcp_masked_flags_candidate", bytes(build_packet_from_entry(masked_flags_entry))),
        (
            "ipv4_options",
            bytes(
                Ether(src="02:00:00:00:10:01", dst="02:00:00:00:10:02")
                / IP(src="192.0.2.1", dst="192.0.2.2", options=b"\x01\x01\x01\x01")
                / TCP(sport=12345, dport=80, flags="S")
                / Raw(b"OPTIONS")
            ),
        ),
        (
            "first_fragment_mf",
            bytes(
                Ether(src="02:00:00:00:10:03", dst="02:00:00:00:10:04")
                / IP(src="192.0.2.3", dst="192.0.2.4", proto=6, flags="MF", frag=0)
                / Raw(b"FIRST-FRAGMENT")
            ),
        ),
        (
            "noninitial_fragment",
            bytes(
                Ether(src="02:00:00:00:10:05", dst="02:00:00:00:10:06")
                / IP(src="192.0.2.5", dst="192.0.2.6", proto=6, frag=1)
                / Raw(b"NONINITIAL")
            ),
        ),
        ("truncated_ipv4", bytes(Ether(type=0x0800)) + b"\x45" * 10),
        (
            "truncated_tcp",
            bytes(
                Ether(src="02:00:00:00:10:07", dst="02:00:00:00:10:08")
                / IP(src="192.0.2.7", dst="192.0.2.8", proto=6)
                / Raw(b"SHORT-TCP!")
            ),
        ),
    ]

    channel = grpc.insecure_channel(GRPC_ADDRESS)
    try:
        grpc.channel_ready_future(channel).result(timeout=5)
    except grpc.FutureTimeoutError as error:
        raise SystemExit("ERROR: BMv2 P4Runtime is not reachable") from error
    stub = p4runtime_pb2_grpc.P4RuntimeStub(channel)
    counter_id = find_counter_id(load_p4info())

    results = []
    failures = []
    for name, frame in cases:
        expected, reason = expected_classification(compiled_entries, frame)
        before = read_counters(stub, counter_id)
        send_raw(frame)
        time.sleep(0.25)
        after = read_counters(stub, counter_id)
        delta = {key: after[key] - before[key] for key in before}
        observed_categories = [key for key, value in delta.items() if value == 1]
        passed = observed_categories == [expected]
        result = {
            "case": name,
            "offline_expected": expected,
            "offline_reason": reason,
            "counter_delta": delta,
            "observed_categories": observed_categories,
            "status": "PASS" if passed else "FAIL",
        }
        results.append(result)
        if not passed:
            failures.append(result)

    payload = {
        "status": "VALID" if not failures else "INVALID",
        "counter_layout": {
            "0": "p4_candidate",
            "1": "p4_no_match",
            "2": "packet_domain_fallback",
        },
        "entries_used": len(entries),
        "cases": results,
        "failures": failures,
    }
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_FILE.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(payload, indent=2))
    channel.close()
    if failures:
        raise SystemExit(1)


if __name__ == "__main__":
    main()

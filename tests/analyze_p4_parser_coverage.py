#!/usr/bin/env python3
"""Classify Ethernet frames according to the current ids_prefilter P4 parser."""

import argparse
from collections import Counter
import json
from pathlib import Path
import struct

from scapy.utils import RawPcapReader

from p4_packet_domain import classify_frame_for_prefilter


IPV4 = 0x0800
ARP = 0x0806
IPV6 = 0x86DD
LLDP = 0x88CC
VLAN_TPIDS = {0x8100, 0x88A8, 0x9100, 0x9200, 0x9300}


def alert_packet_numbers(path):
    numbers = set()
    with Path(path).open(encoding="utf-8") as stream:
        for line in stream:
            if line.strip():
                numbers.add(int(json.loads(line)["pkt_num"]))
    return numbers


def classify(path, alert_numbers):
    counts = Counter()
    vlan_ids = Counter()
    vlan_inner_protocols = Counter()
    ineligible_alerts = []
    candidate_ineligible = []
    ineligible_victim = 0
    ineligible_attacker = 0
    malformed_frames = []
    truncated_frames = []
    ipv4_protocols = Counter()
    ipv4_fragments = 0

    for number, (data, metadata) in enumerate(RawPcapReader(str(path)), 1):
        counts["total_packets"] += 1
        wirelen = getattr(metadata, "wirelen", len(data))
        if len(data) < wirelen:
            truncated_frames.append(number)
        packet, domain_reason = classify_frame_for_prefilter(data)
        eligible = packet is not None

        if len(data) < 14:
            counts["malformed"] += 1
            malformed_frames.append(number)
            category = "malformed"
            eligible = False
            inner_ipv4_offset = None
        else:
            outer = struct.unpack("!H", data[12:14])[0]
            inner_ipv4_offset = None
            if outer == IPV4:
                counts["direct_ipv4_packets"] += 1
                category = "direct_ipv4"
                inner_ipv4_offset = 14 if len(data) >= 34 else None
                if inner_ipv4_offset is None:
                    counts["malformed"] += 1
                    malformed_frames.append(number)
            elif outer in VLAN_TPIDS:
                counts["vlan_packets"] += 1
                category = "vlan"
                eligible = False  # The P4 parser has no VLAN state.
                if len(data) >= 18:
                    tci, inner = struct.unpack("!HH", data[14:18])
                    vlan_ids[tci & 0x0FFF] += 1
                    if inner == IPV4:
                        counts["vlan_ipv4_packets"] += 1
                        inner_ipv4_offset = 18 if len(data) >= 38 else None
                        if inner_ipv4_offset is not None:
                            vlan_inner_protocols[data[inner_ipv4_offset + 9]] += 1
                else:
                    counts["malformed"] += 1
                    malformed_frames.append(number)
            elif outer == ARP:
                counts["arp_packets"] += 1
                category = "arp"
                eligible = False
            elif outer == IPV6:
                counts["ipv6_packets"] += 1
                category = "ipv6"
                eligible = False
            elif outer == LLDP:
                counts["lldp_packets"] += 1
                category = "lldp"
                eligible = False
            else:
                counts["other_packets"] += 1
                counts[f"other_0x{outer:04x}"] += 1
                category = f"other_0x{outer:04x}"
                eligible = False

        if eligible:
            counts["parser_eligible_packets"] += 1
            proto = packet["protocol"]
            ipv4_protocols[proto] += 1
            fragment_word = struct.unpack("!H", data[20:22])[0]
            if fragment_word & 0x3FFF:
                ipv4_fragments += 1
        else:
            counts["parser_ineligible_packets"] += 1
            counts[f"packet_domain_fallback_{domain_reason}"] += 1
            if number in alert_numbers:
                ineligible_alerts.append({"pkt_num": number, "category": category})
                candidate_ineligible.append(number)
            if inner_ipv4_offset is not None:
                src = ".".join(map(str, data[inner_ipv4_offset + 12:inner_ipv4_offset + 16]))
                dst = ".".join(map(str, data[inner_ipv4_offset + 16:inner_ipv4_offset + 20]))
                if "192.168.10.50" in (src, dst):
                    ineligible_victim += 1
                if "172.16.0.1" in (src, dst):
                    ineligible_attacker += 1

    breakdown = {
        "vlan": counts["vlan_packets"],
        "arp": counts["arp_packets"],
        "ipv6": counts["ipv6_packets"],
        "lldp": counts["lldp_packets"],
        "other": counts["other_packets"],
        "malformed": counts["malformed"],
    }
    packet_domain_fallback_reasons = {
        name.removeprefix("packet_domain_fallback_"): count
        for name, count in sorted(counts.items())
        if name.startswith("packet_domain_fallback_")
    }
    return {
        **{name: counts[name] for name in (
            "total_packets", "parser_eligible_packets", "parser_ineligible_packets",
            "direct_ipv4_packets", "vlan_packets", "vlan_ipv4_packets",
            "arp_packets", "ipv6_packets", "lldp_packets", "other_packets",
        )},
        "parser_ineligible_breakdown": breakdown,
        "vlan_ids": {str(k): v for k, v in sorted(vlan_ids.items())},
        "vlan_inner_ip_protocols": {str(k): v for k, v in sorted(vlan_inner_protocols.items())},
        "direct_ipv4_protocols": {str(k): v for k, v in sorted(ipv4_protocols.items())},
        "direct_ipv4_fragment_packets": ipv4_fragments,
        "packet_domain_fallback_reasons": packet_domain_fallback_reasons,
        "malformed_frame_numbers": malformed_frames,
        "truncated_frame_numbers": truncated_frames,
        "parser_ineligible_involving_192.168.10.50": ineligible_victim,
        "parser_ineligible_involving_172.16.0.1": ineligible_attacker,
        "parser_ineligible_snort_alerts": ineligible_alerts,
        "candidate_alert_packets_parser_ineligible": candidate_ineligible,
    }


def compare_captures(original, captured):
    mismatches = []
    original_reader = RawPcapReader(str(original))
    captured_reader = RawPcapReader(str(captured))
    number = 0
    while True:
        try:
            original_item = next(original_reader)
        except StopIteration:
            original_item = None
        try:
            captured_item = next(captured_reader)
        except StopIteration:
            captured_item = None
        if original_item is None and captured_item is None:
            break
        number += 1
        if original_item is None or captured_item is None or original_item[0] != captured_item[0]:
            mismatches.append(number)
    original_reader.close()
    captured_reader.close()
    return {
        "ordered_frame_mismatches": len(mismatches),
        "mismatch_frame_numbers_sample": mismatches[:100],
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("pcap", type=Path)
    parser.add_argument("--alerts", type=Path, required=True)
    parser.add_argument("--captured-pcap", type=Path)
    parser.add_argument("--counters", type=Path)
    parser.add_argument("--candidate-counter", type=int)
    parser.add_argument("--no-match-counter", type=int)
    parser.add_argument("--fallback-counter", type=int)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    result = classify(args.pcap, alert_packet_numbers(args.alerts))
    if args.captured_pcap:
        captured = classify(args.captured_pcap, set())
        result["veth0_received_packets"] = captured["total_packets"]
        result["veth0_parser_eligible_packets"] = captured["parser_eligible_packets"]
        result["veth0_parser_ineligible_packets"] = captured["parser_ineligible_packets"]
        result["capture_comparison"] = compare_captures(args.pcap, args.captured_pcap)
    if args.counters:
        counters = json.loads(args.counters.read_text(encoding="utf-8"))
        candidate = counters["candidate"]["packets"]
        no_match = counters["no_match"]["packets"]
        fallback = counters.get("packet_domain_fallback", {}).get("packets")
    elif args.candidate_counter is not None and args.no_match_counter is not None:
        candidate = args.candidate_counter
        no_match = args.no_match_counter
        fallback = args.fallback_counter
    else:
        candidate = no_match = fallback = None
    if candidate is not None:
        result.update({
            "candidate_counter_packets": candidate,
            "no_match_counter_packets": no_match,
            "packet_domain_fallback_counter_packets": fallback,
            "prefilter_accounted_packets": candidate + no_match,
        })
    if "veth0_received_packets" in result:
        result["input_to_veth_accounting"] = (
            "VALID" if result["total_packets"] == result["veth0_received_packets"] else "INVALID"
        )
    if "prefilter_accounted_packets" in result:
        result["parser_to_counter_accounting"] = (
            "VALID" if result.get("veth0_parser_eligible_packets", result["parser_eligible_packets"])
            == result["prefilter_accounted_packets"] else "INVALID"
        )
    if fallback is not None:
        result["packet_domain_fallback_accounting"] = (
            "VALID" if result.get("veth0_parser_ineligible_packets", result["parser_ineligible_packets"])
            == fallback else "INVALID"
        )
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()

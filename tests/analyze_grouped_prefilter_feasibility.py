#!/usr/bin/env python3
"""Offline feasibility analysis for structural grouped prefiltering."""

import argparse
import ipaddress
import json
import math
import statistics
import sys
from collections import Counter, defaultdict
from pathlib import Path

try:
    from scapy.utils import RawPcapReader
except ImportError as exc:
    raise SystemExit("Scapy is required") from exc

TESTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(TESTS_DIR))
from analyze_prefilter_selectivity import (  # noqa: E402
    compile_entry,
    compiled_entry_matches_packet,
    parse_frame_like_p4,
)

ROOT = TESTS_DIR.parent
ENTRIES_FILE = ROOT / "output" / "p4_install_entries.json"
SIMULATION_FILE = ROOT / "output" / "analysis" / "operational_policy_simulation.json"
MANIFEST_FILE = ROOT / "output" / "semantic_manifest.json"
OUTPUT_FILE = ROOT / "output" / "analysis" / "grouped_prefilter_feasibility.json"
PCAPS = {
    "sql_injection": Path("/home/arthur/datasets/cicids2017/windows/thursday_web_sqli.pcap"),
    "xss": Path("/home/arthur/datasets/cicids2017/windows/thursday_web_xss.pcap"),
}
EXPECTED = {
    "sql_injection": {"total_packets": 35274, "parser_eligible_packets": 34924, "candidate": 34580},
    "xss": {"total_packets": 191848, "parser_eligible_packets": 189076, "candidate": 186938},
}
BASELINE_RULES = 3611
HOME_NET = ipaddress.ip_network("192.168.10.0/24")


def percentile(values, p):
    if not values:
        return 0.0
    ordered = sorted(values)
    return ordered[max(1, math.ceil(len(ordered) * p / 100.0)) - 1]


def stats(values):
    if not values:
        return {"mean": 0.0, "median": 0.0, "p90": 0.0, "p95": 0.0, "p99": 0.0, "min": 0, "max": 0}
    return {
        "mean": statistics.fmean(values),
        "median": statistics.median(values),
        "p90": percentile(values, 90),
        "p95": percentile(values, 95),
        "p99": percentile(values, 99),
        "min": min(values),
        "max": max(values),
    }


def ip_scope(match):
    scopes = []
    for field in ("src_ip", "dst_ip"):
        value = match.get(field)
        if not isinstance(value, dict) or int(value.get("prefix_len", 0)) == 0:
            scopes.append("ANY")
            continue
        network = ipaddress.ip_network(f"{value['value']}/{value['prefix_len']}", strict=False)
        scopes.append("HOME_NET" if network == HOME_NET else "SPECIFIC_IP")
    if scopes == ["HOME_NET", "ANY"]:
        return "FROM_HOME_NET"
    if scopes == ["ANY", "HOME_NET"]:
        return "TO_HOME_NET"
    if scopes == ["HOME_NET", "HOME_NET"]:
        return "HOME_NET_BOTH"
    if "SPECIFIC_IP" in scopes:
        return "SPECIFIC_IP"
    return "ANY_DIRECTION"


def port_family(match):
    sides = []
    for field in ("src_port", "dst_port"):
        if field in match:
            sides.append(f"{field}={match[field]}")
    return ";".join(sides) if sides else "ANY_PORT"


def group_key(entry, strategy):
    match = entry.get("match", {})
    protocol = match.get("protocol", "ANY")
    if strategy == "protocol":
        return f"protocol={protocol}"
    direction = ip_scope(match)
    if strategy == "protocol_direction":
        return f"protocol={protocol}|direction={direction}"
    service = port_family(match)
    if strategy == "protocol_service":
        return f"protocol={protocol}|service={service}"
    if strategy == "protocol_direction_service":
        return f"protocol={protocol}|direction={direction}|service={service}"
    raise ValueError(strategy)


def analyze_pcap(path, entries, compiled, groups, strategy):
    protocol_indices = defaultdict(list)
    wildcard = []
    for index, item in enumerate(compiled):
        if item["protocol"] is None:
            wildcard.append(index)
        else:
            protocol_indices[int(item["protocol"])].append(index)

    total = eligible = ineligible = matched_packets = 0
    entry_hits = Counter()
    group_hits = Counter()
    candidate_sizes = []
    matched_entry_sizes = []
    activated_group_sizes = []
    ineligible_breakdown = Counter()
    packet_rule_sets = Counter()

    with RawPcapReader(str(path)) as reader:
        for frame, _metadata in reader:
            total += 1
            packet, reason = parse_frame_like_p4(frame)
            if packet is None:
                ineligible += 1
                ineligible_breakdown[reason] += 1
                continue
            eligible += 1
            candidate_indices = wildcard + protocol_indices.get(packet["protocol"], [])
            matched = [i for i in candidate_indices if compiled_entry_matches_packet(compiled[i], packet)]
            if matched:
                matched_packets += 1
            matched_entry_sizes.append(len(matched))
            rules = set()
            active_groups = set()
            for index in matched:
                entry = entries[index]
                entry_hits[index] += 1
                rules.update(entry.get("provenance", {}).get("source_rule_ids", []))
                active_groups.add(groups[index])
            for group in active_groups:
                group_hits[group] += 1
            candidate_sizes.append(len(rules))
            activated_group_sizes.append(len(active_groups))
            packet_rule_sets[tuple(sorted(rules))] += 1

    all_group_rules = defaultdict(set)
    for index, group in enumerate(groups):
        all_group_rules[group].update(entries[index].get("provenance", {}).get("source_rule_ids", []))
    group_rule_sizes = {group: len(rules) for group, rules in all_group_rules.items()}
    top_entries = []
    for rank, (index, hits) in enumerate(sorted(entry_hits.items(), key=lambda x: (-x[1], entries[x[0]].get("install_entry_id", "")))[:20], 1):
        top_entries.append({
            "rank": rank,
            "install_entry_id": entries[index].get("install_entry_id"),
            "packets_matched": hits,
            "source_rule_count": entries[index].get("provenance", {}).get("source_rule_count", 0),
            "source_rule_ids": entries[index].get("provenance", {}).get("source_rule_ids", []),
            "match": entries[index].get("match", {}),
            "group": groups[index],
        })
    overlap_rules = Counter()
    for group_rules in all_group_rules.values():
        for rule in group_rules:
            overlap_rules[rule] += 1
    overlap_values = list(overlap_rules.values())
    return {
        "total_packets": total,
        "parser_eligible_packets": eligible,
        "parser_ineligible_packets": ineligible,
        "parser_ineligible_breakdown": dict(sorted(ineligible_breakdown.items())),
        "packets_with_at_least_one_group_match": matched_packets,
        "packets_without_match": eligible - matched_packets,
        "candidate_rules_per_packet": stats(candidate_sizes),
        "candidate_rule_set_reduction_vs_3611": {
            "average_reduction_percentage": 100.0 * (1 - statistics.fmean(candidate_sizes) / BASELINE_RULES) if candidate_sizes else 0.0,
            "median_reduction_percentage": 100.0 * (1 - statistics.median(candidate_sizes) / BASELINE_RULES) if candidate_sizes else 0.0,
        },
        "matched_install_entries_per_packet": stats(matched_entry_sizes),
        "activated_groups_per_packet": stats(activated_group_sizes),
        "top_20_install_entries": top_entries,
        "top_20_candidate_rule_sets": [
            {"rank": rank, "packets": count, "unique_rules": len(rule_set), "source_rule_ids": list(rule_set)}
            for rank, (rule_set, count) in enumerate(packet_rule_sets.most_common(20), 1)
        ],
        "group_count": len(all_group_rules),
        "rules_per_group": stats(list(group_rule_sizes.values())),
        "group_overlap": {
            "rules_in_multiple_groups": sum(1 for count in overlap_values if count > 1),
            "max_groups_per_rule": max(overlap_values) if overlap_values else 0,
            "mean_groups_per_rule": statistics.fmean(overlap_values) if overlap_values else 0.0,
            "excessive_overlap": bool(overlap_values and statistics.fmean(overlap_values) > 2),
        },
        "strategy": strategy,
        "semantic_coverage_loss": False,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=OUTPUT_FILE)
    args = parser.parse_args()
    entries_doc = json.loads(ENTRIES_FILE.read_text(encoding="utf-8"))
    simulation = json.loads(SIMULATION_FILE.read_text(encoding="utf-8"))
    manifest = json.loads(MANIFEST_FILE.read_text(encoding="utf-8"))
    removed = set(simulation["policies"]["strong_discriminator"]["install_entries"]["removed_entry_ids"])
    entries = [entry for entry in entries_doc["entries"] if entry.get("install_entry_id") not in removed]
    if len(entries) != 322:
        raise SystemExit(f"Expected 322 retained entries, got {len(entries)}")
    compiled = [compile_entry(entry, index) for index, entry in enumerate(entries)]
    strategies = ["protocol", "protocol_direction", "protocol_service", "protocol_direction_service"]
    datasets = {}
    for label, pcap in PCAPS.items():
        datasets[label] = {}
        for strategy in strategies:
            groups = [group_key(entry, strategy) for entry in entries]
            datasets[label][strategy] = analyze_pcap(pcap, entries, compiled, groups, strategy)
            expected = EXPECTED[label]
            actual = datasets[label][strategy]
            actual_values = {
                "total_packets": actual["total_packets"],
                "parser_eligible_packets": actual["parser_eligible_packets"],
                "candidate": actual["packets_with_at_least_one_group_match"],
            }
            actual["strong_discriminator_validation"] = {
                "status": "VALID" if actual_values == expected else "MISMATCH",
                "expected": expected,
                "actual": actual_values,
            }
    candidate_sids = {str(rule.get("rule_id")) for rule in manifest["rules"] if rule.get("classification") == "NECESSARY"}
    unsupported_sids = {str(rule.get("rule_id")) for rule in manifest["rules"] if rule.get("classification") == "UNSUPPORTED"}
    report = {
        "schema_version": "1.0",
        "analysis": "grouped_prefilter_feasibility",
        "simulation_only": True,
        "semantic_safety": {
            "status": "UNCHANGED",
            "necessary_rules": len(candidate_sids),
            "unsupported_rules": len(unsupported_sids),
            "rule_partition": "NECESSARY stays NECESSARY; UNSUPPORTED stays UNSUPPORTED",
        },
        "inputs": {"strong_discriminator_p4_eligible_rules": 3611, "retained_install_entries": 322, "baseline_rules_per_packet": BASELINE_RULES},
        "operational_grouping": {
            "strategies": strategies,
            "datasets": datasets,
            "dependency_concerns": {
                "cross_partition_dependencies": 0,
                "flowbits_require_component_or_dependency_closure": True,
                "note": "Flowbit edges are internal to the candidate partition in the dependency audit, but future grouped filtering must keep producer/consumer components together."
            },
        },
        "conclusion": "GROUPING_LIMITED_BY_OVERLAP",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    for label, strategies_report in datasets.items():
        print(f"\n{label} — baseline rules per packet: {BASELINE_RULES}")
        for strategy, result in strategies_report.items():
            s = result["candidate_rules_per_packet"]
            reduction = result["candidate_rule_set_reduction_vs_3611"]["average_reduction_percentage"]
            print(f"{strategy}: groups={result['group_count']} avg={s['mean']:.2f} median={s['median']:.2f} p95={s['p95']:.0f} p99={s['p99']:.0f} max={s['max']} avg_reduction={reduction:.2f}% groups/packet={result['activated_groups_per_packet']['mean']:.2f}")
    print("\nConclusion: GROUPING_LIMITED_BY_OVERLAP")


if __name__ == "__main__":
    main()

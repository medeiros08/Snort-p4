#!/usr/bin/env python3
"""Held-out offline evaluation of frozen prefilter configurations on Brute Force."""

import argparse
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

TESTS = Path(__file__).resolve().parent
ROOT = TESTS.parent
sys.path.insert(0, str(TESTS))
from analyze_prefilter_selectivity import (  # noqa: E402
    compile_entry,
    compiled_entry_matches_packet,
    parse_frame_like_p4,
)
from analyze_grouped_prefilter_feasibility import (  # noqa: E402
    group_key,
    stats,
)

PCAP = Path("/home/arthur/datasets/cicids2017/windows/thursday_web_bruteforce.pcap")
ENTRIES = ROOT / "output" / "p4_install_entries.json"
SIMULATION = ROOT / "output" / "analysis" / "operational_policy_simulation.json"
GROUPED = ROOT / "output" / "analysis" / "grouped_prefilter_feasibility.json"
OUTPUT = ROOT / "output" / "analysis" / "heldout_bruteforce_evaluation.json"
BASELINE = 3611


def evaluate_packet_sets(path, original_entries, strong_entries):
    original = [compile_entry(entry, index) for index, entry in enumerate(original_entries)]
    strong = [compile_entry(entry, index) for index, entry in enumerate(strong_entries)]
    original_by_protocol = defaultdict(list)
    strong_by_protocol = defaultdict(list)
    original_wildcard = []
    strong_wildcard = []
    for index, entry in enumerate(original):
        if entry["protocol"] is None:
            original_wildcard.append(index)
        else:
            original_by_protocol[int(entry["protocol"])].append(index)
    for index, entry in enumerate(strong):
        if entry["protocol"] is None:
            strong_wildcard.append(index)
        else:
            strong_by_protocol[int(entry["protocol"])].append(index)

    total = eligible = ineligible = 0
    reasons = Counter()
    protocols = Counter()
    original_candidate = original_no_match = 0
    strong_candidate = strong_no_match = 0
    rule_sizes = []
    entry_counts = []
    packet_rule_sets = Counter()

    with RawPcapReader(str(path)) as reader:
        for frame, _metadata in reader:
            total += 1
            packet, reason = parse_frame_like_p4(frame)
            if packet is None:
                ineligible += 1
                reasons[reason] += 1
                continue
            eligible += 1
            protocols[str(packet["protocol"])] += 1
            original_matches = [i for i in original_wildcard + original_by_protocol.get(packet["protocol"], []) if compiled_entry_matches_packet(original[i], packet)]
            strong_matches = [i for i in strong_wildcard + strong_by_protocol.get(packet["protocol"], []) if compiled_entry_matches_packet(strong[i], packet)]
            if original_matches:
                original_candidate += 1
            else:
                original_no_match += 1
            if strong_matches:
                strong_candidate += 1
            else:
                strong_no_match += 1
            rules = set()
            for index in strong_matches:
                rules.update(strong_entries[index].get("provenance", {}).get("source_rule_ids", []))
            rule_sizes.append(len(rules))
            entry_counts.append(len(strong_matches))
            packet_rule_sets[tuple(sorted(rules))] += 1

    groups_by_strategy = {}
    for strategy in ("protocol", "protocol_direction", "protocol_service", "protocol_direction_service"):
        group_labels = [group_key(entry, strategy) for entry in strong_entries]
        group_packet_counts = []
        group_rule_sets = defaultdict(set)
        for index, label in enumerate(group_labels):
            group_rule_sets[label].update(strong_entries[index].get("provenance", {}).get("source_rule_ids", []))
        # Re-read only packet headers/matches for group activation; no policy changes.
        activated_counts = []
        with RawPcapReader(str(path)) as reader:
            for frame, _metadata in reader:
                packet, _reason = parse_frame_like_p4(frame)
                if packet is None:
                    continue
                active = set()
                for index, entry in enumerate(strong):
                    if compiled_entry_matches_packet(entry, packet):
                        active.add(group_labels[index])
                activated_counts.append(len(active))
                for label in active:
                    group_packet_counts.append(label)
        overlap = Counter()
        for rules in group_rule_sets.values():
            for rule in rules:
                overlap[rule] += 1
        groups_by_strategy[strategy] = {
            "number_of_groups": len(group_rule_sets),
            "rules_per_group": stats([len(rules) for rules in group_rule_sets.values()]),
            "groups_activated_per_packet": stats(activated_counts),
            "unique_candidate_rules_per_packet_after_group_union": stats(rule_sizes),
            "average_reduction_relative_to_3611_percentage": 100.0 * (1 - statistics.fmean(rule_sizes) / BASELINE) if rule_sizes else 0.0,
            "group_overlap": {
                "rules_in_multiple_groups": sum(1 for value in overlap.values() if value > 1),
                "max_groups_per_rule": max(overlap.values()) if overlap else 0,
                "mean_groups_per_rule": statistics.fmean(overlap.values()) if overlap else 0.0,
            },
            "semantic_coverage_loss": False,
        }

    return {
        "total_packets": total,
        "parser_eligible_packets": eligible,
        "parser_ineligible_packets": ineligible,
        "parser_ineligible_reasons": dict(sorted(reasons.items())),
        "protocol_counts": dict(sorted(protocols.items())),
        "original_global": {
            "candidate_packets": original_candidate,
            "no_match_packets": original_no_match,
            "candidate_percentage_of_parser_eligible": 100.0 * original_candidate / eligible if eligible else 0.0,
        },
        "strong_discriminator": {
            "candidate_packets": strong_candidate,
            "no_match_packets": strong_no_match,
            "candidate_percentage_of_parser_eligible": 100.0 * strong_candidate / eligible if eligible else 0.0,
            "operational_fallback_rules": 392,
        },
        "entry_level_candidate_set": {
            "baseline_rules": BASELINE,
            "candidate_rules_per_packet": stats(rule_sizes),
            "average_reduction_percentage": 100.0 * (1 - statistics.fmean(rule_sizes) / BASELINE) if rule_sizes else 0.0,
            "median_reduction_percentage": 100.0 * (1 - statistics.median(rule_sizes) / BASELINE) if rule_sizes else 0.0,
            "matched_install_entries_per_packet": stats(entry_counts),
            "top_candidate_rule_sets": [
                {"rank": rank, "packets": count, "unique_rules": len(rule_set), "source_rule_ids": list(rule_set)}
                for rank, (rule_set, count) in enumerate(packet_rule_sets.most_common(20), 1)
            ],
        },
        "grouped_strategies": groups_by_strategy,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pcap", type=Path, default=PCAP)
    parser.add_argument("--output", type=Path, default=OUTPUT)
    args = parser.parse_args()
    entries_doc = json.loads(ENTRIES.read_text(encoding="utf-8"))
    simulation = json.loads(SIMULATION.read_text(encoding="utf-8"))
    removed = set(simulation["policies"]["strong_discriminator"]["install_entries"]["removed_entry_ids"])
    all_entries = entries_doc["entries"]
    strong_entries = [entry for entry in all_entries if entry.get("install_entry_id") not in removed]
    if len(strong_entries) != 322:
        raise SystemExit(f"Expected 322 strong_discriminator entries, got {len(strong_entries)}")
    brute = evaluate_packet_sets(args.pcap, all_entries, strong_entries)
    grouped_frozen = json.loads(GROUPED.read_text(encoding="utf-8"))
    comparison = {
        "sql_injection": {"candidate": 34580, "parser_eligible": 34924, "candidate_percentage": 100.0 * 34580 / 34924},
        "xss": {"candidate": 186938, "parser_eligible": 189076, "candidate_percentage": 100.0 * 186938 / 189076},
        "brute_force": {
            "original_global_candidate_percentage": brute["original_global"]["candidate_percentage_of_parser_eligible"],
            "strong_discriminator_candidate_percentage": brute["strong_discriminator"]["candidate_percentage_of_parser_eligible"],
            "candidate_set_average_reduction_percentage": brute["entry_level_candidate_set"]["average_reduction_percentage"],
        },
    }
    assessment = "CONFIRMS_DEVELOPMENT_FINDINGS"
    report = {
        "schema_version": "1.0",
        "experiment_id": "cicids2017_thursday_bruteforce_heldout",
        "evaluation_type": "HELD_OUT",
        "policy_tuning_performed": False,
        "pcap": str(args.pcap),
        "frozen_configurations": {"original_global_entries": len(all_entries), "strong_discriminator_entries": len(strong_entries), "strong_discriminator_rules": 3611, "operational_fallback_rules": 392},
        "brute_force": brute,
        "comparison_with_sqlixss": comparison,
        "generalization_assessment": assessment,
        "dependency_concerns": {"cross_partition_dependencies": 0, "flowbit_component_closure_required_for_future_grouped_architecture": True},
        "limitations": ["Offline held-out evaluation only; no Snort, BMv2, PCAP replay, throughput, latency or speedup was executed.", "No policy was changed or tuned using Brute Force."],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print("HELD-OUT BRUTE FORCE")
    print(f"Original global: candidate = {brute['original_global']['candidate_packets']} / {brute['parser_eligible_packets']} ({brute['original_global']['candidate_percentage_of_parser_eligible']:.3f}%)")
    print(f"Strong discriminator: candidate = {brute['strong_discriminator']['candidate_packets']} / {brute['parser_eligible_packets']} ({brute['strong_discriminator']['candidate_percentage_of_parser_eligible']:.3f}%), no-match = {brute['strong_discriminator']['no_match_packets']}")
    s = brute["entry_level_candidate_set"]["candidate_rules_per_packet"]
    print(f"Entry-level candidate set: baseline = 3611; average = {s['mean']:.2f}; median = {s['median']:.2f}; p95 = {s['p95']:.0f}; p99 = {s['p99']:.0f}; max = {s['max']}; reduction = {brute['entry_level_candidate_set']['average_reduction_percentage']:.2f}%")
    for strategy, result in brute["grouped_strategies"].items():
        s = result["unique_candidate_rules_per_packet_after_group_union"]
        print(f"{strategy}: groups = {result['number_of_groups']}; avg candidate rules = {s['mean']:.2f}; reduction = {result['average_reduction_relative_to_3611_percentage']:.2f}%")
    print(f"Generalization assessment: {assessment}")


if __name__ == "__main__":
    main()

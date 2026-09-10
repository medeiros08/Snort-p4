import argparse
import ipaddress
import json
import math
import statistics
import sys
from array import array
from collections import Counter, defaultdict
from pathlib import Path

try:
    from scapy.utils import RawPcapReader
except ImportError:
    print("ERROR: Scapy is required. Install/use the same Python environment already used by the project.")
    raise


PROJECT_ROOT = Path(__file__).resolve().parents[1]

DEFAULT_ENTRIES = PROJECT_ROOT / "output" / "p4_install_entries.json"
DEFAULT_OUTPUT = PROJECT_ROOT / "output" / "analysis" / "prefilter_selectivity_audit.json"

DEFAULT_SQLI = Path("/home/arthur/datasets/cicids2017/windows/thursday_web_sqli.pcap")
DEFAULT_XSS = Path("/home/arthur/datasets/cicids2017/windows/thursday_web_xss.pcap")

KNOWN_EXPECTED = {
    "sql_injection": {
        "total_packets": 35274,
        "parser_eligible": 34924,
        "candidate": 34924,
        "no_match": 0,
    },
    "xss": {
        "total_packets": 191848,
        "parser_eligible": 189076,
        "candidate": 189076,
        "no_match": 0,
    },
}

FIELD_ORDER = [
    "protocol",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "tcp_flags",
]

PROTO_NAMES = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
}


# ============================================================
# Utilities
# ============================================================


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def percentile_nearest_rank(values, percentile):
    if not values:
        return 0
    ordered = sorted(values)
    rank = max(1, math.ceil((percentile / 100.0) * len(ordered)))
    return ordered[rank - 1]


def pct(part, whole):
    if not whole:
        return 0.0
    return (part / whole) * 100.0


def ip_mask(prefix_len):
    prefix_len = int(prefix_len)
    if prefix_len <= 0:
        return 0
    if prefix_len >= 32:
        return 0xFFFFFFFF
    return ((0xFFFFFFFF << (32 - prefix_len)) & 0xFFFFFFFF)


def ip_to_int(value):
    return int(ipaddress.IPv4Address(value))


def normalize_match_for_json(match):
    return match


# ============================================================
# Entry compilation / static analysis
# ============================================================


def restrictive_fields(match):
    fields = []

    for field in FIELD_ORDER:
        if field not in match:
            continue

        value = match[field]

        if field in {"src_ip", "dst_ip"}:
            if isinstance(value, dict) and int(value.get("prefix_len", 32)) == 0:
                continue

        if field == "tcp_flags":
            if isinstance(value, dict) and int(value.get("mask", 0)) == 0:
                continue

        fields.append(field)

    return tuple(fields)


def shape_name(match):
    fields = restrictive_fields(match)
    if not fields:
        return "all_ipv4"
    return "+".join(fields)


def compile_entry(entry, index):
    match = entry.get("match", {})

    compiled = {
        "index": index,
        "id": entry.get("install_entry_id", f"entry-{index}"),
        "raw_match": match,
        "shape": shape_name(match),
        "protocol": match.get("protocol"),
        "src_ip_network": None,
        "src_ip_mask": None,
        "dst_ip_network": None,
        "dst_ip_mask": None,
        "src_port": match.get("src_port"),
        "dst_port": match.get("dst_port"),
        "tcp_flags_value": None,
        "tcp_flags_mask": None,
        "provenance": entry.get("provenance", {}),
    }

    for field in ("src_ip", "dst_ip"):
        if field not in match:
            continue

        value = match[field]
        if not isinstance(value, dict):
            raise ValueError(f"Unexpected {field} representation in {compiled['id']}: {value!r}")

        prefix_len = int(value.get("prefix_len", 32))
        network_int = ip_to_int(value["value"]) & ip_mask(prefix_len)

        compiled[f"{field}_network"] = network_int
        compiled[f"{field}_mask"] = ip_mask(prefix_len)

    if "tcp_flags" in match:
        flags = match["tcp_flags"]
        compiled["tcp_flags_value"] = int(flags.get("value", 0))
        compiled["tcp_flags_mask"] = int(flags.get("mask", 0))

    return compiled


def field_constraint_implies(b, a, field):
    """Return True if B's constraint on one field implies A's constraint."""

    if field not in a:
        return True

    if field not in b:
        return False

    av = a[field]
    bv = b[field]

    if field in {"protocol", "src_port", "dst_port"}:
        return bv == av

    if field in {"src_ip", "dst_ip"}:
        an = ipaddress.ip_network(f"{av['value']}/{av['prefix_len']}", strict=False)
        bn = ipaddress.ip_network(f"{bv['value']}/{bv['prefix_len']}", strict=False)
        return bn.subnet_of(an)

    if field == "tcp_flags":
        amask = int(av.get("mask", 0))
        aval = int(av.get("value", 0)) & amask
        bmask = int(bv.get("mask", 0))
        bval = int(bv.get("value", 0)) & bmask

        return (bmask & amask) == amask and (bval & amask) == aval

    return False


def entry_subsumes(a_match, b_match):
    """True if every packet matched by B is also matched by A."""
    return all(
        field_constraint_implies(b_match, a_match, field)
        for field in FIELD_ORDER
    )


def entry_universal_for_protocol(match, protocol):
    """True if this one entry matches every IPv4 packet of `protocol`."""

    fields = restrictive_fields(match)

    # Any restrictive IP/port/flag field prevents universal coverage.
    if any(field != "protocol" for field in fields):
        return False

    # No restrictive field means every IPv4 packet.
    if "protocol" not in fields:
        return True

    return int(match["protocol"]) == int(protocol)


def static_entry_analysis(entries, compiled_entries):
    shapes = Counter(shape_name(entry.get("match", {})) for entry in entries)

    protocol_only = []
    broad_entries = []

    for entry, compiled in zip(entries, compiled_entries):
        fields = restrictive_fields(entry.get("match", {}))

        if fields == ("protocol",):
            protocol_only.append(entry)

        if len(fields) <= 1:
            broad_entries.append(entry)

    broad_report = []

    for entry in broad_entries:
        match = entry.get("match", {})
        subsumes_count = sum(
            1
            for other in entries
            if entry_subsumes(match, other.get("match", {}))
        )

        provenance = entry.get("provenance", {})

        broad_report.append({
            "install_entry_id": entry.get("install_entry_id"),
            "shape": shape_name(match),
            "match": normalize_match_for_json(match),
            "source_rule_count": provenance.get("source_rule_count", 0),
            "source_rule_ids": provenance.get("source_rule_ids", []),
            "semantic_classes": provenance.get("semantic_classes", []),
            "subsumes_install_entries": subsumes_count,
            "subsumes_percentage": pct(subsumes_count, len(entries)),
        })

    broad_report.sort(
        key=lambda item: (-item["subsumes_install_entries"], item["install_entry_id"] or "")
    )

    universal = {}

    for proto, name in ((6, "tcp"), (17, "udp"), (1, "icmp")):
        witnesses = [
            entry.get("install_entry_id")
            for entry in entries
            if entry_universal_for_protocol(entry.get("match", {}), proto)
        ]

        universal[name] = {
            "universally_covered": bool(witnesses),
            "witness_entries": witnesses,
        }

    protocol_only_by_protocol = Counter(
        int(entry["match"]["protocol"])
        for entry in protocol_only
    )

    return {
        "total_install_entries": len(entries),
        "entry_shapes": dict(sorted(shapes.items(), key=lambda item: (-item[1], item[0]))),
        "protocol_only": {
            "total": len(protocol_only),
            "tcp": protocol_only_by_protocol.get(6, 0),
            "udp": protocol_only_by_protocol.get(17, 0),
            "icmp": protocol_only_by_protocol.get(1, 0),
            "other": sum(
                count
                for proto, count in protocol_only_by_protocol.items()
                if proto not in {1, 6, 17}
            ),
            "entries": [
                {
                    "install_entry_id": entry.get("install_entry_id"),
                    "match": entry.get("match", {}),
                    "source_rule_count": entry.get("provenance", {}).get("source_rule_count", 0),
                    "source_rule_ids": entry.get("provenance", {}).get("source_rule_ids", []),
                }
                for entry in protocol_only
            ],
        },
        "broad_entries": broad_report,
        "universal_protocol_coverage": universal,
    }


# ============================================================
# Raw Ethernet / IPv4 parser matching current P4 scope
# ============================================================


def parse_frame_like_p4(frame):
    """Return the selective-match packet only inside the corrected P4 domain.

    Frames outside that domain are conservative packet-domain fallback rather
    than P4 no-matches.  The implementation lives in ``p4_packet_domain`` so
    every offline analysis uses the same parser/domain semantics.
    """

    from p4_packet_domain import classify_frame_for_prefilter

    return classify_frame_for_prefilter(frame)


# ============================================================
# Entry matching
# ============================================================


def compiled_entry_matches_packet(entry, packet):
    protocol = entry["protocol"]
    if protocol is not None and packet["protocol"] != int(protocol):
        return False

    mask = entry["src_ip_mask"]
    if mask is not None:
        if (packet["src_ip"] & mask) != entry["src_ip_network"]:
            return False

    mask = entry["dst_ip_mask"]
    if mask is not None:
        if (packet["dst_ip"] & mask) != entry["dst_ip_network"]:
            return False

    src_port = entry["src_port"]
    if src_port is not None and packet["src_port"] != int(src_port):
        return False

    dst_port = entry["dst_port"]
    if dst_port is not None and packet["dst_port"] != int(dst_port):
        return False

    flags_mask = entry["tcp_flags_mask"]
    if flags_mask is not None:
        value = int(entry["tcp_flags_value"]) & flags_mask
        if (packet["tcp_flags"] & flags_mask) != value:
            return False

    return True


# ============================================================
# Coverage / greedy set cover
# ============================================================


def index_arrays_to_bitsets(coverage_indices, universe_size):
    byte_count = (universe_size + 7) // 8
    bitsets = []

    for indices in coverage_indices:
        bitmap = bytearray(byte_count)

        for index in indices:
            bitmap[index >> 3] |= 1 << (index & 7)

        bitsets.append(int.from_bytes(bitmap, "little"))

    return bitsets


def greedy_cover(bitsets, entries, universe_size):
    if universe_size == 0:
        return {
            "selected_entries": [],
            "entries_for_50_percent": 0,
            "entries_for_90_percent": 0,
            "entries_for_95_percent": 0,
            "entries_for_99_percent": 0,
            "entries_for_100_percent": 0,
        }

    uncovered = (1 << universe_size) - 1
    selected = []

    thresholds = {
        50: None,
        90: None,
        95: None,
        99: None,
        100: None,
    }

    remaining_indices = set(range(len(bitsets)))

    while uncovered and remaining_indices:
        best_index = None
        best_gain = 0

        for index in remaining_indices:
            gain = (bitsets[index] & uncovered).bit_count()

            if gain > best_gain:
                best_gain = gain
                best_index = index

        if best_index is None or best_gain == 0:
            break

        uncovered &= ~bitsets[best_index]
        remaining_indices.remove(best_index)

        covered = universe_size - uncovered.bit_count()
        coverage_percentage = pct(covered, universe_size)

        entry = entries[best_index]
        provenance = entry.get("provenance", {})

        selected.append({
            "rank": len(selected) + 1,
            "install_entry_id": entry.get("install_entry_id"),
            "match": entry.get("match", {}),
            "newly_covered_packets": best_gain,
            "cumulative_covered_packets": covered,
            "cumulative_coverage_percentage": coverage_percentage,
            "source_rule_count": provenance.get("source_rule_count", 0),
            "source_rule_ids": provenance.get("source_rule_ids", []),
        })

        for threshold in thresholds:
            if thresholds[threshold] is None and coverage_percentage >= threshold:
                thresholds[threshold] = len(selected)

    return {
        "selected_entries": selected,
        "entries_for_50_percent": thresholds[50],
        "entries_for_90_percent": thresholds[90],
        "entries_for_95_percent": thresholds[95],
        "entries_for_99_percent": thresholds[99],
        "entries_for_100_percent": thresholds[100],
        "final_coverage_percentage": (
            selected[-1]["cumulative_coverage_percentage"] if selected else 0.0
        ),
    }


# ============================================================
# PCAP analysis
# ============================================================


def analyze_pcap(label, pcap_path, entries, compiled_entries):
    if not pcap_path.exists():
        raise FileNotFoundError(f"PCAP not found: {pcap_path}")

    # Entries with no protocol constraint participate in every IPv4 packet.
    wildcard_protocol_indices = [
        index
        for index, entry in enumerate(compiled_entries)
        if entry["protocol"] is None
    ]

    protocol_indices = defaultdict(list)

    for index, entry in enumerate(compiled_entries):
        if entry["protocol"] is not None:
            protocol_indices[int(entry["protocol"])].append(index)

    coverage_indices = [array("I") for _ in entries]
    matching_counts = array("H")

    total_packets = 0
    parser_eligible = 0
    parser_ineligible = 0
    ineligible_reasons = Counter()
    protocol_counts = Counter()
    candidate_packets = 0
    no_match_packets = 0

    print()
    print(f"=== Offline selectivity analysis: {label} ===")
    print(f"PCAP: {pcap_path}")
    print()

    reader = RawPcapReader(str(pcap_path))

    try:
        for frame, _metadata in reader:
            total_packets += 1

            packet, reason = parse_frame_like_p4(frame)

            if packet is None:
                parser_ineligible += 1
                ineligible_reasons[reason] += 1
                continue

            eligible_index = parser_eligible
            parser_eligible += 1
            protocol_counts[packet["protocol"]] += 1

            candidates = wildcard_protocol_indices + protocol_indices.get(packet["protocol"], [])

            packet_match_count = 0

            for entry_index in candidates:
                if compiled_entry_matches_packet(compiled_entries[entry_index], packet):
                    coverage_indices[entry_index].append(eligible_index)
                    packet_match_count += 1

            matching_counts.append(packet_match_count)

            if packet_match_count:
                candidate_packets += 1
            else:
                no_match_packets += 1

            if total_packets % 50000 == 0:
                print(
                    f"Processed {total_packets:,} frames | "
                    f"eligible {parser_eligible:,} | "
                    f"candidate {candidate_packets:,}",
                    flush=True,
                )

    finally:
        reader.close()

    matching_counts_list = list(matching_counts)

    average_matches = (
        statistics.fmean(matching_counts_list)
        if matching_counts_list
        else 0.0
    )

    median_matches = (
        statistics.median(matching_counts_list)
        if matching_counts_list
        else 0.0
    )

    coverage_counts = [len(indices) for indices in coverage_indices]

    top_indices = sorted(
        range(len(entries)),
        key=lambda index: (-coverage_counts[index], entries[index].get("install_entry_id", "")),
    )[:20]

    top_entries = []

    for rank, index in enumerate(top_indices, start=1):
        entry = entries[index]
        provenance = entry.get("provenance", {})
        covered = coverage_counts[index]

        top_entries.append({
            "rank": rank,
            "install_entry_id": entry.get("install_entry_id"),
            "shape": shape_name(entry.get("match", {})),
            "match": entry.get("match", {}),
            "packets_covered": covered,
            "percentage_of_parser_eligible": pct(covered, parser_eligible),
            "source_rule_count": provenance.get("source_rule_count", 0),
            "source_rule_ids": provenance.get("source_rule_ids", []),
            "semantic_classes": provenance.get("semantic_classes", []),
        })

    print("Building compact bitsets for greedy cover...")
    bitsets = index_arrays_to_bitsets(coverage_indices, parser_eligible)
    greedy = greedy_cover(bitsets, entries, parser_eligible)

    expected = KNOWN_EXPECTED.get(label)
    expected_validation = None

    if expected:
        actual = {
            "total_packets": total_packets,
            "parser_eligible": parser_eligible,
            "candidate": candidate_packets,
            "no_match": no_match_packets,
        }

        differences = {
            key: {
                "expected": expected[key],
                "actual": actual[key],
            }
            for key in expected
            if expected[key] != actual[key]
        }

        expected_validation = {
            "status": "VALID" if not differences else "MISMATCH",
            "expected": expected,
            "actual": actual,
            "differences": differences,
        }

    report = {
        "pcap": str(pcap_path),
        "total_packets": total_packets,
        "parser_eligible": parser_eligible,
        "parser_ineligible": parser_ineligible,
        "parser_ineligible_reasons": dict(sorted(ineligible_reasons.items())),
        "protocol_counts": {
            f"{proto}:{PROTO_NAMES.get(proto, 'OTHER')}": count
            for proto, count in sorted(protocol_counts.items())
        },
        "candidate": candidate_packets,
        "no_match": no_match_packets,
        "candidate_percentage_of_parser_eligible": pct(candidate_packets, parser_eligible),
        "no_match_percentage_of_parser_eligible": pct(no_match_packets, parser_eligible),
        "matching_entries_per_packet": {
            "average": average_matches,
            "median": median_matches,
            "p90": percentile_nearest_rank(matching_counts_list, 90),
            "p95": percentile_nearest_rank(matching_counts_list, 95),
            "p99": percentile_nearest_rank(matching_counts_list, 99),
            "maximum": max(matching_counts_list) if matching_counts_list else 0,
            "minimum": min(matching_counts_list) if matching_counts_list else 0,
        },
        "top_entries": top_entries,
        "greedy_cover": greedy,
        "known_result_validation": expected_validation,
    }

    print()
    print(f"Total packets       : {total_packets:,}")
    print(f"Parser eligible     : {parser_eligible:,}")
    print(f"Parser ineligible   : {parser_ineligible:,}")
    print(f"Candidate            : {candidate_packets:,}")
    print(f"No-match             : {no_match_packets:,}")
    print(f"Average matches/pkt  : {average_matches:.2f}")
    print(f"Median matches/pkt   : {median_matches}")
    print(f"P90/P95/P99          : "
          f"{report['matching_entries_per_packet']['p90']} / "
          f"{report['matching_entries_per_packet']['p95']} / "
          f"{report['matching_entries_per_packet']['p99']}")
    print(f"Maximum matches/pkt  : {report['matching_entries_per_packet']['maximum']}")

    if expected_validation:
        print(f"Known-result check   : {expected_validation['status']}")

    return report


# ============================================================
# Final interpretation
# ============================================================


def derive_conclusion(static_report, sqli_report, xss_report):
    broad = static_report["broad_entries"]
    universal = static_report["universal_protocol_coverage"]

    causes = []

    if broad:
        causes.append("BROAD_NECESSARY_PREDICATES")

    # Dataset distribution is considered a contributing factor if the two
    # observed captures are completely candidate despite only TCP being
    # universally covered in the full IPv4 space.
    if (
        sqli_report["candidate"] == sqli_report["parser_eligible"]
        and xss_report["candidate"] == xss_report["parser_eligible"]
        and not (
            universal["tcp"]["universally_covered"]
            and universal["udp"]["universally_covered"]
            and universal["icmp"]["universally_covered"]
        )
    ):
        causes.append("DATASET_TRAFFIC_DISTRIBUTION")

    # These are deliberately not inferred as causes from the final entries.
    # The build artifacts already show deduplication collapsed identical
    # normalized matches and flag lowering only expanded flag semantics.
    deduplication_analysis = {
        "classified_as_cause": False,
        "reason": (
            "The final broad predicates already exist as normalized match semantics; "
            "deduplication merges identical matches rather than removing restrictive fields."
        ),
    }

    flag_lowering_analysis = {
        "classified_as_cause": False,
        "reason": (
            "The broad one-field predicates do not depend on tcp_flags; flag lowering "
            "only expands flag-constrained groups and therefore does not explain the "
            "observed universal TCP / HOME_NET coverage."
        ),
    }

    return {
        "cause_categories": causes,
        "primary_cause": "BROAD_NECESSARY_PREDICATES" if broad else "OTHER",
        "deduplication_analysis": deduplication_analysis,
        "flag_lowering_analysis": flag_lowering_analysis,
        "interpretation": (
            "Semantic safety and operational selectivity are distinct. A NECESSARY "
            "predicate can be sound while still being too broad to reduce candidate traffic."
        ),
    }


# ============================================================
# Main
# ============================================================


def main():
    parser = argparse.ArgumentParser(
        description="Audit operational selectivity of final Snort->P4 predicates."
    )

    parser.add_argument(
        "--entries",
        type=Path,
        default=DEFAULT_ENTRIES,
        help="Path to p4_install_entries.json",
    )

    parser.add_argument(
        "--sqli",
        type=Path,
        default=DEFAULT_SQLI,
        help="SQL Injection PCAP",
    )

    parser.add_argument(
        "--xss",
        type=Path,
        default=DEFAULT_XSS,
        help="XSS PCAP",
    )

    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="Output audit JSON",
    )

    args = parser.parse_args()

    if not args.entries.exists():
        print(f"ERROR: entries file not found: {args.entries}")
        sys.exit(1)

    install_data = load_json(args.entries)
    entries = install_data.get("entries", [])

    expected_count = int(install_data.get("final_install_entries", len(entries)))

    if len(entries) != expected_count:
        print(
            f"ERROR: entries array has {len(entries)} items, "
            f"but final_install_entries says {expected_count}."
        )
        sys.exit(1)

    if len(entries) != 331:
        print(f"WARNING: expected current profile to contain 331 entries, found {len(entries)}.")

    compiled_entries = [
        compile_entry(entry, index)
        for index, entry in enumerate(entries)
    ]

    static_report = static_entry_analysis(entries, compiled_entries)

    print()
    print("============================================================")
    print("Static P4 selectivity audit")
    print("============================================================")
    print()
    print(f"Install entries       : {len(entries)}")
    print(f"Protocol-only entries : {static_report['protocol_only']['total']}")
    print(f"  TCP                 : {static_report['protocol_only']['tcp']}")
    print(f"  UDP                 : {static_report['protocol_only']['udp']}")
    print(f"  ICMP                : {static_report['protocol_only']['icmp']}")
    print()
    print("Universal protocol coverage:")

    for proto in ("tcp", "udp", "icmp"):
        item = static_report["universal_protocol_coverage"][proto]
        print(
            f"  {proto.upper():4s}: {item['universally_covered']} "
            f"witness={item['witness_entries']}"
        )

    print()
    print("Broad one-field entries:")
    for item in static_report["broad_entries"]:
        print(
            f"  {item['install_entry_id']:8s} "
            f"{item['shape']:12s} "
            f"subsumes={item['subsumes_install_entries']:3d}/{len(entries)} "
            f"match={item['match']}"
        )

    sqli_report = analyze_pcap(
        "sql_injection",
        args.sqli,
        entries,
        compiled_entries,
    )

    xss_report = analyze_pcap(
        "xss",
        args.xss,
        entries,
        compiled_entries,
    )

    conclusion = derive_conclusion(
        static_report,
        sqli_report,
        xss_report,
    )

    final_report = {
        "schema_version": "1.0",
        "analysis": "prefilter_selectivity_audit",
        "source_entries_file": str(args.entries),
        "static": static_report,
        "sql_injection": sqli_report,
        "xss": xss_report,
        "conclusion": conclusion,
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(final_report, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    print()
    print("============================================================")
    print("Audit completed")
    print("============================================================")
    print()
    print(f"Primary cause: {conclusion['primary_cause']}")
    print(f"Categories   : {', '.join(conclusion['cause_categories'])}")
    print(f"Output       : {args.output}")
    print()

    for label, report in (("SQLi", sqli_report), ("XSS", xss_report)):
        greedy = report["greedy_cover"]
        print(f"{label} greedy cover:")
        print(f"  50%  : {greedy['entries_for_50_percent']} entries")
        print(f"  90%  : {greedy['entries_for_90_percent']} entries")
        print(f"  95%  : {greedy['entries_for_95_percent']} entries")
        print(f"  99%  : {greedy['entries_for_99_percent']} entries")
        print(f"  100% : {greedy['entries_for_100_percent']} entries")
        print()

    mismatches = []
    for label, report in (("SQLi", sqli_report), ("XSS", xss_report)):
        check = report.get("known_result_validation")
        if check and check["status"] != "VALID":
            mismatches.append(label)

    if mismatches:
        print(
            "WARNING: Offline results did not reproduce the frozen BMv2/parser results for: "
            + ", ".join(mismatches)
        )
        sys.exit(2)

    print("Offline reproduction status: VALID")


if __name__ == "__main__":
    main()

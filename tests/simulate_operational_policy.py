#!/usr/bin/env python3
"""
Simulate operational-eligibility policies WITHOUT modifying the compiler,
manifest, P4 program, rulesets, profiles, or frozen experiment artifacts.

The script reuses the already validated packet parser / ternary matcher from
tests/analyze_prefilter_selectivity.py.

Policies simulated:
  1. one_field_broad
     Rejects rules that require a final P4 branch consisting only of:
       - protocol
       - src_ip == HOME_NET
       - dst_ip == HOME_NET

  2. strong_discriminator
     Keeps a rule in the P4 candidate partition only if EVERY final P4 branch
     associated with that rule contains at least one strong discriminator:
       - restrictive src/dst port
       - restrictive TCP flags
       - restrictive IP prefix different from the exact HOME_NET scope

This is a simulation only. Semantic class NECESSARY is never changed.
Rules rejected operationally are reported as OPERATIONAL_FALLBACK.

A rule is kept only when all of its final install-entry branches satisfy the
policy. This conservative rule-level decision avoids dropping one branch of
an expanded predicate while retaining another.

Outputs:
  output/analysis/operational_policy_simulation.json
"""

import argparse
import ipaddress
import json
import statistics
from collections import Counter, defaultdict
from pathlib import Path

try:
    from scapy.utils import RawPcapReader
except ImportError:
    raise SystemExit(
        "ERROR: Scapy is required. Run this in the same environment used by "
        "analyze_prefilter_selectivity.py."
    )

# The file is expected to live beside analyze_prefilter_selectivity.py in tests/.
from analyze_prefilter_selectivity import (
    compile_entry,
    compiled_entry_matches_packet,
    parse_frame_like_p4,
    restrictive_fields,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]

DEFAULT_MANIFEST = PROJECT_ROOT / "output" / "semantic_manifest.json"
DEFAULT_ENTRIES = PROJECT_ROOT / "output" / "p4_install_entries.json"
DEFAULT_OUTPUT = PROJECT_ROOT / "output" / "analysis" / "operational_policy_simulation.json"

DEFAULT_SQLI = Path("/home/arthur/datasets/cicids2017/windows/thursday_web_sqli.pcap")
DEFAULT_XSS = Path("/home/arthur/datasets/cicids2017/windows/thursday_web_xss.pcap")

DEFAULT_HOME_NET = "192.168.10.0/24"

FOCUS_SIDS = {
    "254", "272", "402", "1382", "1882", "32937", "54793", "56585"
}


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def pct(part, whole):
    return 0.0 if not whole else (part / whole) * 100.0


def as_network(value):
    if not isinstance(value, dict):
        return None
    prefix = int(value.get("prefix_len", 32))
    if prefix <= 0:
        return ipaddress.IPv4Network("0.0.0.0/0")
    return ipaddress.IPv4Network(f"{value['value']}/{prefix}", strict=False)


def exact_home_net_ip(match, field, home_net):
    if field not in match:
        return False
    net = as_network(match[field])
    return net == home_net


def non_home_specific_ip(match, home_net):
    """
    Structural discriminator:
    any restrictive IP prefix other than exactly HOME_NET.

    This intentionally does NOT use SQLi/XSS traffic frequencies.
    It is a configuration-independent structural test relative to HOME_NET.
    """
    for field in ("src_ip", "dst_ip"):
        if field not in match:
            continue
        net = as_network(match[field])
        if net is None or net.prefixlen == 0:
            continue
        if net != home_net:
            return True
    return False


def classify_entry_policy(match, policy, home_net):
    fields = restrictive_fields(match)
    field_set = set(fields)

    if policy == "one_field_broad":
        if fields == ("protocol",):
            return False, ["PROTOCOL_ONLY"]

        if fields == ("src_ip",) and exact_home_net_ip(match, "src_ip", home_net):
            return False, ["SRC_HOME_NET_ONLY"]

        if fields == ("dst_ip",) and exact_home_net_ip(match, "dst_ip", home_net):
            return False, ["DST_HOME_NET_ONLY"]

        return True, ["NOT_ONE_FIELD_BROAD"]

    if policy == "strong_discriminator":
        strong_reasons = []

        if "src_port" in field_set:
            strong_reasons.append("SRC_PORT")
        if "dst_port" in field_set:
            strong_reasons.append("DST_PORT")
        if "tcp_flags" in field_set:
            strong_reasons.append("TCP_FLAGS")
        if non_home_specific_ip(match, home_net):
            strong_reasons.append("NON_HOME_SPECIFIC_IP")

        if strong_reasons:
            return True, strong_reasons

        weak = []
        if "protocol" in field_set:
            weak.append("PROTOCOL_NOT_STRONG")
        if exact_home_net_ip(match, "src_ip", home_net):
            weak.append("SRC_HOME_NET_SCOPE_ONLY")
        if exact_home_net_ip(match, "dst_ip", home_net):
            weak.append("DST_HOME_NET_SCOPE_ONLY")
        if not weak:
            weak.append("NO_STRONG_DISCRIMINATOR")
        return False, weak

    raise ValueError(f"Unknown policy: {policy}")


def build_rule_entry_map(entries):
    rule_to_entry_indices = defaultdict(list)
    for idx, entry in enumerate(entries):
        for sid in entry.get("provenance", {}).get("source_rule_ids", []):
            rule_to_entry_indices[str(sid)].append(idx)
    return rule_to_entry_indices


def summarize_semantic_rules(manifest):
    rules = manifest.get("rules", [])
    semantic = Counter()
    candidate = set()
    unsupported = set()

    by_sid = {}
    for rule in rules:
        sid = str(rule.get("rule_id", rule.get("parsed_rule", {}).get("sid", "")))
        if not sid:
            continue
        by_sid[sid] = rule

        cls = str(rule.get("classification", "UNKNOWN"))
        semantic[cls] += 1

        if rule.get("prefilter_candidate") is True:
            candidate.add(sid)
        if cls == "UNSUPPORTED":
            unsupported.add(sid)

    return {
        "semantic_counts": dict(sorted(semantic.items())),
        "candidate_sids": candidate,
        "unsupported_sids": unsupported,
        "rules_by_sid": by_sid,
    }


def simulate_rule_partition(entries, manifest_info, policy, home_net):
    rule_to_entries = build_rule_entry_map(entries)
    semantic_candidate = manifest_info["candidate_sids"]

    entry_policy = []
    for idx, entry in enumerate(entries):
        keep, reasons = classify_entry_policy(entry.get("match", {}), policy, home_net)
        entry_policy.append({
            "index": idx,
            "id": entry.get("install_entry_id", f"entry-{idx}"),
            "strong": keep,
            "reasons": reasons,
            "match": entry.get("match", {}),
        })

    eligible = set()
    fallback = set()
    fallback_reasons = {}
    unmapped = set()

    for sid in sorted(semantic_candidate, key=lambda x: int(x) if x.isdigit() else x):
        indices = rule_to_entries.get(sid, [])

        if not indices:
            fallback.add(sid)
            unmapped.add(sid)
            fallback_reasons[sid] = {
                "reason": "NO_FINAL_INSTALL_ENTRY",
                "weak_entries": [],
            }
            continue

        weak = [entry_policy[i] for i in indices if not entry_policy[i]["strong"]]

        if weak:
            fallback.add(sid)
            fallback_reasons[sid] = {
                "reason": "AT_LEAST_ONE_WEAK_FINAL_BRANCH",
                "weak_entries": [
                    {
                        "install_entry_id": e["id"],
                        "match": e["match"],
                        "policy_reasons": e["reasons"],
                    }
                    for e in weak
                ],
            }
        else:
            eligible.add(sid)

    retained_entries = []
    removed_entries = []

    for idx, entry in enumerate(entries):
        source_sids = {
            str(x) for x in entry.get("provenance", {}).get("source_rule_ids", [])
        }
        needed_by = sorted(
            source_sids & eligible,
            key=lambda x: int(x) if x.isdigit() else x,
        )

        record = {
            "install_entry_id": entry.get("install_entry_id", f"entry-{idx}"),
            "match": entry.get("match", {}),
            "source_rule_count": entry.get("provenance", {}).get(
                "source_rule_count", len(source_sids)
            ),
            "source_rule_ids": sorted(
                source_sids,
                key=lambda x: int(x) if x.isdigit() else x,
            ),
            "needed_by_operationally_eligible_sids": needed_by,
            "entry_policy_strong": entry_policy[idx]["strong"],
            "entry_policy_reasons": entry_policy[idx]["reasons"],
        }

        if needed_by:
            retained_entries.append((idx, entry, record))
        else:
            removed_entries.append(record)

    return {
        "policy": policy,
        "eligible_sids": eligible,
        "fallback_sids": fallback,
        "fallback_reasons": fallback_reasons,
        "unmapped_sids": unmapped,
        "retained_entries": retained_entries,
        "removed_entries": removed_entries,
        "entry_policy": entry_policy,
    }


def offline_selectivity(pcap_path, retained_entries):
    entries = [item[1] for item in retained_entries]
    compiled = [compile_entry(entry, i) for i, entry in enumerate(entries)]

    # Small protocol index. Entries with protocol=None must be considered for all IPv4.
    proto_specific = defaultdict(list)
    proto_any = []
    for ce in compiled:
        if ce["protocol"] is None:
            proto_any.append(ce)
        else:
            proto_specific[int(ce["protocol"])].append(ce)

    total = 0
    eligible = 0
    candidate = 0
    no_match = 0
    ineligible_reasons = Counter()
    protocol_counts = Counter()
    match_multiplicity = Counter()

    for raw, _meta in RawPcapReader(str(pcap_path)):
        total += 1
        packet, reason = parse_frame_like_p4(bytes(raw))
        if packet is None:
            ineligible_reasons[reason] += 1
            continue

        eligible += 1
        proto = int(packet["protocol"])
        protocol_counts[proto] += 1

        candidates = proto_any + proto_specific.get(proto, [])
        matches = 0
        for ce in candidates:
            if compiled_entry_matches_packet(ce, packet):
                matches += 1

        match_multiplicity[matches] += 1
        if matches:
            candidate += 1
        else:
            no_match += 1

    # Exact average from histogram without storing one value per packet.
    if eligible:
        average = sum(k * v for k, v in match_multiplicity.items()) / eligible
    else:
        average = 0.0

    # Median from histogram.
    median = 0
    if eligible:
        target1 = (eligible - 1) // 2
        target2 = eligible // 2
        cumulative = 0
        m1 = m2 = None
        for k in sorted(match_multiplicity):
            next_c = cumulative + match_multiplicity[k]
            if m1 is None and target1 < next_c:
                m1 = k
            if m2 is None and target2 < next_c:
                m2 = k
                break
            cumulative = next_c
        median = (m1 + m2) / 2 if m1 is not None and m2 is not None else 0

    return {
        "pcap": str(pcap_path),
        "total_packets": total,
        "parser_eligible": eligible,
        "parser_ineligible": total - eligible,
        "parser_ineligible_reasons": dict(sorted(ineligible_reasons.items())),
        "protocol_counts": {
            str(k): v for k, v in sorted(protocol_counts.items())
        },
        "candidate": candidate,
        "no_match": no_match,
        "candidate_percentage_of_parser_eligible": pct(candidate, eligible),
        "no_match_percentage_of_parser_eligible": pct(no_match, eligible),
        "matching_entries_per_packet": {
            "average": average,
            "median": median,
            "minimum": min(match_multiplicity) if match_multiplicity else 0,
            "maximum": max(match_multiplicity) if match_multiplicity else 0,
            "histogram": {
                str(k): v for k, v in sorted(match_multiplicity.items())
            },
        },
    }


def focus_rule_report(manifest_info, result):
    report = {}
    eligible = result["eligible_sids"]
    fallback = result["fallback_sids"]
    by_sid = manifest_info["rules_by_sid"]

    for sid in sorted(FOCUS_SIDS, key=int):
        rule = by_sid.get(sid)
        if rule is None:
            continue

        if sid in eligible:
            operational = "P4_ELIGIBLE"
        elif sid in fallback:
            operational = "OPERATIONAL_FALLBACK"
        else:
            operational = "NOT_IN_SEMANTIC_CANDIDATE_SET"

        report[sid] = {
            "semantic_class": rule.get("classification"),
            "original_prefilter_candidate": rule.get("prefilter_candidate"),
            "operational_decision": operational,
            "selective_predicates": rule.get("selective_predicates", []),
            "fallback_reason": result["fallback_reasons"].get(sid),
        }

    return report


def policy_report(result, manifest_info, entries, home_net, run_pcaps, sqli, xss):
    eligible = result["eligible_sids"]
    fallback = result["fallback_sids"]
    retained = result["retained_entries"]
    removed = result["removed_entries"]

    report = {
        "policy": result["policy"],
        "definition": {
            "home_net": str(home_net),
            "rule_level_decision": (
                "A semantic NECESSARY rule is P4_ELIGIBLE only if every final "
                "install-entry branch associated with that rule satisfies the "
                "operational policy."
            ),
            "semantic_class_is_modified": False,
        },
        "rule_partition": {
            "semantic_candidate_rules": len(manifest_info["candidate_sids"]),
            "p4_eligible": len(eligible),
            "operational_fallback": len(fallback),
            "unsupported_fallback": len(manifest_info["unsupported_sids"]),
            "unmapped_semantic_candidates": len(result["unmapped_sids"]),
            "p4_eligible_sids": sorted(
                eligible, key=lambda x: int(x) if x.isdigit() else x
            ),
            "operational_fallback_sids": sorted(
                fallback, key=lambda x: int(x) if x.isdigit() else x
            ),
        },
        "install_entries": {
            "original": len(entries),
            "retained": len(retained),
            "removed": len(removed),
            "retained_percentage": pct(len(retained), len(entries)),
            "removed_entry_ids": [x["install_entry_id"] for x in removed],
        },
        "known_broad_entry_status": {},
        "focus_rules": focus_rule_report(manifest_info, result),
        "dependency_recheck": {
            "status": "REQUIRED_BEFORE_IMPLEMENTATION",
            "reason": (
                "The existing dependency audit was computed for the old "
                "CANDIDATE/UNSUPPORTED partition. Moving NECESSARY rules to "
                "OPERATIONAL_FALLBACK creates a new partition and requires a "
                "fresh flowbit/state dependency audit before implementation."
            ),
        },
    }

    retained_ids = {x[2]["install_entry_id"] for x in retained}
    for eid in ("p4-106", "p4-40", "p4-138", "p4-3", "p4-5"):
        original = next(
            (e for e in entries if e.get("install_entry_id") == eid),
            None,
        )
        if original is not None:
            report["known_broad_entry_status"][eid] = {
                "retained": eid in retained_ids,
                "match": original.get("match", {}),
                "source_rule_ids": original.get("provenance", {}).get(
                    "source_rule_ids", []
                ),
            }

    # Small representative fallback diagnostics, not the complete huge map.
    reason_counts = Counter()
    weak_entry_counts = Counter()
    samples = []

    for sid, detail in result["fallback_reasons"].items():
        reason_counts[detail["reason"]] += 1
        for weak in detail.get("weak_entries", []):
            for r in weak.get("policy_reasons", []):
                weak_entry_counts[r] += 1
        if len(samples) < 30:
            samples.append({"sid": sid, **detail})

    report["fallback_diagnostics"] = {
        "rule_reason_counts": dict(sorted(reason_counts.items())),
        "weak_entry_reason_counts": dict(sorted(weak_entry_counts.items())),
        "sample_rules": samples,
    }

    if run_pcaps:
        print(f"\n[{result['policy']}] SQLi offline simulation...")
        report["sql_injection"] = offline_selectivity(sqli, retained)

        print(f"[{result['policy']}] XSS offline simulation...")
        report["xss"] = offline_selectivity(xss, retained)

    return report


def print_policy_summary(report):
    rp = report["rule_partition"]
    ie = report["install_entries"]

    print("\n" + "=" * 68)
    print(f"Policy: {report['policy']}")
    print("=" * 68)
    print(f"Semantic candidate rules : {rp['semantic_candidate_rules']:,}")
    print(f"P4 eligible              : {rp['p4_eligible']:,}")
    print(f"Operational fallback     : {rp['operational_fallback']:,}")
    print(f"Unsupported fallback     : {rp['unsupported_fallback']:,}")
    print(f"Unmapped                 : {rp['unmapped_semantic_candidates']:,}")
    print(f"Install entries          : {ie['original']} -> {ie['retained']} "
          f"(removed {ie['removed']})")

    print("\nBroad-entry status:")
    for eid, item in report["known_broad_entry_status"].items():
        print(f"  {eid:8s} retained={str(item['retained']):5s} match={item['match']}")

    if "sql_injection" in report:
        s = report["sql_injection"]
        x = report["xss"]
        print("\nOffline selectivity:")
        print(
            f"  SQLi candidate: {s['candidate']:,}/{s['parser_eligible']:,} "
            f"({s['candidate_percentage_of_parser_eligible']:.3f}%) | "
            f"no-match {s['no_match']:,}"
        )
        print(
            f"  XSS  candidate: {x['candidate']:,}/{x['parser_eligible']:,} "
            f"({x['candidate_percentage_of_parser_eligible']:.3f}%) | "
            f"no-match {x['no_match']:,}"
        )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    ap.add_argument("--entries", type=Path, default=DEFAULT_ENTRIES)
    ap.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    ap.add_argument("--home-net", default=DEFAULT_HOME_NET)
    ap.add_argument("--sqli", type=Path, default=DEFAULT_SQLI)
    ap.add_argument("--xss", type=Path, default=DEFAULT_XSS)
    ap.add_argument(
        "--skip-pcaps",
        action="store_true",
        help="Run only the structural/rule-partition simulation.",
    )
    args = ap.parse_args()

    for path in (args.manifest, args.entries):
        if not path.exists():
            raise SystemExit(f"ERROR: required file not found: {path}")

    if not args.skip_pcaps:
        for path in (args.sqli, args.xss):
            if not path.exists():
                raise SystemExit(f"ERROR: PCAP not found: {path}")

    home_net = ipaddress.IPv4Network(args.home_net, strict=False)

    print("Loading manifest...")
    manifest = load_json(args.manifest)
    print("Loading final install entries...")
    entries_doc = load_json(args.entries)
    entries = entries_doc.get("entries", [])

    manifest_info = summarize_semantic_rules(manifest)

    print("\nSemantic baseline")
    print("-----------------")
    print(f"Rules in manifest         : {sum(manifest_info['semantic_counts'].values()):,}")
    print(f"Semantic classes          : {manifest_info['semantic_counts']}")
    print(f"Original P4 candidates    : {len(manifest_info['candidate_sids']):,}")
    print(f"Final install entries     : {len(entries):,}")

    all_reports = {}

    for policy in ("one_field_broad", "strong_discriminator"):
        result = simulate_rule_partition(
            entries,
            manifest_info,
            policy,
            home_net,
        )

        report = policy_report(
            result,
            manifest_info,
            entries,
            home_net,
            run_pcaps=not args.skip_pcaps,
            sqli=args.sqli,
            xss=args.xss,
        )

        all_reports[policy] = report
        print_policy_summary(report)

    final = {
        "schema_version": "1.0",
        "analysis": "operational_policy_simulation",
        "simulation_only": True,
        "no_pipeline_files_modified": True,
        "inputs": {
            "semantic_manifest": str(args.manifest),
            "p4_install_entries": str(args.entries),
            "home_net": str(home_net),
            "sql_injection_pcap": None if args.skip_pcaps else str(args.sqli),
            "xss_pcap": None if args.skip_pcaps else str(args.xss),
        },
        "semantic_baseline": {
            "classification": manifest_info["semantic_counts"],
            "prefilter_candidate": len(manifest_info["candidate_sids"]),
            "unsupported": len(manifest_info["unsupported_sids"]),
            "install_entries": len(entries),
        },
        "policies": all_reports,
        "methodological_note": (
            "SQLi and XSS are diagnostic/development traces for the operational "
            "policy. Do not use the unseen Brute Force window to tune this "
            "policy before it is frozen."
        ),
        "next_required_step": (
            "Inspect this simulation, choose/freeze an operational policy, then "
            "recompute rule-state/flowbit dependencies for the NEW partition "
            "before modifying the compiler or executing Brute Force."
        ),
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(final, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    print("\n" + "=" * 68)
    print("Simulation complete")
    print("=" * 68)
    print(f"Output: {args.output}")
    print("\nIMPORTANT:")
    print("- No semantic class was changed.")
    print("- No compiler/P4/ruleset/profile/snapshot file was changed.")
    print("- Do NOT execute Brute Force yet.")
    print("- Re-run the dependency audit after choosing a policy.")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Residual selectivity audit for the simulated strong_discriminator policy.

Purpose:
- Do NOT modify the compiler, semantic manifest, P4 program, rulesets, profiles,
  or frozen experiments.
- Reconstruct the 322 retained install entries from
  output/analysis/operational_policy_simulation.json.
- Re-run offline packet matching on the SQLi and XSS diagnostic PCAPs.
- Measure which retained entries still dominate the candidate union.
- Produce top-entry coverage and greedy cover after the broad predicates were
  removed by strong_discriminator.

Output:
  output/analysis/residual_selectivity_audit.json

Semantics. The frozen output above is the legacy strong plan (331 -> 322
entries). Since 2026-10-05 the root of output/ is the snort3 compilation, so
--semantica legacy reads the archived entries and --semantica snort3 (235 ->
225 entries) writes residual_selectivity_audit_snort3.json:

  python tests/analyze_residual_selectivity.py --semantica legacy
  python tests/analyze_residual_selectivity.py --semantica snort3 \
      --sqli .../thursday_web_sqli.pcap --xss .../thursday_web_xss.pcap
"""

import argparse
import json
from pathlib import Path

import analyze_prefilter_selectivity as aps

PROJECT_ROOT = Path(__file__).resolve().parents[1]

ANALYSIS = PROJECT_ROOT / "output" / "analysis"
SOURCES = {
    "legacy": {
        "entries": PROJECT_ROOT / "output" / "historical" / "legacy_header_semantics" / "p4_install_entries.json",
        "simulation": ANALYSIS / "operational_policy_simulation.json",
        "output": ANALYSIS / "residual_selectivity_audit.json",
        "expected": {
            "sql_injection": {"parser_eligible": 34924, "candidate": 34580, "no_match": 344},
            "xss": {"parser_eligible": 189076, "candidate": 186938, "no_match": 2138},
        },
    },
    "snort3": {
        "entries": PROJECT_ROOT / "output" / "p4_install_entries.json",
        "simulation": ANALYSIS / "operational_policy_simulation_snort3.json",
        "output": ANALYSIS / "residual_selectivity_audit_snort3.json",
        "expected": {
            "sql_injection": {"parser_eligible": 34924, "candidate": 32234, "no_match": 2690},
            "xss": {"parser_eligible": 189076, "candidate": 174277, "no_match": 14799},
        },
    },
}

DEFAULT_SQLI_PCAP = Path("/home/arthur/datasets/cicids2017/windows/thursday_web_sqli.pcap")
DEFAULT_XSS_PCAP = Path("/home/arthur/datasets/cicids2017/windows/thursday_web_xss.pcap")

EXPECTED = SOURCES["legacy"]["expected"]


def load_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def validate_result(label, report):
    expected = EXPECTED[label]
    actual = {
        "parser_eligible": report["parser_eligible"],
        "candidate": report["candidate"],
        "no_match": report["no_match"],
    }
    differences = {
        key: {"expected": expected[key], "actual": actual[key]}
        for key in expected
        if expected[key] != actual[key]
    }
    return {
        "status": "VALID" if not differences else "MISMATCH",
        "expected": expected,
        "actual": actual,
        "differences": differences,
    }


def summarize_greedy(report):
    greedy = report["greedy_cover"]
    selected = greedy.get("selected_entries", [])

    first_ten = selected[:10]
    return {
        "entries_for_50_percent": greedy.get("entries_for_50_percent"),
        "entries_for_90_percent": greedy.get("entries_for_90_percent"),
        "entries_for_95_percent": greedy.get("entries_for_95_percent"),
        "entries_for_99_percent": greedy.get("entries_for_99_percent"),
        "entries_for_100_percent": greedy.get("entries_for_100_percent"),
        "final_coverage_percentage": greedy.get("final_coverage_percentage"),
        "first_10_selected_entries": first_ten,
    }


def classify_residual_pattern(report):
    greedy = report["greedy_cover"]
    n99 = greedy.get("entries_for_99_percent")
    final_cov = greedy.get("final_coverage_percentage", 0.0)

    if n99 is not None and n99 <= 5:
        return {
            "category": "FEW_REMAINING_ENTRIES_DOMINATE",
            "reason": f"{n99} retained entries are sufficient to cover at least 99% of parser-eligible packets.",
        }

    if n99 is not None and n99 <= 20:
        return {
            "category": "SMALL_RESIDUAL_SET_DOMINATES",
            "reason": f"{n99} retained entries are sufficient to cover at least 99% of parser-eligible packets.",
        }

    if n99 is not None:
        return {
            "category": "DISTRIBUTED_UNION_COVERAGE",
            "reason": f"{n99} retained entries are required to reach 99% coverage.",
        }

    return {
        "category": "BELOW_99_PERCENT_FINAL_UNION",
        "reason": f"The retained union reaches only {final_cov:.6f}% of parser-eligible packets.",
    }


def print_top(label, report):
    print()
    print(f"Top residual entries: {label}")
    print("-" * 68)
    for item in report["top_entries"][:10]:
        print(
            f"{item['rank']:>2}. {item['install_entry_id']:<8} "
            f"{item['percentage_of_parser_eligible']:>8.3f}% "
            f"packets={item['packets_covered']:<7} "
            f"shape={item['shape']:<35} "
            f"match={item['match']}"
        )

    g = report["greedy_cover"]
    print()
    print("Greedy thresholds:")
    print(f"  50%  : {g.get('entries_for_50_percent')}")
    print(f"  90%  : {g.get('entries_for_90_percent')}")
    print(f"  95%  : {g.get('entries_for_95_percent')}")
    print(f"  99%  : {g.get('entries_for_99_percent')}")
    print(f"  100% : {g.get('entries_for_100_percent')}")
    print(f"  Final: {g.get('final_coverage_percentage'):.6f}%")

    print()
    print("First greedy entries:")
    for item in g.get("selected_entries", [])[:10]:
        print(
            f"  {item['rank']:>2}. {item['install_entry_id']:<8} "
            f"+{item['newly_covered_packets']:<7} "
            f"cum={item['cumulative_coverage_percentage']:.3f}% "
            f"match={item['match']}"
        )


def main():
    global EXPECTED
    parser = argparse.ArgumentParser(description="Residual selectivity audit for the strong_discriminator policy.")
    parser.add_argument("--semantica", choices=sorted(SOURCES), default="snort3")
    parser.add_argument("--sqli", type=Path, default=DEFAULT_SQLI_PCAP)
    parser.add_argument("--xss", type=Path, default=DEFAULT_XSS_PCAP)
    args = parser.parse_args()
    source = SOURCES[args.semantica]
    ENTRIES_FILE, SIMULATION_FILE, OUTPUT_FILE = source["entries"], source["simulation"], source["output"]
    SQLI_PCAP, XSS_PCAP = args.sqli, args.xss
    EXPECTED = source["expected"]

    for path in (ENTRIES_FILE, SIMULATION_FILE, SQLI_PCAP, XSS_PCAP):
        if not path.exists():
            raise SystemExit(f"ERROR: required file not found: {path}")

    entries_doc = load_json(ENTRIES_FILE)
    all_entries = entries_doc["entries"]

    simulation = load_json(SIMULATION_FILE)
    strong = simulation["policies"]["strong_discriminator"]

    removed_ids = set(strong["install_entries"]["removed_entry_ids"])
    retained_entries = [
        entry
        for entry in all_entries
        if entry.get("install_entry_id") not in removed_ids
    ]

    expected_retained = strong["install_entries"]["retained"]

    print("=" * 68)
    print("Residual selectivity audit — strong_discriminator")
    print("=" * 68)
    print(f"Original install entries : {len(all_entries)}")
    print(f"Removed by policy        : {len(removed_ids)}")
    print(f"Retained entries         : {len(retained_entries)}")
    print(f"Expected retained        : {expected_retained}")

    if len(retained_entries) != expected_retained:
        raise SystemExit(
            f"ERROR: retained entry mismatch: "
            f"{len(retained_entries)} != {expected_retained}"
        )

    # Disable the original v1 known-result expectation, because this audit is
    # intentionally evaluating a different simulated entry set.
    aps.KNOWN_EXPECTED = {}

    compiled = [
        aps.compile_entry(entry, index)
        for index, entry in enumerate(retained_entries)
    ]

    sqli = aps.analyze_pcap(
        "residual_sql_injection",
        SQLI_PCAP,
        retained_entries,
        compiled,
    )

    xss = aps.analyze_pcap(
        "residual_xss",
        XSS_PCAP,
        retained_entries,
        compiled,
    )

    sqli_validation = validate_result("sql_injection", sqli)
    xss_validation = validate_result("xss", xss)

    print_top("SQLi", sqli)
    print_top("XSS", xss)

    print()
    print("Reproduction checks:")
    print(f"  SQLi: {sqli_validation['status']}")
    print(f"  XSS : {xss_validation['status']}")

    sqli_pattern = classify_residual_pattern(sqli)
    xss_pattern = classify_residual_pattern(xss)

    print()
    print("Residual pattern:")
    print(f"  SQLi: {sqli_pattern['category']} — {sqli_pattern['reason']}")
    print(f"  XSS : {xss_pattern['category']} — {xss_pattern['reason']}")

    out = {
        "schema_version": "1.0",
        "analysis": "residual_selectivity_audit",
        "simulation_only": True,
        "policy": "strong_discriminator",
        "inputs": {
            "p4_install_entries": str(ENTRIES_FILE),
            "operational_policy_simulation": str(SIMULATION_FILE),
            "sql_injection_pcap": str(SQLI_PCAP),
            "xss_pcap": str(XSS_PCAP),
        },
        "entry_set": {
            "original_entries": len(all_entries),
            "removed_entries": len(removed_ids),
            "retained_entries": len(retained_entries),
            "removed_entry_ids": sorted(removed_ids),
        },
        "sql_injection": {
            **sqli,
            "simulation_reproduction": sqli_validation,
            "greedy_summary": summarize_greedy(sqli),
            "residual_pattern": sqli_pattern,
        },
        "xss": {
            **xss,
            "simulation_reproduction": xss_validation,
            "greedy_summary": summarize_greedy(xss),
            "residual_pattern": xss_pattern,
        },
        "interpretation_rule": {
            "few_remaining_entries_dominate": "entries_for_99_percent <= 5",
            "small_residual_set_dominates": "6 <= entries_for_99_percent <= 20",
            "distributed_union_coverage": "entries_for_99_percent > 20",
            "below_99_percent_final_union": "the retained union never reaches 99%",
        },
        "next_step": (
            "Use the residual coverage structure to decide whether another "
            "structural policy refinement is justified or whether the binary "
            "global P4_CANDIDATE abstraction itself is the main selectivity "
            "limitation. Do not execute Brute Force or modify the compiler yet."
        ),
    }

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_FILE.write_text(
        json.dumps(out, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    print()
    print("=" * 68)
    print("Residual audit complete")
    print("=" * 68)
    print(f"Output: {OUTPUT_FILE}")
    print("Do NOT execute Brute Force yet.")


if __name__ == "__main__":
    main()

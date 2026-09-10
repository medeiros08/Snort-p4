#!/usr/bin/env python3
"""Assemble the reproducible report for the CIC-IDS2017 SQLi experiment."""

import argparse
import hashlib
import json
from pathlib import Path


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--experiment-dir", type=Path, required=True)
    parser.add_argument("--pcap", type=Path, required=True)
    args = parser.parse_args()

    snort = read_json(args.experiment_dir / "snort_comparison.json")
    alert = read_json(args.experiment_dir / "p4_alert_preservation.json")
    coverage = read_json(args.experiment_dir / "p4_parser_coverage.json")
    report_path = args.experiment_dir / "report.json"
    previous_report = read_json(report_path) if report_path.exists() else {}

    snort_valid = all(snort[field] == 0 for field in (
        "unknown_alerts", "candidate_missing", "candidate_additional",
        "unsupported_missing", "unsupported_additional", "union_missing",
        "union_additional",
    ))
    alert_valid = (
        alert["packet_accounting_ok"]
        and alert["candidate"]["packets"] == snort["unique_candidate_alert_packets"]
        and alert["no_match"]["packets"] == 0
    )
    replay_valid = coverage["input_to_veth_accounting"] == "VALID"
    parser_valid = coverage["parser_to_counter_accounting"] == "VALID"
    status = "VALID" if all((snort_valid, alert_valid, replay_valid, parser_valid)) else "INVALID"

    total_packets = coverage["total_packets"]
    eligible = coverage["parser_eligible_packets"]
    ineligible = coverage["parser_ineligible_packets"]
    candidate_packets = coverage["candidate_counter_packets"]
    no_match_packets = coverage["no_match_counter_packets"]
    old_measurement = previous_report.get("p4_selectivity")
    report = {
        "experiment_id": "cicids2017_thursday_sqli",
        "dataset": "CIC-IDS2017 Thursday Web Attacks - SQL Injection window",
        "pcap": str(args.pcap),
        "pcap_sha256": sha256(args.pcap),
        "profile": "cicids2017",
        "home_net": "192.168.10.0/24",
        "pcap_packets": total_packets,
        "snort": snort,
        "snort_rule_split_preservation": {
            "status": "VALID" if snort_valid else "INVALID",
            "comparison_key": ["pkt_num", "gid", "sid", "rev"],
        },
        "p4_alert_preservation": {
            "status": "VALID" if alert_valid else "INVALID",
            "unique_candidate_alert_packets": snort["unique_candidate_alert_packets"],
            "unique_alert_packets": snort["unique_candidate_alert_packets"],
            "observed_packets": alert["observed_packets"],
            "candidate_packets": alert["candidate"]["packets"],
            "no_match_packets": alert["no_match"]["packets"],
            "candidate_bytes": alert["candidate"]["bytes"],
            "no_match_bytes": alert["no_match"]["bytes"],
            "preservation_percentage": (
                100.0 * alert["candidate"]["packets"]
                / snort["unique_candidate_alert_packets"]
            ),
            "packet_accounting": "VALID" if alert["packet_accounting_ok"] else "INVALID",
            "replay": {"interface": alert["interface"], "batch_size": 50, "inter_seconds": 0.05},
        },
        "parser_coverage": {
            "total_packets": total_packets,
            "direct_ipv4": coverage["direct_ipv4_packets"],
            "parser_eligible": eligible,
            "parser_ineligible": ineligible,
            "arp": coverage["arp_packets"],
            "ipv6": coverage["ipv6_packets"],
            "cdp_llc": coverage["other_packets"],
            "vlan": coverage["vlan_packets"],
            "malformed": len(coverage["malformed_frame_numbers"]),
            "parser_coverage_percentage": 100.0 * eligible / total_packets,
        },
        "replay_accounting": {
            "input_packets": total_packets,
            "veth0_received": coverage["veth0_received_packets"],
            "missing": total_packets - coverage["veth0_received_packets"],
            "status": "VALID" if replay_valid else "INVALID",
        },
        "p4_selectivity": {
            "parser_eligible_packets": eligible,
            "candidate_packets": candidate_packets,
            "no_match_packets": no_match_packets,
            "candidate_percentage_of_parser_eligible": 100.0 * candidate_packets / eligible,
            "no_match_percentage_of_parser_eligible": 100.0 * no_match_packets / eligible,
            "parser_p4_accounting": "VALID" if parser_valid else "INVALID",
            "categories": ["P4_CANDIDATE", "P4_NO_MATCH", "PARSER_INELIGIBLE"],
        },
        "capture_composition": {
            "candidate_percentage_of_total_capture": 100.0 * candidate_packets / total_packets,
            "parser_ineligible_percentage_of_total_capture": 100.0 * ineligible / total_packets,
        },
        "experimental_replay_preference": {
            "script": "tests/replay_pcap_raw.py",
            "reason": "AF_PACKET raw replay preserves captured Ethernet bytes; PcapReader/sendp requires separate accounting validation.",
        },
        "measurement_history": [
            {
                "status": "INVALID_MEASUREMENT_SUPERSEDED",
                "method": "PcapReader/sendp bulk replay",
                "input_packets": old_measurement.get("input_packets", 35274) if old_measurement else 35274,
                "prefilter_accounted_packets": old_measurement.get("observed_packets", 30503) if old_measurement else 30503,
                "reason": "Transient replay-path accounting failure; superseded by audited AF_PACKET raw replay with veth0 capture.",
            }
        ],
        "status": status,
        "limitations": [
            "Dynamic alert preservation exercises only one candidate SID (254); 100% does not represent general coverage of all 4003 candidate rules.",
            "SID 254 is not evidence of ground-truth SQL Injection detection. This experiment measures the behavior of the configured Snort ruleset, not detection of the CIC-IDS2017 dataset label.",
            "PARSER_INELIGIBLE is distinct from P4_NO_MATCH and is not interpreted as a no-match.",
        ],
    }
    report_path.write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()

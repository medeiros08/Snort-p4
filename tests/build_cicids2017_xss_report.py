#!/usr/bin/env python3
"""Build the audited CIC-IDS2017 Thursday XSS experiment report."""

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
    alert = read_json(args.experiment_dir / "candidate_alert_parser_coverage.json")
    coverage = read_json(args.experiment_dir / "p4_parser_coverage.json")

    snort_valid = all(snort[field] == 0 for field in (
        "unknown_alerts", "candidate_missing", "candidate_additional",
        "unsupported_missing", "unsupported_additional", "union_missing",
        "union_additional",
    ))
    eligible_alerts = alert["parser_eligible_packets"]
    ineligible_alerts = alert["parser_ineligible_packets"]
    alert_valid = (
        alert["candidate_counter_packets"] == eligible_alerts
        and alert["no_match_counter_packets"] == 0
        and alert["parser_to_counter_accounting"] == "VALID"
    )
    replay_valid = coverage["input_to_veth_accounting"] == "VALID"
    parser_valid = coverage["parser_to_counter_accounting"] == "VALID"
    status = "VALID" if all((snort_valid, alert_valid, replay_valid, parser_valid)) else "INVALID"

    total = coverage["total_packets"]
    eligible = coverage["parser_eligible_packets"]
    ineligible = coverage["parser_ineligible_packets"]
    candidate = coverage["candidate_counter_packets"]
    no_match = coverage["no_match_counter_packets"]

    report = {
        "experiment_id": "cicids2017_thursday_xss",
        "dataset": "CIC-IDS2017 Thursday Web Attacks",
        "window": "XSS",
        "profile": "cicids2017",
        "home_net": "192.168.10.0/24",
        "pcap": str(args.pcap),
        "pcap_sha256": sha256(args.pcap),
        "pcap_packets": total,
        "snort": snort,
        "snort_rule_split_preservation": {
            "status": "VALID" if snort_valid else "INVALID",
            "comparison_key": ["pkt_num", "gid", "sid", "rev"],
        },
        "p4_alert_preservation": {
            "status": "VALID" if alert_valid else "INVALID",
            "candidate_alerts": snort["baseline_candidate_alerts"],
            "unique_alert_packets": snort["unique_candidate_alert_packets"],
            "parser_eligible_alert_packets": eligible_alerts,
            "parser_ineligible_alert_packets": ineligible_alerts,
            "candidate_packets": alert["candidate_counter_packets"],
            "no_match_packets": alert["no_match_counter_packets"],
            "preservation_percentage": (
                100.0 * alert["candidate_counter_packets"] / eligible_alerts
                if eligible_alerts else None
            ),
            "replay": {"script": "tests/replay_pcap_raw.py", "interface": "veth1", "inter_seconds": 0.02},
        },
        "parser_coverage": {
            "total_packets": total,
            "parser_eligible": eligible,
            "parser_ineligible": ineligible,
            "direct_ipv4": coverage["direct_ipv4_packets"],
            "arp": coverage["arp_packets"],
            "ipv6": coverage["ipv6_packets"],
            "vlan": coverage["vlan_packets"],
            "vlan_ipv4": coverage["vlan_ipv4_packets"],
            "cdp_llc": coverage["lldp_packets"] + coverage["other_packets"],
            "other": coverage["other_packets"],
            "malformed": len(coverage["malformed_frame_numbers"]),
        },
        "replay_accounting": {
            "input_packets": total,
            "veth0_received": coverage["veth0_received_packets"],
            "missing": total - coverage["veth0_received_packets"],
            "status": "VALID" if replay_valid else "INVALID",
        },
        "p4_selectivity": {
            "parser_eligible_packets": eligible,
            "candidate_packets": candidate,
            "no_match_packets": no_match,
            "candidate_percentage_of_parser_eligible": 100.0 * candidate / eligible,
            "no_match_percentage_of_parser_eligible": 100.0 * no_match / eligible,
            "parser_p4_accounting": "VALID" if parser_valid else "INVALID",
            "categories": ["P4_CANDIDATE", "P4_NO_MATCH", "PARSER_INELIGIBLE"],
        },
        "capture_composition": {
            "candidate_percentage_of_total_capture": 100.0 * candidate / total,
            "parser_ineligible_percentage_of_total_capture": 100.0 * ineligible / total,
        },
        "status": status,
        "limitations": [
            "Alert preservation covers only the SIDs exercised by this PCAP; it is not general coverage of all 4003 candidate rules.",
            "Fired SIDs must not be interpreted as proof of CIC-IDS2017 XSS ground-truth detection; this experiment measures the configured Snort ruleset behavior.",
            "PARSER_INELIGIBLE is distinct from P4_NO_MATCH and is not a safe-bypass decision because UNSUPPORTED rules remain.",
        ],
    }
    (args.experiment_dir / "report.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()

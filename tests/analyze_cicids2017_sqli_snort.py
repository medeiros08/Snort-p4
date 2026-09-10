#!/usr/bin/env python3
"""Compare the SQLi Snort runs as multisets and extract candidate packets."""

import argparse
from collections import Counter
import json
from pathlib import Path
import re

from scapy.utils import RawPcapReader, RawPcapWriter


KEY_FIELDS = ("pkt_num", "gid", "sid", "rev")


def load_alerts(path: Path):
    alerts = []
    with path.open(encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, 1):
            if line.strip():
                try:
                    alerts.append(json.loads(line))
                except json.JSONDecodeError as error:
                    raise ValueError(f"{path}:{line_number}: {error}") from error
    return alerts


def load_rule_sids(path: Path):
    text = path.read_text(encoding="utf-8")
    return {int(value) for value in re.findall(r"(?:^|[;\s])sid\s*:\s*(\d+)\s*;", text)}


def key(alert):
    return tuple(int(alert[field]) for field in KEY_FIELDS)


def sid_messages(alerts):
    result = {}
    for alert in alerts:
        result.setdefault(str(int(alert["sid"])), set()).add(alert.get("msg", ""))
    return {sid: sorted(messages) for sid, messages in sorted(result.items(), key=lambda item: int(item[0]))}


def sid_alert_counts(alerts):
    return {
        str(sid): count
        for sid, count in sorted(
            Counter(int(alert["sid"]) for alert in alerts).items()
        )
    }


def extract_raw_packets(source, destination, packet_numbers):
    """Extract numbered records while preserving their captured Ethernet bytes."""
    wanted = set(packet_numbers)
    writer = RawPcapWriter(str(destination), linktype=1, sync=True)
    try:
        for number, (data, _metadata) in enumerate(RawPcapReader(str(source)), 1):
            if number in wanted:
                writer.write(data)
    finally:
        writer.close()


def comparison(expected, actual):
    expected_counter = Counter(map(key, expected))
    actual_counter = Counter(map(key, actual))
    return {
        "missing": sum((expected_counter - actual_counter).values()),
        "additional": sum((actual_counter - expected_counter).values()),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--experiment-dir", type=Path, required=True)
    parser.add_argument("--pcap", type=Path, required=True)
    parser.add_argument("--candidate-rules", type=Path, required=True)
    parser.add_argument("--unsupported-rules", type=Path, required=True)
    args = parser.parse_args()

    full = load_alerts(args.experiment_dir / "baseline_full.jsonl")
    candidate = load_alerts(args.experiment_dir / "candidate.jsonl")
    unsupported = load_alerts(args.experiment_dir / "unsupported.jsonl")
    candidate_sids = load_rule_sids(args.candidate_rules)
    unsupported_sids = load_rule_sids(args.unsupported_rules)
    overlap = candidate_sids & unsupported_sids
    if overlap:
        raise RuntimeError(f"partition SID overlap: {sorted(overlap)}")

    baseline_candidate = [alert for alert in full if int(alert["sid"]) in candidate_sids]
    baseline_unsupported = [alert for alert in full if int(alert["sid"]) in unsupported_sids]
    known_sids = candidate_sids | unsupported_sids
    baseline_unknown = [alert for alert in full if int(alert["sid"]) not in known_sids]

    candidate_cmp = comparison(baseline_candidate, candidate)
    unsupported_cmp = comparison(baseline_unsupported, unsupported)
    union_cmp = comparison(full, candidate + unsupported)
    packet_numbers = sorted({int(alert["pkt_num"]) for alert in baseline_candidate})

    extracted = args.experiment_dir / "candidate_alert_packets.pcap"
    if packet_numbers:
        extract_raw_packets(args.pcap, extracted, packet_numbers)
    elif extracted.exists():
        extracted.unlink()

    result = {
        "partition_rule_sids": {"candidate": len(candidate_sids), "unsupported": len(unsupported_sids)},
        "full_alerts": len(full),
        "baseline_candidate_alerts": len(baseline_candidate),
        "baseline_unsupported_alerts": len(baseline_unsupported),
        "unknown_alerts": len(baseline_unknown),
        "candidate_run_alerts": len(candidate),
        "unsupported_run_alerts": len(unsupported),
        "candidate_missing": candidate_cmp["missing"],
        "candidate_additional": candidate_cmp["additional"],
        "unsupported_missing": unsupported_cmp["missing"],
        "unsupported_additional": unsupported_cmp["additional"],
        "union_missing": union_cmp["missing"],
        "union_additional": union_cmp["additional"],
        "unique_full_sids": len({int(alert["sid"]) for alert in full}),
        "unique_candidate_sids": len({int(alert["sid"]) for alert in baseline_candidate}),
        "unique_unsupported_sids": len({int(alert["sid"]) for alert in baseline_unsupported}),
        "full_sid_messages": sid_messages(full),
        "candidate_sid_messages": sid_messages(baseline_candidate),
        "unsupported_sid_messages": sid_messages(baseline_unsupported),
        "full_sid_alert_counts": sid_alert_counts(full),
        "candidate_sid_alert_counts": sid_alert_counts(baseline_candidate),
        "unsupported_sid_alert_counts": sid_alert_counts(baseline_unsupported),
        "unique_candidate_alert_packets": len(packet_numbers),
        "candidate_alert_packet_numbers": packet_numbers,
    }
    output = args.experiment_dir / "snort_comparison.json"
    output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()

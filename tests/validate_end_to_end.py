import argparse
import json
import re
import sys

from collections import Counter
from pathlib import Path


PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parents[1]
)


DEFAULT_BASELINE = (
    PROJECT_ROOT
    / "output"
    / "alert_preservation_baseline.jsonl"
)

DEFAULT_CANDIDATE = (
    PROJECT_ROOT
    / "output"
    / "alert_preservation_candidate.jsonl"
)

DEFAULT_P4 = (
    PROJECT_ROOT
    / "output"
    / "alert_preservation_controlled_p4_classification.jsonl"
)

CANDIDATE_RULES = (
    PROJECT_ROOT
    / "output"
    / "snort_candidate.rules"
)

UNSUPPORTED_RULES = (
    PROJECT_ROOT
    / "output"
    / "snort_unsupported.rules"
)

DEFAULT_REPORT = (
    PROJECT_ROOT
    / "output"
    / "end_to_end_controlled_report.json"
)


SID_RE = re.compile(
    r"\bsid\s*:\s*(\d+)\s*;",
    re.IGNORECASE,
)


# ============================================================
# Loaders
# ============================================================


def load_jsonl(path):

    records = []

    with open(
        path,
        "r",
        encoding="utf-8",
    ) as file:

        for line_number, line in enumerate(
            file,
            start=1,
        ):

            line = line.strip()

            if not line:
                continue

            try:

                record = json.loads(
                    line
                )

            except json.JSONDecodeError as error:

                raise ValueError(
                    f"Invalid JSON in "
                    f"{path.name}, "
                    f"line {line_number}: "
                    f"{error}"
                )

            records.append(
                record
            )

    return records


def load_rule_sids(path):

    sids = set()

    text = path.read_text(
        encoding="utf-8",
        errors="replace",
    )

    for match in SID_RE.finditer(
        text
    ):

        sids.add(
            int(
                match.group(1)
            )
        )

    return sids


# ============================================================
# Alert representation
# ============================================================


def alert_key(alert):

    return (
        int(
            alert.get(
                "pkt_num",
                -1,
            )
        ),
        int(
            alert.get(
                "gid",
                -1,
            )
        ),
        int(
            alert.get(
                "sid",
                -1,
            )
        ),
        int(
            alert.get(
                "rev",
                -1,
            )
        ),
    )


def alert_to_dict(
    key,
    alert=None,
):

    result = {
        "pkt_num": key[0],
        "gid": key[1],
        "sid": key[2],
        "rev": key[3],
    }

    if alert:

        result["msg"] = (
            alert.get(
                "msg"
            )
        )

    return result


# ============================================================
# P4 classifications
# ============================================================


def build_p4_index(
    records
):

    index = {}

    duplicates = []

    for record in records:

        pkt_num = int(
            record[
                "pkt_num"
            ]
        )

        if pkt_num in index:

            duplicates.append(
                pkt_num
            )

        index[
            pkt_num
        ] = record

    return (
        index,
        sorted(
            set(
                duplicates
            )
        ),
    )


# ============================================================
# Main
# ============================================================


def main():

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--baseline",
        default=str(
            DEFAULT_BASELINE
        ),
    )

    parser.add_argument(
        "--candidate",
        default=str(
            DEFAULT_CANDIDATE
        ),
    )

    parser.add_argument(
        "--p4",
        default=str(
            DEFAULT_P4
        ),
    )

    parser.add_argument(
        "--output",
        default=str(
            DEFAULT_REPORT
        ),
    )

    args = parser.parse_args()

    baseline_path = Path(
        args.baseline
    )

    candidate_path = Path(
        args.candidate
    )

    p4_path = Path(
        args.p4
    )

    output_path = Path(
        args.output
    )

    required = [
        baseline_path,
        candidate_path,
        p4_path,
        CANDIDATE_RULES,
        UNSUPPORTED_RULES,
    ]

    for path in required:

        if not path.exists():

            print(
                f"ERROR: Missing file: "
                f"{path}"
            )

            sys.exit(1)

    # ========================================================
    # Load experiment artifacts
    # ========================================================

    try:

        baseline_alerts = (
            load_jsonl(
                baseline_path
            )
        )

        candidate_alerts = (
            load_jsonl(
                candidate_path
            )
        )

        p4_records = (
            load_jsonl(
                p4_path
            )
        )

    except Exception as error:

        print(
            f"ERROR: {error}"
        )

        sys.exit(1)

    candidate_sids = (
        load_rule_sids(
            CANDIDATE_RULES
        )
    )

    unsupported_sids = (
        load_rule_sids(
            UNSUPPORTED_RULES
        )
    )

    # ========================================================
    # Rule-set validation
    # ========================================================

    overlapping_rule_sids = (
        candidate_sids
        & unsupported_sids
    )

    # ========================================================
    # Separate baseline alerts by semantic treatment
    # ========================================================

    baseline_candidate_alerts = [
        alert

        for alert in baseline_alerts

        if int(
            alert.get(
                "sid",
                -1,
            )
        )
        in candidate_sids
    ]

    baseline_unsupported_alerts = [
        alert

        for alert in baseline_alerts

        if int(
            alert.get(
                "sid",
                -1,
            )
        )
        in unsupported_sids
    ]

    baseline_unknown_alerts = [
        alert

        for alert in baseline_alerts

        if (
            int(
                alert.get(
                    "sid",
                    -1,
                )
            )
            not in candidate_sids
            and
            int(
                alert.get(
                    "sid",
                    -1,
                )
            )
            not in unsupported_sids
        )
    ]

    # ========================================================
    # Compare Snort baseline vs candidate run
    #
    # Counter is used instead of a simple set so alert
    # multiplicity is preserved.
    # ========================================================

    baseline_candidate_counter = Counter(
        alert_key(
            alert
        )
        for alert
        in baseline_candidate_alerts
    )

    candidate_counter = Counter(
        alert_key(
            alert
        )
        for alert
        in candidate_alerts
    )

    preserved_counter = (
        baseline_candidate_counter
        & candidate_counter
    )

    missing_counter = (
        baseline_candidate_counter
        - candidate_counter
    )

    additional_counter = (
        candidate_counter
        - baseline_candidate_counter
    )

    baseline_candidate_count = sum(
        baseline_candidate_counter.values()
    )

    preserved_count = sum(
        preserved_counter.values()
    )

    missing_count = sum(
        missing_counter.values()
    )

    additional_count = sum(
        additional_counter.values()
    )

    if baseline_candidate_count:

        snort_preservation_rate = (
            preserved_count
            / baseline_candidate_count
            * 100.0
        )

    else:

        snort_preservation_rate = (
            100.0
        )

    # ========================================================
    # Candidate-run structural validation
    # ========================================================

    candidate_run_unsupported = [
        alert

        for alert in candidate_alerts

        if int(
            alert.get(
                "sid",
                -1,
            )
        )
        in unsupported_sids
    ]

    candidate_run_unknown = [
        alert

        for alert in candidate_alerts

        if (
            int(
                alert.get(
                    "sid",
                    -1,
                )
            )
            not in candidate_sids
        )
    ]

    # ========================================================
    # P4 index
    # ========================================================

    (
        p4_index,
        duplicate_p4_packets,
    ) = build_p4_index(
        p4_records
    )

    ambiguous_p4_records = [
        record

        for record in p4_records

        if record.get(
            "classification"
        )
        == "AMBIGUOUS"
    ]

    # ========================================================
    # Check semantic implication experimentally:
    #
    # Snort candidate alert
    #          =>
    # P4 CANDIDATE
    #
    # We use alerts from the FULL baseline whose SIDs belong
    # to the candidate rule set.
    # ========================================================

    p4_false_negative_alerts = []

    missing_p4_classifications = []

    candidate_alert_packet_numbers = set()

    for alert in baseline_candidate_alerts:

        pkt_num = int(
            alert[
                "pkt_num"
            ]
        )

        candidate_alert_packet_numbers.add(
            pkt_num
        )

        classification = (
            p4_index.get(
                pkt_num
            )
        )

        if classification is None:

            missing_p4_classifications.append(
                {
                    "pkt_num": pkt_num,
                    "sid": int(
                        alert[
                            "sid"
                        ]
                    ),
                    "msg": alert.get(
                        "msg"
                    ),
                }
            )

            continue

        if (
            classification.get(
                "classification"
            )
            != "CANDIDATE"
        ):

            p4_false_negative_alerts.append(
                {
                    "pkt_num": pkt_num,
                    "sid": int(
                        alert[
                            "sid"
                        ]
                    ),
                    "msg": alert.get(
                        "msg"
                    ),
                    "p4_classification": (
                        classification.get(
                            "classification"
                        )
                    ),
                }
            )

    p4_false_negative_packets = sorted(
        {
            item[
                "pkt_num"
            ]

            for item
            in p4_false_negative_alerts
        }
    )

    missing_p4_packets = sorted(
        {
            item[
                "pkt_num"
            ]

            for item
            in missing_p4_classifications
        }
    )

    candidate_alert_packet_count = len(
        candidate_alert_packet_numbers
    )

    covered_alert_packets = (
        candidate_alert_packet_count
        - len(
            set(
                p4_false_negative_packets
            )
            |
            set(
                missing_p4_packets
            )
        )
    )

    if candidate_alert_packet_count:

        p4_alert_packet_preservation = (
            covered_alert_packets
            / candidate_alert_packet_count
            * 100.0
        )

    else:

        p4_alert_packet_preservation = (
            100.0
        )

    # ========================================================
    # Overall P4 traffic classification
    # ========================================================

    p4_candidate_packets = sum(
        1
        for record in p4_records
        if record.get(
            "classification"
        )
        == "CANDIDATE"
    )

    p4_no_match_packets = sum(
        1
        for record in p4_records
        if record.get(
            "classification"
        )
        == "NO_MATCH"
    )

    p4_ambiguous_packets = sum(
        1
        for record in p4_records
        if record.get(
            "classification"
        )
        == "AMBIGUOUS"
    )

    p4_total_packets = len(
        p4_records
    )

    if p4_total_packets:

        p4_candidate_rate = (
            p4_candidate_packets
            / p4_total_packets
            * 100.0
        )

    else:

        p4_candidate_rate = 0.0

    # ========================================================
    # Validation status
    # ========================================================

    errors = []
    warnings = []

    if overlapping_rule_sids:

        errors.append(
            "candidate and unsupported "
            "rule sets overlap"
        )

    if missing_count:

        errors.append(
            "candidate Snort run lost "
            "baseline candidate alerts"
        )

    if candidate_run_unsupported:

        errors.append(
            "candidate Snort run produced "
            "an unsupported SID"
        )

    if candidate_run_unknown:

        errors.append(
            "candidate Snort run produced "
            "a SID outside candidate set"
        )

    if p4_false_negative_alerts:

        errors.append(
            "P4 NO_MATCH observed for "
            "candidate baseline alert"
        )

    if missing_p4_classifications:

        errors.append(
            "baseline candidate alert "
            "packet lacks P4 classification"
        )

    if ambiguous_p4_records:

        errors.append(
            "ambiguous P4 packet "
            "classification detected"
        )

    if duplicate_p4_packets:

        errors.append(
            "duplicate packet numbers "
            "in P4 classification"
        )

    if baseline_unknown_alerts:

        warnings.append(
            "baseline contains alerts "
            "whose SIDs are outside both "
            "experimental rule subsets"
        )

    if additional_count:

        warnings.append(
            "candidate run contains "
            "additional alerts not observed "
            "in baseline candidate alerts"
        )

    status = (
        "VALID"
        if not errors
        else "INVALID"
    )

    # ========================================================
    # Human-readable details
    # ========================================================

    baseline_lookup = {
        alert_key(
            alert
        ): alert

        for alert in baseline_alerts
    }

    candidate_lookup = {
        alert_key(
            alert
        ): alert

        for alert in candidate_alerts
    }

    missing_alert_details = []

    for key, count in sorted(
        missing_counter.items()
    ):

        alert = baseline_lookup.get(
            key
        )

        detail = alert_to_dict(
            key,
            alert,
        )

        detail[
            "occurrences"
        ] = count

        missing_alert_details.append(
            detail
        )

    additional_alert_details = []

    for key, count in sorted(
        additional_counter.items()
    ):

        alert = candidate_lookup.get(
            key
        )

        detail = alert_to_dict(
            key,
            alert,
        )

        detail[
            "occurrences"
        ] = count

        additional_alert_details.append(
            detail
        )

    # ========================================================
    # Report
    # ========================================================

    report = {
        "schema_version": "1.0",

        "status": status,

        "rule_sets": {
            "candidate_sids": len(
                candidate_sids
            ),

            "unsupported_sids": len(
                unsupported_sids
            ),

            "overlap": sorted(
                overlapping_rule_sids
            ),
        },

        "snort": {
            "baseline_total_alerts": len(
                baseline_alerts
            ),

            "baseline_candidate_alerts": (
                len(
                    baseline_candidate_alerts
                )
            ),

            "baseline_unsupported_alerts": (
                len(
                    baseline_unsupported_alerts
                )
            ),

            "baseline_unknown_alerts": (
                len(
                    baseline_unknown_alerts
                )
            ),

            "candidate_run_alerts": len(
                candidate_alerts
            ),

            "preserved_candidate_alerts": (
                preserved_count
            ),

            "missing_candidate_alerts": (
                missing_count
            ),

            "additional_candidate_alerts": (
                additional_count
            ),

            "candidate_alert_preservation_percentage": (
                snort_preservation_rate
            ),

            "missing_alert_details": (
                missing_alert_details
            ),

            "additional_alert_details": (
                additional_alert_details
            ),
        },

        "p4": {
            "classified_packets": (
                p4_total_packets
            ),

            "candidate_packets": (
                p4_candidate_packets
            ),

            "no_match_packets": (
                p4_no_match_packets
            ),

            "ambiguous_packets": (
                p4_ambiguous_packets
            ),

            "candidate_packet_percentage": (
                p4_candidate_rate
            ),

            "baseline_candidate_alert_packets": (
                candidate_alert_packet_count
            ),

            "preserved_candidate_alert_packets": (
                covered_alert_packets
            ),

            "false_negative_alerts": len(
                p4_false_negative_alerts
            ),

            "false_negative_packets": len(
                p4_false_negative_packets
            ),

            "missing_classification_packets": len(
                missing_p4_packets
            ),

            "alert_packet_preservation_percentage": (
                p4_alert_packet_preservation
            ),

            "false_negative_details": (
                p4_false_negative_alerts
            ),

            "missing_classification_details": (
                missing_p4_classifications
            ),
        },

        "errors": errors,
        "warnings": warnings,
    }

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    output_path.write_text(
        json.dumps(
            report,
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    # ========================================================
    # Console
    # ========================================================

    print()
    print(
        "=== End-to-End Prefilter Validation ==="
    )
    print()

    print(
        "Rule sets"
    )
    print(
        "-" * 55
    )

    print(
        f"Candidate SIDs             : "
        f"{len(candidate_sids)}"
    )

    print(
        f"Unsupported SIDs           : "
        f"{len(unsupported_sids)}"
    )

    print()

    print(
        "Snort"
    )
    print(
        "-" * 55
    )

    print(
        f"Baseline alerts            : "
        f"{len(baseline_alerts)}"
    )

    print(
        f"Baseline candidate alerts  : "
        f"{len(baseline_candidate_alerts)}"
    )

    print(
        f"Baseline unsupported alerts: "
        f"{len(baseline_unsupported_alerts)}"
    )

    print(
        f"Candidate-run alerts       : "
        f"{len(candidate_alerts)}"
    )

    print(
        f"Preserved candidate alerts : "
        f"{preserved_count}"
    )

    print(
        f"Missing candidate alerts   : "
        f"{missing_count}"
    )

    print(
        f"Additional alerts          : "
        f"{additional_count}"
    )

    print(
        f"Alert preservation         : "
        f"{snort_preservation_rate:.2f}%"
    )

    print()

    print(
        "P4 / BMv2"
    )
    print(
        "-" * 55
    )

    print(
        f"Classified packets         : "
        f"{p4_total_packets}"
    )

    print(
        f"Candidate packets          : "
        f"{p4_candidate_packets}"
    )

    print(
        f"No-match packets           : "
        f"{p4_no_match_packets}"
    )

    print(
        f"Ambiguous packets          : "
        f"{p4_ambiguous_packets}"
    )

    print(
        f"Alert-bearing candidate pkts: "
        f"{candidate_alert_packet_count}"
    )

    print(
        f"P4 false-negative alerts   : "
        f"{len(p4_false_negative_alerts)}"
    )

    print(
        f"P4 false-negative packets  : "
        f"{len(p4_false_negative_packets)}"
    )

    print(
        f"P4 alert preservation      : "
        f"{p4_alert_packet_preservation:.2f}%"
    )

    print()

    if warnings:

        print(
            "Warnings"
        )
        print(
            "-" * 55
        )

        for warning in warnings:

            print(
                f"- {warning}"
            )

        print()

    if errors:

        print(
            "Errors"
        )
        print(
            "-" * 55
        )

        for error in errors:

            print(
                f"- {error}"
            )

        print()

    print(
        f"Validation status          : "
        f"{status}"
    )

    print(
        f"Report                     : "
        f"{output_path}"
    )

    if errors:

        sys.exit(1)


if __name__ == "__main__":
    main()
    
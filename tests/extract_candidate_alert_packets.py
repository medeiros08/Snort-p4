import argparse
import json
import re
import sys

from pathlib import Path

from scapy.all import PcapReader, PcapWriter


PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parents[1]
)

CANDIDATE_RULES = (
    PROJECT_ROOT
    / "output"
    / "snort_candidate.rules"
)

SID_RE = re.compile(
    r"\bsid\s*:\s*(\d+)\s*;",
    re.IGNORECASE,
)


def load_candidate_sids():

    text = CANDIDATE_RULES.read_text(
        encoding="utf-8",
        errors="replace",
    )

    return {
        int(match.group(1))
        for match
        in SID_RE.finditer(text)
    }


def load_alert_packets(
    alert_file,
    candidate_sids,
):

    packet_numbers = set()

    candidate_alerts = 0
    all_alerts = 0

    with open(
        alert_file,
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

                alert = json.loads(line)

            except json.JSONDecodeError as error:

                raise ValueError(
                    f"Invalid JSON at "
                    f"line {line_number}: {error}"
                )

            all_alerts += 1

            sid = int(
                alert.get(
                    "sid",
                    -1,
                )
            )

            if sid not in candidate_sids:
                continue

            pkt_num = int(
                alert.get(
                    "pkt_num",
                    -1,
                )
            )

            if pkt_num <= 0:

                raise ValueError(
                    "Candidate alert without "
                    f"valid pkt_num: {alert}"
                )

            candidate_alerts += 1

            packet_numbers.add(
                pkt_num
            )

    return (
        packet_numbers,
        all_alerts,
        candidate_alerts,
    )


def main():

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "pcap",
        help="Original PCAP",
    )

    parser.add_argument(
        "alerts",
        help="Snort FULL alert JSONL",
    )

    parser.add_argument(
        "--output",
        default=None,
    )

    args = parser.parse_args()

    pcap_path = Path(
        args.pcap
    ).resolve()

    alerts_path = Path(
        args.alerts
    ).resolve()

    if not pcap_path.exists():

        print(
            f"ERROR: PCAP not found: "
            f"{pcap_path}"
        )

        sys.exit(1)

    if not alerts_path.exists():

        print(
            f"ERROR: alerts not found: "
            f"{alerts_path}"
        )

        sys.exit(1)

    if not CANDIDATE_RULES.exists():

        print(
            f"ERROR: candidate rules not found: "
            f"{CANDIDATE_RULES}"
        )

        sys.exit(1)

    if args.output:

        output_path = Path(
            args.output
        ).resolve()

    else:

        output_path = (
            PROJECT_ROOT
            / "output"
            / (
                pcap_path.stem
                + "_candidate_alert_packets.pcap"
            )
        )

    candidate_sids = (
        load_candidate_sids()
    )

    try:

        (
            target_packets,
            total_alerts,
            candidate_alerts,
        ) = load_alert_packets(
            alerts_path,
            candidate_sids,
        )

    except Exception as error:

        print(
            f"ERROR: {error}"
        )

        sys.exit(1)

    print()
    print(
        "=== Candidate Alert Packet Extraction ==="
    )
    print()

    print(
        f"Candidate SIDs           : "
        f"{len(candidate_sids)}"
    )

    print(
        f"Total baseline alerts    : "
        f"{total_alerts}"
    )

    print(
        f"Candidate alerts         : "
        f"{candidate_alerts}"
    )

    print(
        f"Unique alert packets     : "
        f"{len(target_packets)}"
    )

    print()

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    writer = PcapWriter(
        str(output_path),
        append=False,
        sync=True,
    )

    extracted = 0
    input_packets = 0
    missing = set(
        target_packets
    )

    try:

        with PcapReader(
            str(pcap_path)
        ) as reader:

            for pkt_num, packet in enumerate(
                reader,
                start=1,
            ):

                input_packets += 1

                if pkt_num not in target_packets:
                    continue

                writer.write(
                    packet
                )

                extracted += 1

                missing.discard(
                    pkt_num
                )

    finally:

        writer.close()

    print(
        f"Input PCAP packets       : "
        f"{input_packets}"
    )

    print(
        f"Extracted packets        : "
        f"{extracted}"
    )

    print(
        f"Missing packet numbers   : "
        f"{len(missing)}"
    )

    print(
        f"Output                   : "
        f"{output_path}"
    )

    print()

    if missing:

        print(
            "Extraction status       : INVALID"
        )

        print(
            f"Missing pkt_num values   : "
            f"{sorted(missing)[:50]}"
        )

        sys.exit(1)

    if extracted != len(
        target_packets
    ):

        print(
            "Extraction status       : INVALID"
        )

        sys.exit(1)

    print(
        "Extraction status       : VALID"
    )


if __name__ == "__main__":
    main()
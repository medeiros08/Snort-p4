import argparse
import json
import sys
import time

from pathlib import Path

import grpc

from google.protobuf import text_format

from scapy.all import (
    PcapReader,
    sendp,
)

from p4.v1 import p4runtime_pb2
from p4.v1 import p4runtime_pb2_grpc
from p4.config.v1 import p4info_pb2


PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parents[1]
)

P4INFO_FILE = (
    PROJECT_ROOT
    / "output"
    / "ids_prefilter.p4info.txt"
)

GRPC_ADDRESS = "127.0.0.1:9559"
DEVICE_ID = 0

COUNTER_NAME = (
    "MyIngress.prefilter_counter"
)


def load_p4info():

    p4info = p4info_pb2.P4Info()

    text = P4INFO_FILE.read_text(
        encoding="utf-8",
        errors="ignore",
    )

    text_format.Merge(
        text,
        p4info,
    )

    return p4info


def find_counter_id(p4info):

    for counter in p4info.counters:

        if (
            counter.preamble.name
            == COUNTER_NAME
            or
            counter.preamble.alias
            == "prefilter_counter"
        ):

            return counter.preamble.id

    raise RuntimeError(
        "prefilter_counter not found"
    )


def read_counter(
    stub,
    counter_id,
    index,
):

    request = (
        p4runtime_pb2.ReadRequest()
    )

    request.device_id = DEVICE_ID

    entity = request.entities.add()

    entity.counter_entry.counter_id = (
        counter_id
    )

    entity.counter_entry.index.index = (
        index
    )

    for response in stub.Read(
        request
    ):

        for result in response.entities:

            if result.HasField(
                "counter_entry"
            ):

                data = (
                    result
                    .counter_entry
                    .data
                )

                return {
                    "packets": int(
                        data.packet_count
                    ),

                    "bytes": int(
                        data.byte_count
                    ),
                }

    return {
        "packets": 0,
        "bytes": 0,
    }


def read_counters(
    stub,
    counter_id,
):

    return {
        "candidate": read_counter(
            stub,
            counter_id,
            0,
        ),

        "no_match": read_counter(
            stub,
            counter_id,
            1,
        ),
    }


def delta(
    after,
    before,
):

    return {
        "packets": (
            after["packets"]
            - before["packets"]
        ),

        "bytes": (
            after["bytes"]
            - before["bytes"]
        ),
    }


def main():

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "pcap",
    )

    parser.add_argument(
        "--interface",
        default="veth1",
    )

    parser.add_argument(
        "--batch-size",
        type=int,
        default=1000,
    )

    parser.add_argument(
        "--inter",
        type=float,
        default=0.0,
    )

    parser.add_argument(
        "--output",
        default=None,
    )

    args = parser.parse_args()

    pcap_path = Path(
        args.pcap
    ).resolve()

    if not pcap_path.exists():

        print(
            f"ERROR: PCAP not found: "
            f"{pcap_path}"
        )

        sys.exit(1)

    if args.batch_size <= 0:

        print(
            "ERROR: batch-size must be > 0"
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
                + "_bmv2_bulk.json"
            )
        )

    # --------------------------------------------------------
    # P4Runtime
    # --------------------------------------------------------

    channel = grpc.insecure_channel(
        GRPC_ADDRESS
    )

    try:

        grpc.channel_ready_future(
            channel
        ).result(
            timeout=5
        )

    except grpc.FutureTimeoutError:

        print(
            "ERROR: BMv2 P4Runtime server "
            "is not reachable."
        )

        sys.exit(1)

    stub = (
        p4runtime_pb2_grpc
        .P4RuntimeStub(
            channel
        )
    )

    p4info = load_p4info()

    counter_id = find_counter_id(
        p4info
    )

    before = read_counters(
        stub,
        counter_id,
    )

    # --------------------------------------------------------
    # Replay
    # --------------------------------------------------------

    print()
    print(
        "=== Bulk BMv2 PCAP Classification ==="
    )
    print()

    print(
        f"PCAP       : {pcap_path}"
    )

    print(
        f"Interface  : {args.interface}"
    )

    print(
        f"Batch size : {args.batch_size}"
    )

    print(
        f"Inter      : {args.inter}"
    )

    print()

    total_sent = 0
    total_input_bytes = 0

    batch = []

    start = time.time()

    with PcapReader(
        str(pcap_path)
    ) as reader:

        for packet in reader:

            batch.append(
                packet
            )

            total_input_bytes += len(
                bytes(packet)
            )

            if (
                len(batch)
                >= args.batch_size
            ):

                sendp(
                    batch,
                    iface=args.interface,
                    inter=args.inter,
                    verbose=False,
                )

                total_sent += len(
                    batch
                )

                print(
                    f"\rSent: {total_sent}",
                    end="",
                    flush=True,
                )

                batch = []

        if batch:

            sendp(
                batch,
                iface=args.interface,
                inter=args.inter,
                verbose=False,
            )

            total_sent += len(
                batch
            )

    print()

    # Allow BMv2 counters to settle.
    time.sleep(1.0)

    elapsed = (
        time.time()
        - start
    )

    after = read_counters(
        stub,
        counter_id,
    )

    candidate = delta(
        after["candidate"],
        before["candidate"],
    )

    no_match = delta(
        after["no_match"],
        before["no_match"],
    )

    observed_packets = (
        candidate["packets"]
        + no_match["packets"]
    )

    observed_bytes = (
        candidate["bytes"]
        + no_match["bytes"]
    )

    packet_accounting_ok = (
        observed_packets
        == total_sent
    )

    if observed_packets:

        candidate_packet_rate = (
            candidate["packets"]
            / observed_packets
            * 100.0
        )

        no_match_packet_rate = (
            no_match["packets"]
            / observed_packets
            * 100.0
        )

    else:

        candidate_packet_rate = 0.0
        no_match_packet_rate = 0.0

    if observed_bytes:

        candidate_byte_rate = (
            candidate["bytes"]
            / observed_bytes
            * 100.0
        )

        no_match_byte_rate = (
            no_match["bytes"]
            / observed_bytes
            * 100.0
        )

    else:

        candidate_byte_rate = 0.0
        no_match_byte_rate = 0.0

    report = {
        "pcap": str(
            pcap_path
        ),

        "interface": (
            args.interface
        ),

        "input_packets": (
            total_sent
        ),

        "input_bytes": (
            total_input_bytes
        ),

        "candidate": (
            candidate
        ),

        "no_match": (
            no_match
        ),

        "observed_packets": (
            observed_packets
        ),

        "observed_bytes": (
            observed_bytes
        ),

        "candidate_packet_percentage": (
            candidate_packet_rate
        ),

        "no_match_packet_percentage": (
            no_match_packet_rate
        ),

        "candidate_byte_percentage": (
            candidate_byte_rate
        ),

        "no_match_byte_percentage": (
            no_match_byte_rate
        ),

        "packet_accounting_ok": (
            packet_accounting_ok
        ),

        "elapsed_seconds": (
            elapsed
        ),
    }

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    output_path.write_text(
        json.dumps(
            report,
            indent=2,
        ),
        encoding="utf-8",
    )

    print()
    print(
        "Results"
    )
    print(
        "-" * 55
    )

    print(
        f"Input packets       : "
        f"{total_sent}"
    )

    print(
        f"Observed packets    : "
        f"{observed_packets}"
    )

    print(
        f"Candidate packets   : "
        f"{candidate['packets']}"
    )

    print(
        f"No-match packets    : "
        f"{no_match['packets']}"
    )

    print()

    print(
        f"Candidate pkt rate  : "
        f"{candidate_packet_rate:.2f}%"
    )

    print(
        f"No-match pkt rate   : "
        f"{no_match_packet_rate:.2f}%"
    )

    print()

    print(
        f"Candidate byte rate : "
        f"{candidate_byte_rate:.2f}%"
    )

    print(
        f"No-match byte rate  : "
        f"{no_match_byte_rate:.2f}%"
    )

    print()

    print(
        f"Elapsed             : "
        f"{elapsed:.2f}s"
    )

    print(
        f"Packet accounting   : "
        f"{'VALID' if packet_accounting_ok else 'INVALID'}"
    )

    print(
        f"Output              : "
        f"{output_path}"
    )

    channel.close()

    if not packet_accounting_ok:

        sys.exit(1)


if __name__ == "__main__":
    main()
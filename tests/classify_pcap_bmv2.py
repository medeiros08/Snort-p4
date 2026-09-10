import argparse
import json
import sys
import time
from pathlib import Path

import grpc

from google.protobuf import text_format

from scapy.all import rdpcap, sendp

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

    responses = stub.Read(
        request
    )

    for response in responses:

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
                    "packets": data.packet_count,
                    "bytes": data.byte_count,
                }

    return {
        "packets": 0,
        "bytes": 0,
    }


def read_all(
    stub,
    counter_id,
):

    return {
        "candidate": read_counter(
            stub,
            counter_id,
            0,
        ),

        "miss": read_counter(
            stub,
            counter_id,
            1,
        ),
    }


def main():

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "pcap",
        help="PCAP file to classify",
    )

    parser.add_argument(
        "--interface",
        default="veth1",
    )

    parser.add_argument(
        "--output",
        default=None,
    )

    parser.add_argument(
        "--delay",
        type=float,
        default=0.20,
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
                + "_p4_classification.jsonl"
            )
        )

    packets = rdpcap(
        str(pcap_path)
    )

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
            "ERROR: BMv2 is not reachable."
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

    print()
    print(
        "=== PCAP -> BMv2 Classification ==="
    )
    print()

    print(
        f"PCAP       : {pcap_path}"
    )

    print(
        f"Packets    : {len(packets)}"
    )

    print(
        f"Interface  : {args.interface}"
    )

    print(
        f"Counter ID : {counter_id}"
    )

    print()

    results = []

    candidate_count = 0
    miss_count = 0
    ambiguous_count = 0

    for pkt_num, packet in enumerate(
        packets,
        start=1,
    ):

        before = read_all(
            stub,
            counter_id,
        )

        sendp(
            packet,
            iface=args.interface,
            count=1,
            verbose=False,
        )

        time.sleep(
            args.delay
        )

        after = read_all(
            stub,
            counter_id,
        )

        candidate_delta = (
            after["candidate"]["packets"]
            - before["candidate"]["packets"]
        )

        miss_delta = (
            after["miss"]["packets"]
            - before["miss"]["packets"]
        )

        if (
            candidate_delta == 1
            and
            miss_delta == 0
        ):

            classification = (
                "CANDIDATE"
            )

            candidate_count += 1

        elif (
            candidate_delta == 0
            and
            miss_delta == 1
        ):

            classification = (
                "NO_MATCH"
            )

            miss_count += 1

        else:

            classification = (
                "AMBIGUOUS"
            )

            ambiguous_count += 1

        record = {
            "pkt_num": pkt_num,

            "classification": (
                classification
            ),

            "candidate_delta": (
                candidate_delta
            ),

            "miss_delta": (
                miss_delta
            ),

            "packet_length": len(
                bytes(packet)
            ),
        }

        results.append(
            record
        )

        print(
            f"{pkt_num:>5}/"
            f"{len(packets):<5} "
            f"{classification}"
        )

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with open(
        output_path,
        "w",
        encoding="utf-8",
    ) as file:

        for record in results:

            file.write(
                json.dumps(
                    record
                )
                + "\n"
            )

    print()
    print(
        "Summary"
    )
    print(
        "-" * 50
    )

    print(
        f"Candidate : {candidate_count}"
    )

    print(
        f"No match  : {miss_count}"
    )

    print(
        f"Ambiguous : {ambiguous_count}"
    )

    print(
        f"Total     : {len(results)}"
    )

    print()

    print(
        f"Output    : {output_path}"
    )

    if ambiguous_count:

        print()
        print(
            "Classification status: "
            "AMBIGUOUS_RESULTS"
        )

        sys.exit(1)

    print()
    print(
        "Classification status: VALID"
    )

    channel.close()


if __name__ == "__main__":
    main()
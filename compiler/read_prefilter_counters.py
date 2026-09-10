import sys
from pathlib import Path

import grpc

from google.protobuf import text_format

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


def find_counter(p4info):

    for counter in p4info.counters:

        if (
            counter.preamble.name
            == COUNTER_NAME
            or
            counter.preamble.alias
            == "prefilter_counter"
        ):
            return counter

    return None


def read_counter_index(
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

        for result_entity in response.entities:

            if result_entity.HasField(
                "counter_entry"
            ):

                data = (
                    result_entity
                    .counter_entry
                    .data
                )

                return {
                    "packets": (
                        data.packet_count
                    ),

                    "bytes": (
                        data.byte_count
                    ),
                }

    return {
        "packets": 0,
        "bytes": 0,
    }


def main():

    print()
    print(
        "=== Prefilter Counters ==="
    )
    print()

    if not P4INFO_FILE.exists():

        print(
            "ERROR: P4Info not found:"
        )

        print(
            P4INFO_FILE
        )

        sys.exit(1)

    p4info = load_p4info()

    counter = find_counter(
        p4info
    )

    if counter is None:

        print(
            "ERROR: prefilter_counter "
            "not found in P4Info."
        )

        sys.exit(1)

    counter_id = (
        counter.preamble.id
    )

    print(
        f"Counter ID       : "
        f"{counter_id}"
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
            "ERROR: BMv2 P4Runtime "
            "server is not reachable."
        )

        sys.exit(1)

    stub = (
        p4runtime_pb2_grpc
        .P4RuntimeStub(
            channel
        )
    )

    candidate = (
        read_counter_index(
            stub,
            counter_id,
            0,
        )
    )

    no_match = (
        read_counter_index(
            stub,
            counter_id,
            1,
        )
    )

    packet_domain_fallback = (
        read_counter_index(
            stub,
            counter_id,
            2,
        )
    )

    total_packets = (
        candidate["packets"]
        + no_match["packets"]
        + packet_domain_fallback["packets"]
    )

    total_bytes = (
        candidate["bytes"]
        + no_match["bytes"]
        + packet_domain_fallback["bytes"]
    )

    print()
    print(
        "Candidate / table hit"
    )
    print(
        "-" * 45
    )

    print(
        f"Packets          : "
        f"{candidate['packets']}"
    )

    print(
        f"Bytes            : "
        f"{candidate['bytes']}"
    )

    print()
    print(
        "No prefilter match"
    )
    print(
        "-" * 45
    )

    print(
        f"Packets          : "
        f"{no_match['packets']}"
    )

    print(
        f"Bytes            : "
        f"{no_match['bytes']}"
    )

    print()
    print(
        "Packet-domain fallback"
    )
    print(
        "-" * 45
    )

    print(
        f"Packets          : "
        f"{packet_domain_fallback['packets']}"
    )

    print(
        f"Bytes            : "
        f"{packet_domain_fallback['bytes']}"
    )

    print()
    print(
        "Totals"
    )
    print(
        "-" * 45
    )

    print(
        f"Packets          : "
        f"{total_packets}"
    )

    print(
        f"Bytes            : "
        f"{total_bytes}"
    )

    table_accounted_packets = (
        candidate["packets"]
        + no_match["packets"]
    )

    if table_accounted_packets:

        hit_rate = (
            candidate["packets"]
            / table_accounted_packets
            * 100
        )

        miss_rate = (
            no_match["packets"]
            / table_accounted_packets
            * 100
        )

        print()

        print(
            f"Candidate rate (supported domain): "
            f"{hit_rate:.2f}%"
        )

        print(
            f"No-match rate (supported domain): "
            f"{miss_rate:.2f}%"
        )

    channel.close()


if __name__ == "__main__":
    main()

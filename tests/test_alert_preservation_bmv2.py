import sys
import time
from pathlib import Path

import grpc

from google.protobuf import text_format

from scapy.all import (
    rdpcap,
    sendp,
)

from p4.v1 import p4runtime_pb2
from p4.v1 import p4runtime_pb2_grpc
from p4.config.v1 import p4info_pb2


# ============================================================
# Configuration
# ============================================================


PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parents[1]
)


PCAP_FILE = (
    PROJECT_ROOT
    / "output"
    / "alert_preservation_controlled.pcap"
)


P4INFO_FILE = (
    PROJECT_ROOT
    / "output"
    / "ids_prefilter.p4info.txt"
)


INTERFACE = "veth1"

GRPC_ADDRESS = "127.0.0.1:9559"

DEVICE_ID = 0

COUNTER_NAME = (
    "MyIngress.prefilter_counter"
)


EXPECTED = [
    {
        "packet": 1,
        "sid": 221,
    },
    {
        "packet": 2,
        "sid": 225,
    },
    {
        "packet": 3,
        "sid": 382,
    },
]


# ============================================================
# P4Info
# ============================================================


def load_p4info():

    p4info = (
        p4info_pb2.P4Info()
    )

    text = P4INFO_FILE.read_text(
        encoding="utf-8",
        errors="ignore",
    )

    text_format.Merge(
        text,
        p4info,
    )

    return p4info


def find_counter_id(
    p4info
):

    for counter in p4info.counters:

        if (
            counter.preamble.name
            == COUNTER_NAME
            or
            counter.preamble.alias
            == "prefilter_counter"
        ):

            return (
                counter.preamble.id
            )

    raise RuntimeError(
        "prefilter_counter "
        "not found in P4Info"
    )


# ============================================================
# Counter reader
# ============================================================


def read_counter(
    stub,
    counter_id,
    index,
):

    request = (
        p4runtime_pb2
        .ReadRequest()
    )

    request.device_id = (
        DEVICE_ID
    )

    entity = (
        request.entities.add()
    )

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

        "miss": read_counter(
            stub,
            counter_id,
            1,
        ),
    }


# ============================================================
# Main
# ============================================================


def main():

    print()
    print(
        "=== Controlled Alert Preservation: BMv2 ==="
    )
    print()

    if not PCAP_FILE.exists():

        print(
            f"ERROR: PCAP not found: "
            f"{PCAP_FILE}"
        )

        sys.exit(1)

    if not P4INFO_FILE.exists():

        print(
            f"ERROR: P4Info not found: "
            f"{P4INFO_FILE}"
        )

        sys.exit(1)

    packets = rdpcap(
        str(
            PCAP_FILE
        )
    )

    if len(packets) != 3:

        print(
            f"ERROR: Expected 3 packets, "
            f"found {len(packets)}"
        )

        sys.exit(1)

    # --------------------------------------------------------
    # P4Runtime connection
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

    p4info = load_p4info()

    counter_id = find_counter_id(
        p4info
    )

    print(
        f"Counter ID        : "
        f"{counter_id}"
    )

    print(
        f"Interface         : "
        f"{INTERFACE}"
    )

    print(
        f"Packets in PCAP   : "
        f"{len(packets)}"
    )

    print()

    failures = []

    # ========================================================
    # Test packet by packet
    # ========================================================

    for index, packet in enumerate(
        packets,
        start=1,
    ):

        expected = EXPECTED[
            index - 1
        ]

        before = read_counters(
            stub,
            counter_id,
        )

        sendp(
            packet,
            iface=INTERFACE,
            count=1,
            verbose=False,
        )

        time.sleep(
            0.4
        )

        after = read_counters(
            stub,
            counter_id,
        )

        candidate_delta = (
            after[
                "candidate"
            ][
                "packets"
            ]
            -
            before[
                "candidate"
            ][
                "packets"
            ]
        )

        miss_delta = (
            after[
                "miss"
            ][
                "packets"
            ]
            -
            before[
                "miss"
            ][
                "packets"
            ]
        )

        valid = (
            candidate_delta == 1
            and
            miss_delta == 0
        )

        status = (
            "PASS"
            if valid
            else "FAIL"
        )

        print(
            f"Packet {index} | "
            f"SID {expected['sid']} | "
            f"candidate +{candidate_delta} | "
            f"miss +{miss_delta} | "
            f"{status}"
        )

        if not valid:

            failures.append(
                {
                    "packet": index,
                    "sid": (
                        expected[
                            "sid"
                        ]
                    ),
                    "candidate_delta": (
                        candidate_delta
                    ),
                    "miss_delta": (
                        miss_delta
                    ),
                }
            )

    # ========================================================
    # Final result
    # ========================================================

    print()
    print(
        "-" * 70
    )

    if not failures:

        print(
            "Alert-preservation prefilter "
            "test status: VALID"
        )

        print()

        print(
            "Observed:"
        )

        print(
            "  SID 221 -> P4 candidate"
        )

        print(
            "  SID 225 -> P4 candidate"
        )

        print(
            "  SID 382 -> P4 candidate"
        )

        print()

        print(
            "Controlled false negatives: 0"
        )

    else:

        print(
            "Alert-preservation prefilter "
            "test status: INVALID"
        )

        print()

        for failure in failures:

            print(
                failure
            )

        sys.exit(1)

    channel.close()


if __name__ == "__main__":
    main()
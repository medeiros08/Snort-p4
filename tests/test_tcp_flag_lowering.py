import ipaddress
import json
import sys
import time
from pathlib import Path

import grpc

from scapy.all import (
    Ether,
    IP,
    TCP,
    Raw,
    sendp,
)

from google.protobuf import text_format

from p4.v1 import p4runtime_pb2
from p4.v1 import p4runtime_pb2_grpc
from p4.config.v1 import p4info_pb2


# ============================================================
# Paths / configuration
# ============================================================


PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parents[1]
)

NORMALIZED_FILE = (
    PROJECT_ROOT
    / "output"
    / "p4runtime_entries.json"
)

FINAL_FILE = (
    PROJECT_ROOT
    / "output"
    / "p4_install_entries.json"
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


# ============================================================
# JSON
# ============================================================


def load_entries(path):

    with open(
        path,
        "r",
        encoding="utf-8",
    ) as file:

        data = json.load(file)

    if isinstance(data, list):

        return data

    return data.get(
        "entries",
        [],
    )


# ============================================================
# IP helpers
# ============================================================


def choose_ip(
    condition,
    default,
):

    if not condition:

        return default

    address = condition[
        "value"
    ]

    prefix_len = int(
        condition[
            "prefix_len"
        ]
    )

    network = ipaddress.ip_network(
        f"{address}/{prefix_len}",
        strict=False,
    )

    if network.num_addresses > 2:

        return str(
            network.network_address
            + 1
        )

    return str(
        network.network_address
    )


def ip_matches(
    address,
    condition,
):

    if not condition:

        return True

    network = ipaddress.ip_network(
        f"{condition['value']}/"
        f"{condition['prefix_len']}",
        strict=False,
    )

    return (
        ipaddress.ip_address(
            address
        )
        in network
    )


# ============================================================
# TCP flags
# ============================================================


FLAG_NAMES = {
    0x80: "C",
    0x40: "E",
    0x20: "U",
    0x10: "A",
    0x08: "P",
    0x04: "R",
    0x02: "S",
    0x01: "F",
}


def flag_integer_to_scapy(
    value
):

    result = ""

    for bit in [
        0x80,
        0x40,
        0x20,
        0x10,
        0x08,
        0x04,
        0x02,
        0x01,
    ]:

        if value & bit:

            result += FLAG_NAMES[
                bit
            ]

    return result or 0


def bit_names(
    value
):

    names = []

    for bit, name in FLAG_NAMES.items():

        if value & bit:

            names.append(
                name
            )

    return names


# ============================================================
# Find '*' expressions before lowering
# ============================================================


def find_star_entries(
    normalized_entries
):

    results = []

    seen = set()

    for entry in normalized_entries:

        match = entry.get(
            "match",
            {},
        )

        flags = match.get(
            "tcp_flags"
        )

        if not isinstance(
            flags,
            dict,
        ):

            continue

        modifier = flags.get(
            "modifier"
        )

        if modifier != "*":

            continue

        test_mask = int(
            flags.get(
                "test_mask",
                0,
            )
        )

        ignore_mask = int(
            flags.get(
                "ignore_mask",
                0,
            )
        )

        effective = (
            test_mask
            & (
                ~ignore_mask
                & 0xFF
            )
        )

        if effective == 0:

            continue

        # Semantic identity before flag lowering.
        non_flag_match = {
            key: value

            for key, value
            in match.items()

            if key != "tcp_flags"
        }

        key = json.dumps(
            {
                "match": non_flag_match,
                "effective": effective,
            },
            sort_keys=True,
        )

        if key in seen:

            continue

        seen.add(
            key
        )

        results.append(
            {
                "source_entry": entry,
                "non_flag_match": (
                    non_flag_match
                ),
                "flags": flags,
                "effective": effective,
            }
        )

    return results


# ============================================================
# Descriptor
# ============================================================


def build_descriptor(
    star_case,
    flag_value,
):

    match = star_case[
        "non_flag_match"
    ]

    protocol = int(
        match.get(
            "protocol",
            6,
        )
    )

    src_ip = choose_ip(
        match.get(
            "src_ip"
        ),
        "192.0.2.10",
    )

    dst_ip = choose_ip(
        match.get(
            "dst_ip"
        ),
        "198.51.100.20",
    )

    src_port = int(
        match.get(
            "src_port",
            40000,
        )
    )

    dst_port = int(
        match.get(
            "dst_port",
            40001,
        )
    )

    return {
        "protocol": protocol,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "tcp_flags": flag_value,
    }


# ============================================================
# Local evaluation of final installed entries
# ============================================================


def final_entry_matches(
    entry,
    descriptor,
):

    match = entry.get(
        "match",
        {},
    )

    if (
        "protocol" in match
        and
        int(
            match[
                "protocol"
            ]
        )
        != descriptor[
            "protocol"
        ]
    ):

        return False

    if not ip_matches(
        descriptor[
            "src_ip"
        ],
        match.get(
            "src_ip"
        ),
    ):

        return False

    if not ip_matches(
        descriptor[
            "dst_ip"
        ],
        match.get(
            "dst_ip"
        ),
    ):

        return False

    if (
        "src_port" in match
        and
        int(
            match[
                "src_port"
            ]
        )
        != descriptor[
            "src_port"
        ]
    ):

        return False

    if (
        "dst_port" in match
        and
        int(
            match[
                "dst_port"
            ]
        )
        != descriptor[
            "dst_port"
        ]
    ):

        return False

    if "tcp_flags" in match:

        flags = match[
            "tcp_flags"
        ]

        value = int(
            flags[
                "value"
            ]
        )

        mask = int(
            flags[
                "mask"
            ]
        )

        if (
            descriptor[
                "tcp_flags"
            ]
            & mask
        ) != (
            value
            & mask
        ):

            return False

    return True


def matching_final_entries(
    final_entries,
    descriptor,
):

    return [
        entry

        for entry in final_entries

        if final_entry_matches(
            entry,
            descriptor,
        )
    ]


# ============================================================
# Packet construction
# ============================================================


def build_packet(
    descriptor,
):

    ethernet = Ether(
        src="02:00:00:00:10:01",
        dst="02:00:00:00:10:02",
    )

    ipv4 = IP(
        src=descriptor[
            "src_ip"
        ],
        dst=descriptor[
            "dst_ip"
        ],
        proto=6,
    )

    tcp = TCP(
        sport=descriptor[
            "src_port"
        ],
        dport=descriptor[
            "dst_port"
        ],
        flags=flag_integer_to_scapy(
            descriptor[
                "tcp_flags"
            ]
        ),
    )

    return (
        ethernet
        / ipv4
        / tcp
        / Raw(
            b"P4FLAGTEST"
        )
    )


# ============================================================
# P4Runtime counter reader
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

                return {
                    "packets": (
                        result
                        .counter_entry
                        .data
                        .packet_count
                    ),

                    "bytes": (
                        result
                        .counter_entry
                        .data
                        .byte_count
                    ),
                }

    return {
        "packets": 0,
        "bytes": 0,
    }


# ============================================================
# Main
# ============================================================


def main():

    print()
    print(
        "=== TCP Flag Lowering Functional Test ==="
    )
    print()

    for path in [
        NORMALIZED_FILE,
        FINAL_FILE,
        P4INFO_FILE,
    ]:

        if not path.exists():

            print(
                f"ERROR: Missing file: {path}"
            )

            sys.exit(1)

    normalized_entries = (
        load_entries(
            NORMALIZED_FILE
        )
    )

    final_entries = (
        load_entries(
            FINAL_FILE
        )
    )

    star_cases = (
        find_star_entries(
            normalized_entries
        )
    )

    print(
        f"Normalized entries     : "
        f"{len(normalized_entries)}"
    )

    print(
        f"Final install entries  : "
        f"{len(final_entries)}"
    )

    print(
        f"Distinct '*' cases     : "
        f"{len(star_cases)}"
    )

    print()

    if not star_cases:

        print(
            "ERROR: No TCP flag '*' "
            "expressions were found."
        )

        sys.exit(1)

    tests = []

    # ========================================================
    # Generate one packet for every branch of '*'
    # ========================================================

    for case_index, case in enumerate(
        star_cases,
        start=1,
    ):

        effective = case[
            "effective"
        ]

        bits = [
            bit

            for bit in [
                0x80,
                0x40,
                0x20,
                0x10,
                0x08,
                0x04,
                0x02,
                0x01,
            ]

            if effective & bit
        ]

        print(
            f"'*' case {case_index}"
        )

        print(
            f"  effective mask : "
            f"0x{effective:02x}"
        )

        print(
            f"  accepted flags : "
            f"{bit_names(effective)}"
        )

        print(
            f"  branches       : "
            f"{len(bits)}"
        )

        for bit in bits:

            descriptor = (
                build_descriptor(
                    case,
                    bit,
                )
            )

            matches = (
                matching_final_entries(
                    final_entries,
                    descriptor,
                )
            )

            if not matches:

                print()
                print(
                    "ERROR: A '*' branch does "
                    "not match any final P4 entry."
                )

                print(
                    f"Case: {case_index}"
                )

                print(
                    f"Flag: "
                    f"0x{bit:02x}"
                )

                print(
                    descriptor
                )

                sys.exit(1)

            tests.append(
                {
                    "case": case_index,
                    "flag_bit": bit,
                    "flag_name": (
                        FLAG_NAMES[
                            bit
                        ]
                    ),
                    "descriptor": (
                        descriptor
                    ),
                    "matches": (
                        matches
                    ),
                }
            )

        print()

    # ========================================================
    # Connect to BMv2
    # ========================================================

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

    before_hit = read_counter(
        stub,
        counter_id,
        0,
    )

    before_miss = read_counter(
        stub,
        counter_id,
        1,
    )

    print(
        "Counters before"
    )

    print(
        "-" * 55
    )

    print(
        f"Candidate packets : "
        f"{before_hit['packets']}"
    )

    print(
        f"No-match packets  : "
        f"{before_miss['packets']}"
    )

    print()

    # ========================================================
    # Send actual packets
    # ========================================================

    print(
        "Sending '*' branch packets"
    )

    print(
        "-" * 55
    )

    for index, test in enumerate(
        tests,
        start=1,
    ):

        packet = build_packet(
            test[
                "descriptor"
            ]
        )

        matching_ids = [
            entry.get(
                "install_entry_id"
            )

            for entry in test[
                "matches"
            ]
        ]

        print(
            f"{index:>2}. "
            f"case={test['case']} "
            f"flag={test['flag_name']} "
            f"(0x{test['flag_bit']:02x}) "
            f"local_matches="
            f"{matching_ids[:5]}"
        )

        sendp(
            packet,
            iface=INTERFACE,
            count=1,
            verbose=False,
        )

        time.sleep(
            0.20
        )

    time.sleep(
        0.5
    )

    # ========================================================
    # Read counters after
    # ========================================================

    after_hit = read_counter(
        stub,
        counter_id,
        0,
    )

    after_miss = read_counter(
        stub,
        counter_id,
        1,
    )

    hit_delta = (
        after_hit["packets"]
        - before_hit["packets"]
    )

    miss_delta = (
        after_miss["packets"]
        - before_miss["packets"]
    )

    expected_hits = len(
        tests
    )

    print()
    print(
        "Counters after"
    )

    print(
        "-" * 55
    )

    print(
        f"Candidate packets : "
        f"{after_hit['packets']}"
    )

    print(
        f"No-match packets  : "
        f"{after_miss['packets']}"
    )

    print()

    print(
        "Observed delta"
    )

    print(
        "-" * 55
    )

    print(
        f"Candidate delta   : "
        f"+{hit_delta}"
    )

    print(
        f"No-match delta    : "
        f"+{miss_delta}"
    )

    print()

    print(
        f"Expected candidate delta: "
        f"+{expected_hits}"
    )

    print()

    if (
        hit_delta
        == expected_hits
        and
        miss_delta
        == 0
    ):

        print(
            "TCP flag '*' lowering status: VALID"
        )

    else:

        print(
            "TCP flag '*' lowering status: "
            "UNEXPECTED_RESULT"
        )

        sys.exit(1)

    channel.close()


if __name__ == "__main__":
    main()
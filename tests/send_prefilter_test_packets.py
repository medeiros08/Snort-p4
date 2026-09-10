import ipaddress
import json
import sys
import time
from pathlib import Path

from scapy.all import (
    Ether,
    IP,
    TCP,
    UDP,
    ICMP,
    Raw,
    sendp,
)


PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parents[1]
)

ENTRIES_FILE = (
    PROJECT_ROOT
    / "output"
    / "p4_install_entries.json"
)

INTERFACE = "veth1"


# ============================================================
# Utilities
# ============================================================


def load_entries():

    with open(
        ENTRIES_FILE,
        "r",
        encoding="utf-8",
    ) as file:

        data = json.load(file)

    return data.get(
        "entries",
        [],
    )


def choose_ip(ip_match, default):

    if not ip_match:

        return default

    value = ip_match["value"]

    prefix_len = int(
        ip_match["prefix_len"]
    )

    network = ipaddress.ip_network(
        f"{value}/{prefix_len}",
        strict=False,
    )

    # Prefer a host-looking address when possible.
    if network.num_addresses > 2:

        return str(
            network.network_address + 1
        )

    return str(
        network.network_address
    )


def flags_integer_to_scapy(value):

    """
    P4 representation:

        C E U A P R S F
        7 6 5 4 3 2 1 0
    """

    mapping = [
        (0x80, "C"),
        (0x40, "E"),
        (0x20, "U"),
        (0x10, "A"),
        (0x08, "P"),
        (0x04, "R"),
        (0x02, "S"),
        (0x01, "F"),
    ]

    result = ""

    for bit, name in mapping:

        if value & bit:

            result += name

    return result or 0


# ============================================================
# Entry selection
# ============================================================


def find_protocol_entry(
    entries,
    protocol,
    avoid_flags=False,
):

    for entry in entries:

        match = entry.get(
            "match",
            {},
        )

        if match.get(
            "protocol"
        ) != protocol:

            continue

        if (
            avoid_flags
            and
            "tcp_flags" in match
        ):

            continue

        return entry

    return None


# ============================================================
# Packet construction from an install predicate
# ============================================================


def build_packet_from_entry(
    entry
):

    match = entry[
        "match"
    ]

    protocol = match.get(
        "protocol"
    )

    src_ip = choose_ip(
        match.get("src_ip"),
        "192.0.2.10",
    )

    dst_ip = choose_ip(
        match.get("dst_ip"),
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

    ethernet = Ether(
        src="02:00:00:00:00:01",
        dst="02:00:00:00:00:02",
    )

    ipv4 = IP(
        src=src_ip,
        dst=dst_ip,
    )

    # --------------------------------------------------------
    # TCP
    # --------------------------------------------------------

    if protocol == 6:

        ipv4.proto = 6

        flag_value = 0x02  # SYN by default

        if "tcp_flags" in match:

            flag_match = match[
                "tcp_flags"
            ]

            flag_value = int(
                flag_match[
                    "value"
                ]
            )

        tcp = TCP(
            sport=src_port,
            dport=dst_port,
            flags=flags_integer_to_scapy(
                flag_value
            ),
        )

        return (
            ethernet
            / ipv4
            / tcp
            / Raw(b"P4TEST")
        )

    # --------------------------------------------------------
    # UDP
    # --------------------------------------------------------

    if protocol == 17:

        ipv4.proto = 17

        udp = UDP(
            sport=src_port,
            dport=dst_port,
        )

        return (
            ethernet
            / ipv4
            / udp
            / Raw(b"P4TEST")
        )

    # --------------------------------------------------------
    # ICMP
    # --------------------------------------------------------

    if protocol == 1:

        ipv4.proto = 1

        return (
            ethernet
            / ipv4
            / ICMP(
                type=8,
                code=0,
            )
            / Raw(b"P4TEST")
        )

    raise ValueError(
        f"Unsupported test protocol: {protocol}"
    )


# ============================================================
# Local evaluator used to search for a guaranteed table miss
# ============================================================


def ip_matches(
    packet_ip,
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
            packet_ip
        )
        in network
    )


def entry_matches_descriptor(
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
        int(match["protocol"])
        != descriptor["protocol"]
    ):

        return False

    if not ip_matches(
        descriptor["src_ip"],
        match.get("src_ip"),
    ):

        return False

    if not ip_matches(
        descriptor["dst_ip"],
        match.get("dst_ip"),
    ):

        return False

    if (
        "src_port" in match
        and
        int(match["src_port"])
        != descriptor["src_port"]
    ):

        return False

    if (
        "dst_port" in match
        and
        int(match["dst_port"])
        != descriptor["dst_port"]
    ):

        return False

    if "tcp_flags" in match:

        condition = match[
            "tcp_flags"
        ]

        value = int(
            condition["value"]
        )

        mask = int(
            condition["mask"]
        )

        if (
            descriptor["tcp_flags"]
            & mask
        ) != (
            value
            & mask
        ):

            return False

    return True


def find_miss_descriptor(
    entries
):

    protocols = [
        47,   # GRE
        89,   # OSPF
        253,  # experimental
        6,
        17,
        1,
    ]

    source_ips = [
        "203.0.113.10",
        "198.51.100.10",
        "192.0.2.10",
        "172.31.255.254",
        "8.8.8.8",
    ]

    destination_ips = [
        "203.0.113.20",
        "198.51.100.20",
        "192.0.2.20",
        "172.31.255.253",
        "1.1.1.1",
    ]

    ports = [
        65000,
        54321,
        31337,
        65535,
        1,
    ]

    for protocol in protocols:

        for src_ip in source_ips:

            for dst_ip in destination_ips:

                for src_port in ports:

                    for dst_port in ports:

                        descriptor = {
                            "protocol": protocol,
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,

                            # Non-TCP/UDP protocols leave the
                            # generic L4 metadata at zero.
                            "src_port": (
                                src_port
                                if protocol in {6, 17}
                                else 0
                            ),

                            "dst_port": (
                                dst_port
                                if protocol in {6, 17}
                                else 0
                            ),

                            "tcp_flags": (
                                0x02
                                if protocol == 6
                                else 0
                            ),
                        }

                        matched = any(
                            entry_matches_descriptor(
                                entry,
                                descriptor,
                            )
                            for entry in entries
                        )

                        if not matched:

                            return descriptor

    return None


def build_miss_packet(
    descriptor
):

    ethernet = Ether(
        src="02:00:00:00:00:11",
        dst="02:00:00:00:00:12",
    )

    ipv4 = IP(
        src=descriptor["src_ip"],
        dst=descriptor["dst_ip"],
        proto=descriptor["protocol"],
    )

    protocol = descriptor[
        "protocol"
    ]

    if protocol == 6:

        return (
            ethernet
            / ipv4
            / TCP(
                sport=descriptor["src_port"],
                dport=descriptor["dst_port"],
                flags="S",
            )
            / Raw(b"P4MISS")
        )

    if protocol == 17:

        return (
            ethernet
            / ipv4
            / UDP(
                sport=descriptor["src_port"],
                dport=descriptor["dst_port"],
            )
            / Raw(b"P4MISS")
        )

    if protocol == 1:

        return (
            ethernet
            / ipv4
            / ICMP(
                type=8,
                code=0,
            )
            / Raw(b"P4MISS")
        )

    # Protocol such as GRE / OSPF / experimental.
    return (
        ethernet
        / ipv4
        / Raw(b"P4MISS")
    )


# ============================================================
# Main
# ============================================================


def main():

    print()
    print(
        "=== BMv2 Prefilter Functional Test ==="
    )
    print()

    if not ENTRIES_FILE.exists():

        print(
            "ERROR: install entries not found:"
        )

        print(
            ENTRIES_FILE
        )

        sys.exit(1)

    entries = load_entries()

    print(
        f"Install predicates : {len(entries)}"
    )

    print(
        f"Injection interface: {INTERFACE}"
    )

    print()

    # ========================================================
    # Find representative hits
    # ========================================================

    tcp_entry = find_protocol_entry(
        entries,
        6,
        avoid_flags=True,
    )

    udp_entry = find_protocol_entry(
        entries,
        17,
    )

    icmp_entry = find_protocol_entry(
        entries,
        1,
    )

    required = {
        "TCP": tcp_entry,
        "UDP": udp_entry,
        "ICMP": icmp_entry,
    }

    for name, entry in required.items():

        if entry is None:

            print(
                f"ERROR: Could not find "
                f"a {name} install predicate."
            )

            sys.exit(1)

    tests = []

    for name, entry in required.items():

        packet = (
            build_packet_from_entry(
                entry
            )
        )

        tests.append(
            {
                "name": name,
                "expected": "CANDIDATE",
                "entry_id": entry.get(
                    "install_entry_id"
                ),
                "match": entry.get(
                    "match"
                ),
                "packet": packet,
            }
        )

    # ========================================================
    # Find a locally verified miss
    # ========================================================

    miss_descriptor = (
        find_miss_descriptor(
            entries
        )
    )

    if miss_descriptor is None:

        print(
            "ERROR: Could not construct "
            "a guaranteed local table miss."
        )

        sys.exit(1)

    tests.append(
        {
            "name": "MISS",
            "expected": "NO_MATCH",
            "entry_id": None,
            "match": miss_descriptor,
            "packet": build_miss_packet(
                miss_descriptor
            ),
        }
    )

    # ========================================================
    # Display test plan
    # ========================================================

    print(
        "Test plan"
    )

    print(
        "-" * 70
    )

    for index, test in enumerate(
        tests,
        start=1,
    ):

        print(
            f"{index}. "
            f"{test['name']:<5} "
            f"expected={test['expected']}"
        )

        if test[
            "entry_id"
        ]:

            print(
                f"   install entry: "
                f"{test['entry_id']}"
            )

        print(
            f"   predicate    : "
            f"{test['match']}"
        )

    print()

    # ========================================================
    # Send
    # ========================================================

    for index, test in enumerate(
        tests,
        start=1,
    ):

        print(
            f"Sending {index}/"
            f"{len(tests)}: "
            f"{test['name']}"
        )

        sendp(
            test["packet"],
            iface=INTERFACE,
            count=1,
            verbose=False,
        )

        time.sleep(
            0.25
        )

    print()

    print(
        "Packets sent successfully."
    )

    print()

    print(
        "Expected counter delta:"
    )

    print(
        "  candidate / hit : +3 packets"
    )

    print(
        "  no-match        : +1 packet"
    )

    print()

    print(
        "Now read the counters."
    )


if __name__ == "__main__":
    main()
from pathlib import Path

from scapy.all import (
    Ether,
    IP,
    ICMP,
    Raw,
    wrpcap,
)


PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parents[1]
)

OUTPUT_FILE = (
    PROJECT_ROOT
    / "output"
    / "alert_preservation_controlled.pcap"
)


def ethernet():
    return Ether(
        src="02:00:00:00:20:01",
        dst="02:00:00:00:20:02",
    )


def packet_sid_221():
    """
    SID 221

    alert icmp $EXTERNAL_NET any -> $HOME_NET any
    icmp_id:678
    itype:8
    content:"1234"
    """

    return (
        ethernet()
        / IP(
            src="192.0.2.10",
            dst="10.0.0.10",
        )
        / ICMP(
            type=8,
            code=0,
            id=678,
            seq=1,
        )
        / Raw(b"1234")
    )


def packet_sid_225():
    """
    SID 225

    alert icmp $HOME_NET any -> $EXTERNAL_NET any
    icmp_id:669
    itype:0
    content:"sicken"
    """

    return (
        ethernet()
        / IP(
            src="10.0.0.10",
            dst="192.0.2.20",
        )
        / ICMP(
            type=0,
            code=0,
            id=669,
            seq=1,
        )
        / Raw(b"sicken")
    )


def packet_sid_382():
    """
    SID 382

    alert icmp $EXTERNAL_NET any -> $HOME_NET any
    itype:8
    content:"abcdefghijklmnop"
    depth 16
    """

    return (
        ethernet()
        / IP(
            src="192.0.2.11",
            dst="10.0.0.11",
        )
        / ICMP(
            type=8,
            code=0,
            id=1234,
            seq=2,
        )
        / Raw(
            b"abcdefghijklmnop"
        )
    )


def main():

    packets = [
        packet_sid_221(),
        packet_sid_225(),
        packet_sid_382(),
    ]

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    wrpcap(
        str(OUTPUT_FILE),
        packets,
    )

    print()
    print(
        "=== Controlled Alert Preservation PCAP ==="
    )
    print()

    print(
        f"Packets : {len(packets)}"
    )

    print(
        f"Output  : {OUTPUT_FILE}"
    )

    print()
    print(
        "Expected target alerts:"
    )

    print(
        "  packet 1 -> SID 221"
    )

    print(
        "  packet 2 -> SID 225"
    )

    print(
        "  packet 3 -> SID 382"
    )


if __name__ == "__main__":
    main()
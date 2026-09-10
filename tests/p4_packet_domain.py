#!/usr/bin/env python3
"""Offline packet-domain classifier that mirrors ``ids_prefilter.p4``.

The P4 parser intentionally performs selective matching only for direct
Ethernet/IPv4 packets with a base IPv4 header (IHL=5), no fragmentation, and
successful L4 extraction for TCP, UDP, and ICMP.  Every other frame is a
conservative packet-domain fallback, not a P4 no-match.
"""

from __future__ import annotations

from typing import Any, Dict, Optional, Tuple


TYPE_IPV4 = 0x0800
PROTO_ICMP = 1
PROTO_TCP = 6
PROTO_UDP = 17


def classify_frame_for_prefilter(
    frame: bytes,
) -> Tuple[Optional[Dict[str, int]], str]:
    """Return ``(packet, reason)`` using the corrected P4 packet domain.

    ``packet`` is present only when the P4 table is safely applicable.  A
    ``None`` packet denotes conservative packet-domain fallback; ``reason``
    identifies the first parser/domain condition that excluded the frame.
    """

    if len(frame) < 14:
        return None, "truncated_ethernet"

    eth_type = int.from_bytes(frame[12:14], "big")
    if eth_type != TYPE_IPV4:
        return None, f"ethertype_0x{eth_type:04x}"

    ip_offset = 14
    if len(frame) < ip_offset + 20:
        return None, "truncated_ipv4"

    version_ihl = frame[ip_offset]
    version = version_ihl >> 4
    ihl_words = version_ihl & 0x0F
    if version != 4:
        return None, "ipv4_version_not_4"
    if ihl_words != 5:
        return None, "ipv4_ihl_not_5"

    flags = (frame[ip_offset + 6] >> 5) & 0x07
    frag_offset = (
        ((frame[ip_offset + 6] & 0x1F) << 8)
        | frame[ip_offset + 7]
    )
    if frag_offset != 0 or flags not in {0, 2}:
        return None, "ipv4_fragmented_or_reserved_flags"

    protocol = frame[ip_offset + 9]
    src_ip = int.from_bytes(frame[ip_offset + 12:ip_offset + 16], "big")
    dst_ip = int.from_bytes(frame[ip_offset + 16:ip_offset + 20], "big")
    l4_offset = ip_offset + 20

    src_port = 0
    dst_port = 0
    tcp_flags = 0

    if protocol == PROTO_TCP:
        if len(frame) < l4_offset + 20:
            return None, "truncated_tcp"
        src_port = int.from_bytes(frame[l4_offset:l4_offset + 2], "big")
        dst_port = int.from_bytes(frame[l4_offset + 2:l4_offset + 4], "big")
        tcp_flags = frame[l4_offset + 13]
    elif protocol == PROTO_UDP:
        if len(frame) < l4_offset + 8:
            return None, "truncated_udp"
        src_port = int.from_bytes(frame[l4_offset:l4_offset + 2], "big")
        dst_port = int.from_bytes(frame[l4_offset + 2:l4_offset + 4], "big")
    elif protocol == PROTO_ICMP:
        if len(frame) < l4_offset + 4:
            return None, "truncated_icmp"

    return {
        "protocol": protocol,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "tcp_flags": tcp_flags,
    }, "supported_packet_domain"

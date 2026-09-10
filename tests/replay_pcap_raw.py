#!/usr/bin/env python3
"""Replay the exact captured Ethernet bytes without Scapy reserialization."""

import argparse
import socket
import time

from scapy.utils import RawPcapReader


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("pcap")
    parser.add_argument("--interface", default="veth1")
    parser.add_argument("--inter", type=float, default=0.02)
    parser.add_argument(
        "--limit",
        type=int,
        help="Replay at most this many frames (measurement validation only).",
    )
    args = parser.parse_args()

    sent = 0
    raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    raw_socket.bind((args.interface, 0))
    started = time.monotonic()
    try:
        for frame, _metadata in RawPcapReader(args.pcap):
            if args.limit is not None and sent >= args.limit:
                break
            raw_socket.send(frame)
            sent += 1
            if sent % 500 == 0:
                print(f"Sent: {sent}", flush=True)
            if args.inter:
                time.sleep(args.inter)
    finally:
        raw_socket.close()
    print(f"Input packets: {sent}")
    print(f"Elapsed seconds: {time.monotonic() - started:.6f}")


if __name__ == "__main__":
    main()

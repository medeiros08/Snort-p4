import json
import ipaddress
import re

from collections import Counter
from pathlib import Path


INPUT_FILE = "../output/p4_entries_expanded.json"
OUTPUT_FILE = "../output/p4runtime_entries.json"


# ============================================================
# TCP flag representation
# ============================================================


TCP_FLAG_MAP = {
    "F": 0x01,
    "S": 0x02,
    "R": 0x04,
    "P": 0x08,
    "A": 0x10,
    "U": 0x20,
    "E": 0x40,
    "C": 0x80,
}


FLAG_MODIFIERS = {
    "+",
    "*",
    "!",
}


VALID_FLAG_PATTERN = re.compile(
    r"^[FSRPAUEC0]*$"
)


# ============================================================
# IPv4 normalization
# ============================================================


def normalize_ip(value):
    """
    Normalize one IPv4 address/network into an explicit
    value + prefix representation.

    Examples:

        10.0.0.1
            ->
        {
            "value": "10.0.0.1",
            "prefix_len": 32
        }

        10.0.0.0/24
            ->
        {
            "value": "10.0.0.0",
            "prefix_len": 24
        }
    """

    network = ipaddress.ip_network(
        str(value).strip(),
        strict=False,
    )

    if network.version != 4:

        raise ValueError(
            f"Only IPv4 is supported: {value}"
        )

    return {
        "value": str(
            network.network_address
        ),

        "prefix_len": (
            network.prefixlen
        ),
    }


# ============================================================
# Port normalization
# ============================================================


def normalize_port(value):
    """
    Normalize one exact L4 port.

    Port ranges and negated ports must never reach this stage;
    those semantics are handled earlier by target capability.
    """

    if isinstance(
        value,
        bool,
    ):

        raise ValueError(
            f"Invalid boolean port value: {value}"
        )

    try:
        port = int(
            str(value).strip()
        )

    except (TypeError, ValueError):

        raise ValueError(
            f"Invalid exact port: {value}"
        )

    if not 0 <= port <= 65535:

        raise ValueError(
            f"Port outside 0..65535: {value}"
        )

    return port


# ============================================================
# Protocol normalization
# ============================================================


def normalize_protocol(value):
    """
    Normalize one IPv4 protocol number.

    At this stage symbolic Snort names should already have
    been converted by p4_backend.py.
    """

    if isinstance(
        value,
        bool,
    ):

        raise ValueError(
            f"Invalid boolean protocol value: {value}"
        )

    try:
        protocol = int(
            str(value).strip()
        )

    except (TypeError, ValueError):

        raise ValueError(
            f"Invalid protocol number: {value}"
        )

    if not 0 <= protocol <= 255:

        raise ValueError(
            f"Protocol outside 0..255: {value}"
        )

    return protocol


# ============================================================
# TCP flags
# ============================================================


def flags_to_mask(flags):
    """
    Convert Snort TCP flag symbols into the conventional
    8-bit TCP flag mask.

        F = FIN
        S = SYN
        R = RST
        P = PSH
        A = ACK
        U = URG
        E = ECE
        C = CWR

    '0' contributes no set bits.
    """

    mask = 0

    for flag in flags:

        if flag == "0":
            continue

        if flag not in TCP_FLAG_MAP:

            raise ValueError(
                "Unsupported TCP flag character: "
                f"{flag}"
            )

        mask |= TCP_FLAG_MAP[
            flag
        ]

    return mask


def split_flag_expression(value):
    """
    Parse the supported Snort flags representation.

    Supported examples:

        S
        SA
        +SA
        *SA
        !R
        SF,CE

    Suffix modifier forms are also tolerated because they
    were observed during development:

        SA+
        FRS*

    Digit-bearing and otherwise unsupported expressions
    should already have been marked FALLBACK before reaching
    the backend.
    """

    raw = str(
        value
    ).strip().upper()

    if not raw:

        raise ValueError(
            "Empty TCP flags expression"
        )

    # --------------------------------------------------------
    # Optional ignored-flags component
    # --------------------------------------------------------

    if "," in raw:

        parts = raw.split(
            ","
        )

        if len(parts) != 2:

            raise ValueError(
                "Invalid TCP flags expression: "
                f"{raw}"
            )

        test_part = parts[0]
        ignore_part = parts[1]

    else:

        test_part = raw
        ignore_part = ""

    test_part = (
        test_part.strip()
    )

    ignore_part = (
        ignore_part.strip()
    )

    modifier = None

    # --------------------------------------------------------
    # Prefix modifier:
    #
    # +SA
    # *SA
    # !R
    # --------------------------------------------------------

    if (
        test_part
        and
        test_part[0]
        in FLAG_MODIFIERS
    ):

        modifier = (
            test_part[0]
        )

        test_part = (
            test_part[1:]
        )

    # --------------------------------------------------------
    # Development compatibility:
    #
    # SA+
    # FRS*
    # --------------------------------------------------------

    elif (
        test_part
        and
        test_part[-1]
        in FLAG_MODIFIERS
    ):

        modifier = (
            test_part[-1]
        )

        test_part = (
            test_part[:-1]
        )

    return {
        "raw": raw,

        "modifier": (
            modifier
        ),

        "test_flags": (
            test_part
        ),

        "ignore_flags": (
            ignore_part
        ),
    }


def normalize_tcp_flags(value):
    """
    Preserve the comparison semantics required to compile a
    Snort flags expression later into a P4 ternary predicate.

    We intentionally do not reduce every expression to one
    exact byte here.

    Output:

        {
            "raw": "SA",
            "modifier": "EXACT",
            "test_mask": 18,
            "ignore_mask": 0
        }

    The following P4 translation stage is responsible for
    deriving ternary value/mask behavior from these semantics.
    """

    parsed = (
        split_flag_expression(
            value
        )
    )

    test_flags = (
        parsed[
            "test_flags"
        ]
    )

    ignore_flags = (
        parsed[
            "ignore_flags"
        ]
    )

    modifier = (
        parsed[
            "modifier"
        ]
    )

    if not VALID_FLAG_PATTERN.fullmatch(
        test_flags
    ):

        raise ValueError(
            "Unsupported TCP test flags: "
            f"{parsed['raw']}"
        )

    if (
        ignore_flags
        and
        not VALID_FLAG_PATTERN.fullmatch(
            ignore_flags
        )
    ):

        raise ValueError(
            "Unsupported TCP ignore-mask flags: "
            f"{parsed['raw']}"
        )

    test_mask = (
        flags_to_mask(
            test_flags
        )
    )

    ignore_mask = (
        flags_to_mask(
            ignore_flags
        )
    )

    return {
        "raw": (
            parsed[
                "raw"
            ]
        ),

        "modifier": (
            modifier
            if modifier is not None
            else "EXACT"
        ),

        "test_mask": (
            test_mask
        ),

        "ignore_mask": (
            ignore_mask
        ),
    }


# ============================================================
# Match normalization
# ============================================================


SUPPORTED_MATCH_FIELDS = {
    "protocol",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "tcp_flags",
}


def normalize_match(match):
    """
    Normalize one concrete semantic backend match into the
    representation consumed by the P4Runtime translation
    layer.

    No list-valued field should remain after expansion.
    """

    if not isinstance(
        match,
        dict,
    ):

        raise ValueError(
            "Backend match must be a dictionary"
        )

    # --------------------------------------------------------
    # Catch unexpected backend fields early instead of
    # silently discarding them.
    # --------------------------------------------------------

    unknown_fields = (
        set(match.keys())
        - SUPPORTED_MATCH_FIELDS
    )

    if unknown_fields:

        raise ValueError(
            "Unknown P4 backend match fields: "
            f"{sorted(unknown_fields)}"
        )

    normalized = {}

    # --------------------------------------------------------
    # Protocol
    # --------------------------------------------------------

    if "protocol" in match:

        normalized[
            "protocol"
        ] = normalize_protocol(
            match[
                "protocol"
            ]
        )

    # --------------------------------------------------------
    # IPv4
    # --------------------------------------------------------

    if "src_ip" in match:

        normalized[
            "src_ip"
        ] = normalize_ip(
            match[
                "src_ip"
            ]
        )

    if "dst_ip" in match:

        normalized[
            "dst_ip"
        ] = normalize_ip(
            match[
                "dst_ip"
            ]
        )

    # --------------------------------------------------------
    # Ports
    # --------------------------------------------------------

    if "src_port" in match:

        normalized[
            "src_port"
        ] = normalize_port(
            match[
                "src_port"
            ]
        )

    if "dst_port" in match:

        normalized[
            "dst_port"
        ] = normalize_port(
            match[
                "dst_port"
            ]
        )

    # --------------------------------------------------------
    # TCP flags
    # --------------------------------------------------------

    if "tcp_flags" in match:

        normalized[
            "tcp_flags"
        ] = normalize_tcp_flags(
            match[
                "tcp_flags"
            ]
        )

    return normalized


# ============================================================
# Main
# ============================================================


def main():

    input_path = Path(
        INPUT_FILE
    )

    output_path = Path(
        OUTPUT_FILE
    )

    if not input_path.exists():

        print(
            "ERROR: Input file not found: "
            f"{input_path.resolve()}"
        )

        return

    with open(
        input_path,
        "r",
        encoding="utf-8",
    ) as file:

        data = json.load(
            file
        )

    source_entries = data.get(
        "entries",
        [],
    )

    normalized_entries = []

    failures = []

    semantic_class_counter = (
        Counter()
    )

    protocol_counter = Counter()

    orientation_counter = (
        Counter()
    )

    entries_with_flags = 0

    entries_with_ports = 0

    entries_with_ip = 0

    # ========================================================
    # Normalize entries
    # ========================================================

    for entry in source_entries:

        backend_entry_id = (
            entry.get(
                "backend_entry_id"
            )
        )

        rule_id = (
            entry.get(
                "rule_id"
            )
        )

        try:

            original_match = (
                entry.get(
                    "match",
                    {},
                )
            )

            normalized_match = (
                normalize_match(
                    original_match
                )
            )

            semantic_class = (
                entry.get(
                    "semantic_class"
                )
            )

            orientation = (
                entry.get(
                    "orientation",
                    "forward",
                )
            )

            # ------------------------------------------------
            # Statistics
            # ------------------------------------------------

            semantic_class_counter[
                semantic_class
            ] += 1

            orientation_counter[
                orientation
            ] += 1

            if (
                "protocol"
                in normalized_match
            ):

                protocol_counter[
                    normalized_match[
                        "protocol"
                    ]
                ] += 1

            if (
                "tcp_flags"
                in normalized_match
            ):

                entries_with_flags += 1

            if (
                "src_port"
                in normalized_match
                or
                "dst_port"
                in normalized_match
            ):

                entries_with_ports += 1

            if (
                "src_ip"
                in normalized_match
                or
                "dst_ip"
                in normalized_match
            ):

                entries_with_ip += 1

            # ------------------------------------------------
            # P4Runtime-neutral normalized representation
            # ------------------------------------------------

            normalized_entry = {
                "backend_entry_id": (
                    backend_entry_id
                ),

                "rule_id": str(
                    rule_id
                ),

                "rule_type": (
                    entry.get(
                        "rule_type"
                    )
                ),

                "semantic_class": (
                    semantic_class
                ),

                "final_detection": (
                    entry.get(
                        "final_detection"
                    )
                ),

                "orientation": (
                    orientation
                ),

                "expansion_index": (
                    entry.get(
                        "expansion_index"
                    )
                ),

                "expansion_count": (
                    entry.get(
                        "expansion_count"
                    )
                ),

                "table": (
                    "ids_prefilter"
                ),

                "match": (
                    normalized_match
                ),

                # --------------------------------------------
                # Important semantic correction:
                #
                # The switch selects traffic for the IDS.
                # It does NOT claim that this specific Snort
                # SID matched.
                # --------------------------------------------

                "action": {
                    "name": (
                        "send_to_ids"
                    ),
                },
            }

            normalized_entries.append(
                normalized_entry
            )

        except Exception as error:

            failures.append(
                {
                    "backend_entry_id": (
                        backend_entry_id
                    ),

                    "rule_id": (
                        rule_id
                    ),

                    "error": str(
                        error
                    ),

                    "original_match": (
                        entry.get(
                            "match",
                            {},
                        )
                    ),
                }
            )

    # ========================================================
    # Output
    # ========================================================

    output = {
        "schema_version": "2.0",

        "source_file": (
            input_path.name
        ),

        "source_entries": len(
            source_entries
        ),

        "normalized_entries": len(
            normalized_entries
        ),

        "failed_entries": len(
            failures
        ),

        "table": (
            "ids_prefilter"
        ),

        "statistics": {
            "semantic_classes": dict(
                semantic_class_counter
            ),

            "orientations": dict(
                orientation_counter
            ),

            "protocols": dict(
                protocol_counter
            ),

            "entries_with_ip": (
                entries_with_ip
            ),

            "entries_with_ports": (
                entries_with_ports
            ),

            "entries_with_tcp_flags": (
                entries_with_flags
            ),
        },

        "entries": (
            normalized_entries
        ),

        "failures": (
            failures
        ),
    }

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with open(
        output_path,
        "w",
        encoding="utf-8",
        newline="\n",
    ) as file:

        json.dump(
            output,
            file,
            indent=2,
            ensure_ascii=False,
        )

    # ========================================================
    # Report
    # ========================================================

    print()
    print(
        "=== P4Runtime Entry Normalization ==="
    )
    print()

    print(
        f"Source entries          : "
        f"{len(source_entries)}"
    )

    print(
        f"Normalized entries      : "
        f"{len(normalized_entries)}"
    )

    print(
        f"Failed entries          : "
        f"{len(failures)}"
    )

    print()

    print(
        "Normalized entry features"
    )
    print(
        "-" * 55
    )

    print(
        f"Entries with IPv4       : "
        f"{entries_with_ip}"
    )

    print(
        f"Entries with ports      : "
        f"{entries_with_ports}"
    )

    print(
        f"Entries with TCP flags  : "
        f"{entries_with_flags}"
    )

    print()

    print(
        "Orientations"
    )
    print(
        "-" * 55
    )

    for orientation, count in (
        orientation_counter.most_common()
    ):

        print(
            f"{str(orientation):<20} "
            f"{count:>6}"
        )

    print()

    print(
        "IP protocol values"
    )
    print(
        "-" * 55
    )

    protocol_names = {
        1: "ICMP",
        6: "TCP",
        17: "UDP",
    }

    for protocol, count in sorted(
        protocol_counter.items()
    ):

        name = protocol_names.get(
            protocol,
            "OTHER",
        )

        print(
            f"{protocol:>3} "
            f"({name:<5}) : "
            f"{count:>6}"
        )

    print()

    print(
        f"Output:"
    )

    print(
        output_path.resolve()
    )

    if failures:

        print()
        print(
            "Normalization failures"
        )
        print(
            "=" * 70
        )

        for failure in (
            failures[:30]
        ):

            print(
                f"SID "
                f"{failure['rule_id']} | "
                f"{failure['error']} | "
                f"{failure['original_match']}"
            )


if __name__ == "__main__":
    main()
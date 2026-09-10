import ipaddress
import json

from pathlib import Path


INPUT_FILE = "../output/p4_install_entries.json"
P4INFO_FILE = "../output/ids_prefilter.p4info.txt"
OUTPUT_FILE = "../output/p4runtime_install_plan.json"


# ============================================================
# Expected P4Info contract
# ============================================================


TABLE_NAME = "MyIngress.ids_prefilter"
TABLE_ID = 43167662

ACTION_NAME = "MyIngress.send_to_ids"
ACTION_ID = 30911920


FIELD_INFO = {
    "protocol": {
        "field_id": 1,
        "p4_name": "hdr.ipv4.protocol",
        "bitwidth": 8,
    },

    "src_ip": {
        "field_id": 2,
        "p4_name": "hdr.ipv4.srcAddr",
        "bitwidth": 32,
    },

    "dst_ip": {
        "field_id": 3,
        "p4_name": "hdr.ipv4.dstAddr",
        "bitwidth": 32,
    },

    "src_port": {
        "field_id": 4,
        "p4_name": "meta.l4_src_port",
        "bitwidth": 16,
    },

    "dst_port": {
        "field_id": 5,
        "p4_name": "meta.l4_dst_port",
        "bitwidth": 16,
    },

    "tcp_flags": {
        "field_id": 6,
        "p4_name": "meta.tcp_flags",
        "bitwidth": 8,
    },
}


# ============================================================
# Integer encoding
# ============================================================


def max_value_for_bitwidth(
    bitwidth
):
    return (
        1 << bitwidth
    ) - 1


def validate_integer_width(
    value,
    bitwidth,
    field_name,
):
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
    ):

        raise ValueError(
            f"{field_name} must be an integer: "
            f"{value}"
        )

    maximum = (
        max_value_for_bitwidth(
            bitwidth
        )
    )

    if not 0 <= value <= maximum:

        raise ValueError(
            f"{field_name} value {value} "
            f"does not fit bit<{bitwidth}>"
        )


def integer_to_hex(
    value,
    bitwidth,
):
    """
    Encode one integer using the exact number of bytes
    required by the P4 field.

    Examples:

        bit<8>  6
            -> "06"

        bit<16> 80
            -> "0050"

        bit<32> 0x0a000000
            -> "0a000000"
    """

    validate_integer_width(
        value,
        bitwidth,
        "integer",
    )

    byte_width = (
        bitwidth + 7
    ) // 8

    return value.to_bytes(
        byte_width,
        byteorder="big",
    ).hex()


# ============================================================
# IPv4 ternary encoding
# ============================================================


def ipv4_to_integer(
    value
):
    address = ipaddress.ip_address(
        str(value)
    )

    if address.version != 4:

        raise ValueError(
            f"Only IPv4 is supported: "
            f"{value}"
        )

    return int(
        address
    )


def prefix_to_mask(
    prefix_len
):
    if (
        not isinstance(prefix_len, int)
        or isinstance(prefix_len, bool)
        or not 0 <= prefix_len <= 32
    ):

        raise ValueError(
            f"Invalid IPv4 prefix length: "
            f"{prefix_len}"
        )

    if prefix_len == 0:

        return 0

    return (
        0xFFFFFFFF
        << (
            32 - prefix_len
        )
    ) & 0xFFFFFFFF


def encode_ipv4_ternary(
    value
):
    """
    Input:

        {
            "value": "10.0.0.0",
            "prefix_len": 24
        }

    Output:

        value = 0a000000
        mask  = ffffff00

    Although Snort uses CIDR syntax, the current P4 table
    declares the IP fields as TERNARY rather than LPM.
    """

    if not isinstance(
        value,
        dict,
    ):

        raise ValueError(
            f"IPv4 match is not an object: "
            f"{value}"
        )

    address = value.get(
        "value"
    )

    prefix_len = value.get(
        "prefix_len"
    )

    address_integer = (
        ipv4_to_integer(
            address
        )
    )

    mask_integer = (
        prefix_to_mask(
            prefix_len
        )
    )

    # Canonicalize value according to mask.
    address_integer &= (
        mask_integer
    )

    # A zero-mask ternary key is equivalent to wildcard and
    # should therefore not be emitted.
    if mask_integer == 0:

        return None

    return {
        "value": integer_to_hex(
            address_integer,
            32,
        ),

        "mask": integer_to_hex(
            mask_integer,
            32,
        ),
    }


# ============================================================
# Exact fields represented as ternary
# ============================================================


def encode_exact_ternary(
    value,
    bitwidth,
):
    """
    Exact semantic value represented in a ternary P4 key.

        protocol = 6

    becomes:

        value = 06
        mask  = ff
    """

    validate_integer_width(
        value,
        bitwidth,
        "ternary value",
    )

    mask = (
        max_value_for_bitwidth(
            bitwidth
        )
    )

    return {
        "value": integer_to_hex(
            value,
            bitwidth,
        ),

        "mask": integer_to_hex(
            mask,
            bitwidth,
        ),
    }


# ============================================================
# TCP flag encoding
# ============================================================


def encode_tcp_flags(
    value
):
    """
    TCP flags have already been lowered into:

        {
            "value": X,
            "mask": Y
        }

    Both fields are bit<8>.
    """

    if not isinstance(
        value,
        dict,
    ):

        raise ValueError(
            f"tcp_flags must be a dictionary: "
            f"{value}"
        )

    flag_value = value.get(
        "value"
    )

    flag_mask = value.get(
        "mask"
    )

    validate_integer_width(
        flag_value,
        8,
        "tcp_flags value",
    )

    validate_integer_width(
        flag_mask,
        8,
        "tcp_flags mask",
    )

    if flag_mask == 0:

        return None

    # Canonical ternary representation.
    flag_value &= flag_mask

    return {
        "value": integer_to_hex(
            flag_value,
            8,
        ),

        "mask": integer_to_hex(
            flag_mask,
            8,
        ),
    }


# ============================================================
# One semantic match field -> P4Runtime field
# ============================================================


def encode_match_field(
    semantic_name,
    value,
):
    if semantic_name not in (
        FIELD_INFO
    ):

        raise ValueError(
            "Unknown backend field: "
            f"{semantic_name}"
        )

    info = FIELD_INFO[
        semantic_name
    ]

    bitwidth = info[
        "bitwidth"
    ]

    if semantic_name in {
        "src_ip",
        "dst_ip",
    }:

        encoded = (
            encode_ipv4_ternary(
                value
            )
        )

    elif semantic_name == "tcp_flags":

        encoded = (
            encode_tcp_flags(
                value
            )
        )

    else:

        encoded = (
            encode_exact_ternary(
                value,
                bitwidth,
            )
        )

    if encoded is None:

        return None

    return {
        "field_id": (
            info[
                "field_id"
            ]
        ),

        "field_name": (
            info[
                "p4_name"
            ]
        ),

        "match_type": (
            "TERNARY"
        ),

        "bitwidth": (
            bitwidth
        ),

        "ternary": {
            "value_hex": (
                encoded[
                    "value"
                ]
            ),

            "mask_hex": (
                encoded[
                    "mask"
                ]
            ),
        },
    }


# ============================================================
# Entry encoding
# ============================================================


def calculate_priority(
    encoded_fields
):
    """
    Every entry currently executes exactly the same positive
    action: send_to_ids().

    Therefore overlap between two matching entries does not
    change the semantic result.

    We still assign a legal non-zero deterministic ternary
    priority.

    Priority 1 is sufficient for the present prototype.
    """

    return 1


def encode_entry(
    entry
):
    match = entry.get(
        "match",
        {},
    )

    if not match:

        raise ValueError(
            "Install entry has empty match"
        )

    encoded_fields = []

    for semantic_name in (
        "protocol",
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "tcp_flags",
    ):

        if semantic_name not in match:
            continue

        encoded = (
            encode_match_field(
                semantic_name,
                match[
                    semantic_name
                ],
            )
        )

        if encoded is not None:

            encoded_fields.append(
                encoded
            )

    if not encoded_fields:

        raise ValueError(
            "Install entry became wildcard-only "
            "after P4Runtime encoding"
        )

    encoded_fields.sort(
        key=lambda item: (
            item[
                "field_id"
            ]
        )
    )

    priority = (
        calculate_priority(
            encoded_fields
        )
    )

    return {
        "install_entry_id": (
            entry.get(
                "install_entry_id"
            )
        ),

        "table": {
            "name": (
                TABLE_NAME
            ),

            "id": (
                TABLE_ID
            ),
        },

        "priority": (
            priority
        ),

        "match": (
            encoded_fields
        ),

        "action": {
            "name": (
                ACTION_NAME
            ),

            "id": (
                ACTION_ID
            ),

            "params": [],
        },

        "provenance": (
            entry.get(
                "provenance",
                {},
            )
        ),
    }


# ============================================================
# P4Info verification
# ============================================================


def verify_p4info_text(
    text
):
    """
    Fail early if the compiled P4Info does not contain the
    contract used by this generator.

    We deliberately verify names and IDs instead of silently
    assuming that the P4 program has not changed.
    """

    required_fragments = [
        f'id: {TABLE_ID}',
        f'name: "{TABLE_NAME}"',

        'id: 1',
        'name: "hdr.ipv4.protocol"',

        'id: 2',
        'name: "hdr.ipv4.srcAddr"',

        'id: 3',
        'name: "hdr.ipv4.dstAddr"',

        'id: 4',
        'name: "meta.l4_src_port"',

        'id: 5',
        'name: "meta.l4_dst_port"',

        'id: 6',
        'name: "meta.tcp_flags"',

        f'id: {ACTION_ID}',
        f'name: "{ACTION_NAME}"',
    ]

    missing = []

    for fragment in (
        required_fragments
    ):

        if fragment not in text:

            missing.append(
                fragment
            )

    if missing:

        raise ValueError(
            "Compiled P4Info does not match the "
            "expected backend contract. Missing: "
            f"{missing}"
        )


# ============================================================
# Validation of encoded entries
# ============================================================


def validate_encoded_entries(
    entries
):
    errors = []

    seen_ids = set()

    for entry in entries:

        entry_id = entry.get(
            "install_entry_id"
        )

        if entry_id in seen_ids:

            errors.append(
                {
                    "install_entry_id": (
                        entry_id
                    ),

                    "message": (
                        "duplicate install_entry_id"
                    ),
                }
            )

        seen_ids.add(
            entry_id
        )

        if entry.get(
            "priority",
            0,
        ) <= 0:

            errors.append(
                {
                    "install_entry_id": (
                        entry_id
                    ),

                    "message": (
                        "ternary entry has "
                        "non-positive priority"
                    ),
                }
            )

        field_ids = set()

        for field in entry.get(
            "match",
            [],
        ):

            field_id = field.get(
                "field_id"
            )

            if field_id in field_ids:

                errors.append(
                    {
                        "install_entry_id": (
                            entry_id
                        ),

                        "message": (
                            "duplicate match field "
                            f"ID {field_id}"
                        ),
                    }
                )

            field_ids.add(
                field_id
            )

            ternary = field.get(
                "ternary",
                {},
            )

            value_hex = ternary.get(
                "value_hex",
                "",
            )

            mask_hex = ternary.get(
                "mask_hex",
                "",
            )

            bitwidth = field.get(
                "bitwidth"
            )

            expected_bytes = (
                bitwidth + 7
            ) // 8

            if (
                len(value_hex)
                != expected_bytes * 2
            ):

                errors.append(
                    {
                        "install_entry_id": (
                            entry_id
                        ),

                        "message": (
                            f"field {field_id} has "
                            "incorrect value width"
                        ),
                    }
                )

            if (
                len(mask_hex)
                != expected_bytes * 2
            ):

                errors.append(
                    {
                        "install_entry_id": (
                            entry_id
                        ),

                        "message": (
                            f"field {field_id} has "
                            "incorrect mask width"
                        ),
                    }
                )

            try:

                value_integer = int(
                    value_hex,
                    16,
                )

                mask_integer = int(
                    mask_hex,
                    16,
                )

            except ValueError:

                errors.append(
                    {
                        "install_entry_id": (
                            entry_id
                        ),

                        "message": (
                            f"field {field_id} "
                            "contains invalid hex"
                        ),
                    }
                )

                continue

            if mask_integer == 0:

                errors.append(
                    {
                        "install_entry_id": (
                            entry_id
                        ),

                        "message": (
                            f"field {field_id} "
                            "has zero ternary mask"
                        ),
                    }
                )

            if (
                value_integer
                & (
                    ~mask_integer
                )
            ):

                errors.append(
                    {
                        "install_entry_id": (
                            entry_id
                        ),

                        "message": (
                            f"field {field_id} "
                            "has non-canonical "
                            "ternary value/mask"
                        ),
                    }
                )

    return errors


# ============================================================
# Main
# ============================================================


def main():
    input_path = Path(
        INPUT_FILE
    )

    p4info_path = Path(
        P4INFO_FILE
    )

    output_path = Path(
        OUTPUT_FILE
    )

    if not input_path.exists():

        print(
            "ERROR: Install entries not found: "
            f"{input_path.resolve()}"
        )

        return

    if not p4info_path.exists():

        print(
            "ERROR: P4Info not found: "
            f"{p4info_path.resolve()}"
        )

        return

    # ========================================================
    # Verify compiled P4 contract
    # ========================================================

    p4info_text = (
        p4info_path.read_text(
            encoding="utf-8",
            errors="ignore",
        )
    )

    try:

        verify_p4info_text(
            p4info_text
        )

    except Exception as error:

        print(
            "ERROR: P4Info verification failed:"
        )

        print(
            error
        )

        return

    # ========================================================
    # Read lowered install predicates
    # ========================================================

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

    encoded_entries = []

    encoding_failures = []

    for entry in source_entries:

        try:

            encoded_entries.append(
                encode_entry(
                    entry
                )
            )

        except Exception as error:

            encoding_failures.append(
                {
                    "install_entry_id": (
                        entry.get(
                            "install_entry_id"
                        )
                    ),

                    "message": str(
                        error
                    ),

                    "match": (
                        entry.get(
                            "match"
                        )
                    ),
                }
            )

    # ========================================================
    # Validate encoded representation
    # ========================================================

    validation_errors = (
        validate_encoded_entries(
            encoded_entries
        )
    )

    # ========================================================
    # Field-use statistics
    # ========================================================

    field_usage = {
        semantic_name: 0
        for semantic_name
        in FIELD_INFO
    }

    field_id_to_semantic = {
        info[
            "field_id"
        ]: semantic_name

        for (
            semantic_name,
            info
        )
        in FIELD_INFO.items()
    }

    for entry in encoded_entries:

        for field in entry.get(
            "match",
            [],
        ):

            semantic_name = (
                field_id_to_semantic.get(
                    field[
                        "field_id"
                    ]
                )
            )

            if semantic_name:

                field_usage[
                    semantic_name
                ] += 1

    # ========================================================
    # Output
    # ========================================================

    output = {
        "schema_version": "1.0",

        "source_file": (
            input_path.name
        ),

        "p4info_file": (
            p4info_path.name
        ),

        "table": {
            "name": TABLE_NAME,
            "id": TABLE_ID,
        },

        "action": {
            "name": ACTION_NAME,
            "id": ACTION_ID,
        },

        "source_install_entries": len(
            source_entries
        ),

        "encoded_entries": len(
            encoded_entries
        ),

        "encoding_failures": (
            encoding_failures
        ),

        "validation_errors": (
            validation_errors
        ),

        "field_usage": (
            field_usage
        ),

        "priority_policy": {
            "type": "constant",
            "value": 1,

            "reason": (
                "All positive prefilter entries "
                "execute the same send_to_ids action; "
                "overlap therefore does not alter "
                "the classification result."
            ),
        },

        "entries": (
            encoded_entries
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
        "=== P4Runtime Install Plan Generation ==="
    )
    print()

    print(
        f"Source install entries : "
        f"{len(source_entries)}"
    )

    print(
        f"Encoded entries        : "
        f"{len(encoded_entries)}"
    )

    print(
        f"Encoding failures      : "
        f"{len(encoding_failures)}"
    )

    print(
        f"Validation errors      : "
        f"{len(validation_errors)}"
    )

    print()

    print(
        "P4Info contract"
    )
    print(
        "-" * 55
    )

    print(
        f"Table ID               : "
        f"{TABLE_ID}"
    )

    print(
        f"Action ID              : "
        f"{ACTION_ID}"
    )

    print()

    print(
        "Field usage"
    )
    print(
        "-" * 55
    )

    for semantic_name in (
        "protocol",
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "tcp_flags",
    ):

        print(
            f"{semantic_name:<20} "
            f"{field_usage[semantic_name]:>6}"
        )

    print()

    print(
        f"Priority               : 1"
    )

    print()

    if encoding_failures:

        print(
            "ENCODING FAILURES"
        )
        print(
            "=" * 70
        )

        for failure in (
            encoding_failures[:30]
        ):

            print(
                f"{failure['install_entry_id']} | "
                f"{failure['message']} | "
                f"{failure['match']}"
            )

        print()

    if validation_errors:

        print(
            "VALIDATION ERRORS"
        )
        print(
            "=" * 70
        )

        for error in (
            validation_errors[:30]
        ):

            print(
                f"{error['install_entry_id']} | "
                f"{error['message']}"
            )

        print()

    status = (
        "VALID"
        if (
            not encoding_failures
            and
            not validation_errors
        )
        else "INVALID"
    )

    print(
        f"Install plan status    : "
        f"{status}"
    )

    print(
        f"Output                 : "
        f"{output_path.resolve()}"
    )


if __name__ == "__main__":
    main()
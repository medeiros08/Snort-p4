import json
import ipaddress

from collections import Counter
from pathlib import Path


INPUT_FILE = "../output/p4runtime_entries.json"
OUTPUT_FILE = "../output/backend_validation.json"


# ============================================================
# Current P4 backend contract
# ============================================================

EXPECTED_TABLE = "ids_prefilter"
EXPECTED_ACTION = "send_to_ids"

P4_TABLE_SIZE = 8192


SUPPORTED_MATCH_FIELDS = {
    "protocol",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "tcp_flags",
}


SUPPORTED_PROTOCOLS = {
    1,      # ICMP
    6,      # TCP
    17,     # UDP
}


SUPPORTED_FLAG_MODIFIERS = {
    "EXACT",
    "+",
    "*",
    "!",
}


# ============================================================
# Utility
# ============================================================


def add_issue(
    issues,
    entry,
    message,
):
    issues.append(
        {
            "backend_entry_id": entry.get(
                "backend_entry_id"
            ),

            "rule_id": entry.get(
                "rule_id"
            ),

            "message": message,
        }
    )


def make_hashable(value):
    """
    Convert nested JSON-compatible structures into a stable
    hashable representation.
    """

    if isinstance(value, dict):

        return tuple(
            sorted(
                (
                    key,
                    make_hashable(item),
                )
                for key, item in value.items()
            )
        )

    if isinstance(value, list):

        return tuple(
            make_hashable(item)
            for item in value
        )

    return value


def normalized_match_key(match):
    """
    Stable key used to detect identical backend matches.

    rule_id is intentionally not included because the P4
    action only marks traffic as candidate for the IDS.
    """

    return tuple(
        sorted(
            (
                field,
                make_hashable(value),
            )
            for field, value in match.items()
        )
    )


def contains_list(value):
    """
    Concrete normalized backend entries must not contain
    unresolved list-valued alternatives.
    """

    if isinstance(value, list):
        return True

    if isinstance(value, dict):

        return any(
            contains_list(item)
            for item in value.values()
        )

    return False


def bit_count(value):
    return bin(
        int(value)
    ).count("1")


# ============================================================
# IPv4 validation
# ============================================================


def validate_ip_field(
    field_name,
    value,
    entry,
    errors,
):
    if not isinstance(value, dict):

        add_issue(
            errors,
            entry,
            (
                f"{field_name} is not a normalized "
                f"IPv4 object: {value}"
            ),
        )

        return

    if (
        "value" not in value
        or
        "prefix_len" not in value
    ):

        add_issue(
            errors,
            entry,
            (
                f"{field_name} is missing "
                f"value/prefix_len: {value}"
            ),
        )

        return

    ip_value = value.get(
        "value"
    )

    prefix_len = value.get(
        "prefix_len"
    )

    try:

        address = ipaddress.ip_address(
            ip_value
        )

    except ValueError:

        add_issue(
            errors,
            entry,
            (
                f"{field_name} has invalid "
                f"IPv4 address: {ip_value}"
            ),
        )

        return

    if address.version != 4:

        add_issue(
            errors,
            entry,
            (
                f"{field_name} is not IPv4: "
                f"{ip_value}"
            ),
        )

    if (
        not isinstance(prefix_len, int)
        or isinstance(prefix_len, bool)
        or not 0 <= prefix_len <= 32
    ):

        add_issue(
            errors,
            entry,
            (
                f"{field_name} has invalid "
                f"prefix length: {prefix_len}"
            ),
        )

        return

    try:

        network = ipaddress.ip_network(
            f"{ip_value}/{prefix_len}",
            strict=False,
        )

        canonical = str(
            network.network_address
        )

        if canonical != str(ip_value):

            add_issue(
                errors,
                entry,
                (
                    f"{field_name} is not canonical: "
                    f"{ip_value}/{prefix_len} "
                    f"should start at {canonical}"
                ),
            )

    except ValueError:

        add_issue(
            errors,
            entry,
            (
                f"{field_name} cannot form "
                f"a valid IPv4 prefix"
            ),
        )


# ============================================================
# Port validation
# ============================================================


def validate_port_field(
    field_name,
    value,
    entry,
    errors,
):
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
    ):

        add_issue(
            errors,
            entry,
            (
                f"{field_name} is not an exact "
                f"integer port: {value}"
            ),
        )

        return

    if not 0 <= value <= 65535:

        add_issue(
            errors,
            entry,
            (
                f"{field_name} outside "
                f"0..65535: {value}"
            ),
        )


# ============================================================
# TCP flag validation
# ============================================================


def analyze_tcp_flags(
    value,
    entry,
    errors,
):
    """
    Validate normalized Snort TCP flags and determine whether
    the expression fits one P4 ternary entry or requires
    multiple entries.
    """

    if not isinstance(value, dict):

        add_issue(
            errors,
            entry,
            (
                "tcp_flags is not a normalized "
                f"object: {value}"
            ),
        )

        return {
            "status": "INVALID",
        }

    required_fields = {
        "raw",
        "modifier",
        "test_mask",
        "ignore_mask",
    }

    missing = (
        required_fields
        - set(value.keys())
    )

    if missing:

        add_issue(
            errors,
            entry,
            (
                "tcp_flags missing fields: "
                f"{sorted(missing)}"
            ),
        )

        return {
            "status": "INVALID",
        }

    modifier = value.get(
        "modifier"
    )

    test_mask = value.get(
        "test_mask"
    )

    ignore_mask = value.get(
        "ignore_mask"
    )

    if modifier not in SUPPORTED_FLAG_MODIFIERS:

        add_issue(
            errors,
            entry,
            (
                "unsupported TCP flag modifier: "
                f"{modifier}"
            ),
        )

        return {
            "status": "INVALID",
        }

    for name, mask in (
        ("test_mask", test_mask),
        ("ignore_mask", ignore_mask),
    ):

        if (
            not isinstance(mask, int)
            or isinstance(mask, bool)
            or not 0 <= mask <= 0xFF
        ):

            add_issue(
                errors,
                entry,
                (
                    f"invalid TCP flag "
                    f"{name}: {mask}"
                ),
            )

            return {
                "status": "INVALID",
            }

    effective_test_mask = (
        test_mask
        & (
            ~ignore_mask
            & 0xFF
        )
    )

    # EXACT, + and ! can be lowered directly to one
    # ternary predicate.

    if modifier in {
        "EXACT",
        "+",
        "!",
    }:

        return {
            "status": "DIRECT_TERNARY",

            "effective_test_mask": (
                effective_test_mask
            ),
        }

    # '*' means that at least one of the tested bits must
    # be present.
    #
    # One tested bit -> one ternary entry.
    # Multiple tested bits -> union of multiple entries.

    if modifier == "*":

        tested_bits = bit_count(
            effective_test_mask
        )

        if tested_bits <= 1:

            return {
                "status": "DIRECT_TERNARY",

                "effective_test_mask": (
                    effective_test_mask
                ),
            }

        return {
            "status": "MULTI_ENTRY_REQUIRED",

            "required_entries": tested_bits,

            "effective_test_mask": (
                effective_test_mask
            ),
        }

    return {
        "status": "INVALID",
    }


# ============================================================
# Entry validation
# ============================================================


def validate_entry(
    entry,
    errors,
    warnings,
):
    table = entry.get(
        "table"
    )

    action = entry.get(
        "action",
        {},
    )

    match = entry.get(
        "match",
        {},
    )

    semantic_class = entry.get(
        "semantic_class"
    )

    final_detection = entry.get(
        "final_detection"
    )

    # --------------------------------------------------------
    # Table
    # --------------------------------------------------------

    if table != EXPECTED_TABLE:

        add_issue(
            errors,
            entry,
            f"unexpected table: {table}",
        )

    # --------------------------------------------------------
    # Action
    # --------------------------------------------------------

    if not isinstance(action, dict):

        add_issue(
            errors,
            entry,
            (
                "action is not a dictionary: "
                f"{action}"
            ),
        )

    else:

        action_name = action.get(
            "name"
        )

        if action_name != EXPECTED_ACTION:

            add_issue(
                errors,
                entry,
                (
                    "unexpected action: "
                    f"{action_name}"
                ),
            )

        extra_action_fields = (
            set(action.keys())
            - {
                "name",
            }
        )

        if extra_action_fields:

            add_issue(
                errors,
                entry,
                (
                    "action contains unexpected "
                    f"arguments: "
                    f"{sorted(extra_action_fields)}"
                ),
            )

    # --------------------------------------------------------
    # Semantic contract
    # --------------------------------------------------------

    if semantic_class not in {
        "EXACT",
        "NECESSARY",
    }:

        add_issue(
            errors,
            entry,
            (
                "backend contains rule with "
                "invalid semantic class: "
                f"{semantic_class}"
            ),
        )

    if (
        semantic_class == "NECESSARY"
        and
        final_detection != "SNORT"
    ):

        add_issue(
            errors,
            entry,
            (
                "NECESSARY backend entry must "
                "retain SNORT final detection"
            ),
        )

    # --------------------------------------------------------
    # Match structure
    # --------------------------------------------------------

    if not isinstance(match, dict):

        add_issue(
            errors,
            entry,
            "match is not a dictionary",
        )

        return None

    if not match:

        add_issue(
            errors,
            entry,
            (
                "backend entry contains "
                "an empty match"
            ),
        )

    if contains_list(match):

        add_issue(
            errors,
            entry,
            (
                "backend entry still contains "
                "an unresolved list"
            ),
        )

    unknown_fields = (
        set(match.keys())
        - SUPPORTED_MATCH_FIELDS
    )

    if unknown_fields:

        add_issue(
            errors,
            entry,
            (
                "unsupported P4 match fields: "
                f"{sorted(unknown_fields)}"
            ),
        )

    # --------------------------------------------------------
    # Protocol
    # --------------------------------------------------------

    protocol = match.get(
        "protocol"
    )

    if protocol is not None:

        if (
            not isinstance(protocol, int)
            or isinstance(protocol, bool)
            or not 0 <= protocol <= 255
        ):

            add_issue(
                errors,
                entry,
                (
                    "invalid protocol value: "
                    f"{protocol}"
                ),
            )

        elif protocol not in SUPPORTED_PROTOCOLS:

            add_issue(
                errors,
                entry,
                (
                    "protocol is not supported by "
                    "the current P4 parser/backend: "
                    f"{protocol}"
                ),
            )

    # --------------------------------------------------------
    # IPv4
    # --------------------------------------------------------

    if "src_ip" in match:

        validate_ip_field(
            "src_ip",
            match["src_ip"],
            entry,
            errors,
        )

    if "dst_ip" in match:

        validate_ip_field(
            "dst_ip",
            match["dst_ip"],
            entry,
            errors,
        )

    # --------------------------------------------------------
    # Ports
    # --------------------------------------------------------

    has_ports = (
        "src_port" in match
        or
        "dst_port" in match
    )

    if "src_port" in match:

        validate_port_field(
            "src_port",
            match["src_port"],
            entry,
            errors,
        )

    if "dst_port" in match:

        validate_port_field(
            "dst_port",
            match["dst_port"],
            entry,
            errors,
        )

    if has_ports:

        # ----------------------------------------------------
        # Explicit L4 protocol
        #
        # When protocol is present, exact ports are meaningful
        # only for TCP or UDP in the current backend.
        # ----------------------------------------------------

        if protocol is not None:

            if protocol not in {
                6,
                17,
            }:

                add_issue(
                    errors,
                    entry,
                    (
                        "L4 port predicate is incompatible "
                        "with explicit protocol="
                        f"{protocol}"
                    ),
                )

        # ----------------------------------------------------
        # No explicit L4 protocol
        #
        # This is valid for NECESSARY rules derived from
        # traditional Snort headers such as:
        #
        #     alert http any $HTTP_PORTS -> $HOME_NET any
        #
        # The application-service condition is delegated to
        # Snort while the port remains a conservative
        # necessary prefilter condition.
        #
        # It is not sufficient for EXACT semantics.
        # ----------------------------------------------------

        elif semantic_class == "EXACT":

            add_issue(
                errors,
                entry,
                (
                    "EXACT entry contains L4 port "
                    "without an explicit TCP/UDP protocol"
                ),
            )

    # --------------------------------------------------------
    # TCP flags
    # --------------------------------------------------------

    flag_analysis = None

    if "tcp_flags" in match:

        if protocol != 6:

            add_issue(
                errors,
                entry,
                (
                    "TCP flags predicate exists "
                    f"with protocol={protocol}"
                ),
            )

        flag_analysis = analyze_tcp_flags(
            match["tcp_flags"],
            entry,
            errors,
        )

    # --------------------------------------------------------
    # Orientation
    # --------------------------------------------------------

    orientation = entry.get(
        "orientation"
    )

    if orientation not in {
        "forward",
        "reverse",
    }:

        add_issue(
            errors,
            entry,
            (
                "invalid concrete orientation: "
                f"{orientation}"
            ),
        )

    return flag_analysis


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
        "source_entries",
        0,
    )

    normalized_entries_count = data.get(
        "normalized_entries",
        0,
    )

    normalization_failures = data.get(
        "failures",
        [],
    )

    entries = data.get(
        "entries",
        [],
    )

    errors = []
    warnings = []

    protocol_counter = Counter()

    semantic_class_counter = Counter()

    orientation_counter = Counter()

    flag_lowering_counter = Counter()

    flag_multi_entry_extra = 0

    # ========================================================
    # Top-level consistency
    # ========================================================

    if normalization_failures:

        errors.append(
            {
                "backend_entry_id": (
                    "<normalization>"
                ),

                "rule_id": None,

                "message": (
                    f"{len(normalization_failures)} "
                    "normalization failures remain "
                    "in input"
                ),
            }
        )

    if normalized_entries_count != len(entries):

        errors.append(
            {
                "backend_entry_id": (
                    "<manifest>"
                ),

                "rule_id": None,

                "message": (
                    "normalized_entries does not "
                    "match len(entries): "
                    f"{normalized_entries_count} "
                    f"!= {len(entries)}"
                ),
            }
        )

    if source_entries != len(entries):

        errors.append(
            {
                "backend_entry_id": (
                    "<manifest>"
                ),

                "rule_id": None,

                "message": (
                    "source_entries does not match "
                    "normalized concrete entries: "
                    f"{source_entries} "
                    f"!= {len(entries)}"
                ),
            }
        )

    # ========================================================
    # Validate each entry
    # ========================================================

    match_occurrences = Counter()

    for entry in entries:

        match = entry.get(
            "match",
            {},
        )

        protocol = match.get(
            "protocol"
        )

        if protocol is not None:

            protocol_counter[
                protocol
            ] += 1

        semantic_class_counter[
            entry.get(
                "semantic_class"
            )
        ] += 1

        orientation_counter[
            entry.get(
                "orientation"
            )
        ] += 1

        flag_analysis = validate_entry(
            entry,
            errors,
            warnings,
        )

        if flag_analysis:

            status = flag_analysis.get(
                "status"
            )

            flag_lowering_counter[
                status
            ] += 1

            if status == "MULTI_ENTRY_REQUIRED":

                required = flag_analysis.get(
                    "required_entries",
                    1,
                )

                flag_multi_entry_extra += (
                    required
                    - 1
                )

        key = normalized_match_key(
            match
        )

        match_occurrences[
            key
        ] += 1

    # ========================================================
    # Duplicate analysis
    # ========================================================

    unique_matches = len(
        match_occurrences
    )

    duplicate_entries = (
        len(entries)
        - unique_matches
    )

    duplicated_match_groups = sum(
        1
        for count in match_occurrences.values()
        if count > 1
    )

    maximum_duplicate_multiplicity = max(
        match_occurrences.values(),
        default=0,
    )

    # ========================================================
    # Capacity
    # ========================================================

    raw_capacity_ok = (
        len(entries)
        <= P4_TABLE_SIZE
    )

    unique_capacity_ok = (
        unique_matches
        <= P4_TABLE_SIZE
    )

    estimated_entries_after_flag_lowering = (
        unique_matches
        + flag_multi_entry_extra
    )

    estimated_capacity_ok = (
        estimated_entries_after_flag_lowering
        <= P4_TABLE_SIZE
    )

    if not estimated_capacity_ok:

        errors.append(
            {
                "backend_entry_id": (
                    "<table>"
                ),

                "rule_id": None,

                "message": (
                    "estimated concrete P4 entries "
                    "after flag lowering exceed "
                    f"table size {P4_TABLE_SIZE}: "
                    f"{estimated_entries_after_flag_lowering}"
                ),
            }
        )

    # ========================================================
    # Status
    # ========================================================

    if errors:

        backend_status = "INVALID"

    elif (
        flag_lowering_counter[
            "MULTI_ENTRY_REQUIRED"
        ]
        > 0
    ):

        backend_status = (
            "VALID_WITH_FLAG_EXPANSION"
        )

    else:

        backend_status = "VALID"

    # ========================================================
    # Report
    # ========================================================

    report = {
        "schema_version": "2.1",

        "source_file": input_path.name,

        "source_entries": source_entries,

        "normalized_entries": (
            normalized_entries_count
        ),

        "validation_errors": len(
            errors
        ),

        "validation_warnings": len(
            warnings
        ),

        "unique_normalized_matches": (
            unique_matches
        ),

        "duplicate_entries": (
            duplicate_entries
        ),

        "duplicated_match_groups": (
            duplicated_match_groups
        ),

        "maximum_duplicate_multiplicity": (
            maximum_duplicate_multiplicity
        ),

        "table_capacity": (
            P4_TABLE_SIZE
        ),

        "raw_entries_fit_table": (
            raw_capacity_ok
        ),

        "unique_entries_fit_table": (
            unique_capacity_ok
        ),

        "flag_lowering": {
            "direct_ternary": (
                flag_lowering_counter[
                    "DIRECT_TERNARY"
                ]
            ),

            "multi_entry_required": (
                flag_lowering_counter[
                    "MULTI_ENTRY_REQUIRED"
                ]
            ),

            "estimated_additional_entries": (
                flag_multi_entry_extra
            ),
        },

        "estimated_entries_after_dedup_and_flag_lowering": (
            estimated_entries_after_flag_lowering
        ),

        "estimated_entries_fit_table": (
            estimated_capacity_ok
        ),

        "protocols": dict(
            protocol_counter
        ),

        "semantic_classes": dict(
            semantic_class_counter
        ),

        "orientations": dict(
            orientation_counter
        ),

        "backend_status": (
            backend_status
        ),

        "errors": errors,

        "warnings": warnings,
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
            report,
            file,
            indent=2,
            ensure_ascii=False,
        )

    # ========================================================
    # Console report
    # ========================================================

    print()
    print(
        "=== Backend / P4 Compatibility Validation ==="
    )
    print()

    print(
        f"Source entries                : "
        f"{source_entries}"
    )

    print(
        f"Normalized entries            : "
        f"{normalized_entries_count}"
    )

    print(
        f"Validation errors             : "
        f"{len(errors)}"
    )

    print(
        f"Validation warnings           : "
        f"{len(warnings)}"
    )

    print()

    print(
        "Normalized match deduplication"
    )
    print(
        "-" * 60
    )

    print(
        f"Unique matches                 : "
        f"{unique_matches}"
    )

    print(
        f"Duplicate entries              : "
        f"{duplicate_entries}"
    )

    print(
        f"Duplicated match groups        : "
        f"{duplicated_match_groups}"
    )

    print(
        f"Maximum duplicate multiplicity : "
        f"{maximum_duplicate_multiplicity}"
    )

    print()

    print(
        "TCP flag lowering"
    )
    print(
        "-" * 60
    )

    print(
        f"Direct ternary                 : "
        f"{flag_lowering_counter['DIRECT_TERNARY']}"
    )

    print(
        f"Need multi-entry expansion     : "
        f"{flag_lowering_counter['MULTI_ENTRY_REQUIRED']}"
    )

    print(
        f"Estimated additional entries   : "
        f"{flag_multi_entry_extra}"
    )

    print()

    print(
        "Table capacity"
    )
    print(
        "-" * 60
    )

    print(
        f"Configured table size          : "
        f"{P4_TABLE_SIZE}"
    )

    print(
        f"Raw concrete entries           : "
        f"{len(entries)}"
    )

    print(
        f"Unique concrete matches        : "
        f"{unique_matches}"
    )

    print(
        f"After flag lowering (estimated): "
        f"{estimated_entries_after_flag_lowering}"
    )

    print(
        f"Fits configured table          : "
        f"{estimated_capacity_ok}"
    )

    print()

    print(
        "Protocols"
    )
    print(
        "-" * 60
    )

    protocol_names = {
        1: "ICMP",
        6: "TCP",
        17: "UDP",
    }

    for protocol, count in sorted(
        protocol_counter.items()
    ):

        print(
            f"{protocol:>3} "
            f"({protocol_names.get(protocol, 'OTHER'):<5}) "
            f": {count:>6}"
        )

    print()

    print(
        f"Backend status                : "
        f"{backend_status}"
    )

    print(
        f"Output                        : "
        f"{output_path.resolve()}"
    )

    if errors:

        print()
        print(
            "VALIDATION ERRORS"
        )
        print(
            "=" * 75
        )

        for issue in errors[:50]:

            print(
                f"Entry "
                f"{issue.get('backend_entry_id')} | "
                f"SID {issue.get('rule_id')} | "
                f"{issue.get('message')}"
            )

    if warnings:

        print()
        print(
            "VALIDATION WARNINGS"
        )
        print(
            "=" * 75
        )

        for issue in warnings[:50]:

            print(
                f"Entry "
                f"{issue.get('backend_entry_id')} | "
                f"SID {issue.get('rule_id')} | "
                f"{issue.get('message')}"
            )


if __name__ == "__main__":
    main()
import json

from copy import deepcopy
from pathlib import Path


INPUT_FILE = "../output/p4runtime_entries.json"
OUTPUT_FILE = "../output/p4_install_entries.json"


# ============================================================
# Generic utilities
# ============================================================


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


def match_key(match):
    """
    Stable semantic key for one P4 match.
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


def append_unique(
    container,
    value,
):
    if value is None:
        return

    if value not in container:
        container.append(value)


def merge_unique(
    destination,
    source,
):
    for value in source:

        if value not in destination:
            destination.append(
                value
            )


def sortable_rule_id(value):
    """
    Sort numeric SIDs numerically while still allowing
    non-numeric IDs if they appear in future inputs.
    """

    text = str(value)

    try:

        return (
            0,
            int(text),
        )

    except ValueError:

        return (
            1,
            text,
        )


# ============================================================
# Provenance
# ============================================================


def create_provenance(
    entry
):
    provenance = {
        "source_rule_ids": [],

        "source_backend_entry_ids": [],

        "semantic_classes": [],

        "rule_types": [],

        "orientations": [],
    }

    append_unique(
        provenance[
            "source_rule_ids"
        ],
        str(
            entry.get(
                "rule_id"
            )
        ),
    )

    append_unique(
        provenance[
            "source_backend_entry_ids"
        ],
        entry.get(
            "backend_entry_id"
        ),
    )

    append_unique(
        provenance[
            "semantic_classes"
        ],
        entry.get(
            "semantic_class"
        ),
    )

    append_unique(
        provenance[
            "rule_types"
        ],
        entry.get(
            "rule_type"
        ),
    )

    append_unique(
        provenance[
            "orientations"
        ],
        entry.get(
            "orientation"
        ),
    )

    return provenance


def merge_provenance(
    destination,
    source,
):
    for field in (
        "source_rule_ids",
        "source_backend_entry_ids",
        "semantic_classes",
        "rule_types",
        "orientations",
    ):

        merge_unique(
            destination[field],
            source.get(
                field,
                [],
            ),
        )


def finalize_provenance(
    provenance
):
    provenance[
        "source_rule_ids"
    ] = sorted(
        provenance[
            "source_rule_ids"
        ],
        key=sortable_rule_id,
    )

    provenance[
        "source_backend_entry_ids"
    ] = sorted(
        provenance[
            "source_backend_entry_ids"
        ]
    )

    provenance[
        "semantic_classes"
    ] = sorted(
        provenance[
            "semantic_classes"
        ]
    )

    provenance[
        "rule_types"
    ] = sorted(
        provenance[
            "rule_types"
        ]
    )

    provenance[
        "orientations"
    ] = sorted(
        provenance[
            "orientations"
        ]
    )

    provenance[
        "source_rule_count"
    ] = len(
        provenance[
            "source_rule_ids"
        ]
    )

    provenance[
        "source_backend_entry_count"
    ] = len(
        provenance[
            "source_backend_entry_ids"
        ]
    )


# ============================================================
# First deduplication stage
# ============================================================


def deduplicate_normalized_entries(
    entries
):
    """
    Collapse identical normalized semantic matches.

    The P4 action is only:

        send_to_ids()

    so two rules that produce the same prefilter predicate do
    not require two physical table entries.

    Snort SID provenance is retained separately.
    """

    groups = {}

    for entry in entries:

        match = entry.get(
            "match",
            {},
        )

        key = match_key(
            match
        )

        if key not in groups:

            groups[
                key
            ] = {
                "match": deepcopy(
                    match
                ),

                "table": entry.get(
                    "table",
                    "ids_prefilter",
                ),

                "action": {
                    "name": "send_to_ids",
                },

                "provenance": (
                    create_provenance(
                        entry
                    )
                ),
            }

        else:

            merge_provenance(
                groups[
                    key
                ][
                    "provenance"
                ],

                create_provenance(
                    entry
                ),
            )

    return list(
        groups.values()
    )


# ============================================================
# TCP flags lowering
# ============================================================


def flag_bits(mask):
    """
    Return each individual set bit in one 8-bit mask.

    Example:

        0x12
            ->
        [0x02, 0x10]
    """

    result = []

    for bit_index in range(8):

        bit = (
            1
            << bit_index
        )

        if mask & bit:

            result.append(
                bit
            )

    return result


def lower_tcp_flags(
    flags
):
    """
    Lower normalized Snort flags semantics into one or more
    P4 ternary value/mask pairs.

    P4 representation:

        {
            "value": <8-bit value>,
            "mask":  <8-bit ternary mask>
        }

    Semantics:

    EXACT
        All non-ignored flags are compared.

    +
        All tested flags must be set. Other flags are
        don't-care.

    !
        All tested flags must be clear.

    *
        At least one tested flag must be set.

        With multiple tested bits, this is represented as the
        union of one ternary entry per tested bit.
    """

    if not isinstance(
        flags,
        dict,
    ):

        raise ValueError(
            "tcp_flags must be a normalized "
            "dictionary"
        )

    modifier = flags.get(
        "modifier"
    )

    test_mask = flags.get(
        "test_mask"
    )

    ignore_mask = flags.get(
        "ignore_mask"
    )

    if (
        not isinstance(test_mask, int)
        or
        not isinstance(ignore_mask, int)
    ):

        raise ValueError(
            f"Invalid TCP flags masks: {flags}"
        )

    test_mask &= 0xFF
    ignore_mask &= 0xFF

    effective_test_mask = (
        test_mask
        & (
            ~ignore_mask
            & 0xFF
        )
    )

    # --------------------------------------------------------
    # EXACT
    #
    # Compare every bit except explicitly ignored flags.
    #
    # Example:
    #
    #     flags:S;
    #
    # value = SYN
    # mask  = 0xff
    #
    # Example:
    #
    #     flags:SF,CE;
    #
    # CWR and ECE are don't-care.
    # --------------------------------------------------------

    if modifier == "EXACT":

        comparison_mask = (
            ~ignore_mask
            & 0xFF
        )

        comparison_value = (
            test_mask
            & comparison_mask
        )

        if comparison_mask == 0:

            return [
                None
            ]

        return [
            {
                "value": (
                    comparison_value
                ),

                "mask": (
                    comparison_mask
                ),
            }
        ]

    # --------------------------------------------------------
    # +
    #
    # All specified bits must be present; unspecified bits may
    # take any value.
    # --------------------------------------------------------

    if modifier == "+":

        if effective_test_mask == 0:

            return [
                None
            ]

        return [
            {
                "value": (
                    effective_test_mask
                ),

                "mask": (
                    effective_test_mask
                ),
            }
        ]

    # --------------------------------------------------------
    # !
    #
    # Specified bits must not be set.
    # --------------------------------------------------------

    if modifier == "!":

        if effective_test_mask == 0:

            return [
                None
            ]

        return [
            {
                "value": 0,

                "mask": (
                    effective_test_mask
                ),
            }
        ]

    # --------------------------------------------------------
    # *
    #
    # At least one tested flag must be set.
    #
    # A ternary match cannot express an OR between arbitrary
    # bits inside one table entry, therefore:
    #
    #     flags:*SA
    #
    # becomes:
    #
    #     SYN = 1
    #
    # OR
    #
    #     ACK = 1
    #
    # represented by two entries.
    # --------------------------------------------------------

    if modifier == "*":

        bits = flag_bits(
            effective_test_mask
        )

        if not bits:

            raise ValueError(
                "TCP flags '*' expression has "
                "no effective tested bits: "
                f"{flags}"
            )

        return [
            {
                "value": bit,

                "mask": bit,
            }
            for bit in bits
        ]

    raise ValueError(
        "Unsupported TCP flag modifier: "
        f"{modifier}"
    )


# ============================================================
# Match lowering
# ============================================================


def lower_match(
    match
):
    """
    Lower one normalized semantic match into one or more
    directly installable P4-level matches.

    At present only TCP flags require semantic lowering.
    IPv4 prefix conversion to the exact P4Runtime wire format
    is intentionally handled in the next stage.
    """

    if (
        "tcp_flags"
        not in match
    ):

        return [
            deepcopy(
                match
            )
        ]

    base_match = deepcopy(
        match
    )

    flags = base_match.pop(
        "tcp_flags"
    )

    lowered_flags = (
        lower_tcp_flags(
            flags
        )
    )

    results = []

    for flag_match in lowered_flags:

        lowered_match = deepcopy(
            base_match
        )

        # None means the flag condition became unconstrained
        # after masking and therefore should be omitted from
        # the ternary table key.
        if flag_match is not None:

            lowered_match[
                "tcp_flags"
            ] = flag_match

        results.append(
            lowered_match
        )

    return results


# ============================================================
# Lower unique semantic groups
# ============================================================


def lower_unique_groups(
    unique_groups
):
    lowered = []

    groups_with_flags = 0
    groups_expanded_by_flags = 0
    additional_flag_entries = 0

    for group in unique_groups:

        source_match = group[
            "match"
        ]

        if (
            "tcp_flags"
            in source_match
        ):

            groups_with_flags += 1

        lowered_matches = (
            lower_match(
                source_match
            )
        )

        if len(
            lowered_matches
        ) > 1:

            groups_expanded_by_flags += 1

            additional_flag_entries += (
                len(
                    lowered_matches
                )
                - 1
            )

        for lowered_match in (
            lowered_matches
        ):

            lowered.append(
                {
                    "table": group[
                        "table"
                    ],

                    "action": deepcopy(
                        group[
                            "action"
                        ]
                    ),

                    "match": (
                        lowered_match
                    ),

                    "provenance": deepcopy(
                        group[
                            "provenance"
                        ]
                    ),
                }
            )

    statistics = {
        "groups_with_flags": (
            groups_with_flags
        ),

        "groups_expanded_by_flags": (
            groups_expanded_by_flags
        ),

        "additional_flag_entries": (
            additional_flag_entries
        ),
    }

    return (
        lowered,
        statistics,
    )


# ============================================================
# Final deduplication
# ============================================================


def final_deduplication(
    lowered_entries
):
    """
    Different normalized flag expressions can lower to the
    same actual P4 ternary predicate.

    Deduplicate again after lowering and merge provenance.
    """

    groups = {}

    for entry in (
        lowered_entries
    ):

        key = match_key(
            entry[
                "match"
            ]
        )

        if key not in groups:

            groups[
                key
            ] = deepcopy(
                entry
            )

        else:

            merge_provenance(
                groups[
                    key
                ][
                    "provenance"
                ],

                entry[
                    "provenance"
                ],
            )

    return list(
        groups.values()
    )


# ============================================================
# Final validation
# ============================================================


def validate_final_entries(
    entries
):
    errors = []

    for entry in entries:

        match = entry.get(
            "match",
            {},
        )

        if not match:

            errors.append(
                (
                    entry.get(
                        "install_entry_id"
                    ),
                    "empty P4 match",
                )
            )

        if "tcp_flags" in match:

            flags = match[
                "tcp_flags"
            ]

            if not isinstance(
                flags,
                dict,
            ):

                errors.append(
                    (
                        entry.get(
                            "install_entry_id"
                        ),
                        "lowered tcp_flags "
                        "is not a dictionary",
                    )
                )

                continue

            value = flags.get(
                "value"
            )

            mask = flags.get(
                "mask"
            )

            if (
                not isinstance(
                    value,
                    int,
                )
                or
                not isinstance(
                    mask,
                    int,
                )
            ):

                errors.append(
                    (
                        entry.get(
                            "install_entry_id"
                        ),
                        "invalid tcp_flags "
                        "value/mask",
                    )
                )

                continue

            if not (
                0 <= value <= 255
                and
                0 < mask <= 255
            ):

                errors.append(
                    (
                        entry.get(
                            "install_entry_id"
                        ),
                        "tcp_flags outside "
                        "8-bit ternary range",
                    )
                )

    return errors


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

    entries = data.get(
        "entries",
        [],
    )

    source_count = len(
        entries
    )

    # ========================================================
    # Stage 1:
    # Deduplicate identical normalized semantic predicates
    # ========================================================

    unique_groups = (
        deduplicate_normalized_entries(
            entries
        )
    )

    unique_before_lowering = len(
        unique_groups
    )

    # ========================================================
    # Stage 2:
    # Lower TCP flags
    # ========================================================

    (
        lowered_entries,
        lowering_statistics,
    ) = lower_unique_groups(
        unique_groups
    )

    lowered_before_final_dedup = len(
        lowered_entries
    )

    # ========================================================
    # Stage 3:
    # Deduplicate actual P4 predicates
    # ========================================================

    final_entries = (
        final_deduplication(
            lowered_entries
        )
    )

    # ========================================================
    # IDs and provenance
    # ========================================================

    for index, entry in enumerate(
        final_entries,
        start=1,
    ):

        entry[
            "install_entry_id"
        ] = (
            f"p4-{index}"
        )

        finalize_provenance(
            entry[
                "provenance"
            ]
        )

    final_count = len(
        final_entries
    )

    final_duplicates_removed = (
        lowered_before_final_dedup
        - final_count
    )

    # ========================================================
    # Final validation
    # ========================================================

    validation_errors = (
        validate_final_entries(
            final_entries
        )
    )

    # ========================================================
    # Statistics
    # ========================================================

    total_reduction = (
        source_count
        - final_count
    )

    reduction_percentage = (
        total_reduction
        / source_count
        * 100
        if source_count
        else 0
    )

    maximum_rule_provenance = max(
        (
            entry[
                "provenance"
            ][
                "source_rule_count"
            ]
            for entry in final_entries
        ),
        default=0,
    )

    # ========================================================
    # Output
    # ========================================================

    output = {
        "schema_version": "1.0",

        "source_file": (
            input_path.name
        ),

        "table": (
            "ids_prefilter"
        ),

        "action": (
            "send_to_ids"
        ),

        "source_entries": (
            source_count
        ),

        "unique_matches_before_flag_lowering": (
            unique_before_lowering
        ),

        "lowered_entries_before_final_dedup": (
            lowered_before_final_dedup
        ),

        "final_install_entries": (
            final_count
        ),

        "final_duplicates_removed": (
            final_duplicates_removed
        ),

        "total_reduction": (
            total_reduction
        ),

        "reduction_percentage": (
            reduction_percentage
        ),

        "flag_lowering": (
            lowering_statistics
        ),

        "maximum_source_rules_per_install_entry": (
            maximum_rule_provenance
        ),

        "validation_errors": [
            {
                "install_entry_id": (
                    entry_id
                ),

                "message": message,
            }
            for entry_id, message
            in validation_errors
        ],

        "entries": (
            final_entries
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
        "=== Final P4 Entry Lowering ==="
    )
    print()

    print(
        f"Source normalized entries       : "
        f"{source_count}"
    )

    print(
        f"Unique before flag lowering     : "
        f"{unique_before_lowering}"
    )

    print(
        f"Groups containing TCP flags     : "
        f"{lowering_statistics['groups_with_flags']}"
    )

    print(
        f"Groups expanded by '*' flags    : "
        f"{lowering_statistics['groups_expanded_by_flags']}"
    )

    print(
        f"Additional entries from flags   : "
        f"{lowering_statistics['additional_flag_entries']}"
    )

    print(
        f"Before final dedup              : "
        f"{lowered_before_final_dedup}"
    )

    print(
        f"Duplicates after lowering       : "
        f"{final_duplicates_removed}"
    )

    print(
        f"Final install entries           : "
        f"{final_count}"
    )

    print()

    print(
        f"Total entries removed           : "
        f"{total_reduction}"
    )

    print(
        f"Reduction                       : "
        f"{reduction_percentage:.2f}%"
    )

    print(
        f"Maximum rules/install entry     : "
        f"{maximum_rule_provenance}"
    )

    print(
        f"Validation errors               : "
        f"{len(validation_errors)}"
    )

    print()

    if validation_errors:

        print(
            "LOWERING VALIDATION ERRORS"
        )

        print(
            "=" * 70
        )

        for (
            entry_id,
            message,
        ) in validation_errors[:30]:

            print(
                f"{entry_id}: "
                f"{message}"
            )

        print()

    print(
        f"Output:"
    )

    print(
        output_path.resolve()
    )


if __name__ == "__main__":
    main()
import paths

import ast
import json

from copy import deepcopy
from itertools import product
from pathlib import Path

import pipeline_gate


INPUT_FILE = (
    paths.OUTPUT_DIR
    / "p4_entries.json"
)
OUTPUT_FILE = (
    paths.OUTPUT_DIR
    / "p4_entries_expanded.json"
)


# ============================================================
# Backend fields that may contain finite alternatives
# ============================================================


EXPANDABLE_FIELDS = {
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "tcp_flags",
}


# ============================================================
# Finite-list normalization
# ============================================================


def parse_textual_list(value):
    """
    Convert a textual finite-list representation into a
    Python list.

    Examples:

        "[80,8080]"
            ->
        [80, 8080]

        "[139,445]"
            ->
        [139, 445]
    """

    if not isinstance(
        value,
        str,
    ):
        return None

    text = value.strip()

    if not (
        text.startswith("[")
        and text.endswith("]")
    ):
        return None

    # --------------------------------------------------------
    # First try Python literal syntax.
    # --------------------------------------------------------

    try:

        parsed = ast.literal_eval(
            text
        )

        if isinstance(
            parsed,
            (list, tuple),
        ):

            return list(
                parsed
            )

    except (
        ValueError,
        SyntaxError,
    ):
        pass

    # --------------------------------------------------------
    # Fallback for Snort-style lists.
    # --------------------------------------------------------

    inner = (
        text[1:-1]
        .strip()
    )

    if not inner:
        return []

    values = []

    for item in inner.split(","):

        item = item.strip()

        if not item:
            continue

        # Remove simple quotes.
        if (
            len(item) >= 2
            and
            item[0] == item[-1]
            and
            item[0] in {
                "'",
                '"',
            }
        ):

            item = item[
                1:-1
            ]

        try:

            converted = int(
                item
            )

        except ValueError:

            converted = item

        values.append(
            converted
        )

    return values


def normalize_to_list(value):
    """
    Normalize scalar, Python-list or textual-list values.
    """

    if isinstance(
        value,
        list,
    ):
        return value

    if isinstance(
        value,
        tuple,
    ):
        return list(
            value
        )

    textual_list = (
        parse_textual_list(
            value
        )
    )

    if textual_list is not None:

        return textual_list

    return [
        value
    ]


def value_is_list_like(value):
    """
    True when the value still represents more than one
    finite alternative.
    """

    if isinstance(
        value,
        (list, tuple),
    ):
        return True

    if isinstance(
        value,
        str,
    ):

        return (
            parse_textual_list(
                value
            )
            is not None
        )

    return False


# ============================================================
# Duplicate keys
# ============================================================


def make_hashable(value):

    if isinstance(
        value,
        dict,
    ):

        return tuple(
            sorted(
                (
                    key,
                    make_hashable(item),
                )
                for key, item
                in value.items()
            )
        )

    if isinstance(
        value,
        (list, tuple),
    ):

        return tuple(
            make_hashable(item)
            for item in value
        )

    return value


def entry_match_key(match):

    return tuple(
        sorted(
            (
                field,
                make_hashable(value),
            )
            for field, value
            in match.items()
        )
    )


# ============================================================
# Bidirectional expansion
# ============================================================


def reverse_match_orientation(
    match
):
    """
    Reverse source/destination orientation.

        src_ip   <-> dst_ip
        src_port <-> dst_port
    """

    reversed_match = deepcopy(
        match
    )

    # --------------------------------------------------------
    # IP pair
    # --------------------------------------------------------

    src_ip_present = (
        "src_ip" in match
    )

    dst_ip_present = (
        "dst_ip" in match
    )

    src_ip = match.get(
        "src_ip"
    )

    dst_ip = match.get(
        "dst_ip"
    )

    reversed_match.pop(
        "src_ip",
        None,
    )

    reversed_match.pop(
        "dst_ip",
        None,
    )

    if dst_ip_present:

        reversed_match[
            "src_ip"
        ] = dst_ip

    if src_ip_present:

        reversed_match[
            "dst_ip"
        ] = src_ip

    # --------------------------------------------------------
    # Port pair
    # --------------------------------------------------------

    src_port_present = (
        "src_port" in match
    )

    dst_port_present = (
        "dst_port" in match
    )

    src_port = match.get(
        "src_port"
    )

    dst_port = match.get(
        "dst_port"
    )

    reversed_match.pop(
        "src_port",
        None,
    )

    reversed_match.pop(
        "dst_port",
        None,
    )

    if dst_port_present:

        reversed_match[
            "src_port"
        ] = dst_port

    if src_port_present:

        reversed_match[
            "dst_port"
        ] = src_port

    return reversed_match


def reverse_expansion_fields(
    expansion_fields
):
    """
    Reverse field names together with a bidirectional match.

    This is essential.

    Example:

        original:
            dst_port = [80, 8080]
            expansion_fields = ["dst_port"]

        reversed:
            src_port = [80, 8080]

    Therefore the reversed expansion field must become:

            ["src_port"]
    """

    reversed_fields = []

    for field in (
        expansion_fields
        or []
    ):

        if field == "src_ip":

            reversed_fields.append(
                "dst_ip"
            )

        elif field == "dst_ip":

            reversed_fields.append(
                "src_ip"
            )

        elif field == "src_port":

            reversed_fields.append(
                "dst_port"
            )

        elif field == "dst_port":

            reversed_fields.append(
                "src_port"
            )

        else:

            reversed_fields.append(
                field
            )

    return reversed_fields


def build_orientations(
    entry
):
    """
    Materialize Snort direction semantics.

    Both the concrete match AND the semantic expansion-field
    names are transformed for the reverse orientation.
    """

    match = deepcopy(
        entry.get(
            "match",
            {},
        )
    )

    direction = entry.get(
        "direction"
    )

    expansion_fields = list(
        entry.get(
            "expansion_fields",
            [],
        )
    )

    if direction == "<>":

        return [
            {
                "orientation": "forward",

                "match": (
                    match
                ),

                "expansion_fields": (
                    expansion_fields
                ),
            },

            {
                "orientation": "reverse",

                "match": (
                    reverse_match_orientation(
                        match
                    )
                ),

                "expansion_fields": (
                    reverse_expansion_fields(
                        expansion_fields
                    )
                ),
            },
        ]

    return [
        {
            "orientation": "forward",

            "match": match,

            "expansion_fields": (
                expansion_fields
            ),
        }
    ]


# ============================================================
# Finite alternative expansion
# ============================================================


def expand_match_lists(
    match,
    expansion_fields,
):
    """
    Expand finite alternatives for fields explicitly marked
    EXPANDED by the semantic capability analysis.
    """

    expansion_fields = set(
        expansion_fields
        or []
    )

    expandable = {}

    static_fields = {}

    for field, value in (
        match.items()
    ):

        if (
            field
            in EXPANDABLE_FIELDS
            and
            field
            in expansion_fields
        ):

            values = (
                normalize_to_list(
                    value
                )
            )

            if not values:

                raise ValueError(
                    "Empty finite expansion "
                    f"for {field}: {value}"
                )

            expandable[
                field
            ] = values

        else:

            static_fields[
                field
            ] = value

    if not expandable:

        return [
            deepcopy(
                match
            )
        ]

    fields = list(
        expandable.keys()
    )

    value_lists = [
        expandable[
            field
        ]
        for field in fields
    ]

    expanded_matches = []

    for combination in product(
        *value_lists
    ):

        concrete_match = deepcopy(
            static_fields
        )

        for field, value in zip(
            fields,
            combination,
        ):

            concrete_match[
                field
            ] = value

        expanded_matches.append(
            concrete_match
        )

    return expanded_matches


# ============================================================
# Entry expansion
# ============================================================


def expand_entry(
    entry
):
    """
    Convert one semantic backend entry into concrete entries.

        direction
            ↓
        orientation-specific expansion fields
            ↓
        finite expansion
            ↓
        duplicate elimination
    """

    orientations = (
        build_orientations(
            entry
        )
    )

    concrete_results = []

    seen_matches = set()

    for orientation_info in (
        orientations
    ):

        orientation = (
            orientation_info[
                "orientation"
            ]
        )

        oriented_match = (
            orientation_info[
                "match"
            ]
        )

        orientation_expansion_fields = [
            field
            for field in (
                orientation_info[
                    "expansion_fields"
                ]
            )
            if field != "direction"
        ]

        expanded_matches = (
            expand_match_lists(
                oriented_match,
                orientation_expansion_fields,
            )
        )

        for concrete_match in (
            expanded_matches
        ):

            match_key = (
                entry_match_key(
                    concrete_match
                )
            )

            if match_key in (
                seen_matches
            ):
                continue

            seen_matches.add(
                match_key
            )

            new_entry = deepcopy(
                entry
            )

            new_entry[
                "match"
            ] = concrete_match

            new_entry[
                "orientation"
            ] = orientation

            new_entry[
                "direction"
            ] = None

            # Expansion is now fully materialized.
            new_entry[
                "expansion_fields"
            ] = []

            concrete_results.append(
                new_entry
            )

    total = len(
        concrete_results
    )

    for index, concrete_entry in enumerate(
        concrete_results,
        start=1,
    ):

        concrete_entry[
            "backend_entry_id"
        ] = (
            f"{entry['rule_id']}"
            f"-{index}"
        )

        concrete_entry[
            "expansion_index"
        ] = index

        concrete_entry[
            "expansion_count"
        ] = total

    return concrete_results


# ============================================================
# Theoretical expansion
# ============================================================


def count_finite_alternatives(
    match,
    expansion_fields,
):
    """
    Count alternatives for one particular orientation.
    """

    count = 1

    expansion_fields = set(
        expansion_fields
        or []
    )

    for field, value in (
        match.items()
    ):

        if (
            field
            not in EXPANDABLE_FIELDS
            or
            field
            not in expansion_fields
        ):
            continue

        values = normalize_to_list(
            value
        )

        count *= len(
            values
        )

    return count


def count_theoretical_expansion(
    entry
):
    """
    Calculate theoretical concrete alternatives before
    deduplication using orientation-specific field mappings.
    """

    total = 0

    for orientation_info in (
        build_orientations(
            entry
        )
    ):

        expansion_fields = [
            field
            for field in (
                orientation_info[
                    "expansion_fields"
                ]
            )
            if field != "direction"
        ]

        total += (
            count_finite_alternatives(
                orientation_info[
                    "match"
                ],
                expansion_fields,
            )
        )

    return total


# ============================================================
# Concrete-entry validation
# ============================================================


def find_unresolved_list_values(
    concrete_entries
):
    """
    Verify globally that no finite list survives into a
    concrete backend entry.

    This intentionally checks ALL expandable backend fields,
    not merely the original expansion_fields metadata.
    """

    issues = []

    for entry in concrete_entries:

        match = entry.get(
            "match",
            {},
        )

        for field in (
            EXPANDABLE_FIELDS
        ):

            if field not in match:
                continue

            value = match[
                field
            ]

            if value_is_list_like(
                value
            ):

                issues.append(
                    {
                        "backend_entry_id": (
                            entry.get(
                                "backend_entry_id"
                            )
                        ),

                        "rule_id": (
                            entry.get(
                                "rule_id"
                            )
                        ),

                        "orientation": (
                            entry.get(
                                "orientation"
                            )
                        ),

                        "field": field,

                        "value": value,
                    }
                )

    return issues


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

    expanded_entries = []

    expansion_counter = {}

    rules_with_declared_expansion = 0

    rules_with_actual_expansion = 0

    rules_with_list_expansion = 0

    rules_with_direction_expansion = 0

    duplicate_concrete_entries_removed = 0

    empty_match_entries = []

    # ========================================================
    # Expansion
    # ========================================================

    for entry in source_entries:

        rule_id = str(
            entry.get(
                "rule_id"
            )
        )

        direction = (
            entry.get(
                "direction"
            )
        )

        expansion_fields = (
            entry.get(
                "expansion_fields",
                [],
            )
        )

        if expansion_fields:

            rules_with_declared_expansion += 1

        finite_fields = [
            field
            for field in expansion_fields
            if (
                field != "direction"
                and
                field
                in EXPANDABLE_FIELDS
            )
        ]

        if finite_fields:

            rules_with_list_expansion += 1

        if direction == "<>":

            rules_with_direction_expansion += 1

        theoretical_count = (
            count_theoretical_expansion(
                entry
            )
        )

        concrete_entries = (
            expand_entry(
                entry
            )
        )

        actual_count = len(
            concrete_entries
        )

        if actual_count > 1:

            rules_with_actual_expansion += 1

        if (
            theoretical_count
            > actual_count
        ):

            duplicate_concrete_entries_removed += (
                theoretical_count
                - actual_count
            )

        expanded_entries.extend(
            concrete_entries
        )

        expansion_counter[
            rule_id
        ] = actual_count

        for concrete_entry in (
            concrete_entries
        ):

            if not concrete_entry.get(
                "match"
            ):

                empty_match_entries.append(
                    concrete_entry.get(
                        "backend_entry_id"
                    )
                )

    # ========================================================
    # Global post-expansion validation
    # ========================================================

    unresolved_list_values = (
        find_unresolved_list_values(
            expanded_entries
        )
    )

    # ========================================================
    # Statistics
    # ========================================================

    maximum_expansion = max(
        expansion_counter.values(),
        default=0,
    )

    average_expansion = (
        len(expanded_entries)
        / len(source_entries)
        if source_entries
        else 0
    )

    expansion_distribution = {}

    for count in (
        expansion_counter.values()
    ):

        key = str(
            count
        )

        expansion_distribution[
            key
        ] = (
            expansion_distribution.get(
                key,
                0,
            )
            + 1
        )

    # ========================================================
    # Output
    # ========================================================

    output = {
        "schema_version": "2.2",

        "source_file": (
            input_path.name
        ),

        "source_entries": len(
            source_entries
        ),

        "expanded_entries": len(
            expanded_entries
        ),

        "rules_with_declared_expansion": (
            rules_with_declared_expansion
        ),

        "rules_with_actual_expansion": (
            rules_with_actual_expansion
        ),

        "rules_with_list_expansion": (
            rules_with_list_expansion
        ),

        "rules_with_direction_expansion": (
            rules_with_direction_expansion
        ),

        "duplicate_concrete_entries_removed": (
            duplicate_concrete_entries_removed
        ),

        "unresolved_list_values": (
            unresolved_list_values
        ),

        "maximum_entries_per_rule": (
            maximum_expansion
        ),

        "average_entries_per_rule": (
            average_expansion
        ),

        "expansion_distribution": (
            expansion_distribution
        ),

        "entries": (
            expanded_entries
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
        "=== P4 Entry Expansion ==="
    )
    print()

    print(
        f"Source entries               : "
        f"{len(source_entries)}"
    )

    print(
        f"Concrete entries             : "
        f"{len(expanded_entries)}"
    )

    print(
        f"Rules declaring expansion    : "
        f"{rules_with_declared_expansion}"
    )

    print(
        f"Rules with actual expansion  : "
        f"{rules_with_actual_expansion}"
    )

    print(
        f"Rules with list expansion    : "
        f"{rules_with_list_expansion}"
    )

    print(
        f"Rules with <> expansion      : "
        f"{rules_with_direction_expansion}"
    )

    print(
        f"Duplicates removed           : "
        f"{duplicate_concrete_entries_removed}"
    )

    print(
        f"Maximum entries/rule         : "
        f"{maximum_expansion}"
    )

    print(
        f"Average entries/rule         : "
        f"{average_expansion:.2f}"
    )

    print(
        f"Concrete empty matches       : "
        f"{len(empty_match_entries)}"
    )

    print(
        f"Unresolved list values       : "
        f"{len(unresolved_list_values)}"
    )

    print()
    print(
        "Expansion distribution"
    )
    print(
        "-" * 50
    )

    for count in sorted(
        expansion_distribution,
        key=lambda value: int(
            value
        ),
    ):

        print(
            f"{count:>4} entries/rule : "
            f"{expansion_distribution[count]:>5} rules"
        )

    if unresolved_list_values:

        print()
        print(
            "UNRESOLVED LIST VALUES"
        )
        print(
            "=" * 70
        )

        for issue in (
            unresolved_list_values[:30]
        ):

            print(
                f"SID {issue['rule_id']} | "
                f"{issue['orientation']} | "
                f"{issue['field']} = "
                f"{issue['value']}"
            )

    print()
    print(
        f"Output:"
    )
    print(
        output_path.resolve()
    )


    pipeline_gate.aplicar(
        OUTPUT_FILE
    )

if __name__ == "__main__":
    main()
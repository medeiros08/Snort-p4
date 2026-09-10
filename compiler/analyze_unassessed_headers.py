from collections import Counter, defaultdict
from pathlib import Path

from parser import parse_rule
from build_semantic_ir import build_semantic_ir


RULESET_FILE = "../rules/snort3-community.rules"


def is_candidate_rule(line):
    line = line.strip()

    if not line:
        return False

    if line.startswith("#"):
        return False

    return True


def classify_raw_value(field, value):
    """
    Preliminary syntactic classification.

    This does NOT decide P4 support.

    It only tells us what kinds of expressions appear
    in the semantic IR.
    """

    if value is None:
        return "NONE"

    text = str(value).strip()

    if text.lower() == "any":
        return "ANY"

    if text.startswith("!"):
        return "NEGATED"

    if text.startswith("$"):
        return "VARIABLE"

    if (
        text.startswith("[")
        and text.endswith("]")
    ):
        return "LIST"

    if field in {
        "src_port",
        "dst_port",
    }:
        if ":" in text:
            return "PORT_RANGE"

        try:
            int(text)
            return "EXACT_PORT"

        except ValueError:
            return "OTHER_PORT"

    if field in {
        "src_ip",
        "dst_ip",
    }:
        if "/" in text:
            return "CIDR"

        parts = text.split(".")

        if (
            len(parts) == 4
            and all(
                part.isdigit()
                for part in parts
            )
        ):
            return "EXACT_IPV4"

        return "OTHER_ADDRESS"

    if field == "direction":
        if text == "->":
            return "FORWARD"

        if text == "<>":
            return "BIDIRECTIONAL"

        return "OTHER_DIRECTION"

    if field == "protocol":
        return text.lower()

    return "OPTION_VALUE"


def main():
    ruleset_path = Path(
        RULESET_FILE
    )

    if not ruleset_path.exists():
        print(
            "ERROR: Ruleset not found:",
            ruleset_path.resolve(),
        )
        return

    candidate_rules = 0
    parsed_rules = 0
    semantic_failures = 0

    field_counter = Counter()

    field_value_class = defaultdict(
        Counter
    )

    option_header_counter = Counter()

    rules_with_field = Counter()

    examples = defaultdict(list)

    with open(
        ruleset_path,
        "r",
        encoding="utf-8",
        errors="ignore",
    ) as file:

        for line_number, line in enumerate(
            file,
            start=1,
        ):

            if not is_candidate_rule(
                line
            ):
                continue

            candidate_rules += 1

            try:
                parsed = parse_rule(
                    line
                )

            except Exception:
                continue

            if parsed is None:
                continue

            parsed_rules += 1

            try:
                semantic_rule = (
                    build_semantic_ir(
                        parsed
                    )
                )

            except Exception as error:
                semantic_failures += 1

                print(
                    f"Semantic failure "
                    f"line {line_number}: "
                    f"{error}"
                )

                continue

            seen_fields = set()

            for predicate in (
                semantic_rule.predicates
            ):

                if (
                    predicate.kind
                    != "HEADER"
                ):
                    continue

                if (
                    predicate.backend_treatment
                    != "UNASSESSED"
                ):
                    continue

                field = (
                    predicate.field
                    or "UNKNOWN"
                )

                value = predicate.value

                field_counter[
                    field
                ] += 1

                seen_fields.add(
                    field
                )

                value_class = (
                    classify_raw_value(
                        field,
                        value,
                    )
                )

                field_value_class[
                    field
                ][
                    value_class
                ] += 1

                if (
                    predicate.source_option
                    is not None
                ):
                    option_header_counter[
                        predicate.source_option
                    ] += 1

                example_key = (
                    field,
                    value_class,
                )

                if (
                    len(
                        examples[
                            example_key
                        ]
                    )
                    < 5
                ):
                    examples[
                        example_key
                    ].append(
                        (
                            semantic_rule.rule_id,
                            value,
                        )
                    )

            for field in seen_fields:
                rules_with_field[
                    field
                ] += 1

    print()
    print(
        "=== UNASSESSED Header Analysis ==="
    )
    print()

    print(
        f"Candidate rules    : "
        f"{candidate_rules}"
    )

    print(
        f"Parsed rules       : "
        f"{parsed_rules}"
    )

    print(
        f"Semantic failures  : "
        f"{semantic_failures}"
    )

    print()

    print(
        "Header fields"
    )
    print(
        "-" * 60
    )

    for field, count in (
        field_counter.most_common()
    ):

        rules = rules_with_field[
            field
        ]

        percentage = (
            rules / parsed_rules * 100
            if parsed_rules
            else 0
        )

        print(
            f"{field:<20} "
            f"{count:>6} predicates | "
            f"{rules:>5} rules "
            f"({percentage:6.2f}%)"
        )

    print()

    print(
        "Value classes by field"
    )
    print(
        "=" * 70
    )

    for field in sorted(
        field_value_class.keys()
    ):

        print()
        print(
            field.upper()
        )

        print(
            "-" * 50
        )

        for value_class, count in (
            field_value_class[
                field
            ].most_common()
        ):

            print(
                f"{value_class:<25} "
                f"{count:>6}"
            )

    print()
    print(
        "Header options"
    )
    print(
        "-" * 50
    )

    for option, count in (
        option_header_counter
        .most_common()
    ):

        print(
            f"{option:<25} "
            f"{count:>6}"
        )

    print()
    print(
        "Examples"
    )
    print(
        "=" * 70
    )

    for (
        field,
        value_class,
    ), values in sorted(
        examples.items()
    ):

        print()
        print(
            f"{field} / "
            f"{value_class}"
        )

        print(
            "-" * 50
        )

        for sid, value in values:

            print(
                f"SID {sid}: "
                f"{value}"
            )


if __name__ == "__main__":
    main()
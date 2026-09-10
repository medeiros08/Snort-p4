from collections import Counter, defaultdict
from pathlib import Path

from parser import parse_rule
from build_semantic_ir import (
    build_semantic_ir,
    APPLICATION_OPTIONS,
)


RULESET_FILE = "../rules/snort3-community.rules"


def is_candidate_rule(line):
    line = line.strip()

    if not line:
        return False

    if line.startswith("#"):
        return False

    return True


def main():
    ruleset_path = Path(
        RULESET_FILE
    )

    candidate_rules = 0
    parsed_rules = 0
    semantic_failures = 0

    generic_counter = Counter()
    generic_rule_counter = Counter()

    examples = defaultdict(list)

    rules_with_generic = 0

    for line_number, line in enumerate(
        ruleset_path.open(
            "r",
            encoding="utf-8",
            errors="ignore",
        ),
        start=1,
    ):

        if not is_candidate_rule(
            line
        ):
            continue

        candidate_rules += 1

        try:
            parsed = parse_rule(
                line.strip()
            )

            parsed_rules += 1

            semantic_rule = (
                build_semantic_ir(
                    parsed
                )
            )

        except Exception as error:
            semantic_failures += 1

            print(
                f"Failure line "
                f"{line_number}: "
                f"{error}"
            )

            continue

        seen = set()

        for predicate in (
            semantic_rule.predicates
        ):

            if (
                predicate.kind
                != "APPLICATION"
            ):
                continue

            operator = str(
                predicate.operator
            ).strip().lower()

            # Explicitly modeled application semantics.
            if operator in (
                APPLICATION_OPTIONS
            ):
                continue

            # Explicit service-rule header representation.
            if (
                operator
                == "service_header"
            ):
                continue

            generic_counter[
                operator
            ] += 1

            seen.add(
                operator
            )

            if (
                len(
                    examples[
                        operator
                    ]
                )
                < 5
            ):
                examples[
                    operator
                ].append(
                    {
                        "sid": (
                            semantic_rule
                            .rule_id
                        ),
                        "value": (
                            predicate.value
                        ),
                        "line": (
                            line_number
                        ),
                    }
                )

        if seen:
            rules_with_generic += 1

        for operator in seen:
            generic_rule_counter[
                operator
            ] += 1

    print()
    print(
        "=== Generic Application "
        "Option Analysis ==="
    )
    print()

    print(
        f"Candidate rules       : "
        f"{candidate_rules}"
    )

    print(
        f"Parsed rules          : "
        f"{parsed_rules}"
    )

    print(
        f"Semantic failures     : "
        f"{semantic_failures}"
    )

    print(
        f"Rules with generic ops: "
        f"{rules_with_generic}"
    )

    print()

    print(
        "Generic application operators"
    )
    print(
        "-" * 70
    )

    if not generic_counter:
        print(
            "None"
        )

    for operator, count in (
        generic_counter.most_common()
    ):

        rules = (
            generic_rule_counter[
                operator
            ]
        )

        percentage = (
            rules
            / parsed_rules
            * 100
            if parsed_rules
            else 0
        )

        print(
            f"{operator:<30} "
            f"{count:>6} occurrences | "
            f"{rules:>5} rules "
            f"({percentage:6.2f}%)"
        )

    print()

    print(
        "Examples"
    )
    print(
        "=" * 70
    )

    for operator, values in (
        examples.items()
    ):

        print()
        print(
            operator.upper()
        )

        print(
            "-" * 60
        )

        for example in values:

            print(
                f"SID {example['sid']} "
                f"(line {example['line']}): "
                f"{example['value']}"
            )


if __name__ == "__main__":
    main()
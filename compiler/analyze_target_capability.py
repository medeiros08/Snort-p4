from collections import Counter
from pathlib import Path

from parser import parse_rule
from build_semantic_ir import build_semantic_ir
from target_capability import assess_rule


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

    treatment_counter = Counter()
    reason_counter = Counter()

    rules_with_treatment = Counter()

    field_treatment_counter = Counter()

    rules_fully_assessed = 0
    rules_still_unassessed = 0

    examples = {}

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

                assessed_rule, reasons = (
                    assess_rule(
                        semantic_rule
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

            seen_treatments = set()

            still_unassessed = False

            for predicate in (
                assessed_rule.predicates
            ):

                treatment = (
                    predicate
                    .backend_treatment
                )

                treatment_counter[
                    treatment
                ] += 1

                seen_treatments.add(
                    treatment
                )

                if (
                    treatment
                    == "UNASSESSED"
                ):
                    still_unassessed = True

                if (
                    predicate.kind
                    == "HEADER"
                ):
                    field_treatment_counter[
                        (
                            predicate.field,
                            treatment,
                        )
                    ] += 1

            for treatment in (
                seen_treatments
            ):
                rules_with_treatment[
                    treatment
                ] += 1

            if still_unassessed:
                rules_still_unassessed += 1

            else:
                rules_fully_assessed += 1

            for item in reasons:

                reason = item[
                    "reason"
                ]

                reason_counter[
                    reason
                ] += 1

                if reason not in examples:
                    examples[
                        reason
                    ] = []

                if (
                    len(
                        examples[
                            reason
                        ]
                    )
                    < 5
                ):
                    examples[
                        reason
                    ].append(
                        (
                            assessed_rule.rule_id,
                            item["field"],
                            item["value"],
                        )
                    )

    print()
    print(
        "=== Target Capability Analysis ==="
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

    print()

    print(
        f"Fully assessed rules  : "
        f"{rules_fully_assessed}"
    )

    print(
        f"Still UNASSESSED      : "
        f"{rules_still_unassessed}"
    )

    print()

    print(
        "Treatments - predicate occurrences"
    )
    print(
        "-" * 60
    )

    for treatment, count in (
        treatment_counter.most_common()
    ):
        print(
            f"{treatment:<20} "
            f"{count:>7}"
        )

    print()

    print(
        "Rules containing each treatment"
    )
    print(
        "-" * 60
    )

    for treatment, count in (
        rules_with_treatment
        .most_common()
    ):

        percentage = (
            count / parsed_rules * 100
            if parsed_rules
            else 0
        )

        print(
            f"{treatment:<20} "
            f"{count:>5} "
            f"({percentage:6.2f}%)"
        )

    print()

    print(
        "Header field / treatment"
    )
    print(
        "-" * 70
    )

    for (
        field,
        treatment,
    ), count in sorted(
        field_treatment_counter.items()
    ):
        print(
            f"{field:<20} "
            f"{treatment:<15} "
            f"{count:>6}"
        )

    print()

    print(
        "Decision reasons"
    )
    print(
        "-" * 70
    )

    for reason, count in (
        reason_counter.most_common()
    ):
        print(
            f"{reason:<45} "
            f"{count:>6}"
        )

    print()

    print(
        "Examples"
    )
    print(
        "=" * 70
    )

    for reason, values in (
        examples.items()
    ):

        print()
        print(
            reason
        )

        print(
            "-" * 50
        )

        for (
            sid,
            field,
            value,
        ) in values:

            print(
                f"SID {sid}: "
                f"{field}={value}"
            )


if __name__ == "__main__":
    main()
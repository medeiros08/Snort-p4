from collections import Counter
from pathlib import Path

from parser import parse_rule
from variable_resolver import (
    load_variables,
    resolve_rule_variables,
)
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

    if not ruleset_path.exists():
        print(
            "ERROR: Ruleset not found:",
            ruleset_path.resolve(),
        )
        return

    variables = load_variables()

    candidate_rules = 0
    parsed_rules = 0
    semantic_failures = 0

    rules_with_resolution = 0
    total_resolutions = 0

    resolved_field_counter = Counter()

    treatment_counter = Counter()
    rules_with_treatment = Counter()

    field_treatment_counter = Counter()
    reason_counter = Counter()

    rules_fully_assessed = 0
    rules_still_unassessed = 0

    unresolved_examples = []
    resolution_examples = []

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
                # ------------------------------------------------
                # 1. Resolve Snort variables on parsed rule
                # ------------------------------------------------

                resolved_rule, resolution_log = (
                    resolve_rule_variables(
                        parsed,
                        variables,
                    )
                )

                if resolution_log:
                    rules_with_resolution += 1

                total_resolutions += len(
                    resolution_log
                )

                for item in resolution_log:

                    resolved_field_counter[
                        item["field"]
                    ] += 1

                    if (
                        len(
                            resolution_examples
                        )
                        < 20
                    ):
                        resolution_examples.append(
                            {
                                "sid": parsed.get(
                                    "sid"
                                ),
                                "field": item[
                                    "field"
                                ],
                                "original": item[
                                    "original"
                                ],
                                "resolved": item[
                                    "resolved"
                                ],
                            }
                        )

                # ------------------------------------------------
                # 2. Build semantic IR after variable resolution
                # ------------------------------------------------

                semantic_rule = build_semantic_ir(
                    resolved_rule
                )

                # ------------------------------------------------
                # 3. Target capability analysis
                # ------------------------------------------------

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
                        len(
                            unresolved_examples
                        )
                        < 20
                    ):
                        unresolved_examples.append(
                            {
                                "sid": (
                                    assessed_rule
                                    .rule_id
                                ),
                                "field": (
                                    predicate
                                    .field
                                ),
                                "value": (
                                    predicate
                                    .value
                                ),
                            }
                        )

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

                reason_counter[
                    item["reason"]
                ] += 1

    print()
    print(
        "=== Target Capability Analysis "
        "(After Variable Resolution) ==="
    )
    print()

    print(
        f"Candidate rules          : "
        f"{candidate_rules}"
    )

    print(
        f"Parsed rules             : "
        f"{parsed_rules}"
    )

    print(
        f"Semantic failures        : "
        f"{semantic_failures}"
    )

    print()

    print(
        "Variable resolution"
    )
    print(
        "-" * 60
    )

    print(
        f"Rules with resolution    : "
        f"{rules_with_resolution}"
    )

    print(
        f"Total resolved fields    : "
        f"{total_resolutions}"
    )

    print()

    for field, count in (
        resolved_field_counter
        .most_common()
    ):
        print(
            f"{field:<20} "
            f"{count:>6}"
        )

    print()

    print(
        "Assessment"
    )
    print(
        "-" * 60
    )

    print(
        f"Fully assessed rules     : "
        f"{rules_fully_assessed}"
    )

    print(
        f"Still UNASSESSED         : "
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
            f"{reason:<50} "
            f"{count:>6}"
        )

    print()

    print(
        "Resolution examples"
    )
    print(
        "=" * 70
    )

    if not resolution_examples:
        print(
            "None"
        )

    for example in (
        resolution_examples
    ):

        print(
            f"SID {example['sid']}: "
            f"{example['field']} "
            f"{example['original']} "
            f"-> "
            f"{example['resolved']}"
        )

    print()

    print(
        "Remaining UNASSESSED examples"
    )
    print(
        "=" * 70
    )

    if not unresolved_examples:
        print(
            "None"
        )

    for example in (
        unresolved_examples
    ):

        print(
            f"SID {example['sid']}: "
            f"{example['field']}="
            f"{example['value']}"
        )


if __name__ == "__main__":
    main()
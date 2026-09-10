from collections import Counter
from pathlib import Path

from parser import parse_rule

from variable_resolver import (
    load_variables,
    resolve_rule_variables,
)

from build_semantic_ir import (
    build_semantic_ir,
)

from target_capability import (
    assess_rule,
)

from semantic_classifier import (
    classify_assessed_rule,
)


RULESET_FILE = (
    "../rules/snort3-community.rules"
)


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

    variables = load_variables()

    candidate_rules = 0
    parsed_rules = 0
    failures = 0

    classification_counter = (
        Counter()
    )

    candidate_counter = Counter()

    final_detection_counter = (
        Counter()
    )

    selective_field_counter = (
        Counter()
    )

    reason_counter = Counter()

    predicate_count_distribution = (
        Counter()
    )

    examples = {
        "EXACT": [],
        "NECESSARY": [],
        "UNSUPPORTED": [],
    }

    unsupported_details = []

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
                resolved_rule, _ = (
                    resolve_rule_variables(
                        parsed,
                        variables,
                    )
                )

                semantic_rule = (
                    build_semantic_ir(
                        resolved_rule
                    )
                )

                assessed_rule, _ = (
                    assess_rule(
                        semantic_rule
                    )
                )

                classification = (
                    classify_assessed_rule(
                        assessed_rule
                    )
                )

            except Exception as error:
                failures += 1

                print(
                    f"Failure line "
                    f"{line_number}: "
                    f"{error}"
                )

                continue

            classification_counter[
                classification.classification
            ] += 1

            candidate_counter[
                classification.prefilter_candidate
            ] += 1

            final_detection_counter[
                classification.final_detection
            ] += 1

            predicate_count_distribution[
                len(
                    classification
                    .selective_predicates
                )
            ] += 1

            for predicate in (
                classification
                .selective_predicates
            ):

                selective_field_counter[
                    predicate["field"]
                ] += 1

            for reason in (
                classification.reasons
            ):

                reason_counter[
                    reason
                ] += 1

            cls = (
                classification
                .classification
            )

            if (
                len(
                    examples[cls]
                )
                < 10
            ):
                examples[
                    cls
                ].append(
                    {
                        "sid": (
                            classification
                            .rule_id
                        ),

                        "selective": (
                            classification
                            .selective_predicates
                        ),

                        "preserved": (
                            classification
                            .preserved_predicates
                        ),

                        "expanded": (
                            classification
                            .expanded_predicates
                        ),

                        "delegated": (
                            classification
                            .delegated_predicates
                        ),

                        "fallback": (
                            classification
                            .fallback_predicates
                        ),
                    }
                )

            if (
                cls
                == "UNSUPPORTED"
            ):

                unsupported_details.append(
                    classification
                )

    print()
    print(
        "=== Semantic Rule "
        "Classification ==="
    )
    print()

    print(
        f"Candidate rules      : "
        f"{candidate_rules}"
    )

    print(
        f"Parsed rules         : "
        f"{parsed_rules}"
    )

    print(
        f"Pipeline failures    : "
        f"{failures}"
    )

    print()

    print(
        "Semantic classification"
    )
    print(
        "-" * 60
    )

    for cls in [
        "EXACT",
        "NECESSARY",
        "UNSUPPORTED",
    ]:

        count = (
            classification_counter[
                cls
            ]
        )

        percentage = (
            count
            / parsed_rules
            * 100
            if parsed_rules
            else 0
        )

        print(
            f"{cls:<15} "
            f"{count:>5} "
            f"({percentage:6.2f}%)"
        )

    print()

    candidate_count = (
        candidate_counter[
            True
        ]
    )

    non_candidate_count = (
        candidate_counter[
            False
        ]
    )

    print(
        "Prefilter eligibility"
    )
    print(
        "-" * 60
    )

    print(
        f"Candidate          : "
        f"{candidate_count:>5} "
        f"("
        f"{candidate_count / parsed_rules * 100:6.2f}%"
        f")"
    )

    print(
        f"Not candidate      : "
        f"{non_candidate_count:>5} "
        f"("
        f"{non_candidate_count / parsed_rules * 100:6.2f}%"
        f")"
    )

    print()

    print(
        "Final detection"
    )
    print(
        "-" * 60
    )

    for detector, count in (
        final_detection_counter
        .most_common()
    ):

        print(
            f"{detector:<20} "
            f"{count:>5}"
        )

    print()

    print(
        "Selective predicate fields"
    )
    print(
        "-" * 60
    )

    for field, count in (
        selective_field_counter
        .most_common()
    ):

        print(
            f"{field:<20} "
            f"{count:>6}"
        )

    print()

    print(
        "Selective predicate count "
        "per rule"
    )
    print(
        "-" * 60
    )

    for count in sorted(
        predicate_count_distribution
    ):

        rules = (
            predicate_count_distribution[
                count
            ]
        )

        percentage = (
            rules
            / parsed_rules
            * 100
        )

        print(
            f"{count:>2} predicates : "
            f"{rules:>5} "
            f"({percentage:6.2f}%)"
        )

    print()

    print(
        "Classification reasons"
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
        "Examples"
    )
    print(
        "=" * 70
    )

    for cls in [
        "EXACT",
        "NECESSARY",
        "UNSUPPORTED",
    ]:

        print()
        print(
            cls
        )
        print(
            "-" * 60
        )

        if not examples[cls]:
            print(
                "None"
            )

        for example in (
            examples[cls]
        ):

            print(
                f"SID "
                f"{example['sid']}: "
                f"selective="
                f"{example['selective']} "
                f"| preserved="
                f"{example['preserved']} "
                f"expanded="
                f"{example['expanded']} "
                f"delegated="
                f"{example['delegated']} "
                f"fallback="
                f"{example['fallback']}"
            )

    print()

    print(
        "UNSUPPORTED rules"
    )
    print(
        "=" * 70
    )

    if not unsupported_details:
        print(
            "None"
        )

    for item in (
        unsupported_details
    ):

        print(
            f"SID {item.rule_id}: "
            f"preserved="
            f"{item.preserved_predicates}, "
            f"expanded="
            f"{item.expanded_predicates}, "
            f"delegated="
            f"{item.delegated_predicates}, "
            f"fallback="
            f"{item.fallback_predicates}"
        )


if __name__ == "__main__":
    main()
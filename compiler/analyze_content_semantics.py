from collections import Counter
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

    total_content = 0

    negated_content = 0
    content_with_modifiers = 0
    content_without_modifiers = 0

    modifier_counter = Counter()

    rule_counter = Counter()

    modifier_combination_counter = Counter()

    unrecognized_modifiers = Counter()

    examples = {
        "negated": [],
        "absolute": [],
        "relative": [],
        "fast_pattern": [],
    }

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

            rule_has_content = False
            rule_has_negated = False
            rule_has_modifier = False

            rule_has_nocase = False
            rule_has_fast_pattern = False

            rule_has_absolute = False
            rule_has_relative = False

            rule_has_fp_window = False

            for predicate in (
                semantic_rule.predicates
            ):

                if (
                    predicate.operator
                    != "content"
                ):
                    continue

                rule_has_content = True
                total_content += 1

                value = predicate.value

                if not isinstance(
                    value,
                    dict,
                ):
                    continue

                negated = value.get(
                    "negated",
                    False,
                )

                if negated:
                    negated_content += 1
                    rule_has_negated = True

                    if (
                        len(
                            examples["negated"]
                        )
                        < 10
                    ):
                        examples[
                            "negated"
                        ].append(
                            (
                                semantic_rule.rule_id,
                                value.get(
                                    "pattern"
                                ),
                            )
                        )

                modifiers = (
                    predicate.modifiers
                    or []
                )

                if modifiers:
                    content_with_modifiers += 1
                    rule_has_modifier = True

                else:
                    content_without_modifiers += 1

                modifier_names = []

                for modifier in modifiers:

                    if not isinstance(
                        modifier,
                        dict,
                    ):
                        continue

                    name = modifier.get(
                        "name"
                    )

                    recognized = modifier.get(
                        "recognized",
                        False,
                    )

                    if not name:
                        continue

                    modifier_names.append(
                        name
                    )

                    modifier_counter[
                        name
                    ] += 1

                    if not recognized:
                        unrecognized_modifiers[
                            name
                        ] += 1

                    if name == "nocase":
                        rule_has_nocase = True

                    if name == "fast_pattern":
                        rule_has_fast_pattern = True

                        if (
                            len(
                                examples[
                                    "fast_pattern"
                                ]
                            )
                            < 10
                        ):
                            examples[
                                "fast_pattern"
                            ].append(
                                (
                                    semantic_rule.rule_id,
                                    value.get(
                                        "pattern"
                                    ),
                                )
                            )

                    if name in {
                        "depth",
                        "offset",
                    }:
                        rule_has_absolute = True

                        if (
                            len(
                                examples[
                                    "absolute"
                                ]
                            )
                            < 10
                        ):
                            examples[
                                "absolute"
                            ].append(
                                (
                                    semantic_rule.rule_id,
                                    name,
                                    modifier.get(
                                        "value"
                                    ),
                                )
                            )

                    if name in {
                        "distance",
                        "within",
                    }:
                        rule_has_relative = True

                        if (
                            len(
                                examples[
                                    "relative"
                                ]
                            )
                            < 10
                        ):
                            examples[
                                "relative"
                            ].append(
                                (
                                    semantic_rule.rule_id,
                                    name,
                                    modifier.get(
                                        "value"
                                    ),
                                )
                            )

                    if name in {
                        "fast_pattern_offset",
                        "fast_pattern_length",
                    }:
                        rule_has_fp_window = True

                if modifier_names:
                    modifier_combination_counter[
                        tuple(
                            modifier_names
                        )
                    ] += 1

            if rule_has_content:
                rule_counter[
                    "content"
                ] += 1

            if rule_has_negated:
                rule_counter[
                    "negated"
                ] += 1

            if rule_has_modifier:
                rule_counter[
                    "modified"
                ] += 1

            if rule_has_nocase:
                rule_counter[
                    "nocase"
                ] += 1

            if rule_has_fast_pattern:
                rule_counter[
                    "fast_pattern"
                ] += 1

            if rule_has_absolute:
                rule_counter[
                    "absolute_position"
                ] += 1

            if rule_has_relative:
                rule_counter[
                    "relative_position"
                ] += 1

            if rule_has_fp_window:
                rule_counter[
                    "fast_pattern_window"
                ] += 1

    print()
    print(
        "=== Content Semantic Analysis ==="
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
        f"Total content predicates : "
        f"{total_content}"
    )

    print(
        f"Negated content          : "
        f"{negated_content}"
    )

    print(
        f"Content with modifiers   : "
        f"{content_with_modifiers}"
    )

    print(
        f"Content without modifiers: "
        f"{content_without_modifiers}"
    )

    print()

    print(
        "Modifier frequency"
    )
    print(
        "-" * 50
    )

    for name, count in (
        modifier_counter.most_common()
    ):
        print(
            f"{name:<25} "
            f"{count:>6}"
        )

    print()

    print(
        "Rules containing content semantics"
    )
    print(
        "-" * 50
    )

    for key in [
        "content",
        "modified",
        "nocase",
        "fast_pattern",
        "absolute_position",
        "relative_position",
        "negated",
        "fast_pattern_window",
    ]:

        count = rule_counter[
            key
        ]

        percentage = (
            count / parsed_rules * 100
            if parsed_rules
            else 0
        )

        print(
            f"{key:<25} "
            f"{count:>5} "
            f"({percentage:6.2f}%)"
        )

    print()

    print(
        "Most common modifier combinations"
    )
    print(
        "-" * 60
    )

    for combination, count in (
        modifier_combination_counter
        .most_common(20)
    ):
        print(
            f"{str(combination):<45} "
            f"{count:>6}"
        )

    print()

    print(
        "Unrecognized modifiers"
    )
    print(
        "-" * 50
    )

    if unrecognized_modifiers:

        for name, count in (
            unrecognized_modifiers
            .most_common()
        ):
            print(
                f"{name:<25} "
                f"{count:>6}"
            )

    else:
        print(
            "None"
        )

    print()

    print(
        "Examples"
    )
    print(
        "=" * 70
    )

    for category, values in (
        examples.items()
    ):

        print()
        print(
            category.upper()
        )
        print(
            "-" * 50
        )

        for value in values:
            print(
                value
            )


if __name__ == "__main__":
    main()
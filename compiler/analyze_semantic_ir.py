from collections import Counter
from pathlib import Path

from parser import parse_rule
from build_semantic_ir import build_semantic_ir


RULESET_FILE = "../rules/snort3-community.rules"
OUTPUT_FILE = "../output/semantic_ir_analysis.txt"


def is_candidate_rule(line):
    line = line.strip()

    if not line:
        return False

    if line.startswith("#"):
        return False

    return True


def main():
    ruleset_path = Path(RULESET_FILE)
    output_path = Path(OUTPUT_FILE)

    if not ruleset_path.exists():
        print(
            f"ERROR: Ruleset not found: "
            f"{ruleset_path.resolve()}"
        )
        return

    total_candidate_rules = 0
    parsed_rules = 0
    parse_failures = 0
    semantic_failures = 0

    rule_type_counter = Counter()
    predicate_kind_counter = Counter()
    treatment_counter = Counter()
    operator_counter = Counter()

    rules_with_kind = Counter()
    rules_with_treatment = Counter()

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
            if not is_candidate_rule(line):
                continue

            total_candidate_rules += 1

            try:
                parsed_rule = parse_rule(line)

                if parsed_rule is None:
                    parse_failures += 1
                    continue

                parsed_rules += 1

            except Exception:
                parse_failures += 1
                continue

            try:
                semantic_rule = build_semantic_ir(
                    parsed_rule
                )

            except Exception as error:
                semantic_failures += 1

                print(
                    f"Semantic IR failure at "
                    f"line {line_number}: "
                    f"{error}"
                )

                continue

            rule_type_counter[
                semantic_rule.rule_type
            ] += 1

            seen_kinds = set()
            seen_treatments = set()

            for predicate in semantic_rule.predicates:
                predicate_kind_counter[
                    predicate.kind
                ] += 1

                treatment_counter[
                    predicate.backend_treatment
                ] += 1

                operator_counter[
                    predicate.operator
                ] += 1

                seen_kinds.add(
                    predicate.kind
                )

                seen_treatments.add(
                    predicate.backend_treatment
                )

            for kind in seen_kinds:
                rules_with_kind[kind] += 1

            for treatment in seen_treatments:
                rules_with_treatment[
                    treatment
                ] += 1

    lines = []

    lines.append(
        "=== Semantic IR Analysis ==="
    )

    lines.append("")

    lines.append(
        f"Candidate rules     : "
        f"{total_candidate_rules}"
    )

    lines.append(
        f"Parsed rules        : "
        f"{parsed_rules}"
    )

    lines.append(
        f"Parse failures      : "
        f"{parse_failures}"
    )

    lines.append(
        f"Semantic failures   : "
        f"{semantic_failures}"
    )

    lines.append("")

    lines.append(
        "Rule types"
    )

    lines.append(
        "-" * 50
    )

    for rule_type, count in (
        rule_type_counter.most_common()
    ):
        percentage = (
            count / parsed_rules * 100
            if parsed_rules
            else 0
        )

        lines.append(
            f"{rule_type:<20} "
            f"{count:>5} "
            f"({percentage:6.2f}%)"
        )

    lines.append("")

    lines.append(
        "Predicate kinds "
        "(total occurrences)"
    )

    lines.append(
        "-" * 50
    )

    for kind, count in (
        predicate_kind_counter.most_common()
    ):
        lines.append(
            f"{kind:<20} "
            f"{count:>6}"
        )

    lines.append("")

    lines.append(
        "Rules containing each "
        "predicate kind"
    )

    lines.append(
        "-" * 50
    )

    for kind, count in (
        rules_with_kind.most_common()
    ):
        percentage = (
            count / parsed_rules * 100
            if parsed_rules
            else 0
        )

        lines.append(
            f"{kind:<20} "
            f"{count:>5} "
            f"({percentage:6.2f}%)"
        )

    lines.append("")

    lines.append(
        "Backend treatments "
        "(total occurrences)"
    )

    lines.append(
        "-" * 50
    )

    for treatment, count in (
        treatment_counter.most_common()
    ):
        lines.append(
            f"{treatment:<20} "
            f"{count:>6}"
        )

    lines.append("")

    lines.append(
        "Rules containing each "
        "backend treatment"
    )

    lines.append(
        "-" * 50
    )

    for treatment, count in (
        rules_with_treatment.most_common()
    ):
        percentage = (
            count / parsed_rules * 100
            if parsed_rules
            else 0
        )

        lines.append(
            f"{treatment:<20} "
            f"{count:>5} "
            f"({percentage:6.2f}%)"
        )

    lines.append("")

    lines.append(
        "Most frequent semantic operators"
    )

    lines.append(
        "-" * 50
    )

    for operator, count in (
        operator_counter.most_common(40)
    ):
        lines.append(
            f"{operator:<30} "
            f"{count:>6}"
        )

    report = "\n".join(
        lines
    )

    print()
    print(report)

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with open(
        output_path,
        "w",
        encoding="utf-8",
    ) as file:
        file.write(report)

    print()
    print(
        f"Output: "
        f"{output_path.resolve()}"
    )


if __name__ == "__main__":
    main()
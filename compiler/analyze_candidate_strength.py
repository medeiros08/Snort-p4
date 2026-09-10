from collections import Counter
from pathlib import Path

from parser import parse_rule
from classifier import classify_rule
from variable_resolver import (
    load_variables,
    resolve_rule_variables
)


RULESET = "../rules/snort3-community.rules"


def join_multiline_rules(lines):
    rules = []
    current = []

    for raw_line in lines:
        line = raw_line.strip()

        if not line or line.startswith("#"):
            continue

        current.append(line)

        if line.endswith(")"):
            rules.append(" ".join(current))
            current = []

    if current:
        rules.append(" ".join(current))

    return rules


def main():
    path = Path(RULESET)

    if not path.exists():
        print(
            f"ERROR: Ruleset not found: "
            f"{path.resolve()}"
        )
        return

    variables = load_variables()

    with open(
        path,
        "r",
        encoding="utf-8",
        errors="ignore"
    ) as file:
        lines = file.readlines()

    candidate_rules = join_multiline_rules(lines)

    parsed = 0
    prefilter_rules = 0

    preserved_count_distribution = Counter()
    delegated_count_distribution = Counter()

    preserved_field_distribution = Counter()

    examples = []

    for rule_text in candidate_rules:
        try:
            rule = parse_rule(rule_text)
            parsed += 1

            resolved_rule, _ = resolve_rule_variables(
                rule,
                variables
            )

            result = classify_rule(
                resolved_rule
            )

            if not result["prefilter_candidate"]:
                continue

            prefilter_rules += 1

            preserved = result["preserved"]
            delegated = result["delegated"]

            preserved_count = len(preserved)
            delegated_count = len(delegated)

            preserved_count_distribution[
                preserved_count
            ] += 1

            delegated_count_distribution[
                delegated_count
            ] += 1

            field_names = {
                predicate["name"]
                for predicate in preserved
            }

            for name in field_names:
                preserved_field_distribution[
                    name
                ] += 1

            if len(examples) < 10:
                examples.append({
                    "sid": result["rule_id"],
                    "preserved": preserved_count,
                    "delegated": delegated_count,
                    "fields": sorted(field_names)
                })

        except Exception:
            continue

    print(
        "\n=== Candidate Predicate Strength Analysis ==="
    )

    print(f"Parsed rules          : {parsed}")
    print(
        f"Pre-filter candidates : "
        f"{prefilter_rules}"
    )

    print(
        "\nNumber of preserved predicates "
        "per candidate rule"
    )
    print("-" * 55)

    for count in sorted(
        preserved_count_distribution
    ):
        rules = preserved_count_distribution[count]

        percentage = (
            rules / prefilter_rules * 100
            if prefilter_rules
            else 0
        )

        print(
            f"{count:>2} preserved predicates : "
            f"{rules:>5} rules "
            f"({percentage:6.2f}%)"
        )

    print(
        "\nNumber of delegated predicates "
        "per candidate rule"
    )
    print("-" * 55)

    for count in sorted(
        delegated_count_distribution
    ):
        rules = delegated_count_distribution[count]

        percentage = (
            rules / prefilter_rules * 100
            if prefilter_rules
            else 0
        )

        print(
            f"{count:>2} delegated predicates : "
            f"{rules:>5} rules "
            f"({percentage:6.2f}%)"
        )

    print(
        "\nPreserved fields among "
        "pre-filter candidates"
    )
    print("-" * 55)

    for name, count in (
        preserved_field_distribution.most_common()
    ):
        percentage = (
            count / prefilter_rules * 100
            if prefilter_rules
            else 0
        )

        print(
            f"{name:<20} "
            f"{count:>5} "
            f"({percentage:6.2f}%)"
        )

    print("\nExamples")
    print("-" * 55)

    for item in examples:
        print(
            f"SID {item['sid']} | "
            f"preserved={item['preserved']} | "
            f"delegated={item['delegated']} | "
            f"fields={item['fields']}"
        )


if __name__ == "__main__":
    main()
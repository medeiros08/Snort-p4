from collections import Counter
from pathlib import Path

from parser import parse_rule


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

    with open(path, "r", encoding="utf-8", errors="ignore") as file:
        lines = file.readlines()

    candidate_rules = join_multiline_rules(lines)

    feature_counter = Counter()

    parsed = 0
    failed = 0

    for rule_text in candidate_rules:
        try:
            rule = parse_rule(rule_text)
            parsed += 1

            # Count each option at most once per rule.
            option_names = {
                option["name"]
                for option in rule["options"]
            }

            for option_name in option_names:
                feature_counter[option_name] += 1

        except Exception:
            failed += 1

    print("\n=== Snort Rule Feature Analysis ===")
    print(f"Candidate rules : {len(candidate_rules)}")
    print(f"Parsed rules    : {parsed}")
    print(f"Parse failures  : {failed}")

    print("\nMost common options by number of rules")
    print("-" * 55)

    for name, count in feature_counter.most_common(25):
        percentage = (count / parsed * 100) if parsed else 0

        print(
            f"{name:<25} "
            f"{count:>5} rules "
            f"({percentage:6.2f}%)"
        )


if __name__ == "__main__":
    main()
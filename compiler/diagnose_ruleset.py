from parser import parse_rule
from collections import Counter
from pathlib import Path
import re


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


def extract_option_names(rule_text):
    match = re.search(r"\((.*)\)$", rule_text)

    if not match:
        return []

    options_text = match.group(1)

    names = []

    for part in options_text.split(";"):
        part = part.strip()

        if not part:
            continue

        if ":" in part:
            name = part.split(":", 1)[0].strip()
        else:
            name = part.split()[0].strip()

        names.append(name)

    return names


def main():
    path = Path(RULESET)

    with open(path, "r", encoding="utf-8", errors="ignore") as file:
        lines = file.readlines()

    rules = join_multiline_rules(lines)

    parsed = 0
    failed = 0

    failure_examples = []
    option_counter = Counter()

    for rule in rules:
        try:
            parsed_rule = parse_rule(rule)
            parsed += 1

            for option in parsed_rule["options"]:
                option_counter[option["name"]] += 1

        except Exception:
            failed += 1

            for name in extract_option_names(rule):
                option_counter[name] += 1

            if len(failure_examples) < 10:
                failure_examples.append(rule)

    total = len(rules)

    print("\n=== Snort 3 Community Ruleset Diagnosis ===")
    print(f"Total candidate rules : {total}")
    print(f"Parsed successfully   : {parsed}")
    print(f"Parse failures        : {failed}")

    if total:
        print(f"Parser success rate   : {parsed / total * 100:.2f}%")

    print("\nMost frequent rule options:")
    print("-" * 40)

    for name, count in option_counter.most_common(20):
        print(f"{name:<25} {count}")

    print("\nFirst parse failure examples:")
    print("-" * 40)

    for index, rule in enumerate(failure_examples, start=1):
        print(f"\n[{index}] {rule[:500]}")


if __name__ == "__main__":
    main()
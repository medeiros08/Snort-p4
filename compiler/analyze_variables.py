from collections import Counter
from pathlib import Path
import re

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


def extract_variables(value):
    """
    Extracts Snort-style variables such as:
    $HOME_NET
    $EXTERNAL_NET
    $HTTP_PORTS
    """
    if not value:
        return []

    return re.findall(r"\$[A-Za-z_][A-Za-z0-9_]*", value)


def main():
    path = Path(RULESET)

    if not path.exists():
        print(f"ERROR: Ruleset not found: {path.resolve()}")
        return

    with open(path, "r", encoding="utf-8", errors="ignore") as file:
        lines = file.readlines()

    candidate_rules = join_multiline_rules(lines)

    address_variables = Counter()
    port_variables = Counter()
    all_variables = Counter()

    parsed = 0
    failed = 0
    rules_with_address_variables = 0
    rules_with_port_variables = 0

    for rule_text in candidate_rules:
        try:
            rule = parse_rule(rule_text)
            parsed += 1

            address_values = [
                rule["source"]["address"],
                rule["destination"]["address"]
            ]

            port_values = [
                rule["source"]["port"],
                rule["destination"]["port"]
            ]

            local_address_variables = set()
            local_port_variables = set()

            for value in address_values:
                variables = extract_variables(value)

                for variable in variables:
                    address_variables[variable] += 1
                    all_variables[variable] += 1
                    local_address_variables.add(variable)

            for value in port_values:
                variables = extract_variables(value)

                for variable in variables:
                    port_variables[variable] += 1
                    all_variables[variable] += 1
                    local_port_variables.add(variable)

            if local_address_variables:
                rules_with_address_variables += 1

            if local_port_variables:
                rules_with_port_variables += 1

        except Exception:
            failed += 1

    print("\n=== Snort Variable Analysis ===")

    print(f"Candidate rules             : {len(candidate_rules)}")
    print(f"Parsed rules                : {parsed}")
    print(f"Parse failures              : {failed}")

    print(
        f"Rules with address variables: "
        f"{rules_with_address_variables}"
    )

    print(
        f"Rules with port variables   : "
        f"{rules_with_port_variables}"
    )

    print("\nAddress variables")
    print("-" * 55)

    for variable, count in address_variables.most_common():
        percentage = (
            count / parsed * 100
            if parsed
            else 0
        )

        print(
            f"{variable:<25} "
            f"{count:>5} occurrences "
            f"({percentage:6.2f}% of parsed rules)"
        )

    print("\nPort variables")
    print("-" * 55)

    for variable, count in port_variables.most_common():
        percentage = (
            count / parsed * 100
            if parsed
            else 0
        )

        print(
            f"{variable:<25} "
            f"{count:>5} occurrences "
            f"({percentage:6.2f}% of parsed rules)"
        )

    print("\nAll variables")
    print("-" * 55)

    for variable, count in all_variables.most_common():
        print(
            f"{variable:<25} "
            f"{count}"
        )


if __name__ == "__main__":
    main()
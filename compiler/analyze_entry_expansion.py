import json
from collections import Counter
from pathlib import Path


INPUT_FILE = "../output/p4_entries_expanded.json"


def main():
    path = Path(INPUT_FILE)

    if not path.exists():
        print(f"ERROR: File not found: {path.resolve()}")
        return

    with open(path, "r", encoding="utf-8") as file:
        data = json.load(file)

    entries = data.get("entries", [])

    rule_counter = Counter()

    for entry in entries:
        rule_counter[entry["rule_id"]] += 1

    total_rules = len(rule_counter)
    total_entries = len(entries)

    average = (
        total_entries / total_rules
        if total_rules
        else 0
    )

    distribution = Counter(
        rule_counter.values()
    )

    print("\n=== P4 Entry Expansion Analysis ===")

    print(f"Rules represented     : {total_rules}")
    print(f"Concrete entries      : {total_entries}")
    print(f"Average entries/rule  : {average:.2f}")

    print("\nEntries generated per rule")
    print("-" * 45)

    for entries_per_rule in sorted(distribution):
        count = distribution[entries_per_rule]

        percentage = (
            count / total_rules * 100
            if total_rules
            else 0
        )

        print(
            f"{entries_per_rule} entry/entries : "
            f"{count:>5} rules "
            f"({percentage:6.2f}%)"
        )


if __name__ == "__main__":
    main()
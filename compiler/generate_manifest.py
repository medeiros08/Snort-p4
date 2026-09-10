import json
from pathlib import Path

from parser import parse_rules_file
from classifier import classify_rule


INPUT_RULES = "../rules/test.rules"
OUTPUT_FILE = "../output/manifest.json"


def main():
    rules = parse_rules_file(INPUT_RULES)

    results = []

    for rule in rules:
        result = classify_rule(rule)
        results.append(result)

    output_path = Path(OUTPUT_FILE)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as file:
        json.dump(results, file, indent=2)

    print(f"Manifest generated successfully:")
    print(output_path.resolve())
    print(f"Rules processed: {len(results)}")


if __name__ == "__main__":
    main()
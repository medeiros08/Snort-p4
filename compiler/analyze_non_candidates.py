from collections import Counter
from pathlib import Path

from parser import parse_rule
from classifier import classify_rule


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
        print(f"ERROR: Ruleset not found: {path.resolve()}")
        return

    with open(path, "r", encoding="utf-8", errors="ignore") as file:
        lines = file.readlines()

    candidate_rules = join_multiline_rules(lines)

    total_parsed = 0
    non_candidates = 0
    unsupported = 0

    reason_counter = Counter()
    delegated_field_counter = Counter()

    sample_rules = []

    for rule_text in candidate_rules:
        try:
            rule = parse_rule(rule_text)
            total_parsed += 1

            result = classify_rule(rule)

            if result["prefilter_candidate"]:
                continue

            non_candidates += 1

            if result["classification"] == "UNSUPPORTED":
                unsupported += 1

            local_reasons = set()

            for predicate in result["delegated"]:
                name = predicate["name"]
                reason = predicate.get("reason", "unknown")

                delegated_field_counter[name] += 1
                local_reasons.add(reason)

            for reason in local_reasons:
                reason_counter[reason] += 1

            if len(sample_rules) < 10:
                sample_rules.append({
                    "sid": rule["sid"],
                    "classification": result["classification"],
                    "preserved": result["preserved"],
                    "delegated": result["delegated"]
                })

        except Exception:
            continue

    print("\n=== Non-Candidate Rule Analysis ===")

    print(f"Parsed rules           : {total_parsed}")
    print(f"Non-candidates         : {non_candidates}")
    print(f"Unsupported            : {unsupported}")

    if total_parsed:
        print(
            f"Non-candidate rate     : "
            f"{non_candidates / total_parsed * 100:.2f}%"
        )

    print("\nReasons preventing initial backend support")
    print("-" * 65)

    for reason, count in reason_counter.most_common(20):
        percentage = (
            count / non_candidates * 100
            if non_candidates
            else 0
        )

        print(
            f"{reason:<48} "
            f"{count:>5} "
            f"({percentage:6.2f}%)"
        )

    print("\nMost frequent delegated fields among non-candidates")
    print("-" * 65)

    for name, count in delegated_field_counter.most_common(20):
        print(
            f"{name:<30} "
            f"{count}"
        )

    print("\nExample non-candidate rules")
    print("-" * 65)

    for item in sample_rules:
        print(f"\nSID: {item['sid']}")
        print(f"Class: {item['classification']}")

        print("Preserved:")
        for predicate in item["preserved"]:
            print(
                f"  - {predicate['name']}: "
                f"{predicate['value']}"
            )

        print("Delegated:")
        for predicate in item["delegated"]:
            print(
                f"  - {predicate['name']}: "
                f"{predicate.get('value')} | "
                f"{predicate.get('reason')}"
            )


if __name__ == "__main__":
    main()
    
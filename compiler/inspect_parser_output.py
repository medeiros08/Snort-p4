from pathlib import Path
from pprint import pprint

from parser import parse_rule


RULESET_FILE = "../rules/snort3-community.rules"


def is_candidate_rule(line):
    line = line.strip()

    if not line:
        return False

    if line.startswith("#"):
        return False

    return True


def main():
    ruleset_path = Path(RULESET_FILE)

    if not ruleset_path.exists():
        print(
            f"ERROR: Ruleset not found: "
            f"{ruleset_path.resolve()}"
        )
        return

    shown = 0

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

            try:
                parsed = parse_rule(line)

            except Exception:
                continue

            if parsed is None:
                continue

            print()
            print("=" * 70)
            print(
                f"RULE #{shown + 1} "
                f"(ruleset line {line_number})"
            )
            print("=" * 70)

            print("\nRAW RULE:")
            print(line.strip())

            print("\nPARSED TYPE:")
            print(type(parsed).__name__)

            print("\nKEYS:")
            if isinstance(parsed, dict):
                print(
                    list(parsed.keys())
                )

            print("\nFULL PARSED OBJECT:")
            pprint(
                parsed,
                width=120,
                sort_dicts=False,
            )

            shown += 1

            if shown >= 3:
                break


if __name__ == "__main__":
    main()
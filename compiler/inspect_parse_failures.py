from pathlib import Path

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
    failures = []

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

            stripped = line.strip()

            try:
                parsed = parse_rule(
                    stripped
                )

            except Exception as error:
                failures.append(
                    {
                        "line": line_number,
                        "rule": stripped,
                        "error": repr(error),
                    }
                )

                continue

            if parsed is None:
                failures.append(
                    {
                        "line": line_number,
                        "rule": stripped,
                        "error": "parse_rule returned None",
                    }
                )

                continue

            parsed_rules += 1

    print()
    print(
        "=== Parse Failure Inspection ==="
    )
    print()

    print(
        f"Candidate rules : "
        f"{candidate_rules}"
    )

    print(
        f"Parsed rules    : "
        f"{parsed_rules}"
    )

    print(
        f"Parse failures  : "
        f"{len(failures)}"
    )

    print()

    print(
        "=" * 100
    )

    for index, failure in enumerate(
        failures,
        start=1,
    ):

        print()
        print(
            f"FAILURE #{index}"
        )

        print(
            f"Line: "
            f"{failure['line']}"
        )

        print(
            f"Error: "
            f"{failure['error']}"
        )

        print()

        print(
            failure["rule"]
        )

        print()

        # Show only the beginning of the rule separately.
        # This helps identify service/file rule syntax.
        header = failure[
            "rule"
        ].split(
            "(",
            1,
        )[0].strip()

        print(
            "HEADER:"
        )

        print(
            header
        )

        print()

        print(
            "-" * 100
        )


if __name__ == "__main__":
    main()
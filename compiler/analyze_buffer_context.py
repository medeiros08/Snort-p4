from collections import Counter
from pathlib import Path

from parser import parse_rule
from build_semantic_ir import (
    build_semantic_ir,
)


RULESET_FILE = (
    "../rules/snort3-community.rules"
)


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

    candidate_rules = 0
    parsed_rules = 0
    semantic_failures = 0

    total_content = 0

    content_by_buffer = Counter()
    rules_by_buffer = Counter()

    examples = {}

    missing_buffer = 0

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

            try:
                parsed = parse_rule(
                    line
                )

            except Exception:
                continue

            if parsed is None:
                continue

            parsed_rules += 1

            try:
                semantic_rule = (
                    build_semantic_ir(
                        parsed
                    )
                )

            except Exception as error:
                semantic_failures += 1

                print(
                    f"Semantic failure "
                    f"line {line_number}: "
                    f"{error}"
                )

                continue

            seen_buffers = set()

            for predicate in (
                semantic_rule.predicates
            ):

                if not (
                    predicate.kind == "PAYLOAD"
                    and
                    predicate.operator == "content"
                ):
                    continue

                total_content += 1

                buffer_name = (
                    predicate.buffer
                )

                if buffer_name is None:
                    missing_buffer += 1
                    buffer_name = (
                        "<missing>"
                    )

                content_by_buffer[
                    buffer_name
                ] += 1

                seen_buffers.add(
                    buffer_name
                )

                if (
                    buffer_name
                    not in examples
                ):
                    examples[
                        buffer_name
                    ] = []

                if (
                    len(
                        examples[
                            buffer_name
                        ]
                    )
                    < 5
                ):
                    pattern = (
                        predicate.value.get(
                            "pattern"
                        )
                        if isinstance(
                            predicate.value,
                            dict,
                        )
                        else predicate.value
                    )

                    examples[
                        buffer_name
                    ].append(
                        {
                            "sid": (
                                semantic_rule
                                .rule_id
                            ),

                            "pattern": (
                                pattern
                            ),

                            "line": (
                                line_number
                            ),
                        }
                    )

            for buffer_name in (
                seen_buffers
            ):

                rules_by_buffer[
                    buffer_name
                ] += 1

    print()
    print(
        "=== Stored Buffer Context Analysis ==="
    )
    print()

    print(
        f"Candidate rules          : "
        f"{candidate_rules}"
    )

    print(
        f"Parsed rules             : "
        f"{parsed_rules}"
    )

    print(
        f"Semantic failures        : "
        f"{semantic_failures}"
    )

    print()

    print(
        f"Total content predicates : "
        f"{total_content}"
    )

    print(
        f"Missing buffer context   : "
        f"{missing_buffer}"
    )

    print()

    print(
        "Content occurrences by stored buffer"
    )
    print(
        "-" * 60
    )

    for buffer_name, count in (
        content_by_buffer.most_common()
    ):

        percentage = (
            count
            / total_content
            * 100
            if total_content
            else 0
        )

        print(
            f"{buffer_name:<25} "
            f"{count:>6} "
            f"({percentage:6.2f}%)"
        )

    print()

    print(
        "Rules containing stored buffer context"
    )
    print(
        "-" * 60
    )

    for buffer_name, count in (
        rules_by_buffer.most_common()
    ):

        percentage = (
            count
            / parsed_rules
            * 100
            if parsed_rules
            else 0
        )

        print(
            f"{buffer_name:<25} "
            f"{count:>6} "
            f"({percentage:6.2f}%)"
        )

    print()

    print(
        "Examples"
    )
    print(
        "=" * 70
    )

    for buffer_name, values in (
        examples.items()
    ):

        print()
        print(
            buffer_name.upper()
        )

        print(
            "-" * 60
        )

        for example in values:

            print(
                f"SID {example['sid']} "
                f"(line {example['line']}): "
                f"{example['pattern']}"
            )


if __name__ == "__main__":
    main()
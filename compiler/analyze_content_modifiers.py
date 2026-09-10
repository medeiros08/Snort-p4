from collections import Counter
from pathlib import Path

from parser import parse_rule


RULESET_FILE = "../rules/snort3-community.rules"


KNOWN_CONTENT_MODIFIERS = {
    "fast_pattern",
    "nocase",
    "width",
    "endian",
    "offset",
    "depth",
    "distance",
    "within",
}


def is_candidate_rule(line):
    line = line.strip()

    if not line:
        return False

    if line.startswith("#"):
        return False

    return True


def find_modifier_separator(value):
    """
    The current parser often removes the opening quote from
    content values while leaving the closing quote when
    modifiers follow.

    Examples:

        original:
            content:"abc,def",depth 10;

        parser value:
            abc,def",depth 10

        original:
            content:!"abc",within 20;

        parser value:
            !"abc",within 20

    We therefore search for an unescaped closing quote
    immediately followed by a comma.

    Returns the position of the comma that starts the
    modifier section, or None if no modifier suffix exists.
    """

    escaped = False

    for index, char in enumerate(value):

        if escaped:
            escaped = False
            continue

        if char == "\\":
            escaped = True
            continue

        if char != '"':
            continue

        next_index = index + 1

        if (
            next_index < len(value)
            and value[next_index] == ","
        ):
            return next_index

    return None


def split_modifier_suffix(text):
    """
    Split the modifier suffix.

    At this stage commas belong to the modifier grammar,
    not to the content pattern.
    """

    return [
        part.strip()
        for part in text.split(",")
        if part.strip()
    ]


def modifier_name(text):
    text = text.strip()

    if not text:
        return None

    # Snort syntax normally looks like:
    #
    # depth 10
    # within 100
    # nocase
    # fast_pattern
    #
    return text.split(
        None,
        1,
    )[0].lower()


def analyze_content_value(value):
    """
    Returns:

        pattern
        modifiers

    modifiers is a list of raw modifier strings.
    """

    separator = find_modifier_separator(
        value
    )

    if separator is None:
        return value, []

    # separator points to comma after the closing quote
    pattern = value[
        :separator
    ].strip()

    suffix = value[
        separator + 1:
    ].strip()

    modifiers = split_modifier_suffix(
        suffix
    )

    return pattern, modifiers


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

    total_rules = 0
    parsed_rules = 0

    total_content = 0

    content_with_modifiers = 0
    content_without_modifiers = 0

    rules_with_modified_content = 0

    modifier_counter = Counter()
    modifier_combination_counter = Counter()

    unknown_modifier_counter = Counter()

    examples = []

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

            total_rules += 1

            try:
                parsed = parse_rule(
                    line
                )

            except Exception:
                continue

            if parsed is None:
                continue

            parsed_rules += 1

            found_modified_content = False

            options = parsed.get(
                "options",
                []
            )

            for option in options:

                if not isinstance(
                    option,
                    dict,
                ):
                    continue

                option_name = str(
                    option.get(
                        "name",
                        "",
                    )
                ).lower()

                if option_name != "content":
                    continue

                total_content += 1

                value = str(
                    option.get(
                        "value",
                        "",
                    )
                )

                pattern, modifiers = (
                    analyze_content_value(
                        value
                    )
                )

                if not modifiers:
                    content_without_modifiers += 1
                    continue

                content_with_modifiers += 1
                found_modified_content = True

                modifier_names = []

                for modifier in modifiers:

                    name = modifier_name(
                        modifier
                    )

                    if not name:
                        continue

                    modifier_names.append(
                        name
                    )

                    modifier_counter[
                        name
                    ] += 1

                    if (
                        name
                        not in KNOWN_CONTENT_MODIFIERS
                    ):
                        unknown_modifier_counter[
                            name
                        ] += 1

                modifier_combination_counter[
                    tuple(modifier_names)
                ] += 1

                if len(examples) < 30:
                    examples.append(
                        {
                            "line": line_number,
                            "sid": parsed.get(
                                "sid"
                            ),
                            "original": value,
                            "pattern": pattern,
                            "modifiers": modifiers,
                        }
                    )

            if found_modified_content:
                rules_with_modified_content += 1

    print()
    print(
        "=== Content Modifier Analysis v2 ==="
    )
    print()

    print(
        f"Candidate rules             : "
        f"{total_rules}"
    )

    print(
        f"Parsed rules                : "
        f"{parsed_rules}"
    )

    print(
        f"Total content options       : "
        f"{total_content}"
    )

    print(
        f"Content with modifiers      : "
        f"{content_with_modifiers}"
    )

    print(
        f"Content without modifiers   : "
        f"{content_without_modifiers}"
    )

    print(
        f"Rules with modified content : "
        f"{rules_with_modified_content}"
    )

    print()

    print(
        "Modifier frequency"
    )
    print(
        "-" * 50
    )

    for name, count in (
        modifier_counter.most_common()
    ):
        print(
            f"{name:<25} "
            f"{count:>6}"
        )

    print()

    print(
        "Most common combinations"
    )
    print(
        "-" * 50
    )

    for combination, count in (
        modifier_combination_counter
        .most_common(20)
    ):
        print(
            f"{str(combination):<45} "
            f"{count:>6}"
        )

    print()

    print(
        "Unknown modifier candidates"
    )
    print(
        "-" * 50
    )

    if unknown_modifier_counter:

        for name, count in (
            unknown_modifier_counter
            .most_common()
        ):
            print(
                f"{name:<25} "
                f"{count:>6}"
            )

    else:
        print(
            "None"
        )

    print()

    print(
        "Examples"
    )
    print(
        "-" * 70
    )

    for example in examples:

        print(
            f"SID {example['sid']} "
            f"(line {example['line']})"
        )

        print(
            "ORIGINAL :",
            example["original"],
        )

        print(
            "PATTERN  :",
            example["pattern"],
        )

        print(
            "MODIFIERS:",
            example["modifiers"],
        )

        print()


if __name__ == "__main__":
    main()
import json
from pathlib import Path

from parser import parse_rule
from classifier import classify_rule
from variable_resolver import (
    load_variables,
    resolve_rule_variables
)


RULESET = "../rules/snort3-community.rules"
OUTPUT = "../output/community_manifest.json"


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
    ruleset_path = Path(RULESET)
    output_path = Path(OUTPUT)

    variables = load_variables()

    with open(
        ruleset_path,
        "r",
        encoding="utf-8",
        errors="ignore"
    ) as file:
        lines = file.readlines()

    candidate_rules = join_multiline_rules(lines)

    manifest = []

    failed = []

    for index, rule_text in enumerate(
        candidate_rules,
        start=1
    ):
        try:
            parsed_rule = parse_rule(rule_text)

            resolved_rule, resolution_log = (
                resolve_rule_variables(
                    parsed_rule,
                    variables
                )
            )

            classification = classify_rule(
                resolved_rule
            )

            manifest.append({
                "rule_id":
                    classification["rule_id"],

                "classification":
                    classification["classification"],

                "prefilter_candidate":
                    classification[
                        "prefilter_candidate"
                    ],

                "data_plane_action":
                    classification[
                        "data_plane_action"
                    ],

                "final_detection":
                    classification[
                        "final_detection"
                    ],

                "preserved":
                    classification["preserved"],

                "delegated":
                    classification["delegated"],

                "variable_resolution":
                    resolution_log
            })

        except Exception as error:
            failed.append({
                "index": index,
                "rule": rule_text,
                "error": str(error)
            })

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with open(
        output_path,
        "w",
        encoding="utf-8"
    ) as file:
        json.dump(
            {
                "ruleset": "Snort 3 Community Rules",
                "total_candidate_rules":
                    len(candidate_rules),
                "compiled_rules":
                    len(manifest),
                "failed_rules":
                    len(failed),
                "rules":
                    manifest,
                "failures":
                    failed
            },
            file,
            indent=2
        )

    print(
        "\n=== Community Manifest Generated ==="
    )

    print(
        f"Candidate rules : "
        f"{len(candidate_rules)}"
    )

    print(
        f"Compiled rules  : "
        f"{len(manifest)}"
    )

    print(
        f"Failures        : "
        f"{len(failed)}"
    )

    print(
        f"Output          : "
        f"{output_path.resolve()}"
    )


if __name__ == "__main__":
    main()
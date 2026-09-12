import paths

import json

from collections import Counter
from pathlib import Path

from parser import parse_rule

from variable_resolver import (
    load_variables,
    resolve_rule_variables,
)

from build_semantic_ir import (
    build_semantic_ir,
)

from target_capability import (
    assess_rule,
)

from semantic_classifier import (
    classify_assessed_rule,
)

from semantic_manifest import (
    build_manifest_record,
)

import pipeline_gate


RULESET_FILE = (
    paths.RULES_DIR
    / "snort3-community.rules"
)

# Rotulos gravados no manifesto. Mantidos relativos e literais para que
# o artefato nao dependa de onde o repositorio esta instalado.
RULESET_LABEL = (
    "../rules/snort3-community.rules"
)

VARIABLES_LABEL = (
    "../config/snort_variables.json"
)

OUTPUT_FILE = (
    paths.OUTPUT_DIR
    / "semantic_manifest.json"
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

    output_path = Path(
        OUTPUT_FILE
    )

    if not ruleset_path.exists():

        print(
            "ERROR: Ruleset not found:",
            ruleset_path.resolve(),
        )

        return

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    variables = load_variables()

    candidate_rules = 0
    compiled_rules = 0
    failures = 0

    classification_counter = (
        Counter()
    )

    rule_type_counter = Counter()

    candidate_counter = Counter()

    records = []

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

            raw_rule = line.strip()

            try:
                # --------------------------------------------
                # Parse
                # --------------------------------------------

                parsed_rule = parse_rule(
                    raw_rule
                )

                # Preserve source text in manifest.
                parsed_rule[
                    "raw_rule"
                ] = raw_rule

                # --------------------------------------------
                # Variable resolution
                # --------------------------------------------

                (
                    resolved_rule,
                    resolution_log,
                ) = resolve_rule_variables(
                    parsed_rule,
                    variables,
                )

                resolved_rule[
                    "raw_rule"
                ] = raw_rule

                # --------------------------------------------
                # Semantic IR
                # --------------------------------------------

                semantic_rule = (
                    build_semantic_ir(
                        resolved_rule
                    )
                )

                # --------------------------------------------
                # Target capability analysis
                # --------------------------------------------

                (
                    assessed_rule,
                    capability_reasons,
                ) = assess_rule(
                    semantic_rule
                )

                # --------------------------------------------
                # Semantic classification
                # --------------------------------------------

                classification = (
                    classify_assessed_rule(
                        assessed_rule
                    )
                )

                # --------------------------------------------
                # Manifest record
                # --------------------------------------------

                record = (
                    build_manifest_record(
                        parsed_rule=parsed_rule,

                        resolved_rule=(
                            resolved_rule
                        ),

                        semantic_rule=(
                            semantic_rule
                        ),

                        assessed_rule=(
                            assessed_rule
                        ),

                        classification=(
                            classification
                        ),

                        capability_reasons=(
                            capability_reasons
                        ),

                        resolution_log=(
                            resolution_log
                        ),
                    )
                )

                records.append(
                    record
                )

                compiled_rules += 1

                classification_counter[
                    classification
                    .classification
                ] += 1

                rule_type_counter[
                    semantic_rule.rule_type
                ] += 1

                candidate_counter[
                    classification
                    .prefilter_candidate
                ] += 1

            except Exception as error:

                failures += 1

                print()
                print(
                    f"FAILURE line "
                    f"{line_number}"
                )

                print(
                    raw_rule
                )

                print(
                    repr(error)
                )

    # --------------------------------------------------------
    # Top-level manifest structure
    # --------------------------------------------------------

    manifest = {
        "schema_version": "2.0",

        "compiler": (
            "snort-p4-semantic"
        ),

        "ruleset": RULESET_LABEL,

        "variable_profile": VARIABLES_LABEL,

        "summary": {
            "candidate_rules": (
                candidate_rules
            ),

            "compiled_rules": (
                compiled_rules
            ),

            "failures": (
                failures
            ),

            "rule_types": dict(
                rule_type_counter
            ),

            "classification": {
                "EXACT": (
                    classification_counter[
                        "EXACT"
                    ]
                ),

                "NECESSARY": (
                    classification_counter[
                        "NECESSARY"
                    ]
                ),

                "UNSUPPORTED": (
                    classification_counter[
                        "UNSUPPORTED"
                    ]
                ),
            },

            "prefilter_candidate": (
                candidate_counter[
                    True
                ]
            ),

            "not_prefilter_candidate": (
                candidate_counter[
                    False
                ]
            ),
        },

        "rules": records,
    }

    with open(
        output_path,
        "w",
        encoding="utf-8",
        newline="\n",
    ) as file:

        json.dump(
            manifest,
            file,
            indent=2,
            ensure_ascii=False,
        )

    print()
    print(
        "=== Semantic Manifest Generation ==="
    )
    print()

    print(
        f"Candidate rules      : "
        f"{candidate_rules}"
    )

    print(
        f"Compiled rules       : "
        f"{compiled_rules}"
    )

    print(
        f"Failures             : "
        f"{failures}"
    )

    print()

    print(
        "Rule types"
    )
    print(
        "-" * 50
    )

    for rule_type, count in (
        rule_type_counter.most_common()
    ):

        print(
            f"{rule_type:<20} "
            f"{count:>5}"
        )

    print()

    print(
        "Semantic classification"
    )
    print(
        "-" * 50
    )

    for classification in [
        "EXACT",
        "NECESSARY",
        "UNSUPPORTED",
    ]:

        count = (
            classification_counter[
                classification
            ]
        )

        percentage = (
            count
            / compiled_rules
            * 100
            if compiled_rules
            else 0
        )

        print(
            f"{classification:<15} "
            f"{count:>5} "
            f"({percentage:6.2f}%)"
        )

    print()

    print(
        "Prefilter eligibility"
    )
    print(
        "-" * 50
    )

    print(
        f"Candidate      : "
        f"{candidate_counter[True]}"
    )

    print(
        f"Not candidate  : "
        f"{candidate_counter[False]}"
    )

    print()

    print(
        "Output:"
    )

    print(
        output_path.resolve()
    )


    pipeline_gate.aplicar(
        OUTPUT_FILE
    )

if __name__ == "__main__":
    main()
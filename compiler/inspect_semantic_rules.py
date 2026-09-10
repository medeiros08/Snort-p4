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
    is_selective_predicate,
)


RULESET_FILE = "../rules/snort3-community.rules"


# Regras escolhidas para validação manual.
#
# 498, 2462, 2463, 2464:
#     todas as regras UNSUPPORTED.
#
# 105:
#     exemplo NECESSARY comum.
#
# 110, 121:
#     NECESSARY com FALLBACK.
#
# 223:
#     exemplo com expansão de lista.
#
# 271:
#     exemplo bidirecional.
#
# 163:
#     exemplo com flags não suportadas.
TARGET_SIDS = {
    "105",
    "110",
    "121",
    "163",
    "223",
    "271",
    "498",
    "2462",
    "2463",
    "2464",
}


def is_candidate_rule(line):
    line = line.strip()

    if not line:
        return False

    if line.startswith("#"):
        return False

    return True


def print_separator():
    print()
    print("=" * 100)
    print()


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

    variables = load_variables()

    found = set()

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

            try:
                parsed = parse_rule(
                    line
                )

            except Exception:
                continue

            if parsed is None:
                continue

            sid = str(
                parsed.get(
                    "sid"
                )
            )

            if sid not in TARGET_SIDS:
                continue

            found.add(
                sid
            )

            resolved_rule, resolution_log = (
                resolve_rule_variables(
                    parsed,
                    variables,
                )
            )

            semantic_rule = (
                build_semantic_ir(
                    resolved_rule
                )
            )

            assessed_rule, capability_reasons = (
                assess_rule(
                    semantic_rule
                )
            )

            classification = (
                classify_assessed_rule(
                    assessed_rule
                )
            )

            print_separator()

            print(
                f"SID {sid}"
            )

            print(
                f"Ruleset line: "
                f"{line_number}"
            )

            print()

            print(
                "ORIGINAL RULE"
            )
            print(
                "-" * 100
            )

            print(
                line.strip()
            )

            print()

            print(
                "VARIABLE RESOLUTION"
            )
            print(
                "-" * 100
            )

            if not resolution_log:
                print(
                    "None"
                )

            for item in (
                resolution_log
            ):

                print(
                    f"{item['field']}: "
                    f"{item['original']} "
                    f"-> "
                    f"{item['resolved']}"
                )

            print()

            print(
                "CLASSIFICATION"
            )
            print(
                "-" * 100
            )

            print(
                f"classification     : "
                f"{classification.classification}"
            )

            print(
                f"prefilter_candidate: "
                f"{classification.prefilter_candidate}"
            )

            print(
                f"final_detection    : "
                f"{classification.final_detection}"
            )

            print(
                f"preserved          : "
                f"{classification.preserved_predicates}"
            )

            print(
                f"expanded           : "
                f"{classification.expanded_predicates}"
            )

            print(
                f"delegated          : "
                f"{classification.delegated_predicates}"
            )

            print(
                f"fallback           : "
                f"{classification.fallback_predicates}"
            )

            print()

            print(
                "CLASSIFICATION REASONS"
            )
            print(
                "-" * 100
            )

            for reason in (
                classification.reasons
            ):
                print(
                    reason
                )

            print()

            print(
                "SEMANTIC PREDICATES"
            )
            print(
                "-" * 100
            )

            for index, predicate in enumerate(
                assessed_rule.predicates
            ):

                selective = (
                    is_selective_predicate(
                        predicate
                    )
                )

                print(
                    f"[{index:02}] "
                    f"kind={predicate.kind:<15} "
                    f"field={str(predicate.field):<18} "
                    f"operator={str(predicate.operator):<20} "
                    f"treatment={predicate.backend_treatment:<12} "
                    f"selective={str(selective):<5}"
                )

                print(
                    f"     value="
                    f"{predicate.value}"
                )

                if predicate.modifiers:
                    print(
                        f"     modifiers="
                        f"{predicate.modifiers}"
                    )

                if predicate.buffer:
                    print(
                        f"     buffer="
                        f"{predicate.buffer}"
                    )

            print()

            print(
                "TARGET CAPABILITY DECISIONS"
            )
            print(
                "-" * 100
            )

            if not capability_reasons:
                print(
                    "None"
                )

            for item in (
                capability_reasons
            ):

                print(
                    f"{item['field']}: "
                    f"{item['value']} "
                    f"-> "
                    f"{item['treatment']} "
                    f"("
                    f"{item['reason']}"
                    f")"
                )

            print()

            print(
                "SELECTIVE P4 PREDICATES"
            )
            print(
                "-" * 100
            )

            if not (
                classification
                .selective_predicates
            ):
                print(
                    "None"
                )

            for predicate in (
                classification
                .selective_predicates
            ):

                print(
                    f"{predicate['field']}: "
                    f"{predicate['value']} "
                    f"[{predicate['treatment']}]"
                )

    print_separator()

    missing = (
        TARGET_SIDS
        - found
    )

    print(
        f"Requested SIDs: "
        f"{len(TARGET_SIDS)}"
    )

    print(
        f"Found         : "
        f"{len(found)}"
    )

    if missing:
        print(
            "Missing:",
            sorted(
                missing
            ),
        )

    else:
        print(
            "Missing       : None"
        )


if __name__ == "__main__":
    main()
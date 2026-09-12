import json
from collections import Counter
from pathlib import Path
import sys


MANIFEST_FILE = "../output/semantic_manifest.json"


def fail(errors, rule_id, message):
    errors.append(
        {
            "rule_id": rule_id,
            "message": message,
        }
    )


def main():
    manifest_path = Path(
        MANIFEST_FILE
    )

    if not manifest_path.exists():
        print(
            "ERROR: Manifest not found:",
            manifest_path.resolve(),
        )
        return

    with open(
        manifest_path,
        "r",
        encoding="utf-8",
    ) as file:
        manifest = json.load(file)

    rules = manifest.get(
        "rules",
        [],
    )

    errors = []
    warnings = []

    classification_counter = Counter()
    rule_type_counter = Counter()

    candidate_counter = Counter()

    rules_with_unassessed = 0
    exact_with_delegated = 0
    exact_with_fallback = 0

    service_with_header_predicates = 0

    for rule in rules:

        rule_id = rule.get(
            "rule_id",
            "<unknown>",
        )

        classification = rule.get(
            "classification"
        )

        rule_type = rule.get(
            "rule_type"
        )

        candidate = rule.get(
            "prefilter_candidate"
        )

        final_detection = rule.get(
            "final_detection"
        )

        selective = rule.get(
            "selective_predicates",
            [],
        )

        preserved = rule.get(
            "preserved",
            [],
        )

        expanded = rule.get(
            "expanded",
            [],
        )

        delegated = rule.get(
            "delegated",
            [],
        )

        fallback = rule.get(
            "fallback",
            [],
        )

        unassessed = rule.get(
            "unassessed",
            [],
        )

        classification_counter[
            classification
        ] += 1

        rule_type_counter[
            rule_type
        ] += 1

        candidate_counter[
            candidate
        ] += 1

        # ----------------------------------------------------
        # No UNASSESSED predicates should survive
        # ----------------------------------------------------

        if unassessed:

            rules_with_unassessed += 1

            fail(
                errors,
                rule_id,
                "rule contains UNASSESSED predicates",
            )

        # ----------------------------------------------------
        # NECESSARY invariants
        # ----------------------------------------------------

        if classification == "NECESSARY":

            if not candidate:

                fail(
                    errors,
                    rule_id,
                    "NECESSARY rule is not marked "
                    "as prefilter candidate",
                )

            if not selective:

                fail(
                    errors,
                    rule_id,
                    "NECESSARY rule has no "
                    "selective predicates",
                )

            if final_detection != "SNORT":

                fail(
                    errors,
                    rule_id,
                    "NECESSARY rule must use "
                    "SNORT as final detection",
                )

        # ----------------------------------------------------
        # UNSUPPORTED invariants
        # ----------------------------------------------------

        elif classification == "UNSUPPORTED":

            if candidate:

                fail(
                    errors,
                    rule_id,
                    "UNSUPPORTED rule cannot be "
                    "a prefilter candidate",
                )

            if selective:

                fail(
                    errors,
                    rule_id,
                    "UNSUPPORTED rule unexpectedly "
                    "contains selective predicates",
                )

            if final_detection != "SNORT":

                fail(
                    errors,
                    rule_id,
                    "UNSUPPORTED rule must remain "
                    "with SNORT",
                )

        # ----------------------------------------------------
        # EXACT invariants
        # ----------------------------------------------------

        elif classification == "EXACT":

            if not candidate:

                fail(
                    errors,
                    rule_id,
                    "EXACT rule must be a candidate",
                )

            if delegated:

                exact_with_delegated += 1

                fail(
                    errors,
                    rule_id,
                    "EXACT rule contains DELEGATED "
                    "predicates",
                )

            if fallback:

                exact_with_fallback += 1

                fail(
                    errors,
                    rule_id,
                    "EXACT rule contains FALLBACK "
                    "predicates",
                )

        else:

            fail(
                errors,
                rule_id,
                f"unknown classification: "
                f"{classification}",
            )

        # ----------------------------------------------------
        # SERVICE rules must not contain fabricated
        # traditional header predicates.
        # ----------------------------------------------------

        if rule_type == "SERVICE":

            traditional_fields = {
                "protocol",
                "src_ip",
                "src_port",
                "direction",
                "dst_ip",
                "dst_port",
            }

            found_traditional = []

            for predicate in (
                preserved
                + expanded
                + fallback
                + unassessed
            ):

                if (
                    predicate.get(
                        "kind"
                    )
                    == "HEADER"
                ):

                    field = predicate.get(
                        "field"
                    )

                    if (
                        field
                        in traditional_fields
                    ):

                        found_traditional.append(
                            field
                        )

            if found_traditional:

                service_with_header_predicates += 1

                fail(
                    errors,
                    rule_id,
                    "SERVICE rule contains "
                    "traditional header predicates: "
                    f"{found_traditional}",
                )

            if not rule.get(
                "service_header"
            ):

                warnings.append(
                    {
                        "rule_id": rule_id,
                        "message": (
                            "SERVICE rule has no "
                            "service_header"
                        ),
                    }
                )

    # --------------------------------------------------------
    # Top-level summary consistency
    # --------------------------------------------------------

    summary = manifest.get(
        "summary",
        {},
    )

    if (
        summary.get(
            "compiled_rules"
        )
        != len(rules)
    ):

        fail(
            errors,
            "<manifest>",
            "compiled_rules does not match "
            "number of rule records",
        )

    expected_classification = (
        summary.get(
            "classification",
            {}
        )
    )

    for name in [
        "EXACT",
        "NECESSARY",
        "UNSUPPORTED",
    ]:

        if (
            expected_classification.get(
                name,
                0,
            )
            != classification_counter[
                name
            ]
        ):

            fail(
                errors,
                "<manifest>",
                f"classification summary mismatch "
                f"for {name}",
            )

    # --------------------------------------------------------
    # Print report
    # --------------------------------------------------------

    print()
    print(
        "=== Semantic Manifest Validation ==="
    )
    print()

    print(
        f"Rules                    : "
        f"{len(rules)}"
    )

    print(
        f"Errors                   : "
        f"{len(errors)}"
    )

    print(
        f"Warnings                 : "
        f"{len(warnings)}"
    )

    print()

    print(
        "Rule types"
    )
    print(
        "-" * 50
    )

    for name, count in (
        rule_type_counter.most_common()
    ):

        print(
            f"{name:<20} "
            f"{count:>5}"
        )

    print()

    print(
        "Classification"
    )
    print(
        "-" * 50
    )

    for name in [
        "EXACT",
        "NECESSARY",
        "UNSUPPORTED",
    ]:

        print(
            f"{name:<15} "
            f"{classification_counter[name]:>5}"
        )

    print()

    print(
        "Prefilter eligibility"
    )
    print(
        "-" * 50
    )

    print(
        f"Candidate              : "
        f"{candidate_counter[True]}"
    )

    print(
        f"Not candidate          : "
        f"{candidate_counter[False]}"
    )

    print()

    print(
        "Invariant checks"
    )
    print(
        "-" * 60
    )

    print(
        f"Rules with UNASSESSED  : "
        f"{rules_with_unassessed}"
    )

    print(
        f"EXACT with DELEGATED   : "
        f"{exact_with_delegated}"
    )

    print(
        f"EXACT with FALLBACK    : "
        f"{exact_with_fallback}"
    )

    print(
        f"SERVICE with headers   : "
        f"{service_with_header_predicates}"
    )

    print()

    parse_failures = (
        manifest
        .get("summary", {})
        .get("failures", 0)
    )

    if errors:

        print(
            "ERRORS"
        )
        print(
            "=" * 70
        )

        for error in errors[:50]:

            print(
                f"SID {error['rule_id']}: "
                f"{error['message']}"
            )

    elif not parse_failures:

        print(
            "Manifest status: VALID"
        )

    if warnings:

        print()
        print(
            "WARNINGS"
        )
        print(
            "=" * 70
        )

        for warning in warnings[:50]:

            print(
                f"SID {warning['rule_id']}: "
                f"{warning['message']}"
            )

    # Gate de falha.
    #
    # Este e o unico estagio que verifica os invariantes semanticos do
    # manifesto, e ate aqui imprimia os erros e terminava com codigo 0, de
    # modo que o build prosseguia sobre um manifesto invalido.
    #
    # summary.failures entra no gate porque nunca era lido por ninguem: uma
    # regra que falha no parse some do manifesto sem virar UNSUPPORTED e sem
    # aparecer em qualquer das duas particoes.
    if errors or parse_failures:

        print()
        print(
            "GATE: FALHOU — manifesto semantico invalido:"
        )

        if errors:
            print(
                f"       erros de invariante: "
                f"{len(errors)}"
            )

        if parse_failures:
            print(
                f"       summary.failures: "
                f"{parse_failures} regra(s) "
                f"sumiram no parsing"
            )

        sys.exit(1)


if __name__ == "__main__":
    main()
from collections import Counter
from pathlib import Path

from parser import parse_rule
from classifier import classify_rule
from variable_resolver import (
    load_variables,
    resolve_rule_variables
)


RULESET = "../rules/snort3-community.rules"


def join_multiline_rules(lines):
    """
    Junta regras Snort que ocupam múltiplas linhas.
    Ignora comentários e linhas vazias.
    """
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

    # Carrega as variáveis definidas em config/snort_variables.json
    variables = load_variables()

    classifications = Counter()
    prefilter_candidates = Counter()
    preserved_counter = Counter()
    delegated_counter = Counter()

    resolved_rule_counter = 0
    resolution_counter = Counter()

    parsed = 0
    failed = 0

    for rule_text in candidate_rules:
        try:
            # --------------------------------------------------
            # 1. Parsing da regra
            # --------------------------------------------------

            rule = parse_rule(rule_text)
            parsed += 1

            # --------------------------------------------------
            # 2. Resolução das variáveis Snort
            # --------------------------------------------------

            resolved_rule, resolution_log = resolve_rule_variables(
                rule,
                variables
            )

            if resolution_log:
                resolved_rule_counter += 1

            for resolution in resolution_log:
                resolution_counter[resolution["field"]] += 1

            # --------------------------------------------------
            # 3. Classificação semântica
            # --------------------------------------------------

            result = classify_rule(resolved_rule)

            classifications[result["classification"]] += 1

            # --------------------------------------------------
            # 4. Elegibilidade operacional para pré-filtro
            # --------------------------------------------------

            if result["prefilter_candidate"]:
                prefilter_candidates["yes"] += 1
            else:
                prefilter_candidates["no"] += 1

            # --------------------------------------------------
            # 5. Predicados preservados
            # --------------------------------------------------

            for predicate in result["preserved"]:
                preserved_counter[predicate["name"]] += 1

            # --------------------------------------------------
            # 6. Predicados delegados
            # --------------------------------------------------

            for predicate in result["delegated"]:
                delegated_counter[predicate["name"]] += 1

        except Exception:
            failed += 1

    total = len(candidate_rules)

    # ==================================================
    # Informações gerais
    # ==================================================

    print("\n=== Real Ruleset Semantic Analysis ===")

    print(f"Candidate rules      : {total}")
    print(f"Parsed rules         : {parsed}")
    print(f"Parse failures       : {failed}")

    parser_success = (
        parsed / total * 100
        if total
        else 0
    )

    print(
        f"Parser success rate  : "
        f"{parser_success:.2f}%"
    )

    # ==================================================
    # Resolução de variáveis
    # ==================================================

    print("\nVariable resolution")
    print("-" * 45)

    resolution_percentage = (
        resolved_rule_counter / parsed * 100
        if parsed
        else 0
    )

    print(
        f"Rules with resolved variables : "
        f"{resolved_rule_counter} "
        f"({resolution_percentage:.2f}%)"
    )

    print("\nResolved fields")
    print("-" * 45)

    for field, count in resolution_counter.most_common():
        print(
            f"{field:<25} "
            f"{count}"
        )

    # ==================================================
    # Classificação semântica
    # ==================================================

    print("\nSemantic classifications")
    print("-" * 45)

    for classification in [
        "EXACT",
        "NECESSARY",
        "UNSUPPORTED"
    ]:
        count = classifications.get(
            classification,
            0
        )

        percentage = (
            count / parsed * 100
            if parsed
            else 0
        )

        print(
            f"{classification:<12}: "
            f"{count:>5} "
            f"({percentage:6.2f}%)"
        )

    semantic_coverage = (
        classifications.get("EXACT", 0)
        +
        classifications.get("NECESSARY", 0)
    )

    semantic_coverage_percentage = (
        semantic_coverage / parsed * 100
        if parsed
        else 0
    )

    print("-" * 45)

    print(
        f"Semantic coverage : "
        f"{semantic_coverage}/{parsed} "
        f"({semantic_coverage_percentage:.2f}%)"
    )

    # ==================================================
    # Elegibilidade para pré-filtro
    # ==================================================

    print("\nPre-filter eligibility")
    print("-" * 45)

    eligible = prefilter_candidates.get(
        "yes",
        0
    )

    not_eligible = prefilter_candidates.get(
        "no",
        0
    )

    eligible_percentage = (
        eligible / parsed * 100
        if parsed
        else 0
    )

    not_eligible_percentage = (
        not_eligible / parsed * 100
        if parsed
        else 0
    )

    print(
        f"Candidate     : "
        f"{eligible:>5} "
        f"({eligible_percentage:6.2f}%)"
    )

    print(
        f"Not candidate : "
        f"{not_eligible:>5} "
        f"({not_eligible_percentage:6.2f}%)"
    )

    # ==================================================
    # Predicados preservados
    # ==================================================

    print("\nMost frequent preserved predicates")
    print("-" * 45)

    for name, count in preserved_counter.most_common(15):
        print(
            f"{name:<25} "
            f"{count}"
        )

    # ==================================================
    # Predicados delegados
    # ==================================================

    print("\nMost frequent delegated predicates")
    print("-" * 45)

    for name, count in delegated_counter.most_common(20):
        print(
            f"{name:<25} "
            f"{count}"
        )

    # ==================================================
    # Verificação de consistência
    # ==================================================

    classified_total = sum(
        classifications.values()
    )

    eligibility_total = (
        eligible
        +
        not_eligible
    )

    print("\nConsistency checks")
    print("-" * 45)

    print(
        f"Parsed vs classified : "
        f"{parsed} / {classified_total}"
    )

    print(
        f"Parsed vs eligibility: "
        f"{parsed} / {eligibility_total}"
    )

    if (
        parsed == classified_total
        and
        parsed == eligibility_total
    ):
        print("Status               : OK")
    else:
        print("Status               : CHECK REQUIRED")


if __name__ == "__main__":
    main()
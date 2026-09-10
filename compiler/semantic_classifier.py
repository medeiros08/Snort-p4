from dataclasses import dataclass, asdict
from typing import Any, Dict, List


SEMANTIC_TREATMENTS = {
    "PRESERVED",
    "EXPANDED",
    "DELEGATED",
    "FALLBACK",
    "UNASSESSED",
}


@dataclass
class RuleClassification:
    rule_id: str

    classification: str

    prefilter_candidate: bool

    exact_semantics: bool

    has_selective_predicate: bool

    preserved_predicates: int

    expanded_predicates: int

    delegated_predicates: int

    fallback_predicates: int

    unassessed_predicates: int

    selective_predicates: List[Dict[str, Any]]

    reasons: List[str]

    final_detection: str = "SNORT"

    def to_dict(self):
        return asdict(self)


def is_wildcard(value):
    if value is None:
        return False

    return (
        isinstance(value, str)
        and value.strip().lower() == "any"
    )


def protocol_is_selective(predicate):
    """
    tcp/udp/icmp restrict the packet set.

    'ip' is represented as a wildcard and therefore
    is not selective.
    """

    value = str(
        predicate.value
    ).strip().lower()

    return value in {
        "tcp",
        "udp",
        "icmp",
    }


def ip_is_selective(predicate):
    """
    Concrete IPv4/CIDR expressions are selective.
    'any' is not.
    """

    value = predicate.value

    if is_wildcard(value):
        return False

    if isinstance(value, list):
        return len(value) > 0

    return value is not None


def port_is_selective(predicate):
    """
    Exact ports and successfully expandable port lists
    are selective.

    'any' is not.
    """

    value = predicate.value

    if is_wildcard(value):
        return False

    if isinstance(value, list):
        return len(value) > 0

    return value is not None


def flags_are_selective(predicate):
    return True


def direction_is_selective(predicate):
    """
    Direction is structural rather than an independent
    traffic predicate.

    A forward arrow by itself does not reduce the packet
    set if addresses and ports are wildcards.

    Bidirectional expansion likewise changes orientation
    but is not counted as an independent selective
    predicate.
    """

    return False


def is_selective_predicate(predicate):
    """
    Determine whether an already assessed P4 predicate
    actually reduces the traffic candidate set.

    Only PRESERVED and EXPANDED predicates can contribute
    to selectivity.
    """

    if predicate.backend_treatment not in {
        "PRESERVED",
        "EXPANDED",
    }:
        return False

    field = predicate.field

    if field == "protocol":
        return protocol_is_selective(
            predicate
        )

    if field in {
        "src_ip",
        "dst_ip",
    }:
        return ip_is_selective(
            predicate
        )

    if field in {
        "src_port",
        "dst_port",
    }:
        return port_is_selective(
            predicate
        )

    if field == "flags":
        return flags_are_selective(
            predicate
        )

    if field == "direction":
        return direction_is_selective(
            predicate
        )

    return False


def classify_assessed_rule(
    assessed_rule,
):
    """
    Classify one rule after:

        parsing
        variable resolution
        semantic IR construction
        target capability analysis

    EXACT:
        Every detection-relevant predicate is represented
        equivalently in the data plane.

    NECESSARY:
        At least one selective, safely represented
        predicate exists, but some detection semantics
        remain delegated or unsupported by the current
        backend.

    UNSUPPORTED:
        No useful selective P4 predicate can safely act
        as a prefilter for the rule.
    """

    counts = {
        "PRESERVED": 0,
        "EXPANDED": 0,
        "DELEGATED": 0,
        "FALLBACK": 0,
        "UNASSESSED": 0,
    }

    selective = []

    reasons = []

    for predicate in (
        assessed_rule.predicates
    ):

        treatment = (
            predicate.backend_treatment
        )

        if treatment in counts:
            counts[
                treatment
            ] += 1

        if is_selective_predicate(
            predicate
        ):
            selective.append(
                {
                    "kind": predicate.kind,
                    "field": predicate.field,
                    "operator": predicate.operator,
                    "value": predicate.value,
                    "treatment": treatment,
                }
            )

    has_selective = (
        len(selective) > 0
    )

    has_delegated = (
        counts["DELEGATED"] > 0
    )

    has_fallback = (
        counts["FALLBACK"] > 0
    )

    has_unassessed = (
        counts["UNASSESSED"] > 0
    )

    # OUT_OF_SCOPE predicates intentionally do not
    # participate in semantic detection equivalence.

    exact_semantics = (
        not has_delegated
        and not has_fallback
        and not has_unassessed
    )

    if exact_semantics:
        classification = "EXACT"

        prefilter_candidate = True

        final_detection = (
            "DATA_PLANE"
        )

        reasons.append(
            "all_detection_predicates_represented"
        )

    elif has_selective:
        classification = (
            "NECESSARY"
        )

        prefilter_candidate = True

        final_detection = "SNORT"

        reasons.append(
            "safe_selective_necessary_predicate_available"
        )

        if has_delegated:
            reasons.append(
                "detection_predicates_delegated_to_snort"
            )

        if has_fallback:
            reasons.append(
                "unsupported_predicates_omitted_from_prefilter"
            )

        if has_unassessed:
            reasons.append(
                "unassessed_predicates_present"
            )

    else:
        classification = (
            "UNSUPPORTED"
        )

        prefilter_candidate = False

        final_detection = "SNORT"

        reasons.append(
            "no_safe_selective_data_plane_predicate"
        )

        if has_delegated:
            reasons.append(
                "detection_predicates_delegated_to_snort"
            )

        if has_fallback:
            reasons.append(
                "unsupported_backend_predicates_present"
            )

        if has_unassessed:
            reasons.append(
                "unassessed_predicates_present"
            )

    return RuleClassification(
        rule_id=str(
            assessed_rule.rule_id
        ),

        classification=(
            classification
        ),

        prefilter_candidate=(
            prefilter_candidate
        ),

        exact_semantics=(
            exact_semantics
        ),

        has_selective_predicate=(
            has_selective
        ),

        preserved_predicates=(
            counts["PRESERVED"]
        ),

        expanded_predicates=(
            counts["EXPANDED"]
        ),

        delegated_predicates=(
            counts["DELEGATED"]
        ),

        fallback_predicates=(
            counts["FALLBACK"]
        ),

        unassessed_predicates=(
            counts["UNASSESSED"]
        ),

        selective_predicates=(
            selective
        ),

        reasons=reasons,

        final_detection=(
            final_detection
        ),
    )
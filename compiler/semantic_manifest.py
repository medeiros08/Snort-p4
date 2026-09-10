from dataclasses import asdict, is_dataclass


def serialize_value(value):
    """
    Convert values used by the semantic IR into objects
    that can be safely written as JSON.
    """

    if is_dataclass(value):
        return asdict(value)

    if isinstance(value, dict):
        return {
            key: serialize_value(item)
            for key, item in value.items()
        }

    if isinstance(value, list):
        return [
            serialize_value(item)
            for item in value
        ]

    if isinstance(value, tuple):
        return [
            serialize_value(item)
            for item in value
        ]

    return value


def predicate_to_dict(predicate):
    """
    Serialize one SemanticPredicate.
    """

    return {
        "kind": predicate.kind,

        "field": predicate.field,

        "operator": predicate.operator,

        "value": serialize_value(
            predicate.value
        ),

        "buffer": predicate.buffer,

        "modifiers": serialize_value(
            predicate.modifiers
        ),

        "backend_treatment": (
            predicate.backend_treatment
        ),

        "source_option": (
            predicate.source_option
        ),

        "source_index": (
            predicate.source_index
        ),
    }


def predicates_with_treatment(
    assessed_rule,
    treatment,
):
    """
    Return all predicates with one backend treatment.
    """

    return [
        predicate_to_dict(predicate)
        for predicate in assessed_rule.predicates
        if (
            predicate.backend_treatment
            == treatment
        )
    ]


def detection_predicates(
    assessed_rule,
):
    """
    Return all predicates that participate in detection
    semantics.

    OUT_OF_SCOPE metadata is intentionally excluded.
    """

    return [
        predicate_to_dict(predicate)
        for predicate in assessed_rule.predicates
        if (
            predicate.backend_treatment
            != "OUT_OF_SCOPE"
        )
    ]


def metadata_predicates(
    assessed_rule,
):
    return [
        predicate_to_dict(predicate)
        for predicate in assessed_rule.predicates
        if (
            predicate.backend_treatment
            == "OUT_OF_SCOPE"
        )
    ]


def build_manifest_record(
    parsed_rule,
    resolved_rule,
    semantic_rule,
    assessed_rule,
    classification,
    capability_reasons,
    resolution_log,
):
    """
    Build one auditable compilation-manifest record.

    The manifest intentionally preserves the distinction
    between:

        source syntax
        semantic IR
        target capability
        rule classification
        backend eligibility
    """

    rule_type = (
        semantic_rule.rule_type
    )

    service_header = None

    if rule_type == "SERVICE":

        service_header = (
            semantic_rule
            .metadata
            .get(
                "_service_header"
            )
        )

    return {
        # ----------------------------------------------------
        # Identity
        # ----------------------------------------------------

        "rule_id": str(
            semantic_rule.rule_id
        ),

        "action": (
            semantic_rule.action
        ),

        "rule_type": (
            rule_type
        ),

        "service_header": (
            service_header
        ),

        # ----------------------------------------------------
        # Semantic classification
        # ----------------------------------------------------

        "classification": (
            classification.classification
        ),

        "prefilter_candidate": (
            classification.prefilter_candidate
        ),

        "exact_semantics": (
            classification.exact_semantics
        ),

        "has_selective_predicate": (
            classification
            .has_selective_predicate
        ),

        "final_detection": (
            classification.final_detection
        ),

        # ----------------------------------------------------
        # Selective P4 predicate subset
        # ----------------------------------------------------

        "selective_predicates": (
            serialize_value(
                classification
                .selective_predicates
            )
        ),

        # ----------------------------------------------------
        # Backend treatment groups
        # ----------------------------------------------------

        "preserved": (
            predicates_with_treatment(
                assessed_rule,
                "PRESERVED",
            )
        ),

        "expanded": (
            predicates_with_treatment(
                assessed_rule,
                "EXPANDED",
            )
        ),

        "delegated": (
            predicates_with_treatment(
                assessed_rule,
                "DELEGATED",
            )
        ),

        "fallback": (
            predicates_with_treatment(
                assessed_rule,
                "FALLBACK",
            )
        ),

        "unassessed": (
            predicates_with_treatment(
                assessed_rule,
                "UNASSESSED",
            )
        ),

        # ----------------------------------------------------
        # Detection semantics and metadata
        # ----------------------------------------------------

        "detection_predicates": (
            detection_predicates(
                assessed_rule
            )
        ),

        "metadata_predicates": (
            metadata_predicates(
                assessed_rule
            )
        ),

        # ----------------------------------------------------
        # Decision evidence
        # ----------------------------------------------------

        "classification_reasons": (
            list(
                classification.reasons
            )
        ),

        "capability_decisions": (
            serialize_value(
                capability_reasons
            )
        ),

        # ----------------------------------------------------
        # Snort variable audit
        # ----------------------------------------------------

        "variable_resolution": (
            serialize_value(
                resolution_log
            )
        ),

        # ----------------------------------------------------
        # Summary counts
        # ----------------------------------------------------

        "counts": {
            "preserved": (
                classification
                .preserved_predicates
            ),

            "expanded": (
                classification
                .expanded_predicates
            ),

            "delegated": (
                classification
                .delegated_predicates
            ),

            "fallback": (
                classification
                .fallback_predicates
            ),

            "unassessed": (
                classification
                .unassessed_predicates
            ),

            "selective": len(
                classification
                .selective_predicates
            ),
        },

        # ----------------------------------------------------
        # Parsed/resolved representations
        #
        # Useful for auditability and debugging.
        # ----------------------------------------------------

        "parsed_rule": (
            serialize_value(
                parsed_rule
            )
        ),

        "resolved_rule": (
            serialize_value(
                resolved_rule
            )
        ),

        # ----------------------------------------------------
        # Semantic metadata
        # ----------------------------------------------------

        "metadata": (
            serialize_value(
                semantic_rule.metadata
            )
        ),
    }
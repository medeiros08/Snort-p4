from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional


PREDICATE_KINDS = {
    "HEADER",
    "PAYLOAD",
    "BUFFER",
    "APPLICATION",
    "FLOW_STATE",
    "TEMPORAL",
    "POST_DETECTION",
    "METADATA",
}


BACKEND_TREATMENTS = {
    "UNASSESSED",
    "PRESERVED",
    "DELEGATED",
    "EXPANDED",
    "FALLBACK",
    "OUT_OF_SCOPE",
}


@dataclass
class SemanticPredicate:
    """
    Semantic representation of one component of a Snort rule.

    The semantic IR describes what a rule component means.
    Backend capability decisions are performed later.

    source_index preserves the original order of Snort options.
    This is important for options whose semantics depend on
    buffers, cursors, or previous predicates.
    """

    kind: str
    operator: str

    value: Any = None

    field: Optional[str] = None
    buffer: Optional[str] = None

    modifiers: Optional[List[Any]] = None

    backend_treatment: str = "UNASSESSED"

    source_option: Optional[str] = None
    source_index: Optional[int] = None


    def __post_init__(self):

        if self.kind not in PREDICATE_KINDS:
            raise ValueError(
                f"Unknown predicate kind: {self.kind}"
            )

        if (
            self.backend_treatment
            not in BACKEND_TREATMENTS
        ):
            raise ValueError(
                "Unknown backend treatment: "
                f"{self.backend_treatment}"
            )

        if self.modifiers is None:
            self.modifiers = []


    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SemanticRuleIR:
    """
    Semantic-level intermediate representation
    of one Snort rule.
    """

    rule_id: Any

    action: str

    rule_type: str

    raw_rule: Optional[str]

    predicates: List[SemanticPredicate]

    metadata: Dict[str, Any]


    def to_dict(self) -> Dict[str, Any]:

        return {
            "rule_id": self.rule_id,

            "action": self.action,

            "rule_type": self.rule_type,

            "raw_rule": self.raw_rule,

            "predicates": [
                predicate.to_dict()
                for predicate in self.predicates
            ],

            "metadata": self.metadata,
        }


# ============================================================
# Predicate factory helpers
# ============================================================


def make_header_predicate(
    field,
    operator,
    value,
    backend_treatment="UNASSESSED",
    source_option=None,
    source_index=None,
):

    return SemanticPredicate(
        kind="HEADER",

        field=field,

        operator=operator,

        value=value,

        backend_treatment=backend_treatment,

        source_option=source_option,

        source_index=source_index,
    )


def make_payload_predicate(
    operator,
    value=None,
    buffer="default",
    modifiers=None,
    source_option=None,
    source_index=None,
    backend_treatment="DELEGATED",
):

    return SemanticPredicate(
        kind="PAYLOAD",

        operator=operator,

        value=value,

        buffer=buffer,

        modifiers=modifiers or [],

        backend_treatment=backend_treatment,

        source_option=source_option,

        source_index=source_index,
    )


def make_buffer_predicate(
    operator,
    value=None,
    source_option=None,
    source_index=None,
):

    return SemanticPredicate(
        kind="BUFFER",

        operator=operator,

        value=value,

        backend_treatment="DELEGATED",

        source_option=source_option,

        source_index=source_index,
    )


def make_application_predicate(
    operator,
    value=None,
    source_option=None,
    source_index=None,
):

    return SemanticPredicate(
        kind="APPLICATION",

        operator=operator,

        value=value,

        backend_treatment="DELEGATED",

        source_option=source_option,

        source_index=source_index,
    )


def make_flow_predicate(
    operator,
    value=None,
    source_option=None,
    source_index=None,
):

    return SemanticPredicate(
        kind="FLOW_STATE",

        operator=operator,

        value=value,

        backend_treatment="DELEGATED",

        source_option=source_option,

        source_index=source_index,
    )


def make_temporal_predicate(
    operator,
    value=None,
    source_option=None,
    source_index=None,
):

    return SemanticPredicate(
        kind="TEMPORAL",

        operator=operator,

        value=value,

        backend_treatment="DELEGATED",

        source_option=source_option,

        source_index=source_index,
    )


def make_post_detection_predicate(
    operator,
    value=None,
    source_option=None,
    source_index=None,
):

    return SemanticPredicate(
        kind="POST_DETECTION",

        operator=operator,

        value=value,

        backend_treatment="DELEGATED",

        source_option=source_option,

        source_index=source_index,
    )


def make_metadata_predicate(
    operator,
    value=None,
    source_option=None,
    source_index=None,
):

    return SemanticPredicate(
        kind="METADATA",

        operator=operator,

        value=value,

        backend_treatment="OUT_OF_SCOPE",

        source_option=source_option,

        source_index=source_index,
    )
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
COMPILER_DIR = PROJECT_ROOT / "compiler"

sys.path.insert(
    0,
    str(COMPILER_DIR)
)


from build_semantic_ir import build_semantic_ir


def test_rule_with_content():
    parsed_rule = {
        "action": "alert",
        "protocol": "tcp",
        "src_ip": "any",
        "src_port": "any",
        "direction": "->",
        "dst_ip": "10.0.0.2",
        "dst_port": "80",
        "options": {
            "content": "attack",
            "sid": "1002",
        },
    }

    semantic_rule = build_semantic_ir(
        parsed_rule
    )

    assert semantic_rule.rule_type == "TRADITIONAL"

    kinds = [
        predicate.kind
        for predicate in semantic_rule.predicates
    ]

    assert "HEADER" in kinds
    assert "PAYLOAD" in kinds

    content_predicates = [
        predicate
        for predicate in semantic_rule.predicates
        if predicate.operator == "content"
    ]

    assert len(content_predicates) == 1

    assert (
        content_predicates[0].backend_treatment
        == "DELEGATED"
    )


def test_rule_with_flow_and_flags():
    parsed_rule = {
        "action": "alert",
        "protocol": "tcp",
        "src_ip": "any",
        "src_port": "any",
        "direction": "->",
        "dst_ip": "10.0.0.2",
        "dst_port": "80",
        "options": {
            "flags": "S",
            "flow": "to_server,established",
            "sid": "1003",
        },
    }

    semantic_rule = build_semantic_ir(
        parsed_rule
    )

    flags = [
        predicate
        for predicate in semantic_rule.predicates
        if predicate.field == "flags"
    ]

    flow = [
        predicate
        for predicate in semantic_rule.predicates
        if predicate.operator == "flow"
    ]

    assert len(flags) == 1
    assert flags[0].kind == "HEADER"
    assert flags[0].backend_treatment == "UNASSESSED"

    assert len(flow) == 1
    assert flow[0].kind == "FLOW_STATE"
    assert flow[0].backend_treatment == "DELEGATED"


if __name__ == "__main__":
    test_rule_with_content()
    test_rule_with_flow_and_flags()

    print(
        "Semantic IR tests passed."
    )
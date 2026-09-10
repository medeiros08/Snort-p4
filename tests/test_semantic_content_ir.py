import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
COMPILER_DIR = PROJECT_ROOT / "compiler"

sys.path.insert(
    0,
    str(COMPILER_DIR)
)


from build_semantic_ir import build_semantic_ir


def test_content_is_structured():
    parsed_rule = {
        "sid": 9001,

        "action": "alert",

        "protocol": "tcp",

        "source": {
            "address": "any",
            "port": "any",
        },

        "direction": "->",

        "destination": {
            "address": "10.0.0.2",
            "port": "80",
        },

        "options": [
            {
                "name": "content",
                "value": (
                    '!"|00|",within 100,'
                    'distance 2,nocase'
                ),
            },

            {
                "name": "sid",
                "value": "9001",
            },
        ],
    }

    semantic_rule = build_semantic_ir(
        parsed_rule
    )

    contents = [
        predicate
        for predicate in semantic_rule.predicates
        if predicate.operator == "content"
    ]

    assert len(contents) == 1

    content = contents[0]

    assert content.kind == "PAYLOAD"

    assert (
        content.value["pattern"]
        == "|00|"
    )

    assert (
        content.value["negated"]
        is True
    )

    modifier_map = {
        modifier["name"]:
        modifier["value"]

        for modifier
        in content.modifiers
    }

    assert (
        modifier_map["within"]
        == 100
    )

    assert (
        modifier_map["distance"]
        == 2
    )

    assert (
        modifier_map["nocase"]
        is True
    )

    assert (
        content.backend_treatment
        == "DELEGATED"
    )


if __name__ == "__main__":
    test_content_is_structured()

    print(
        "Semantic content IR tests passed."
    )
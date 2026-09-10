import sys
from pathlib import Path


PROJECT_ROOT = Path(
    __file__
).resolve().parents[1]

COMPILER_DIR = (
    PROJECT_ROOT
    / "compiler"
)

sys.path.insert(
    0,
    str(COMPILER_DIR),
)


from parser import parse_rule
from build_semantic_ir import (
    build_semantic_ir,
)


def test_http_uri_context():

    rule = parse_rule(
        'alert http ( '
        'http_uri; '
        'content:"first"; '
        'content:"second"; '
        'http_header; '
        'content:"User-Agent"; '
        'sid:9001; '
        ')'
    )

    ir = build_semantic_ir(
        rule
    )

    contents = [
        predicate
        for predicate in ir.predicates
        if (
            predicate.kind == "PAYLOAD"
            and
            predicate.operator == "content"
        )
    ]

    assert len(contents) == 3

    assert (
        contents[0].buffer
        == "http_uri"
    )

    assert (
        contents[1].buffer
        == "http_uri"
    )

    assert (
        contents[2].buffer
        == "http_header"
    )


def test_pkt_data_switch():

    rule = parse_rule(
        'alert tcp any any -> any any ( '
        'http_uri; '
        'content:"uri-value"; '
        'pkt_data; '
        'content:"packet-value"; '
        'sid:9002; '
        ')'
    )

    ir = build_semantic_ir(
        rule
    )

    contents = [
        predicate
        for predicate in ir.predicates
        if (
            predicate.kind == "PAYLOAD"
            and
            predicate.operator == "content"
        )
    ]

    assert len(contents) == 2

    assert (
        contents[0].buffer
        == "http_uri"
    )

    assert (
        contents[1].buffer
        == "pkt_data"
    )


def test_default_context():

    rule = parse_rule(
        'alert tcp any any -> any any ( '
        'content:"plain-payload"; '
        'sid:9003; '
        ')'
    )

    ir = build_semantic_ir(
        rule
    )

    contents = [
        predicate
        for predicate in ir.predicates
        if (
            predicate.kind == "PAYLOAD"
            and
            predicate.operator == "content"
        )
    ]

    assert len(contents) == 1

    assert (
        contents[0].buffer
        == "default"
    )


if __name__ == "__main__":

    test_http_uri_context()
    test_pkt_data_switch()
    test_default_context()

    print(
        "Buffer context tests passed."
    )
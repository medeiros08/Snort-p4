from parser import parse_rule
from build_semantic_ir import build_semantic_ir

r = parse_rule(
    'alert http ( flow:to_server,established; http_uri; content:"test"; sid:9999; )'
)

ir = build_semantic_ir(r)

print(ir.rule_type)

for p in ir.predicates:
    print(
        p.kind,
        p.operator,
        p.value,
        p.backend_treatment,
    )
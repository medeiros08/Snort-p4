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

# Sem estas checagens o arquivo so imprimia e o runner o contava como PASSA.
assert ir.rule_type == "SERVICE", ir.rule_type
assert not [p for p in ir.predicates if p.kind == "HEADER"], (
    "regra de servico nao pode ganhar predicado de cabecalho"
)
assert any(
    p.kind == "APPLICATION" and p.operator == "service_header" and p.value == "http"
    for p in ir.predicates
)

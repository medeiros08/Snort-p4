import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "compiler"))

from parser import parse_rule
from variable_resolver import (
    load_variables,
    resolve_rule_variables
)


def main():
    variables = load_variables()

    rule_text = (
        'alert tcp $EXTERNAL_NET any -> '
        '$HOME_NET $HTTP_PORTS '
        '(content:"attack"; sid:2001;)'
    )

    rule = parse_rule(rule_text)

    resolved_rule, log = resolve_rule_variables(
        rule,
        variables
    )

    print("\nOriginal rule fields")
    print("-" * 40)

    print(rule["source"])
    print(rule["destination"])

    print("\nResolved rule fields")
    print("-" * 40)

    print(resolved_rule["source"])
    print(resolved_rule["destination"])

    print("\nResolution log")
    print("-" * 40)

    for item in log:
        print(
            f"{item['field']}: "
            f"{item['original']} -> "
            f"{item['resolved']}"
        )

    # Sem estas checagens o arquivo so imprimia e o runner o contava como
    # PASSA qualquer que fosse a resolucao.
    assert resolved_rule["source"] == {
        "address": variables["EXTERNAL_NET"],
        "port": "any",
    }, resolved_rule["source"]
    assert resolved_rule["destination"] == {
        "address": variables["HOME_NET"],
        "port": variables["HTTP_PORTS"],
    }, resolved_rule["destination"]
    assert [item["field"] for item in log] == [
        "src_ip",
        "dst_ip",
        "dst_port",
    ], log
    assert rule["destination"]["address"] == "$HOME_NET"


if __name__ == "__main__":
    main()
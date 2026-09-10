from parser import parse_rules_file
from classifier import classify_rule
from pprint import pprint


rules = parse_rules_file("../rules/test.rules")

print(f"\nRules analyzed: {len(rules)}\n")

for rule in rules:
    result = classify_rule(rule)

    pprint(result)
    print("-" * 60)
from parser import parse_rules_file
from pprint import pprint


rules = parse_rules_file("../rules/test.rules")

print(f"\nParsed rules: {len(rules)}\n")

for rule in rules:
    pprint(rule)
    print("-" * 60)
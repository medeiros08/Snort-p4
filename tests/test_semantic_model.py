import sys
from pathlib import Path

# Allows importing modules from compiler/
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "compiler"))

from parser import parse_rule
from classifier import classify_rule


TEST_CASES = [
    {
        "rule": (
            'alert tcp any any -> 10.0.0.2 80 '
            '(flags:S; sid:1001;)'
        ),
        "expected_class": "EXACT",
        "expected_prefilter": True,
    },
    {
        "rule": (
            'alert tcp any any -> 10.0.0.2 80 '
            '(content:"attack"; sid:1002;)'
        ),
        "expected_class": "NECESSARY",
        "expected_prefilter": True,
    },
    {
        "rule": (
            'alert tcp any any -> any any '
            '(pcre:"/malware/i"; sid:1003;)'
        ),
        "expected_class": "NECESSARY",
        "expected_prefilter": False,
    },
]


def main():
    failures = 0

    for case in TEST_CASES:
        rule = parse_rule(case["rule"])
        result = classify_rule(rule)

        actual_class = result["classification"]
        actual_prefilter = result.get("prefilter_candidate")

        class_ok = actual_class == case["expected_class"]
        prefilter_ok = actual_prefilter == case["expected_prefilter"]

        status = "PASS" if class_ok and prefilter_ok else "FAIL"

        print(
            f"SID {rule['sid']}: {status} | "
            f"class={actual_class} | "
            f"prefilter={actual_prefilter}"
        )

        if status == "FAIL":
            failures += 1

    print("-" * 60)

    if failures:
        print(f"{failures} test(s) failed.")
    else:
        print("All semantic model tests passed.")


if __name__ == "__main__":
    main()
    
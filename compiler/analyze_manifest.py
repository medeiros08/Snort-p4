import json
from collections import Counter


MANIFEST_FILE = "../output/manifest.json"


def main():
    with open(MANIFEST_FILE, "r", encoding="utf-8") as file:
        manifest = json.load(file)

    classifications = Counter(
        item["classification"] for item in manifest
    )

    total = len(manifest)

    print("\nSemantic Classification Summary")
    print("-" * 40)

    for classification in ["EXACT", "NECESSARY", "UNSUPPORTED"]:
        count = classifications.get(classification, 0)
        percentage = (count / total * 100) if total else 0

        print(
            f"{classification:<12}: "
            f"{count:>3} rules "
            f"({percentage:6.2f}%)"
        )

    coverage = (
        classifications.get("EXACT", 0)
        + classifications.get("NECESSARY", 0)
    )

    coverage_percentage = (
        coverage / total * 100
        if total
        else 0
    )

    print("-" * 40)
    print(f"Total rules   : {total}")
    print(
        f"Rule coverage : {coverage}/{total} "
        f"({coverage_percentage:.2f}%)"
    )


if __name__ == "__main__":
    main()
    
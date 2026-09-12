import json
import re
import sys
from pathlib import Path


PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parents[1]
)

MANIFEST_FILE = (
    PROJECT_ROOT
    / "output"
    / "semantic_manifest.json"
)

SOURCE_RULES_FILE = (
    PROJECT_ROOT
    / "rules"
    / "snort3-community.rules"
)

CANDIDATE_OUTPUT = (
    PROJECT_ROOT
    / "output"
    / "snort_candidate.rules"
)

UNSUPPORTED_OUTPUT = (
    PROJECT_ROOT
    / "output"
    / "snort_unsupported.rules"
)

REPORT_OUTPUT = (
    PROJECT_ROOT
    / "output"
    / "snort_experiment_split.json"
)


SID_RE = re.compile(
    r"\bsid\s*:\s*(\d+)\s*;",
    re.IGNORECASE,
)


# ============================================================
# Generic manifest helpers
# ============================================================


def recursive_find(
    obj,
    keys,
):
    """
    Find the first value associated with one of the requested
    keys inside a nested dictionary.

    This keeps the experiment generator tolerant to small
    manifest schema changes.
    """

    if isinstance(obj, dict):

        for key in keys:

            if key in obj:
                return obj[key]

        for value in obj.values():

            result = recursive_find(
                value,
                keys,
            )

            if result is not None:
                return result

    elif isinstance(obj, list):

        for value in obj:

            result = recursive_find(
                value,
                keys,
            )

            if result is not None:
                return result

    return None


def find_rule_records(
    manifest,
):
    """
    Locate the rule-level records in semantic_manifest.json.
    """

    if isinstance(manifest, list):
        return manifest

    if not isinstance(
        manifest,
        dict,
    ):
        raise ValueError(
            "Manifest root is neither "
            "an object nor a list."
        )

    for key in (
        "rules",
        "entries",
        "records",
    ):

        value = manifest.get(
            key
        )

        if isinstance(
            value,
            list,
        ):

            return value

    raise ValueError(
        "Could not locate rule records "
        "inside semantic_manifest.json"
    )


def normalize_sid(
    value,
):

    if value is None:
        return None

    if isinstance(
        value,
        int,
    ):

        return value

    text = str(
        value
    ).strip()

    match = re.search(
        r"\d+",
        text,
    )

    if not match:
        return None

    return int(
        match.group(0)
    )


def normalize_class(
    value,
):

    if value is None:
        return None

    return str(
        value
    ).strip().upper()


def normalize_candidate(
    value,
):

    if isinstance(
        value,
        bool,
    ):
        return value

    if isinstance(
        value,
        int,
    ):
        return value != 0

    if isinstance(
        value,
        str,
    ):

        normalized = (
            value.strip().lower()
        )

        if normalized in {
            "true",
            "yes",
            "1",
            "candidate",
        }:
            return True

        if normalized in {
            "false",
            "no",
            "0",
            "not_candidate",
            "non_candidate",
        }:
            return False

    return None


# ============================================================
# Manifest index
# ============================================================


def build_manifest_index(
    manifest,
):

    records = find_rule_records(
        manifest
    )

    sid_index = {}

    failures = []

    for index, record in enumerate(
        records,
        start=1,
    ):

        sid = normalize_sid(
            recursive_find(
                record,
                (
                    "sid",
                    "rule_sid",
                    "rule_id",
                ),
            )
        )

        semantic_class = normalize_class(
            recursive_find(
                record,
                (
                    "semantic_class",
                    "classification",
                    "class",
                ),
            )
        )

        prefilter_candidate = normalize_candidate(
            recursive_find(
                record,
                (
                    "prefilter_candidate",
                    "candidate",
                ),
            )
        )

        if sid is None:

            failures.append(
                {
                    "record": index,
                    "reason": "missing SID",
                }
            )

            continue

        if semantic_class is None:

            failures.append(
                {
                    "record": index,
                    "sid": sid,
                    "reason": (
                        "missing semantic class"
                    ),
                }
            )

            continue

   # Candidate status is deliberately separate from
# semantic class.
#
# If an older manifest lacks the explicit field,
# use the current semantic policy as a fallback.

        if prefilter_candidate is None:

            prefilter_candidate = (
                semantic_class
                in {
                    "EXACT",
                    "NECESSARY",
                }
            )

        if sid in sid_index:

            previous = sid_index[
                sid
            ]

            if (
                previous[
                    "semantic_class"
                ]
                != semantic_class
                or
                previous[
                    "prefilter_candidate"
                ]
                != prefilter_candidate
            ):

                raise ValueError(
                    "Conflicting manifest "
                    f"records for SID {sid}"
                )

            continue

        sid_index[
            sid
        ] = {
            "semantic_class": (
                semantic_class
            ),

            "prefilter_candidate": (
                prefilter_candidate
            ),
        }

    return (
        records,
        sid_index,
        failures,
    )


# ============================================================
# Source rules
# ============================================================


def extract_sid_from_rule(
    line,
):

    match = SID_RE.search(
        line
    )

    if not match:
        return None

    return int(
        match.group(1)
    )


# ============================================================
# Main
# ============================================================


def main():

    print()
    print(
        "=== Snort Experimental Rule Split ==="
    )
    print()

    for path in (
        MANIFEST_FILE,
        SOURCE_RULES_FILE,
    ):

        if not path.exists():

            print(
                "ERROR: Missing file:"
            )

            print(
                path
            )

            sys.exit(1)

    # --------------------------------------------------------
    # Load manifest
    # --------------------------------------------------------

    with open(
        MANIFEST_FILE,
        "r",
        encoding="utf-8",
    ) as file:

        manifest = json.load(
            file
        )

    try:

        (
            manifest_records,
            manifest_index,
            manifest_failures,
        ) = build_manifest_index(
            manifest
        )

    except Exception as error:

        print(
            "ERROR while reading manifest:"
        )

        print(
            error
        )

        sys.exit(1)

    # --------------------------------------------------------
    # Load original Snort rules
    # --------------------------------------------------------

    source_lines = (
        SOURCE_RULES_FILE
        .read_text(
            encoding="utf-8",
            errors="replace",
        )
        .splitlines(
            keepends=True
        )
    )

    candidate_lines = []

    unsupported_lines = []

    source_sids = set()

    duplicate_source_sids = []

    missing_in_manifest = []

    lines_without_sid = []

    semantic_counts = {}

    candidate_class_counts = {}

    unsupported_class_counts = {}

    # --------------------------------------------------------
    # Split rules
    # --------------------------------------------------------

    for line_number, line in enumerate(
        source_lines,
        start=1,
    ):

        stripped = line.strip()

        if not stripped:
            continue

        sid = extract_sid_from_rule(
            line
        )

        if sid is None:

            lines_without_sid.append(
                {
                    "line": line_number,
                    "text": (
                        stripped[:200]
                    ),
                }
            )

            continue

        if sid in source_sids:

            duplicate_source_sids.append(
                sid
            )

        source_sids.add(
            sid
        )

        info = manifest_index.get(
            sid
        )

        if info is None:

            missing_in_manifest.append(
                sid
            )

            continue

        semantic_class = (
            info[
                "semantic_class"
            ]
        )

        is_candidate = (
            info[
                "prefilter_candidate"
            ]
        )

        semantic_counts[
            semantic_class
        ] = (
            semantic_counts.get(
                semantic_class,
                0,
            )
            + 1
        )

        if is_candidate:

            candidate_lines.append(
                line
            )

            candidate_class_counts[
                semantic_class
            ] = (
                candidate_class_counts.get(
                    semantic_class,
                    0,
                )
                + 1
            )

        else:

            unsupported_lines.append(
                line
            )

            unsupported_class_counts[
                semantic_class
            ] = (
                unsupported_class_counts.get(
                    semantic_class,
                    0,
                )
                + 1
            )

    # --------------------------------------------------------
    # Cross-check manifest against original rules
    # --------------------------------------------------------

    manifest_sids = set(
        manifest_index.keys()
    )

    missing_in_source = sorted(
        manifest_sids
        - source_sids
    )

    missing_in_manifest = sorted(
        set(
            missing_in_manifest
        )
    )

    duplicate_source_sids = sorted(
        set(
            duplicate_source_sids
        )
    )

    # --------------------------------------------------------
    # Validation
    # --------------------------------------------------------

    validation_errors = []

    if manifest_failures:

        validation_errors.append(
            "manifest records could not "
            "be interpreted"
        )

    if missing_in_manifest:

        validation_errors.append(
            "source rules missing from manifest"
        )

    if missing_in_source:

        validation_errors.append(
            "manifest SIDs missing from "
            "source ruleset"
        )

    if duplicate_source_sids:

        validation_errors.append(
            "duplicate SIDs in source rules"
        )

    if lines_without_sid:

        validation_errors.append(
            "non-empty source lines "
            "without SID"
        )

    total_split = (
        len(candidate_lines)
        + len(unsupported_lines)
    )

    if (
        total_split
        != len(source_sids)
    ):

        validation_errors.append(
            "split count does not equal "
            "source SID count"
        )

    # --------------------------------------------------------
    # Only write rule files if structurally valid
    # --------------------------------------------------------

    if not validation_errors:

        CANDIDATE_OUTPUT.write_text(
            "".join(
                candidate_lines
            ),
            encoding="utf-8",
            newline="",
        )

        UNSUPPORTED_OUTPUT.write_text(
            "".join(
                unsupported_lines
            ),
            encoding="utf-8",
            newline="",
        )

    # --------------------------------------------------------
    # Report
    # --------------------------------------------------------

    report = {
        "schema_version": "1.0",

        "source_rules_file": (
            SOURCE_RULES_FILE.name
        ),

        "manifest_file": (
            MANIFEST_FILE.name
        ),

        "manifest_records": len(
            manifest_records
        ),

        "manifest_indexed_sids": len(
            manifest_index
        ),

        "source_lines": len(
            source_lines
        ),

        "source_sids": len(
            source_sids
        ),

        "candidate_rules": len(
            candidate_lines
        ),

        "non_candidate_rules": len(
            unsupported_lines
        ),

        "semantic_counts": (
            semantic_counts
        ),

        "candidate_class_counts": (
            candidate_class_counts
        ),

        "non_candidate_class_counts": (
            unsupported_class_counts
        ),

        "manifest_failures": (
            manifest_failures
        ),

        "missing_in_manifest": (
            missing_in_manifest
        ),

        "missing_in_source": (
            missing_in_source
        ),

        "duplicate_source_sids": (
            duplicate_source_sids
        ),

        "lines_without_sid": (
            lines_without_sid
        ),

        "validation_errors": (
            validation_errors
        ),
    }

    REPORT_OUTPUT.write_text(
        json.dumps(
            report,
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
        newline="",
    )

    print(
        f"Manifest records       : "
        f"{len(manifest_records)}"
    )

    print(
        f"Manifest indexed SIDs  : "
        f"{len(manifest_index)}"
    )

    print(
        f"Source rule SIDs       : "
        f"{len(source_sids)}"
    )

    print()

    print(
        "Semantic classes"
    )

    print(
        "-" * 50
    )

    for semantic_class in sorted(
        semantic_counts
    ):

        print(
            f"{semantic_class:<20} "
            f"{semantic_counts[semantic_class]:>6}"
        )

    print()

    print(
        f"Candidate rules        : "
        f"{len(candidate_lines)}"
    )

    print(
        f"Non-candidate rules    : "
        f"{len(unsupported_lines)}"
    )

    print()

    print(
        f"Missing in manifest    : "
        f"{len(missing_in_manifest)}"
    )

    print(
        f"Missing in source      : "
        f"{len(missing_in_source)}"
    )

    print(
        f"Duplicate source SIDs  : "
        f"{len(duplicate_source_sids)}"
    )

    print(
        f"Lines without SID      : "
        f"{len(lines_without_sid)}"
    )

    print()

    status = (
        "VALID"
        if not validation_errors
        else "INVALID"
    )

    print(
        f"Split status           : "
        f"{status}"
    )

    if validation_errors:

        print()
        print(
            "Validation errors:"
        )

        for error in validation_errors:

            print(
                f"  - {error}"
            )

    else:

        print()

        print(
            f"Candidate output       : "
            f"{CANDIDATE_OUTPUT}"
        )

        print(
            f"Unsupported output     : "
            f"{UNSUPPORTED_OUTPUT}"
        )

    print(
        f"Report                 : "
        f"{REPORT_OUTPUT}"
    )


if __name__ == "__main__":
    main()
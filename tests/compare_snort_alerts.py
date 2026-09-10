import json
import sys
from pathlib import Path


PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parents[1]
)

BASELINE_FILE = (
    PROJECT_ROOT
    / "output"
    / "alert_preservation_baseline.jsonl"
)

CANDIDATE_FILE = (
    PROJECT_ROOT
    / "output"
    / "alert_preservation_candidate.jsonl"
)


def load_alerts(path):

    alerts = []

    with open(
        path,
        "r",
        encoding="utf-8",
    ) as file:

        for line_number, line in enumerate(
            file,
            start=1,
        ):

            line = line.strip()

            if not line:
                continue

            try:

                record = json.loads(
                    line
                )

            except json.JSONDecodeError:

                print(
                    f"ERROR: invalid JSON "
                    f"in {path.name}, "
                    f"line {line_number}"
                )

                sys.exit(1)

            alerts.append(
                record
            )

    return alerts


def alert_key(alert):

    return (
        int(
            alert.get(
                "pkt_num",
                -1,
            )
        ),

        int(
            alert.get(
                "gid",
                -1,
            )
        ),

        int(
            alert.get(
                "sid",
                -1,
            )
        ),

        int(
            alert.get(
                "rev",
                -1,
            )
        ),
    )


def main():

    print()
    print(
        "=== Snort Alert Preservation Comparison ==="
    )
    print()

    for path in (
        BASELINE_FILE,
        CANDIDATE_FILE,
    ):

        if not path.exists():

            print(
                f"ERROR: missing file: "
                f"{path}"
            )

            sys.exit(1)

    baseline = load_alerts(
        BASELINE_FILE
    )

    candidate = load_alerts(
        CANDIDATE_FILE
    )

    baseline_map = {
        alert_key(alert): alert
        for alert in baseline
    }

    candidate_map = {
        alert_key(alert): alert
        for alert in candidate
    }

    baseline_keys = set(
        baseline_map
    )

    candidate_keys = set(
        candidate_map
    )

    preserved = (
        baseline_keys
        & candidate_keys
    )

    missing = (
        baseline_keys
        - candidate_keys
    )

    additional = (
        candidate_keys
        - baseline_keys
    )

    print(
        f"Baseline alerts        : "
        f"{len(baseline)}"
    )

    print(
        f"Candidate alerts       : "
        f"{len(candidate)}"
    )

    print(
        f"Preserved alerts       : "
        f"{len(preserved)}"
    )

    print(
        f"Missing from candidate : "
        f"{len(missing)}"
    )

    print(
        f"Additional candidate   : "
        f"{len(additional)}"
    )

    print()

    if missing:

        print(
            "MISSING ALERTS"
        )

        print(
            "-" * 70
        )

        for key in sorted(
            missing
        ):

            alert = baseline_map[
                key
            ]

            print(
                f"packet={key[0]} "
                f"gid={key[1]} "
                f"sid={key[2]} "
                f"rev={key[3]} "
                f"msg={alert.get('msg')}"
            )

        print()

    if additional:

        print(
            "ADDITIONAL ALERTS"
        )

        print(
            "-" * 70
        )

        for key in sorted(
            additional
        ):

            alert = candidate_map[
                key
            ]

            print(
                f"packet={key[0]} "
                f"gid={key[1]} "
                f"sid={key[2]} "
                f"rev={key[3]} "
                f"msg={alert.get('msg')}"
            )

        print()

    if not missing:

        preservation = (
            100.0
            if baseline
            else 100.0
        )

        print(
            f"Alert preservation     : "
            f"{preservation:.2f}%"
        )

        print()

        print(
            "Comparison status      : VALID"
        )

    else:

        preservation = (
            len(preserved)
            / len(baseline_keys)
            * 100
            if baseline_keys
            else 0.0
        )

        print(
            f"Alert preservation     : "
            f"{preservation:.2f}%"
        )

        print()

        print(
            "Comparison status      : "
            "ALERT_LOSS_DETECTED"
        )

        sys.exit(1)


if __name__ == "__main__":
    main()
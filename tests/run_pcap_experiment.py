import argparse
import os
import subprocess
import sys

from pathlib import Path


PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parents[1]
)

OUTPUT_DIR = (
    PROJECT_ROOT
    / "output"
)

SNORT_CONFIG = (
    PROJECT_ROOT
    / "config"
    / "snort3_experiment.lua"
)

FULL_RULES = (
    PROJECT_ROOT
    / "rules"
    / "snort3-community.rules"
)

CANDIDATE_RULES = (
    PROJECT_ROOT
    / "output"
    / "snort_candidate.rules"
)

CLASSIFIER = (
    PROJECT_ROOT
    / "tests"
    / "classify_pcap_bmv2.py"
)

VALIDATOR = (
    PROJECT_ROOT
    / "tests"
    / "validate_end_to_end.py"
)


def run_command(
    command,
    description,
    stdout_file=None,
    env=None,
):
    print()
    print(
        f"=== {description} ==="
    )
    print()

    print(
        "Command:"
    )

    print(
        " ".join(
            str(part)
            for part in command
        )
    )

    print()

    if stdout_file:

        stdout_file.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        with open(
            stdout_file,
            "w",
            encoding="utf-8",
        ) as output:

            result = subprocess.run(
                command,
                cwd=PROJECT_ROOT,
                stdout=output,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
            )

    else:

        result = subprocess.run(
            command,
            cwd=PROJECT_ROOT,
            env=env,
        )

    if result.returncode != 0:

        print()
        print(
            f"ERROR: {description} failed."
        )

        if (
            stdout_file
            and
            result.stderr
        ):

            print()
            print(
                result.stderr
            )

        sys.exit(
            result.returncode
        )

    print(
        f"{description}: OK"
    )


def build_snort_environment(
    snort_root,
):
    env = os.environ.copy()

    library_path = str(
        snort_root
        / "lib"
    )

    previous = env.get(
        "LD_LIBRARY_PATH",
        "",
    )

    if previous:

        env[
            "LD_LIBRARY_PATH"
        ] = (
            library_path
            + ":"
            + previous
        )

    else:

        env[
            "LD_LIBRARY_PATH"
        ] = (
            library_path
        )

    return env


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Run the complete Snort -> P4 "
            "prefilter experiment for one PCAP."
        )
    )

    parser.add_argument(
        "pcap",
        help=(
            "Input PCAP file"
        ),
    )

    parser.add_argument(
        "--label",
        default=None,
        help=(
            "Experiment label. "
            "Default: PCAP filename."
        ),
    )

    parser.add_argument(
        "--interface",
        default="veth1",
        help=(
            "BMv2 injection interface. "
            "Default: veth1."
        ),
    )

    parser.add_argument(
        "--delay",
        type=float,
        default=0.20,
        help=(
            "Delay between injected packets."
        ),
    )

    args = parser.parse_args()

    pcap = Path(
        args.pcap
    ).resolve()

    if not pcap.exists():

        print(
            f"ERROR: PCAP not found: "
            f"{pcap}"
        )

        sys.exit(1)

    label = (
        args.label
        if args.label
        else pcap.stem
    )

    safe_label = (
        label
        .replace(
            " ",
            "_",
        )
        .replace(
            "/",
            "_",
        )
        .replace(
            "\\",
            "_",
        )
    )

    home = Path.home()

    snort_root = (
        home
        / "snort3-install"
    )

    snort_binary = (
        snort_root
        / "bin"
        / "snort"
    )

    p4runtime_python = (
        home
        / ".venvs"
        / "p4runtime"
        / "bin"
        / "python"
    )

    required_files = [
        snort_binary,
        SNORT_CONFIG,
        FULL_RULES,
        CANDIDATE_RULES,
        CLASSIFIER,
        VALIDATOR,
        p4runtime_python,
    ]

    for required in required_files:

        if not required.exists():

            print(
                f"ERROR: Required file "
                f"not found: {required}"
            )

            sys.exit(1)

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    baseline_output = (
        OUTPUT_DIR
        / (
            f"{safe_label}"
            "_baseline.jsonl"
        )
    )

    candidate_output = (
        OUTPUT_DIR
        / (
            f"{safe_label}"
            "_candidate.jsonl"
        )
    )

    p4_output = (
        OUTPUT_DIR
        / (
            f"{safe_label}"
            "_p4.jsonl"
        )
    )

    report_output = (
        OUTPUT_DIR
        / (
            f"{safe_label}"
            "_report.json"
        )
    )

    snort_env = (
        build_snort_environment(
            snort_root
        )
    )

    alert_lua = (
        "alert_json = { "
        "fields = "
        "'pkt_num gid sid rev msg "
        "src_addr dst_addr' "
        "}"
    )

    print()
    print(
        "==========================================="
    )
    print(
        " Snort -> P4 End-to-End PCAP Experiment"
    )
    print(
        "==========================================="
    )
    print()

    print(
        f"Label      : {safe_label}"
    )

    print(
        f"PCAP       : {pcap}"
    )

    print(
        f"Snort      : {snort_binary}"
    )

    print(
        f"Interface  : {args.interface}"
    )

    print()

    # ========================================================
    # 1. Full Snort baseline
    # ========================================================

    baseline_command = [
        str(
            snort_binary
        ),
        "-q",
        "-c",
        str(
            SNORT_CONFIG
        ),
        "-R",
        str(
            FULL_RULES
        ),
        "-r",
        str(
            pcap
        ),
        "-A",
        "alert_json",
        "--lua",
        alert_lua,
    ]

    run_command(
        baseline_command,
        "Snort FULL baseline",
        stdout_file=baseline_output,
        env=snort_env,
    )

    # ========================================================
    # 2. Candidate Snort ruleset
    # ========================================================

    candidate_command = [
        str(
            snort_binary
        ),
        "-q",
        "-c",
        str(
            SNORT_CONFIG
        ),
        "-R",
        str(
            CANDIDATE_RULES
        ),
        "-r",
        str(
            pcap
        ),
        "-A",
        "alert_json",
        "--lua",
        alert_lua,
    ]

    run_command(
        candidate_command,
        "Snort candidate ruleset",
        stdout_file=candidate_output,
        env=snort_env,
    )

    # ========================================================
    # 3. BMv2 classification
    #
    # Raw packet injection requires root privileges.
    # Only this subprocess is executed through sudo.
    # ========================================================

    classify_command = [
        "sudo",
        str(
            p4runtime_python
        ),
        str(
            CLASSIFIER
        ),
        str(
            pcap
        ),
        "--interface",
        args.interface,
        "--output",
        str(
            p4_output
        ),
        "--delay",
        str(
            args.delay
        ),
    ]

    run_command(
        classify_command,
        "BMv2 packet classification",
    )

    # ========================================================
    # 4. End-to-end validation
    # ========================================================

    validator_command = [
        sys.executable,
        str(
            VALIDATOR
        ),
        "--baseline",
        str(
            baseline_output
        ),
        "--candidate",
        str(
            candidate_output
        ),
        "--p4",
        str(
            p4_output
        ),
        "--output",
        str(
            report_output
        ),
    ]

    run_command(
        validator_command,
        "End-to-end validation",
    )

    # ========================================================
    # Final summary
    # ========================================================

    print()
    print(
        "==========================================="
    )
    print(
        " Experiment completed successfully"
    )
    print(
        "==========================================="
    )
    print()

    print(
        f"Baseline alerts : "
        f"{baseline_output}"
    )

    print(
        f"Candidate alerts: "
        f"{candidate_output}"
    )

    print(
        f"P4 results      : "
        f"{p4_output}"
    )

    print(
        f"Final report    : "
        f"{report_output}"
    )

    print()


if __name__ == "__main__":
    main()
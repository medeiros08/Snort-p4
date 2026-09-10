import argparse
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parents[1]
)

COMPILER_DIR = (
    PROJECT_ROOT
    / "compiler"
)

CONFIG_DIR = (
    PROJECT_ROOT
    / "config"
)

OUTPUT_DIR = (
    PROJECT_ROOT
    / "output"
)

P4_SOURCE = (
    PROJECT_ROOT
    / "p4"
    / "ids_prefilter.p4"
)

SNORT3_ROOT = (
    Path.home()
    / "snort3-install"
)

SNORT3_BINARY = (
    SNORT3_ROOT
    / "bin"
    / "snort"
)


# ============================================================
# Pipeline scripts
# ============================================================


PYTHON_STEPS = [
    (
        "generate_semantic_manifest.py",
        "Semantic manifest generation",
    ),

    (
        "validate_semantic_manifest.py",
        "Semantic manifest validation",
    ),

    (
        "generate_snort_experiment_rules.py",
        "Snort experimental rule split",
    ),

    (
        "generate_p4_entries.py",
        "P4 backend generation",
    ),

    (
        "expand_p4_entries.py",
        "P4 entry expansion",
    ),

    (
        "normalize_p4_entries.py",
        "P4 entry normalization",
    ),

    (
        "validate_backend.py",
        "Backend compatibility validation",
    ),

    (
        "lower_p4_entries.py",
        "Final P4 entry lowering",
    ),
]


SNAPSHOT_OUTPUT_FILES = [
    "semantic_manifest.json",
    "snort_candidate.rules",
    "snort_unsupported.rules",
    "snort_experiment_split.json",

    "p4_entries.json",
    "p4_entries_expanded.json",
    "p4runtime_entries.json",

    "backend_validation.json",
    "p4_install_entries.json",
    "p4runtime_install_plan.json",

    "ids_prefilter.json",
    "ids_prefilter.p4info.txt",
]


SNAPSHOT_CONFIG_FILES = [
    "active_profile.json",
    "snort_variables.json",
    "snort3_experiment.lua",
]


# ============================================================
# Command execution
# ============================================================


def command_text(command):

    return " ".join(
        str(part)
        for part in command
    )


def run_command(
    command,
    description,
    cwd=PROJECT_ROOT,
    env=None,
    log_path=None,
):

    print()
    print(
        "=" * 70
    )

    print(
        description
    )

    print(
        "=" * 70
    )

    print()

    print(
        command_text(command)
    )

    print()

    result = subprocess.run(
        command,
        cwd=cwd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    output = (
        result.stdout
        if result.stdout
        else ""
    )

    print(
        output,
        end=""
    )

    if log_path is not None:

        log_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        log_path.write_text(
            output,
            encoding="utf-8",
        )

    if result.returncode != 0:

        print()
        print(
            f"ERROR: {description} failed "
            f"with return code "
            f"{result.returncode}"
        )

        sys.exit(
            result.returncode
        )

    print()
    print(
        f"{description}: OK"
    )

    return output


# ============================================================
# Environment
# ============================================================


def snort_environment():

    env = os.environ.copy()

    library_path = str(
        SNORT3_ROOT
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
        ] = library_path

    return env


# ============================================================
# JSON utilities
# ============================================================


def load_json_if_exists(path):

    if not path.exists():
        return None

    try:

        return json.loads(
            path.read_text(
                encoding="utf-8"
            )
        )

    except Exception:

        return None


def nested_value(
    data,
    *keys,
):

    current = data

    for key in keys:

        if not isinstance(
            current,
            dict,
        ):
            return None

        current = current.get(
            key
        )

    return current


# ============================================================
# Snort validation
# ============================================================


def validate_snort_ruleset(
    rules_file,
    description,
    log_file,
):

    if not SNORT3_BINARY.exists():

        print(
            "ERROR: Snort 3 executable "
            "not found:"
        )

        print(
            SNORT3_BINARY
        )

        sys.exit(1)

    config = (
        CONFIG_DIR
        / "snort3_experiment.lua"
    )

    command = [
        str(
            SNORT3_BINARY
        ),

        "-c",
        str(
            config
        ),

        "-R",
        str(
            rules_file
        ),

        "-T",
    ]

    output = run_command(
        command,
        description,
        env=snort_environment(),
        log_path=log_file,
    )

    if (
        "successfully validated"
        not in output.lower()
    ):

        print()
        print(
            "ERROR: Snort returned success "
            "but the expected validation "
            "message was not found."
        )

        sys.exit(1)


# ============================================================
# P4 compilation
# ============================================================


def compile_p4(
    log_file,
):

    compiler = shutil.which(
        "p4c-bm2-ss"
    )

    if compiler is None:

        print(
            "ERROR: p4c-bm2-ss "
            "was not found in PATH."
        )

        sys.exit(1)

    command = [
        compiler,

        "--p4v",
        "16",

        "--p4runtime-files",
        str(
            OUTPUT_DIR
            / "ids_prefilter.p4info.txt"
        ),

        "-o",
        str(
            OUTPUT_DIR
            / "ids_prefilter.json"
        ),

        str(
            P4_SOURCE
        ),
    ]

    run_command(
        command,
        "P4 program compilation",
        log_path=log_file,
    )


# ============================================================
# Snapshot
# ============================================================


def copy_file(
    source,
    destination,
):

    if not source.exists():

        raise FileNotFoundError(
            f"Expected artifact does not "
            f"exist: {source}"
        )

    destination.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    shutil.copy2(
        source,
        destination,
    )


def snapshot_profile(
    profile_name,
):

    profile_dir = (
        OUTPUT_DIR
        / "profiles"
        / profile_name
    )

    artifacts_dir = (
        profile_dir
        / "artifacts"
    )

    config_dir = (
        profile_dir
        / "config"
    )

    artifacts_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    config_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    for filename in (
        SNAPSHOT_OUTPUT_FILES
    ):

        source = (
            OUTPUT_DIR
            / filename
        )

        destination = (
            artifacts_dir
            / filename
        )

        copy_file(
            source,
            destination,
        )

    for filename in (
        SNAPSHOT_CONFIG_FILES
    ):

        source = (
            CONFIG_DIR
            / filename
        )

        destination = (
            config_dir
            / filename
        )

        copy_file(
            source,
            destination,
        )

    return profile_dir


# ============================================================
# Build report
# ============================================================


def create_build_report(
    profile_name,
    profile_dir,
):

    active_profile = (
        load_json_if_exists(
            CONFIG_DIR
            / "active_profile.json"
        )
        or {}
    )

    semantic_manifest = (
        load_json_if_exists(
            OUTPUT_DIR
            / "semantic_manifest.json"
        )
        or {}
    )

    split = (
        load_json_if_exists(
            OUTPUT_DIR
            / "snort_experiment_split.json"
        )
        or {}
    )

    backend = (
        load_json_if_exists(
            OUTPUT_DIR
            / "backend_validation.json"
        )
        or {}
    )

    lowered = (
        load_json_if_exists(
            OUTPUT_DIR
            / "p4_install_entries.json"
        )
        or {}
    )

    runtime_plan = (
        load_json_if_exists(
            OUTPUT_DIR
            / "p4runtime_install_plan.json"
        )
        or {}
    )

    report = {
        "schema_version": "1.0",

        "profile": (
            profile_name
        ),

        "built_at_utc": (
            datetime.now(
                timezone.utc
            ).isoformat()
        ),

        "active_profile": (
            active_profile
        ),

        "snort_split": {
            "source_sids": (
                split.get(
                    "source_sids"
                )
            ),

            "candidate_rules": (
                split.get(
                    "candidate_rules"
                )
            ),

            "non_candidate_rules": (
                split.get(
                    "non_candidate_rules"
                )
            ),

            "semantic_counts": (
                split.get(
                    "semantic_counts"
                )
            ),

            "validation_errors": (
                split.get(
                    "validation_errors"
                )
            ),
        },

        "semantic_manifest": {
            "schema_version": (
                semantic_manifest.get(
                    "schema_version"
                )
            ),
        },

        "backend": {
            "validation_errors": (
                backend.get(
                    "validation_errors"
                )
            ),

            "validation_warnings": (
                backend.get(
                    "validation_warnings"
                )
            ),

            "fits_table": (
                nested_value(
                    backend,
                    "capacity",
                    "fits"
                )
            ),
        },

        "p4_install": {
            "source_entries": (
                lowered.get(
                    "source_entries"
                )
            ),

            "final_install_entries": (
                lowered.get(
                    "final_install_entries"
                )
            ),

            "reduction_percentage": (
                lowered.get(
                    "reduction_percentage"
                )
            ),
        },

        "p4runtime": {
            "source_install_entries": (
                runtime_plan.get(
                    "source_install_entries"
                )
            ),

            "encoded_entries": (
                runtime_plan.get(
                    "encoded_entries"
                )
            ),

            "encoding_failures": len(
                runtime_plan.get(
                    "encoding_failures",
                    [],
                )
            ),

            "validation_errors": len(
                runtime_plan.get(
                    "validation_errors",
                    [],
                )
            ),
        },

        "snapshot_directory": str(
            profile_dir
            .relative_to(
                PROJECT_ROOT
            )
        ),

        "status": "VALID",
    }

    report_file = (
        profile_dir
        / "build_report.json"
    )

    report_file.write_text(
        json.dumps(
            report,
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )

    return (
        report,
        report_file
    )


# ============================================================
# Main
# ============================================================


def main():

    parser = argparse.ArgumentParser(
        description=(
            "Select and completely rebuild "
            "one Snort -> P4 experimental "
            "profile."
        )
    )

    parser.add_argument(
        "profile",
        help=(
            "Profile name, e.g. "
            "controlled or cicids2017"
        ),
    )

    args = parser.parse_args()

    profile_name = (
        args.profile.strip()
    )

    logs_dir = (
        OUTPUT_DIR
        / "build_logs"
        / profile_name
    )

    print()
    print(
        "############################################"
    )

    print(
        "# Snort -> P4 Profile Build"
    )

    print(
        "############################################"
    )

    print()

    print(
        f"Profile : {profile_name}"
    )

    print(
        f"Python  : {sys.executable}"
    )

    print()

    # ========================================================
    # 1. Select profile
    # ========================================================

    run_command(
        [
            sys.executable,
            str(
                COMPILER_DIR
                / "select_profile.py"
            ),
            profile_name,
        ],
        "Profile selection",
        log_path=(
            logs_dir
            / "01_select_profile.log"
        ),
    )

    # ========================================================
    # 2. Semantic / backend pipeline
    # ========================================================

    step_number = 2

    for (
        script_name,
        description,
    ) in PYTHON_STEPS:

        script = (
            COMPILER_DIR
            / script_name
        )

        if not script.exists():

            print(
                "ERROR: Pipeline script "
                "not found:"
            )

            print(
                script
            )

            sys.exit(1)

        run_command(
            [
                sys.executable,
                str(
                    script
                ),
            ],
            description,
            cwd=COMPILER_DIR,
            log_path=(
                logs_dir
                / (
                    f"{step_number:02d}_"
                    f"{script.stem}.log"
                )
            ),
        )

        step_number += 1

    # ========================================================
    # 3. Validate Snort FULL
    # ========================================================

    validate_snort_ruleset(
        PROJECT_ROOT
        / "rules"
        / "snort3-community.rules",

        "Snort FULL ruleset validation",

        logs_dir
        / (
            f"{step_number:02d}_"
            "snort_full.log"
        ),
    )

    step_number += 1

    # ========================================================
    # 4. Validate candidate subset
    # ========================================================

    validate_snort_ruleset(
        OUTPUT_DIR
        / "snort_candidate.rules",

        "Snort candidate ruleset validation",

        logs_dir
        / (
            f"{step_number:02d}_"
            "snort_candidate.log"
        ),
    )

    step_number += 1

    # ========================================================
    # 5. Validate unsupported subset
    # ========================================================

    validate_snort_ruleset(
        OUTPUT_DIR
        / "snort_unsupported.rules",

        "Snort unsupported ruleset validation",

        logs_dir
        / (
            f"{step_number:02d}_"
            "snort_unsupported.log"
        ),
    )

    step_number += 1

    # ========================================================
    # 6. Compile P4
    # ========================================================

    compile_p4(
        logs_dir
        / (
            f"{step_number:02d}_"
            "compile_p4.log"
        )
    )

    step_number += 1

    # ========================================================
    # 7. Generate final P4Runtime plan
    # ========================================================

    run_command(
        [
            sys.executable,
            str(
                COMPILER_DIR
                / "generate_p4runtime_install.py"
            ),
        ],

        "P4Runtime install-plan generation",

        cwd=COMPILER_DIR,

        log_path=(
            logs_dir
            / (
                f"{step_number:02d}_"
                "generate_p4runtime_install.log"
            )
        ),
    )

    # ========================================================
    # 8. Snapshot all artifacts
    # ========================================================

    try:

        profile_dir = (
            snapshot_profile(
                profile_name
            )
        )

    except Exception as error:

        print()
        print(
            "ERROR while creating "
            "profile snapshot:"
        )

        print(
            error
        )

        sys.exit(1)

    # ========================================================
    # 9. Build report
    # ========================================================

    (
        report,
        report_file,
    ) = create_build_report(
        profile_name,
        profile_dir,
    )

    # ========================================================
    # Final report
    # ========================================================

    print()
    print(
        "############################################"
    )

    print(
        "# Profile build completed"
    )

    print(
        "############################################"
    )

    print()

    print(
        f"Profile                 : "
        f"{profile_name}"
    )

    print(
        f"HOME_NET                : "
        f"{report['active_profile'].get('HOME_NET')}"
    )

    print()

    print(
        f"Source Snort rules      : "
        f"{report['snort_split'].get('source_sids')}"
    )

    print(
        f"Candidate rules         : "
        f"{report['snort_split'].get('candidate_rules')}"
    )

    print(
        f"Unsupported rules       : "
        f"{report['snort_split'].get('non_candidate_rules')}"
    )

    print()

    print(
        f"Final install entries   : "
        f"{report['p4_install'].get('final_install_entries')}"
    )

    print(
        f"P4Runtime encoded       : "
        f"{report['p4runtime'].get('encoded_entries')}"
    )

    print(
        f"P4Runtime failures      : "
        f"{report['p4runtime'].get('encoding_failures')}"
    )

    print(
        f"P4Runtime errors        : "
        f"{report['p4runtime'].get('validation_errors')}"
    )

    print()

    print(
        f"Snapshot                : "
        f"{profile_dir}"
    )

    print(
        f"Build report            : "
        f"{report_file}"
    )

    print()

    print(
        "Profile build status    : VALID"
    )


if __name__ == "__main__":
    main()
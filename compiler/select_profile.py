import argparse
import json
import re
import sys

from pathlib import Path


# ============================================================
# Project paths
# ============================================================


PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parents[1]
)

PROFILES_DIR = (
    PROJECT_ROOT
    / "config"
    / "profiles"
)

ACTIVE_VARIABLES_FILE = (
    PROJECT_ROOT
    / "config"
    / "snort_variables.json"
)

SNORT_CONFIG_FILE = (
    PROJECT_ROOT
    / "config"
    / "snort3_experiment.lua"
)

ACTIVE_PROFILE_FILE = (
    PROJECT_ROOT
    / "config"
    / "active_profile.json"
)


# ============================================================
# Supported experimental variables
# ============================================================


# O conjunto e o de ips.variables do Snort 3.12.2.0 com o snort.lua padrao,
# conferido por tests/check_profile_vs_snort.py contra
# `snort --dump-config-text` no rig. Variavel que o Snort define e o perfil
# nao definisse faria o compilador recusar uma regra que o Snort aceita.
#
# DNS_SERVERS, FTP_SERVERS e SSH_SERVERS valem 'any' nos perfis, e nao
# HOME_NET: o snort.lua faz HOME_NET = 'any' (linha 24) antes de incluir o
# snort_defaults.lua, que atribui HOME_NET a elas (linhas 35-41) ali mesmo;
# a configuracao do experimento so redefine HOME_NET depois. O valor
# efetivo no Snort e 'any', e e ele que o perfil tem de reproduzir.
NETWORK_VARIABLES = [
    "HOME_NET",
    "EXTERNAL_NET",
    "HTTP_SERVERS",
    "SQL_SERVERS",
    "SMTP_SERVERS",
    "TELNET_SERVERS",
    "SIP_SERVERS",
    "DNS_SERVERS",
    "FTP_SERVERS",
    "SSH_SERVERS",
]


PORT_VARIABLES = [
    "HTTP_PORTS",
    "ORACLE_PORTS",
    "FILE_DATA_PORTS",
    "SIP_PORTS",
    "SSH_PORTS",
    "FTP_PORTS",
    "MAIL_PORTS",
]


REQUIRED_VARIABLES = (
    NETWORK_VARIABLES
    + PORT_VARIABLES
)


PROFILE_NAME_RE = re.compile(
    r"^[A-Za-z0-9_-]+$"
)


# ============================================================
# Profile-name validation
# ============================================================


def validate_profile_name(
    profile_name,
):
    if not PROFILE_NAME_RE.match(
        profile_name
    ):

        raise ValueError(
            "Invalid profile name. "
            "Use only letters, numbers, "
            "underscore and hyphen."
        )


# ============================================================
# Network-variable validation
# ============================================================


def validate_network_variable(
    name,
    value,
):
    if not isinstance(
        value,
        str,
    ):

        raise ValueError(
            f"{name} must be a string."
        )

    value = value.strip()

    if not value:

        raise ValueError(
            f"{name} cannot be empty."
        )

    return value


# ============================================================
# Port-variable validation
# ============================================================


def validate_port_variable(
    name,
    value,
):
    if not isinstance(
        value,
        list,
    ):

        raise ValueError(
            f"{name} must be a JSON list."
        )

    if not value:

        raise ValueError(
            f"{name} cannot be empty."
        )

    normalized = []

    for port in value:

        if (
            not isinstance(
                port,
                int,
            )
            or isinstance(
                port,
                bool,
            )
        ):

            raise ValueError(
                f"{name} contains "
                f"a non-integer port: "
                f"{port}"
            )

        if not 0 <= port <= 65535:

            raise ValueError(
                f"{name} contains "
                f"invalid port: "
                f"{port}"
            )

        normalized.append(
            port
        )

    return normalized


# ============================================================
# Complete profile validation
# ============================================================


def validate_profile(
    profile,
):
    if not isinstance(
        profile,
        dict,
    ):

        raise ValueError(
            "Profile root must be "
            "a JSON object."
        )

    # --------------------------------------------------------
    # Required variables
    # --------------------------------------------------------

    missing = [
        name

        for name in REQUIRED_VARIABLES

        if name not in profile
    ]

    if missing:

        raise ValueError(
            "Profile is missing "
            f"variables: {missing}"
        )

    # --------------------------------------------------------
    # Variables not currently used by the compiler
    # --------------------------------------------------------

    extra = sorted(
        set(
            profile.keys()
        )
        - set(
            REQUIRED_VARIABLES
        )
    )

    # --------------------------------------------------------
    # Normalize
    # --------------------------------------------------------

    normalized = {}

    for name in NETWORK_VARIABLES:

        normalized[
            name
        ] = validate_network_variable(
            name,
            profile[
                name
            ],
        )

    for name in PORT_VARIABLES:

        normalized[
            name
        ] = validate_port_variable(
            name,
            profile[
                name
            ],
        )

    return (
        normalized,
        extra,
    )


# ============================================================
# Lua utilities
# ============================================================


def lua_quote(
    value,
):
    """
    Safely quote one string for the generated Lua file.
    """

    value = (
        str(
            value
        )
        .replace(
            "\\",
            "\\\\",
        )
        .replace(
            "'",
            "\\'",
        )
    )

    return (
        "'"
        + value
        + "'"
    )


def ports_to_snort_string(
    ports,
):
    """
    Snort 3 accepts the configured port variables in
    space-separated form.

    Example:

        [80, 8080]

    becomes:

        "80 8080"
    """

    return " ".join(
        str(
            port
        )
        for port in ports
    )


# ============================================================
# Snort 3 experiment configuration generation
# ============================================================


def generate_snort_lua(
    profile_name,
    profile,
):
    """
    Generate the complete Snort 3 experiment configuration.

    The standard Snort configuration is imported first.

    Then:

    1. file_magic.rules is disabled for the experiment;
    2. network variables are overridden;
    3. port variables are overridden.

    The file-inspection module itself is not removed. Only its
    default rules_file is removed so that Snort's loaded-rule
    counts correspond to the community ruleset under study.
    """

    lines = []

    # ========================================================
    # Header
    # ========================================================

    lines.append(
        "------------------------------------------------------------"
    )

    lines.append(
        "-- AUTO-GENERATED FILE"
    )

    lines.append(
        "--"
    )

    lines.append(
        "-- Generated by compiler/select_profile.py"
    )

    lines.append(
        f"-- Active profile: "
        f"{profile_name}"
    )

    lines.append(
        "--"
    )

    lines.append(
        "-- Do not edit this file manually."
    )

    lines.append(
        "------------------------------------------------------------"
    )

    lines.append("")

    # ========================================================
    # Standard Snort 3 configuration
    # ========================================================

    lines.append(
        "local snort3_root = "
        "os.getenv('HOME') .. "
        "'/snort3-install'"
    )

    lines.append("")

    lines.append(
        "include("
    )

    lines.append(
        "    snort3_root .. "
        "'/etc/snort/snort.lua'"
    )

    lines.append(
        ")"
    )

    lines.append("")

    # ========================================================
    # Disable automatic file_magic.rules
    # ========================================================
    #
    # The default Snort 3 configuration enables file_inspect
    # with:
    #
    #     rules_file = 'file_magic.rules'
    #
    # Those built-in file-identification rules are outside the
    # community ruleset analyzed by this project.
    #
    # They would otherwise add 219 rules to every experiment:
    #
    #     FULL        4017 -> 4236
    #     CANDIDATE   4003 -> 4222
    #     UNSUPPORTED   14 -> 233
    #
    # Reassigning file_inspect to an empty configuration keeps
    # the inspector available while removing its default
    # file_magic.rules from the experimental rule counts.
    # ========================================================

    lines.append(
        "------------------------------------------------------------"
    )

    lines.append(
        "-- Experimental isolation"
    )

    lines.append(
        "------------------------------------------------------------"
    )

    lines.append("")

    lines.append(
        "-- Prevent Snort's default file_magic.rules "
        "from being loaded."
    )

    lines.append(
        "file_inspect = { }"
    )

    lines.append("")

    # ========================================================
    # Experimental network profile
    # ========================================================

    lines.append(
        "------------------------------------------------------------"
    )

    lines.append(
        "-- Experimental network profile"
    )

    lines.append(
        "------------------------------------------------------------"
    )

    lines.append("")

    lines.append(
        "HOME_NET = "
        + lua_quote(
            profile[
                "HOME_NET"
            ]
        )
    )

    lines.append(
        "EXTERNAL_NET = "
        + lua_quote(
            profile[
                "EXTERNAL_NET"
            ]
        )
    )

    lines.append("")

    # ========================================================
    # Snort network variables
    # ========================================================

    lines.append(
        "------------------------------------------------------------"
    )

    lines.append(
        "-- Network variables"
    )

    lines.append(
        "------------------------------------------------------------"
    )

    lines.append("")

    for name in NETWORK_VARIABLES:

        lines.append(
            f"ips.variables.nets.{name} = "
            + lua_quote(
                profile[
                    name
                ]
            )
        )

    lines.append("")

    # ========================================================
    # Snort port variables
    # ========================================================

    lines.append(
        "------------------------------------------------------------"
    )

    lines.append(
        "-- Port variables"
    )

    lines.append(
        "------------------------------------------------------------"
    )

    lines.append("")

    for name in PORT_VARIABLES:

        value = ports_to_snort_string(
            profile[
                name
            ]
        )

        lines.append(
            f"ips.variables.ports.{name} = "
            + lua_quote(
                value
            )
        )

    lines.append("")

    # ========================================================
    # End marker
    # ========================================================

    lines.append(
        "------------------------------------------------------------"
    )

    lines.append(
        "-- End of generated experimental configuration"
    )

    lines.append(
        "------------------------------------------------------------"
    )

    lines.append("")

    return "\n".join(
        lines
    )


# ============================================================
# JSON writer
# ============================================================


def write_json(
    path,
    data,
):
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    path.write_text(
        json.dumps(
            data,
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
        newline="",
    )


# ============================================================
# Main
# ============================================================


def main():

    parser = argparse.ArgumentParser(
        description=(
            "Select the active experimental "
            "Snort/P4 network profile."
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
        args.profile
        .strip()
    )

    # ========================================================
    # Validate requested profile name
    # ========================================================

    try:

        validate_profile_name(
            profile_name
        )

    except ValueError as error:

        print(
            f"ERROR: {error}"
        )

        sys.exit(1)

    # ========================================================
    # Locate profile
    # ========================================================

    profile_file = (
        PROFILES_DIR
        / f"{profile_name}.json"
    )

    if not profile_file.exists():

        print(
            "ERROR: Profile not found:"
        )

        print(
            profile_file
        )

        print()

        available = sorted(
            path.stem

            for path in PROFILES_DIR.glob(
                "*.json"
            )
        )

        print(
            "Available profiles:"
        )

        for name in available:

            print(
                f"  - {name}"
            )

        sys.exit(1)

    # ========================================================
    # Load and validate profile JSON
    # ========================================================

    try:

        raw_profile = json.loads(
            profile_file.read_text(
                encoding="utf-8"
            )
        )

        (
            profile,
            extra_variables,
        ) = validate_profile(
            raw_profile
        )

    except Exception as error:

        print(
            "ERROR: Invalid profile:"
        )

        print(
            error
        )

        sys.exit(1)

    # ========================================================
    # Generate compiler variable configuration
    # ========================================================

    write_json(
        ACTIVE_VARIABLES_FILE,
        profile,
    )

    # ========================================================
    # Generate matching Snort configuration
    # ========================================================

    snort_lua = (
        generate_snort_lua(
            profile_name,
            profile,
        )
    )

    SNORT_CONFIG_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    SNORT_CONFIG_FILE.write_text(
        snort_lua,
        encoding="utf-8",
        newline="",
    )

    # ========================================================
    # Record active profile metadata
    # ========================================================

    active_profile = {
        "profile": (
            profile_name
        ),

        # as_posix, e nao str: no Windows str() grava `config\\...` e o
        # arquivo muda conforme a maquina que selecionou o perfil.
        "profile_file": (
            profile_file.relative_to(
                PROJECT_ROOT
            ).as_posix()
        ),

        "compiler_variables_file": (
            ACTIVE_VARIABLES_FILE.relative_to(
                PROJECT_ROOT
            ).as_posix()
        ),

        "snort_configuration_file": (
            SNORT_CONFIG_FILE.relative_to(
                PROJECT_ROOT
            ).as_posix()
        ),

        "HOME_NET": (
            profile[
                "HOME_NET"
            ]
        ),

        "EXTERNAL_NET": (
            profile[
                "EXTERNAL_NET"
            ]
        ),

        "network_variables": {
            name: profile[
                name
            ]

            for name in NETWORK_VARIABLES
        },

        "port_variables": {
            name: profile[
                name
            ]

            for name in PORT_VARIABLES
        },

        "snort_default_file_magic_disabled": (
            True
        ),

        "extra_variables_ignored": (
            extra_variables
        ),
    }

    write_json(
        ACTIVE_PROFILE_FILE,
        active_profile,
    )

    # ========================================================
    # Human-readable report
    # ========================================================

    print()
    print(
        "=== Experimental Profile Selection ==="
    )

    print()

    print(
        f"Selected profile        : "
        f"{profile_name}"
    )

    print(
        f"HOME_NET                : "
        f"{profile['HOME_NET']}"
    )

    print(
        f"EXTERNAL_NET            : "
        f"{profile['EXTERNAL_NET']}"
    )

    print()

    print(
        "Snort experiment isolation"
    )

    print(
        "-" * 55
    )

    print(
        "Default file_magic.rules: DISABLED"
    )

    print()

    print(
        f"Compiler variables      : "
        f"{ACTIVE_VARIABLES_FILE}"
    )

    print(
        f"Snort configuration     : "
        f"{SNORT_CONFIG_FILE}"
    )

    print(
        f"Active-profile metadata : "
        f"{ACTIVE_PROFILE_FILE}"
    )

    if extra_variables:

        print()

        print(
            "WARNING: Extra variables "
            "were present and ignored:"
        )

        for name in extra_variables:

            print(
                f"  - {name}"
            )

    print()

    print(
        "Profile selection status: VALID"
    )


if __name__ == "__main__":
    main()
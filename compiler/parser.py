import re

from typing import Dict, List


SUPPORTED_OPTIONS = {
    "flags",
    "sid",
}

UNSUPPORTED_OPTIONS = {
    "content",
    "pcre",
    "flowbits",
    "file_data",
}


def split_options(
    options_text: str,
) -> List[str]:
    """
    Split Snort rule options on semicolons while
    preserving semicolons that appear inside quoted
    strings.
    """

    parts = []
    current = []

    inside_quotes = False
    escaped = False

    for char in options_text:

        if char == "\\" and not escaped:
            escaped = True
            current.append(char)
            continue

        if (
            char == '"'
            and not escaped
        ):
            inside_quotes = (
                not inside_quotes
            )

        if (
            char == ";"
            and not inside_quotes
        ):
            item = "".join(
                current
            ).strip()

            if item:
                parts.append(
                    item
                )

            current = []

        else:
            current.append(
                char
            )

        escaped = False

    item = "".join(
        current
    ).strip()

    if item:
        parts.append(
            item
        )

    return parts


def parse_option(
    option: str,
) -> Dict:
    """
    Parse one Snort option while preserving the raw
    option value used by later semantic normalizers.
    """

    if ":" in option:

        key, value = option.split(
            ":",
            1,
        )

        return {
            "name": key.strip(),
            "value": (
                value
                .strip()
                .strip('"')
            ),
        }

    return {
        "name": option.strip(),
        "value": None,
    }


def parse_options(
    options_text: str,
) -> List[Dict]:

    return [
        parse_option(
            option
        )
        for option in split_options(
            options_text
        )
    ]


def extract_sid(
    parsed_options: List[Dict],
):
    """
    Extract SID without making it mandatory.
    """

    sid = None

    for option in parsed_options:

        if option["name"] != "sid":
            continue

        try:
            sid = int(
                option["value"]
            )

        except (
            TypeError,
            ValueError,
        ):
            sid = option[
                "value"
            ]

    return sid


def parse_traditional_rule(
    rule: str,
):
    """
    Parse traditional Snort header syntax:

        alert tcp any any -> any 80 (...)
    """

    match = re.match(
        r"^(?P<action>\w+)\s+"
        r"(?P<protocol>\w+)\s+"
        r"(?P<src_ip>\S+)\s+"
        r"(?P<src_port>\S+)\s+"
        r"(?P<direction>->|<>|<-)\s+"
        r"(?P<dst_ip>\S+)\s+"
        r"(?P<dst_port>\S+)\s*"
        r"\((?P<options>.*)\)$",
        rule,
    )

    if not match:
        return None

    data = match.groupdict()

    parsed_options = (
        parse_options(
            data["options"]
        )
    )

    sid = extract_sid(
        parsed_options
    )

    return {
        "sid": sid,

        "action": data[
            "action"
        ],

        "protocol": data[
            "protocol"
        ],

        "rule_type": (
            "TRADITIONAL"
        ),

        "source": {
            "address": data[
                "src_ip"
            ],

            "port": data[
                "src_port"
            ],
        },

        "direction": data[
            "direction"
        ],

        "destination": {
            "address": data[
                "dst_ip"
            ],

            "port": data[
                "dst_port"
            ],
        },

        "options": (
            parsed_options
        ),
    }


def parse_service_rule(
    rule: str,
):
    """
    Parse Snort 3 service-oriented rules such as:

        alert http (...)
        alert ssl (...)

    These rules intentionally do NOT receive invented
    source/destination header fields.
    """

    match = re.match(
        r"^(?P<action>\w+)\s+"
        r"(?P<service>\w+)\s*"
        r"\((?P<options>.*)\)$",
        rule,
    )

    if not match:
        return None

    data = match.groupdict()

    parsed_options = (
        parse_options(
            data["options"]
        )
    )

    sid = extract_sid(
        parsed_options
    )

    service = data[
        "service"
    ]

    return {
        "sid": sid,

        "action": data[
            "action"
        ],

        # Kept for compatibility with the current
        # parsed-rule representation. For SERVICE rules,
        # this means the Snort service header, not an
        # IPv4 protocol number.
        "protocol": service,

        "service": service,

        "rule_type": (
            "SERVICE"
        ),

        "source": None,

        "direction": None,

        "destination": None,

        "options": (
            parsed_options
        ),
    }


def parse_rule(
    rule: str,
) -> Dict:
    """
    Parse either:

    1. Traditional Snort rules

       alert tcp src_ip src_port -> dst_ip dst_port (...)

    2. Snort 3 service rules

       alert http (...)
       alert ssl (...)

    Traditional syntax is attempted first so existing
    behavior remains unchanged.
    """

    rule = rule.strip()

    traditional = (
        parse_traditional_rule(
            rule
        )
    )

    if traditional is not None:
        return traditional

    service = (
        parse_service_rule(
            rule
        )
    )

    if service is not None:
        return service

    raise ValueError(
        f"Could not parse rule: "
        f"{rule}"
    )


def parse_rules_file(
    path: str,
) -> List[Dict]:

    rules = []

    with open(
        path,
        "r",
        encoding="utf-8",
    ) as file:

        for (
            line_number,
            line,
        ) in enumerate(
            file,
            start=1,
        ):

            line = line.strip()

            if (
                not line
                or line.startswith("#")
            ):
                continue

            try:
                rules.append(
                    parse_rule(
                        line
                    )
                )

            except ValueError as error:

                print(
                    f"[line "
                    f"{line_number}] "
                    f"{error}"
                )

    return rules
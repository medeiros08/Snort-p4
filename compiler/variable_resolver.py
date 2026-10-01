import paths

import json
from pathlib import Path


CONFIG_FILE = (
    paths.VARIABLES_FILE
)


def load_variables():
    path = Path(CONFIG_FILE)

    if not path.exists():
        raise FileNotFoundError(
            f"Variable configuration not found: {path.resolve()}"
        )

    with open(
        path,
        "r",
        encoding="utf-8",
    ) as file:
        return json.load(file)


def is_variable_reference(value):
    return (
        isinstance(value, str)
        and value.strip().startswith("$")
        and len(value.strip()) > 1
    )


def is_textual_list(value):
    if not isinstance(value, str):
        return False

    text = value.strip()

    return (
        text.startswith("[")
        and text.endswith("]")
    )


def parse_textual_list(value):
    text = value.strip()

    if not is_textual_list(text):
        return None

    inner = text[1:-1].strip()

    if not inner:
        return []

    return [
        item.strip()
        for item in inner.split(",")
        if item.strip()
    ]


def normalize_scalar(value):
    if not isinstance(value, str):
        return value

    text = value.strip()

    try:
        return int(text)

    except ValueError:
        return text


def resolve_variable_reference(
    value,
    variables,
):
    if not is_variable_reference(value):
        return value, False

    variable_name = value.strip()[1:]

    if variable_name not in variables:
        return value, False

    return variables[variable_name], True


def flatten_value(value):
    if isinstance(value, list):
        flattened = []

        for item in value:
            flattened.extend(
                flatten_value(item)
            )

        return flattened

    return [value]


def resolve_list_value(
    value,
    variables,
):
    if isinstance(value, list):
        items = value

    elif is_textual_list(value):
        items = parse_textual_list(value)

    else:
        return value, False

    resolved_items = []
    changed = False

    for item in items:

        if is_variable_reference(item):
            resolved, item_changed = (
                resolve_variable_reference(
                    item,
                    variables,
                )
            )

            if item_changed:
                changed = True

                resolved_items.extend(
                    flatten_value(resolved)
                )
            else:
                resolved_items.append(item)

            continue

        if isinstance(item, list):
            nested, nested_changed = (
                resolve_list_value(
                    item,
                    variables,
                )
            )

            changed = (
                changed
                or nested_changed
            )

            resolved_items.extend(
                flatten_value(nested)
            )

            continue

        resolved_items.append(
            normalize_scalar(item)
        )

    return resolved_items, changed


def resolve_value(
    value,
    variables,
):
    if is_variable_reference(value):
        return resolve_variable_reference(
            value,
            variables,
        )

    if (
        isinstance(value, list)
        or is_textual_list(value)
    ):
        return resolve_list_value(
            value,
            variables,
        )

    return value, False


def resolve_rule_variables(
    rule,
    variables,
):
    """
    Resolve variables only where the parsed rule
    actually has traditional header fields.

    SERVICE rules intentionally have no source,
    direction or destination.
    """

    rule_type = rule.get(
        "rule_type",
        "TRADITIONAL",
    )

    resolved_rule = {
        "sid": rule.get("sid"),
        "action": rule.get("action"),
        "protocol": rule.get("protocol"),
        "rule_type": rule_type,
        "options": list(
            rule.get(
                "options",
                [],
            )
        ),
    }

    # Preserve service identifier if present.
    if "service" in rule:
        resolved_rule["service"] = (
            rule["service"]
        )

    resolution_log = []

    # --------------------------------------------
    # SERVICE rule
    # --------------------------------------------

    if rule_type == "SERVICE":
        resolved_rule["source"] = None
        resolved_rule["direction"] = None
        resolved_rule["destination"] = None

        return (
            resolved_rule,
            resolution_log,
        )

    # --------------------------------------------
    # TRADITIONAL rule
    # --------------------------------------------

    resolved_rule["source"] = {
        "address": (
            rule["source"]["address"]
        ),
        "port": (
            rule["source"]["port"]
        ),
    }

    resolved_rule["direction"] = (
        rule["direction"]
    )

    resolved_rule["destination"] = {
        "address": (
            rule["destination"]["address"]
        ),
        "port": (
            rule["destination"]["port"]
        ),
    }

    fields = [
        (
            "src_ip",
            "source",
            "address",
        ),
        (
            "src_port",
            "source",
            "port",
        ),
        (
            "dst_ip",
            "destination",
            "address",
        ),
        (
            "dst_port",
            "destination",
            "port",
        ),
    ]

    for (
        field_name,
        section,
        key,
    ) in fields:

        original = (
            resolved_rule[
                section
            ][
                key
            ]
        )

        resolved, changed = (
            resolve_value(
                original,
                variables,
            )
        )

        if changed:
            resolved_rule[
                section
            ][
                key
            ] = resolved

            resolution_log.append(
                {
                    "field": field_name,
                    "original": original,
                    "resolved": resolved,
                }
            )

    return (
        resolved_rule,
        resolution_log,
    )
from copy import deepcopy


SUPPORTED_L3_PROTOCOLS = {
    "tcp",
    "udp",
    "icmp",
}


HEADER_FIELDS_CURRENT_BACKEND = {
    "protocol",
    "src_ip",
    "src_port",
    "direction",
    "dst_ip",
    "dst_port",
    "flags",
}


HEADER_FIELDS_FUTURE_P4 = {
    "ttl",
    "id",
    "ip_proto",

    "seq",
    "ack",

    "itype",
    "icode",
    "icmp_id",
    "icmp_seq",

    "fragbits",
}


def is_variable(value):
    if value is None:
        return False

    return (
        isinstance(value, str)
        and value.strip().startswith("$")
    )


def is_any(value):
    if value is None:
        return False

    return (
        isinstance(value, str)
        and value.strip().lower() == "any"
    )


def is_python_list(value):
    return isinstance(
        value,
        list,
    )


def is_textual_list(value):
    if not isinstance(
        value,
        str,
    ):
        return False

    text = value.strip()

    return (
        text.startswith("[")
        and text.endswith("]")
    )


def is_list(value):
    return (
        is_python_list(value)
        or is_textual_list(value)
    )


def is_negated(value):
    if not isinstance(
        value,
        str,
    ):
        return False

    return value.strip().startswith("!")


def is_port_range(value):
    if value is None:
        return False

    if not isinstance(
        value,
        str,
    ):
        return False

    text = value.strip()

    return (
        ":" in text
        and not is_textual_list(text)
        and not is_variable(text)
    )


def is_exact_port(value):
    if value is None:
        return False

    if isinstance(
        value,
        int,
    ):
        return (
            0 <= value <= 65535
        )

    try:
        port = int(
            str(value).strip()
        )

        return (
            0 <= port <= 65535
        )

    except ValueError:
        return False


def is_ipv4_or_cidr(value):
    if value is None:
        return False

    if not isinstance(
        value,
        str,
    ):
        return False

    text = value.strip()

    if is_any(text):
        return False

    if is_variable(text):
        return False

    if is_textual_list(text):
        return False

    if is_negated(text):
        return False

    address_part = text.split(
        "/",
        1,
    )[0]

    parts = address_part.split(".")

    if len(parts) != 4:
        return False

    try:
        numbers = [
            int(part)
            for part in parts
        ]

    except ValueError:
        return False

    if not all(
        0 <= number <= 255
        for number in numbers
    ):
        return False

    if "/" in text:

        try:
            prefix = int(
                text.split(
                    "/",
                    1,
                )[1]
            )

        except ValueError:
            return False

        if not (
            0 <= prefix <= 32
        ):
            return False

    return True


def parse_textual_list(value):
    """
    Convert a simple textual Snort list:

        [80,443,8080]

    into:

        ["80", "443", "8080"]

    This is intentionally conservative. Nested lists or
    more complex Snort expressions are left as raw items
    and assessed individually.
    """

    text = value.strip()

    if not (
        text.startswith("[")
        and text.endswith("]")
    ):
        return None

    inner = text[
        1:-1
    ].strip()

    if not inner:
        return []

    return [
        item.strip()
        for item in inner.split(",")
        if item.strip()
    ]


def normalize_list_items(value):
    """
    Return list items from either:

        Python list:
            [80, 8080]

    or textual Snort list:
            "[80,8080]"
    """

    if is_python_list(value):
        return value

    if is_textual_list(value):
        return parse_textual_list(
            value
        )

    return None


def assess_protocol(predicate):
    value = str(
        predicate.value
    ).strip().lower()

    if value in SUPPORTED_L3_PROTOCOLS:
        return (
            "PRESERVED",
            "supported_ip_protocol",
        )

    if value == "ip":
        return (
            "PRESERVED",
            "protocol_wildcard",
        )

    return (
        "DELEGATED",
        "application_or_unsupported_protocol",
    )


def assess_ip_list(value):
    items = normalize_list_items(
        value
    )

    if items is None:
        return (
            "FALLBACK",
            "invalid_address_list",
        )

    if not items:
        return (
            "FALLBACK",
            "empty_address_list",
        )

    for item in items:

        if is_negated(item):
            return (
                "FALLBACK",
                "address_list_contains_negation",
            )

        if is_variable(item):
            return (
                "UNASSESSED",
                "address_list_contains_variable",
            )

        if not is_ipv4_or_cidr(
            item
        ):
            return (
                "FALLBACK",
                "address_list_contains_unsupported_element",
            )

    return (
        "EXPANDED",
        "address_list_requires_expansion",
    )


def assess_ip(predicate):
    value = predicate.value

    if is_any(value):
        return (
            "PRESERVED",
            "wildcard",
        )

    if is_variable(value):
        return (
            "UNASSESSED",
            "requires_variable_resolution",
        )

    if is_negated(value):
        return (
            "FALLBACK",
            "negated_address_not_supported",
        )

    if is_list(value):
        return assess_ip_list(
            value
        )

    if is_ipv4_or_cidr(value):
        return (
            "PRESERVED",
            "ipv4_or_cidr_supported",
        )

    return (
        "FALLBACK",
        "unsupported_address_expression",
    )


def assess_port_list(value):
    """
    A list is EXPANDED only if every element is an exact
    supported port.

    Examples:

        [80,443]
            -> EXPANDED

        [135,139,445,593,1024:]
            -> FALLBACK

        [80,!443]
            -> FALLBACK
    """

    items = normalize_list_items(
        value
    )

    if items is None:
        return (
            "FALLBACK",
            "invalid_port_list",
        )

    if not items:
        return (
            "FALLBACK",
            "empty_port_list",
        )

    for item in items:

        if is_variable(item):
            return (
                "UNASSESSED",
                "port_list_contains_variable",
            )

        if is_negated(item):
            return (
                "FALLBACK",
                "port_list_contains_negation",
            )

        if is_port_range(item):
            return (
                "FALLBACK",
                "port_list_contains_range",
            )

        if not is_exact_port(item):
            return (
                "FALLBACK",
                "port_list_contains_unsupported_element",
            )

    return (
        "EXPANDED",
        "port_list_requires_expansion",
    )


def assess_port(predicate):
    value = predicate.value

    if is_any(value):
        return (
            "PRESERVED",
            "wildcard",
        )

    if is_variable(value):
        return (
            "UNASSESSED",
            "requires_variable_resolution",
        )

    if is_negated(value):
        return (
            "FALLBACK",
            "negated_port_not_supported",
        )

    if is_list(value):
        return assess_port_list(
            value
        )

    if is_port_range(value):
        return (
            "FALLBACK",
            "port_range_not_supported",
        )

    if is_exact_port(value):
        return (
            "PRESERVED",
            "exact_port_supported",
        )

    return (
        "FALLBACK",
        "unsupported_port_expression",
    )


def assess_direction(predicate):
    value = str(
        predicate.value
    ).strip()

    if value == "->":
        return (
            "PRESERVED",
            "forward_direction_supported",
        )

    if value == "<>":
        return (
            "EXPANDED",
            "bidirectional_requires_expansion",
        )

    return (
        "FALLBACK",
        "unsupported_direction",
    )


def assess_flags(predicate):
    """
    Current backend has partial TCP flags support.

    Simple forms are passed to the backend normalizer.
    Historical/unknown encodings containing digits are
    conservatively sent to fallback.
    """

    value = str(
        predicate.value
    ).strip()

    if any(
        character.isdigit()
        for character in value
    ):
        return (
            "FALLBACK",
            "unsupported_flags_encoding",
        )

    return (
        "PRESERVED",
        "flags_supported_by_backend_normalizer",
    )


def assess_future_header(predicate):
    """
    These fields are semantically suitable for P4, but
    are not implemented in the current backend.
    """

    return (
        "DELEGATED",
        "p4_candidate_not_implemented_in_current_backend",
    )


def assess_header_predicate(predicate):
    field = predicate.field

    if field == "protocol":
        return assess_protocol(
            predicate
        )

    if field in {
        "src_ip",
        "dst_ip",
    }:
        return assess_ip(
            predicate
        )

    if field in {
        "src_port",
        "dst_port",
    }:
        return assess_port(
            predicate
        )

    if field == "direction":
        return assess_direction(
            predicate
        )

    if field == "flags":
        return assess_flags(
            predicate
        )

    if field in HEADER_FIELDS_FUTURE_P4:
        return assess_future_header(
            predicate
        )

    return (
        "DELEGATED",
        "header_field_not_supported_by_current_backend",
    )


# Header fields Snort 3 stops checking on a service-based rule once the
# flow's identified service is one of the rule's services. Snort 3.12.2.0:
# src/detection/detection_options.cc sets check_ports = 0 on a service match;
# src/detection/rtn_checks.cc then skips CheckSrcPort*/CheckDstPort* and
# returns early from CheckProto, while CheckSrcIP/CheckDstIP always run.
# Documented at docs/vendor/snort3/doc/user/concepts.txt:290.
SERVICE_SKIPPED_HEADER_FIELDS = {
    "protocol",
    "src_port",
    "dst_port",
}

# "snort3" (the default since 2026-10-05) follows Snort 3's evaluation and
# delegates the fields above. "legacy" assesses the header of a
# service-based rule like a port-based one; it reproduces the artifacts
# archived in output/historical/legacy_header_semantics/. See
# paper/IDS_P4/SERVICE_BASED_HEADER_FINDING.md and
# paper/IDS_P4/HEADER_SEMANTICS_DEFAULT_SUPERSESSION.md.
SERVICE_HEADER_SEMANTICS = (
    "legacy",
    "snort3",
)


# Header protocols Snort 3 treats as IP protocols. Any other name is a
# service protocol: src/parser/parse_rule.cc adds it to the rule's services
# and SetupRTNFuncList marks the rule USER_MODE, for which fp_eval_rtn
# (src/detection/fp_detect.cc) forces check_ports = 1, so the header stays
# checked in full.
IP_HEADER_PROTOCOLS = {
    "ip",
    "tcp",
    "udp",
    "icmp",
}

# Snort 3 also adds services to a rule that has no `service` option, in
# validate_services (Snort 3.12.2.0, src/detection/fp_utils.cc). An option
# that sets a buffer registered by an inspector adds that inspector's
# services; the buffer map is loaded from every inspector plugin, configured
# or not (InspectorManager::load_buffer_map, src/managers/inspector_manager.cc).
# Any other option adds the service guess_service derives from its name
# prefix, listed here as in the source.
SNORT3_GUESSED_SERVICE_PREFIXES = (
    "http_",
    "cip_",
    "enip_",
    "dce_",
    "dnp3_",
    "gtp_",
    "mms_",
    "modbus_",
    "s7commplus_",
    "sip_",
    "socks_",
    "ssl_",
)

# Buffers an inspector registers. Confirmed in the source: dce_tcp and
# dce_udp (service dcerpc) and dce_smb (netbios-ssn) register dce_iface,
# dce_stub_data and file_data. The rest are options the corpus calls
# service-specific (docs/vendor/snort3/doc/user/concepts.txt:293) whose
# registration was not traced; counting a rule as service-based only
# broadens its predicate.
SNORT3_SERVICE_BUFFERS = {
    "dce_iface",
    "dce_stub_data",
    "file_data",
    "js_data",
    "vba_data",
    "script_data",
}


def rule_services(semantic_rule):
    return [
        predicate.value
        for predicate in semantic_rule.predicates
        if predicate.kind == "APPLICATION"
        and predicate.source_option == "service"
    ]


def header_names_service(semantic_rule):
    return any(
        predicate.kind == "HEADER"
        and predicate.field == "protocol"
        and str(predicate.value).lower() not in IP_HEADER_PROTOCOLS
        for predicate in semantic_rule.predicates
    )


def implied_service_options(semantic_rule):
    """Options through which Snort 3 adds a service to the rule.

    A buffer-setting option with one of the guessed prefixes that no
    inspector registers would add nothing in Snort; it is counted anyway,
    which errs toward delegating.
    """

    return sorted(
        {
            predicate.source_option
            for predicate in semantic_rule.predicates
            if predicate.source_option
            and (
                predicate.source_option in SNORT3_SERVICE_BUFFERS
                or predicate.source_option.startswith(
                    SNORT3_GUESSED_SERVICE_PREFIXES
                )
            )
        }
    )


def snort3_service_based(semantic_rule):
    """True when a service match makes Snort 3 skip this rule's header ports
    and protocol: the rule has a service, from `service` or implied by an
    option, and its header names an IP protocol."""

    if header_names_service(semantic_rule):
        return False
    return bool(
        rule_services(semantic_rule)
        or implied_service_options(semantic_rule)
    )


def service_skipped_fields(semantic_rule):
    """Header fields a service match makes Snort 3 skip for this rule.

    The TCP flags option returns NO_MATCH on a packet without a TCP header
    (Snort 3.12.2.0, src/ips_options/ips_flags.cc, TcpFlagOption::eval), so a
    rule carrying `flags` can only alert on TCP and its protocol stays a
    necessary condition even when the header check is skipped.
    """

    skipped = set(SERVICE_SKIPPED_HEADER_FIELDS)
    if any(
        predicate.kind == "HEADER" and predicate.field == "flags"
        for predicate in semantic_rule.predicates
    ):
        skipped.discard("protocol")
    return skipped


def assess_rule(
    semantic_rule,
    service_header_semantics="snort3",
):
    """
    Return a deep copy of the semantic rule with
    backend treatments assigned to UNASSESSED
    header predicates.

    The original semantic IR remains target-neutral.
    """

    if service_header_semantics not in SERVICE_HEADER_SEMANTICS:
        raise ValueError(
            f"unknown service_header_semantics: {service_header_semantics}"
        )

    assessed_rule = deepcopy(
        semantic_rule
    )

    reasons = []

    service_based = (
        service_header_semantics == "snort3"
        and snort3_service_based(assessed_rule)
    )
    skipped_fields = (
        service_skipped_fields(assessed_rule)
        if service_based
        else set()
    )

    for predicate in (
        assessed_rule.predicates
    ):

        if predicate.kind != "HEADER":
            continue

        if (
            predicate.backend_treatment
            != "UNASSESSED"
        ):
            continue

        if predicate.field in skipped_fields:
            treatment, reason = (
                "DELEGATED",
                "service_based_header_not_checked_on_service_match",
            )
        else:
            treatment, reason = (
                assess_header_predicate(
                    predicate
                )
            )

        predicate.backend_treatment = (
            treatment
        )

        reasons.append(
            {
                "field": predicate.field,
                "value": predicate.value,
                "treatment": treatment,
                "reason": reason,
            }
        )

    return assessed_rule, reasons
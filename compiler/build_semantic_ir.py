from semantic_ir import (
    SemanticRuleIR,
    make_application_predicate,
    make_buffer_predicate,
    make_flow_predicate,
    make_header_predicate,
    make_metadata_predicate,
    make_payload_predicate,
    make_post_detection_predicate,
    make_temporal_predicate,
)

from option_normalizer import normalize_content


# ============================================================
# Option categories
# ============================================================


METADATA_OPTIONS = {
    "msg",
    "sid",
    "gid",
    "rev",
    "reference",
    "metadata",
    "classtype",
    "priority",
    "rem",
}


# ------------------------------------------------------------
# Sticky / inspection buffers
# ------------------------------------------------------------

BUFFER_OPTIONS = {
    "pkt_data",
    "raw_data",
    "file_data",
    "js_data",
    "vba_data",
    "base64_data",

    "http_uri",
    "http_raw_uri",

    "http_header",
    "http_raw_header",

    "http_cookie",
    "http_raw_cookie",

    "http_client_body",
    "http_raw_body",

    "http_param",

    "http_method",

    "http_version",

    "http_stat_code",
    "http_stat_msg",

    "http_trailer",
    "http_raw_trailer",
}


# ------------------------------------------------------------
# DCE / RPC application semantics
# ------------------------------------------------------------

DCE_OPTIONS = {
    "dce_iface",
    "dce_opnum",
    "dce_stub_data",
}


# ------------------------------------------------------------
# SIP application semantics
# ------------------------------------------------------------

SIP_OPTIONS = {
    "sip_method",
    "sip_stat_code",
    "sip_header",
}


# ------------------------------------------------------------
# BER / ASN.1 payload semantics
# ------------------------------------------------------------

BER_OPTIONS = {
    "ber_skip",
    "ber_data",
}


# ------------------------------------------------------------
# Payload semantics
# ------------------------------------------------------------

PAYLOAD_OPTIONS = {
    "content",

    "pcre",
    "regex",

    "isdataat",
    "dsize",

    "byte_extract",
    "byte_test",
    "byte_math",
    "byte_jump",

    "base64_decode",

    "bufferlen",

    # Explicit BER / ASN.1 payload operations.
    *BER_OPTIONS,
}


# ------------------------------------------------------------
# Flow / state
# ------------------------------------------------------------

FLOW_OPTIONS = {
    "flow",
    "flowbits",

    "stream_reassemble",
    "stream_size",
}


# ------------------------------------------------------------
# Temporal
# ------------------------------------------------------------

TEMPORAL_OPTIONS = {
    "detection_filter",
}


# ------------------------------------------------------------
# Post-detection
# ------------------------------------------------------------

POST_DETECTION_OPTIONS = {
    "replace",
    "tag",
}


# ------------------------------------------------------------
# Application / protocol semantics
# ------------------------------------------------------------

APPLICATION_OPTIONS = {
    "service",

    "file_type",

    "ssl_state",
    "ssl_version",

    "rpc",

    # Explicit DCE / RPC semantics.
    *DCE_OPTIONS,

    # Explicit SIP semantics.
    *SIP_OPTIONS,
}


# ------------------------------------------------------------
# Non-payload packet-header options
# ------------------------------------------------------------

HEADER_NON_PAYLOAD_OPTIONS = {
    "flags",

    "ttl",
    "tos",
    "id",

    "fragoffset",
    "fragbits",

    "ip_proto",

    "seq",
    "ack",
    "window",

    "itype",
    "icode",

    "icmp_id",
    "icmp_seq",
}


# ============================================================
# Option representation normalization
# ============================================================


def normalize_options(options):
    """
    Convert parser options into an ordered list of
    (name, value) pairs.

    Duplicates are intentionally preserved.

    Option order is semantically important in Snort,
    especially for sticky buffers and cursor-dependent
    payload operations.
    """

    normalized = []

    if options is None:
        return normalized

    # --------------------------------------------------------
    # Dictionary representation
    # --------------------------------------------------------

    if isinstance(options, dict):

        for name, value in options.items():

            normalized.append(
                (
                    str(name),
                    value,
                )
            )

        return normalized

    # --------------------------------------------------------
    # List representation
    # --------------------------------------------------------

    if isinstance(options, list):

        for item in options:

            # ------------------------------------------------
            # Current parser representation:
            #
            # {
            #     "name": "content",
            #     "value": "..."
            # }
            # ------------------------------------------------

            if isinstance(item, dict):

                if "name" in item:

                    normalized.append(
                        (
                            str(item["name"]),
                            item.get("value"),
                        )
                    )

                    continue

                if "option" in item:

                    normalized.append(
                        (
                            str(item["option"]),
                            item.get("value"),
                        )
                    )

                    continue

                if "key" in item:

                    normalized.append(
                        (
                            str(item["key"]),
                            item.get("value"),
                        )
                    )

                    continue

                if len(item) == 1:

                    name, value = next(
                        iter(item.items())
                    )

                    normalized.append(
                        (
                            str(name),
                            value,
                        )
                    )

                    continue

                raise ValueError(
                    "Unknown option dictionary format: "
                    f"{item}"
                )

            # ------------------------------------------------
            # Tuple / list representation
            # ------------------------------------------------

            if isinstance(
                item,
                (tuple, list),
            ):

                if len(item) >= 2:

                    normalized.append(
                        (
                            str(item[0]),
                            item[1],
                        )
                    )

                    continue

                if len(item) == 1:

                    normalized.append(
                        (
                            str(item[0]),
                            None,
                        )
                    )

                    continue

            # ------------------------------------------------
            # Raw textual representation
            # ------------------------------------------------

            if isinstance(item, str):

                text = item.strip()

                if ":" in text:

                    name, value = text.split(
                        ":",
                        1,
                    )

                    normalized.append(
                        (
                            name.strip(),
                            value.strip(),
                        )
                    )

                else:

                    normalized.append(
                        (
                            text,
                            None,
                        )
                    )

                continue

            raise ValueError(
                "Unknown option representation: "
                f"{repr(item)}"
            )

        return normalized

    raise ValueError(
        "Unsupported options container: "
        f"{type(options).__name__}"
    )


# ============================================================
# Parser compatibility layer
# ============================================================


def get_source(parsed_rule):
    """
    Support traditional parsed rules and legacy/unit-test
    representations.

    SERVICE rules intentionally return None-valued source
    fields instead of fabricated packet-header semantics.
    """

    source = parsed_rule.get(
        "source"
    )

    if isinstance(
        source,
        dict,
    ):

        return {
            "address": source.get(
                "address"
            ),

            "port": source.get(
                "port"
            ),
        }

    return {
        "address": parsed_rule.get(
            "src_ip"
        ),

        "port": parsed_rule.get(
            "src_port"
        ),
    }


def get_destination(parsed_rule):
    """
    Support traditional parsed rules and legacy/unit-test
    representations.

    SERVICE rules intentionally return None-valued
    destination fields.
    """

    destination = parsed_rule.get(
        "destination"
    )

    if isinstance(
        destination,
        dict,
    ):

        return {
            "address": destination.get(
                "address"
            ),

            "port": destination.get(
                "port"
            ),
        }

    return {
        "address": parsed_rule.get(
            "dst_ip"
        ),

        "port": parsed_rule.get(
            "dst_port"
        ),
    }


# ============================================================
# Rule type
# ============================================================


def infer_rule_type(parsed_rule):
    """
    Determine the high-level Snort rule type.

    Current semantic categories:

        TRADITIONAL
        SERVICE
        FILE
        FILE_ID
    """

    explicit_type = parsed_rule.get(
        "rule_type"
    )

    if explicit_type:

        return str(
            explicit_type
        ).upper()

    protocol = str(
        parsed_rule.get(
            "protocol",
            "",
        )
    ).lower()

    if protocol == "file":
        return "FILE"

    if protocol == "file_id":
        return "FILE_ID"

    # --------------------------------------------------------
    # Current traditional parser representation
    # --------------------------------------------------------

    source = parsed_rule.get(
        "source"
    )

    destination = parsed_rule.get(
        "destination"
    )

    if (
        isinstance(source, dict)
        and isinstance(destination, dict)
    ):
        return "TRADITIONAL"

    # --------------------------------------------------------
    # Legacy / test representation
    # --------------------------------------------------------

    flat_header_fields = {
        "src_ip",
        "src_port",
        "dst_ip",
        "dst_port",
        "direction",
    }

    if any(
        field in parsed_rule
        for field in flat_header_fields
    ):
        return "TRADITIONAL"

    return "SERVICE"


# ============================================================
# Traditional header semantics
# ============================================================


def add_traditional_header_predicates(
    parsed_rule,
    predicates,
):
    """
    Add traditional Snort packet-header predicates.

    No backend capability decision is made at this layer.

    Packet-header predicates therefore begin as
    UNASSESSED and are later evaluated by the target
    capability analyzer.
    """

    protocol = parsed_rule.get(
        "protocol"
    )

    if protocol is not None:

        predicates.append(
            make_header_predicate(
                field="protocol",

                operator="exact",

                value=protocol,

                backend_treatment="UNASSESSED",
            )
        )

    source = get_source(
        parsed_rule
    )

    destination = get_destination(
        parsed_rule
    )

    src_ip = source.get(
        "address"
    )

    src_port = source.get(
        "port"
    )

    dst_ip = destination.get(
        "address"
    )

    dst_port = destination.get(
        "port"
    )

    direction = parsed_rule.get(
        "direction"
    )

    if src_ip is not None:

        predicates.append(
            make_header_predicate(
                field="src_ip",

                operator="raw",

                value=src_ip,

                backend_treatment="UNASSESSED",
            )
        )

    if src_port is not None:

        predicates.append(
            make_header_predicate(
                field="src_port",

                operator="raw",

                value=src_port,

                backend_treatment="UNASSESSED",
            )
        )

    if direction is not None:

        predicates.append(
            make_header_predicate(
                field="direction",

                operator="raw",

                value=direction,

                backend_treatment="UNASSESSED",
            )
        )

    if dst_ip is not None:

        predicates.append(
            make_header_predicate(
                field="dst_ip",

                operator="raw",

                value=dst_ip,

                backend_treatment="UNASSESSED",
            )
        )

    if dst_port is not None:

        predicates.append(
            make_header_predicate(
                field="dst_port",

                operator="raw",

                value=dst_port,

                backend_treatment="UNASSESSED",
            )
        )


# ============================================================
# Service-rule header semantics
# ============================================================


def add_service_header_predicate(
    parsed_rule,
    predicates,
):
    """
    Represent Snort 3 service-oriented rule headers.

    Examples:

        alert http (...)
        alert ssl (...)

    The service token is NOT treated as an IPv4/L4
    protocol field.

    It is represented as application semantics and is
    delegated to Snort in the current target backend.
    """

    service = parsed_rule.get(
        "service"
    )

    if service is None:

        service = parsed_rule.get(
            "protocol"
        )

    if service is None:
        return

    predicates.append(
        make_application_predicate(
            operator="service_header",

            value=service,

            source_option="service_header",

            source_index=-1,
        )
    )


def add_rule_header_semantics(
    parsed_rule,
    predicates,
):
    """
    Dispatch header semantics according to the high-level
    rule type.

    SERVICE rules intentionally do not receive invented
    source/destination packet-header predicates.
    """

    rule_type = infer_rule_type(
        parsed_rule
    )

    if rule_type == "TRADITIONAL":

        add_traditional_header_predicates(
            parsed_rule,
            predicates,
        )

        return

    if rule_type == "SERVICE":

        add_service_header_predicate(
            parsed_rule,
            predicates,
        )

        return

    # FILE / FILE_ID and future non-traditional rule types:
    #
    # Do not fabricate traditional packet headers.
    #
    # Their semantics can be modeled explicitly when
    # support for those rule classes is introduced.


# ============================================================
# Option classification
# ============================================================


def classify_option(
    option_name,
    option_value,
    source_index,
):
    """
    Convert one normalized Snort option into a semantic
    predicate.

    This stage classifies semantics, but does not decide
    whether a target P4 backend can represent them.
    """

    option_name = str(
        option_name
    ).strip().lower()

    # --------------------------------------------------------
    # Metadata
    # --------------------------------------------------------

    if option_name in METADATA_OPTIONS:

        return make_metadata_predicate(
            operator=option_name,

            value=option_value,

            source_option=option_name,

            source_index=source_index,
        )

    # --------------------------------------------------------
    # Inspection / sticky buffer
    # --------------------------------------------------------

    if option_name in BUFFER_OPTIONS:

        return make_buffer_predicate(
            operator=option_name,

            value=option_value,

            source_option=option_name,

            source_index=source_index,
        )

    # --------------------------------------------------------
    # Payload
    # --------------------------------------------------------

    if option_name in PAYLOAD_OPTIONS:

        # ----------------------------------------------------
        # CONTENT receives its own normalizer because pattern
        # negation and modifiers carry structured semantics.
        # ----------------------------------------------------

        if option_name == "content":

            normalized_content = (
                normalize_content(
                    str(option_value)
                )
            )

            return make_payload_predicate(
                operator="content",

                value={
                    "pattern": (
                        normalized_content[
                            "pattern"
                        ]
                    ),

                    "negated": (
                        normalized_content[
                            "negated"
                        ]
                    ),
                },

                modifiers=(
                    normalized_content[
                        "modifiers"
                    ]
                ),

                source_option="content",

                source_index=source_index,

                backend_treatment="DELEGATED",
            )

        # BER/ASN.1, PCRE, byte operations, etc. remain
        # delegated to Snort but are explicitly represented
        # as payload semantics.

        return make_payload_predicate(
            operator=option_name,

            value=option_value,

            source_option=option_name,

            source_index=source_index,

            backend_treatment="DELEGATED",
        )

    # --------------------------------------------------------
    # Flow / state
    # --------------------------------------------------------

    if option_name in FLOW_OPTIONS:

        return make_flow_predicate(
            operator=option_name,

            value=option_value,

            source_option=option_name,

            source_index=source_index,
        )

    # --------------------------------------------------------
    # Temporal
    # --------------------------------------------------------

    if option_name in TEMPORAL_OPTIONS:

        return make_temporal_predicate(
            operator=option_name,

            value=option_value,

            source_option=option_name,

            source_index=source_index,
        )

    # --------------------------------------------------------
    # Post-detection
    # --------------------------------------------------------

    if option_name in POST_DETECTION_OPTIONS:

        return make_post_detection_predicate(
            operator=option_name,

            value=option_value,

            source_option=option_name,

            source_index=source_index,
        )

    # --------------------------------------------------------
    # Application / protocol semantics
    #
    # Includes:
    #   service
    #   SSL
    #   RPC
    #   DCE
    #   SIP
    # --------------------------------------------------------

    if option_name in APPLICATION_OPTIONS:

        return make_application_predicate(
            operator=option_name,

            value=option_value,

            source_option=option_name,

            source_index=source_index,
        )

    # --------------------------------------------------------
    # Header-level non-payload options
    #
    # Their semantics are recognized, but representability
    # in P4 is intentionally deferred to the target
    # capability analyzer.
    # --------------------------------------------------------

    if option_name in HEADER_NON_PAYLOAD_OPTIONS:

        return make_header_predicate(
            field=option_name,

            operator="option",

            value=option_value,

            backend_treatment="UNASSESSED",

            source_option=option_name,

            source_index=source_index,
        )

    # --------------------------------------------------------
    # Unknown / not explicitly categorized
    #
    # Never silently discard a Snort option.
    #
    # Unknown semantics remain visible in the IR and are
    # conservatively delegated to Snort.
    # --------------------------------------------------------

    return make_application_predicate(
        operator=option_name,

        value=option_value,

        source_option=option_name,

        source_index=source_index,
    )


# ============================================================
# Semantic IR builder
# ============================================================


def build_semantic_ir(
    parsed_rule
):
    """
    Build target-neutral semantic IR from one parsed Snort
    rule.

    Processing order:

        parsed rule
            ↓
        rule-type semantics
            ↓
        ordered options
            ↓
        sticky-buffer tracking
            ↓
        structured semantic predicates

    Backend capability decisions are intentionally performed
    later by the target capability analyzer.
    """

    predicates = []

    rule_type = infer_rule_type(
        parsed_rule
    )

    # --------------------------------------------------------
    # Header / service semantics
    # --------------------------------------------------------

    add_rule_header_semantics(
        parsed_rule,
        predicates,
    )

    # --------------------------------------------------------
    # Ordered Snort options
    # --------------------------------------------------------

    raw_options = parsed_rule.get(
        "options",
        [],
    )

    options = normalize_options(
        raw_options
    )

    metadata = {}

    rule_id = parsed_rule.get(
        "sid"
    )

    # --------------------------------------------------------
    # Sticky-buffer context
    #
    # Snort options are order-sensitive.
    #
    # A sticky-buffer selector changes the inspection buffer
    # associated with subsequent payload predicates until
    # another selector changes that context.
    # --------------------------------------------------------

    current_buffer = "default"

    for source_index, (
        option_name,
        option_value,
    ) in enumerate(options):

        normalized_name = str(
            option_name
        ).strip().lower()

        # ----------------------------------------------------
        # Update active sticky buffer BEFORE classifying
        # subsequent payload semantics.
        # ----------------------------------------------------

        if normalized_name in BUFFER_OPTIONS:

            current_buffer = (
                normalized_name
            )

        # ----------------------------------------------------
        # Create semantic predicate
        # ----------------------------------------------------

        predicate = classify_option(
            option_name,
            option_value,
            source_index,
        )

        # ----------------------------------------------------
        # Associate payload semantics with the active
        # inspection buffer.
        #
        # This includes content, pcre, byte operations and
        # BER operations.
        # ----------------------------------------------------

        if predicate.kind == "PAYLOAD":

            predicate.buffer = (
                current_buffer
            )

        predicates.append(
            predicate
        )

        # ----------------------------------------------------
        # Metadata copy
        # ----------------------------------------------------

        if normalized_name in METADATA_OPTIONS:

            if normalized_name in metadata:

                current_value = metadata[
                    normalized_name
                ]

                if not isinstance(
                    current_value,
                    list,
                ):

                    current_value = [
                        current_value
                    ]

                current_value.append(
                    option_value
                )

                metadata[
                    normalized_name
                ] = current_value

            else:

                metadata[
                    normalized_name
                ] = option_value

        # ----------------------------------------------------
        # SID
        # ----------------------------------------------------

        if normalized_name == "sid":

            rule_id = option_value

    # --------------------------------------------------------
    # Preserve parser-level SERVICE information for audit
    # and manifest generation.
    # --------------------------------------------------------

    if rule_type == "SERVICE":

        service = parsed_rule.get(
            "service"
        )

        if service is None:

            service = parsed_rule.get(
                "protocol"
            )

        metadata[
            "_service_header"
        ] = service

    # --------------------------------------------------------
    # Final semantic rule
    # --------------------------------------------------------

    return SemanticRuleIR(
        rule_id=rule_id,

        action=parsed_rule.get(
            "action",
            "unknown",
        ),

        rule_type=rule_type,

        raw_rule=parsed_rule.get(
            "raw_rule"
        ),

        predicates=predicates,

        metadata=metadata,
    )
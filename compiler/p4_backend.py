import backend_fields


PROTOCOL_MAP = {
    "icmp": 1,
    "tcp": 6,
    "udp": 17,
}


# ============================================================
# Supported backend fields
# ============================================================


MATCH_FIELDS = {
    "protocol",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "flags",
}


STRUCTURAL_FIELDS = {
    "direction",
}


# ============================================================
# Basic normalization
# ============================================================


def normalize_protocol(value):
    """
    Convert a Snort protocol name to the IPv4 protocol number
    expected by the current P4 backend.

    'ip' means no L4 protocol restriction and therefore does
    not generate a protocol match.

    Unknown / application-level protocol names are omitted
    from the P4 predicate. Their semantics remain delegated
    to Snort through the semantic manifest.
    """

    if value is None:
        return None

    value = str(
        value
    ).strip().lower()

    if value in {
        "",
        "any",
        "ip",
    }:
        return None

    return PROTOCOL_MAP.get(
        value
    )


def is_wildcard(value):
    """
    Return True when a semantic value means unrestricted
    matching for the current backend.
    """

    if value is None:
        return True

    if isinstance(value, str):

        normalized = (
            value.strip().lower()
        )

        return normalized in {
            "",
            "any",
            "ip",
        }

    return False


# ============================================================
# Predicate extraction
# ============================================================


def get_backend_predicates(
    rule_manifest
):
    """
    Return predicates that the capability analysis explicitly
    marked as representable by the current backend.

    PRESERVED:
        Directly representable.

    EXPANDED:
        Representable after finite expansion, which is handled
        by the next backend stage.

    DELEGATED and FALLBACK predicates are intentionally not
    emitted into the P4 match.
    """

    predicates = []

    for treatment in (
        "preserved",
        "expanded",
    ):

        for predicate in rule_manifest.get(
            treatment,
            [],
        ):

            copied = dict(
                predicate
            )

            copied[
                "_manifest_treatment"
            ] = treatment.upper()

            predicates.append(
                copied
            )

    return predicates


def get_backend_field_map(
    rule_manifest
):
    """
    Convert backend-representable predicates into a map keyed
    by semantic header field.

    Example:

        {
            "protocol": {
                "value": "tcp",
                "treatment": "PRESERVED"
            },

            "dst_port": {
                "value": [80, 8080],
                "treatment": "EXPANDED"
            }
        }

    The map deliberately preserves the treatment because the
    expansion stage must know which values came from explicit
    semantic expansion.
    """

    fields = {}

    collisions = []

    for predicate in get_backend_predicates(
        rule_manifest
    ):

        if predicate.get(
            "kind"
        ) != "HEADER":
            continue

        field = predicate.get(
            "field"
        )

        if field is None:
            continue

        field = str(
            field
        ).strip().lower()

        if (
            field not in MATCH_FIELDS
            and
            field not in STRUCTURAL_FIELDS
        ):
            continue

        if field in fields:

            # O mesmo campo aparece mais de uma vez na regra. Manter apenas
            # uma das condicoes conjuntas continua sendo uma relaxacao
            # segura (A e B implica B), mas ate aqui isso acontecia em
            # silencio absoluto: sem contador, sem aviso, sem campo de
            # falha. A colisao passa a ser registrada na entrada.
            collisions.append(
                {
                    "field": field,
                    "kept": predicate.get(
                        "value"
                    ),
                    "discarded": fields[field].get(
                        "value"
                    ),
                }
            )

        fields[field] = {
            "value": predicate.get(
                "value"
            ),

            "operator": predicate.get(
                "operator"
            ),

            "treatment": predicate.get(
                "_manifest_treatment"
            ),

            "source_option": predicate.get(
                "source_option"
            ),

            "source_index": predicate.get(
                "source_index"
            ),
        }

    # Devolve tambem as colisoes para que build_p4_entry possa registra-las
    # na entrada. Antes, o mesmo campo aparecendo duas vezes era
    # sobrescrito sem deixar rastro nenhum.
    return fields, collisions


# ============================================================
# Match construction
# ============================================================


def add_protocol_match(
    match,
    field_info,
):
    if field_info is None:
        return

    value = field_info.get(
        "value"
    )

    protocol_number = (
        normalize_protocol(
            value
        )
    )

    if protocol_number is None:
        return

    match[
        "protocol"
    ] = protocol_number


def add_value_match(
    match,
    output_name,
    field_info,
):
    """
    Add one ordinary backend field.

    Lists are intentionally preserved here. Finite list
    expansion belongs to expand_p4_entries.py, not to this
    adapter.
    """

    if field_info is None:
        return

    value = field_info.get(
        "value"
    )

    if is_wildcard(
        value
    ):
        return

    match[
        output_name
    ] = value


def add_flags_match(
    match,
    field_info,
):
    if field_info is None:
        return

    value = field_info.get(
        "value"
    )

    if is_wildcard(
        value
    ):
        return

    match[
        "tcp_flags"
    ] = value


# ============================================================
# Main backend adapter
# ============================================================


def build_p4_entry(
    rule_manifest
):
    """
    Convert one rule from semantic_manifest.json into an
    intermediate P4 backend entry.

    IMPORTANT:

    This function does NOT reinterpret Snort syntax.

    It consumes only decisions already made by:

        parser
            ->
        semantic IR
            ->
        target capability analysis
            ->
        semantic classification
            ->
        semantic manifest

    Only semantic prefilter candidates are emitted.

    DELEGATED predicates remain with Snort.

    FALLBACK predicates are deliberately omitted from the
    prefilter predicate.

    EXPANDED predicates remain explicit so the next stage can
    materialize their finite alternatives.
    """

    if not rule_manifest.get(
        "prefilter_candidate",
        False,
    ):
        return None

    classification = (
        rule_manifest.get(
            "classification"
        )
    )

    if classification not in {
        "EXACT",
        "NECESSARY",
    }:
        return None

    fields, collisions = get_backend_field_map(
        rule_manifest
    )

    match = {}

    # --------------------------------------------------------
    # Protocol
    # --------------------------------------------------------

    add_protocol_match(
        match,
        fields.get(
            "protocol"
        ),
    )

    # --------------------------------------------------------
    # IPv4 addresses
    # --------------------------------------------------------

    add_value_match(
        match,
        "src_ip",
        fields.get(
            "src_ip"
        ),
    )

    add_value_match(
        match,
        "dst_ip",
        fields.get(
            "dst_ip"
        ),
    )

    # --------------------------------------------------------
    # L4 ports
    # --------------------------------------------------------

    add_value_match(
        match,
        "src_port",
        fields.get(
            "src_port"
        ),
    )

    add_value_match(
        match,
        "dst_port",
        fields.get(
            "dst_port"
        ),
    )

    # --------------------------------------------------------
    # TCP flags
    # --------------------------------------------------------

    add_flags_match(
        match,
        fields.get(
            "flags"
        ),
    )

    # --------------------------------------------------------
    # Direction
    #
    # '->' is already represented by src/dst orientation and
    # requires no table field.
    #
    # '<>' is structural semantics. It must be retained so the
    # expansion stage can generate both orientations.
    # --------------------------------------------------------

    direction = None

    direction_info = fields.get(
        "direction"
    )

    if direction_info is not None:

        direction = (
            direction_info.get(
                "value"
            )
        )

    # --------------------------------------------------------
    # Audit information
    # --------------------------------------------------------

    expansion_fields = []

    for field, info in fields.items():

        if (
            info.get(
                "treatment"
            )
            == "EXPANDED"
        ):

            # Traduz para o nome usado na chave da tabela. Sem isto,
            # um `flags` EXPANDED viraria expansion_fields=["flags"],
            # nome que o expansor nao reconhece, e a entrada nunca seria
            # expandida.
            expansion_fields.append(
                backend_fields.nome_de_backend(
                    field
                )
            )

    entry = {
        "rule_id": str(
            rule_manifest.get(
                "rule_id"
            )
        ),

        "rule_type": (
            rule_manifest.get(
                "rule_type"
            )
        ),

        "semantic_class": (
            classification
        ),

        "final_detection": (
            rule_manifest.get(
                "final_detection"
            )
        ),

        "match": match,

        # Structural information used by the expansion stage.
        "direction": direction,

        "expansion_fields": (
            expansion_fields
        ),

        # Keep semantic counts for backend auditing.
        "semantic_counts": (
            rule_manifest.get(
                "counts",
                {}
            )
        ),

        # The data plane only selects traffic that must
        # continue to the IDS. It does not replace Snort's
        # detection decision for NECESSARY rules.
        "action": {
            "name": "send_to_ids",
        },
    }

    # Chave acrescentada APENAS quando houve colisao, para nao alterar os
    # artefatos de um ruleset que nao a exercita. Nenhuma das 4.017 regras
    # do ruleset avaliado repete um campo de cabecalho.
    if collisions:
        entry["field_collisions"] = collisions

    return entry
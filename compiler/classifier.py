from compatibility import analyze_header


SUPPORTED_OPTIONS = {
    "flags"
}

METADATA_OPTIONS = {
    "msg",
    "sid",
    "rev",
    "gid",
    "reference",
    "metadata",
    "classtype",
    "priority"
}


def classify_rule(rule):
    preserved = []
    delegated = []

    header_analysis = analyze_header(rule)

    header_values = {
        "protocol": rule["protocol"],
        "src_ip": rule["source"]["address"],
        "src_port": rule["source"]["port"],
        "direction": rule["direction"],
        "dst_ip": rule["destination"]["address"],
        "dst_port": rule["destination"]["port"]
    }

    has_supported_semantic_predicate = False
    has_selective_predicate = False
    has_unsupported_detection_predicate = False

    # Analyze header fields.
    for name, analysis in header_analysis.items():
        value = header_values[name]

        if analysis["supported"]:
            # Protocol is semantically relevant even when broad.
            if name == "protocol":
                preserved.append({
                    "name": name,
                    "value": value
                })
                has_supported_semantic_predicate = True

            elif analysis["restrictive"]:
                preserved.append({
                    "name": name,
                    "value": value
                })
                has_supported_semantic_predicate = True
                has_selective_predicate = True

        else:
            # "any" is not unsupported; analyze_header already marks it supported.
            delegated.append({
                "name": name,
                "value": value,
                "reason": analysis["reason"]
            })
            has_unsupported_detection_predicate = True

    # Analyze Snort options.
    for option in rule["options"]:
        name = option["name"]

        # Metadata does not affect detection semantics.
        if name in METADATA_OPTIONS:
            continue

        if name in SUPPORTED_OPTIONS:
            preserved.append({
                "name": name,
                "value": option["value"]
            })
            has_supported_semantic_predicate = True
            has_selective_predicate = True

        else:
            delegated.append({
                "name": name,
                "value": option["value"],
                "reason": "option unsupported by initial target profile"
            })
            has_unsupported_detection_predicate = True

    # Semantic classification.
    if not has_unsupported_detection_predicate:
        classification = "EXACT"

    elif has_supported_semantic_predicate:
        classification = "NECESSARY"

    else:
        classification = "UNSUPPORTED"

    # Operational usefulness is independent from semantic class.
    if classification == "EXACT":
        prefilter_candidate = True

    elif classification == "NECESSARY":
        prefilter_candidate = has_selective_predicate

    else:
        prefilter_candidate = False

    # Operational action.
    if classification == "EXACT":
        data_plane_action = "DIRECT"

    elif classification == "NECESSARY" and prefilter_candidate:
        data_plane_action = "PREFILTER"

    else:
        data_plane_action = "DELEGATE"

    return {
        "rule_id": rule["sid"],
        "classification": classification,
        "prefilter_candidate": prefilter_candidate,
        "preserved": preserved,
        "delegated": delegated,
        "data_plane_action": data_plane_action,
        "final_detection": (
            "DATA_PLANE"
            if classification == "EXACT"
            else "SNORT"
        )
    }
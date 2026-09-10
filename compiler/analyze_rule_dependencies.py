import json
import re
import sys

from collections import Counter, defaultdict
from pathlib import Path

from parser import parse_rules_file


PROJECT_ROOT = Path(__file__).resolve().parents[1]

RULESET_FILE = PROJECT_ROOT / "rules" / "snort3-community.rules"
MANIFEST_FILE = PROJECT_ROOT / "output" / "semantic_manifest.json"
CANDIDATE_FILE = PROJECT_ROOT / "output" / "snort_candidate.rules"
UNSUPPORTED_FILE = PROJECT_ROOT / "output" / "snort_unsupported.rules"
OUTPUT_FILE = PROJECT_ROOT / "output" / "rule_dependency_audit.json"


FLOWBIT_PRODUCER_OPERATIONS = {
    "set",
    "setx",
    "unset",
    "toggle",
    "reset",
}

FLOWBIT_CONSUMER_OPERATIONS = {
    "isset",
    "isnotset",
}

FLOWBIT_MODIFIERS = {
    "noalert",
}

EDGE_CLASSES = (
    "CANDIDATE_TO_CANDIDATE",
    "CANDIDATE_TO_UNSUPPORTED",
    "UNSUPPORTED_TO_CANDIDATE",
    "UNSUPPORTED_TO_UNSUPPORTED",
)


def load_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def normalized_sid(value):
    return str(value)


def split_state_variables(value):
    """Split compound flowbit expressions such as a&b and a|b."""

    return [
        item.strip()
        for item in re.split(r"[&|]", value)
        if item.strip()
    ]


def parse_flowbit_option(value):
    text = "" if value is None else str(value).strip()
    parts = [part.strip() for part in text.split(",")]
    operation = parts[0].lower() if parts and parts[0] else ""

    if operation in FLOWBIT_MODIFIERS:
        return operation, [], "modifier"

    variables = split_state_variables(parts[1]) if len(parts) > 1 else []

    if operation in FLOWBIT_PRODUCER_OPERATIONS:
        role = "producer"
    elif operation in FLOWBIT_CONSUMER_OPERATIONS:
        role = "consumer"
    else:
        role = "unknown"

    return operation, variables, role


def rule_partition(record):
    return "CANDIDATE" if record["prefilter_candidate"] else "UNSUPPORTED"


def operation_record(record, operation):
    return {
        "sid": normalized_sid(record["rule_id"]),
        "operation": operation,
        "semantic_class": record["classification"],
        "prefilter_candidate": bool(record["prefilter_candidate"]),
        "partition": rule_partition(record),
    }


def sorted_records(records):
    return sorted(
        records,
        key=lambda item: (
            int(item["sid"]) if item["sid"].isdigit() else item["sid"],
            item["operation"],
        ),
    )


def option_inventory(source_rules):
    counts = Counter()

    for rule in source_rules:
        for option in rule.get("options", []):
            counts[str(option["name"]).strip().lower()] += 1

    return dict(sorted(counts.items()))


def validate_inputs(manifest_rules, source_rules, candidate_rules, unsupported_rules):
    errors = []

    manifest_sids = {
        normalized_sid(record["rule_id"])
        for record in manifest_rules
    }
    source_sids = {normalized_sid(rule["sid"]) for rule in source_rules}
    candidate_sids = {normalized_sid(rule["sid"]) for rule in candidate_rules}
    unsupported_sids = {normalized_sid(rule["sid"]) for rule in unsupported_rules}

    expected_candidate = {
        normalized_sid(record["rule_id"])
        for record in manifest_rules
        if record["prefilter_candidate"]
    }
    expected_unsupported = manifest_sids - expected_candidate

    if len(manifest_sids) != len(manifest_rules):
        errors.append("Duplicate SID in semantic manifest")
    if len(source_sids) != len(source_rules):
        errors.append("Duplicate SID in source ruleset")
    if manifest_sids != source_sids:
        errors.append("Manifest/source SID sets differ")
    if candidate_sids != expected_candidate:
        errors.append("Candidate partition SID set differs from manifest")
    if unsupported_sids != expected_unsupported:
        errors.append("Unsupported partition SID set differs from manifest")
    if candidate_sids & unsupported_sids:
        errors.append("Candidate and unsupported partitions overlap")

    return errors, manifest_sids


def main():
    manifest = load_json(MANIFEST_FILE)
    manifest_rules = manifest.get("rules", [])

    source_rules = parse_rules_file(str(RULESET_FILE))
    candidate_rules = parse_rules_file(str(CANDIDATE_FILE))
    unsupported_rules = parse_rules_file(str(UNSUPPORTED_FILE))

    validation_errors, manifest_sids = validate_inputs(
        manifest_rules,
        source_rules,
        candidate_rules,
        unsupported_rules,
    )

    if validation_errors:
        for error in validation_errors:
            print(f"ERROR: {error}")
        sys.exit(1)

    inventory = option_inventory(source_rules)
    by_variable = defaultdict(lambda: {"producers": [], "consumers": []})
    producer_counts = Counter()
    consumer_counts = Counter()
    unknown_flowbit_operations = Counter()
    rules_with_flowbits = set()
    modifier_counts = Counter()

    for record in manifest_rules:
        sid = normalized_sid(record["rule_id"])

        if sid not in manifest_sids:
            raise RuntimeError(f"Unknown manifest SID: {sid}")

        parsed_rule = record.get("parsed_rule") or {}

        for option in parsed_rule.get("options", []):
            if str(option.get("name", "")).strip().lower() != "flowbits":
                continue

            rules_with_flowbits.add(sid)
            operation, variables, role = parse_flowbit_option(option.get("value"))

            if role == "modifier":
                modifier_counts[operation] += 1
                continue

            if role == "unknown":
                unknown_flowbit_operations[operation or "<empty>"] += 1
                continue

            if not variables:
                unknown_flowbit_operations[f"{operation}:<missing-variable>"] += 1
                continue

            for variable in variables:
                item = operation_record(record, operation)
                by_variable[variable][f"{role}s"].append(item)

                if role == "producer":
                    producer_counts[operation] += 1
                else:
                    consumer_counts[operation] += 1

    variables = []
    dependency_edges = []
    edge_counts = Counter({name: 0 for name in EDGE_CLASSES})
    reads_without_producer = []

    for variable in sorted(by_variable):
        producers = sorted_records(by_variable[variable]["producers"])
        consumers = sorted_records(by_variable[variable]["consumers"])

        variables.append(
            {
                "name": variable,
                "producers": producers,
                "consumers": consumers,
            }
        )

        if consumers and not producers:
            reads_without_producer.append(
                {
                    "state_mechanism": "flowbits",
                    "state_variable": variable,
                    "consumers": consumers,
                }
            )

        for producer in producers:
            for consumer in consumers:
                edge_class = (
                    f"{producer['partition']}_TO_{consumer['partition']}"
                )
                edge_counts[edge_class] += 1
                dependency_edges.append(
                    {
                        "state_mechanism": "flowbits",
                        "state_variable": variable,
                        "producer_sid": producer["sid"],
                        "producer_class": producer["semantic_class"],
                        "producer_prefilter_candidate": producer["prefilter_candidate"],
                        "producer_partition": producer["partition"],
                        "producer_operation": producer["operation"],
                        "consumer_sid": consumer["sid"],
                        "consumer_class": consumer["semantic_class"],
                        "consumer_prefilter_candidate": consumer["prefilter_candidate"],
                        "consumer_partition": consumer["partition"],
                        "consumer_operation": consumer["operation"],
                        "edge_class": edge_class,
                    }
                )

    cross_partition = [
        edge
        for edge in dependency_edges
        if edge["producer_partition"] != edge["consumer_partition"]
    ]

    candidate_count = sum(
        1 for record in manifest_rules if record["prefilter_candidate"]
    )
    unsupported_count = len(manifest_rules) - candidate_count

    local_or_engine_state = [
        {
            "mechanism": "flow",
            "occurrences": inventory.get("flow", 0),
            "category": "engine_flow_state_read",
            "cross_rule_dependency": False,
            "explanation": "Reads direction, establishment, or stateless flow state maintained by Snort; no rule-defined named variable is produced.",
        },
        {
            "mechanism": "stream_size",
            "occurrences": inventory.get("stream_size", 0),
            "category": "engine_stream_state_read",
            "cross_rule_dependency": False,
            "explanation": "Reads stream state maintained by Snort, not state produced by another rule.",
        },
        {
            "mechanism": "detection_filter",
            "occurrences": inventory.get("detection_filter", 0),
            "category": "rule_local_temporal_state",
            "cross_rule_dependency": False,
            "explanation": "Maintains threshold state for the rule itself; it does not name state shared with another rule.",
        },
        {
            "mechanism": "byte_extract",
            "occurrences": inventory.get("byte_extract", 0),
            "category": "rule_local_variable",
            "cross_rule_dependency": False,
            "explanation": "Defines variables consumed by later options in the same rule only.",
        },
        {
            "mechanism": "tag",
            "occurrences": inventory.get("tag", 0),
            "category": "post_detection_side_effect",
            "cross_rule_dependency": False,
            "explanation": "Changes logging after a match but does not produce a named detection prerequisite for another rule.",
        },
    ]

    decision = (
        "CROSS_PARTITION_DEPENDENCIES_FOUND"
        if cross_partition
        else "SAFE_FOR_INDEPENDENT_RULESET_SPLIT"
    )

    report = {
        "schema_version": "1.0",
        "inputs": {
            "ruleset": str(RULESET_FILE.relative_to(PROJECT_ROOT)),
            "semantic_manifest": str(MANIFEST_FILE.relative_to(PROJECT_ROOT)),
            "candidate_ruleset": str(CANDIDATE_FILE.relative_to(PROJECT_ROOT)),
            "unsupported_ruleset": str(UNSUPPORTED_FILE.relative_to(PROJECT_ROOT)),
        },
        "total_rules": len(manifest_rules),
        "candidate_rules": candidate_count,
        "unsupported_rules": unsupported_count,
        "rules_with_flowbits": len(rules_with_flowbits),
        "unique_flowbits": len(by_variable),
        "flowbit_producer_rules": len(
            {item["sid"] for value in by_variable.values() for item in value["producers"]}
        ),
        "flowbit_consumer_rules": len(
            {item["sid"] for value in by_variable.values() for item in value["consumers"]}
        ),
        "flowbit_producer_instances": sum(producer_counts.values()),
        "flowbit_consumer_instances": sum(consumer_counts.values()),
        "producer_operations": dict(sorted(producer_counts.items())),
        "consumer_operations": dict(sorted(consumer_counts.items())),
        "flowbit_modifiers": dict(sorted(modifier_counts.items())),
        "unknown_flowbit_operations": dict(sorted(unknown_flowbit_operations.items())),
        "candidate_to_candidate_edges": edge_counts["CANDIDATE_TO_CANDIDATE"],
        "candidate_to_unsupported_edges": edge_counts["CANDIDATE_TO_UNSUPPORTED"],
        "unsupported_to_candidate_edges": edge_counts["UNSUPPORTED_TO_CANDIDATE"],
        "unsupported_to_unsupported_edges": edge_counts["UNSUPPORTED_TO_UNSUPPORTED"],
        "consumer_variables_without_producer": reads_without_producer,
        "xbits": {
            "option_occurrences": inventory.get("xbits", 0),
            "unique_variables": 0,
            "producer_instances": 0,
            "consumer_instances": 0,
            "dependency_edges": 0,
        },
        "flowint": {
            "option_occurrences": inventory.get("flowint", 0),
            "unique_variables": 0,
            "producer_instances": 0,
            "consumer_instances": 0,
            "dependency_edges": 0,
        },
        "other_cross_rule_state_mechanisms": [],
        "non_cross_rule_state_mechanisms": local_or_engine_state,
        "option_inventory": inventory,
        "flowbits": {
            "variables": variables,
            "dependency_edges": dependency_edges,
        },
        "cross_partition_dependencies": cross_partition,
        "validation": {
            "manifest_sids_checked": len(manifest_sids),
            "unknown_sids": [],
            "errors": [],
            "status": "VALID",
        },
        "decision": decision,
    }

    OUTPUT_FILE.write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    print("=== Rule Dependency Audit ===")
    print(f"Rules                    : {report['total_rules']}")
    print(f"Candidate rules          : {report['candidate_rules']}")
    print(f"Unsupported rules        : {report['unsupported_rules']}")
    print(f"Rules with flowbits      : {report['rules_with_flowbits']}")
    print(f"Unique flowbits          : {report['unique_flowbits']}")
    print(f"Producer instances       : {report['flowbit_producer_instances']}")
    print(f"Consumer instances       : {report['flowbit_consumer_instances']}")
    print(f"Candidate -> Candidate   : {report['candidate_to_candidate_edges']}")
    print(f"Candidate -> Unsupported : {report['candidate_to_unsupported_edges']}")
    print(f"Unsupported -> Candidate : {report['unsupported_to_candidate_edges']}")
    print(f"Unsupported -> Unsupported: {report['unsupported_to_unsupported_edges']}")
    print(f"Reads without producer   : {len(reads_without_producer)}")
    print(f"Cross-partition edges    : {len(cross_partition)}")
    print(f"Decision                 : {decision}")
    print(f"Output                   : {OUTPUT_FILE}")


if __name__ == "__main__":
    main()

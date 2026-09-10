# Semantic Soundness Audit

## 1. Executive summary

This is a static implementation-to-manuscript audit. No traffic experiment,
ruleset build, policy retuning, or frozen-artifact regeneration was performed.

For the frozen Community-ruleset build, no transformation was found that makes
an installed candidate predicate more restrictive than a source rule under the
implemented Ethernet/IPv4 profile. The argument is conditional and
predicate-level: for a NECESSARY rule, a source match entails the represented
header conjunction, and the audited backend stages preserve or broaden that
conjunction as specified below. It is not a claim of full Snort equivalence or
stateful end-to-end bypass safety.

One manuscript qualification was required: EXACT is a classifier category, but
the implemented P4 backend emits the common `send_to_ids` candidate-marking
action. It does not implement a general direct data-plane detection action.

## 2. Actual compiler constructs audited

| Source construct | Normalized IR / capability decision | Generated and lowered representation | Semantic treatment | Implementation evidence |
|---|---|---|---|---|
| Traditional protocol `tcp`, `udp`, `icmp` | Header `protocol`; `PRESERVED` | IPv4 protocol number 6, 17, or 1; exact ternary key | Exact-preserving within the Ethernet/IPv4 profile | `parser.py:parse_traditional_rule`; `build_semantic_ir.py:add_traditional_header_predicates`; `target_capability.py:assess_protocol`; `p4_backend.py:normalize_protocol`; `normalize_p4_entries.py:normalize_protocol` |
| Traditional protocol `ip` | Header `protocol`; `PRESERVED` as `protocol_wildcard` | No L4 protocol key | Conservative within the IPv4 parser scope | Same functions; `p4_backend.py:normalize_protocol` omits the L4 key for `ip` |
| Source/destination IPv4 or CIDR | Header `src_ip`/`dst_ip`; `PRESERVED` | Canonical IPv4 network plus prefix, then P4Runtime ternary value/mask | Exact CIDR membership preservation | `target_capability.py:assess_ip`; `normalize_p4_entries.py:normalize_ip`; `generate_p4runtime_install.py:encode_ipv4_ternary` |
| Whole-field network variable | Resolved before IR/capability assessment; frozen manifest records the resolution | Same as resolved IPv4/CIDR | Safe under the explicit resolved-profile assumption | `variable_resolver.py:resolve_value`, `resolve_rule_variables`; manifest `variable_resolution` |
| Exact source/destination port | Header port; `PRESERVED` | Exact 16-bit ternary key | Exact-preserving | `target_capability.py:assess_port`; `normalize_p4_entries.py:normalize_port`; `generate_p4runtime_install.py:encode_exact_ternary` |
| Finite address/port list | `EXPANDED` only after every element is accepted | Cartesian product of alternatives; one concrete entry per combination | Exact union of finite alternatives | `target_capability.py:assess_ip_list`, `assess_port_list`; `expand_p4_entries.py:expand_match_lists` |
| Negated address/port, port range, invalid/complex list | `FALLBACK` or `UNASSESSED`, never a concrete supported value | Field omitted from P4 predicate | Conservative relaxation; if no other selective header exists, UNSUPPORTED | `target_capability.py:assess_ip`, `assess_port`; `p4_backend.py:get_backend_predicates` |
| Direction `->` | `PRESERVED` structural field | Forward source/destination orientation | Preserved | `target_capability.py:assess_direction`; `expand_p4_entries.py:build_orientations` |
| Direction `<>` | `EXPANDED` structural field | Forward and reverse matches, including swapped IPs, ports, and expansion-field names | Exact union of both orientations | `expand_p4_entries.py:reverse_match_orientation`, `reverse_expansion_fields`, `build_orientations` |
| Direction `<-` | `FALLBACK` | Omitted from predicate | Conservative relaxation or UNSUPPORTED if no selective represented header remains | `target_capability.py:assess_direction` |
| Accepted TCP-flag forms | Header `flags`; `PRESERVED` after capability assessment | Normalized masks; `*` lowered into one ternary entry per tested bit | Safe under the flag-normalizer semantics and TCP validation | `normalize_p4_entries.py:normalize_tcp_flags`; `lower_p4_entries.py:lower_tcp_flags`; `validate_backend.py:analyze_tcp_flags`; `tests/test_tcp_flag_lowering.py` |
| Payload/content, PCRE, byte operations, sticky buffers | Ordered semantic predicates; content normalization retains pattern, negation, modifiers, and buffer context | No P4 match | Delegated to Snort; omission broadens, rather than establishes detection | `build_semantic_ir.py:classify_option`, `build_semantic_ir.py:build_semantic_ir`; `option_normalizer.py:normalize_content` |
| Flow/state, flowbits, stream, temporal, application/service semantics | Flow/state, temporal, or application predicates | No P4 match | Delegated to Snort | `build_semantic_ir.py:classify_option`; `semantic_ir.py:make_flow_predicate` and related constructors |
| Service-style rule | Service header becomes an application predicate; no traditional header is fabricated | No entry without another selective represented header | UNSUPPORTED in the frozen service cases; Snort fallback | `parser.py:parse_service_rule`; `build_semantic_ir.py:add_service_header_predicate`; `semantic_classifier.py:classify_assessed_rule` |

## 3. Predicate-level soundness argument added to the manuscript

The manuscript now defines `H_r` as the conjunction of source header conditions
marked PRESERVED or EXPANDED, and `U_r` as delegated, fallback, or unassessed
detection-relevant conditions. Under the implemented profile:

```text
r(x) => H_r(x)
H_r(x) => L(H_r)(x) = p_r(x)
therefore r(x) => p_r(x)
```

The argument relies only on the represented header subset; it does not assume
that omitted content, state, stream, normalization, or application semantics
are true for every candidate packet. They can make `p_r` broader, which is the
reason for NECESSARY rather than EXACT.

## 4. Potential `r => p_r` failure modes checked

| Potential failure mode | Static result | Classification | Evidence |
|---|---|---|---|
| List expansion drops an alternative | Finite accepted alternatives are expanded with Cartesian product; frozen artifact reports no unresolved list values. | SAFE BY CONSTRUCTION | `expand_p4_entries.py:expand_match_lists`, `find_unresolved_list_values`; `output/p4_entries_expanded.json` |
| Bidirectional rule reverses fields incorrectly | Reverse expansion swaps source/destination IPs, ports, and expansion metadata together. | SAFE BY CONSTRUCTION | `expand_p4_entries.py:reverse_match_orientation`, `reverse_expansion_fields` |
| Variable resolution narrows a rule unexpectedly | Whole-field variables resolve before capability assessment; unresolved expressions do not become supported concrete values. | SAFE UNDER EXPLICIT ASSUMPTION | `variable_resolver.py`; frozen profile and manifest resolution log |
| CIDR conversion changes membership | `ipaddress.ip_network(..., strict=False)` canonicalizes address/prefix; runtime uses the matching ternary prefix mask. | SAFE BY CONSTRUCTION | `normalize_p4_entries.py:normalize_ip`; `generate_p4runtime_install.py:prefix_to_mask`, `encode_ipv4_ternary` |
| Range or negation becomes a narrower exact match | These forms are fallback/unassessed and excluded from the P4 predicate. | FALLBACK REQUIRED | `target_capability.py:assess_ip`, `assess_port` |
| TCP-flag lowering excludes a source match | Direct forms use ternary masks; `*` becomes the union over tested bits. Frozen backend validation and the existing lowering test cover the installed representation. | SAFE UNDER EXPLICIT ASSUMPTION | `lower_p4_entries.py:lower_tcp_flags`; `tests/test_tcp_flag_lowering.py` |
| Deduplication removes a logical match | Only identical normalized/lowered matches are merged; every action is `send_to_ids`. | SAFE BY CONSTRUCTION | `lower_p4_entries.py:deduplicate_normalized_entries`, `final_deduplication` |
| P4Runtime encoding changes key width or prefix semantics | Fields are width-validated and P4Info names/IDs are checked before encoding. | SAFE BY CONSTRUCTION | `generate_p4runtime_install.py:validate_integer_width`, `encode_match_field`, `verify_p4info_text`, `validate_encoded_entries` |
| A non-IPv4/parser-ineligible packet is treated as a P4 no-match | The manuscript and experiment reports separate parser-ineligible frames from P4 no-match. | SAFE UNDER EXPLICIT ASSUMPTION | Implemented parser scope and frozen parser-coverage artifacts |

No genuine implementation gap affecting `r => p_r` was found in the frozen
build. The flag claim remains explicitly limited to forms accepted by the
current normalizer; it is not a claim of complete Snort TCP-flags grammar
coverage.

## 5. Backend preservation analysis

1. `p4_backend.py:get_backend_predicates` consumes only manifest predicates
   marked PRESERVED or EXPANDED; DELEGATED and FALLBACK predicates are not
   silently converted into table keys.
2. List and direction expansion materializes a union of concrete matches.
3. Normalization rejects malformed IPv4, port, protocol, or flag values instead
   of silently coercing them.
4. Deduplication changes physical installation state only. Since all merged
   entries execute `send_to_ids`, the logical candidate union is unchanged.
5. Provenance must be unioned when identical matches are merged. The lowering
   code retains `source_rule_ids`, backend-entry IDs, semantic classes, rule
   types, and orientations; the resulting source-rule union supports the
   offline candidate-rule-set analysis.
6. The frozen backend validation reports zero validation errors; the frozen
   lowering artifact reports no final-entry validation errors; the frozen
   P4Runtime plan reports no encoding failures or validation errors.

## 6. Safety levels distinguished

- **Level A — predicate-level rule safety:** conditional implication
  `r => p_r` under the audited parser, resolved profile, accepted header forms,
  and lowering assumptions.
- **Level B — packet-level prefilter preservation:** finite empirical evidence
  that observed parser-eligible candidate-alert packets were marked candidate
  in the evaluated traces.
- **Level C — end-to-end stateful IDS preservation:** not established in
  general. Packet dropping can affect stream state, flow state, flowbits,
  temporal dependencies, reassembly, and application/protocol context. The
  implemented P4 program marks candidate metadata and does not establish
  arbitrary safe packet bypass.

## 7. EXACT validation status

The frozen Community-ruleset manifest reports EXACT=0, NECESSARY=4003, and
UNSUPPORTED=14. Therefore there is no reported trace-based or ruleset-level
EXACT result. The repository contains a legacy component-level semantic-model
test (`tests/test_semantic_model.py`) with a header-only EXACT expectation and
an older illustrative `output/manifest.json`; these are not evidence of
experimental EXACT validation for the current frozen pipeline. The manuscript
now says this explicitly.

## 8. UNSUPPORTED and NECESSARY explanation

The 14 frozen UNSUPPORTED rules divide into four traditional rules and ten
service-style rules. The traditional cases have nonselective represented
headers together with delegated content or byte-level conditions. The service
cases retain delegated service-header, flow, buffer, payload, and in some
cases PCRE or BER/byte semantics, but intentionally receive no fabricated
traditional header fields. In each case, `classify_assessed_rule` finds no
selective represented predicate, so no P4 entry is emitted and the rule stays
in Snort fallback.

NECESSARY rules commonly combine one or more selective represented headers
with delegated content/payload-buffer, flow/state, application/service, or
PCRE semantics. A smaller subset also has fallback port-range, negated-port,
or digit-bearing flag expressions; these rules remain candidates only when
another selective represented header is available. No new traffic measurement
or inferred aggregate count is used for this explanation.

## 9. Manuscript changes and claim qualification

Modified sections in `main.tex`:

- **Problem Formulation:** added *Predicate-Level Soundness of Partial
  Compilation* and qualified EXACT as a semantic class rather than an
  implemented generic direct-detection action.
- **Proposed Approach:** added Table `tab:compilation-semantics` and an
  implementation-grounded backend/lowering explanation.
- **Experimental Methodology:** replaced wording that implied an experimental
  EXACT evaluation with the scoped legacy unit-scenario statement and the
  frozen EXACT=0 result.
- **Results/RQ1:** added the frozen-artifact explanation of the 14
  UNSUPPORTED cases and the common reasons for NECESSARY classification.

The audit searched `semantic safety`, `safe`, `sound`, `preserve`,
`guarantee`, `equivalent`, `equivalence`, `correct`, and `correctly`.
Ambiguous wording about direct EXACT execution and generic preservation was
qualified. Remaining occurrences either refer to the conditional Level-A
implication, explicitly observed Level-B preservation, or limitations that
deny Level-C equivalence.

## 10. Compilation status

The requested clean build completed successfully:

```text
latexmk -C
latexmk -pdf -interaction=nonstopmode main.tex
```

- Exit status: 0
- Fatal errors: 0
- Undefined citations: 0
- Undefined references: 0
- Overfull boxes greater than 10 pt: 0
- Underfull boxes: 0
- Final PDF: 29 pages, 373,568 bytes

The new compilation-semantics table was rendered and visually inspected after
being placed on a landscape page. No clipping or overlap was observed.

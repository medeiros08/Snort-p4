# Snort 3 Language Support Matrix

This document records, construct by construct, what the Snort 3 rule language
allows, what the compiler does with it, and what reaches the P4 table. It
replaces the earlier version, which stopped in the middle of Section 1 and
wrongly stated that service rules are not parsed (finding H10 of
`docs/review/2026-09-11_analise_completa.md`).

Sources:

- **Snort 3 behavior:** the pinned corpus in `docs/vendor/snort3/`
  (tag 3.12.2.0; `docs/vendor/MANIFEST.md`) and, where the corpus is silent,
  the Snort 3.12.2.0 source, cited by file.
- **Compiler behavior:** `compiler/parser.py`, `compiler/build_semantic_ir.py`,
  `compiler/target_capability.py`, `compiler/semantic_classifier.py`.
- **Counts:** `output/semantic_manifest.json`, the frozen manifest of the
  4,017-rule Community ruleset under the `cicids2017` profile. A count is the
  number of header decisions or of rules using an option.

A construct being valid in Snort does not make it representable in P4, and a
header field that Snort evaluates for one rule may be skipped for another
(Section 5).

---

## 1. Status Legend

| Treatment | Meaning for the P4 predicate |
|---|---|
| PRESERVED | Represented as an exact or ternary key |
| EXPANDED | Represented as several keys (list, `<>`, `*` flags) |
| DELEGATED | Not in the predicate; Snort evaluates it |
| FALLBACK | Not in the predicate; the form cannot be represented safely |

DELEGATED and FALLBACK both omit the condition, which only widens the
predicate. No treatment narrows it.

---

## 2. Rule Forms

| Form | Snort 3 | Parser / IR | Backend | Rules |
|---|---|---|---|---:|
| Traditional header `action proto src sport dir dst dport (...)` | valid | `parse_traditional_rule`, full IR | header keys | 4,007 |
| Service header `alert http (...)`, `alert ssl (...)` | valid ("alert file and alert service rules", `upgrade/differences.txt`) | `parse_service_rule`; no IPv4/L4 header is invented | no entry; classified UNSUPPORTED | 10 |
| File header `alert file (...)` | valid | parsed as a service header with service `file` | no entry | 0 |
| Direction `->` | valid | PRESERVED | forward entry | 3,996 |
| Direction `<>` | valid | EXPANDED | forward and reverse entries | 11 |
| Direction `<-` | rejected by Snort ("illegal direction specifier") | rejected by the parser, as Snort does | — | 0 |
| Unbalanced quotes | rejected by Snort | rejected (`RegraMalformada`) | — | 0 |

---

## 3. Header Fields

| Field and form | Treatment | Reason recorded in the manifest | Decisions |
|---|---|---|---:|
| `protocol` tcp / udp / icmp | PRESERVED | `supported_ip_protocol` | 3,973 |
| `protocol` ip | PRESERVED as a wildcard | `protocol_wildcard` | 22 |
| `protocol` naming a service in a traditional header (`alert http any any -> $HOME_NET any`) | DELEGATED; addresses and ports assessed normally | `application_or_unsupported_protocol` | 12 |
| Address, IPv4 or CIDR, after variable resolution | PRESERVED | `ipv4_or_cidr_supported` | 3,989 |
| Address `any` | PRESERVED as a wildcard | `wildcard` | 4,025 |
| Port, exact | PRESERVED | `exact_port_supported` | 967 |
| Port, finite list (including resolved `$HTTP_PORTS`) | EXPANDED | `port_list_requires_expansion` | 2,651 |
| Port `any` | PRESERVED as a wildcard | `wildcard` | 4,318 |
| Port range `N:M`, `N:`, `:M` | FALLBACK | `port_range_not_supported` | 62 |
| Port list containing a range | FALLBACK | `port_list_contains_range` | 14 |
| Negated port | FALLBACK | `negated_port_not_supported` | 2 |
| TCP `flags`, forms the normalizer accepts | PRESERVED (`*` lowered to a union) | `flags_supported_by_backend_normalizer` | 10 |
| TCP `flags` with reserved-bit digits (`12`) or other forms | FALLBACK | `unsupported_flags_encoding` | 4 |
| `itype`, `icode`, `icmp_id`, `icmp_seq`, `ttl`, `id`, `ip_proto`, `seq`, `ack`, `fragbits` | DELEGATED | `p4_candidate_not_implemented_in_current_backend` | 237 |

Variable resolution substitutes whole-field variables from
`config/snort_variables.json`; with the profile's `EXTERNAL_NET = any`, the
external side resolves to a wildcard.

Port ranges could be represented exactly as ternary prefixes, and the ICMP
fields are already parsed by the P4 program; both are recorded as possible
improvements (H12, M1, M2 of the 2026-09-11 review), not as current behavior.

---

## 4. Rule Options

All non-header options are kept in the IR and the manifest and are never
part of the P4 predicate.

| IR kind | Options in the ruleset (rules using each) | Treatment |
|---|---|---|
| PAYLOAD | `content` 3,898; `pcre` 1,027; `byte_test` 254; `isdataat` 209; `bufferlen` 191; `byte_jump` 173; `dsize` 23; `byte_extract` 9; `base64_decode` 3; `ber_skip` 2; `ber_data` 2 | DELEGATED |
| BUFFER (sticky buffers) | `http_uri` 1,692; `http_header` 557; `file_data` 263; `http_client_body` 237; `http_raw_uri` 206; `pkt_data` 195; `http_method` 123; `http_cookie` 31; `raw_data` 7; `http_stat_code` 5; `base64_data` 3; `http_raw_header` 3; `http_stat_msg` 3 | DELEGATED |
| FLOW_STATE | `flow` 3,841; `flowbits` 242; `stream_size` 1 | DELEGATED |
| APPLICATION | `service` 2,930; `dce_iface` 15; `dce_opnum` 15; `dce_stub_data` 14; `ssl_state` 7; `sip_stat_code` 4; `sip_method` 3; `ssl_version` 2; `sip_header` 2 | DELEGATED |
| TEMPORAL | `detection_filter` 33 | DELEGATED |
| METADATA | `msg`, `sid`, `rev`, `classtype`, `metadata` 4,017 each; `reference` 3,239; `gid` 79 | not detection-relevant |

Snort evaluates a candidate rule's options left to right after a fast-pattern
search and stops at the first that fails (`doc/user/concepts.txt`, "Rule
Evaluation"). Delegating an option therefore never removes a condition from
Snort; it only removes it from the P4 predicate.

---

## 5. Service-Based Rules

A rule is service-based when it declares `service`, uses a service-specific
option, or has a service header (`doc/user/concepts.txt:290-296`). When the
service Snort has identified for the flow is one of the rule's services,
Snort 3.12.2.0 skips the header port checks and the protocol check but still
checks addresses (`src/detection/detection_options.cc`,
`src/detection/rtn_checks.cc`). A different identified service rejects the
rule; an unidentified service leaves the full header checked.

A service-specific option adds services only to a rule that has none, in
`validate_services` (`src/detection/fp_utils.cc`): a selected buffer that an
inspector registers adds that inspector's services, and other options add
one guessed from the name prefix. In the evaluated ruleset this reaches three
NECESSARY rules without `service:` (529, 3238, 3239): `dce_iface` and
`dce_stub_data` add `dcerpc` and `netbios-ssn`.

| Compiler mode | Header of a service-based rule | Rules affected |
|---|---|---:|
| `snort3` (default since 2026-10-05) | protocol, `src_port`, `dst_port` DELEGATED (`service_based_header_not_checked_on_service_match`); protocol kept when the rule has `flags`, which only matches TCP (`src/ips_options/ips_flags.cc`) | 2,931 NECESSARY rules under `legacy` (2,928 with `service:`, 3 DCE) |
| `legacy` (`--service-header-semantics legacy`; artifacts archived in `output/historical/legacy_header_semantics/`) | assessed as for a port-based rule: protocol and ports PRESERVED/EXPANDED | same |

Under `legacy`, the predicate of these rules is a necessary condition only on
traffic whose service Snort has not identified.

A traditional header that names a service protocol instead of an IP protocol
(the 12 `alert http ... -> ...` rules of Section 3) behaves differently:
`SetupRTNFuncList` (`src/parser/parse_rule.cc`) marks such a rule
`USER_MODE`, and `fp_eval_rtn` (`src/detection/fp_detect.cc`) then forces the
port checks back on. Their ports are therefore necessary conditions, and
neither mode changes them. Details and measured effect:
`paper/IDS_P4/SERVICE_BASED_HEADER_FINDING.md`,
`output/analysis/service_header_semantics_whatif.json`.

---

## 6. Packet Domain

The P4 program applies the predicate table only to direct Ethernet/IPv4 with
IHL = 5, no fragmentation, flags 0 or DF, and no parser error. Every other
frame (ARP, IPv6, LLDP, VLAN-tagged, IPv4 options, fragments, truncated IPv4,
TCP, UDP, or ICMP headers) is marked candidate on the
`PACKET_DOMAIN_FALLBACK` counter. IPv4 with another L4 protocol, such as GRE,
stays inside the domain without ports. Offline mirror:
`tests/p4_packet_domain.py`; tests: `tests/test_packet_domain_offline.py`
(offline) and `tests/test_ipv4_packet_domain_guard.py` (BMv2).

---

## 7. Classification

| Class | Condition | Rules |
|---|---|---:|
| EXACT | no delegated, fallback, or unassessed detection predicate | 0 |
| NECESSARY | at least one selective represented header predicate | 4,003 |
| UNSUPPORTED | no selective represented header predicate | 14 |

A predicate is selective when it is PRESERVED or EXPANDED and restricts the
packet set: `tcp`/`udp`/`icmp` protocol, a concrete or finite address or
port, or TCP flags; `ip`, `any`, and direction alone are not
(`docs/semantic_model.md` §5.1). The 14 UNSUPPORTED rules are the 10
service-header rules, three `ip_proto` rules whose only restriction is
delegated, and sid 498 (`alert ip any any -> any any` with payload only).

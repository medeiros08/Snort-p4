# Service-Based Rules: the Header Is Not a Necessary Condition

**Date:** 2026-09-27
**Status:** finding confirmed from the Snort 3.12.2.0 source and documentation;
not yet reproduced on the data plane. The manuscript is revised to state the
scope of its claims. The compiler implements the corrected semantics as an
option (§8); the frozen artifacts still use the original one.

## 1. Summary

The compiler derives each NECESSARY predicate from the rule header and relies
on `r(x) => H_r(x)`: a packet on which the rule alerts satisfies the header
conditions the compiler represents. In Snort 3.12.2.0 this does not hold for
**service-based** rules. When the service Snort has identified for the flow is
one of the rule's services, Snort does not check the header ports or protocol;
it still checks the header addresses.

2,931 of the 4,003 NECESSARY rules are service-based and carry protocol and,
in almost every case, port conditions in their compiled predicate: 2,928
declare `service:`, and three (529, 3238, 3239) receive services from their
DCE options (§2.3). For those rules, the predicate-level relation `r => p_r`
holds only on traffic where Snort evaluates the full header.

The implemented 331-entry global plan remains candidate-complete for 2,922 of
the 2,931, and for the TCP part of the other nine, because it contains
port-free entries covering every packet to or from `HOME_NET` and every TCP
packet. The 322-entry strong-discriminator plan covers none of them, and the
per-packet candidate rule sets inherit the same gap for the 2,877 it
prefilters; the three DCE rules are in its operational fallback.

## 2. Evidence

### 2.1 Documentation (pinned corpus)

`docs/vendor/snort3/doc/user/concepts.txt:290-296` (tag 3.12.2.0, see
`docs/vendor/MANIFEST.md`):

> For a _port-based_ rule, all components of the rule header have to match
> before the rule fires. For a _service-based_ rule, evaluation of the header
> is skipped.

A rule becomes service-based when the `service` option is present, when a
service-specific option is present, or when the header names a service
protocol. The example that follows states that, with the service assigned
on the flow, "tcp" proto and port "90" have no effect.

### 2.2 Source code, tag 3.12.2.0

`src/detection/detection_options.cc`, before the header check (abridged; the
debug-trace call before `return false` is omitted and the trailing comment is
ours):

```c
int check_ports = 1;
if ( snort_protocol_id != UNKNOWN_PROTOCOL_ID )
{
    ...
    if ( std::any_of(sig_info.services.cbegin(), sig_info.services.cend(),
        [snort_protocol_id] (const SignatureServiceInfo& svc)
        { return snort_protocol_id == svc.snort_protocol_id; }) )
        check_ports = 0;

    if ( !sig_info.services.empty() and check_ports )
        return false;   // service mismatch
}
return fp_eval_rtn(getRtnFromOtn(node->otn), p, check_ports);
```

`src/detection/rtn_checks.cc`: `CheckSrcPortEqual`, `CheckDstPortEqual` and
the `NotEq` variants pass straight to the next check when `check_ports == 0`;
`CheckProto` begins with `if ( !check_ports ) return 1;`; `CheckSrcIP` and
`CheckDstIP` do not read `check_ports`.

`src/parser/parse_rule.cc`, `SetupRTNFuncList`: for a unidirectional rule the
chain is destination port, source port, source IP, destination IP, then
`CheckProto`. The early `return 1` of `CheckProto` therefore comes after both
address checks, so addresses are always enforced.

### 2.3 How a rule acquires services

A rule's service list is filled from three sources at 3.12.2.0:

- the `service` option;
- a service protocol in the header: `src/parser/parse_rule.cc` calls
  `add_service_to_otn` when `is_service_protocol` holds for the header
  protocol, and the rule is `USER_MODE` (§4);
- its other options, in `validate_services`
  (`src/detection/fp_utils.cc:496-574`), called from `parse_rule.cc` for
  every rule. An option that sets a buffer (cursor type above `CAT_ADJUST`)
  is looked up in a buffer map; if the rule has no service yet, a buffer
  registered by one inspector adds that inspector's service, and a buffer
  registered by several adds all of them (`add_default_services`). Any other
  option is matched by name prefix in `guess_service`
  (`fp_utils.cc:169-205`: `http_`, `cip_`, `enip_`, `dce_`, `dnp3_`, `gtp_`,
  `mms_`, `modbus_`, `s7commplus_`, `sip_`, `socks_`, `ssl_`), used only
  when no buffer added a service.

The buffer map comes from the `buffers` field of every inspector plugin's
`InspectApi`, loaded whether or not the inspector is configured
(`InspectorManager::load_buffer_map`, `src/managers/inspector_manager.cc:808-818`).
`dce_tcp` and `dce_udp` register `dce_iface`, `dce_stub_data` and `file_data`
with service `dcerpc`, and `dce_smb` registers the same three with
`netbios-ssn` (`src/service_inspectors/dce_rpc/dce_tcp.cc:210-235`,
`dce_udp.cc:200-225`, `dce_smb.cc:486-511`). `Dce2IfaceOption` and
`Dce2StubDataOption` return `CAT_SET_FAST_PATTERN`
(`ips_dce_iface.cc:229-230`, `ips_dce_stub_data.cc:57-58`), so a rule with
`dce_iface` or `dce_stub_data` and no `service:` receives `dcerpc` and
`netbios-ssn`.

### 2.4 What this means

For a rule with services `S`, Snort's header acceptance of packet `x` is:

| Service identified for `x` | Header checks |
|---|---|
| unknown | ports, addresses, protocol |
| in `S` | addresses only |
| known, not in `S` | rule rejected |

The necessary condition common to every case is the address condition. Ports
and protocol are necessary only when the service is unknown. The experimental
configuration includes Snort's default `snort.lua`, whose wizard identifies
services by content, so HTTP on a port outside `HTTP_PORTS = 80 8080` is
assigned the `http` service and HTTP rules are evaluated there without their
port condition.

Concrete case: sid 144, `alert tcp $EXTERNAL_NET any -> $HOME_NET 21
(... service:ftp; ...)`, compiles to `{tcp, dst 192.168.10.0/24, dst_port 21}`.
An FTP session identified on port 2121 can raise sid 144 while that predicate
is false.

## 3. Quantification

Produced by `tests/analyze_service_based_headers.py`
→ `output/analysis/service_based_header_exposure.json`.

| Quantity | Value |
|---|---:|
| NECESSARY rules | 4,003 |
| with explicit `service:` | 2,928 |
| of these, with protocol (and usually port) in the selective predicates | 2,928 |
| of these, P4-eligible in the strong-discriminator partition | 2,877 |
| would keep a selective predicate with address conditions only | 2,921 |
| would have no selective predicate left | 7 |
| without `service:`, service protocol in the header (`USER_MODE`, not exposed) | 12 |
| without `service:`, services added by options (§2.3), exposed | 3 |
| service-based and exposed, in all | 2,931 |

Most frequent services among the 2,928: `http` 2,314, `imap` 150, `pop3` 138,
`smtp` 131, `ftp-data` 95, `ftp` 94.

The three rules with implied services are sids 529, 3238 and 3239, each with
`dce_iface`, `dce_opnum` and `dce_stub_data`, which gives them `dcerpc` and
`netbios-ssn`. Their selective predicates are `{protocol, dst_ip}`: each
port list contains a range (`1024:`), which falls back, so none constrains a
port. None is P4-eligible in the strong-discriminator partition. The other
1,060 NECESSARY rules without `service:` use only core options (content,
pcre, flow, byte and ICMP/IP header options), none of which sets an
inspector buffer or matches a `guess_service` prefix;
`tests/test_service_header_semantics.py::test_opcoes_do_ruleset_classificadas`
checks this over the manifest.

## 4. Plan-Level Coverage

For each exposed rule, the region Snort can alert on when the service is
identified is {rule addresses} × {any port} × {any protocol}. The table asks
whether an installed port-free entry contains that region.

| Plan | Whole region | TCP part only | None |
|---|---:|---:|---:|
| Global, 331 entries | 2,919 + 3 | 9 | 0 |
| Strong discriminator, 322 entries | 0 | 0 | 2,928 + 3 |

The "+ 3" are the rules with implied services, reported separately in the
artifact (`expostas_por_servico_implicito`); `p4-40` covers all three. The
strong plan does not prefilter them: they are in its operational fallback,
whose rules apply to every packet.

In the global plan, `p4-40` (destination `HOME_NET`) and `p4-138` (source
`HOME_NET`) carry no port or protocol, and `p4-106` covers every TCP packet.
The nine partial cases are sids 1415 and 1416 (SNMP over UDP to
255.255.255.255), 1941 (TFTP over UDP, any to any), 28852, 29174 and 38993
(HTTP, any to any), and 56583 to 56585 (Kerberos, any to any): for these a
non-TCP packet of the service on another port would not be marked candidate.

The strong-discriminator policy removed the nine entries that constrain at
most the protocol and exactly `HOME_NET`. It keeps six port-free entries
(`p4-23`, `p4-84`, `p4-85`, `p4-99`, `p4-116`, `p4-289`), which carry TCP flags
or other addresses, and none of them contains the region of any exposed rule.

A header that names a service protocol instead of an IP protocol is an
exception to §2.4. `SetupRTNFuncList` marks such a rule `USER_MODE`, and
`fp_eval_rtn` then forces `check_ports = 1`, so its ports stay checked. The
twelve NECESSARY rules of the form `alert http ... -> ...` are therefore not
exposed, and none declares `service:`. An earlier revision of this document
left the three DCE rules unconfirmed; §2.3 now traces how their options add
services.

## 5. Why No Experiment Observed It

- The CICIDS2017 web windows carry HTTP on the header ports, and the alerts
  observed are dominated by non-HTTP sids (254, 399, 402, 650, 1394).
- The end-to-end campaign synthesizes each witness on the rule's own header
  port (`tests/campaign_witness.py`, "porta de servico coerente"), so it never
  places a service on a port outside the header.
- The campaign alerts that fall outside the alerting rule's own entries are all
  HTTP flush acknowledgments; the data packet of each of those requests
  matched the rule's own entries. They reflect stream attribution, not port
  skipping.

## 6. Effect on the Manuscript's Claims

| Claim | Effect |
|---|---|
| RQ1, 4,003 NECESSARY with `r => p_r` | Holds for the 1,060 port-based NECESSARY rules and the 12 `alert http ... -> ...` rules, whose ports Snort keeps checking (1,072 in all); for the 2,931 service-based ones (2,928 with `service:`, 3 with services implied by DCE options) the predicate is necessary only where Snort evaluates the full header. An address-only predicate would be necessary for them and selective for 2,924. |
| Predicate-level soundness argument (§4.4) | The premise `r(x) => H_r(x)` must exclude ports and protocol for service-based rules. |
| Global prefilter conservatism | Plan-level candidate-completeness holds for 2,922 of 2,931 exposed rules and for the TCP part of the rest, through broad port-free entries. |
| Global selectivity (100%) | Unaffected. |
| Strong-discriminator ablation | Not candidate-complete for any exposed rule when a service runs on a port outside its header. Its no-match packets cannot be taken as irrelevant to those rules. |
| Per-packet candidate rule sets, 91–96% (81–86% full ruleset) | Computed from port-constrained predicates, so they can omit a service-based rule for a packet of that service on another port. An address-only derivation for service-based rules would give larger sets, so the reported reductions are an upper bound on it. |
| Observed alert preservation and campaign verdicts | Stand as measured; they did not exercise off-header service ports. |

## 7. Changes in This Revision

The manuscript now states the Snort 3 service-based evaluation rule, scopes
`r => p_r` to port-based rules and to traffic evaluated with the full header,
reports the exposure and coverage numbers above, and qualifies the
strong-discriminator and candidate-set results accordingly. No frozen number
changes.

## 8. Required Before Claims Can Be Restored

1. **Compiler.** Implemented as an option, not as the default:
   `python compiler/generate_semantic_manifest.py --service-header-semantics snort3`
   delegates `protocol`, `src_port` and `dst_port` of service-based rules
   (reason `service_based_header_not_checked_on_service_match`) and keeps the
   protocol when the rule carries `flags`, because the TCP flags option
   returns NO_MATCH without a TCP header (`src/ips_options/ips_flags.cc`,
   `TcpFlagOption::eval`). Service-based means `service:` or an option through
   which §2.3 adds a service (`implied_service_options` in
   `compiler/target_capability.py`, which also counts the buffer-setting
   options the corpus calls service-specific even where their registration
   was not traced, since delegating only broadens), and a header that names an
   IP protocol: a `USER_MODE` header keeps its fields. The default `legacy`
   regenerates the frozen manifest and the rest of the pipeline byte for
   byte. Switching the default regenerates every frozen
   artifact and must go through a supersession document together with the
   trace re-runs of item 3.

   Structural effect, from `tests/whatif_service_header_semantics.py` →
   `output/analysis/service_header_semantics_whatif.json` (the same policy
   code first reproduces the frozen partition 3,611 / 392 / 322):

   | | legacy (frozen) | snort3 |
   |---|---:|---:|
   | NECESSARY / UNSUPPORTED | 4,003 / 14 | 3,996 / 21 |
   | predicate instances → final entries | 6,675 → 331 | 4,040 → 235 |
   | strong-discriminator eligible / fallback | 3,611 / 392 | 739 / 3,257 |
   | lower bound on applicable rules per packet | 406 | 3,278 |
   | upper bound on full-ruleset candidate reduction | 89.89% | 18.40% |

   Adding the three DCE rules to the `snort3` mode changed none of these
   numbers: they were already outside the strong-discriminator partition,
   and their entries merge with ones other rules produce.
2. **Data plane test (rig).** Prepared: `tests/generate_offport_service_cases.py`
   writes `output/campaign/servico_fora_do_cabecalho/` (200 HTTP rules with
   `service:http`, seed 20260927, 1,600 frames, pcap sha256 `b150423d…`). Each
   witness is the usual HTTP flow moved to destination port 18080, outside
   `HTTP_PORTS`; the wizard should still identify HTTP from the warm-up
   request and server response. For all 200, none of the rule's own entries
   matches the witness; the global plan predicts candidate (through `p4-3` or
   `p4-5`), and the strong plan predicts no-match with every rule still
   prefiltered. On the rig:

       python tests/run_campaign_bmv2.py --casos output/campaign/servico_fora_do_cabecalho
       python tests/run_campaign_bmv2.py --casos output/campaign/servico_fora_do_cabecalho \
           --plano output/campaign/plano_strong_discriminator/p4runtime_install_plan.json \
           --particao output/campaign/plano_strong_discriminator/particao.json --sufixo _strong

   If Snort skips the port, the global run reports CONFIRMED and the strong run
   reports VIOLATION for the alerting cases (exit code 1 is the expected
   outcome). If every case is VACUOUS in both runs, the source reading does not
   hold on the rig and this finding must be revisited.
3. **Recompute** the strong-discriminator partition, its trace-level rates,
   and the per-packet candidate rule sets from the corrected predicates.
   Done offline on 2026-09-27 (`tests/rederive_trace_metrics.py` →
   `output/analysis/trace_metrics_by_semantics.json`, windows cut from the
   downloaded capture and checked against the dataset record). The legacy
   pass reproduces the frozen post-correction values exactly; then, for
   SQLi / XSS / Brute Force under `snort3`:

   | | legacy (frozen) | snort3 |
   |---|---:|---:|
   | global candidate rate | 100% / 100% / 100% | 100% / 100% / 100% |
   | strong-discriminator candidate rate | 99.015% / 98.869% / 98.942% | 92.298% / 92.173% / 94.885% |
   | mean candidate set (eligible base) | 179.28 / 140.49 / 324.52 of 3,611 | 3.97 / 3.94 / 4.48 of 739 |
   | full-ruleset reduction | 85.43% / 86.40% / 81.81% | 18.30% / 18.30% / 18.29% |

   Offline, with the parser mirror and matcher of the frozen strong rates;
   no `snort3` plan has been installed on BMv2.

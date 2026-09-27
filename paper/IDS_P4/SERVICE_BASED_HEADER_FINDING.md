# Service-Based Rules: the Header Is Not a Necessary Condition

**Date:** 2026-09-27
**Status:** finding confirmed from the Snort 3.12.2.0 source and documentation;
not yet reproduced on the data plane. The manuscript is revised to state the
scope of its claims; the compiler is unchanged in this revision.

## 1. Summary

The compiler derives each NECESSARY predicate from the rule header and relies
on `r(x) => H_r(x)`: a packet on which the rule alerts satisfies the header
conditions the compiler represents. In Snort 3.12.2.0 this does not hold for
**service-based** rules. When the service Snort has identified for the flow is
one of the rule's services, Snort does not check the header ports or protocol;
it still checks the header addresses.

2,928 of the 4,003 NECESSARY rules declare `service:` and carry protocol and,
in almost every case, port conditions in their compiled predicate. For those
rules, the predicate-level relation `r => p_r` holds only on traffic where
Snort evaluates the full header.

The implemented 331-entry global plan remains candidate-complete for 2,919 of
the 2,928, and for the TCP part of the other nine, because it contains
port-free entries covering every packet to or from `HOME_NET` and every TCP
packet. The 322-entry strong-discriminator plan covers none of them, and the
per-packet candidate rule sets inherit the same gap.

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

### 2.3 What this means

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
| service-specific options without `service:` (not counted; mechanism unverified) | 15 |

Most frequent services among the 2,928: `http` 2,316, `imap` 150, `pop3` 138,
`smtp` 131, `ftp-data` 95, `ftp` 94.

## 4. Plan-Level Coverage

For each exposed rule, the region Snort can alert on when the service is
identified is {rule addresses} × {any port} × {any protocol}. The table asks
whether an installed port-free entry contains that region.

| Plan | Whole region | TCP part only | None |
|---|---:|---:|---:|
| Global, 331 entries | 2,919 | 9 | 0 |
| Strong discriminator, 322 entries | 0 | 0 | 2,928 |

In the global plan, `p4-40` (destination `HOME_NET`) and `p4-138` (source
`HOME_NET`) carry no port or protocol, and `p4-106` covers every TCP packet.
The nine partial cases are sids 1415 and 1416 (SNMP over UDP to
255.255.255.255), 1941 (TFTP over UDP, any to any), 28852, 29174 and 38993
(HTTP, any to any), and 56583 to 56585 (Kerberos, any to any): for these a
non-TCP packet of the service on another port would not be marked candidate.

The strong-discriminator policy removed exactly the port-free entries, so its
retained predicates constrain ports or protocol for every exposed rule.

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
| RQ1, 4,003 NECESSARY with `r => p_r` | Holds for the 1,075 NECESSARY rules without an explicit `service:` (15 of them use service-specific options and may also be service-based; unverified); for the 2,928 service-based ones the predicate is necessary only where Snort evaluates the full header. An address-only predicate would be necessary for them and selective for 2,921. |
| Predicate-level soundness argument (§4.4) | The premise `r(x) => H_r(x)` must exclude ports and protocol for service-based rules. |
| Global prefilter conservatism | Plan-level candidate-completeness holds for 2,919 of 2,928 exposed rules and for the TCP part of the rest, through broad port-free entries. |
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

1. **Compiler.** For rules with services, mark header port and protocol
   predicates as delegated with a reason such as
   `service_based_header_not_evaluated`, keep address predicates, and
   regenerate. This changes the frozen artifacts and must go through a
   supersession document.
2. **Data plane test (rig).** A campaign variant that places HTTP witnesses of
   service-based rules on a port outside `HTTP_PORTS` (for example 8000),
   which the wizard should still identify. Expected under the source above:
   Snort alerts, the rule's own predicate is false, the global plan marks the
   packet candidate through `p4-40`/`p4-106`, and the strong plan marks it
   no-match.
3. **Recompute** the strong-discriminator partition, its trace-level rates,
   and the per-packet candidate rule sets from the corrected predicates.

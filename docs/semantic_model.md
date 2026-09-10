# Semantic Model

This document describes the semantic model used by the Snort-to-P4
compiler: what a rule means to the compiler, how that meaning is
represented, and which guarantee each generated data-plane predicate
carries.

It is the conceptual companion of `snort3_support_matrix.md`, which records
per-construct support status. Where this document states a rule, the
authoritative implementation is `compiler/semantic_ir.py`,
`compiler/target_capability.py`, and `compiler/semantic_classifier.py`.

---

## 1. Why a semantic model is needed

A Snort 3 rule is not a single match-action entry. One rule can combine
header conditions, payload inspection, buffer/cursor semantics, flow and
stream state, temporal conditions, service/application semantics, and
post-detection actions. A programmable data plane can evaluate only a
subset of these.

Translating only the representable subset, without recording what was left
out, would present a partial implementation as if it were the original
rule. The semantic model exists to keep that distinction explicit and
auditable at every stage of compilation.

---

## 2. Compilation stages

```
Snort 3 rule text
  -> parser                       (compiler/parser.py)
  -> variable resolution          (compiler/variable_resolver.py)
  -> option normalization         (compiler/option_normalizer.py)
  -> semantic IR                  (compiler/build_semantic_ir.py)
  -> target capability analysis   (compiler/target_capability.py)
  -> semantic classification      (compiler/semantic_classifier.py)
  -> compilation manifest         (compiler/semantic_manifest.py)
  -> P4 backend + lowering        (compiler/p4_backend.py, lower_p4_entries.py)
  -> P4Runtime install plan       (compiler/generate_p4runtime_install.py)
```

Two separations are deliberate:

- **Meaning is separated from capability.** The IR describes what a rule
  component means; only the capability stage decides whether the current
  target can execute it.
- **Capability is separated from classification.** The capability stage
  annotates individual predicates; only the classifier decides what
  guarantee the rule as a whole can carry.

---

## 3. Semantic IR

The IR of a rule (`SemanticRuleIR`) holds `rule_id`, `action`, `rule_type`,
the original `raw_rule`, an ordered list of predicates, and `metadata`.

Each `SemanticPredicate` records `kind`, `operator`, `value`, and optionally
`field`, `buffer`, and `modifiers`, plus `source_option` and `source_index`.

`source_index` preserves the original option order. This matters for
options whose meaning depends on the current buffer, the cursor position,
or a preceding option; discarding order would silently change semantics.

### 3.1 Predicate kinds

| Kind | Meaning | Examples |
|---|---|---|
| `HEADER` | Condition over packet header fields | protocol, `src_ip`, `dst_port`, `flags`, direction |
| `PAYLOAD` | Content inspection over a buffer | `content`, `pcre` |
| `BUFFER` | Buffer or cursor selection/manipulation | sticky buffers, byte operations |
| `APPLICATION` | Service or application-layer semantics | `service:` on service-style rules |
| `FLOW_STATE` | Flow, stream, or cross-packet state | `flow`, `flowbits`, stream conditions |
| `TEMPORAL` | Time- or rate-dependent conditions | `detection_filter` |
| `POST_DETECTION` | Actions applied after a detection decision | `react`, `tag` |
| `METADATA` | Non-detection bookkeeping | `msg`, `reference`, `classtype` |

Nothing is dropped: every option that the parser recognizes becomes a
predicate, including options the backend cannot execute.

### 3.2 Backend treatments

The capability stage annotates each predicate with exactly one treatment:

| Treatment | Meaning for the generated predicate |
|---|---|
| `PRESERVED` | Represented in the data plane without relaxation |
| `EXPANDED` | Represented as a union of concrete entries (finite lists, `<>`, flag `*`) |
| `DELEGATED` | Not represented in P4; Snort remains responsible for it |
| `FALLBACK` | Recognized but not safely representable; omitted from the predicate, which becomes broader |
| `UNASSESSED` | Not evaluated by the current capability profile |
| `OUT_OF_SCOPE` | Non-detection metadata; excluded from equivalence reasoning |

`DELEGATED` and `FALLBACK` differ in intent. `DELEGATED` means the
condition belongs to Snort by design (payload, state, service).
`FALLBACK` means the compiler recognized a header form it cannot encode
safely — a port range, a negation, an unsupported flag encoding — and
deliberately omitted it. Both omissions can only broaden the predicate,
never narrow it, which is what keeps the necessary relation intact.

---

## 4. Target capability profile

The current profile (`compiler/target_capability.py`) accepts:

- L3/L4 protocols `tcp`, `udp`, `icmp`; `ip` is treated as a wildcard;
- header fields `protocol`, `src_ip`, `dst_ip`, `src_port`, `dst_port`,
  `direction`, `flags`;
- IPv4 addresses and CIDR expressions, canonicalized to network/prefix;
- exact ports, and finite address/port lists, expanded by Cartesian
  product;
- accepted TCP-flag syntax, normalized to value/mask, with `*` lowered to
  a union of entries;
- `->` directly, and `<>` by materializing both orientations.

Explicitly not executable by this backend: payload content, PCRE, stream
reassembly, arbitrary flow state, protocol normalization, port ranges,
negated header expressions, and `<-`. A set of further header fields
(`ttl`, `id`, `seq`, `ack`, `itype`, `icode`, `fragbits`, and others) is
recognized as plausible future P4 work but is not assessed by the current
profile.

---

## 5. Semantic classes

The classifier assigns one class per rule.

### EXACT

Every detection-relevant predicate is represented without relaxation: no
`DELEGATED`, no `FALLBACK`, and no `UNASSESSED` predicate remains
(`OUT_OF_SCOPE` metadata is ignored for this test). Only in this case could
the data plane hold the detection decision.

`EXACT` is a class the classifier supports, not a claim the current
prototype exercises. The evaluated Snort 3 Community ruleset produced
`EXACT = 0`, and the P4 program implements a single positive
`send_to_ids` candidate action rather than a general detection action.

### NECESSARY

At least one *selective* represented predicate exists, but some detection
semantics remain delegated or unrepresentable. The generated predicate is a
conservative prefilter: matching traffic still requires Snort inspection.

### UNSUPPORTED

No safe selective predicate can be derived. No P4 entry is emitted and the
whole rule stays in the Snort fallback partition. `UNSUPPORTED` means "not
safely representable here", never "ignored".

### 5.1 What counts as selective

A predicate contributes to selectivity only if it is `PRESERVED` or
`EXPANDED` **and** actually restricts the packet set:

- protocol: selective for `tcp`/`udp`/`icmp`; `ip` is a wildcard and is not;
- addresses and ports: selective when concrete or a non-empty finite list;
  `any` is not;
- flags: selective;
- direction: **not** selective on its own — it changes orientation but does
  not reduce the packet set when addresses and ports are wildcards.

This is why a rule can have several represented predicates and still be
`UNSUPPORTED`: represented is not the same as selective.

---

## 6. The safety relation

For a rule $r$ and its generated predicate $p_r$, write $H_r$ for the
conjunction of conditions marked `PRESERVED` or `EXPANDED`, and $U_r$ for
everything else (delegated, fallback, unassessed). Let $L$ be backend
lowering. The intended relation for a `NECESSARY` rule is:

```
r(x)  =>  H_r(x)  =>  L(H_r)(x)  =  p_r(x)
```

- The first implication holds because $H_r$ is a subset of the rule's own
  conjunction.
- The second holds because lowering only relaxes: omissions broaden,
  finite lists become unions, CIDRs become prefix masks, `<>` becomes both
  orientations.

The converse is **not** claimed. $p_r \Rightarrow r$ and
$r \Leftrightarrow p_r$ are false in general, which is precisely the
difference between `NECESSARY` and `EXACT`.

### 6.1 The packet-domain precondition

The relation above holds only for packets the data plane can parse as
intended. `p4/ids_prefilter.p4` therefore defines an explicit **supported
packet domain**: untagged Ethernet carrying direct IPv4, with `version = 4`,
`IHL = 5`, `fragOffset = 0`, and flags either `0` or `DF`.

Anything else — non-IPv4 EtherTypes, IPv4 options, fragments, truncated
headers, parser errors — is routed to `packet_domain_fallback`, which marks
the packet as a **candidate** and counts it separately. The data plane fails
open: it never classifies an unparsed packet as a no-match, because a
no-match is the only outcome that could ever justify bypassing Snort.

This is a load-bearing part of the safety argument. A fixed 20-byte IPv4
parse that ignored `IHL` would read option bytes as L4 ports, so a packet
satisfying the source rule could fail its own generated predicate, breaking
$r \Rightarrow p_r$. The domain gate converts that hazard into a
conservative candidate instead.

Counter layout in the P4 program:

| Index | Category | Meaning |
|---:|---|---|
| 0 | `P4_CANDIDATE` | matched an installed predicate inside the supported domain |
| 1 | `P4_NO_MATCH` | inside the supported domain, matched nothing |
| 2 | `PACKET_DOMAIN_FALLBACK` | outside the supported domain; conservative candidate |

These three categories must be reported separately. Collapsing fallback
into no-match would overstate selectivity; collapsing it into candidate
would hide the parser's real coverage.

---

## 7. Compilation manifest

For each rule the manifest records the source syntax, the semantic IR, the
per-predicate capability treatment, the assigned class, the capability
reasons, and the variable-resolution log. It keeps preserved, delegated,
fallback, and unsupported semantics visible instead of collapsing them into
a single "translated" flag.

The manifest is also what makes provenance possible downstream: each final
P4 entry retains the `source_rule_ids` it was derived from. Because
deduplication merges only identical matches, provenance sets are unioned
rather than lost, so a per-packet candidate rule set can be recovered from
the entries a packet matched.

---

## 8. Reading guarantees correctly

| Statement | Supported? |
|---|---|
| A `NECESSARY` predicate keeps every packet its source rule would match, within the supported packet domain | Yes |
| A P4 candidate match means Snort would alert | No |
| `EXACT = 0` means the compiler failed | No — it means no rule had all its semantics represented, and the classifier refuses to call partial preservation equivalence |
| `UNSUPPORTED` rules are dropped | No — they stay in the Snort fallback partition |
| A `P4_NO_MATCH` packet can safely bypass Snort | No — fallback and `UNSUPPORTED` rules still apply |
| High `NECESSARY` coverage implies a selective prefilter | No — semantic safety and operational selectivity are independent properties |

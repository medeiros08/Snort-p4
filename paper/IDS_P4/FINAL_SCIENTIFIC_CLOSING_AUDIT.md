# Final Scientific Closing Audit

## 1. Executive summary

**Final recommendation: NOT_READY.** The closing pass reached the requested
hard stop during static implementation review. The P4 parser extracts a fixed
20-byte IPv4 header and transitions directly to TCP, UDP, or ICMP based on the
protocol field. It does not validate `ihl` or advance over IPv4 options before
extracting the L4 header. By contrast, the offline matcher used by the frozen
selectivity and candidate-set analyses computes the L4 offset from `ihl`.

This difference can invalidate the manuscript's general predicate-level claim
`r => p_r`. A direct IPv4 packet with `IHL > 5` can contain a genuine TCP
destination port required by a Snort rule after the option bytes, while the P4
parser reads option bytes as the TCP ports. The generated P4 predicate can then
fail for traffic satisfying the source rule. This is an implementation gap,
not merely a missing qualification, and triggers hard-stop condition 1.

No new traffic experiment was run, no frozen artifact was regenerated, and no
policy or result was changed. After identifying the blocker, no further
scientific edit was applied to `main.tex`. The already-applied pre-blocker
changes are listed in Section 15 and in `FINAL_CHANGELOG.md`; the new soundness
language in the current manuscript must not be treated as submission-ready.

## 2. Semantic implementation audit

| Construct | Source to IR / capability treatment | Backend / P4 treatment | Static classification |
|---|---|---|---|
| `tcp`, `udp`, `icmp` | Traditional protocol predicate; preserved | IPv4 protocol ternary key | SAFE_BY_CONSTRUCTION only after a correct parser has exposed the intended headers |
| `ip` | Protocol wildcard; preserved | L4 protocol key omitted | SAFE_UNDER_EXPLICIT_ASSUMPTION (direct, valid IPv4) |
| IPv4 address/CIDR | Address predicate; whole-field variables resolved before assessment | Canonical network/prefix, then P4Runtime ternary mask | SAFE_BY_CONSTRUCTION for accepted IPv4/CIDR forms |
| Exact port | Port predicate; preserved | Exact 16-bit ternary key | **IMPLEMENTATION_GAP** for IPv4 options and non-initial fragments because the P4 parser can read the wrong bytes as L4 ports |
| Finite address/port list | Accepted only when all alternatives are supported; expanded | Cartesian product of concrete alternatives | SAFE_BY_CONSTRUCTION as a union, subject to the parser gap for L4 fields |
| Range or negation | Fallback/unassessed | Field omitted from the predicate | FALLBACK_REQUIRED; omission broadens the predicate |
| `any` | Nonselective/wildcard value | Match field omitted | SAFE_BY_CONSTRUCTION as relaxation |
| Direction `->` | Forward orientation preserved | Source/destination orientation retained | SAFE_BY_CONSTRUCTION, subject to correct parsed fields |
| Direction `<>` | Expanded | Forward plus reverse entries, including swapped IPs, ports, and expansion metadata | SAFE_BY_CONSTRUCTION as a union, subject to correct parsed fields |
| Direction `<-` | Fallback | Direction omitted | FALLBACK_REQUIRED |
| Variables | Whole-field resolution and list flattening before assessment | Resolved values lowered normally | SAFE_UNDER_EXPLICIT_ASSUMPTION that the frozen profile is the intended source semantics |
| Accepted TCP flags | Normalized to value/mask; `*` is expanded | Ternary flag entries; `*` becomes a union over tested bits | SAFE_UNDER_EXPLICIT_ASSUMPTION for accepted forms, but affected by the same L4-offset parser gap |
| Service-style rules | Service header retained as application semantics; no traditional header invented | No entry without another selective represented header | DELEGATED / UNSUPPORTED in the frozen service cases |
| Content, buffers, PCRE, byte operations | Ordered semantic predicates retained in IR/manifest | No P4 match | DELEGATED |
| Flow/state, flowbits, stream, temporal semantics | Retained as non-header semantic predicates | No P4 match | DELEGATED; general stateful preservation is not established |
| Protocol-dependent normalization/reassembly | Recorded outside the P4 capability profile | Not reproduced by the P4 program | DELEGATED, with an IMPLEMENTATION_GAP where parser extraction is nevertheless used to enforce L4 keys |
| Deduplication | Identical normalized/lowered matches only | Provenance sets unioned; common positive action retained | SAFE_BY_CONSTRUCTION for the logical candidate union |
| P4Runtime encoding | Validates widths and P4Info identifiers | Exact/ternary byte encoding | SAFE_BY_CONSTRUCTION for the supplied normalized keys |

The frontend, capability analysis, list expansion, direction expansion, CIDR
normalization, fallback treatment, deduplication, and P4Runtime encoding did not
otherwise reveal a narrowing transformation in the frozen build. The blocking
issue is the concrete parser-to-match interpretation of L4 fields.

## 3. Soundness argument

The intended argument decomposes a rule as `r = H_r AND U_r`, where `H_r`
contains conditions selected for P4 representation and `U_r` contains
delegated or fallback semantics. If lowering `L` satisfies
`H_r(x) => L(H_r)(x)`, then `r(x) => H_r(x) => p_r(x)` for
`p_r = L(H_r)`.

The implementation does not currently establish the second implication for
all traffic admitted by the stated Ethernet/IPv4 scope. In
`p4/ids_prefilter.p4`, `parse_ipv4` extracts a fixed header and immediately
selects `parse_tcp`, `parse_udp`, or `parse_icmp`; it neither advances by the
actual `ihl` nor rejects `IHL != 5`. Consequently, a source L4 condition can be
lowered to a table field populated from different bytes. The proof premise
`H_r => L(H_r)` therefore fails for an IPv4-options counterexample.

This audit does not claim a machine-checked proof or end-to-end Snort
equivalence. It concludes that even the proposed predicate-level argument is
blocked until the parser/matcher correspondence is repaired and validated.

## 4. Constructs verified

The following transformations were verified statically and are not the source
of the blocker:

- accepted finite lists are expanded as a Cartesian-product union;
- `<>` generates forward and reverse orientations and swaps source/destination
  addresses, ports, and expansion metadata together;
- IPv4/CIDR values are canonicalized and encoded using prefix ternary masks;
- ranges, negation, unresolved expressions, and unsupported flag forms do not
  become narrower exact keys;
- accepted TCP-flag forms are represented with ternary masks, and `*` is
  lowered to a union of entries;
- deduplication merges identical matches and unions source-rule provenance;
- the final P4Runtime encoder checks field widths and P4Info names/IDs.

These properties are necessary but insufficient to restore the global
soundness claim while the parser can populate L4 keys from the wrong offset.

## 5. Assumptions

The intended predicate relation additionally relies on all of the following:

- the frozen `cicids2017` variable profile is the intended Snort environment;
- traffic is untagged Ethernet carrying direct IPv4;
- L4 headers are present and well formed for the selected IPv4 protocol;
- IPv4 packets have no options (`IHL = 5`) and are not non-initial fragments;
- accepted TCP-flag syntax has the semantics implemented by the normalizer;
- omitted payload, stream, flow/state, temporal, service, and normalization
  conditions remain evaluated by Snort.

The critical problem is that the current P4 program does not enforce the
`IHL = 5` assumption before applying port/flag matches. The frozen parser
coverage artifacts record zero observed direct-IPv4 fragments for SQLi and
XSS (and zero among held-out candidate-alert packets), but they contain no
`IHL`/IPv4-options audit. No new PCAP analysis was performed to fill that gap.

## 6. Implementation gaps

### Blocking gap: IPv4 options

- `p4/ids_prefilter.p4` uses a fixed 20-byte `ipv4_t` and immediately parses
  L4.
- `tests/analyze_prefilter_selectivity.py::parse_frame_like_p4` instead uses
  `l4_offset = ip_offset + ihl`.
- `tests/analyze_p4_parser_coverage.py` treats direct IPv4 with at least 20
  bytes as parser eligible and does not report `IHL` values.
- Therefore, the offline matcher is not a faithful model of the P4 parser for
  IPv4-options traffic, and existing frozen artifacts do not establish that
  the mismatch is absent from every evaluated parser-eligible packet.

### Fragmentation boundary

The P4 parser also does not gate TCP/UDP extraction on `fragOffset == 0`.
Existing frozen coverage reports zero observed direct-IPv4 fragments for the
SQLi/XSS traces, so no inconsistency is asserted for those recorded runs. The
general implementation nevertheless needs an explicit fragmentation policy
before a cross-traffic predicate-level guarantee can be made.

### Prototype action scope

The P4 program has one positive `send_to_ids` action. `EXACT` is a semantic
classifier category, not a general direct data-plane detection action.

## 7. EXACT status

The frozen Community-ruleset result remains `EXACT = 0`,
`NECESSARY = 4003`, and `UNSUPPORTED = 14`. The repository contains a legacy
component-level semantic-model test with a header-only EXACT expectation, but
there is no trace-based EXACT result for the frozen Community ruleset. No
frozen value was changed.

## 8. UNSUPPORTED explanation

The 14 frozen UNSUPPORTED rules comprise four traditional rules and ten
service-style rules. The four traditional cases have nonselective represented
headers while payload or byte-level conditions remain delegated. The ten
service-style cases retain delegated service, flow, buffer, payload, and in
some cases PCRE or byte/BER semantics; the compiler correctly does not invent
traditional headers for them. No safe selective predicate is therefore
emitted, and every rule remains in Snort fallback rather than being ignored.

## 9. NECESSARY explanation

The 4,003 NECESSARY rules typically combine at least one selective represented
header with delegated content/payload-buffer, flow/state, service/application,
or PCRE semantics. A smaller set contains a fallback port range, negated port,
or unsupported flag encoding but still has another selective represented
header. This is a semantic classification, not complete offload. Because of
the parser blocker, the current implementation has not established the claimed
necessary implication over the entire stated Ethernet/IPv4 input scope.

## 10. Conservative fallback-aware candidate-space analysis

The secondary quantity is deterministically derivable from the frozen
partitions, but it was **not added to the manuscript after the hard stop**. The
3,611-rule P4-eligible partition, 392 operational fallback rules, and 14
semantic UNSUPPORTED rules are disjoint and sum to 4,017. Under the explicit
conservative accounting assumption that all 406 fallback rules remain
applicable to every parser-eligible packet:

`E(x) = |C(x)| + 392 + 14`, relative to a 4,017-rule baseline.

| Trace | Frozen mean `|C(x)|` | Fixed fallback | Mean `E(x)` | Conservative candidate-space reduction vs. 4,017 |
|---|---:|---:|---:|---:|
| SQLi | 179.2847898293437 | 406 | 585.2847898293437 | 85.43% |
| XSS | 140.48995641964078 | 406 | 546.4899564196407 | 86.40% |
| Held-out Brute Force | 324.5180653215007 | 406 | 730.5180653215007 | 81.81% |

The arithmetic was checked independently by confirming
`3611 + 392 + 14 = 4017` and recomputing each primary mean from the frozen
reduction formula before adding 406. This is an always-applicable candidate
space accounting view, not the number of rules dynamically executed by Snort,
not processing cost, and not a speedup. The primary 95.04%, 96.11%, and 91.01%
metrics remain unchanged and retain their 3,611-rule denominator.

## 11. Alert diversity

Frozen reports contain the following finite observed diversity:

| Trace | FULL alert events | Unique SIDs | SIDs |
|---|---:|---:|---|
| SQLi (development/diagnostic) | 150 | 1 | 254 |
| XSS (development/diagnostic) | 528 | 2 | 254, 402 |
| Brute Force (held-out) | 2,391 | 5 | 254, 399, 402, 650, 1394 |

The recorded 100% preservation concerns these finite observed alert events and
does not imply semantic coverage of all 4,017 rules, complete detection
preservation, or stateful execution equivalence. The trace labels also do not
show that the fired rules detected the CICIDS2017 ground-truth attack labels.
No policy was retuned after observing Brute Force.

## 12. Reproducibility improvements

The following information was verified from repository sources but was not
inserted into `main.tex` after the hard stop:

- Snort++ 3.12.2.0 is recorded in the frozen build logs.
- The precise ruleset source is `rules/snort3-community.rules` (4,017 rules).
  A read-only checksum of the current file is
  `8c0d9172127a7270ec8084ffbd16d3995df6d27aa0ccc232638f5f0293e68e19`.
- The target is BMv2/v1model; the installer uses device ID 0 and P4Runtime
  endpoint `127.0.0.1:9559`.
- The table capacity is 8,192 entries; 331 final entries are encoded.
- The active profile is `cicids2017`, with
  `HOME_NET = 192.168.10.0/24`; the appendix records the complete profile and
  disabling of default `file_magic.rules` through `file_inspect = {}`.
- SQLi and XSS are development/diagnostic windows; Brute Force is held out.
- Quantitative replay uses the raw AF_PACKET path rather than
  `PcapReader/sendp` without accounting validation.
- Parser accounting separates P4_CANDIDATE, P4_NO_MATCH, and
  PARSER_INELIGIBLE.
- The project directory is not a Git repository, so no commit identifier can
  be reported.

The absent IHL/options audit is now a reproducibility and correctness blocker,
not merely missing environmental detail.

## 13. Claim audit

The global vocabulary search covered safe/safety, sound/soundness, preserve,
preservation, guarantee, correct/correctly, equivalent/equivalence, offload,
offloading, bypass, reduction, acceleration, and speedup.

Claims about frozen counts, installation-state reduction, candidate rates
among parser-eligible packets, offline candidate sets, and finite observed
alerts remain properly scoped. Related Work does not claim “first,” “only,” or
absence of capabilities not established by the reviewed sources. Performance,
dynamic candidate-set execution, and end-to-end stateful equivalence remain
explicitly unclaimed.

The following current manuscript claims are blocked by the parser finding and
must not be accepted as established until implementation and validation are
repaired:

- Abstract: the compiled predicate “conservatively retains every packet
  satisfying the source rule.”
- Introduction and Background: unqualified safe necessary prefilter wording.
- Problem Formulation: the `r => H_r => L(H_r) = p_r` argument over the stated
  Ethernet/IPv4 scope.
- Compilation-semantics table: port and TCP-flag guarantees that omit the
  IPv4-options/fragment parser precondition.
- RQ1 answer, Discussion, and Conclusion: statements that the compiler has
  established `r => p_r` for the evaluated target profile.

Per the hard-stop instruction, these passages were not rewritten to hide the
gap.

## 14. Numerical consistency

All requested frozen values remain internally consistent in `main.tex` and the
official summary: 4,017 parsed rules; 4,003 NECESSARY; 14 UNSUPPORTED; 0 EXACT;
6,675 generated/expanded/normalized predicate instances; 327 unique matches
before flag lowering; 331 final entries; 95.04% installation-state reduction;
3,611 P4-eligible rules; 392 operational fallback rules; strong candidate
rates of 99.015%, 98.869%, and 98.941%; 11,662 held-out no-matches; candidate
set means 179.28, 140.49, and 324.52; primary reductions 95.04%, 96.11%, and
91.01%; 2,391 held-out alerts; 2,289 strong-eligible events; and observed
candidate-set SID membership of 2,289/2,289.

Denominators, development/held-out labels, parser-eligible scope, semantic
versus operational fallback, candidate versus no-match, and offline versus
runtime interpretations are consistent. This numerical check does not resolve
the semantic parser blocker.

## 15. Manuscript modifications

Before the blocker was identified, `main.tex` received these localized edits:

1. Added `Predicate-Level Soundness of Partial Compilation`.
2. Qualified EXACT as a semantic class while noting the implemented common
   `send_to_ids` candidate action.
3. Added a compilation-semantics table grounded in the inspected compiler.
4. Added backend details for list/direction expansion, normalization, TCP-flag
   lowering, P4Runtime encoding, deduplication, and provenance union.
5. Qualified the legacy EXACT unit scenario and retained Community-ruleset
   `EXACT = 0`.
6. Added artifact-derived explanations for the 14 UNSUPPORTED rules and common
   NECESSARY causes.

`SEMANTIC_SOUNDNESS_AUDIT.md` was also created before the parser discrepancy
was found. Its “no implementation gap” conclusion is superseded by this final
audit. After the hard stop, `main.tex` received no conservative metric, alert
diversity, reproducibility, claim-language, or stylistic revision.

## 16. Remaining reviewer concerns

### Potential reject reasons

- The central predicate-safety implication is not established by the actual
  parser for IPv4 options.
- The offline matcher labeled as P4-like is behaviorally different from the
  P4 parser at the L4 offset.
- Repairing the implementation would require revalidation of frozen results,
  including the held-out result, which the current freeze forbids.

### Major concerns

- Technical soundness and semantic argument: blocked.
- Implementation-to-analysis fidelity: blocked for IPv4 options.
- The current manuscript contains pre-blocker safety language that is too
  broad for the implementation.

### Minor concerns

- Alert diversity is limited (one, two, and five unique SIDs across the three
  traces).
- Only one held-out window, one ruleset, and one experimental profile were
  evaluated.
- No EXACT rule occurred in the evaluated Community ruleset.
- The paper is visually readable but long, and landscape tables generate
  numerous non-fatal underfull-box warnings.

### Reviewer questions likely to remain

- How does the data plane treat IPv4 options and fragmentation?
- Why does the offline parser advance by IHL when the P4 parser does not?
- Were all packets underlying the offline candidate-set distributions verified
  to have IHL 5?
- After a parser repair, do SQLi, XSS, and held-out Brute Force retain the same
  packet and candidate-set results without policy retuning?
- How would provenance be consumed safely by a stateful Snort execution path?

## 17. New experiments still needed

The following work is necessary to establish the current central safety claim,
but was not performed:

1. Repair the P4 parser or explicitly gate unsupported IPv4-option and
   fragmentation cases before applying L4 predicates.
2. Make the offline matcher bit-for-bit faithful to the P4 parser semantics.
3. Add controlled regression/dataplane tests with IPv4 options, first and
   non-initial fragments, truncated headers, ports, and TCP flags.
4. Rebuild and revalidate all affected static/runtime artifacts, then verify
   SQLi, XSS, and held-out Brute Force without retuning. This includes an IHL
   distribution/accounting audit.

Additional experiments would be needed for stronger future claims: dynamic
candidate-set-aware stateful Snort execution, throughput/latency measurement,
hardware-target validation, broader rulesets/profiles, and broader traffic and
encapsulation coverage. None was run in this task.

## 18. Final recommendation

**NOT_READY.** Novelty, related-work positioning, frozen numerical accounting,
claim discipline outside the blocker, and presentation are generally strong.
Experimental design correctly distinguishes development from held-out traces
and offline feasibility from runtime performance. However, technical soundness
and the central semantic argument are blocked by a concrete parser/matcher
discrepancy capable of violating `r => p_r`. This cannot be closed through
wording alone under the requested hard-stop rule.

## 19. Compilation status

A clean mechanical build was run after the hard stop without editing
scientific content:

- `latexmk -C`: success.
- `latexmk -pdf -interaction=nonstopmode main.tex`: exit status 0.
- PDF: 29 pages, 373,568 bytes.
- Fatal errors: 0.
- Undefined citations: 0.
- Undefined references: 0.
- Overfull boxes greater than 10 pt: 0 (largest remaining overfull is about
  8.52 pt).
- Underfull-box warnings: 42, primarily narrow cells in the two landscape
  tables; non-fatal.
- Font warnings: 0.
- BibTeX ran and `main.bbl` exists.

Visual inspection covered the title page, Related Work table, compilation
semantics table, result tables, conceptual figure, appendix profile, and
bibliography. No clipping, overlap, unreadable glyph, or broken reference was
observed. The compilation-semantics table and conceptual figure are readable,
but their scientific soundness annotations remain subject to the blocker
above.

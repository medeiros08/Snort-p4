# Parser Packet-Domain Reconciliation

## 1. Purpose

`FINAL_SCIENTIFIC_CLOSING_AUDIT.md` ended with **NOT_READY** because of one
blocking implementation gap: the P4 parser extracted a fixed 20-byte IPv4
header and moved directly to L4, so a packet with IPv4 options could have its
option bytes read as transport ports, breaking `r => p_r`. Under the
requested hard stop, `main.tex` was left unedited from that point on.

The repair and its revalidation were subsequently carried out in the
repository, but the manuscript was never brought back into agreement with
them. This document reconciles the two: it records what changed in the
implementation, what evidence establishes the repair, and which manuscript
passages were updated as a result.

**Status of the blocker: RESOLVED.** The `NOT_READY` recommendation in
`FINAL_SCIENTIFIC_CLOSING_AUDIT.md` §§1, 3, 6, 13, 16, and 18 is superseded
for the parser blocker specifically. Its remaining minor concerns and its
untouched scientific observations continue to apply.

## 2. Timeline reconstructed from artifact timestamps

| When (2026) | Artifact | Event |
|---|---|---|
| Sep 1, 15:03 | `main.tex` | last pre-blocker manuscript edit |
| Sep 1, 17:31 | `FINAL_SCIENTIFIC_CLOSING_AUDIT.md` | blocker identified; `NOT_READY`; hard stop |
| Sep 1, 20:44 | `p4/ids_prefilter.p4` | packet-domain gate implemented |
| Sep 1, 20:55 | `output/analysis/ipv4_packet_domain_guard_test.json` | controlled data-plane suite, 11/11 PASS |
| Sep 1, 20:56 | `.../ipv4_packet_domain_correction/selectivity_revalidation.json` | SQLi/XSS revalidation |
| Sep 1, 21:13 | `.../ipv4_packet_domain_correction/heldout_bruteforce_revalidation.json` | held-out revalidation |
| Sep 2, 17:35 | `.../REPLAY_ACCOUNTING_VALIDATION.md` | SQLi replay accounting, exact |
| Sep 5, 11:56 | `.../replays/bruteforce_*.txt` | held-out replay, not yet reconciled |
| Sep 9 | this document; `REPLAY_ACCOUNTING_VALIDATION_XSS_BRUTEFORCE.md`; `main.tex` | reconciliation |

The manuscript predates both the blocker and its repair, which is why its
pre-blocker safety language survived unqualified.

## 3. What the implementation now does

`p4/ids_prefilter.p4` defines an explicit supported packet domain `D`:
untagged Ethernet carrying direct IPv4 with `version = 4`, `IHL = 5`,
`fragOffset = 0`, flags `0` or `DF`, and no parser error.

- The parser transitions to L4 extraction only on
  `select(version, ihl, flags, fragOffset)` matching `(4,5,0,0)` or
  `(4,5,2,0)`; every other frame is accepted without L4 extraction.
- `MyIngress` re-checks `parser_error`, `ipv4.isValid()`, `version`, `ihl`,
  `fragOffset`, and the flag values before applying `ids_prefilter`.
- Out-of-domain frames execute `packet_domain_fallback()`, which sets
  `prefilter_candidate = 1` and counts index 2. They are never counted as
  no-matches, so no bypass decision can rest on an unparsed frame.

The resulting property is total over input traffic:

```
r(x) => p_r(x) => cand(x)   for x in D
r(x) => cand(x)             for x not in D   (unconditional fallback)
```

The counterexample that blocked the earlier audit — a genuine TCP port
sitting after IPv4 option bytes — now yields a conservative candidate rather
than a wrong table lookup.

## 4. Status of the four remediation items

`FINAL_SCIENTIFIC_CLOSING_AUDIT.md` §17 listed four required actions.

| # | Required action | Status | Evidence |
|---:|---|---|---|
| 1 | Repair the parser or gate IPv4 options and fragmentation before L4 predicates | **DONE** | `p4/ids_prefilter.p4` parser `select` and ingress guard |
| 2 | Make the offline matcher faithful to the P4 parser | **DONE** | `tests/p4_packet_domain.py` is the single shared classifier, imported by `analyze_prefilter_selectivity.py`, `analyze_p4_parser_coverage.py`, and `test_ipv4_packet_domain_guard.py`; `evaluate_heldout_bruteforce.py` inherits it transitively |
| 3 | Controlled regression tests for options, fragments, truncation, ports, flags | **DONE** | `output/analysis/ipv4_packet_domain_guard_test.json`, 11 cases, 0 failures |
| 4 | Rebuild and revalidate affected artifacts on all three traces without retuning | **DONE for the offline analyses; PARTIAL for the held-out data-plane replay** | `selectivity_revalidation.json`, `heldout_bruteforce_revalidation.json` (`policy_tuning_performed: false`), `REPLAY_ACCOUNTING_VALIDATION.md`, `REPLAY_ACCOUNTING_VALIDATION_XSS_BRUTEFORCE.md` |

### Guard suite detail

All eleven cases produced the expected counter delta with the 331-entry plan
installed: TCP/UDP/ICMP candidates, a guaranteed no-match, exact and masked
TCP flags (six in-domain cases), plus IPv4 options (`ipv4_ihl_not_5`), a
first fragment with MF, a non-initial fragment
(`ipv4_fragmented_or_reserved_flags`), a truncated IPv4 header, and a
truncated TCP header (five fallback cases). `failures: []`.

## 5. Effect of the repair on the frozen results

The repair changed classification only for direct-IPv4 frames excluded by the
header gate. The SQLi and XSS traces contain none, so their numbers are
bit-identical. The held-out trace contains 16.

| Quantity | Pre-correction | Post-correction | Note |
|---|---:|---:|---|
| SQLi parser-eligible | 34,924 | 34,924 | unchanged |
| XSS parser-eligible | 189,076 | 189,076 | unchanged |
| Brute Force parser-eligible | 1,101,475 | 1,101,459 | 16 fragmented/reserved-flag frames moved to fallback |
| Brute Force global candidate rate | 100% | 100% | unchanged |
| Brute Force strong candidate rate | 98.941% | 98.942% | denominator shift |
| Brute Force strong no-match | 11,662 | 11,654 | denominator shift |
| Brute Force mean candidate set | 324.52 | 324.52 | unchanged |
| Brute Force mean reduction | 91.01% | 91.01% | unchanged |
| Alert preservation (three traces) | 100% observed | 100% observed | unchanged |

No headline result was overturned. The scientific content of the repair is
that the safety argument is now established rather than assumed, and that
selectivity is reported over a domain the data plane actually enforces.

### Item requiring attention

The alert-preservation counts (150 / 528 / 2,391) were measured before the
correction and were not re-derived under the enforced domain. The 16
reclassified held-out frames remain candidates either way, so no alert packet
can change category from candidate to no-match; still, a re-run of the
alert-preservation scripts under the corrected pipeline would remove the last
pre-correction measurement from the results section. This is recorded as
open rather than claimed as done.

## 6. Manuscript changes applied

Applied to `main.tex` on 2026-09-09, after the reconciliation above:

1. **Abstract** — necessary predicates now stated as retaining every
   satisfying packet *within an explicitly enforced packet domain*, with
   out-of-domain traffic failed open.
2. **Introduction** — safe-necessary-prefilter wording qualified by the
   stated packet domain; a new contribution bullet covers the enforced
   domain and its validation.
3. **Problem Formulation** — new subsection `Enforced Packet Domain`
   (`sec:packet-domain`) defining `D`, the fail-open behavior, and the
   case-split safety statement.
4. **Compilation-semantics table** — port and TCP-flag guarantee cells now
   name the domain precondition; a new row documents options, fragments,
   truncation, and non-IPv4 frames as fail-open.
5. **Proposed Approach** — backend subsection describes the parser gate, the
   ingress re-check, and the three distinct counter categories.
6. **Methodology** — parser-eligible defined as membership in `D`; fallback
   explicitly excluded from the candidate denominator; new paragraph
   `Packet-domain validation` describing the guard suite and the replay
   accounting protocol.
7. **Results** — new subsection `Packet-Domain Enforcement and Validation`
   (`sec:domain-validation`) reporting the 11/11 guard suite, the
   out-of-domain populations per trace, the replay reconciliation, and the
   revalidation outcome; Brute Force row and prose updated to 1,101,459 /
   98.942% / 11,654.
8. **Discussion, RQ1 answer, Conclusion** — `r => p_r` statements qualified
   by the enforced domain and fail-open handling.
9. **Threats to Validity** — parser limits described as handled by exclusion
   rather than approximation, with the selectivity-scope cost stated; replay
   accounting non-uniformity across traces disclosed.

No frozen artifact was regenerated, no experiment was re-executed, no policy
was retuned, and no RQ or title was changed for this reconciliation.

## 7. Open items after this reconciliation

1. Frame-exact Brute Force replay: 87 of 1,108,658 frames (0.008%) lost in
   the transport layer; see `REPLAY_ACCOUNTING_VALIDATION_XSS_BRUTEFORCE.md`
   for the rerun procedure.
2. Re-derive alert preservation under the corrected pipeline (Section 5).
3. `main.pdf` has not been rebuilt: no LaTeX toolchain was available in the
   environment used for this reconciliation. The edited `main.tex` passed a
   structural check (balanced environments and braces, no undefined
   references) but has not been compiled.
4. Previously known and unchanged: no throughput/latency/hardware
   evaluation, no candidate-set-aware Snort execution, one ruleset, one
   profile, one dataset, limited alert-SID diversity.

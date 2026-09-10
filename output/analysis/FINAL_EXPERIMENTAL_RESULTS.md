# Final Experimental Results

This frozen consolidation uses only the artifacts listed in `final_experimental_summary.json`. It does not run experiments, modify policy, or rebuild the pipeline. The active evaluated profile is `cicids2017` with `HOME_NET=192.168.10.0/24`.

## 1. Semantic compilation

All 4,017 source rules were parsed. The semantic IR classifies 0 as `EXACT`, 4,003 as `NECESSARY`, and 14 as `UNSUPPORTED`; therefore 4,003 rules contribute conservative P4 candidate predicates and 14 remain delegated to fallback Snort handling. The P4 marker is not a replacement for Snort evaluation.

## 2. P4 backend

The backend generated, expanded, and normalized 6,675 source entries. There were 327 unique normalized matches before TCP-flag lowering, producing 331 final install entries after four additional flag-lowered entries. Validation is `VALID_WITH_FLAG_EXPANSION`; the P4Runtime plan encodes 331/331 entries with zero encoding failures and zero validation errors, within the 8,192-entry table capacity.

The 95.04% reduction (6,675 to 331) is **install-state deduplication**, not packet-traffic reduction.

## 3. Original global prefilter selectivity

The original global candidate bit selected all parser-eligible packets in every evaluated CICIDS2017 window, so it provided essentially no packet bypass there.

| Dataset | Parser eligible | Candidate | No-match | Candidate % |
|---|---:|---:|---:|---:|
| SQLi | 34,924 | 34,924 | 0 | 100.00% |
| XSS | 189,076 | 189,076 | 0 | 100.00% |
| Held-out Brute Force | 1,101,475 | 1,101,475 | 0 | 100.00% |

## 4. Causal selectivity audit

The principal documented cause is broad, sound-but-operationally-unselective NECESSARY predicates. `p4-106` is `protocol=TCP` and subsumes 246 entries (74.32%); `p4-40` is `dst_ip=192.168.10.0/24` and subsumes 210 (63.44%); and `p4-138` is `src_ip=192.168.10.0/24` and subsumes 107 (32.33%). The residual audit further shows distributed union coverage after removal of the frozen broad-entry set.

Deduplication is not the cause: it merges equal normalized matches rather than discarding fields. TCP-flag lowering is not the cause: the cited broad entries do not use TCP flags. **Semantic safety != operational selectivity.**

## 5. Strong-discriminator ablation

This frozen operational simulation retains 322 entries for 3,611 P4-eligible rules, with 392 operational fallback rules and 14 unsupported fallback rules. It does not redefine `NECESSARY` or `UNSUPPORTED`.

| Dataset | P4-eligible rules | Fallback rules | Candidate % | No-match % |
|---|---:|---:|---:|---:|
| SQLi | 3,611 | 392 + 14 | 99.015% | 0.985% |
| XSS | 3,611 | 392 + 14 | 98.869% | 1.131% |
| Held-out Brute Force | 3,611 | 392 + 14 | 98.941% | 1.059% |

## 6. Entry-level candidate rule set

The baseline is 3,611 rules. This is a per-packet predicate-provenance feasibility result, not a throughput or Snort-execution speedup measurement. Brute Force was held out and no policy was retuned using it.

| Dataset | Average rules | Median | P90 | P95 | P99 | Max | Average reduction |
|---|---:|---:|---:|---:|---:|---:|---:|
| SQLi | 179.28 | 27 | 799 | 799 | 799 | 1,228 | 95.04% |
| XSS | 140.49 | 13 | 799 | 799 | 1,227 | 1,228 | 96.11% |
| Held-out Brute Force | 324.52 | 241 | 799 | 799 | 1,227 | 1,228 | 91.01% |

## 7. Grouping

The frozen strategies were `protocol`, `protocol + direction`, `protocol + service`, and `protocol + direction + service`. Their group counts on held-out Brute Force were 4, 12, 268, and 308 respectively. All reproduced the same effective candidate-rule-set result; the conclusion is **`GROUPING_LIMITED_BY_OVERLAP`**. The 91–96% reduction comes from entry-level predicate provenance/candidate-set selection, not coarse grouping.

## 8. Dynamic alert validation

Semantic split preservation compares FULL Snort with `candidate + unsupported`. P4 preservation concerns only parser-eligible candidate-alert packets. Strong-discriminator preservation is observed-event coverage. Candidate-set SID membership is stateless/event membership only, never proof of stateful per-packet Snort execution equivalence.

| Dataset | FULL | Candidate | Unsupported | Missing / additional | Candidate alert packets | Parser eligible | P4 candidate | P4 no-match | Observed preservation |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| SQLi | 150 | 150 | 0 | 0 / 0 | 150 | 150 | 150 | 0 | 100% |
| XSS | 528 | 528 | 0 | 0 / 0 | 528 | 528 | 528 | 0 | 100% |
| Held-out Brute Force | 2,391 | 2,391 | 0 | 0 / 0 | 2,391 | 2,391 | 2,391 | 0 | 100% |

For held-out Brute Force, five SIDs fired. In the strong-discriminator audit, 2,289 eligible alert events were P4-covered, 102 were fallback-covered, and none were missing. Entry-level candidate-set SID membership was 2,289/2,289.

The historical controlled artifact remains `VALID` (five baseline/candidate alerts; three P4-classified packets), but it is an initial controlled check rather than a CICIDS2017 selectivity result.

## 9. Dependencies

The original partition is `SAFE_FOR_INDEPENDENT_RULESET_SPLIT`: 226 flowbit producer instances, 65 consumers, 636 candidate-to-candidate edges, and zero cross-partition edges. The strong-discriminator partition is also reported `SAFE_FOR_INDEPENDENT_RULESET_SPLIT`, with zero eligible-to-fallback and fallback-to-eligible flowbit edges. This analysis scopes named cross-rule state relationships (flowbits; no xbits/flowint occurrences); it does not constitute formal equivalence for arbitrary stateful traffic.

## 10. Scientific claims

### Supported claims

- The explicit semantic classification and backend compilation results documented above.
- Measured global and strong-discriminator selectivity on the evaluated windows.
- Observed semantic-split and P4 alert-packet preservation results.
- Measured entry-level candidate-rule-set reduction and overlap-limited grouping result.

### Limited / empirical claims

- Generalization is limited to the evaluated ruleset, profile, and CICIDS2017 windows.
- Alert preservation is observed on finite traffic, not formal for all traffic.
- Candidate-set reduction demonstrates feasibility/membership, not execution performance.

### Unsupported claims

- Throughput improvement, latency improvement, Snort speedup, or production-deployment performance.
- Formal equivalence for all possible traffic.
- Dynamic stateful candidate-set execution correctness or performance.

## 11. Threats to validity / limitations

- Results depend on the experimental variable profile and CICIDS2017 traffic distribution.
- Individual windows exercise limited alert-SID diversity.
- SQLi/XSS dataset labels are not themselves proof that the observed Snort alerts detect those ground-truth labels.
- Brute Force was held out from policy development, but remains one held-out window.
- The current parser scope is Ethernet/IPv4 and supported protocols; VLAN is not supported.
- Alert validation is finite and observed; no performance benchmark was run.
- Candidate-set execution is not implemented; stateful Snort semantics exceed simple event membership.

## 12. Paper-ready tables

### Table A — Semantic compilation

| Source rules | Parsed | EXACT | NECESSARY | UNSUPPORTED | Prefilter candidates |
|---:|---:|---:|---:|---:|---:|
| 4,017 | 4,017 | 0 | 4,003 | 14 | 4,003 |

### Table B — Backend lowering

| Source entries | Unique before flags | Final entries | Reduction | Flag additions | Capacity | P4Runtime encoded |
|---:|---:|---:|---:|---:|---:|---:|
| 6,675 | 327 | 331 | 95.04% | 4 | 8,192 | 331/331 |

### Table C — Packet selectivity

| Dataset | Eligible | Candidate | No-match | Candidate % |
|---|---:|---:|---:|---:|
| SQLi | 34,924 | 34,924 | 0 | 100.00% |
| XSS | 189,076 | 189,076 | 0 | 100.00% |
| Held-out Brute Force | 1,101,475 | 1,101,475 | 0 | 100.00% |

### Table D — Candidate-rule-set reduction

| Dataset | Baseline | Average rules | Average reduction |
|---|---:|---:|---:|
| SQLi | 3,611 | 179.28 | 95.04% |
| XSS | 3,611 | 140.49 | 96.11% |
| Held-out Brute Force | 3,611 | 324.52 | 91.01% |

### Table E — Alert preservation

| Dataset | FULL | Candidate alerts | P4 candidate alert packets | P4 no-match | Preservation |
|---|---:|---:|---:|---:|---:|
| SQLi | 150 | 150 | 150 | 0 | 100% |
| XSS | 528 | 528 | 528 | 0 | 100% |
| Held-out Brute Force | 2,391 | 2,391 | 2,391 | 0 | 100% |

### Table F — Grouping comparison

| Strategy | Held-out groups | Effective candidate-set conclusion |
|---|---:|---|
| Protocol | 4 | Same candidate-set result; overlap-limited |
| Protocol + direction | 12 | Same candidate-set result; overlap-limited |
| Protocol + service | 268 | Same candidate-set result; overlap-limited |
| Protocol + direction + service | 308 | Same candidate-set result; overlap-limited |

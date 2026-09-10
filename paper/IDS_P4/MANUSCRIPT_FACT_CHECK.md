# Manuscript Fact Check

Scope: factual audit of quantitative and experimental claims in `main.tex`
against the frozen official sources only:
`../../output/analysis/FINAL_EXPERIMENTAL_RESULTS.md` and
`../../output/analysis/final_experimental_summary.json`. No experiment was
executed for this audit.

| Section | Claim | Source | Status | Correction / Qualification |
|---|---|---|---|---|
| Introduction / Contributions | The contribution is target-aware semantic compilation, explicit classification, and observed preservation rather than bare Snort-to-P4 translation. | Final Results §§1, 4, 8, 10 | VERIFIED | Kept and made explicit. |
| Background | Backend scope is Ethernet/IPv4 header processing and P4 is a candidate marker. | Final Results §11 | NEEDS_QUALIFICATION | Current parser scope and no-VLAN limitation are stated in Results/Limitations. |
| Problem Formulation | `EXACT`, `NECESSARY`, and `UNSUPPORTED` are distinct semantic relations. | Final Results §1 | VERIFIED | `EXACT=0` is stated in Results. |
| Safety Condition | For NECESSARY, `r => p_r`; not `p_r => r`. | Final Results §§1, 10 | NEEDS_QUALIFICATION | Added the direction explicitly. |
| Safety Condition | UNSUPPORTED rules remain delegated/fallback, not ignored. | Final Results §§1, 5 | NEEDS_QUALIFICATION | Added explicitly. |
| Methodology | SQLi/XSS are development/diagnostic; Brute Force is held-out. | Final Results §§6, 11 | VERIFIED | Kept; no retuning after Brute Force is also stated. |
| Methodology | Candidate percentages apply to parser-eligible traffic. | Final Results §§3, 11 | NEEDS_QUALIFICATION | Formula and Results wording now condition the population on parser eligibility. |
| Semantic Compilation Coverage | 4,017 source rules were parsed. | Final Results §§1, 12 Table A | VERIFIED | No correction needed. |
| Semantic Compilation Coverage | EXACT=0, NECESSARY=4,003, UNSUPPORTED=14. | Final Results §§1, 12 Table A | VERIFIED | No correction needed. |
| Semantic Compilation Coverage | 4,003 are conservative candidate predicates, not full Snort implementations. | Final Results §1 | VERIFIED | No correction needed. |
| Backend Feasibility | 6,675 denotes generated, expanded, and normalized predicate instances. | Final Results §2 | NEEDS_QUALIFICATION | Reworded from vague backend output to the exact pipeline stage. |
| Backend Feasibility | 327 unique matches existed before TCP-flag lowering. | Final Results §§2, 12 Table B | VERIFIED | No correction needed. |
| Backend Feasibility | 331 final install entries; P4Runtime 331/331; zero encoding and validation failures. | Final Results §§2, 12 Table B | VERIFIED | No correction needed. |
| Backend Feasibility | 95.04% is installation-state/backend-state deduplication. | Final Results §2 | NEEDS_QUALIFICATION | Explicitly excludes traffic, Snort-rule, processing, and speedup reduction. |
| Global Selectivity | SQLi global candidate rate is 34,924/34,924 (100%) among parser-eligible packets. | Final Results §§3, 12 Table C | VERIFIED | Scope added before the values. |
| Global Selectivity | XSS global candidate rate is 189,076/189,076 (100%) among parser-eligible packets. | Final Results §§3, 12 Table C | VERIFIED | Scope added before the values. |
| Global Selectivity | Held-out Brute Force global candidate rate is 1,101,475/1,101,475 (100%) among parser-eligible packets. | Final Results §§3, 12 Table C | VERIFIED | Scope added before the values. |
| Causal Analysis | `p4-106` is TCP-only; `p4-40` and `p4-138` are HOME_NET address predicates; broad predicates explain poor selectivity. | Final Results §4 | VERIFIED | No correction needed. |
| Causal Analysis | Deduplication and TCP-flag lowering are not the cause of universal coverage. | Final Results §4 | VERIFIED | No correction needed. |
| Strong-discriminator | 3,611 P4-eligible, 392 operational fallback, 14 semantic UNSUPPORTED fallback, and 322 retained entries. | Final Results §5 | NEEDS_QUALIFICATION | Added as an operational ablation, not a new semantic classification. |
| Strong-discriminator | Candidate rates are 99.015% (SQLi), 98.869% (XSS), and 98.941% (held-out Brute Force), among parser-eligible packets. | Final Results §5 | NEEDS_QUALIFICATION | Added population qualifier and frozen/no-retuning statement. |
| Candidate-rule-set reduction | Baseline is 3,611 P4-eligible rules. | Final Results §6 | VERIFIED | No correction needed. |
| Candidate-rule-set reduction | SQLi/XSS reductions are 95.04%/96.11%. | Final Results §6 | VERIFIED | No correction needed. |
| Candidate-rule-set reduction | Held-out Brute Force reduction is 91.01%; average 324.52, median 241, P90/P95 799, P99 1227, max 1228. | Final Results §6 | VERIFIED | No correction needed. |
| Candidate-rule-set reduction | These values are offline candidate-set feasibility, not dynamic Snort execution or speedup. | Final Results §§6, 10, 11 | NEEDS_QUALIFICATION | Added this wording explicitly. |
| Grouping Ablation | Result is `GROUPING_LIMITED_BY_OVERLAP`; four coarse strategies did not create the 91--96% reduction. | Final Results §7 | NEEDS_QUALIFICATION | Added the provenance mapping explanation. |
| Dynamic Alert Preservation | SQLi observed preservation: 150/150 candidate alert packets; no P4 no-match. | Final Results §8 | VERIFIED | No correction needed. |
| Dynamic Alert Preservation | XSS observed preservation: 528/528 candidate alert packets; no P4 no-match. | Final Results §8 | VERIFIED | No correction needed. |
| Dynamic Alert Preservation | Held-out Brute Force: FULL=2,391, five SIDs, split missing/additional=0/0, P4=2,391/2,391. | Final Results §8 | VERIFIED | No correction needed. |
| Dynamic Alert Preservation | Strong audit is 2,289 P4-covered eligible events plus 102 fallback-covered; candidate-set membership is observed 2,289/2,289. | Final Results §8 | NEEDS_QUALIFICATION | Retained as observed event/SID membership, never stateful execution equivalence. |
| Dependencies / Limitations | Original and strong partitions are safe for independent ruleset split with zero cross-partition flowbit edges. | Final Results §9 | VERIFIED | Scope remains named cross-rule state analysis, not arbitrary-traffic equivalence. |
| Discussion / Conclusion | No throughput, latency, Snort speedup, production-performance, or formal-equivalence claim is supported. | Final Results §§10--11 | VERIFIED | Explicit exclusions retained. |

## Totals

- VERIFIED: 21
- NEEDS_QUALIFICATION: 11
- INCORRECT: 0
- UNSUPPORTED: 0

All eleven qualification items were corrected locally in `main.tex`. The audit
found no remaining quantitative or project-experimental claim that conflicts
with the two frozen official sources.

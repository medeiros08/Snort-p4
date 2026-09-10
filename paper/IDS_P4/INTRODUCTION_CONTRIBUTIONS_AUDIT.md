# Introduction and Contributions Audit

## Scope

This audit covers only the Introduction, Contributions, Research Questions,
and Paper Organization in `main.tex`. It was checked against the frozen
results in `output/analysis/FINAL_EXPERIMENTAL_RESULTS.md` and
`output/analysis/final_experimental_summary.json`; no experiment or pipeline
execution was performed.

## Revised Narrative

The Introduction now frames the problem as partial, semantics-aware
compilation of Snort 3 rules to a constrained P4 target. It distinguishes the
safe necessary relation $r \Rightarrow p_r$ from reverse implication or
equivalence, then separates semantic safety from aggregate packet-level
selectivity. It introduces predicate provenance as an offline
candidate-rule-space opportunity rather than a deployed execution mechanism.

## Contribution Support Matrix

| Contribution | Frozen evidence | Status |
|---|---|---|
| Semantic classification into `EXACT`, `NECESSARY`, and `UNSUPPORTED` | 4,017 parsed rules: 0 / 4,003 / 14 | Supported |
| Manifest, delegation/fallback, and entry-to-rule provenance | Semantic manifest and final installation artifacts | Supported |
| Backend lowering and installation-state reduction | 6,675 predicate instances lowered to 331 final installation entries | Supported |
| Semantic safety versus operational selectivity | Original global marker selected 100% of parser-eligible packets in all three evaluated traces | Supported |
| Offline provenance-derived candidate-rule-space analysis | Mean reductions of 95.04% (SQLi), 96.11% (XSS), and 91.01% (held-out Brute Force), relative to 3,611 P4-eligible rules | Supported |
| Observed semantic-split and alert-packet preservation | Finite-trace observations only; no formal equivalence or stateful candidate-set execution claim | Supported with stated qualification |

## Quantitative Preview Check

- `4,003 of 4,017` rules admitted safe necessary predicates: verified.
- `100%` global-candidate rate is explicitly scoped to parser-eligible
  packets and the three evaluated traces: verified.
- `91.01%` held-out Brute Force candidate-rule-space reduction is explicitly
  scoped to the frozen 3,611-rule P4-eligible partition: verified.
- The `6,675 -> 331` figure is explicitly described as installation state,
  not traffic, rule-count, processing, or speedup reduction: verified.

## Research Questions

RQ1--RQ4 were retained unchanged. The contribution claims map to them without
adding an unimplemented runtime candidate-set execution, performance, or
full-offload promise.

## Citations

The Introduction reuses only existing citations: P4ID, P4-ONIDS, and eRBF.
No references were added or invented.

## Claim-Scope Check

The revised text does not claim acceleration, throughput improvement, traffic
reduction, detection accuracy, full offload, formal equivalence, unrestricted
parser coverage, or dynamic stateful candidate-set execution. The current
parser scope and all measured selectivity claims remain bounded by the
evaluated Ethernet/IPv4 parser-eligible traffic.

## Remaining Author Tasks

- Insert the frozen experimental Snort variable profile in the appendix.
- Add the planned conceptual architecture figure.
- Compile with a LaTeX toolchain when one is available.

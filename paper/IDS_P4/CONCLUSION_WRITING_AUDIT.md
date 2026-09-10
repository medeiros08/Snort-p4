# Conclusion Writing Audit

> **Addendum (2026-09-09).** The held-out strong-discriminator candidate
> rate cited below is now 98.942% (was 98.941%) after the IPv4
> packet-domain repair, and the Conclusion's `r => p_r` statement is now
> qualified by the enforced packet domain and its fail-open handling. See
> `PARSER_DOMAIN_RECONCILIATION.md`.

## Paragraphs Written

1. Research problem and semantics-aware, target-aware compilation framing.
2. Conservative answers to RQ1 and RQ2.
3. Direct answer to RQ3 and the residual union-coverage implication.
4. RQ4 observed preservation and provenance utility, followed by bounded
   future work.

## RQ Answers

| RQ | Conclusion answer |
|---|---|
| RQ1 | Most evaluated rules admitted safe NECESSARY predicates; none was EXACT and 14 remained UNSUPPORTED, so partial preservation is not equivalence. |
| RQ2 | The evaluated BMv2/v1model pipeline lowered the frozen predicates to validated installation state within the target constraints. |
| RQ3 | The evaluated global binary prefilter was semantically conservative but poorly selective among parser-eligible packets; residual union coverage persisted after the ablation. |
| RQ4 | The evaluated traces showed observed alert preservation and smaller provenance-derived candidate rule sets, but candidate-set-aware dynamic IDS execution remains future work. |

## Numbers Retained and Checked

- 4,017 parsed; 4,003 NECESSARY; 14 UNSUPPORTED; EXACT 0.
- 6,675 source predicate instances; 331 final entries; 95.04%
  installation-state reduction; 331/331 P4Runtime entries; zero reported
  encoding and validation failures.
- Held-out strong-discriminator candidate rate: 98.941% among parser-eligible
  packets.
- Observed alert preservation: 100% in the three evaluated traces.
- Candidate-rule-space reductions: 95.04% SQLi, 96.11% XSS, and 91.01%
  held-out Brute Force; held-out mean set size 324.52 within the 3,611-rule
  P4-eligible partition.

All values were checked against `FINAL_EXPERIMENTAL_RESULTS.md` and
`final_experimental_summary.json`.

## Overclaims Removed or Avoided

The Conclusion makes no claim of Snort acceleration, throughput or latency
improvement, traffic reduction, production readiness, full rule offload,
formal equivalence, guaranteed preservation, or detection accuracy. The
95.04% backend result is explicitly installation-state reduction, and RQ4 is
explicitly an offline feasibility result.

## Future Work

- Candidate-set-aware and dependency-aware IDS execution.
- Provenance-aware selection beyond coarse grouping.
- Execution-cost evaluation after such an execution mechanism exists.
- Hardware-target evaluation.
- Additional rulesets, profiles, traffic datasets, and parser/protocol/
  encapsulation coverage.

## Unresolved Author-Review Issues

- Insert the frozen experimental variable profile verbatim into the appendix.
- Produce the conceptual architecture figure.
- Compile with a LaTeX toolchain when available.

## Structural Check

The Conclusion is four compact paragraphs and retains the existing appendix,
bibliography, and document closure. The environment lacks `pdflatex`, so the
manuscript received structural rather than compiled verification.

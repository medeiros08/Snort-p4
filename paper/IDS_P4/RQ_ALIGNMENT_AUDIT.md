# RQ Alignment Audit

## Current Research Questions

**RQ1 -- Semantic Coverage.** To what extent can Snort 3 rules be safely
represented by predicates executable in a programmable P4 data plane while
explicitly preserving semantic limitations?

**RQ2 -- Backend Feasibility.** Can the semantically derived predicates be
lowered and installed in a practical P4 target without hiding unsupported
semantics or exceeding target constraints?

**RQ3 -- Operational Selectivity.** How selective is a binary P4 prefilter
when thousands of semantically safe predicates are jointly deployed?

**RQ4 -- Detection Preservation and Alternative Utility.** When packet-level
bypass selectivity is limited, can the compiled predicates still preserve
observed IDS alerts and reduce the per-packet candidate rule space?

## Alignment Matrix

| RQ | Introduction | Methodology | Results | Discussion | Threats | Status |
|---|---|---|---|---|---|---|
| RQ1 | Defines semantic compilation and explicit limits | Semantic classes and target profile explained | 4,017/4,017; EXACT 0; NECESSARY 4,003; UNSUPPORTED 14; 99.65% safe necessary coverage | Explains `r => p_r` and why EXACT=0 matters | Separates coverage from equivalence | ALIGNED |
| RQ2 | Motivates target-aware compilation | BMv2 target and pipeline described; installation metric needs sharper pre-results definition | 6,675 instances; 331 entries; 331/331; zero failures; capacity respected | Limits implication to target feasibility | Excludes hardware/performance claims | MINOR_QUALIFICATION |
| RQ3 | Frames prefiltering problem | Defines parser-eligible candidate metric and held-out protocol | Global rate 100% among parser-eligible for all traces; strong held-out 98.941%, 11,662 no-match | Explains union effect and residual distributed coverage | Limits generalization to configuration and traffic | ALIGNED |
| RQ4 | States observed preservation and candidate-rule selection | Alert-preservation metric defined; candidate-set method needs sharper pre-results definition | Observed preservation and 95.04%/96.11%/91.01% offline rule-space results are separated | Explains alternative utility without runtime claim | Preserves stateful/dynamic-execution limitation | MINOR_QUALIFICATION |

## Concise Supported Answers

- **RQ1:** A very large fraction of the evaluated rules admitted safe
  necessary P4 predicates (4,003/4,017), but none was EXACT and 14 remained
  UNSUPPORTED; this is not full offload or equivalence.
- **RQ2:** The derived predicates were lowered, deduplicated, and validated
  on the evaluated BMv2/v1model target within the 8,192-entry capacity, with
  331/331 P4Runtime entries and zero reported encoding/validation failures.
- **RQ3:** Under the evaluated ruleset and traces, the binary global
  prefilter had poor packet-level bypass selectivity: it marked 100% of
  parser-eligible packets in all three traces, and the frozen ablation still
  marked 98.941% in held-out Brute Force.
- **RQ4:** In evaluated traffic, compiled predicates preserved all observed
  candidate alert events/packets while exposing smaller per-packet candidate
  rule sets; this remains offline feasibility because dynamic stateful
  candidate-set-aware IDS execution was not implemented.

## Contribution Claims Needing Later Revision

The current Contributions subsection is compatible with RQ1--RQ4 and makes
no performance or equivalence claim. A later, non-editorial revision should
make two categories more explicit: (1) the compilation manifest as an
auditable account of preserved, delegated, fallback, and unsupported
semantics; and (2) the causal/selectivity and held-out provenance result as
separate empirical contributions. No contribution text was changed here.

## Methodology-to-Results Traceability

- **Defined adequately:** semantic classes and safety relation (Problem
  Formulation); parser-eligible candidate metric; observed alert preservation;
  held-out trace protocol.
- **Needs later methodological sharpening:** define the installation-state
  reduction formula and explain final-entry deduplication before Results;
  define the provenance-derived per-packet candidate-rule-set procedure and
  its percentiles before Results; distinguish semantic-split preservation,
  P4 alert-packet preservation, ablation coverage, and SID membership in the
  methodology as separate measurements.

## Development and Held-Out Terminology

Terminology is consistent: SQLi and XSS are development/diagnostic traces;
Brute Force is held out, and no retuning occurred after its inspection. No
sentence was found that obscures this distinction by treating all three as
interchangeable evaluation datasets.

## Appendix and Variable Profile Status

No appendix existed. A placeholder appendix, `app:snort-profile`, was added
and linked from Experimental Methodology. It intentionally contains no
reconstructed values; the frozen profile must be inserted verbatim after
author review.

## NAT Wording Status

The frozen metadata search did not directly substantiate the prior NAT claim.
The claim was removed from the manuscript rather than generalized. If the
capture observation is retained later, authors should add frozen
experiment-specific metadata or a documented provenance note; no dataset-wide
NAT claim should be made.

## Remaining Overclaims and TODOs Before Conclusion

No remaining RQ-level performance, full-offload, traffic-reduction, or formal
equivalence overclaim was found. Remaining TODOs are the variable-profile
appendix content, a sharper pre-results methodology definition for backend and
candidate-set metrics, the conceptual figure placeholder, and LaTeX
compilation when a toolchain is available.

# Methodology Metrics Audit

## Definitions Added

- Parser-eligible packet, candidate packet, no-match packet, and their
  parser-eligible denominator.
- Installation-state reduction using the backend artifact fields
  `source_entries` and `final_install_entries`.
- Provenance-based candidate rule set `C(x)` formed from retained matching
  entries and their `source_rule_ids`.
- Candidate-rule-space reduction within the 3,611-rule P4-eligible partition.
- Four distinct finite observed-preservation measures.
- Explicit no-retuning held-out protocol for Brute Force.

## Equations Added

\[
ISR = \left(1 - \frac{N_{\mathrm{install}}}{N_{\mathrm{source}}}\right)
\times 100\%.
\]

The frozen fields are `source_entries=6675` and
`final_install_entries=331` in `output/p4_install_entries.json`, yielding
95.04119850187266%, reported as 95.04%.

\[
C(x) = \bigcup_{e \in E(x)} S(e), \qquad
R(x) = \left(1 - \frac{|C(x)|}{3611}\right) \times 100\%.
\]

The candidate-set formula is consistent with the frozen
strong-discriminator analysis in `final_experimental_summary.json` and
`FINAL_EXPERIMENTAL_RESULTS.md`.

## Exact Artifact Sources

| Metric | Artifact fields / section | Interpretation retained in Methodology |
|---|---|---|
| Semantic classes | `final_experimental_summary.json`: `semantic_compilation` | Safe necessary coverage is not equivalence. |
| Installation-state reduction | `output/p4_install_entries.json`: `source_entries`, `final_install_entries`, `reduction_percentage` | P4 installation state only. |
| P4Runtime feasibility | `final_experimental_summary.json`: `p4_backend.p4runtime_plan` | Encoding/validation feasibility, not performance. |
| Candidate/no-match rate | Final Results §3 / Table C | Denominator is parser-eligible packets. |
| Candidate rule set | Final Results §6 / Table D | Baseline is only 3,611 P4-eligible rules. |
| Alert preservation | Final Results §8 / Table E | Four distinct observed checks, not formal equivalence. |
| Held-out protocol | Final Results §§5--6, 11 | Brute Force held out; no retuning. |

## Fallback Accounting

The methodology now states the frozen strong-discriminator partition:

- 3,611 P4-eligible rules form the candidate-rule-set baseline;
- 392 operational fallback rules remain outside that baseline; and
- 14 semantic UNSUPPORTED rules remain fallback.

An empty candidate set for a parser-eligible packet is not interpreted as a
safe full bypass, because fallback rules remain applicable.

## Preservation Measures Distinguished

1. Semantic split preservation: FULL versus candidate plus UNSUPPORTED
   fallback alerts.
2. P4 alert-packet preservation: P4 candidate/no-match status for observed
   parser-eligible candidate-alert packets.
3. Strong-discriminator observed-event coverage: retained predicates versus
   operational/semantic fallback events.
4. Candidate-set SID membership: event-level membership in `C(x)`, explicitly
   not dynamic stateful Snort execution validation.

## Final RQ Alignment

| RQ | Status | Basis |
|---|---|---|
| RQ1 | ALIGNED | Semantic relation and classification are defined before Results. |
| RQ2 | ALIGNED | Installation-state reduction and target-feasibility scope are now defined before Results. |
| RQ3 | ALIGNED | Parser-eligible candidate/no-match metrics and held-out design are defined before Results. |
| RQ4 | ALIGNED | Provenance procedure, fallback boundary, and distinct observed-preservation checks are now defined before Results. |

## Remaining Methodological TODOs

- Insert the frozen experimental Snort variable profile verbatim into
  Appendix~`app:snort-profile` after author review.
- Add the conceptual architecture figure currently left as a manuscript
  placeholder.
- Compile with a LaTeX toolchain when available.

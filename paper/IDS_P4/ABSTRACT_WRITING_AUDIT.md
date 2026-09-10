# Abstract Writing Audit

## Scope and Sources

Only the abstract in `main.tex` was added in this task. It was checked against
the frozen sources `output/analysis/FINAL_EXPERIMENTAL_RESULTS.md` and
`output/analysis/final_experimental_summary.json`. No experiment, policy,
pipeline, or result artifact was changed.

## Original Abstract

No abstract environment existed before this revision.

## Final Abstract

The final text is the `abstract` environment immediately after `\maketitle`
in `main.tex`. It presents the partial-compilation problem, semantic
classification, manifest provenance, backend feasibility, the global binary
prefilter result, offline candidate-rule-space utility, and finite-trace
observed alert preservation.

## Word Count

229 words, within the requested approximate 180--230-word range.

## Numerical Claims Retained and Verified

| Claim | Frozen source | Verification |
|---|---|---|
| 4,017 evaluated rules | Semantic compilation summary | Verified |
| 4,003 `NECESSARY`, 14 `UNSUPPORTED`, 0 `EXACT` | Semantic compilation summary | Verified |
| 331 final P4 installation entries | Backend summary | Verified |
| 100% candidate rate among parser-eligible packets in SQLi, XSS, and held-out Brute Force | Original global prefilter selectivity table | Verified and denominator-qualified |
| 3,611 to 324.52 rules and 91.01% reduction for held-out Brute Force | Entry-level candidate-rule-set summary | Verified; stated as offline candidate-rule-space reduction within the P4-eligible partition |
| All observed candidate alerts preserved | Dynamic alert validation | Verified and limited to evaluated traces |

## Claims Removed or Qualified

- The abstract makes no acceleration, speedup, throughput, latency, traffic-
  reduction, processing-reduction, line-rate, or production-readiness claim.
- It does not claim full offload, full semantic preservation, formal
  equivalence, detection accuracy, guaranteed preservation, or universal
  generalization.
- The 100% binary-prefilter finding is explicitly limited to
  parser-eligible packets.
- Alert preservation is explicitly observational and limited to the evaluated
  traces.
- Candidate-rule-space reduction is explicitly offline and is not represented
  as runtime Snort execution or performance.

## Terminology Audit

The final abstract contains no occurrences of the requested prohibited search
terms: `accelerat`, `speedup`, `throughput`, `latency`, `traffic reduction`,
`processing reduction`, `full offload`, `fully offloaded`, `formal
equivalence`, `detection accuracy`, `guarantee`, `significant`, or literal
`100%`. The LaTeX expression `100\%` occurs once and is reviewed: it refers
only to the global binary candidate rate among parser-eligible packets.

## Structural Check

The abstract uses one balanced `abstract` environment. The document contains
18 `\begin` and 18 `\end` environment delimiters. LaTeX compilation remains
unavailable because `pdflatex` is not installed in the environment.

## Unresolved Author-Review Issues

- Insert the frozen experimental Snort variable profile into the appendix.
- Add the planned conceptual architecture figure.
- Compile with a LaTeX toolchain when one is available.

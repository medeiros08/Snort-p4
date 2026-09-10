# Final Static Editorial and LaTeX Audit

## 1. Executive Summary

This static audit covered `main.tex`, `references.bib`, the manuscript audit files, and the frozen consolidated results. No experiment, frozen result, or scientific interpretation was changed. Three mechanical edits were made in `main.tex`: an unsupported generalization phrase was narrowed to a held-out observation, `candidate rule set` terminology was standardized, and an in-text reference to the semantic/backend table was added.

Summary: 4 citation keys used; 0 missing citation keys; 0 duplicate labels; 0 unresolved references; 1 live manuscript placeholder; 0 numerical inconsistencies; and 0 unqualified overclaims. LaTeX environment delimiters are balanced (20 `\\begin`, 20 `\\end`). Compilation was not run, as requested.

## 2. TODOs and Placeholders

| File | Line | Context | Action |
|---|---:|---|---|
| `main.tex` | 855 | `Figure placeholder` requests a conceptual compilation/provenance figure. | Unresolved: author must supply or authorize a figure; none was invented. |
| `RQ_ALIGNMENT_AUDIT.md` | 76, 92--94 | Historical audit describes the then-placeholder appendix. | Historical/stale wording; no manuscript action, because the appendix is now complete. |
| `METHODOLOGY_METRICS_AUDIT.md` | 78--83 | Remaining TODO list includes the conceptual figure and compilation. | Figure remains unresolved; compilation remains pending. |
| `RESULTS_WRITING_AUDIT.md` | 59--62 | Remaining TODO list includes the conceptual figure and compilation. | Same unresolved tasks. |
| `THREATS_WRITING_AUDIT.md` | 52 | Heading for remaining TODOs. | Its listed compilation and author-review items remain follow-up. |
| `DISCUSSION_WRITING_AUDIT.md` | 33 | Citation-TODO heading. | No citation TODO is listed; no action. |

No `FIXME`, `XXX`, `citation needed`, `ref?`, `TBD`, or `???` occurrence was found in `main.tex`.

## 3. Citation Audit

Used keys: `lewis2019p4id`, `tavares2021p4onids`, `brum2025rethinking`, and `hagen2025rna` (4 total). All exist in `references.bib`; no entry is uncited and no BibTeX key is duplicated.

Lewis et al., Brum et al., and Hagen et al. contain authors, title, venue, and year. `tavares2021p4onids` is an `@article` with authors, title, and year, but lacks `journal`, volume, issue, pages, and identifier. This entry needs author completion; no metadata were fabricated.

## 4. Citation-Context Concerns

| Location | Citation(s) | Assessment | Note |
|---|---|---|---|
| Introduction, lines 49--52 | P4ID, P4-ONIDS, eRBF | OK | High-level framing is compatible with the cited works' role in the manuscript. |
| Related Work, lines 152--171 | P4ID, P4-ONIDS | NEEDS_AUTHOR_REVIEW | Detailed field, range, aggregation, and flow-information descriptions should be source-checked before submission. |
| Related Work, lines 173--198 | eRBF, RNA | NEEDS_AUTHOR_REVIEW | Detailed claims about context handling and event/template mapping need author verification. |
| Discussion, lines 941--962 | All four | OK | Bounded contextual comparison; no direct empirical comparison claimed. |

No citation was classified `TOO_STRONG_FOR_CITATION`.

## 5. Label and Reference Audit

There are 13 labels and 8 explicit `\\ref` uses. No duplicate label and no missing-label reference was found. `Appendix~\\ref{app:snort-profile}` is valid. Section labels are unreferenced but harmless. All six table labels are cited in prose after adding the missing reference to `tab:semantic-backend`. No figure or equation reference is unresolved.

## 6. Tables and Figures

All six tables have captions followed by labels and are cited in prose. English decimal points are used. Candidate/no-match rates are qualified as parser-eligible where relevant, and 95.04% is correctly identified as installation-state reduction. No actual figure exists; the conceptual-figure paragraph is the sole live placeholder.

## 7. Equations

- The rule tuple defines its symbols immediately afterward.
- The necessary relation is consistently `r \\Rightarrow p_r`; converse and equivalence are explicitly denied for `NECESSARY` predicates.
- `ISR` defines `N_source` and `N_install` before the equation and correctly uses 6,675 and 331 as installation state only.
- `E(x)`, `S(e)`, and `C(x)` are defined before the candidate-rule-set union. Its reduction is explicitly bounded by the 3,611-rule P4-eligible partition; 392 operational-fallback and 14 semantic-UNSUPPORTED rules are outside the denominator.

No notation conflict or reciprocal semantic claim was found.

## 8. Terminology

`Snort 3`, `P4`, `P4Runtime`, `BMv2`, `P4-eligible`, `parser-eligible`, `operational fallback`, `semantic UNSUPPORTED`, `NECESSARY`, `EXACT`, `predicate provenance`, `observed alert preservation`, and `held-out` are consistent. `candidate rule set` was standardized; `candidate-rule-space reduction` remains the explicit offline metric.

## 9. Numerical Consistency

All requested occurrences match `FINAL_EXPERIMENTAL_RESULTS.md`: 4,017/4,003/14/0 semantic classes; 6,675 source instances; 331 final and P4Runtime entries; 95.04% installation-state reduction; 95.04%/96.11%/91.01% candidate-rule-space reductions; 3,611 baseline; 392 operational fallback; 324.52 mean; 241, 799, 1,227, and 1,228 distribution values; 98.941% held-out strong candidate rate; and 2,391/2,289 alert values. No inconsistent meaning was found.

## 10. Claim-Language Audit

Occurrences of acceleration, speedup, throughput, latency, traffic reduction, processing reduction, full offload, equivalent, formal equivalence, detection accuracy, guarantee, prove, significant, line-rate, and 100% occur only in negations, limitations, metric qualifications, or finite observed-preservation results. No unqualified performance, equivalence, offload, accuracy, or universal-generalization claim remains.

The phrase “generalized to the held-out trace” was changed to “a reduction was also observed on the held-out trace,” accurately limiting the claim to one held-out observation.

## 11. Development and Held-Out Consistency

SQLi and XSS are consistently development/diagnostic traces; Brute Force is consistently held-out. The manuscript states that policy and grouping configurations were frozen and that no retuning followed held-out inspection. No contradictory tuning claim was found.

## 12. Appendix and Profile Consistency

The active profile is `cicids2017`; the Appendix label and Methodology reference are valid. The appendix correctly states the 4,017-community-rule evaluation, experimental rather than canonical status, and the generated `file_inspect = { }` isolation of default `file_magic.rules`.

## 13. Current Title Assessment

`IDS-P4` is a serviceable project label but under-describes semantic classification, selectivity, and provenance. It was not changed.

## 14. Suggested Title Alternatives

1. *Semantics-Aware Snort-to-P4 Compilation and Predicate Provenance*
2. *From Semantic Safety to Candidate-Rule Selection in Snort-to-P4 Compilation*
3. *Transparent Semantic Compilation of Snort Rules to P4 Predicates*
4. *Operational Selectivity of Semantically Safe Snort-to-P4 Prefilters*
5. *Predicate Provenance for Semantics-Aware P4 IDS Prefiltering*

## 15. Remaining Blockers Before Compilation

1. Provide or deliberately remove the conceptual architecture figure placeholder.
2. Complete the `tavares2021p4onids` bibliographic metadata.
3. Author-review detailed Related Work assertions against the cited papers.
4. Obtain a LaTeX toolchain and compile; compilation was intentionally not run.

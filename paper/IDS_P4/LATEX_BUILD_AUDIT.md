# LaTeX Build Audit

## Build Result

- Fatal error corrected: `\\text` was used inside `\\mathrm` in the two
  `N_{\\mathrm{parser\\text{-}eligible}}` expressions, but the preamble did
  not load the package that provides `\\text` in math mode.
- Mechanical correction: added `\\usepackage{amsmath}` to `main.tex`.
- The two expressions remain unchanged and compile with their original
  mathematical meaning.
- Commands run, without `-f`: `latexmk -C` followed by
  `latexmk -pdf -interaction=nonstopmode main.tex`.
- `latexmk` exit status: 0 (successful).
- PDF: `main.pdf`, 23 pages, 300,481 bytes.
- BibTeX: executed successfully; `main.bbl` was created.

## Citations and Cross-References

BibTeX read `references.bib` and resolved all expected citation keys:
`lewis2019p4id`, `tavares2021p4onids`, `brum2025rethinking`, and
`hagen2025rna`. The stabilized final log contains no undefined citation and
no undefined reference warning.

## Fatal Errors

None remain.

## Undefined Citations

None remain.

## Undefined References

None remain.

## Remaining Overfull Boxes

The final log has no underfull-box warning. Overfull boxes greater than 10 pt
are listed below; none was changed in this task.

| Width | Source lines | Kind | Likely cause | Mechanical correction to consider later |
|---:|---|---|---|---|
| 27.65 pt | 557--563 | Paragraph/code identifiers | Long `\\texttt` identifiers and compound backend terms in the installation-state definition. | Permit line breaks in identifiers (for example, `\\path`/`\\nolinkurl` with an appropriate package) or make a local wording/layout adjustment. |
| 13.61 pt | 557--563 | Paragraph | The `generated/expanded/normalized` compound and installation-state wording resist line breaking. | Add discretionary line breaks or adjust only local typography. |
| 53.53 pt | 575--580 | Paragraph/code identifier | `\\texttt{source\\_rule\\_ids}` in the provenance definition. | Use a breakable code/path representation or a local discretionary break. |
| 43.75 pt | 695--702 | Table | Eight-column semantic/backend table exceeds the article text width. | Use a width-constrained table layout, reduced table font, or split/reflow columns. |
| 294.33 pt | 720--729 | Table | Seven-column packet-selectivity table is substantially wider than the text block. | Redesign/split the table or use a width-constrained landscape/scaled layout after author review. |
| 100.50 pt | 787--796 | Table | Nine-column candidate-rule-set table exceeds the text width. | Reflow/split columns or use an appropriate constrained layout. |
| 10.92 pt | 814--818 | Paragraph | Long hyphenated preservation terminology. | Add a discretionary break or small local typography adjustment. |
| 307.39 pt | 845--854 | Table | Ten-column alert-preservation table substantially exceeds the text width. | Redesign/split the table or use a width-constrained layout after author review. |
| 121.45 pt | 1106--1112 | Paragraph/path | Long literal configuration paths in `\\texttt`. | Use a breakable path representation or localized line breaks. |

Low-priority overfull boxes remain at 0.28, 0.45, 2.14, 2.22, 4.47, and 6.47 pt.

## Underfull Boxes

None reported in the final log.

## Font Warnings

The final log reports:

```
Font shape `OMS/cmtt/m/n' undefined
using `OMS/cmsy/m/n' instead for symbol `textbraceleft'
```

It occurs at line 1141 in `\\texttt{file\\_inspect = \\{\\}}`. The escaped
braces request a symbol-font brace while typewriter text is active. A safe
future mechanical representation that preserves the literal content is
`\\verb|file_inspect = {}|` in this ordinary paragraph context. It was not
changed in this task. The summary warning about substituted font shapes is a
consequence of this same issue.

## Other Warnings

LaTeX changed one `[h]` float specifier to `[ht]`; this is non-fatal and was
not changed. The conceptual-figure placeholder was not changed.

## Next Mechanical Fixes Required

1. Decide a layout treatment for the four wide result tables before changing
   their structure.
2. Introduce a consistent, breakable representation for long code identifiers
   and configuration paths.
3. Replace the inline `\\texttt` brace construction with the safe verbatim
   representation above, if author-approved.

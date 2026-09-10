# LaTeX Layout Audit

## Build Status

- Commands run: `latexmk -C` and `latexmk -pdf -interaction=nonstopmode main.tex`.
- `latexmk` exit status: 0.
- PDF: 23 pages, 322,117 bytes.
- Fatal errors: none.
- Undefined citations: none in the stabilized final log.
- Undefined references: none in the stabilized final log.

## Mechanical Changes Applied

- Added `\\usepackage[hyphens]{url}` to support breakable literal paths.
- Replaced long configuration paths with `\\path{...}` in the appendix.
- Replaced the problematic brace construction with `\\verb|file_inspect = {}|`.
- Introduced local `\\allowbreak` points in the preservation terminology and
  separated one run-in paragraph heading from its body.
- Kept the semantic/backend table at `\\small` with compact headers and
  reduced local column spacing.
- Kept the packet-selectivity and candidate-rule-set tables at
  `\\footnotesize`, with compact multi-line headers and reduced local column
  spacing.
- Kept the alert-preservation table at `\\scriptsize`, with compact
  multi-line headers and reduced local column spacing.

These are typographic/layout changes only. No scientific text, numerical
value, result, claim, title, research question, or interpretation was altered.

## Overfull Boxes

| Category | Before | After |
|---|---:|---:|
| Overfull boxes greater than 10 pt | 9 | 0 |
| Largest overfull box | 307.39 pt | 6.47 pt |

Resolved elements above 10 pt:

| Previous width | Element | Technique |
|---:|---|---|
| 307.39 pt | Alert-preservation table | Compact multi-line headers, local `\\scriptsize`, and reduced `\\tabcolsep`. |
| 294.33 pt | Packet-selectivity table | Compact multi-line headers, local `\\footnotesize`, and reduced `\\tabcolsep`. |
| 121.45 pt | Appendix configuration paths | Breakable `\\path{...}` representation and sentence-local reflow. |
| 100.50 pt | Candidate-rule-set table | Compact headers, local `\\footnotesize`, and reduced `\\tabcolsep`. |
| 53.53 pt | `source_rule_ids` provenance identifier | Local breakable typewriter representation. |
| 43.75 pt | Semantic/backend table | Compact two-line header, local `\\small`, and reduced `\\tabcolsep`. |
| 27.65 and 13.61 pt | Installation-state identifiers | Breakable path-style identifiers. |
| 10.92 pt | Preservation-terminology paragraph | Local discretionary break points. |

Remaining low-priority overfull boxes are 0.28, 0.45, 2.22, 4.11, 4.25,
4.47, and 6.47 pt. No box at or above 10 pt remains. They were left intact
because they are minor and further changes would not improve the manuscript
proportionally.

## Underfull Boxes

None reported.

## Font Warning

The previous `OMS/cmtt/m/n` warning is resolved. The safe inline verbatim
representation preserves the literal `file_inspect = {}` content without
requesting a missing typewriter symbol-font brace.

## Other Remaining Warning

LaTeX still changes one `[h]` float specifier to `[ht]`. This is non-fatal and
does not affect citation, reference, or font resolution.

## Visual-Safety Check

Rendered inspection covered the semantic/backend table, packet-selectivity
table, candidate-rule-set table, alert-preservation table, and appendix table.
All were readable and stayed within the page margins. Captions and equations
remain legible; the bibliography was not affected. The conceptual-figure
placeholder was not changed.

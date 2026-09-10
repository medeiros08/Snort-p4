# Conceptual Figure Audit

## Integration

The conceptual-figure placeholder at the end of Results was replaced with a
TikZ vector figure in a single-column `figure` environment. The placeholder
text was replaced by a natural in-text reference to
`Figure~\\ref{fig:semantic-compilation-overview}`.

## Packages and Placement

- Added `tikz` with the minimal `arrows.meta` and `positioning` libraries.
- Added `placeins` and a `\\FloatBarrier` before Discussion so the figure
  remains with Results rather than being deferred to the document end.
- Figure label: `fig:semantic-compilation-overview`.
- Final placement: page 18; Discussion begins on page 19.

## Concepts Represented

The figure depicts:

1. Snort 3 rule input and semantic analysis.
2. An `UNSUPPORTED` branch delegated to Snort fallback.
3. A safe `NECESSARY` P4 predicate, target-aware lowering, and a P4 entry
   with rule provenance.
4. Compilation-manifest annotation for preservation, delegation, and
   provenance.
5. The implemented global binary prefilter branch: candidate/no-candidate,
   ruleset-scale predicate union, and observed limited bypass selectivity.
6. The provenance branch: matched entries, `source_rule_ids`, per-packet
   candidate rule set, and observed offline candidate-rule-space reduction.
7. The conceptual `EXACT` class, explicitly annotated as supported by the
   compiler but not observed in the evaluated ruleset.

## Implemented versus Offline Distinction

The implemented pipeline uses solid boxes and arrows. The provenance branch
uses dashed boxes and arrows and is explicitly titled `Offline provenance
analysis`. The caption states that dynamic candidate-set-aware IDS execution
is not implemented. Thus, the figure does not imply a runtime Snort rule mask,
runtime acceleration, or measured throughput/latency improvement.

## Caption

The caption explains semantic delegation/fallback, provenance-preserving
target-aware lowering, the limited selectivity of global binary aggregation,
the offline status of candidate-rule-set derivation, the absence of dynamic
candidate-set execution, and the `EXACT=0` evaluated result. It contains no
additional experimental percentage.

## Compilation and Layout Validation

- Commands: `latexmk -C`; `latexmk -pdf -interaction=nonstopmode main.tex`.
- `latexmk` exit status: 0.
- PDF: 25 pages, 335,910 bytes.
- Fatal errors, undefined citations, and undefined references: none in the
  final stabilized log.
- Font warnings: none.
- New overfull boxes above 10 pt: none.
- No underfull boxes were reported.

Visual inspection of pages 18--19 confirmed that the figure fits within the
text width, labels and arrows are readable, no arrows overlap labels, the
caption is complete, and the float is placed directly before Discussion.

## Scope Confirmation

The title, Abstract, Results text, Discussion text, Conclusion, RQs, frozen
numbers, and experimental interpretations were not changed. No experiment was
executed.

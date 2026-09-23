# Pipeline Architecture Figure Audit

## Integration

A second TikZ vector figure, `fig:pipeline-architecture`, was added at the
start of Section `Proposed Approach` (`sec:approach`), directly after the
paragraph that lists stages (i)--(v). One sentence was appended to that
paragraph to reference it. The figure becomes Figure 1; the existing
conceptual overview (`fig:semantic-compilation-overview`) becomes Figure 2.
All references use `\ref`, so no hardcoded figure number changed.

The only preamble change is the `shapes.symbols` TikZ library, used for the
wavy-bottom `tape` shape.

## Concepts Represented

1. Compiler stages (i)--(v), named as in the Section `Proposed Approach`
   text: rule parsing; variable resolution and IR construction; target
   capability analysis; semantic classification; P4 backend (expansion,
   normalization, lowering, deduplication).
2. Inputs: Snort 3 ruleset, Snort variable profile, target capability
   profile, P4 program (`ids_prefilter.p4`, compiled by `p4c`), replayed
   packet trace.
3. Generated artifacts: compilation manifest, P4Runtime installation plan.
4. Execution targets: Snort 3 (all rules, final detection) and BMv2, which
   marks and counts `P4_CANDIDATE`, `P4_NO_MATCH`, and
   `PACKET_DOMAIN_FALLBACK` separately.

## Claims Deliberately Not Made

- No arrow connects BMv2 to Snort. The manuscript states that the P4 program
  marks candidate metadata and does not implement a forwarding or bypass
  architecture in front of Snort; the caption repeats this.
- Dashed lines are not used. In Figure 2 a dashed style means offline
  provenance analysis, and reusing it here with another meaning would
  conflict.
- The figure contains no experimental number.

## Build Validation

Built from a scratch copy with MiKTeX (`pdflatex`, `bibtex`, `pdflatex`,
`pdflatex`, with `--enable-installer`); the versioned `main.pdf` was not
regenerated.

- Exit status 0 on every pass; no undefined references or citations.
- A baseline build of the committed `main.tex` with the same toolchain has
  32 pages and the same eleven overfull boxes (identical widths). The
  revised manuscript also has 32 pages and introduces no new overfull box.
- The figure is placed at the top of page 10; the section starts on page 9.
- Visual inspection: the figure fits the text width, no label overlaps a box
  or arrow, and no word is hyphenated inside a box.

## Scope Confirmation

No result, number, RQ, or interpretation was changed. No experiment was
executed.

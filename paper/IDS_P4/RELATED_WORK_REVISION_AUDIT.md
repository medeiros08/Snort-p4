# Related Work Revision Audit

## Scope

This revision changes only the Related Work positioning and bibliography. No
experiment was run, and no frozen experimental result, numerical value, title,
research question, rule, profile, compiler, P4 program, or result artifact was
changed.

## Bibliography

- References before revision: 4
- References after revision: 10
- BibTeX validation: successful through the complete `latexmk` build; no
  duplicate keys and no missing cited keys.

| Added key | Work | Section cited |
|---|---|---|
| `lewis2023fourmidable` | 4MIDable | 3.1, Rule-Derived and Hybrid P4 IDS Offloading |
| `fida2026pdpids` | Programmable-data-plane IDS survey | 3.3, Programmable-Data-Plane Security Landscape |
| `alsabeh2022p4securitysurvey` | P4 security applications survey | 3.3, Programmable-Data-Plane Security Landscape |
| `hauser2023p4survey` | General P4 survey | 3.3, Programmable-Data-Plane Security Landscape |
| `mazloum2025p4security` | P4 security implementation lessons | 3.3, Programmable-Data-Plane Security Landscape |
| `senoski2025p4nips` | P4NIPS | 3.1, Rule-Derived and Hybrid P4 IDS Offloading |

The existing P4ID, P4-ONIDS, eRBF, and RNA entries and discussions were
retained.

## Structural changes

The former four-paragraph Related Work section was restructured into four
compact thematic subsections:

1. **Rule-Derived and Hybrid P4 IDS Offloading**: P4ID, P4-ONIDS,
   4MIDable, and P4NIPS.
2. **Context Preservation and Hybrid IDS Processing**: eRBF and RNA.
3. **Programmable-Data-Plane Security Landscape**: the three surveys and the
   implementation-lessons work.
4. **Positioning of This Work**: semantic classification, manifest,
   delegation/fallback, provenance, and the separation of semantic safety from
   binary selectivity.

## P4ID factual correction

The previous wording could be read as describing P4ID solely as
header-derived, stateless filtering. It now states that P4ID derives filters
from Snort-rule header information **and combines stateless and stateful
packet-processing stages**. This is presented as an accurate capability, not
as a criticism.

## Comparison table

Table `tab:related-work-comparison` compares P4ID, P4-ONIDS, 4MIDable, eRBF,
RNA, P4NIPS, and this work across:

- source IDS/rules;
- P4 target;
- rule-derived filtering;
- state/context handling;
- explicit semantic relation;
- provenance retained; and
- main objective.

Entries use `Not explicit in reviewed scope` where the reviewed material does
not establish a feature. This wording deliberately does not infer feature
absence. The table is typeset on a landscape page so all scientific columns
remain readable.

## Novelty positioning

**Before:** the section emphasized that complex IDS semantics are not
reproduced by a data-plane representation and ended with a broad contrast to
other offloading approaches.

**After:** the section explicitly recognizes prior rule-derived filtering,
stateful assistance, resource-aware P4 representation, hybrid
IDS/data-plane execution, context preservation, and event-oriented offload.
It positions this manuscript as focusing on explicit characterization of the
semantic relation of partial compilation, manifest-recorded
preservation/delegation/fallback, provenance retained through lowering and
deduplication, and separate evaluation of semantic safety and aggregate binary
selectivity. Provenance is framed as an offline candidate-rule-space analysis,
not an implemented acceleration path.

## Claims intentionally not made

- No claim that this is the first Snort-to-P4 compilation approach.
- No claim that P4ID or 4MIDable lacks stateful processing.
- No claim that the surveys establish properties of the individual systems in
  the comparison table.
- No claim that P4NIPS performs general semantic Snort-to-P4 compilation.
- No claim that any prior system lacks a feature when that feature is not
  explicit in the reviewed scope.
- No new throughput, latency, acceleration, or detection-equivalence claim.

## Compilation and layout validation

The requested clean build was executed:

```text
latexmk -C
latexmk -pdf -interaction=nonstopmode main.tex
```

- Exit status: 0
- BibTeX: executed successfully
- Fatal errors: 0
- Undefined citations: 0
- Undefined references: 0
- Overfull boxes greater than 10 pt: 0
- Underfull boxes: 0
- Final PDF: 26 pages, 346,729 bytes

The related-work prose and landscape comparison table were rendered and
visually inspected. No clipping, overlap, or unreadable column was observed.

## Remaining author-review uncertainties

- The comparison table intentionally records only properties explicit in the
  reviewed scope; broader source-by-source feature comparison would require a
  dedicated literature review beyond this revision.
- The journal template or target venue may impose a policy on landscape tables;
  if so, the same columns should be retained in an approved wide-table format
  rather than removed.

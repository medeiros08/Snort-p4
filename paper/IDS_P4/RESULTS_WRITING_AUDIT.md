# Results Writing Audit

## Scope

Only `main.tex` was edited. The Results section was written against the frozen
official sources `output/analysis/FINAL_EXPERIMENTAL_RESULTS.md` and
`output/analysis/final_experimental_summary.json`, with the prior manuscript
fact check used as a constraint. No experiment or experimental artifact was
modified.

## Sections written

1. Semantic Compilation Coverage (RQ1)
2. P4 Backend Feasibility (RQ2)
3. Global Binary Prefilter Selectivity (RQ3)
4. Selectivity Causal Analysis (RQ3)
5. Candidate Rule-Set Reduction (RQ4)
6. Coarse-Grained Grouping Ablation (RQ4)
7. Dynamic Alert Preservation (RQ4)

## Tables added or completed

- Table~`tab:semantic-backend`: semantic classification and backend
  feasibility.
- Table~`tab:packet-selectivity`: total, parser-eligible, global candidate,
  global no-match, and strong-discriminator rates.
- Table~`tab:candidate-rules`: offline per-packet candidate rule-set
  feasibility.
- Table~`tab:alert-preservation`: observed semantic-split and P4
  alert-packet preservation.

## Numerical claims checked

| Topic | Checked values | Frozen source |
|---|---|---|
| Semantic coverage | 4,017 parsed; EXACT 0; NECESSARY 4,003; UNSUPPORTED 14; 99.65% candidate coverage | Final Results §§1, 12 Table A |
| Backend | 6,675 instances; 327 unique matches; 331 final entries; 331/331 P4Runtime; zero failures; 8,192 capacity; 95.04% installation-state reduction | Final Results §§2, 12 Table B |
| Global selectivity | SQLi 34,924/34,924; XSS 189,076/189,076; held-out Brute Force 1,101,475/1,101,475 | Final Results §§3, 12 Table C |
| Strong ablation | 3,611 eligible; 392 operational fallback; 14 unsupported fallback; 322 entries; held-out 98.941% candidate and 11,662 no-match | Final Results §§5--6 |
| Candidate-rule sets | SQLi 95.04%; XSS 96.11%; held-out 324.52 mean, median 241, P90/P95 799, P99 1,227, max 1,228, 91.01% | Final Results §§6, 12 Table D |
| Alerts | SQLi 150; XSS 528; held-out 2,391 with five SIDs; 2,289 strong eligible events, 102 fallback, 2,289/2,289 membership | Final Results §8, Table E |

## Intentional qualifications

- All global and strong-discriminator candidate rates are stated as rates
  among parser-eligible packets; parser-ineligible frames are excluded from
  that denominator.
- The 95.04% backend result is named installation-state reduction, not
  traffic reduction, Snort reduction, or speedup.
- Strong discriminator is described as a frozen operational ablation, not a
  new semantic classification.
- Candidate-rule-set figures are explicitly offline feasibility results; no
  candidate-set-aware Snort execution engine was implemented.
- Alert results are consistently named observed alert preservation. The text
  does not claim formal equivalence, guaranteed arbitrary-traffic preservation,
  or detection accuracy.
- Brute Force is identified as held-out and not used for policy retuning.

## Remaining TODOs

- Produce the conceptual architecture figure described by the Results
  placeholder.
- Compile the document when a LaTeX toolchain becomes available.
- Discussion was intentionally not edited in this Results-writing task.

## Inconsistencies

No inconsistency was found between the numerical claims inserted in Results
and the frozen official result summaries.

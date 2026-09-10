# Discussion Writing Audit

## Subsections written

1. Semantic Safety Does Not Imply Operational Selectivity
2. The Union Effect in Large Rule Sets
3. From Binary Packet Bypass to Candidate-Rule Selection
4. Why Coarse-Grained Grouping Did Not Help
5. Implications for P4-Based IDS Offloading

## Central interpretations

- Semantic safety (`r => p_r`) is distinct from operational selectivity;
  neither the converse nor equivalence is claimed for NECESSARY predicates.
- Broad predicates contributed to global coverage, but residual distributed
  union coverage persisted after the frozen strong-discriminator ablation.
- Entry-level provenance retains rule information discarded by a global binary
  candidate bit and supports offline candidate-rule-space feasibility.
- Coarse grouping was limited by overlap under the evaluated ruleset and
  strategies; it did not create the observed 91--96% reduction.
- The architectural implication is provenance-aware downstream selection, not
  implemented Snort acceleration.

## Citations reused

- `\cite{lewis2019p4id,tavares2021p4onids}` for existing work on rule-derived
  P4 filtering and resource-aware data-plane representations.
- `\cite{brum2025rethinking}` for the relevance of IDS context beyond packet
  header matching.
- `\cite{hagen2025rna}` for coordinated programmable-data-plane and IDS
  processing.

## Citation TODOs

None added. The Discussion makes no comparative claim requiring a reference
outside the bibliography already present in the manuscript.

## Numerical claims checked

| Claim family | Checked values | Frozen source |
|---|---|---|
| Semantic classes | 4,003 NECESSARY; 14 UNSUPPORTED; EXACT 0; 4,017 total; 99.65% | Final Results §§1, 12 Table A |
| Strong ablation | 322 entries; 3,611 eligible; 392 operational fallback; 14 unsupported fallback; 98.941% held-out candidate rate | Final Results §5 |
| Candidate-rule sets | 95.04% SQLi; 96.11% XSS; Brute Force mean 324.52, median 241, P95 799, P99 1,227, max 1,228, reduction 91.01% | Final Results §6 |
| Grouping | 4, 12, 268, and 308 groups; overlap-limited conclusion | Final Results §7 |

## Limitations explicitly preserved

- Candidate rates are conditioned on parser-eligible packets.
- Candidate-set results are offline feasibility measurements.
- Dynamic stateful candidate-set execution is unresolved and was not
  implemented.
- No throughput or latency benchmark was conducted; no speedup is claimed.
- Observed alert preservation is not formal equivalence or arbitrary-traffic
  detection preservation.
- Brute Force remains held-out and no policy retuning is asserted.

## Overclaims removed or avoided

- No proof, guarantee, formal-equivalence, full-offload, traffic-reduction,
  throughput-improvement, latency-improvement, or speedup claim is made.
- The Discussion does not attribute poor selectivity solely to the three
  initially broad predicates.
- Grouping is not presented as universally ineffective.

## Statements needing author review

- The proposed future design space (rule masks, partitions, hierarchical
  selectors, candidate metadata, and dependency-aware scheduling) is framed
  as motivation only; authors should retain this framing unless an
  implementation or additional evidence is added.
- The existing Discussion citations are reused for context, not for direct
  empirical comparison of results across systems.

## Structural check

The Discussion contains exactly the five requested subsections. LaTeX
compilation remains unavailable in the current environment because no
`pdflatex` executable is installed; structural environment checks were used
instead.

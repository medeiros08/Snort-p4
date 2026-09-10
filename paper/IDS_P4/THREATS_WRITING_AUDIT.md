# Threats to Validity Writing Audit

## Subsections written

1. Construct Validity
2. Internal Validity
3. External Validity
4. Implementation and Target Limitations
5. Limitations of the Candidate-Set Analysis

## Threats covered

- Construct separation among semantic coverage, equivalence, packet
  selectivity, installation state, candidate-rule-space reduction, observed
  alert preservation, and runtime performance.
- Development/diagnostic use of SQLi and XSS, held-out Brute Force, frozen
  policies and grouping strategies, residual-analysis scope, and flowbit
  dependency-audit scope.
- Dependence on the experimental Snort variable profile, ruleset/version,
  HOME_NET and service-port configuration, CICIDS2017 distribution, selected
  Thursday windows, NAT-affected capture address, and limits of generalization.
- BMv2/v1model target, parser scope, no VLAN support, parser-ineligible
  denominator, unsupported encapsulations/protocols, and lack of hardware or
  line-rate evaluation.
- Offline candidate-set analysis, absent dynamic Snort activation, stateful
  semantics, and the limited meaning of observed 2,289/2,289 SID membership.

## Limitations explicitly retained

- `EXACT=0` is stated as both target/profile limitation and conservative
  classification behavior.
- 95.04% is installation-state reduction only.
- Candidate rates are conditioned on parser-eligible packets.
- SQLi/XSS names are not treated as proof of matching Snort alert semantics.
- Candidate-set reductions remain offline feasibility results.
- No throughput, latency, speedup, line-rate, or production-hardware claim is
  made.
- No formal or arbitrary-traffic equivalence is claimed.

## Claims narrowed

- The static absence of cross-partition flowbit dependencies is limited to the
  evaluated ruleset and does not establish stateful safety for arbitrary Snort
  rulesets.
- Strong discriminator remains an operational ablation, not a semantic
  reclassification.
- Grouping is limited only under the evaluated strategies; no universal claim
  about future grouping algorithms is made.
- Held-out Brute Force strengthens evidence within the setup but does not
  establish production-network generalization.

## Remaining TODOs

- Add a dataset/capture-method reference or explanatory provenance note if the
  final paper needs to substantiate the NAT-affected attacker address.
- Compile with a LaTeX toolchain when one is available.
- Future work may evaluate hardware targets and dynamic stateful
  candidate-set execution; these are not current claims.

## Statements requiring author review

- Confirm whether the NAT-address observation should be supported with a
  dataset-method citation or retained as an experiment-specific observation.
- Confirm whether the chosen experimental variable profile should be included
  verbatim in an appendix for reproducibility.

## Structural check

The Threats section contains exactly the five requested subsections. Results,
Discussion, and Conclusion were not edited in this task. LaTeX compilation is
not available in the environment because `pdflatex` is absent; structural
environment checks are required until a toolchain is installed.

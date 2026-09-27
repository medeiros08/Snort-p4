# Pre-Submission Review Items: Resolution Audit

**Date:** 2026-09-27
**Scope:** the "Antes de submeter" items of
`docs/review/2026-09-11_analise_completa.md` §9 that are still open in
`main.tex`, plus the service-based header finding
(`SERVICE_BASED_HEADER_FINDING.md`), which surfaced while expanding the
Background from the pinned Snort 3 corpus. No frozen number is changed.

## 1. Status of the Review Items

| Item | Before this revision | Resolution |
|---|---|---|
| C1 grouping ablation measures nothing | Text presented the across-strategy invariance as an observation | Option A1 of `docs/review/2026-09-13_achados_experimentais.md`: Results and Discussion now say the invariance is by construction, and bound the cost of grouping from the recorded group structure. The grouped candidate set (A2) still needs the traces on the rig. |
| C3 PDF older than the correction | — | Already resolved (`cc4c2dd`). |
| C4 Table 7 is pre-correction | No caveat | Text and caption state that the P4 columns were replayed alone on BMv2 before the domain gate; an offline re-derivation under the enforced domain reproduces them (new artifact). The data-plane replay remains for the rig. |
| C5 offline vs data plane | Strong columns unlabeled | Table 5 caption and the causal-analysis paragraph state that strong-discriminator rates are offline; the held-out strong audit is labeled offline; the 322-entry plan's only BMv2 installation is the campaign. |
| H1 alert diversity | — | Resolved in `f265520` (Threats, External Validity). |
| H2 conservative reduction | 81.81/85.43/86.40 absent | Defined as $R_{\mathrm{full}}$ in Methodology; reported in Results, Table 6 (new column), Abstract, Introduction, Contributions, Discussion, Limitations, and Conclusion. |
| H5 citations | CICIDS2017, Snort, P4, BMv2, P4Runtime uncited | Seven references added and cited; titles brace-protected. |
| H6 strong-discriminator criterion | Undefined in the manuscript | Criterion stated from `tests/simulate_operational_policy.py::classify_entry_policy`, and the nine removed entry IDs listed. |
| M8 reproducibility statement | — | Already present (versions in Methodology; Artifact Availability). |
| B12 unreferenced `sec:domain-validation` | — | Now referenced from the campaign results. |

## 2. New Numbers and Their Sources

| Manuscript number | Source |
|---|---|
| TCP group holds 3,439 of 3,611 rules; at most 4.8% reduction | `output/analysis/grouped_prefilter_feasibility.json` `rules_per_group.max`; group key `protocol=6` recomputed with `tests/analyze_grouped_prefilter_feasibility.py::group_key` over the 322 retained entries; 1 − 3439/3611 = 4.76% |
| Port-80 TCP group holds 2,024 rules; 2,358 rules in more than one group, up to nine | same recomputation (`protocol_service`); `group_overlap` in the artifact |
| 150/528/2,391 candidate-alert packets reclassified offline, 0 no-match, 0 fallback | `output/analysis/alert_preservation_offline_post_correction.json` (`tests/rederive_alert_preservation_offline.py`) |
| Strong criterion and nine removed IDs | `output/analysis/operational_policy_simulation.json` `policies.strong_discriminator.install_entries.removed_entry_ids`; matches read from `output/p4_install_entries.json` |
| 85.43%, 86.40%, 81.81% | (1 − (mean + 406)/4017) × 100 with the frozen means 179.2848, 140.4900, 324.5181; equals `FINAL_SCIENTIFIC_CLOSING_AUDIT.md` §10 |
| 2,928 service-based NECESSARY rules; 2,877 P4-eligible; 2,921 keep an address predicate; 7 would not | `output/analysis/service_based_header_exposure.json` (`tests/analyze_service_based_headers.py`) |
| 1,075 NECESSARY rules without a declared service | 4,003 − 2,928 |
| Global plan covers 2,919 fully and 9 on TCP only; strong plan covers none | same artifact, `cobertura_da_regiao_sem_porta_e_protocolo` |
| Service counts http 2,316, imap 150, pop3 138, smtp 131 | same artifact, `expostas.servicos` |

## 3. Snort 3 and P4 Statements Added to the Manuscript

Each is backed by the pinned corpus (`./scripts/fetch_reference_docs.sh
status`: all five sources aligned) or by the Snort 3.12.2.0 source.

| Statement | Source |
|---|---|
| Rule header fields and body | `docs/vendor/snort3/doc/user/concepts.txt` (rule anatomy, action/proto/source/dir/dest/body) |
| Fast-pattern search, left-to-right option evaluation aborting on first failure | `concepts.txt`, "Pattern Matching" and "Rule Evaluation" |
| What makes a rule service-based; header evaluation skipped | `concepts.txt:290-296` |
| Ports and protocol skipped, addresses checked, mismatched service rejected | `src/detection/detection_options.cc`, `src/detection/rtn_checks.cc`, `src/parser/parse_rule.cc` at tag 3.12.2.0 |
| Match kinds `exact`, `ternary`, `lpm`; v1model adds `range`, `optional` | `docs/vendor/p4c/p4include/core.p4:75-82`, `v1model.p4:49-52` |
| `simple_switch_grpc` serves P4Runtime | `docs/vendor/bmv2/docs/simple_switch.md:36-37` |
| Pipeline configuration and entry writes; ternary entries carry priority | `docs/vendor/p4runtime/proto/p4/v1/p4runtime.proto:31-37`; `P4Runtime-Spec.mdk:3106` |

## 4. Tests Added

- `tests/test_service_based_headers.py`: coverage classification on synthetic
  entries, the port filter, and coherence of the exposure and re-derivation
  artifacts.
- Suite: 17 pass, 3 environment (grpc), 0 fail.

## 5. Build Validation

MiKTeX, scratch copy, pdflatex + bibtex + pdflatex ×3: exit 0, no undefined
references or citations, the same ten pre-existing overfull boxes, 42 pages.
Pages with the new Background, §4.5, §7.2, Table 6, and the bibliography were
inspected.

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
| C1 grouping ablation measures nothing | Text presented the across-strategy invariance as an observation | Option A1 of `docs/review/2026-09-13_achados_experimentais.md`: Results and Discussion now say the invariance is by construction, and bound the cost of grouping from the recorded group structure. The grouped candidate set (A2) was then measured offline on the traces (§8) and replaces the missing measurement; the structural 4.8% bound stays as context. |
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
| 85.43%, 86.40%, 81.81% | (1 − (mean + 406)/4017) × 100 with the frozen means 179.2848, 140.4900 and, for Brute Force, 324.5228 from the post-correction `output/analysis/ipv4_packet_domain_correction/heldout_bruteforce_revalidation.json` (1,101,459 eligible frames, the population the manuscript reports). The pre-correction 324.5181 of `FINAL_SCIENTIFIC_CLOSING_AUDIT.md` §10, which an earlier version of this row cited, gives the same 81.81% and 91.01% |
| 2,928 NECESSARY rules with `service:`; 2,877 P4-eligible; 2,921 keep an address predicate; 7 would not | `output/analysis/service_based_header_exposure.json` (`tests/analyze_service_based_headers.py`), `expostas` |
| 3 more service-based through DCE options (529, 3238, 3239), 2,931 in all; 2,924 would keep an address predicate | same artifact, `expostas_por_servico_implicito` and `service_based_total`; mechanism in §7 |
| 1,072 NECESSARY rules whose header ports Snort checks | 4,003 − 2,931: the 1,060 port-based rules plus the 12 `alert http` header rules, which `USER_MODE` keeps port-checked (`necessarias_com_protocolo_de_servico_no_cabecalho`) |
| 927 payload-negatives candidate without alert; 7 with alert | `e2e_1000_v4/resultado_strong.jsonl`: candidate payload-negatives by alerted role; the 7 rules (622, 630, 1257, 1415, 1417, 1420, 1421) have no `content` |
| Global plan covers 2,919 + 3 = 2,922 fully and 9 on TCP only; strong plan covers none | same artifact, `cobertura_da_regiao_sem_porta_e_protocolo` and `expostas_por_servico_implicito.cobertura_por_plano` |
| Service counts http 2,314, imap 150, pop3 138, smtp 131 | same artifact, `expostas.servicos` (an earlier revision printed 2,316, the count over all 4,017 rules) |
| Snort 3 semantics: 3,996 / 21, 235 final entries, 739 eligible, 3,257 fallback | `output/analysis/service_header_semantics_whatif.json` (`tests/whatif_service_header_semantics.py`; the legacy side reproduces 3,611 / 392 / 322) |
| 18.40% bound | 739 / 4017, i.e. 1 − (3,257 + 21) / 4,017 |

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
- `tests/test_service_header_semantics.py`: the `snort3` manifest mode, the
  flags exception, and coherence of the what-if artifact.
- Suite: 19 pass, 3 environment (grpc), 0 fail.

## 5. Adversarial Review of the Full Manuscript

After the items above, the whole manuscript was reviewed adversarially
against the artifacts and the Snort 3.12.2.0 source. Every finding was
checked before it was applied; one was rejected.

| Finding | Change |
|---|---|
| Abstract led with the service-based caveat before the results it qualifies | Reordered: results first, then the scope of the necessary relation; "is meant to retain" replaces "conservatively retains" |
| Proposed pipeline read as one deployed system with BMv2 forwarding to Snort | Methodology states that it is evaluated by composition, that no component forwards from BMv2 to Snort, and defines $A_{\mathrm{pipeline}}$ as the union of the two partition runs |
| 1,075 "rules without a declared service" counted the 12 `alert http` rules and three rules with service-specific options inconsistently | 1,060 port-based + 12 `USER_MODE` = 1,072 whose header ports Snort checks; the three are declared unconfirmed (RQ1, Results, Conclusion) |
| §4.5 said the documentation states "the same behavior" | "a coarser form of this rule", and the `USER_MODE` exception is stated with its source files |
| http 2,316 | 2,314 (the count over the 2,928; 2,316 is over all 4,017 rules) |
| "nearly all" constrain a port | 2,877 |
| Strong plan's port-free entries described as none | It removes nine and keeps six (TCP flags or other addresses), none of which contains an exposed rule's region |
| Campaign payload-negatives 934 candidate without alert | 927 without alert and 7 with alert (rules with no `content`), under the strong plan |
| Witness attribution overstated | Each confirmed witness is matched by its own rule's entries and also by an entry of another rule |
| RQ3 called the global prefilter conservative without exception | Except non-TCP traffic of nine service-based rules; the strong ablation is not conservative for service-based rules |
| SQLi 95.04% could be read as the installation-state reduction | Stated as a coincidence with Table 3 |
| "Why no experiment observed it" relied on trace checks | Under the global plan such an alert falls on a packet `p4-40`, `p4-138` or `p4-106` already marks; only the offline strong audit could see it, and it found no missing event |
| Stage numbering, unreferenced Tables 1 and 3, witness-exclusion reason | Stages (i)–(iii) aligned with Figure 1; both tables referenced; exclusions split into unsatisfiable state and generator limits |
| Rejected: the 12 `alert http` header rules are exposed | `SetupRTNFuncList` marks them `USER_MODE` and `fp_eval_rtn` forces `check_ports = 1`; the finding led only to the wording fix in §4.5 |

## 6. Build Validation

MiKTeX, scratch copy, pdflatex + bibtex + pdflatex ×2, sources compared with
`cmp` against the repository: exit 0, no undefined references or
citations, 43 pages. `microtype` and `\emergencystretch` were added and the
related-work table narrowed, which removed every overfull and underfull box
(ten overfull before this revision). Pages with the new Background, §4.5,
§7.2, §7.10, Table 6, and the bibliography were inspected.

## 7. The Three Rules Left Unconfirmed

The first revision of §7.2 counted fifteen NECESSARY rules without `service:`
that use service-specific options and left three of them (529, 3238, 3239)
unconfirmed. Their mechanism is now traced in the Snort 3.12.2.0 source
(`SERVICE_BASED_HEADER_FINDING.md` §2.3):

| Step | Source |
|---|---|
| `validate_services` runs for every rule after the header service is added | `src/parser/parse_rule.cc:1278-1287` |
| A buffer-setting option adds the services registered for its buffer when the rule has none; other options use `guess_service` | `src/detection/fp_utils.cc:110-205, 496-574` |
| The buffer map is built from every inspector plugin, configured or not | `src/managers/inspector_manager.cc:808-818` |
| `dce_tcp`/`dce_udp` register `dce_iface` and `dce_stub_data` under `dcerpc`, `dce_smb` under `netbios-ssn` | `src/service_inspectors/dce_rpc/dce_tcp.cc:210-235`, `dce_udp.cc:200-225`, `dce_smb.cc:486-511` |
| Both options are buffer setters (`CAT_SET_FAST_PATTERN`) | `ips_dce_iface.cc:229-230`, `ips_dce_stub_data.cc:57-58` |

The three rules are therefore service-based, which gives 2,931. Their
predicates constrain the protocol and a `HOME_NET` destination and no port
(each port list contains a range), the global plan covers them through
`p4-40`, and the strong plan keeps them in operational fallback. The 12
`alert http` rules are service-based too, but `USER_MODE` keeps their ports
checked, so 1,072 is unchanged.

The compiler's `snort3` mode now uses the same test
(`snort3_service_based` in `compiler/target_capability.py`), excluding
`USER_MODE` headers. `legacy` regenerates every versioned artifact byte for
byte (worktree check), and the `snort3` what-if numbers are unchanged:
3,996 / 21, 235 entries, 739 eligible, 3,257 fallback. The manuscript's
Abstract, Introduction, Contributions, §4.5, §7.1, §7.2, Construct Validity,
Discussion, and Conclusion now count 2,931, and §4.5 states how a rule
acquires services. Rebuilt: 43 pages, no overfull or underfull box.

## 8. Trace Metrics Measured Offline

With the user's authorization, `Thursday-WorkingHours.pcap` was downloaded
from the mirror recorded in `output/datasets/cicids2017_thursday_metadata.json`.
`tests/cut_cicids2017_windows.py` read it once and cut the three windows. The
capture's sha256, packet count and captured bytes, and every window's packet
count, captured bytes and first and last timestamps, equal the record
(`output/datasets/cicids2017_windows_offline_cut.json`).
`tests/rederive_trace_metrics.py` then ran both semantics. Its legacy pass
reproduced the frozen post-correction eligible counts, global and strong
candidate counts and mean candidate sets of all three windows, which it
checks before it writes anything.

| Manuscript number | Source (`output/analysis/trace_metrics_by_semantics.json`) |
|---|---|
| `snort3` strong rates 92.298% / 92.173% / 94.885% | `snort3.janelas.<w>.strong_candidato_pct` |
| `snort3` mean candidate sets 3.97 / 3.94 / 4.48 of 739; above 99.3% within the partition | `snort3.janelas.<w>.candidate_set_por_entrada` |
| `snort3` full-ruleset reduction 18.30% / 18.30% / 18.29% | same, `reducao.sobre_ruleset_pct` (fallback 3,257 + unsupported 21 counted on every packet) |
| `snort3` global plan 100% | `snort3.janelas.<w>.global_candidato_pct` |
| Table `tab:grouped` and the 12.30–19.10%, 54–57%, 81–92% ranges | `legacy.janelas.<w>.candidate_set_agrupado.<strategy>` |
| Finest grouping within 0.01 points of entry level | largest gap 0.0096 points (Brute Force) |

Manuscript sections changed: Abstract, Introduction, Contributions,
Methodology ($C_G$ defined), §7.2, the grouping subsection with the new
Table `tab:grouped`, the RQ4 answer, the Discussion subsection now titled "Why
Coarse Grouping Does Not Help", the Limitations, and the Conclusion. Nothing
frozen was rewritten. The measurements are offline, and no plan of the
corrected compilation has been installed on BMv2.

### 8.1 Observed Alerts Under Both Semantics

`tests/rederive_alert_coverage_by_semantics.py` →
`output/analysis/alert_coverage_by_semantics.json` repeats, over the cut
windows, the event-level audit of the strong-discriminator plan. It maps each
alert of `baseline_full.jsonl` to the frame with the same `pkt_num` and
checks that the frame's addresses are the alert's. All 3,069 match: 3,068
directly, and one (Brute Force `pkt_num` 776606, SID 650) on the
reverse-direction frame that flushed the reassembled data.

| | SQLi | XSS | Brute Force |
|---|---:|---:|---:|
| alerts | 150 | 528 | 2,391 |
| legacy: covered in the candidate set / fallback / missing | 150 / 0 / 0 | 521 / 7 / 0 | 2,289 / 102 / 0 (frozen audit reproduced) |
| snort3: covered / fallback / missing | 0 / 150 / 0 | 0 / 528 / 0 | 0 / 2,391 / 0 |

Under `snort3`, SID 254 (`service:dns`, 2,960 of the 3,069 alerts) keeps only
its `HOME_NET` destination and becomes operational fallback, like the other
four SIDs. No alert is lost, and none exercises the corrected candidate sets.
The manuscript's §7.2 and RQ4 answer say so.

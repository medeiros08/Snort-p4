# Header-Semantics Default Supersession

## 1. Decision and status

On 2026-10-05 the compiler's default header semantics for service-based rules
changed from `legacy` to `snort3`, by the author's decision. The reason is
`SERVICE_BASED_HEADER_FINDING.md`. Snort 3.12.2.0 does not check header ports
or protocol once it has identified a flow's service. The data-plane test of
2026-09-29 (its §9) confirmed this for 190 HTTP rules. Under `legacy`, the
compiled predicate of the 2,931 service-based `NECESSARY` rules is a
necessary condition only on traffic whose service Snort has not identified.

The manuscript will report the `snort3` numbers as its results and the
`legacy` ones as history, explaining the change.

**Status:**

- The pipeline artifacts at the root of `output/` are now the `snort3`
  compilation. They supersede the `legacy` ones as the compiler's output.
- The `legacy` artifacts are archived byte for byte in
  `output/historical/legacy_header_semantics/`, and every result measured
  with them stays valid as a `legacy` result (§5).
- Data-plane measurements under `snort3` are pending (§6).

## 2. What changed in the code

| File | Change |
|---|---|
| `compiler/target_capability.py` | `assess_rule` defaults to `snort3`; comment points to the archive |
| `compiler/generate_semantic_manifest.py` | `--service-header-semantics` defaults to `snort3`. The manifest still records the semantics only for `snort3`, so a `legacy` run stays byte-identical to the archive. |
| `compiler/run_static_pipeline.py` | new `--semantica {snort3,legacy}`, recorded in `proveniencia.json` |
| `tests/test_service_header_semantics.py` | `test_padrao_e_legacy` becomes `test_padrao_e_snort3` |
| `tests/rederive_trace_metrics.py`, `tests/rederive_alert_coverage_by_semantics.py`, `tests/whatif_service_header_semantics.py`, `tests/analyze_service_based_headers.py` | their `legacy` inputs are read from the archive instead of the root of `output/` |
| `tests/simulate_operational_policy.py` | default output is `operational_policy_simulation_snort3.json`; the frozen `operational_policy_simulation.json` is no longer the default target |
| `tests/build_strong_plan.py` | new `--semantica`. Simulation, entries, and plan always come from the same semantics, because entry ids (`p4-N`) are positional and mean different entries under each one. |
| `README.md`, `docs/semantic_model.md`, `docs/snort3_support_matrix.md` | `snort3` described as the default |

## 3. Archive

`output/historical/legacy_header_semantics/` holds the ten `legacy` pipeline
artifacts exactly as committed at `8c09ad8`, with `SHA256SUMS`:

- `semantic_manifest.json` (`7d34be6b…`)
- `snort_candidate.rules`, `snort_unsupported.rules`,
  `snort_experiment_split.json`
- `p4_entries.json`, `p4_entries_expanded.json`, `p4runtime_entries.json`
- `backend_validation.json`
- `p4_install_entries.json` (`75494c0f…`)
- `p4runtime_install_plan.json` (`d7558983…`)

The compiled P4 program (`output/ids_prefilter.json`, `.p4info.txt`) does not
depend on the semantics and did not change.

## 4. Verification

### 4.1 `legacy` is still reproducible

`compiler/run_static_pipeline.py --semantica legacy` on the project ruleset
regenerates all ten archived artifacts byte for byte (4,003 / 14 / 0, 331
entries).

### 4.2 `snort3` gives the predicted structure

The new default regenerates the root of `output/`, and the stand-alone
executor produces the same ten files byte for byte. The numbers equal the
what-if prediction (`output/analysis/service_header_semantics_whatif.json`):

| | `legacy` (archived) | `snort3` (root of `output/`) |
|---|---:|---:|
| NECESSARY / UNSUPPORTED / EXACT | 4,003 / 14 / 0 | 3,996 / 21 / 0 |
| predicate instances | 6,675 | 4,040 |
| unique matches before flag lowering | 327 | 231 |
| final P4 entries (= P4Runtime plan) | 331 | 235 |
| backend validation errors / warnings | 0 / 0 | 0 / 0 |
| strong-discriminator eligible / fallback / entries kept | 3,611 / 392 / 322 | 739 / 3,257 / 225 |

`snort3` sha256: `semantic_manifest.json` `5a21897e…`,
`p4_install_entries.json` `a9461ef7…`, `p4runtime_install_plan.json`
`b11a2510…`.

### 4.3 The frozen analyses still reproduce from the archive

Re-run after the repointing, and compared with the committed results
ignoring only timestamps:

- `tests/whatif_service_header_semantics.py` is identical.
- `tests/analyze_service_based_headers.py` differs only in the recorded
  input path, which now names the archive.
- `tests/simulate_operational_policy.py` on the archive differs from the
  frozen `operational_policy_simulation.json` only in the four recorded pcap
  paths (`/home/arthur/...` on the earlier rig, `/mnt/c/...` now).

The frozen files were left as committed.

### 4.4 Trace metrics and alert coverage

Both scripts were re-run over the three windows cut on this machine, with
their `legacy` side read from the archive and their `snort3` side compiled
by the script itself. Output went to a scratch directory. Compared with the
committed `output/analysis/trace_metrics_by_semantics.json` and
`output/analysis/alert_coverage_by_semantics.json`, ignoring timestamps and
commit ids, both are **identical** under both semantics.

| Metric under `snort3` | SQLi | XSS | Brute Force |
|---|---:|---:|---:|
| strong-discriminator candidate rate | 92.298% | 92.173% | 94.885% |
| mean C(x), of 739 eligible | 3.97 | 3.94 | 4.48 |
| full-ruleset reduction | 18.30% | 18.30% | 18.29% |
| observed alerts: missing / via fallback | 0 / 150 | 0 / 528 | 0 / 2,391 |

As already reported, every observed alert under `snort3` comes from rules
in operational fallback. The traces therefore do not exercise the `snort3`
strong-discriminator candidate sets.

## 5. What stays valid, and as what

Every result measured before the switch was measured with the `legacy`
compilation and stays valid as such. It is not re-labelled as `snort3`.

| Result | Status |
|---|---|
| Static `legacy` numbers (4,003 / 14 / 0, 6,675 → 331, 95.04%) | valid, `legacy`; archived inputs |
| Frozen trace rates, candidate sets, and alert audits (`output/analysis/`, `output/experiments/`) | valid, `legacy` |
| Data-plane replays (`ipv4_packet_domain_correction/`, `replay_pos_correcao/`) | valid, `legacy` plan of 331 entries |
| Campaigns `e2e_1000_v2`–`v4` and `servico_fora_do_cabecalho` | valid, `legacy` plans (global 331, strong 322) |
| `snort3` offline numbers already in the manuscript (§7.2) | now the primary compilation; they match the new root artifacts (§4.2) |

New `snort3` artifacts, all under new names so that nothing frozen is
overwritten:

- `output/analysis/operational_policy_simulation_snort3.json`
- `output/campaign/plano_strong_discriminator_snort3/` (225 entries, 739
  rules prefiltered, 3,257 in operational fallback)

## 6. Pending

- **Data plane (rig).** Re-measure under the `snort3` plans:
  - the controlled packet-domain and flag cases;
  - the replay accounting of the three windows;
  - alert-packet preservation;
  - the end-to-end campaign;
  - the off-port service test. No VIOLATION is expected under either
    plan: `snort3` predicates no longer constrain the port, so each rule is
    either prefiltered by an address-only predicate that covers the witness,
    or, under the strong-discriminator plan, in operational fallback.
- **Manuscript.** Report the `snort3` numbers as results and the `legacy`
  ones as history.

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
- The data-plane measurements were redone under the `snort3` plans on the
  rig on 2026-10-05/06. Every one matches its offline prediction exactly,
  with no VIOLATION (§6). Only the manuscript is pending (§7).

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
- `output/campaign/particoes_snort3/{global,strong}.json`: the fallback
  partitions of the campaigns (global: the 21 UNSUPPORTED; strong: those
  plus the operational fallback, 3,278)
- `output/analysis/replay_expected_snort3.json`: the offline expected counts
  of every replay (`tests/expected_replay_counts.py`)
- the data-plane results of §6

## 6. Data-plane measurements under `snort3`

Run on the rig with `scripts/rig_fase_b_snort3.sh tudo` at commit `14c2042`,
from 2026-10-05 to 2026-10-06. Plans: global `b11a2510…` (235 entries) and
strong `6d65b1d4…` (225 entries). Every installation read back all its
entries (`Installation status: VALID`).

Every measurement equals its offline prediction exactly. There is no
VIOLATION and no STATE DEPENDENCY.

### 6.1 Controlled cases (global plan)

- **IPv4 packet-domain guard:** `VALID`, 11/11
  (`output/analysis/ipv4_packet_domain_guard_test_snort3.json`). The
  `legacy` 11/11 in `ipv4_packet_domain_guard_test.json` is untouched.
- **TCP flag lowering:** `VALID`, candidate delta +6 of +6 expected
  (`output/analysis/fase_b_snort3/controlados/flags.log`).

### 6.2 Replay accounting

Protocol of the handoff §11: fresh switch, `txqueuelen` 10000, exact-bytes
AF_PACKET sender at 2 ms, 10 s idle audit and 10 s drain. Results are in
`output/analysis/replay_snort3/{global,strong}/`, each with a
`resultado.json` from `tests/analyze_replay_pos_correcao.py`.

All 12 measurements are `ACCOUNTING_VALID`:

- the idle delta is zero;
- the switch counted every frame sent, so no frame was lost;
- each counter category equals the offline expectation in
  `output/analysis/replay_expected_snort3.json`.

| Measurement | Frames | Global: cand / no-match / fallback | Strong: cand / no-match / fallback |
|---|---:|---:|---:|
| SQLi alert packets | 150 | 150 / 0 / 0 | 0 / 150 / 0 |
| XSS alert packets | 528 | 528 / 0 / 0 | 0 / 528 / 0 |
| Brute Force alert packets | 2,391 | 2,391 / 0 / 0 | 3 / 2,388 / 0 |
| SQLi window | 35,274 | 34,924 / 0 / 350 | 32,234 / 2,690 / 350 |
| XSS window | 191,848 | 189,076 / 0 / 2,772 | 174,277 / 14,799 / 2,772 |
| Brute Force window | 1,108,658 | 1,101,459 / 0 / 7,199 | 1,045,116 / 56,343 / 7,199 |

**Global plan.** It admits every supported-domain packet of the three
windows. The Brute Force window gives the same counts as the `legacy`
post-correction replay.

**Strong plan.**
- The candidate rates over the supported domain are 92.298%, 92.173% and
  94.885%. These are the §4.4 trace rates.
- All but 3 alert packets are `P4_NO_MATCH`. This is the predicted outcome,
  not a loss. Every alert in these traces comes from a rule in operational
  fallback (§4.4), which Snort inspects outside the prefilter.

**Timing of the strong Brute Force replay.** Its wall clock spanned the
night, because the WSL VM was paused part of the way through. The sender's
own elapsed time, which does not count the pause, is 3,508 s. The
accounting still closes exactly.

### 6.3 End-to-end campaigns

The fallback partitions are `output/campaign/particoes_snort3/`. Reports are
`relatorio_snort3.json` and `relatorio_strong_snort3.json` in each campaign
directory.

| Campaign | Plan | CONFIRMED | OPERATIONAL FALLBACK | VACUOUS | VIOLATION | STATE DEP. |
|---|---|---:|---:|---:|---:|---:|
| `e2e_1000_v4` | global (235) | 958 | 2 | 40 | 0 | 0 |
| `e2e_1000_v4` | strong (225) | 134 | 826 | 40 | 0 | 0 |
| `servico_fora_do_cabecalho` | global (235) | 190 | 0 | 10 | 0 | 0 |
| `servico_fora_do_cabecalho` | strong (225) | 0 | 190 | 10 | 0 | 0 |

`tests/compare_campaign_snort3.py` checks the runs case by case and writes
`output/analysis/fase_b_snort3/comparacao_campanhas.json`:

- **Against the offline precheck:** in all 2,400 cases, every role's
  measured P4 category equals the one predicted offline. This covers the
  witness, the payload negative, and the header negative.
- **Against Snort:** Snort's alerts are byte-identical between the global
  and strong runs. They also match the `legacy` runs of the same pcaps:
  the same cases alerted, on the same packets. Snort does not depend on the
  installed plan, so only the P4 side changed.

**Differences from `legacy`:**

- **`e2e_1000_v4`, global plan.** The 2 operational-fallback cases are sids
  56583 and 56584. They are `NECESSARY` under `legacy` and `UNSUPPORTED`
  under `snort3` (14 → 21 in §4.2), so the partition sends them to fallback.
- **`e2e_1000_v4`, strong plan.** Compared with the `legacy` strong run:
  - 717 CONFIRMED cases move to operational fallback. Their service-based
    rules leave the strong set under `snort3`.
  - The 2 `legacy` STATE DEPENDENCY cases also move to fallback. They are
    sids 43809 and 47386, alerted on an HTTP flush ACK.
  - 78 witnesses are `P4_NO_MATCH`, all of them for rules in operational
    fallback, as the precheck predicted.
  - The other 134 CONFIRMED, 107 FALLBACK and 40 VACUOUS cases are
    unchanged.
- **`servico_fora_do_cabecalho`, strong plan.** The 190 `legacy` VIOLATIONs
  become 190 OPERATIONAL FALLBACK under `snort3`. Under `snort3`, the strong
  plan no longer prefilters these service-based rules by a port they do not
  check. This closes the discrepancy of `SERVICE_BASED_HEADER_FINDING.md`
  §9. 64 witnesses are `P4_NO_MATCH`, all for rules in fallback, as the
  precheck predicted.
- **`servico_fora_do_cabecalho`, global plan.** The 190 CONFIRMED and 10
  VACUOUS cases are unchanged.

## 7. Pending

- **Manuscript.** Report the `snort3` numbers as results and the `legacy`
  ones as history.

# End-to-End Campaign Integration Audit

## Why

The end-to-end differential campaign (commits `dbe232c` through `b931dd2`,
2026-09-22) was the most direct empirical test of `r => cand` in the project,
but the manuscript did not mention it. The trace-based alert evidence rests
on one, two, and five distinct SIDs; the campaign exercises 1,000 rules.

## What Changed in `main.tex`

| Location | Change |
|---|---|
| Abstract | One clause: campaign over 1,000 sampled rules observed no alert-while-no-match packet. |
| Contributions | New item for the campaign. |
| Methodology, evaluation design | Third stage now names the campaign. |
| New subsection `sec:campaign-method` | Witness synthesis, sample, oracle, one-frame-at-a-time measurement, verdict definitions, own-entry attribution. |
| Results, `sec:selectivity-causal` | Label added so the campaign can cite it. |
| Results, Dynamic Alert Preservation | Old RQ4 answer moved to the end of the new campaign subsection and extended. Pre-existing `\allowbreak` defect fixed ("alert-packetpreservation", "strong-discriminatorobserved-eventcoverage" rendered without spaces); sentence reworded, which also removed a pre-existing 4.25 pt overfull box. |
| New subsection `sec:campaign-results` + Table `tab:campaign` | Verdicts under both plans, own-only attribution, prediction/measurement agreement, payload-negative excess, the two state-dependence cases. |
| Discussion, Union Effect | Paragraph: the union also masks per-rule lowering defects. |
| Threats, Internal Validity | Campaign does not reach UNSUPPORTED rules; witness/IR circularity and why the Snort oracle breaks it; the two IR defects; sampling and single-point limits. |
| Threats, External Validity | Trace SID diversity (1, 2, 5) versus campaign coverage; synthetic traffic caveat. |
| Threats, Candidate-Set Limitations | The measured stream-flush dependence. |
| Conclusion, RQ4 | Campaign result and its two findings. |
| Artifact Availability | Where campaign artifacts live; traces regenerable byte for byte. |
| Preamble and two wide tables | `array` package and a ragged-right `L` column type for the related-work and compilation-semantics tables, which were justified into large inter-word gaps. |

No frozen number was changed. Every existing result, table value, and RQ
answer statement about the traces is unchanged in substance.

## Number Provenance

| Manuscript number | Source |
|---|---|
| 2,142 synthesizable rules; 1,875 excluded | `output/campaign/e2e_1000_v4/proveniencia.json`: `regras_utilizaveis`; 4,017 − 2,142 |
| 14 UNSUPPORTED excluded; 1,654 with blocking options | same file, `recusas` (`classificacao UNSUPPORTED`, `opcao nao sintetizavel`; one reason entry per rule for each prefix) |
| 1,000 cases, stratified, fixed seed | `proveniencia.json`: `casos`, `estratos`, `semente` = 20260918; `tests/generate_campaign_cases.py::selecionar` |
| 6,684 frames, all inside D | `proveniencia.json`: `quadros`, `quadros_fora_do_dominio_p4` = 0 |
| Same sample across runs | `casos.jsonl` SID sequence identical in `e2e_1000`, `_v2`, `_v4` |
| Global: 923 confirmed, 77 vacuous | `e2e_1000_v2/relatorio.json`: `vereditos` |
| Global: 1,000 witnesses and payload-negatives candidate; 101 header-negatives no-match | same file: `testemunha`, `negativo_payload`, `negativo_header` |
| Strong: 851 confirmed, 107 fallback, 40 vacuous, 2 state dependence | `e2e_1000_v4/relatorio_strong.json`: `vereditos` |
| Strong: 934 payload-negatives candidate, 66 no-match | same file: `negativo_payload` |
| Zero violations, both runs | both reports: no `VIOLACAO` key |
| Attributions agree for every case | both reports: `divergencia_de_atribuicao` = 0 |
| 153 own-only, 698 own-and-others | `e2e_1000_v4/atribuicao_strong.json`: `cobertura_da_testemunha_por_veredito.CONFIRMADO` |
| 0 own-only under global plan | `e2e_1000_v2/atribuicao.json`: same field (all 923 `propria_e_outras`) |
| Fallback: 66 no-match, 41 via other rules | `atribuicao_strong.json`: `FALLBACK_OPERACIONAL` = {`nenhuma`: 66, `so_outras`: 41} |
| 2,101/2,101 prediction = measurement, both runs | `atribuicao.json`, `atribuicao_strong.json`: `concordancia_predicao_medicao` |
| SIDs 43809 and 47386 | `e2e_1000_v4/resultado_strong.jsonl`: `veredito` = `DEPENDENCIA_DE_ESTADO`, alerted role `flush`, category `P4_NO_MATCH` |
| SID 28982 vacuous | `resultado_strong.jsonl`; `IR_CONTENT_NEGATION_SUPERSESSION.md` |
| 322 / 331 entries | `plano_strong_discriminator/particao.json`: `entradas_retidas` / `entradas_originais` |
| Trace SIDs 1, 2, 5 | `output/experiments/cicids2017_thursday_{sqli,xss,bruteforce}/report.json`: `unique_full_sids` |
| Generator revisions, none with a violation | global: `e2e_1000` 873/127, `_v2` 923/77; strong: `_v2` 836, `_v3` 841, `_v4` 851 confirmed |

The own-only and agreement figures are new analysis, produced by
`tests/analyze_campaign_attribution.py` and pinned by
`tests/test_campaign_attribution.py`, which checks the recorded artifacts
against the run reports.

## Validity of the Measurements Cited

- `e2e_1000_v4` ran at 2026-09-22T20:50Z against the semantic manifest
  `cfceee73…` (the tree of `b931dd2`), after the content-whitespace repair
  and before the negation repair (`9de315e`). Both repairs left every P4
  artifact byte-identical; `IR_CONTENT_NEGATION_SUPERSESSION.md` §5 already
  records the v4 campaign as valid with SID 28982 vacuous.
- The strong-discriminator partition was built from
  `output/p4_install_entries.json` `75494c0f…`,
  `output/p4runtime_install_plan.json` `d7558983…`, and
  `output/analysis/operational_policy_simulation.json` `78e21d47…`; the
  current files have the same digests.
- Reproducibility of the untracked trace was checked: running the case
  generator in a worktree at `b931dd2` produced `campanha.pcap` with SHA-256
  `ca5486f0…`, equal to the digest in `proveniencia.json`, and a
  byte-identical `casos.jsonl`.

## Claims Deliberately Not Made

- The campaign is not called a proof or a guarantee; wording is "observed".
- No claim about rules outside the synthesizable subset, about UNSUPPORTED
  rules, or about real-traffic alert rates.
- Confirmations under the global plan are not presented as tests of each
  rule's lowering; the manuscript states they are not attributable.
- The state-dependence cases are not called violations: the witness was a
  candidate. The manuscript says a no-match-withholding deployment "could"
  delay or suppress those alerts; the campaign did not run such a deployment.

## Build Validation

MiKTeX build of a scratch copy (pdflatex ×3; no new citations). Exit 0, no
undefined references or citations. Ten overfull boxes remain, all present in
the committed baseline; the eleventh baseline box (4.25 pt, Dynamic Alert
Preservation) was removed by the rewording above. The PDF grows from 32 to 36
pages. Pages with the new method, results, table, threats, and the two
reformatted wide tables were inspected visually.

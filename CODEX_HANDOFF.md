# Codex Handoff

Atualizado em 2026-09-09. Substitui integralmente a versão de 2026-08-26, cujas
seções 12 a 15 descreviam trabalho que já foi executado.

## 1. Objetivo científico atual

Avaliar uma arquitetura híbrida em que o P4 atua como prefilter/candidate marker
para o Snort, preservando a semântica do ruleset e medindo correção, cobertura
do parser e seletividade operacional. O P4 não substitui o Snort e não é
evidência de detecção da ground truth do CIC-IDS2017.

O entregável é o artigo em `paper/IDS_P4/main.tex`. Código e experimentos
existem para sustentar afirmações do manuscrito.

## 2. Arquitetura

`Snort rules -> semantic IR -> semantic manifest -> P4 backend -> P4Runtime plan -> BMv2`

O fluxo gera candidatos conservadores; regras UNSUPPORTED continuam exigindo
fallback Snort. O data plane impõe um domínio de pacotes explícito (seção 9) e
faz fail-open fora dele.

Documentação conceitual: `docs/semantic_model.md`; matriz de suporte da
linguagem: `docs/snort3_support_matrix.md`.

## 3. Perfil ativo

- Perfil: `cicids2017`
- `HOME_NET`: `192.168.10.0/24`
- Configuração ativa: `config/active_profile.json`
- Snort++ 3.12.2.0
- Ruleset: `rules/snort3-community.rules`, 4.017 regras,
  sha256 `8c0d9172127a7270ec8084ffbd16d3995df6d27aa0ccc232638f5f0293e68e19`

## 4. Resultados estáticos congelados

- Source rules: 4017
- EXACT: 0
- NECESSARY: 4003
- UNSUPPORTED: 14
- Instâncias de predicado geradas/expandidas/normalizadas: 6675
- Matches únicos antes do lowering de flags: 327
- Entradas P4 finais: 331
- P4Runtime: 331/331
- Encoding failures: 0
- Validation errors: 0

## 5. Auditoria de dependências

- Decisão: `SAFE_FOR_INDEPENDENT_RULESET_SPLIT`
- Dependências cross-partition: zero
- CANDIDATE -> UNSUPPORTED: 0
- UNSUPPORTED -> CANDIDATE: 0
- Reads sem producer: 0
- Xbits/flowint: 0

Auditada tanto na partição original quanto na partição strong-discriminator.

## 6. Correção do domínio de pacotes IPv4

Em 2026-09-01 a auditoria `paper/IDS_P4/FINAL_SCIENTIFIC_CLOSING_AUDIT.md`
identificou que o parser P4 extraía um cabeçalho IPv4 fixo de 20 bytes e ia
direto para L4, sem validar `ihl` nem fragmentação. Isso podia quebrar
`r => p_r` para tráfego com opções IPv4. Veredito: `NOT_READY`.

A correção foi implementada no mesmo dia em `p4/ids_prefilter.p4`:

- o parser só transiciona para L4 quando `(version, ihl, flags, fragOffset)`
  casa com `(4,5,0,0)` ou `(4,5,2,0)`;
- `MyIngress` repete a checagem e ainda rejeita `parser_error`;
- tudo fora do domínio executa `packet_domain_fallback()`, que marca candidato
  incondicionalmente e conta no índice 2.

O matcher offline foi unificado em `tests/p4_packet_domain.py`, importado por
`analyze_prefilter_selectivity.py`, `analyze_p4_parser_coverage.py` e
`test_ipv4_packet_domain_guard.py`.

Suíte de guarda: `output/analysis/ipv4_packet_domain_guard_test.json`,
11 casos, 0 falhas — TCP/UDP/ICMP candidate, no-match garantido, flags exatas e
mascaradas, opções IPv4, primeiro fragmento, fragmento não inicial, IPv4
truncado e TCP truncado.

Estado do bloqueio: **RESOLVIDO**. Ver
`paper/IDS_P4/PARSER_DOMAIN_RECONCILIATION.md` para linha do tempo, evidência,
tabela pré/pós valores e as mudanças aplicadas no manuscrito.

## 7. Categorias obrigatórias

Manter separadas em todos os relatórios:

- `P4_CANDIDATE` (contador 0): predicado instalado correspondeu, dentro do
  domínio suportado.
- `P4_NO_MATCH` (contador 1): dentro do domínio, nenhum predicado correspondeu.
- `PACKET_DOMAIN_FALLBACK` (contador 2): fora do domínio (não-IPv4, `IHL != 5`,
  fragmento, truncado, erro de parser). Candidato conservador, nunca no-match.

Taxas de candidato e no-match usam apenas o domínio suportado como
denominador. Colapsar fallback em no-match superestima seletividade; colapsar
em candidate esconde a cobertura real do parser.

## 8. Resultados por janela (pós-correção)

Artefatos: `output/experiments/`, `output/analysis/ipv4_packet_domain_correction/`.

| Janela | Pacotes | Domínio | Fallback | Global cand. | Strong cand. | Strong no-match |
|---|---:|---:|---:|---:|---:|---:|
| SQLi (dev) | 35.274 | 34.924 | 350 | 100% | 99,015% | 0,985% |
| XSS (dev) | 191.848 | 189.076 | 2.772 | 100% | 98,869% | 1,131% |
| Brute Force (held-out) | 1.108.658 | 1.101.459 | 7.199 | 100% | 98,942% | 1,058% |

Apenas o Brute Force tem frames IPv4 diretos excluídos pelo gate: 16 com
fragmentação ou flags reservadas. SQLi e XSS não mudaram com a correção.

Alertas e preservação:

| Janela | FULL | SIDs únicos | Missing/Additional | P4 cand. | P4 no-match | Preservação |
|---|---:|---:|---:|---:|---:|---:|
| SQLi | 150 | 1 (254) | 0/0 | 150 | 0 | 100% |
| XSS | 528 | 2 (254, 402) | 0/0 | 528 | 0 | 100% |
| Brute Force | 2.391 | 5 (254, 399, 402, 650, 1394) | 0/0 | 2.391 | 0 | 100% |

Held-out: auditoria strong cobriu 2.289 eventos elegíveis por predicados
retidos e 102 por fallback, com zero missing; pertinência de SID no candidate
set observada em 2.289/2.289. `policy_tuning_performed: false`.

Candidate rule set (baseline 3.611 regras P4-elegíveis):

| Janela | Média | Mediana | P90 | P95 | P99 | Máx | Redução média |
|---|---:|---:|---:|---:|---:|---:|---:|
| SQLi | 179,28 | 27 | 799 | 799 | 799 | 1228 | 95,04% |
| XSS | 140,49 | 13 | 799 | 799 | 1227 | 1228 | 96,11% |
| Brute Force | 324,52 | 241 | 799 | 799 | 1227 | 1228 | 91,01% |

Ablação strong-discriminator: 322 entradas retidas, 3.611 regras elegíveis, 392
em fallback operacional, 14 UNSUPPORTED semânticas. É ablação operacional, não
reclassificação semântica.

Agrupamento grosseiro: 4, 12, 268 e 308 grupos produziram o mesmo candidate set
efetivo. Conclusão `GROUPING_LIMITED_BY_OVERLAP`.

Análise causal: `p4-106` (só protocolo TCP) subsume 246 entradas (74,32%);
`p4-40` (destino `192.168.10.0/24`) subsume 210 (63,44%); `p4-138` (origem
correspondente) subsume 107 (32,33%). Dedup e lowering de flags **não** são a
causa. Conclusão: `BROAD_NECESSARY_PREDICATES` mais cobertura distribuída da
união.

## 9. Metodologia de replay

- Usar `tests/replay_pcap_raw.py`, que envia bytes Ethernet capturados via
  AF_PACKET raw. Não usar `PcapReader/sendp` como evidência quantitativa.
- Instalar o pipeline antes de cada fase: `install_p4runtime.py` usa
  `VERIFY_AND_COMMIT` e a instalação zera os três contadores. Ainda assim,
  medir por **delta** (before/after) e não por valor absoluto.
- Fazer auditoria de idle (delta zero) antes do sender.
- Reconciliar: `frames enviados == P4_CANDIDATE + P4_NO_MATCH + PACKET_DOMAIN_FALLBACK`.
- MTU das quatro veth em 65535 para evitar `EMSGSIZE`.
- Captura com `tcpdump` é diagnóstico secundário: ela observa os dois lados do
  par veth e não é contador de um-frame-por-frame-enviado.

Status do accounting: SQLi `ACCOUNTING_VALID`
(`ipv4_packet_domain_correction/REPLAY_ACCOUNTING_VALIDATION.md`); XSS
`ACCOUNTING_VALID` e Brute Force `ACCOUNTING_PARTIAL`
(`REPLAY_ACCOUNTING_VALIDATION_XSS_BRUTEFORCE.md`).

## 10. Arquivos e scripts importantes

- Perfil/configuração: `config/profiles/cicids2017.json`,
  `config/active_profile.json`, `config/snort3_experiment.lua`
- Seleção/build: `compiler/select_profile.py`, `compiler/build_profile.py`
- Instalação/leitura P4Runtime: `compiler/install_p4runtime.py`,
  `compiler/read_prefilter_counters.py`
- P4: `p4/ids_prefilter.p4`
- Domínio de pacotes offline: `tests/p4_packet_domain.py`
- Suíte de guarda: `tests/test_ipv4_packet_domain_guard.py`
- Ruleset e partições: `rules/snort3-community.rules`,
  `output/snort_candidate.rules`, `output/snort_unsupported.rules`
- Replay raw: `tests/replay_pcap_raw.py`
- Análise parser: `tests/analyze_p4_parser_coverage.py`
- Seletividade: `tests/analyze_prefilter_selectivity.py`,
  `tests/analyze_residual_selectivity.py`
- Held-out: `tests/evaluate_heldout_bruteforce.py`
- Comparação Snort: `tests/analyze_cicids2017_sqli_snort.py`
- Relatórios: `tests/build_cicids2017_sqli_report.py`,
  `tests/build_cicids2017_xss_report.py`
- Planos: `output/p4runtime_install_plan.json`, `output/p4_install_entries.json`,
  `output/ids_prefilter.json`
- Artefatos pré-correção preservados: `output/historical/ipv4_packet_domain_guard_pre_correction/`

## 11. BMv2/P4Runtime

- `simple_switch_grpc`, device-id 0
- P4Runtime/gRPC `127.0.0.1:9559`
- port 0 -> `veth0`, port 1 -> `veth2`
- interface de replay usual: `veth1`
- capacidade da tabela: 8192; 331 entradas do plano cicids2017

Para restaurar: iniciar o BMv2 com `output/ids_prefilter.json`, executar
`compiler/install_p4runtime.py`, confirmar master arbitration, pipeline
configuration e leitura 331/331. Verificar contadores antes de cada fase.

O ambiente de execução é Linux (WSL ou VM). A máquina Windows onde o
diretório vive não tem BMv2, veth nem toolchain LaTeX.

## 12. Pendências que bloqueiam a submissão

1. **Recompilar o PDF.** `main.pdf` é de 2026-09-01 e não corresponde ao
   `main.tex` atual. Verificar a nova linha da tabela de semântica de
   compilação (dentro do `resizebox` em landscape) e o ambiente `cases` da
   subseção `Enforced Packet Domain`.
2. **Re-derivar a preservação de alertas pós-correção.** Os valores 150/528/2.391
   são a única medição do Results ainda vinda do pipeline pré-correção. Os 16
   frames reclassificados continuam candidatos, então nenhum alerta muda de
   categoria — mas isso hoje é argumento, não medição.
3. **Replay frame-exato do Brute Force.** Faltaram 87 de 1.108.658 frames
   (0,0078%), toda a perda na categoria candidate, com fallback exato e
   no-match zero. Procedimento de rerun no documento de accounting.

## 13. Pendências de reforço científico

- Diversidade de alertas baixa: 1, 2 e 5 SIDs únicos; uma única janela held-out.
- Um único ruleset, um perfil e um dataset; CIC-IDS2017 é antigo.
- Sem throughput, latência ou validação em hardware.
- Sem execução candidate-set-aware no Snort (execução dinâmica stateful segue
  em aberto).
- EXACT = 0 no ruleset avaliado.

## 14. Estado de arquivos e Git

O diretório agora **é** um repositório Git (inicializado em 2026-09-09).
Capturas `.pcap` estão fora do versionamento por serem diagnóstico secundário e
regeneráveis pelos scripts de replay; o restante, incluindo artefatos
congelados, está versionado.

Convenção do projeto: artefato congelado não é sobrescrito. Correção entra como
documento novo declarando supersessão, no máximo com adendo curto no topo do
documento antigo apontando para o novo.

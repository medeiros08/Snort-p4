# Análise completa do projeto Snort-p4

**Data:** 2026-09-11
**Escopo:** compilador (`compiler/`), programa de data plane (`p4/`), aparato de teste (`tests/`), artefatos experimentais (`output/`) e manuscrito (`paper/IDS_P4/`)
**Commit analisado:** `162e3fe`
**Natureza:** análise estática e de artefatos. Nenhum arquivo do projeto foi alterado. Nenhum experimento foi re-executado.

---

## 1. Sumário executivo

O projeto está em muito melhor forma do que uma auditoria desta profundidade normalmente encontra. **Nenhum número do manuscrito está errado ou sem lastro** — a aritmética de ponta a ponta se sustenta contra os artefatos, e a disciplina sobre afirmações de desempenho é exemplar (não há uma única alegação de throughput, latência ou line-rate sem ressalva explícita). A separação das três categorias de contador (`P4_CANDIDATE` / `P4_NO_MATCH` / `PACKET_DOMAIN_FALLBACK`) é respeitada em todas as taxas reportadas. O matcher offline (`tests/p4_packet_domain.py`) é semanticamente equivalente ao parser P4, condição a condição. O lowering de flags TCP está correto para todas as formas presentes no ruleset.

Os problemas que restam quase não são erros de cálculo. São de **proveniência, de gate e de interpretação**:

1. **A ablação de agrupamento é vazia.** A métrica `candidate_rules_per_packet` nunca lê a variável `groups`. As quatro "estratégias" são quatro re-execuções bit a bit do mesmo cálculo. Duas subseções do manuscrito repousam sobre uma comparação que não compara nada.
2. **O snapshot congelado do perfil `cicids2017` contém o data plane pré-correção.** O `ids_prefilter.json` do snapshot é byte a byte idêntico à cópia rotulada `pre_correction`. Quem restaurar o BMv2 pela via que o próprio projeto declara autoritativa roda o parser sem o gate de domínio IPv4 — exatamente o bug que o artigo diz ter corrigido.
3. **O `main.pdf` é anterior à correção**, por três horas, e não contém as seções que superam o veredito `NOT_READY`.
4. **A preservação de alertas (150/528/2.391) é medição pré-correção** apresentada sem ressalva na Tabela 7.
5. **A configuração strong-discriminator nunca rodou no data plane** e aparece ao lado de colunas que rodaram.
6. **Nenhum estágio do pipeline consegue falhar.** Zero `sys.exit` em oito scripts, incluindo os dois validadores.

Números desta análise: **58 achados** examinados, **38 confirmados**, **10 plausíveis**, **2 refutados**, **8 rebaixados ou corrigidos** na verificação adversarial. Nenhum achado ficou sem verificação.

---

## 2. Como esta análise foi feita

Três ondas, com verificação adversarial obrigatória antes de qualquer achado entrar neste relatório.

**Onda 1 — seis agentes em paralelo**, cada um com um recorte: semântica da tradução; back-end P4 e lowering; cobertura da linguagem Snort 3; testes e validação; engenharia e reprodutibilidade; manuscrito versus artefatos.

**Onda 2 — verificação adversarial.** Cada achado alto ou crítico foi entregue a céticos independentes instruídos a **demoli-lo**, com lentes distintas: *verdade do código* (o código faz literalmente isto, nestas linhas?) e *caça à mitigação* (existe algo em outro lugar do projeto que já impede esta consequência?). Achados médios receberam um refutador. Quatro reconciliações dirigidas atacaram pontos onde os agentes se contradisseram.

**Onda 3 — verificação direta.** Parte dos achados foi confirmada por medição própria: execução da suíte de testes, comparação de hashes, contagem em artefatos, leitura de mtimes.

### Status de verificação de cada achado

| Status | Significado |
|---|---|
| **CONFIRMADO** | Resistiu à tentativa de refutação, ou foi medido diretamente |
| **PLAUSÍVEL** | Mecanismo confirmado, mas consequência ou severidade em disputa |
| **REFUTADO** | A verificação derrubou o achado. Listados na seção 7, por transparência |
| **NÃO VERIFICADO** | Ficou sem verificação adversarial. Marcado como tal, não como fato |

### Limites desta análise

- A máquina não tem BMv2, veth, gRPC nem toolchain LaTeX. Nada foi re-executado no data plane.
- Os módulos `scapy`, `grpc`, `google.protobuf` e `pytest` não estão instalados, então os testes que dependem deles não puderam rodar.
- A equivalência entre o matcher offline e o parser P4 foi verificada por leitura pareada, não por teste diferencial com fuzzing.
- Sem binário do Snort 3, não foi possível confirmar empiricamente quais formas sintáticas o Snort aceita ou rejeita. Onde isso importa (M11, M13), a afirmação está baseada no código-fonte do Snort ou marcada como não confirmada.

---

## 3. O que está sólido

Registrar isto importa tanto quanto registrar os defeitos — parte do valor da auditoria é saber onde **não** mexer.

- **Rastreabilidade numérica completa.** Todos os valores do `main.tex` (4.017 / 4.003 / 14 / 6.675 / 327 / 331, as taxas de candidato, as distribuições de candidate set) têm artefato de lastro e conferem.
- **Contabilidade das três categorias.** Nenhuma taxa do manuscrito soma `PACKET_DOMAIN_FALLBACK` a candidato ou a no-match; todas usam o domínio suportado como denominador, como o modelo exige.
- **Disciplina sobre desempenho.** As 21 ocorrências de line-rate/throughput/latência/hardware estão todas em negações, limitações ou descrição de trabalho relacionado.
- **Fidelidade do matcher offline.** `tests/p4_packet_domain.py:31-89` é equivalente a `p4/ids_prefilter.p4:162-266` e `:428-438`, condição a condição, incluindo truncamento por protocolo e extração do byte de flags.
- **Accounting de contadores.** Todo pacote incrementa exatamente um dos três índices: o `apply()` é if/else estrito, o `default_action` cobre o miss, e não há `recirculate`/`clone`/`resubmit`.
- **Aritmética 6.675 → 327 → 331.** A dedup só agrupa matches idênticos com a mesma ação, e a expansão de flags confere: 13 grupos com flags, 11 diretos mais 2 expandidos por `*FRS` de 3 bits = 17 entradas; 327 − 13 + 17 = 331.
- **Lowering de flags TCP.** Os quatro ramos (exato com ignore-mask, `+`, `!`, `*`) foram conferidos contra o `CheckTcpFlags` do Snort e estão corretos.
- **Determinismo.** Nenhum `random`, `hash()` ou iteração não ordenada sobre `set`/`dict` nos módulos do pipeline; nenhum timestamp embutido no conteúdo dos artefatos compilados.
- **Proveniência do dataset.** `output/datasets/cicids2017_thursday_metadata.json` documenta o PCAP bruto **e cada uma das três janelas** com sha256 individual, contagem de pacotes, janela temporal em microssegundos e breakdown de protocolos. É mais rigoroso do que a norma da área.

---

## 4. Achados críticos

### C1 — A ablação de agrupamento não mede agrupamento

**Status:** CONFIRMADO · **Arquivo:** `tests/analyze_grouped_prefilter_feasibility.py:136,145,149,180,216,221-223`

A métrica `candidate_rules_per_packet` é estruturalmente insensível à estratégia de agrupamento. O objeto `compiled` é construído **uma vez, fora** do laço de estratégias (`:216`), e o laço de pacotes calcula:

```python
matched = [i for i in candidate_indices if compiled_entry_matches_packet(compiled[i], packet)]   # :136
rules.update(entry["provenance"]["source_rule_ids"])                                              # :145
candidate_sizes.append(len(rules))                                                                # :149
```

`matched` depende só de `compiled` e do pacote. `rules` depende só de `matched`. A variável `groups` é lida em um único ponto do laço (`:146`, `active_groups.add`), e alimenta exclusivamente `activated_groups_per_packet` e `group_hits` — **nunca** `candidate_rules_per_packet`.

Por isso os valores são idênticos bit a bit nas quatro estratégias (SQLi `179,2847898293437`; XSS `140,48995641964078`): é literalmente a métrica *ungrouped* recalculada quatro vezes sobre o mesmo objeto. O contrafactual confirma: a união real de regras do grupo `protocol=6` é **3.439 regras**, contra o máximo de 1.228 e mediana 27 reportados.

**Consequência.** A conclusão `GROUPING_LIMITED_BY_OVERLAP` não é sustentada por esses dados, e duas subseções do manuscrito (`main.tex` L1049-1062 e L1253-1269) descrevem uma comparação que não ocorreu. Um revisor que abrir o script chega a isto em dez minutos.

**Correção mínima:** ou reimplementar a métrica para que o candidate set seja a união das regras dos grupos ativados, ou remover as duas subseções e a conclusão associada.

---

### C2 — O snapshot congelado do perfil contém o data plane pré-correção

**Status:** CONFIRMADO por hash e mtime (achado novo, não presente na primeira onda)

| Arquivo | sha256 (16) | Bytes | mtime |
|---|---|---:|---|
| `output/ids_prefilter.json` | `f5167adc69e8ae05` | 69.830 | 2026-09-01 20:46 |
| `output/profiles/cicids2017/artifacts/ids_prefilter.json` | `41b6215bb5fb3931` | 62.927 | 2026-08-25 17:04 |
| `output/profiles/controlled/artifacts/ids_prefilter.json` | `41b6215bb5fb3931` | 62.927 | — |
| `output/historical/ipv4_packet_domain_guard_pre_correction/ids_prefilter.json` | `41b6215bb5fb3931` | 62.927 | 2026-08-25 17:04 |

O snapshot do perfil `cicids2017` — que a convenção do projeto trata como o artefato congelado autoritativo — é **byte a byte idêntico à cópia explicitamente rotulada `pre_correction`**. O mesmo vale para o `ids_prefilter.p4info.txt`. O programa corrigido existe apenas em `output/` na raiz, com mtime 2026-09-01 20:46, dois minutos depois da correção do fonte `p4/ids_prefilter.p4` (20:44).

**Cenário de falha concreto.** O `CODEX_HANDOFF.md` §11 instrui: "iniciar o BMv2 com `output/ids_prefilter.json`". Isso funciona. Mas a convenção declarada em §14 é que o artefato congelado por perfil é a referência. Qualquer pessoa — revisor, ou o próprio autor daqui a seis meses — que restaure o ambiente a partir de `output/profiles/cicids2017/artifacts/` sobe o BMv2 com o parser **sem** o gate `(version, ihl, flags, fragOffset) ∈ {(4,5,0,0), (4,5,2,0)}`, ou seja, exatamente o data plane que a auditoria `FINAL_SCIENTIFIC_CLOSING_AUDIT.md` declarou `NOT_READY`. Não há nada no diretório do snapshot que avise.

**Correção mínima:** re-snapshotar o perfil `cicids2017` com o programa corrigido, ou adicionar ao diretório do snapshot uma nota declarando que o `ids_prefilter.json`/`p4info` ali são pré-correção e apontando para a cópia válida.

---

### C3 — O `main.pdf` é anterior à correção que desbloqueou o artigo

**Status:** CONFIRMADO por mtime e por ausência de `\newlabel`

| Arquivo | mtime |
|---|---|
| `paper/IDS_P4/main.pdf` | 2026-09-01 **17:28** |
| `paper/IDS_P4/main.aux` | 2026-09-01 17:28 |
| `p4/ids_prefilter.p4` | 2026-09-01 **20:44** |
| `paper/IDS_P4/main.tex` | 2026-09-09 21:30 |

O PDF não é apenas mais antigo que o `.tex` — ele é **três horas mais antigo que a própria correção do P4**. O `main.aux` não contém `\newlabel` para `sec:packet-domain` nem para `sec:domain-validation`, ambos presentes no `main.tex` atual (L354 e L908). O PDF de 29 páginas portanto não contém a subseção *Enforced Packet Domain*, a linha de fail-open da tabela de semântica, o parágrafo *Packet-domain validation* nem a subseção *Packet-Domain Enforcement and Validation*.

**Consequência.** Submeter esse PDF é submeter a versão que a auditoria interna declarou bloqueada.

---

### C4 — A preservação de alertas é medição pré-correção, apresentada sem ressalva

**Status:** CONFIRMADO por mtime

| Artefato | mtime |
|---|---|
| `output/experiments/cicids2017_thursday_sqli/p4_alert_preservation.json` | 2026-08-25 20:18 |
| `output/experiments/cicids2017_thursday_sqli/report.json` | 2026-08-26 15:45 |
| `output/experiments/cicids2017_thursday_xss/report.json` | 2026-08-26 16:10 |
| `output/experiments/cicids2017_thursday_bruteforce/report.json` | 2026-08-31 14:03 |
| `p4/ids_prefilter.p4` (corrigido) | 2026-09-01 20:44 |

O `main.tex` L943-947 enumera explicitamente o que foi revalidado sob o domínio imposto — 100% global, 98,942%, 324,52, 91,01% — e **omite a preservação de alertas** dessa lista. A Tabela 7 (L1091-1107) apresenta "P4 cand. 150/528/2.391, P4 no-match 0, Preservação 100%" sem nenhuma ressalva.

O argumento de que os 16 frames reclassificados permanecem candidatos e portanto nenhum alerta muda de categoria é provavelmente correto — mas hoje é **argumento apresentado como medição**. O próprio `PARSER_DOMAIN_RECONCILIATION.md` §5 e §7.2 registra o item como aberto.

**Correção mínima:** uma frase na Tabela 7 e no texto declarando a proveniência pré-correção, ou a re-execução dos três replays de preservação.

---

### C5 — A configuração strong-discriminator nunca rodou no data plane

**Status:** CONFIRMADO

- `output/analysis/operational_policy_simulation.json` traz `"simulation_only": true`
- `output/analysis/ipv4_packet_domain_guard_test.json` traz `"entries_used": 331`
- `xss_install.log` e `bruteforce_install.log` registram 331 escritas e 331 leituras

Nenhum artefato mostra as 322 entradas instaladas no BMv2. Ainda assim a Tabela 5 (L969-977) posiciona *Strong candidate* e *Strong no-match* como colunas 6 e 7, ao lado de *Eligible* e *Global candidate*, que **são** validadas no data plane, sem qualquer distinção visual ou textual. O mesmo vale para toda a Tabela 6 e para o resultado 2.289/2.289. A expressão "frozen operational ablation" (L966, L995, L1325) sugere, mas não afirma.

**Correção mínima:** declarar literalmente que as linhas strong e todas as métricas de candidate set derivam do classificador offline, e que a configuração de 322 entradas não foi instalada no alvo.

---

### C6 — Nenhum estágio do pipeline consegue falhar

**Status:** CONFIRMADO por medição direta

```
compiler/validate_backend.py             sys.exit=0  raise SystemExit=0
compiler/validate_semantic_manifest.py   sys.exit=0  raise SystemExit=0
compiler/generate_p4_entries.py          sys.exit=0  raise SystemExit=0
compiler/expand_p4_entries.py            sys.exit=0  raise SystemExit=0
compiler/normalize_p4_entries.py         sys.exit=0  raise SystemExit=0
compiler/lower_p4_entries.py             sys.exit=0  raise SystemExit=0
compiler/generate_p4runtime_install.py   sys.exit=0  raise SystemExit=0
compiler/generate_semantic_manifest.py   sys.exit=0  raise SystemExit=0
```

`validate_backend.py` tem 1.451 linhas, acumula erros reais de validação de IP, porta e flags, imprime `VALIDATION ERRORS`, marca `backend_status: INVALID` — e sai com código 0. `validate_semantic_manifest.py` (523 linhas) segue o mesmo padrão. `compiler/build_profile.py:198-208` só checa `returncode`, que é sempre 0.

**Cenário de falha concreto.** Uma entrada que falhe em `normalize_p4_entries` é capturada pelo `try/except` por entrada, registrada em `failures` e **removida** de `p4runtime_entries.json`. O build termina "com sucesso", o plano é gerado com 330 entradas em vez de 331, a instalação reporta `Installation status: VALID`, e a regra correspondente continua listada em `snort_candidate.rules` como candidata P4 — sem predicado instalado. A correspondência artefato-a-artefato que sustenta o argumento `r ⇒ p_r` quebra silenciosamente.

Hoje `failed_entries = 0`, então nenhum resultado congelado está contaminado. É defeito de gate, não de resultado — mas é o defeito de gate que permitiria todos os outros passarem despercebidos.

---

## 5. Achados altos

### H1 — A diversidade de alertas é de uma regra, e o manuscrito não diz

**Status:** CONFIRMADO por medição direta

`output/experiments/cicids2017_thursday_bruteforce/report.json`:

```json
"full_sid_alert_counts": {"254": 2289, "399": 2, "402": 97, "650": 2, "1394": 1}
```

Os 2.289 eventos "strong-eligible" (L1076) e o resultado 2.289/2.289 (L1078, L1405) são **exatamente e apenas o SID 254** — 95,7% de todos os alertas da janela held-out. As mensagens dos cinco SIDs: 254 = `PROTOCOL-DNS SPOOF query response`; 399/402 = ICMP unreachable; 650/1394 = `INDICATOR-SHELLCODE`. **Nenhum é regra de ataque web ou de força bruta**, apesar de a janela ser rotulada brute force.

O `main.tex` cita os cinco SIDs em L1074 mas nunca a distribuição. A seção Threats (L1297-1411) não contém o item de baixa diversidade, embora ele esteja listado no handoff §13 e em `FINAL_SCIENTIFIC_CLOSING_AUDIT.md` §11 e §16. O próprio `sqli/report.json` traz em `limitations[0]` a frase de que "100% não representa cobertura geral das 4.003 regras candidatas" — frase que existe no artefato e não no manuscrito.

### H2 — O denominador de 3.611 exclui 406 regras sempre aplicáveis

**Status:** CONFIRMADO por grep (`85.43`, `86.40`, `81.81` = 0 ocorrências no `main.tex`)

`FINAL_SCIENTIFIC_CLOSING_AUDIT.md` §10 já calculou a versão conservadora: com E(x) = |C(x)| + 392 + 14 sobre 4.017, as reduções caem para **85,43% (SQLi), 86,40% (XSS), 81,81% (Brute Force)**. Nenhum desses três números aparece no manuscrito. O abstract, a introdução, os Results, a Discussion e a Conclusão exibem apenas 91–96%.

Como 3.611 + 392 + 14 = 4.017, o revisor faz essa conta sozinho e a diferença 91,01% → 81,81% passa a parecer escondida. Reportar as duas linhas custa uma frase e remove a objeção.

### H3 — `validate_backend.py` é parcialmente tautológico e não valida nada instalado

**Status:** CONFIRMADO por medição direta

```
compiler/validate_backend.py:8   INPUT_FILE  = "../output/p4runtime_entries.json"
compiler/validate_backend.py:9   OUTPUT_FILE = "../output/backend_validation.json"
```

Referências a `p4_install_entries`: **0**. A `p4runtime_install_plan`: **0**. A `p4info`: **0**. O validador lê o *insumo* do lowering e nunca a saída. Além disso, `normalized_match_key` (`:100-116`) é a mesma função de `lower_p4_entries.match_key` (`:44-57`) — os 327 matches únicos são o mesmo cálculo feito duas vezes — e `analyze_tcp_flags` (`:319-482`) reimplementa a classificação de `lower_tcp_flags`, produzindo `estimated_additional_entries = 4` sem nunca comparar com o value/mask realmente emitido.

**Cenário de falha concreto.** Inverter o ramo `!` em `lower_p4_entries.py:536-543` (trocar `value 0` por `effective_test_mask`) inverteria a semântica de `flags:!S`. `backend_validation.json` continuaria `VALID_WITH_FLAG_EXPANSION` com 327 e 331; `validate_final_entries` só checa tipo e faixa 0..255; `validate_encoded_entries` só checa largura e canonicidade. **Nenhum validador do repositório falharia.**

### H4 — A proveniência dos artefatos não está ancorada

**Status:** CONFIRMADO por hash

`compiler/build_profile.py:451-519` sobrescreve `output/` na raiz a cada build e só depois copia para `output/profiles/<perfil>/artifacts/`. Hoje a raiz é byte a byte idêntica ao snapshot `cicids2017` para `p4_install_entries.json`, `p4_entries.json` e `semantic_manifest.json`, e diferente de `controlled` — porque `cicids2017` foi construído por último (20:04:39Z contra 19:43:34Z).

Mas `tests/analyze_prefilter_selectivity.py:20` e `tests/evaluate_heldout_bruteforce.py:34` leem a **raiz**, não o snapshot do perfil. Reconstruir `controlled` — operação de rotina, não erro — faria esses scripts consumirem silenciosamente entradas com `HOME_NET 10.0.0.0/24` rotuladas como resultado CIC-IDS2017. Sem erro, sem aviso.

### H5 — Zero citações para o dataset, o IDS e a linguagem

**Status:** CONFIRMADO por grep

"CICIDS2017" aparece 8 vezes no `main.tex` e **0 vezes com `\cite`**. As 10 entradas de `references.bib` são todas de trabalho relacionado (`lewis2019p4id`, `tavares2021p4onids`, `hagen2025rna`, `brum2025rethinking`, `lewis2023fourmidable`, `fida2026pdpids`, `alsabeh2022p4securitysurvey`, `hauser2023p4survey`, `mazloum2025p4security`, `senoski2025p4nips`). Não há referência para Snort 3, para a especificação P4, para o modelo v1model/BMv2 nem para o P4Runtime. Em revisão de conferência de redes isso é rejeição quase certa.

### H6 — O critério da política strong-discriminator não existe

**Status:** CONFIRMADO por leitura do artefato

`output/analysis/residual_selectivity_audit.json` traz `removed_entries: 9` e

```json
"removed_entry_ids": ["p4-106","p4-138","p4-20","p4-24","p4-286","p4-3","p4-40","p4-5","p4-80"]
```

O `main.tex` L992 diz apenas "removed the identified broad entry set" e a análise causal nomeia **três** entradas (L983-987). Não há em lugar algum — manuscrito, artefato ou código — a definição do que torna uma entrada "broad". Um terceiro não consegue reproduzir a partição 3.611/392.

**Correção mínima:** publicar o critério, ou publicar os nove IDs.

### H7 — O núcleo do compilador não tem teste, e não existe runner

**Status:** CONFIRMADO por medição direta

Nenhum arquivo de teste importa nenhum destes módulos:

| Módulo | Linhas | Testes que o importam |
|---|---:|---|
| `compiler/validate_backend.py` | 1.451 | 0 |
| `compiler/generate_p4runtime_install.py` | 1.277 | 0 |
| `compiler/expand_p4_entries.py` | 1.275 | 0 |
| `compiler/lower_p4_entries.py` | 1.260 | 0 |
| `compiler/normalize_p4_entries.py` | 1.043 | 0 |
| `compiler/build_profile.py` | 1.090 | 0 |
| `compiler/select_profile.py` | 921 | 0 |

São ~7.300 linhas da lógica central sem cobertura. E não existe `pytest.ini`, `conftest.py`, `pyproject.toml`, `setup.cfg`, `requirements.txt`, `tox.ini`, `Makefile`, `README.md` nem `.github/` — nenhum comando único diz se a suíte passa.

Medição da suíte em Python 3.14.7, a partir da raiz do repositório:

| Resultado | Arquivos |
|---|---|
| Passam | `test_buffer_context`, `test_nested_variable_resolution`, `test_option_normalizer`, `test_semantic_content_ir`, `test_semantic_ir`, `test_semantic_model`, `compiler/test_nested_variable_resolution`, `compiler/test_service_ir` |
| Falha | `test_variable_resolver` → `FileNotFoundError` |
| Não executam | `test_ipv4_packet_domain_guard`, `test_tcp_flag_lowering`, `test_alert_preservation_bmv2` → `ModuleNotFoundError: grpc` |

Três arquivos com nome `test_*` não contêm **nenhum** `assert` nem `sys.exit`: `tests/test_variable_resolver.py`, `tests/test_semantic_model.py` e `compiler/test_service_ir.py`. O `test_semantic_model.py` chega a imprimir "N test(s) failed." e ainda assim sai com código 0. Pior: ele importa `from classifier import classify_rule`, ou seja, testa o classificador **legado**, não o `semantic_classifier.py` que gera o manifesto.

As duas suítes de guarda mais citadas — o gate de domínio IPv4 e o lowering de flags TCP (1.076 linhas) — importam `grpc` no topo do arquivo, então nem os casos puramente offline rodam sem gRPC instalado. Na prática não funcionam como regressão.

### H8 — Nenhum manifesto de dependências

**Status:** CONFIRMADO

`scapy` é importado em ~14 arquivos, `grpc` em 5, `google.protobuf` em 5, `p4.v1`/`p4.config.v1` em 5. Nada declara isso. O `.venv-p4runtime/` presente no checkout contém apenas `pip` e `setuptools` — o único artefato de ambiente do repositório não reproduz o que os experimentos precisam.

### H9 — Subsistema de classificação órfão ao lado dos artefatos oficiais

**Status:** CONFIRMADO

`compiler/classifier.py`, `compatibility.py`, `run_classifier.py`, `generate_manifest.py` e `generate_real_manifest.py` não são importados por nada do pipeline oficial. Produzem `output/manifest.json` e `output/community_manifest.json` (6,8 MB), que ficam lado a lado com `semantic_manifest.json` sem nenhuma indicação de que só o último é real. `run_classifier.py` roda sobre `rules/test.rules`, um arquivo de brinquedo de 178 bytes.

Agrava: esse caminho legado tem um defeito próprio de orientação — `compatibility.py:190-202` com `classifier.py:40-58` marca a direção como `DELEGATED` e preserva src/dst em forward, de modo que `alert udp any 19 <> any 7` (sid 271) perde o sentido `7→19` no manifesto legado. Reexecutar o script errado produz números que não batem com os congelados.

### H10 — A matriz de suporte da linguagem não existe

**Status:** CONFIRMADO por leitura direta

`docs/snort3_support_matrix.md` tem 45 linhas e 1.440 bytes, e termina no meio da Seção 1, em `action protocol src_ip src_port direction dst_ip dst_port`, com bloco ```` ```text ```` sem fechar e sem newline final. Nunca chega a uma tabela de opções — não há uma linha sequer sobre `content`, `flow`, `pcre`, `service`, `flags` ou buffers HTTP. Está commitado assim desde `ce45f97`.

Mesmo assim é citado como referência ativa em `CODEX_HANDOFF.md:24-25` e descrito em `docs/semantic_model.md:8` como o documento que "registra o status de suporte por construto".

Além disso, a linha 39 que sobreviveu à truncagem atribui a causa errada: `| Service rule | SUPPORTED | UNSUPPORTED | UNSUPPORTED | FALLBACK |` afirma que parser e IR não suportam regras de serviço, quando `compiler/parser.py:238-305` tem `parse_service_rule` dedicada e `build_semantic_ir.py:704-746` gera IR completo. O ponto de falha real é a classificação de seletividade, não o parser.

### H11 — Uma entrada anula a seletividade de todas as outras

**Status:** CONFIRMADO por leitura do artefato

`output/p4_install_entries.json`:

```json
{"table":"ids_prefilter","action":{"name":"send_to_ids"},"match":{"protocol":6},
 "provenance":{"source_rule_ids":["1382","32937","54793","56585"],"source_rule_count":4},
 "install_entry_id":"p4-106"}
```

Uma entrada que casa **todo pacote TCP**, gerada por 4 regras, subsome 246 das 331 (74,32%). A causa é `compiler/semantic_classifier.py:56-72`: `protocol_is_selective` aceita `tcp` isolado como predicado seletivo. O contraste interno é revelador — `direction_is_selective` (`:115-128`) corretamente devolve `False` por reconhecer que direção é estrutural e não reduz o conjunto de pacotes quando endereços e portas são wildcards. O mesmo raciocínio se aplica a `protocol` isolado.

Regra real que a gera: sid 32937, `alert tcp any any -> any any (...)`. Enquanto `p4-106` estiver instalada, `P4_NO_MATCH` é inatingível para TCP.

**Correção possível:** tratar protocolo isolado como não-seletivo move 4 regras para `UNSUPPORTED` — fallback Snort, mesma carga de inspeção, zero perda semântica — e devolve seletividade às outras 327.

### H12 — Ranges de porta descartados apesar de a chave ser ternária

**Status:** CONFIRMADO, com números reconciliados

Contagem definitiva no `semantic_manifest.json`:

- **78 decisões** de porta com `FALLBACK`: 62 `port_range_not_supported` + 14 `port_list_contains_range` + 2 `negated_port_not_supported`
- **75 regras distintas** afetadas — a diferença são 3 regras (sids 40840, 40841, 40842) que perdem *ambas* as portas
- **72 regras** ficam apenas com `(protocol, um IP)`: 49 com `{protocol, dst_ip}` e 23 com `{protocol, src_ip}`, confirmado em duas fontes independentes (`selective_predicates` do manifesto e as chaves reais de `p4_entries.json`)

Valores mais frequentes: `1024:` (11), `7777:7778` (10), `6666:7000` (9), `500:` (6), `1025:` (5).

**Cenário concreto.** Sid 110: `alert tcp $EXTERNAL_NET any -> $HOME_NET 12345:12346` — duas portas. A regra vira `p4-3 = {protocol:6, dst_ip:192.168.10.0/24}`, entrada compartilhada por 99 SIDs. Um pacote TCP para `192.168.10.5:443` passa a ser candidato para a sid 110, que só dispararia em 12345/12346.

Nada disso exige aproximação: a chave `meta.l4_dst_port` é **ternary**, então `12345:12346` são duas entradas e `1024:65535` são seis prefixos. O custo total de representar os 62 ranges é de 387 entradas ternárias, levando a tabela a ~700 de 8.192.

O descarte é seguro (`r ⇒ p_r` preservado) — é perda de precisão, não de correção. Mas é precisamente o mecanismo que produz as entradas subsumidoras.

---

## 6. Achados médios e baixos

| ID | Achado | Status |
|---|---|---|
| M1 | 237 predicados de cabeçalho representáveis em P4 (`itype` 124, `icode` 79, `icmp_id` 15, `ip_proto` 4, `ttl`, `fragbits`, `seq`, `ack`) ficam `DELEGATED` via `assess_future_header` (`target_capability.py:537-546`). Sids 221 e 222 diferem só em `itype` (8 vs 0) e colapsam na mesma `p4-20`, que agrega 112 regras. O header ICMP já é parseado em `ids_prefilter.p4:89-94` e descartado | CONFIRMADO |
| M2 | `ip_proto` delegado derruba 3 das 14 `UNSUPPORTED` (sids 2462/2463/2464, IGMP/EIGRP) — limitação de implementação, não intrínseca: é o byte Protocol do IPv4 | CONFIRMADO |
| M3 | Expansão cartesiana sem teto em `expand_p4_entries.py:498-593` e nenhuma checagem de capacidade 8.192 antes da instalação. Uma regra com listas de 20 portas nos dois lados e `<>` gera 800 entradas. Hoje o máximo é 9/regra | CONFIRMADO |
| M4 | Modificador de flags só reconhecido no início ou no fim (`normalize_p4_entries.py:295-330`). `flags:F+S` — válido no Snort, que trata `+`/`*`/`!` caractere a caractere — é descartada silenciosamente | CONFIRMADO |
| M5 | `flags` com `*` é rotulado `PRESERVED`, mas `docs/semantic_model.md:91,117-118` define esse caso como `EXPANDED`. A expansão real ocorre depois, em `lower_p4_entries.py:554-578`; o rótulo inconsistente alimenta o manifesto | CONFIRMADO |
| M6 | Pipeline de replay/seletividade/held-out documentado apenas em prosa (`CODEX_HANDOFF.md` §9-11). Sem Makefile, README ou orquestrador | CONFIRMADO |
| M7 | Zero dispersão, variância, IC ou declaração de execução única. Um replay BMv2 por trace. A tentativa SQLi descartada por `EMSGSIZE` (35.278 frames, 354 de fallback) nunca é mencionada | CONFIRMADO |
| M8 | Nenhuma declaração de reprodutibilidade no manuscrito: sem Snort++ 3.12.2.0, sem sha256 do ruleset, sem endpoint P4Runtime, sem availability statement | CONFIRMADO |
| M9 | A suíte de guarda de 11 casos (`tcp_candidate`, `udp_candidate`, `icmp_candidate`, `guaranteed_no_match`, `tcp_exact_flags_candidate`, `tcp_masked_flags_candidate`, `ipv4_options`, `first_fragment_mf`, `noninitial_fragment`, `truncated_ipv4`, `truncated_tcp`) não cobre nenhuma classe que domina o fallback real: ARP (1.660 no XSS), IPv6 (820), LLDP, VLAN, GRE, `truncated_udp`, `truncated_icmp`. ~99,9% da população de fallback nunca teve confirmação controlada data-plane-vs-offline | CONFIRMADO |
| M10 | Todo o `compiler/` usa caminhos relativos ao *cwd* (40+ constantes `"../..."`), contra 29 arquivos que ancoram em `Path(__file__)`. `variable_resolver.py:5` procura `../config/snort_variables.json`; da raiz do repo isso resolve para fora do projeto. O pipeline só funciona com `cwd=compiler/`, e nada declara isso | CONFIRMADO |
| M11 | Direção `<-` aceita em `parser.py:171` gera predicado com orientação invertida: `direction` vira `FALLBACK` mas src/dst permanecem `PRESERVED` em forward | **REBAIXADO** — ver §8 |
| M12 | **Aspa desbalanceada produz `EXACT` espúrio que a validação aprova.** `split_options` (`parser.py:19-80`) não valida balanceamento e `parse_option` (`:91-105`) faz `.strip('"')` cego. Reproduzido: `msg:"quote " here"` (número ímpar de aspas não escapadas) faz o `msg` engolir `content` e `sid` — 1 opção em vez de 3, `sid = None`, e a regra é classificada **`EXACT`** com `exact_semantics=True`, `delegated=0`, `fallback=0`. `validate_semantic_manifest.py:202-236` valida `EXACT` apenas checando `candidate`, `delegated` e `fallback`, então **aprova o registro sem erro**. `EXACT` é a única classe que autoriza o data plane a decidir a detecção sozinho. Mitigação parcial: `rule_id` vira `None` e `generate_snort_experiment_rules.py:533-539` marcaria o SID como `missing_in_manifest`. Alcance: **0 das 4.017 regras** do ruleset têm número ímpar de aspas não escapadas — latente, sem contaminação | CONFIRMADO |
| M13 | **Regras que falham no parse somem sem gate.** `parser.py:388-394` captura `ValueError`, imprime e descarta; `generate_semantic_manifest.py:226-242` conta em `failures`, exclui do manifesto e continua; `validate_semantic_manifest.py` nunca lê `summary.failures`. Reproduzido: `alert tcp any any -> any [80, 443] (...)` (espaço após a vírgula) levanta `ValueError: Could not parse rule`, porque o regex de `parser.py:166-176` usa `\S+` para a porta. A regra não entra no manifesto, não vira `UNSUPPORTED` e não aparece em nenhuma das duas partições — sem sinal no código de saída (ver C6). Alcance: **0 regras** do ruleset usam essa forma, e `summary.failures = 0` no manifesto congelado — latente. *Não confirmado:* se o Snort 3 de fato tolera espaço após vírgula em lista de cabeçalho (exigiria o binário) | CONFIRMADO (mecanismo) |
| B1 | `flags:AS,12` / `12FS` / `12AP` / `12FSU` (4 regras) vão para `FALLBACK` sendo exatamente representáveis; `TCP_FLAG_MAP` já define `C=0x80` e `E=0x40` | CONFIRMADO |
| B2 | `EXACT` não é código morto: uma regra tradicional só-de-cabeçalho com apenas opções `METADATA` é classificada `EXACT` pelo código atual. `EXACT = 0` é resultado empírico honesto, não categoria vazia por construção | CONFIRMADO |
| B3 | As 14 `UNSUPPORTED` decompõem em 10 regras `SERVICE` (100% das que existem no ruleset) + 3 `ip_proto` + 1 sid 498. Regras `SERVICE` nunca podem ser `NECESSARY` nem `EXACT` porque `is_selective_predicate` só reconhece campos `HEADER` | CONFIRMADO |
| B4 | `SUPPORTED_OPTIONS`/`UNSUPPORTED_OPTIONS` em `parser.py:6-16` são dead code com nomes enganosos: `content`, `pcre`, `flowbits` e `file_data` *são* reconhecidos | CONFIRMADO |
| B5 | Os ramos `!` e `ignore_mask` de `lower_tcp_flags` nunca são executados no build congelado, mas `SEMANTIC_SOUNDNESS_AUDIT.md` §2 e §4 os cita como cobertos por teste. O teste citado seleciona entradas `*` já instaladas e não toca nenhum dos dois | CONFIRMADO |
| B6 | `EXACT` com bit presente em `test_mask` e `ignore_mask` diverge do Snort: `flags:SA,A` é insatisfazível no Snort, mas o compilador emite `value 0x02 / mask 0xEF`, que casa SYN puro. Relaxação segura, divergência não documentada | CONFIRMADO |
| B7 | Campos com máscara zero são apagados na codificação; `src_ip 0.0.0.0/0` e ausência de `src_ip` colidem na mesma chave ternária. Com `CONTINUE_ON_ERROR`, o `ALREADY_EXISTS` faz o `Write` inteiro falhar. Menor prefixo instalado hoje: /23 | CONFIRMADO |
| B8 | 929 `print()` em `compiler/*.py`, zero uso de `logging` | CONFIRMADO |
| B9 | 40 `except Exception`, mais de 20 nos `analyze_*` órfãos | CONFIRMADO |
| B10 | RQ2 pergunta por um "practical P4 target"; só BMv2 foi avaliado | CONFIRMADO |
| B11 | Os replays de preservação usaram PCAPs contendo apenas os pacotes de alerta e parâmetros diferentes por trace (SQLi `batch 50 / inter 0,05 s`; XSS `inter 0,02 s`). A Tabela 7 não os distingue dos replays completos | CONFIRMADO |
| B12 | `\label{sec:domain-validation}` nunca é referenciado | CONFIRMADO |
| B13 | `\documentclass{article}`, 29 páginas, 8 tabelas e 1 figura conceitual, zero gráficos de dados, sem template de conferência, `\date{August 2026}` desatualizado | PLAUSÍVEL |
| B14 | Tabela 5 mistura contagens e percentuais sem rótulo de unidade e não tem coluna para `PACKET_DOMAIN_FALLBACK`, que o modelo exige manter visível | PLAUSÍVEL |
| B15 | Colisão de `95,04%` entre duas métricas distintas (redução de estado de instalação = 95,0412%; redução de candidate-rule-space do SQLi = 95,0350%) exibidas na mesma seção | PLAUSÍVEL |
| B16 | Prioridade ternária constante = 1 em todas as 331 entradas. Inofensivo hoje (todas executam `send_to_ids`), mas impede contador por entrada e o desempate fica por ordem de handle do BMv2, não estável entre reinstalações | PLAUSÍVEL |
| B17 | `assess_flags` devolve `PRESERVED` para qualquer string sem dígito, inclusive `flags:ZZ`. A falha só aparece em `normalize_tcp_flags`, três estágios depois — mas é capturada e registrada em `failures`, não silenciosa | PLAUSÍVEL |
| B18 | Resolução de variáveis single-pass não enxerga dentro de `!$VAR`. Com o `snort.lua` padrão (`EXTERNAL_NET = "!$HOME_NET"`) a restrição de origem é perdida. O perfil ativo usa `any`, então não há impacto congelado | PLAUSÍVEL |
| B19 | Lógica de porta duplicada em cinco lugares com critérios divergentes | PLAUSÍVEL |
| B20 | Caminhos absolutos `/home/arthur/datasets/...` e `veth1`/`127.0.0.1:9559` hardcoded; lista `EXPECTED` de `{packet, sid}` congelada em `test_alert_preservation_bmv2.py` | PLAUSÍVEL |
| B21 | O no-match do strong-discriminator não é bypass realizável — as 406 regras de fallback seguem aplicáveis a todo pacote — e o texto de RQ3 apresenta 98,942%/1,058% sem repetir a ressalva | PLAUSÍVEL |

---

## 7. Achados refutados

Listados porque a transparência sobre o que **não** é problema tem valor próprio.

### R1 — "Duas versões de Python sobre o mesmo código" — REFUTADO

A premissa factual estava errada. O achado afirmava que os `.pyc` cpython-310 estavam todos dentro do venv. Há **27 `.pyc` cpython-310 fora do venv**: 14 em `compiler/__pycache__/` e 13 em `tests/__pycache__/`, cobrindo módulos reais do compilador e scripts de replay. Existe bytecode 3.10 justamente para o código do pipeline, o que contradiz a conclusão de que "o venv nunca foi usado".

### R2 — "Não há hash dos recortes de PCAP" — REFUTADO

Factualmente falso. `output/datasets/cicids2017_thursday_metadata.json` documenta cada uma das três janelas com sha256 individual (linhas 57, 83 e 109), além de `file_size_bytes`, `packets`, `capture_start`/`capture_end` com precisão de microssegundos, breakdown de protocolos, contagem de pacotes da vítima e do atacante e `snort_structural_read = VALID`. O hash é propagado para `report.json` como `pcap_sha256`. É caracterização mais detalhada do que a norma da área.

### R3 — "Contradição entre o handoff e o código sobre atomicidade" — REFUTADO

Não há contradição: as duas afirmações são verdadeiras e falam de mensagens P4Runtime diferentes.

- `install_p4runtime.py:265-268`, em `set_pipeline()`: `request.action = SetForwardingPipelineConfigRequest.VERIFY_AND_COMMIT` — semântica de commit da **configuração de pipeline**
- `install_p4runtime.py:420-423`, em `write_entries()`: `request.atomicity = WriteRequest.CONTINUE_ON_ERROR` — atomicidade da **escrita das entradas**

O `CODEX_HANDOFF.md` §9 diz "instalar o pipeline... `install_p4runtime.py` usa `VERIFY_AND_COMMIT`", e o sujeito da frase é o pipeline. O handoff está correto.

Permanece válido, porém, o ponto substantivo: existe um único `WriteRequest` no repositório, com `CONTINUE_ON_ERROR`, e o ramo `COUNT_MISMATCH` (`:764-787`) apenas imprime e termina com exit 0 — a instalação de entradas não é atômica e uma instalação parcial não interrompe a fase de medição.

---

## 8. Correção a um achado desta própria análise

**M11 — a direção `<-` não é uma quebra de `r ⇒ p_r`.**

A primeira onda reportou isto como quebra real do conservadorismo. A verificação adversarial rebaixou o achado, e a correção é importante o bastante para ficar em seção própria.

O **mecanismo** está confirmado linha a linha, e foi reproduzido por execução: `parser.py:171` aceita `<-`; `target_capability.py:503-506` rebaixa a direção para `FALLBACK`; `p4_backend.py:94-136` só consome predicados `preserved`/`expanded`, então `direction` chega como `None`; `expand_p4_entries.py:448,480-490` emite apenas a orientação forward. A regra resultante é classificada `NECESSARY` com `prefilter_candidate = True`.

Mas a **consequência declarada é falsa**. O Snort 3 rejeita `<-` no parse (`parse_rule.cc`, `parse_rule_dir`, emite `ParseError: illegal direction specifier`) — apenas `->` e `<>` são operadores válidos. A regra nunca carrega. Não existe pacote que dispare no Snort e escape do P4; a implicação `r ⇒ p_r` vale vacuamente. O ruleset avaliado tem zero ocorrências de `<-`.

O que sobra é real, mas menor: um caminho de código anunciado (`parser.py:171` enumera `<-` explicitamente, e `docs/semantic_model.md:123` o lista entre os construtos reconhecidos) cujo tratamento é insonoro, sem nenhum teste. A observação estrutural subjacente continua válida e vale a pena registrar: **direção é um predicado estrutural do qual `src_ip`, `src_port`, `dst_ip` e `dst_port` dependem** — rebaixá-la isoladamente para `FALLBACK` não relaxa o predicado, reinterpreta-o. Se um dia outro construto de direção entrar no parser, a mesma armadilha se repete.

Severidade final: **média**, como robustez e higiene, não como correção.

---

## 9. Recomendações priorizadas

### Antes de submeter

1. **Resolver a ablação de agrupamento (C1).** Reimplementar a métrica ou remover as duas subseções e a conclusão `GROUPING_LIMITED_BY_OVERLAP`. É o único achado que remove conteúdo do artigo.
2. **Recompilar o PDF (C3)** e conferir a tabela de semântica em landscape e o ambiente `cases` da subseção *Enforced Packet Domain*.
3. **Declarar a proveniência pré-correção da Tabela 7 (C4)**, ou re-executar os três replays de preservação.
4. **Separar o que é offline do que é data plane (C5).** Uma frase resolve; a ausência dela é o tipo de coisa que um revisor chama de enganosa.
5. **Reportar a redução conservadora (H2)** ao lado da atual. 81,81% honesto vale mais que 91,01% contestável.
6. **Adicionar a diversidade de alertas às Threats (H1).** A frase já existe em `sqli/report.json:limitations[0]`.
7. **Citar CICIDS2017, Snort 3, P4 e BMv2 (H5).**
8. **Publicar o critério de "broad" ou os nove IDs (H6).**
9. **Adicionar declaração de reprodutibilidade (M8):** versão do Snort, sha256 do ruleset, endpoint, link do repositório.

### Antes de qualquer nova rodada de experimentos

10. **Corrigir o snapshot do perfil (C2).** Enquanto `output/profiles/cicids2017/artifacts/ids_prefilter.json` for a cópia pré-correção, qualquer restauração pela via declarada autoritativa reintroduz o bug.
11. **Fazer os validadores falharem (C6).** `sys.exit(1)` em `validate_backend.py` e `validate_semantic_manifest.py` quando `backend_status == "INVALID"` ou quando houver `failures`. É a correção de maior retorno por linha do projeto inteiro.
12. **Ancorar os scripts de análise no snapshot do perfil (H4)**, não em `output/` na raiz.
13. **Fazer `validate_backend.py` ler os artefatos instalados (H3)** e comparar o value/mask emitido com o esperado, em vez de recalcular o mesmo algoritmo.

### Melhorias de resultado

14. **Implementar ranges de porta como decomposição ternária (H12).** Custo medido: 387 entradas, tabela a ~700/8.192. Devolve precisão a 75 regras e provavelmente **melhora** as métricas de candidate set do artigo.
15. **Reclassificar protocolo isolado como não-seletivo (H11).** Remove `p4-106`, que sozinha subsome 74,32% das entradas, ao custo de mover 4 regras para o fallback do Snort.
16. **Expor `ip_proto`, `itype` e `icode` na chave da tabela (M1, M2).** O header ICMP já é parseado. Converte 3 regras de `UNSUPPORTED` para `NECESSARY` e desfaz o colapso das 112 regras em `p4-20`.

### Higiene

17. Adicionar `requirements.txt` e um runner de testes (H7, H8).
18. Ancorar os caminhos do `compiler/` em `Path(__file__)` (M10).
19. Completar ou remover `docs/snort3_support_matrix.md` (H10) — hoje ele afirma menos do que o código faz, e erra a causa no único ponto em que fala.
20. Mover o subsistema legado para `legacy/` ou removê-lo (H9).
21. Estender a suíte de guarda para ARP, IPv6, VLAN, LLDP, GRE e truncamento de UDP/ICMP (M9) — são as classes que de fato compõem o fallback medido.

---

## 10. Apêndice — evidência das medições diretas

Comandos executados na raiz do repositório, com `git status` limpo antes e depois e sem alteração em nenhum dos 236 arquivos de `output/`, `config/`, `p4/`, `docs/`, `paper/` e `rules/`.

```
# C6 — gates de saída
grep -c 'sys\.exit|raise SystemExit' nos 8 scripts do pipeline  ->  0 em todos

# H3 — o que validate_backend.py lê
compiler/validate_backend.py:8  INPUT_FILE  = "../output/p4runtime_entries.json"
referências a p4_install_entries / p4runtime_install_plan / p4info  ->  0 / 0 / 0

# C2 / H4 — hashes
output/ids_prefilter.json                                        f5167adc69e8ae05  69.830 B
output/profiles/cicids2017/artifacts/ids_prefilter.json          41b6215bb5fb3931  62.927 B
output/historical/..._pre_correction/ids_prefilter.json          41b6215bb5fb3931  62.927 B

# H5 — citações
"CICIDS2017" no main.tex: 8 ocorrências, 0 com \cite
references.bib: 10 entradas, todas de trabalho relacionado

# H2 — redução conservadora
"85.43" / "86.40" / "81.81" no main.tex  ->  0 / 0 / 0
"91.01"                                  ->  10

# H1 — diversidade de alertas
full_sid_alert_counts = {"254": 2289, "399": 2, "402": 97, "650": 2, "1394": 1}

# H11 — a entrada p4-106
{"match": {"protocol": 6}, "provenance": {"source_rule_ids": ["1382","32937","54793","56585"],
 "source_rule_count": 4}, "install_entry_id": "p4-106"}

# M12 — aspa ímpar produz EXACT (processo efêmero, PYTHONDONTWRITEBYTECODE, sem escrita no repo)
regra:     alert tcp any any -> any 80 ( msg:"quote " here"; content:"/x"; sid:9101; )
opções:    [{"name": "msg", "value": "quote \" here\"; content:\"/x\"; sid:9101;"}]   -> 1 opção
sid:       None
resultado: classification=EXACT  exact_semantics=True  delegated=0  fallback=0  preserved=6

controle:  alert tcp any any -> any 80 ( msg:"quote here"; content:"/x"; sid:9102; )
           3 opções, sid=9102, classification=NECESSARY, delegated=1

aspas pares mal posicionadas (msg:"SERVER-WEBAPP "admin" login") -> parseia correto.
O gatilho é número ÍMPAR de aspas não escapadas.

alcance no ruleset real: 0 de 4.017 regras

# M13 — parse failure silenciosa
alert tcp any any -> any [80, 443] (...)  -> ValueError: Could not parse rule
alert tcp any any -> any [80,443]  (...)  -> OK
alcance no ruleset real: 0 regras com espaço após vírgula em lista de cabeçalho
```

---

*Relatório produzido por análise estática e de artefatos, com verificação adversarial. Nenhum arquivo do projeto foi modificado. Todos os achados examinados receberam verificação; os dois que haviam ficado pendentes (M12 e M13) foram fechados por reprodução direta em processo efêmero.*

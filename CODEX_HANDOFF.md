# Codex Handoff

**2026-10-05: o padrão do compilador passou a ser `snort3`** (decisão do
usuário, com o artigo relatando `snort3` como resultado e `legacy` como
histórico). A raiz de `output/` agora é a compilação `snort3`: 3.996 /
21 / 0 e 235 entradas; o strong fica com 739 elegíveis, 3.257 em fallback e
225 entradas.

- Os artefatos `legacy` estão arquivados byte a byte em
  `output/historical/legacy_header_semantics/`.
- Tudo o que foi medido antes da troca continua válido como resultado
  `legacy`. As seções abaixo descrevem esse estado congelado, salvo onde
  dizem o contrário.
- Documento: `paper/IDS_P4/HEADER_SEMANTICS_DEFAULT_SUPERSESSION.md`.
- Pendências novas: as medições no rig sob `snort3` e o manuscrito (§15,
  item 5).

Atualizado em 2026-10-01: as quatro pendências que bloqueavam a submissão
estão concluídas (§15). Desde 2026-09-29 também entraram:

- ruleset e saída configuráveis, com o executor estático (§18);
- o perfil com as 17 variáveis que o Snort efetivamente usa, e a checagem
  dele contra o Snort (§3);
- o título delimitado ao escopo medido, e a afiliação completa (§14).

Em 2026-09-29 o achado service-based foi confirmado no plano de
dados (§10 e §15, item 1). A revisão de 2026-09-27 substituiu integralmente a
versão de 2026-09-09:
desde então entraram a campanha end-to-end, as correções de IR, a revisão
pré-submissão do manuscrito e o achado de regras service-based (§10), que é
agora a pendência principal.

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
fallback Snort. O data plane impõe um domínio de pacotes explícito (§6) e faz
fail-open fora dele. A Figura 1 do artigo desenha esse pipeline.

Documentação conceitual: `docs/semantic_model.md`. O corpus normativo de Snort
3, P4₁₆, p4c, BMv2 e P4Runtime fica em `docs/vendor/` (regenerável por
`scripts/fetch_reference_docs.sh`; pins em `docs/vendor/MANIFEST.md`), e a
skill `.claude/skills/snort3-p4` manda citar esse corpus antes de afirmar
qualquer coisa sobre as linguagens. `docs/snort3_support_matrix.md` registra,
construto por construto, o que o Snort 3 permite, o que o compilador faz e as
contagens do ruleset (reescrito em 2026-09-27; fechou o achado H10).

## 3. Perfil ativo

- Perfil: `cicids2017`
- `HOME_NET`: `192.168.10.0/24`; `HTTP_PORTS`: `80 8080`
- Configuração ativa: `config/active_profile.json`,
  `config/snort3_experiment.lua` (inclui o `snort.lua` padrão, com wizard)
- Snort++ 3.12.2.0
- Ruleset: `rules/snort3-community.rules`, 4.017 regras,
  sha256 `8c0d9172127a7270ec8084ffbd16d3995df6d27aa0ccc232638f5f0293e68e19`

**Variáveis (desde 2026-09-29):** o perfil tem as mesmas 17 variáveis que o
Snort usa em `ips.variables` com `config/snort3_experiment.lua`. Isso foi
conferido contra o próprio Snort, com `--dump-config-text`. Antes, eram 13.

- **As 4 que faltavam:** `DNS_SERVERS`, `FTP_SERVERS` e `SSH_SERVERS` valem
  `any`, e `MAIL_PORTS` vale `110 143`. Uma regra que as usasse seria aceita
  pelo Snort e recusada pelo compilador. O ruleset do projeto não usa
  nenhuma, então os artefatos congelados não mudaram.
- **Por que `any`, e não `HOME_NET`:** o `snort.lua` faz `HOME_NET = 'any'`
  (linha 24) antes de incluir o `snort_defaults.lua`, que copia `HOME_NET`
  para elas ali mesmo (linhas 35–41). A configuração do experimento só
  redefine `HOME_NET` depois.
- **Checagem no rig:** `python tests/check_profile_vs_snort.py`. Sai com 0
  se coincidem, 1 se divergem e 2 se não há Snort na máquina. O último
  relatório está em `output/analysis/perfil_vs_snort.json` (PERFIL OK). O
  teste offline da comparação é `tests/test_profile_vs_snort.py`. A checagem
  ainda não roda dentro do `build_profile.py`.
- `$SHELLCODE_PORTS` e `$AIM_SERVERS` são variáveis do Snort 2. O Snort 3
  não as define e recusa a regra com `FATAL: PortVar Lookup failed`. O
  compilador também recusa, então os dois concordam.

## 4. Resultados estáticos congelados

- Source rules: 4017
- EXACT: 0
- NECESSARY: 4003 (2.931 service-based: 2.928 com `service:` explícito e 3
  com serviço implícito por opção DCE; ver §10)
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

## 6. Domínio de pacotes IPv4 (resolvido)

Correção de 2026-09-01 em `p4/ids_prefilter.p4`: o parser só vai para L4 com
`(version, ihl, flags, fragOffset)` em `(4,5,0,0)` ou `(4,5,2,0)`; `MyIngress`
repete a checagem e rejeita `parser_error`; fora do domínio,
`packet_domain_fallback()` marca candidato e conta no índice 2. Matcher offline
unificado em `tests/p4_packet_domain.py`. Suíte de guarda: 11 casos, 0 falhas.
Detalhes: `paper/IDS_P4/PARSER_DOMAIN_RECONCILIATION.md`.

**Atenção:** os snapshots `output/profiles/*/artifacts/ids_prefilter.json` e
`.p4info.txt` são o programa **pré-correção**. Não subir o BMv2 a partir deles;
usar `output/ids_prefilter.json`. Aviso em
`output/profiles/SUPERSESSION_NOTICE.md`.

## 7. Categorias obrigatórias

Manter separadas em todos os relatórios:

- `P4_CANDIDATE` (contador 0): predicado instalado correspondeu, dentro do
  domínio suportado.
- `P4_NO_MATCH` (contador 1): dentro do domínio, nenhum predicado correspondeu.
- `PACKET_DOMAIN_FALLBACK` (contador 2): fora do domínio (não-IPv4, `IHL != 5`,
  fragmento, truncado, erro de parser). Candidato conservador, nunca no-match.

Taxas de candidato e no-match usam apenas o domínio suportado como
denominador.

## 8. Resultados por janela

Artefatos: `output/experiments/`, `output/analysis/`.

| Janela | Pacotes | Domínio | Fallback | Global cand. | Strong cand. | Strong no-match |
|---|---:|---:|---:|---:|---:|---:|
| SQLi (dev) | 35.274 | 34.924 | 350 | 100% | 99,015% | 0,985% |
| XSS (dev) | 191.848 | 189.076 | 2.772 | 100% | 98,869% | 1,131% |
| Brute Force (held-out) | 1.108.658 | 1.101.459 | 7.199 | 100% | 98,942% | 1,058% |

As colunas strong são do classificador offline; o plano de 322 entradas nunca
foi reproduzido com os traces no BMv2.

Alertas e preservação:

| Janela | FULL | SIDs únicos | Missing/Additional | P4 cand. | P4 no-match | Preservação |
|---|---:|---:|---:|---:|---:|---:|
| SQLi | 150 | 1 (254) | 0/0 | 150 | 0 | 100% |
| XSS | 528 | 2 (254, 402) | 0/0 | 528 | 0 | 100% |
| Brute Force | 2.391 | 5 (254, 399, 402, 650, 1394) | 0/0 | 2.391 | 0 | 100% |

As colunas P4 foram medidas primeiro no BMv2 **antes** do gate de domínio,
reproduzindo só os pacotes de alerta. Em 2026-09-30 foram medidas de novo com
o programa corrigido e com envio dos bytes exatos, e deram contabilidade
exata nas três janelas
(`output/analysis/replay_pos_correcao/REPLAY_POST_CORRECTION_VALIDATION.md`).
A rederivação offline sob o domínio imposto também confere
(`output/analysis/alert_preservation_offline_post_correction.json`).

Candidate rule set (baseline 3.611 regras P4-elegíveis):

| Janela | Média | Mediana | P95 | P99 | Máx | Redução (3.611) | Redução (4.017) |
|---|---:|---:|---:|---:|---:|---:|---:|
| SQLi | 179,28 | 27 | 799 | 799 | 1228 | 95,04% | 85,43% |
| XSS | 140,49 | 13 | 799 | 1227 | 1228 | 96,11% | 86,40% |
| Brute Force | 324,52 | 241 | 799 | 1227 | 1228 | 91,01% | 81,81% |

A última coluna conta as 406 regras de fallback (392 operacionais + 14
UNSUPPORTED), que valem para todo pacote.

Ablação strong-discriminator: entrada é "strong" se restringe porta, flags TCP
ou prefixo IPv4 diferente de exatamente `HOME_NET`; regra é P4-elegível só se
todas as suas entradas finais forem strong. Removeu nove entradas (`p4-3`,
`p4-5`, `p4-20`, `p4-24`, `p4-40`, `p4-80`, `p4-106`, `p4-138`, `p4-286`),
reteve 322, 3.611 regras elegíveis, 392 em fallback operacional.

Agrupamento grosseiro: a métrica de candidate set do estudo não lê os grupos,
então a igualdade entre as quatro estratégias é por construção (achado C1/F-05).
O manuscrito agora diz isso e limita o custo pela estrutura dos grupos (grupo
TCP com 3.439 de 3.611 regras, redução de no máximo 4,8%).

## 9. Campanha end-to-end

Snort como oráculo, BMv2 como alvo, um quadro por vez com leitura de contador.
Gerador `tests/generate_campaign_cases.py` (testemunha em
`tests/campaign_witness.py`), executor `tests/run_campaign_bmv2.py`, atribuição
offline `tests/analyze_campaign_attribution.py`. Amostra estratificada de 1.000
regras (semente 20260918) entre as 2.142 sintetizáveis.

| Rodada | Plano | Confirmados | Violação | Dep. estado | Fallback op. | Vácuos | Só própria |
|---|---|---:|---:|---:|---:|---:|---:|
| `e2e_1000_v2` | global 331 | 923 | 0 | 0 | — | 77 | 0 |
| `e2e_1000_v4` | strong 322 | 851 | 0 | 2 | 107 | 40 | 153 |

Predição offline = contador do BMv2 em 2.101/2.101 quadros nas duas rodadas. Os
dois casos de dependência de estado (sids 43809, 47386) têm o alerta HTTP
atribuído ao ACK de flush do servidor, que o plano strong marca no-match. A v4
rodou antes da correção de negação (`9de315e`); o único caso afetado, sid
28982, saiu vácuo. Os pcaps não são versionados, mas o gerador no commit da
rodada os recria byte a byte (verificado para a v4: `ca5486f0…`).

## 10. Achado aberto: regras service-based

Documento: `paper/IDS_P4/SERVICE_BASED_HEADER_FINDING.md`. Medição:
`tests/analyze_service_based_headers.py` →
`output/analysis/service_based_header_exposure.json`.

No Snort 3.12.2.0, quando o serviço identificado no fluxo é um dos da regra,
portas e protocolo do cabeçalho não são checados; os endereços são
(`src/detection/detection_options.cc`, `rtn_checks.cc`, `parse_rule.cc`;
`docs/vendor/snort3/doc/user/concepts.txt:290`). O compilador põe porta e
protocolo no predicado. Então:

- 2.931 das 4.003 NECESSARY são service-based e têm predicado com protocolo
  (quase sempre porta): para elas `r ⇒ p_r` só vale onde o Snort avalia o
  cabeçalho inteiro. São 2.928 com `service:` e 3 (529, 3238, 3239) que
  recebem `dcerpc` e `netbios-ssn` de `dce_iface`/`dce_stub_data`
  (`validate_services`, `src/detection/fp_utils.cc`). As 12 `alert http`
  ficam de fora: `USER_MODE` mantém as portas checadas. Só com endereços,
  2.924 continuariam seletivas.
- Plano global: cobre a região inteira de 2.922 dessas regras pelas entradas
  sem porta (`p4-40`, `p4-138`) e só a parte TCP das outras 9.
- Plano strong e candidate sets: não cobrem nenhuma das 2.877 que o strong
  pré-filtra; as 3 DCE estão no fallback operacional.

**Confirmado no plano de dados em 2026-09-29** (§9 do documento). Foram 200
regras HTTP com `service:http`, com a testemunha na porta 18080, fora do
cabeçalho de todas elas. Resultado:

- O Snort alertou em 190 casos: 190 sids distintos, com os mesmos 220
  alertas nas duas rodadas.
- Plano global: 190 CONFIRMADO, graças a entradas de outras regras.
- Plano strong: 190 VIOLAÇÃO; a testemunha e o ACK de flush saem no-match.
- 10 vácuos, sem relação com a porta.
- O medido bateu com a previsão da geração.

Escopo: uma porta e um serviço. A generalização vem da leitura do código.

O manuscrito já está revisado para esse escopo (§4.5 e §7.2 do artigo). O
compilador tem a semântica corrigida como opção,
`generate_semantic_manifest.py --service-header-semantics snort3` (padrão
`legacy`, que regenera o congelado byte a byte). Efeito estrutural, sem
tráfego (`tests/whatif_service_header_semantics.py`): 3.996 NECESSARY / 21
UNSUPPORTED, 235 entradas finais, strong com 739 elegíveis e 3.257 em
fallback; redução de candidate set sobre o ruleset limitada a 18,40%.

## 11. Metodologia de replay

- Usar `tests/replay_pcap_raw.py`, que envia bytes Ethernet capturados via
  AF_PACKET raw. Não usar `PcapReader/sendp` como evidência quantitativa.
- Instalar o pipeline antes de cada fase: `install_p4runtime.py` usa
  `VERIFY_AND_COMMIT` e a instalação zera os três contadores. Ainda assim,
  medir por **delta** (before/after) e não por valor absoluto.
- Fazer auditoria de idle (delta zero) antes do sender.
- Reconciliar: `frames enviados == P4_CANDIDATE + P4_NO_MATCH + PACKET_DOMAIN_FALLBACK`.
- MTU das quatro veth em 65535 para evitar `EMSGSIZE`.
- Captura com `tcpdump` é diagnóstico secundário.

Status do accounting: SQLi, XSS e Brute Force `ACCOUNTING_VALID`.

- SQLi e XSS: documentos em `output/analysis/ipv4_packet_domain_correction/`.
- Brute Force: era `ACCOUNTING_PARTIAL`, com 87 frames perdidos. A nova
  rodada de 2026-09-30, com `txqueuelen` 10000 e intervalo de 2 ms, fechou
  exata: 1.108.658 enviados e contados. Documento em
  `output/analysis/replay_pos_correcao/`; roteiro em
  `scripts/rig_replay_pos_correcao.sh`.

## 12. BMv2/P4Runtime

- `simple_switch_grpc` 1.15.0 (build `68f4a978`), device-id 0
- P4Runtime/gRPC `127.0.0.1:9559`
- port 0 -> `veth0`, port 1 -> `veth2`; replay em `veth1`
- capacidade da tabela: 8192; 331 entradas do plano cicids2017

Subir: `sudo ./scripts/setup_bmv2.sh up` com `output/ids_prefilter.json`,
depois `python compiler/install_p4runtime.py` (ou `--plan <plano>`); conferir
master arbitration, pipeline configuration e leitura das entradas.

## 13. Ambiente

- Rig Linux (WSL ou VM): BMv2, veth, Snort, scapy, grpc. Todo experimento de
  data plane roda lá.
- Máquina Windows onde o repositório vive: sem BMv2, veth, Snort ou scapy.
  **Tem LaTeX** (MiKTeX em `AppData\Local\Programs\MiKTeX\miktex\bin\x64\`):
  compilar com pdflatex, bibtex, pdflatex, pdflatex e `--enable-installer`;
  `latexmk` trava. Numa cópia isolada, para não sujar `paper/IDS_P4/`.
- A mesma máquina tem, desde 2026-09-27, a captura
  `C:\Users\amede\datasets\cicids2017\raw\Thursday-WorkingHours.pcap`
  (sha256 conferido) e as três janelas em `...\cicids2017\windows\`, cortadas
  por `tests/cut_cicids2017_windows.py` (registro do corte em
  `output/datasets/cicids2017_windows_offline_cut.json`). Métricas de trace
  offline rodam aqui; replay no BMv2, não.
- Suíte: `python tests/run_tests.py` → 23 passam, 3 não executam (grpc).

## 14. Manuscrito

45 páginas, sem overfull nem underfull box. Duas figuras TikZ (pipeline; visão conceitual) e dez tabelas. A
revisão pré-submissão de 2026-09-27 fechou os itens C1, C4, C5, H2, H5 e H6 da
revisão de 2026-09-11, integrou o achado service-based e aplicou uma revisão
adversarial do manuscrito inteiro (§5 da auditoria abaixo); origem de cada
número em `paper/IDS_P4/REVIEW_ITEMS_RESOLUTION_AUDIT.md` e
`paper/IDS_P4/CAMPAIGN_INTEGRATION_AUDIT.md`. O `main.pdf` versionado
corresponde ao `main.tex` atual.

Versão curta em português em `paper/IDS_P4_PT/` (IEEEtran, 7 páginas, com
Silvio E. Quincozes, FACOM/UFU), reescrita em 2026-09-28 a partir do
`main.tex`. É derivada: número que mudar no `main.tex` muda lá também.

**Título (desde 2026-10-01).** Delimita três coisas: só as condições de
cabeçalho viram predicado, o pré-filtro é conservador (marca candidatos, não
detecta) e a avaliação é no BMv2, sem hardware.

- `main.tex`: *Compiling Snort 3 Rule Headers into Conservative P4
  Prefilters: An Evaluation on BMv2*. Antes era *From Semantic Safety to
  Candidate-Rule-Space Reduction in Snort-to-P4 Compilation*.
- `artigo.tex`: *Compilação de Cabeçalhos de Regras do Snort 3 em
  Pré-filtros P4 Conservadores: Avaliação no BMv2*. Sem "uma", para caber em
  duas linhas.

A afiliação do primeiro autor agora traz a cidade (UNIPAMPA, Alegrete,
Brazil) nos dois manuscritos, e o `main.tex` está datado de outubro de 2026.
Os builds continuam limpos: 45 e 7 páginas (a 45ª veio em 2026-10-05, com a frase sobre rulesets externos e EXACT em External Validity e em Limitações).

**Versão SBRC (2026-10-05).** `paper/IDS_P4_SBRC/`, em português no modelo
oficial da SBC (`sbc-template.sty` e `sbc.bst` sem alteração; origem e
sha256 no README da pasta). O corpo é o do `IDS_P4_PT/artigo.tex`, copiado
por `montar.py`; só a primeira página (abstract e resumo de até 10 linhas
cada) é própria. Dá 14 páginas com as referências, o limite da trilha
principal do SBRC 2026, sem caixa estourada. Cadeia de derivação:
`main.tex` → `IDS_P4_PT` → `IDS_P4_SBRC`.

## 15. Pendências que bloqueiam a submissão

**Todas as quatro concluídas** (a última, o item 3, em 2026-09-30). O
registro de cada uma fica abaixo.

1. **Testar o achado service-based no data plane.** Casos prontos em
   `output/campaign/servico_fora_do_cabecalho/` (gerador
   `tests/generate_offport_service_cases.py`; o pcap é recriado por ele):

       python tests/generate_offport_service_cases.py
       python tests/run_campaign_bmv2.py --casos output/campaign/servico_fora_do_cabecalho
       python tests/run_campaign_bmv2.py --casos output/campaign/servico_fora_do_cabecalho \
           --plano output/campaign/plano_strong_discriminator/p4runtime_install_plan.json \
           --particao output/campaign/plano_strong_discriminator/particao.json --sufixo _strong

   Esperado se o código lido estiver certo: global CONFIRMADO, strong
   VIOLACAO (código de saída 1 é o esperado). Tudo VACUO invalida a leitura.

   **FEITO no rig em 2026-09-29, e confirmou a leitura.** Global: 190
   CONFIRMADO e 10 VACUO. Strong: 190 VIOLACAO e 10 VACUO. Resultados em
   `output/campaign/servico_fora_do_cabecalho/` (`relatorio*.json`,
   `resultado*.jsonl`, `snort_alertas*.jsonl`); análise no §9 de
   `SERVICE_BASED_HEADER_FINDING.md`.

   O resultado já está no manuscrito.
   - `main.tex`: §7.2, um parágrafo novo com o teste; Threats, onde o achado
     passa a ser dado como confirmado no BMv2 para um serviço e uma porta; e
     os limites da campanha, que agora apontam para o teste.
   - `IDS_P4_PT/artigo.tex`: resultados, Limitações e trabalhos futuros.

   Builds limpos: `main.pdf` com 44 páginas e `artigo.pdf` com 7, sem
   overfull nem underfull.
2. **Métricas de trace com a semântica corrigida: FEITO offline em
   2026-09-27**, nesta máquina, com as janelas cortadas da captura (§13):

       python tests/rederive_trace_metrics.py --janela sqli=... --janela xss=... --janela bruteforce=...

   O `legacy` reproduziu o congelado pós-correção exatamente. `snort3`:
   global 100%; strong 92,298% / 92,173% / 94,885% (SQLi/XSS/BF); C(x) médio
   3,97 / 3,94 / 4,48 de 739; redução sobre o ruleset 18,30% / 18,30% /
   18,29%. Saída: `output/analysis/trace_metrics_by_semantics.json`; números
   no manuscrito (§7.2). Auditoria de alertas
   (`tests/rederive_alert_coverage_by_semantics.py` →
   `output/analysis/alert_coverage_by_semantics.json`): o legacy reproduz
   2.289 / 102 / 0; no `snort3` nenhum dos 3.069 alertas se perde, mas todos
   passam a vir de regras em fallback (a sid 254, `service:dns`, fica só com o
   destino `HOME_NET`), então os traces não exercitam os candidate sets
   corrigidos. Resta decidir se o padrão do compilador vira `snort3`
   (regenera os artefatos congelados, com documento de supersessão) e medir os
   planos corrigidos no BMv2.

   **Decisão do usuário (2026-09-28): o padrão continua `legacy` por
   enquanto. Revista em 2026-10-05: o padrão passou a ser `snort3` (item 5).** O artigo segue relatando o congelado e a medição offline
   `snort3` da §7.2. Se a troca voltar à mesa, isto é o que ela muda:
   - Regenera os artefatos do pipeline em `output/` (manifesto, entradas P4,
     plano P4Runtime, `backend_validation.json`): 3.996 NECESSARY / 21
     UNSUPPORTED, 235 entradas em vez de 331, strong com 739 elegíveis.
     Os antigos ficam como congelados de referência, com documento de
     supersessão; nada é sobrescrito sem ele.
   - No artigo, as tabelas de backend, seletividade e candidate sets e o texto
     de RQ1–RQ4 passam a ter dois conjuntos de números, ou os novos com os
     antigos como histórico.
   - Resultados medidos no BMv2 (taxa global pelos contadores, replay de
     preservação, campanha end-to-end, 11 casos controlados) foram feitos com
     o plano `legacy`; para continuarem sendo do data plane com o novo padrão,
     precisam rodar de novo no rig.
   - Sem trocar: o artigo já relata os dois (congelado + medição offline
     `snort3` na §7.2), que é a opção de menor risco para submeter agora.
3. **Replay de preservação no BMv2 corrigido** e **replay frame-exato do Brute
   Force**: **FEITOS no rig em 2026-09-30**, os quatro `ACCOUNTING_VALID`.
   - Pacotes de alerta: 150 / 528 / 2.391, todos candidatos, 0 no-match.
   - Janela Brute Force: 1.108.658 enviados e contados; 1.101.459
     candidatos, 0 no-match, 7.199 fallback, igual ao offline.

   Documento:
   `output/analysis/replay_pos_correcao/REPLAY_POST_CORRECTION_VALIDATION.md`.
4. **Métrica de candidate set agrupada** (F-05, alternativa A2): **FEITO
   offline** na mesma rodada (`candidate_set_agrupado`). Redução média sobre
   as 3.611 elegíveis: protocolo 19,10 / 15,65 / 12,30%; protocolo+direção
   57,34 / 55,10 / 54,10%; protocolo+serviço 89,54 / 92,24 / 81,12%;
   protocolo+direção+serviço a menos de 0,01 ponto do nível de entrada. No
   manuscrito: Tabela `tab:grouped`, §RQ4 e Discussão.

5. **Troca do padrão para `snort3` (2026-10-05).** Feito na máquina
   Windows:
   - padrão trocado;
   - `legacy` arquivado e reproduzível;
   - raiz de `output/` regenerada;
   - simulação strong `snort3` em
     `output/analysis/operational_policy_simulation_snort3.json`;
   - plano strong `snort3` em
     `output/campaign/plano_strong_discriminator_snort3/`.

   Falta:
   - **Rig:** refazer sob os planos `snort3` (global 235, strong 225) os 11
     casos controlados, a contabilidade de replay das três janelas, a
     preservação dos pacotes de alerta, a campanha end-to-end e o teste de
     serviço fora da porta.
   - **Manuscrito:** `snort3` como resultado e `legacy` como histórico.

   Detalhes em `paper/IDS_P4/HEADER_SEMANTICS_DEFAULT_SUPERSESSION.md`.

## 16. Pendências de reforço científico

- Um único ruleset, um perfil e um dataset; CIC-IDS2017 é antigo.
- Diversidade de alertas nos traces: 1, 2 e 5 SIDs. A campanha cobre 851–923
  SIDs, mas com tráfego sintético.
- Sem throughput, latência ou validação em hardware.
- Sem execução candidate-set-aware no Snort.
- EXACT = 0 no ruleset avaliado.
- Achados de melhoria ainda abertos na revisão de 2026-09-11, com o ganho
  máximo medido em 2026-09-27 (regras que sairiam do fallback operacional ÷
  4.017, isto é, o teto do ganho na redução sobre o ruleset do plano strong):
  - H12, faixas de porta em ternário: 73 regras recuperáveis (56 por porta),
    71 hoje fora do strong; ≤ 1,8 ponto no `legacy`, ≤ 1,4 no `snort3`.
    Custo: porta passa a valor/máscara no formato de entrada, no codificador
    P4Runtime, no `validate_backend`, na deduplicação e nos dois casadores.
  - M1, `itype`/`icode` na chave: 124 NECESSARY, 123 hoje no fallback;
    ≤ 3,1 pontos. Exige chave nova no `ids_prefilter.p4` (não compilável aqui).
  - M2, `ip_proto` no campo de protocolo já existente: 3 UNSUPPORTED
    (2462–2464); ≤ 0,07 ponto. Só compilador.
  - H11, protocolo isolado como seletivo: o plano strong já remove essas
    entradas (`p4-106` entre as nove), então a ablação strong é o efeito dele.
  Não implementados: o ganho somado fica abaixo de ~5 pontos e nenhum muda
  a conclusão do artigo. Contagens em `output/analysis/header_precision_bounds.json`
  (`tests/analyze_header_precision_bounds.py`).
- Campanha end-to-end:
  - A `e2e_1000_v4` só foi medida no BMv2 sob o plano strong; nunca rodou
    com o plano global.
  - Restam 40 casos vácuos por limites do gerador de testemunhas.
- **Rulesets de fora** (§18):
  - O compilador aceita sintaxe Snort 2, e desde 2026-10-01 avisa. Os
    predicados P4 saíram iguais aos da versão convertida, mas a atribuição
    de buffers na IR provavelmente sai errada. Isso não foi medido.
  - **Feito em 2026-10-01:** as 10 regras EXACT que o ruleset do Snort 2
    produziu foram conferidas no Snort, nas duas direções, por
    `tests/check_exact_rules.py` (rig, sem `sudo`): 34 quadros, 340 pares
    (quadro, regra) e 0 discordâncias. É a primeira evidência medida de
    EXACT, mas com escopo estreito: pontos amostrados, dentro de D, com o
    casador offline e não o BMv2, e fora do ruleset avaliado
    (`EXTERNAL_RULESETS_ROBUSTNESS.md` §6.1).
  - O sintoma da sintaxe Snort 2 agora gera aviso
    (`compiler/snort2_syntax.py`).
- Trabalho futuro decidido pelo usuário:
  - o compilador como controlador P4Runtime contínuo (atualização
    incremental, troca de plano, telemetria);
  - o encaminhamento por fluxo, para que o Snort receba o fluxo inteiro;
  - o hardware físico, quando houver acesso.

## 17. Estado de arquivos e Git

Repositório Git desde 2026-09-09, remoto `origin` no GitHub. Capturas `.pcap`
ficam fora do versionamento (regeneráveis); o restante, incluindo artefatos
congelados, está versionado.

Convenção do projeto: artefato congelado não é sobrescrito. Correção entra como
documento novo declarando supersessão, no máximo com adendo curto no topo do
documento antigo apontando para o novo.

## 18. Ruleset configurável e testes com outros rulesets

Desde 2026-09-29 o compilador aceita outro ruleset sem tocar nos artefatos
congelados.

- `compiler/paths.py` é a fonte única: `SNORT_P4_RULESET` e
  `SNORT_P4_OUTPUT_DIR`. Sem as variáveis, valem os caminhos de sempre, e o
  pipeline reproduz `output/` byte a byte.
- **Travas:** um ruleset diferente do padrão com a saída em `output/` é
  recusado ao importar `paths`, antes de qualquer escrita. O mesmo vale
  para outro arquivo de variáveis (`SNORT_P4_VARIABLES`, desde
  2026-10-01). O `build_profile.py` recusa as três variáveis.
- **Executor estático (Windows, sem o rig):**

      python compiler/run_static_pipeline.py --ruleset <arquivo.rules> --saida <diretorio> [--limpar] [--perfil <nome>]

  - Roda as mesmas etapas do `build_profile`, de `PYTHON_STEPS` até
    `generate_p4runtime_install.py`. Copia o programa P4 de `output/`,
    porque ele não depende do ruleset.
  - Grava `proveniencia.json`: sha256 do ruleset e do arquivo de
    variáveis, commit, cada etapa e o sha256 de cada artefato.
  - `--perfil <nome>` usa as variáveis de `config/profiles/<nome>.json`,
    validadas e gravadas em `--saida` pelas funções do
    `select_profile.py`, sem reescrever `config/`. Com `--perfil
    controlled`, as entradas P4 saem byte a byte iguais às do snapshot
    congelado desse perfil, de 2026-08-25. O manifesto difere dele só no
    rótulo das variáveis e nas 112 regras das duas correções de IR.
  - Avisa quando o ruleset tem sintaxe do Snort 2
    (`compiler/snort2_syntax.py`).
  - `--limpar` compila uma cópia só com as regras ativas. Para `gid:sid`
    repetido segue o Snort 3 (`parse_rule.cc`, `mergeDuplicateOtn`): fica a
    revisão maior e, no empate, a mais recente. Se as ocorrências diferem
    em ação ou protocolo, recusa, como o Snort.
- **Testes:** `tests/test_ruleset_configuravel.py` e
  `tests/test_limpar_ruleset.py`. Com o ruleset padrão, o executor gera os
  10 artefatos idênticos ao congelado.

**Testes com outros rulesets (2026-09-29, reproduzidos em 2026-10-01).** Os
testes agora são reproduzíveis:

- `scripts/rig_rulesets_externos.sh` (rig) recria as entradas em
  `C:\Users\amede\datasets\rulesets\`, com o sha256 de cada uma.
- `tests/analyze_external_rulesets.py` (Windows) as compila e grava
  `output/analysis/rulesets_externos.json`.
- O documento é `paper/IDS_P4/EXTERNAL_RULESETS_ROBUSTNESS.md`.

Toda recusa coincide com uma recusa do Snort 3: variável indefinida,
`gid:sid` repetido com outro protocolo (o sid 647, em TCP e UDP) e regras
`file_id`. O `compiler/snort2_syntax.py` avisa quando o ruleset tem sintaxe
Snort 2: 3.272 regras no arquivo cru e 2 no convertido. As 2 são falso
positivo de um defeito do parser com `\;`, que não afeta o ruleset do
projeto.

| Ruleset | Regras | Resultado | EXACT / NECESSARY / UNSUPP. | Entradas |
|---|---:|---|---|---:|
| `sensitive_data.rules` (vem com o Snort 3) | 25 | ok | 0 / 25 / 0 | 1 |
| `file_magic.rules` (vem com o Snort 3) | 219 | recusado: são regras `file_id`, não de tráfego | — | — |
| `snort-rules-default` 2.9.15.1 do Ubuntu, convertido pelo `snort2lua` | 3.935 | recusado: 27 regras com variável indefinida | 10 / 3.917 / 8 | — |
| o mesmo, sem essas 27 regras e com `--limpar` | 3.887 | ok | 10 / 3.869 / 8 | 333 |
| o mesmo em sintaxe Snort 2 crua, sem as 27 e limpo | 3.900 | ok | 10 / 3.881 / 9 | 335 |

O que os testes mostraram:

- Nas 3.887 regras comuns às versões crua e convertida, a classificação e as
  entradas P4 são idênticas. As diferenças vêm só das 13 regras que o
  `snort2lua` não converteu.
- As 10 regras EXACT são só de cabeçalho, sem opções de detecção (§16).
- A variável indefinida e as linhas sem SID foram recusadas pelas validações
  de sempre, sem nenhuma decisão implícita.

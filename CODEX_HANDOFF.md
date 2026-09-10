# Codex Handoff

## 1. Objetivo científico atual

Avaliar uma arquitetura híbrida em que o P4 atua como prefilter/candidate marker para o Snort, preservando a semântica do ruleset e medindo correção, cobertura do parser e seletividade operacional. O P4 não substitui o Snort e não é evidência de detecção da ground truth do CIC-IDS2017.

## 2. Arquitetura

`Snort rules -> semantic IR -> semantic manifest -> P4 backend -> P4Runtime plan -> BMv2`

O fluxo gera candidatos conservadores; regras UNSUPPORTED continuam exigindo fallback Snort.

## 3. Perfil ativo

- Perfil: `cicids2017`
- `HOME_NET`: `192.168.10.0/24`
- Configuração ativa: `config/active_profile.json`

## 4. Resultados estáticos congelados

- Source rules: 4017
- EXACT: 0
- NECESSARY: 4003
- UNSUPPORTED: 14
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

## 6. SQL Injection — resultado definitivo

Artefatos: `output/experiments/cicids2017_thursday_sqli/`

- PCAP: 35.274 pacotes
- FULL alerts: 150
- Baseline candidate: 150
- Baseline unsupported: 0
- Unknown: 0
- Candidate run: 150
- Unsupported run: 0
- Missing/additional em todas as comparações: 0/0
- Unique SIDs: 1 (SID 254, 150 alertas)
- Candidate alert packets: 150
- P4 candidate alert packets: 150
- P4 no-match alert packets: 0
- Alert preservation: 100%
- Replay accounting: VALID
- Parser accounting: VALID
- Parser eligible: 34.924
- Parser ineligible: 350 (ARP 125, IPv6 195, CDP/LLC 30)
- P4 candidate: 34.924
- P4 no-match: 0
- Status: VALID

A medição antiga `30503/35274` está preservada como `INVALID_MEASUREMENT_SUPERSEDED`.

## 7. XSS — resultado definitivo

Artefatos: `output/experiments/cicids2017_thursday_xss/`

- PCAP: 191.848 pacotes
- FULL alerts: 528
- Baseline candidate: 528
- Baseline unsupported: 0
- Unknown: 0
- Candidate run: 528
- Unsupported run: 0
- Missing/additional em todas as comparações: 0/0
- Unique SIDs: 2: SID 254 (521 alertas) e SID 402 (7 alertas)
- Candidate alert packets: 528
- Parser-eligible alert packets: 528
- Parser-ineligible alert packets: 0
- P4 candidate alert packets: 528
- P4 no-match alert packets: 0
- Alert preservation: 100%
- Replay accounting: VALID
- Parser eligible: 189.076
- Parser ineligible: 2.772 (ARP 1.660, IPv6 820, CDP 289, LLDP 3)
- P4 candidate: 189.076
- P4 no-match: 0
- Status: VALID

Os SIDs observados não devem ser interpretados como detecção comprovada da ground truth XSS.

## 8. Metodologia de replay

- Preferir `tests/replay_pcap_raw.py`, que envia bytes Ethernet capturados via AF_PACKET raw.
- Não usar `PcapReader/sendp` como evidência quantitativa final sem validação adicional; a reserialização pode alterar frames.
- Para replay completo, capturar simultaneamente em `veth0` e verificar:
  - `PCAP_INPUT == VETH0_RECEIVED`
  - `PARSER_ELIGIBLE == P4_CANDIDATE + P4_NO_MATCH`

## 9. Categorias obrigatórias

Manter separadas em todos os relatórios:

- `P4_CANDIDATE`: predicado P4 instalado correspondeu.
- `P4_NO_MATCH`: frame parser-eligible não correspondeu a predicado instalado.
- `PARSER_INELIGIBLE`: parser atual não produziu `hdr.ipv4` válido (não é no-match).

## 10. Arquivos e scripts importantes

- Perfil/configuração: `config/profiles/cicids2017.json`, `config/active_profile.json`, `config/snort3_experiment.lua`
- Seleção/build: `compiler/select_profile.py`, `compiler/build_profile.py`
- Instalação/leitura P4Runtime: `compiler/install_p4runtime.py`, `compiler/read_prefilter_counters.py`
- P4: `p4/ids_prefilter.p4`
- Ruleset e partições: `rules/snort3-community.rules`, `output/snort_candidate.rules`, `output/snort_unsupported.rules`
- Replay raw: `tests/replay_pcap_raw.py`
- Análise parser: `tests/analyze_p4_parser_coverage.py`
- Comparação Snort: `tests/analyze_cicids2017_sqli_snort.py`
- Relatórios: `tests/build_cicids2017_sqli_report.py`, `tests/build_cicids2017_xss_report.py`
- Planos: `output/p4runtime_install_plan.json`, `output/p4_install_entries.json`, `output/ids_prefilter.json`

## 11. BMv2/P4Runtime

Configuração conhecida:

- `simple_switch_grpc`
- device-id 0
- P4Runtime/gRPC `127.0.0.1:9559`
- port 0 -> `veth0`
- port 1 -> `veth2`
- interface de replay usual: `veth1`
- 331 entradas do plano cicids2017

Para restaurar, iniciar o BMv2 com `output/ids_prefilter.json` e executar `compiler/install_p4runtime.py`; confirmar master arbitration, pipeline configuration e leitura 331/331. Verificar counters iniciais antes de cada fase.

## 12. Ainda não executado

- Janela Brute Force.
- Outros dias/janelas/datasets do CIC-IDS2017.
- PCAPs além das janelas SQLi e XSS auditadas.
- Benchmarks de throughput, latência, speedup ou alegações de offload/economia real.
- Experimentos adicionais de produção.

## 13. Próxima tarefa EXATA

Auditar por que SQLi e XSS tiveram 100% dos parser-eligible packets como `P4_CANDIDATE`, analisando as 331 entradas finais e identificando predicados amplos/protocol-only.

**NÃO executar Brute Force antes dessa auditoria.**

## 14. Hipóteses (não fatos)

- Uma ou mais entradas amplas, possivelmente protocol-only ou com máscaras pouco restritivas, podem cobrir quase todo o tráfego IPv4 elegível.
- A deduplicação/lowering de flags pode ter produzido combinações que ampliam a cobertura efetiva.
- A distribuição das regras candidate exercitadas pelas janelas SQLi/XSS pode não representar a totalidade das 4003 regras.

Essas hipóteses devem ser verificadas diretamente nos 331 entries e não tratadas como conclusões antecipadas.

## 15. Estado de arquivos e Git

O diretório raiz não foi reconhecido como repositório Git pelo ambiente (`git status` retornou: `fatal: not a git repository`). Portanto não há status Git confiável a registrar.

Arquivos de trabalho criados/modificados durante a preparação deste handoff incluem este `CODEX_HANDOFF.md`, os auxiliares em `tests/` listados acima e os artefatos do experimento XSS em `output/experiments/cicids2017_thursday_xss/`. Os resultados e snapshots SQLi/controlled/cicids2017 devem ser tratados como congelados; não sobrescrever.

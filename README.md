# Snort-p4

**Compilação de Cabeçalhos de Regras do Snort 3 em Pré-filtros P4
Conservadores: Avaliação no BMv2**

Arthur de Freitas Medeiros (UNIPAMPA) e Silvio E. Quincozes (FACOM/UFU)

Um compilador que traduz as condições de cabeçalho das regras do Snort 3 em
entradas de tabela P4 e declara, regra a regra, o que a tradução preserva e
o que fica com o Snort. O P4 atua como **marcador de candidatos** para o
Snort, não como substituto: o data plane classifica cada pacote em uma de
três categorias e o Snort continua fazendo a detecção. Regras que o
compilador não consegue representar de forma conservadora continuam
exigindo fallback.

Este repositório tem o artigo, o compilador, o programa P4 e todos os
artefatos e medições que sustentam os números do artigo.

## O artigo

| Versão | PDF | Para quê |
|---|---|---|
| Completa, em inglês | [`paper/IDS_P4/main.pdf`](paper/IDS_P4/main.pdf) | versão de referência (45 páginas); as outras derivam dela |
| Português, sem modelo de evento | [`paper/IDS_P4_CORINGA/artigo.pdf`](paper/IDS_P4_CORINGA/artigo.pdf) | para circular e ler (12 páginas) |
| Português, IEEEtran | [`paper/IDS_P4_PT/artigo.pdf`](paper/IDS_P4_PT/artigo.pdf) | versão curta de conferência (7 páginas) |
| Português, modelo SBC | [`paper/IDS_P4_SBRC/artigo.pdf`](paper/IDS_P4_SBRC/artigo.pdf) | trilha principal do SBRC (14 páginas, o limite) |

Como as versões se relacionam e o que são as auditorias em
`paper/IDS_P4/`: [`paper/README.md`](paper/README.md).

## Resultados principais

Snort 3 Community Ruleset (4.017 regras), Snort 3.12.2.0, BMv2 e as janelas
de quinta-feira do CICIDS2017:

- 3.996 regras ficam com predicado necessário, 21 não suportadas e nenhuma
  exata; o backend instala 235 entradas no BMv2.
- Mesmo assim, o pré-filtro global marca 100% dos pacotes elegíveis nos três
  traços: segurança semântica não implica seletividade.
- Os alertas observados são preservados, e uma campanha com 1.000 regras, com
  o Snort como oráculo e o BMv2 como alvo, não encontra violação.
- Em 2.931 regras baseadas em serviço, o Snort 3 não checa porta nem
  protocolo depois de identificar o serviço, então o compilador mantém só os
  endereços. Numa compilação anterior, que mantinha as portas, um dos planos
  marcou como no-match, no BMv2, as testemunhas de 190 regras HTTP que
  alertaram fora da porta do cabeçalho.
- A proveniência das entradas reduz o conjunto de regras candidatas por
  pacote em só 18,3% do ruleset, contra 81,8% na compilação anterior.

## Mapa do repositório

| Pasta | Conteúdo |
|---|---|
| `paper/` | as quatro versões do artigo e as auditorias do manuscrito |
| `compiler/` | o compilador Snort → P4 (só a biblioteca padrão do Python) |
| `p4/` | o programa P4 (`ids_prefilter.p4`) |
| `rules/` | o ruleset avaliado (Snort 3 Community, 4.017 regras) |
| `config/` | perfil de variáveis do Snort e configuração do experimento |
| `output/` | artefatos gerados e medições; congelados, não se editam à mão |
| `tests/` | testes, campanhas e scripts de análise |
| `scripts/` | montagem do BMv2 e rotinas do ambiente Linux de medição |
| `docs/` | modelo semântico, matriz de suporte do Snort 3 e revisões |
| `CODEX_HANDOFF.md` | estado do projeto, resultados e pendências (notas de trabalho) |

O restante deste README é a referência técnica: a propriedade que o
compilador preserva, como rodar e como reproduzir.

## A propriedade central

    Snort(regra, pacote)  =>  P4_candidato(regra, pacote)

Se um pacote pode satisfazer a regra Snort original, o prefilter não pode
descartá-lo. Uma implementação pode ser deliberadamente **mais permissiva**;
não pode ser silenciosamente mais restritiva.

Quando a propriedade não pode ser preservada, o tratamento é `FALLBACK`,
`UNSUPPORTED` ou limitação explícita — nunca descartar a informação em
silêncio.

## As três categorias do data plane

| Categoria | Contador | Significado |
|---|---|---|
| `P4_CANDIDATE` | 0 | Um predicado instalado casou, dentro do domínio suportado |
| `P4_NO_MATCH` | 1 | Dentro do domínio, nenhum predicado casou |
| `PACKET_DOMAIN_FALLBACK` | 2 | Fora do domínio (não-IPv4, `IHL != 5`, fragmento, truncado, erro de parser) — candidato conservador |

Taxas de candidato e no-match usam **apenas o domínio suportado** como
denominador. Colapsar o fallback em no-match superestima a seletividade;
colapsá-lo em candidato esconde a cobertura real do parser.

## Pipeline

    regras Snort
        -> parser -> resolução de variáveis -> IR semântica
        -> análise de capacidade do alvo -> classificação -> manifesto
        -> backend P4 -> expansão -> normalização -> lowering
        -> plano P4Runtime -> BMv2

Os estágios até o manifesto rodam num processo só, acoplados por objeto
Python. Do manifesto em diante, cada estágio é um processo que se comunica
com o seguinte por arquivo JSON em `output/`.

## Requisitos

O **compilador não tem dependência de terceiros**. Os 22 módulos do
pipeline oficial usam apenas a biblioteca padrão, e qualquer Python 3.10+
recompila o ruleset e reproduz os artefatos.

O que exige ambiente pesado é a instalação no BMv2 e os experimentos:

| Extra | Para quê | Pacotes |
|---|---|---|
| `experiments` | leitura/escrita de pcap | `scapy` |
| `p4runtime` | instalar no BMv2, ler contadores | `grpcio`, `protobuf` + bindings `p4.v1` |
| `dev` | suíte de testes via pytest | `pytest` |

Os bindings `p4.v1` e `p4.config.v1` **não estão no PyPI** — vêm da
compilação de `p4lang/PI` ou do `p4runtime-shell`.

Fora do Python: Snort 3 (validado com 3.12.2.0), `p4c-bm2-ss` e
`simple_switch_grpc`.

## Comandos

    # instalar (só os extras; o núcleo não precisa de nada)
    pip install -e .[dev]
    pip install -e .[experiments,p4runtime]   # só no rig com BMv2

    # rodar a suíte — um veredito único
    python tests/run_tests.py
    python tests/run_tests.py -v              # saída completa das falhas

    # reconstruir um perfil inteiro (exige Snort e p4c)
    python compiler/build_profile.py cicids2017

    # estágios isolados (funcionam de qualquer diretório)
    python compiler/generate_semantic_manifest.py
    python compiler/validate_semantic_manifest.py
    python compiler/validate_backend.py

    # subir o alvo BMv2 (só no rig Linux; cria veth, precisa de root)
    ./scripts/setup_bmv2.sh status        # inspeciona, não altera nada
    sudo ./scripts/setup_bmv2.sh up
    python compiler/install_p4runtime.py
    sudo ./scripts/setup_bmv2.sh down

`setup_bmv2.sh` cuida só da rede e do processo do switch — não compila o P4
(quem faz isso é `build_profile.py`) nem instala entradas na tabela. As veth
saem com MTU 65535, porque o replay escreve quadros maiores que 1500 e o
envio falharia com `EMSGSIZE`, e com IPv6 desligado, para que router
solicitation e multicast do kernel não entrem no switch e não sejam contados.

`build_profile.py` verifica o toolchain **antes** de escrever qualquer
coisa. Numa máquina sem Snort e sem p4c ele aborta com código 1 sem tocar em
nenhum arquivo.

Todos os estágios falham com código diferente de zero quando o artefato que
gravaram declara erro. Um build que termina com sucesso é um build cujos
artefatos estão limpos.

### Outro ruleset

`build_profile.py` compila só o ruleset padrão
(`rules/snort3-community.rules`) em `output/`. Para compilar outro, sem o rig,
use:

    python compiler/run_static_pipeline.py --ruleset <arquivo.rules> --saida <diretorio>

O que ele faz:

- Roda as mesmas etapas do `build_profile`, da regra ao plano P4Runtime.
  Usa as variáveis do perfil ativo, ou as de outro perfil com
  `--perfil <nome>` (`config/profiles/<nome>.json`), sem reescrever
  `config/`.
- Avisa quando o ruleset tem sintaxe do Snort 2, que o Snort 3 recusaria
  (`compiler/snort2_syntax.py`).
- Grava tudo em `--saida`, com um `proveniencia.json` que registra o ruleset
  (sha256 e número de regras), o commit, cada etapa e o sha256 de cada
  artefato.
- Não valida o ruleset no Snort nem compila o P4. O programa P4 não depende do
  ruleset e é copiado de `output/`.

A divisão das regras exige uma regra ativa com SID por linha, sem SID
repetido. Rulesets distribuídos em pacote trazem comentários, regras
comentadas e SIDs repetidos entre arquivos. Nesse caso, acrescente
`--limpar`:

- Compila uma cópia só com as regras ativas e junta as regras quebradas em
  várias linhas com `\`.
- Resolve `gid:sid` repetido como o Snort 3 ao carregar o ruleset: fica a
  revisão maior e, no empate, a mais recente. Recusa o ruleset se as
  ocorrências diferem em ação ou protocolo, como o Snort também recusa.
- Registra tudo o que foi removido no `proveniencia.json`.

Variável que o perfil não define deixa o predicado UNASSESSED, e a validação
recusa o manifesto. O Snort 3 também recusa a regra. Rulesets do Snort 2
usam, por exemplo, `$SHELLCODE_PORTS` e `$AIM_SERVERS`.

Os caminhos vêm de `SNORT_P4_RULESET`, `SNORT_P4_VARIABLES` e
`SNORT_P4_OUTPUT_DIR` (`compiler/paths.py`). Ruleset ou perfil diferente do
padrão com saída em `output/` é recusado antes de qualquer escrita, porque ali
estão os artefatos congelados. Com o ruleset e o perfil padrão, o executor
reproduz esses artefatos byte a byte. Com `--perfil controlled`, as entradas
P4 saem idênticas às do snapshot congelado desse perfil.

### Semântica de cabeçalho de regras service-based

No Snort 3, quando o serviço identificado no fluxo é um dos da regra, porta
e protocolo do cabeçalho não são checados (os endereços são). O manifesto
tem dois modos:

    python compiler/generate_semantic_manifest.py                                   # snort3, padrão
    python compiler/generate_semantic_manifest.py --service-header-semantics legacy

O `snort3`, padrão desde 2026-10-05, delega porta e protocolo das regras
service-based (com `service:` ou com serviço dado por opção, como as DCE),
como o Snort 3 faz. O `legacy` trata o cabeçalho delas como o de uma regra
por porta e reproduz byte a byte os artefatos arquivados em
`output/historical/legacy_header_semantics/`, de que dependem os resultados
congelados anteriores à troca. No executor estático:
`python compiler/run_static_pipeline.py ... --semantica legacy`. Detalhes:
`paper/IDS_P4/SERVICE_BASED_HEADER_FINDING.md` e
`paper/IDS_P4/HEADER_SEMANTICS_DEFAULT_SUPERSESSION.md`.

### Campanha end-to-end

Snort como oráculo e BMv2 como alvo, uma testemunha sintetizada por regra:

    python tests/generate_campaign_cases.py --n 1000           # casos e pcap (qualquer máquina)
    python tests/precheck_campaign_offline.py --casos output/campaign/e2e_1000
    python tests/run_campaign_bmv2.py --casos output/campaign/e2e_1000   # no rig
    python tests/analyze_campaign_attribution.py --casos output/campaign/e2e_1000

`tests/generate_offport_service_cases.py` gera a variante com a testemunha
HTTP fora da porta do cabeçalho, que testa o ponto acima no data plane.

### Métricas de trace fora do rig

As métricas de trace são offline (parser espelhado do P4 e casador de
entradas) e rodam em qualquer máquina com a captura do CIC-IDS2017
(`output/datasets/cicids2017_thursday_metadata.json` registra origem, tamanho
e sha256). Sem scapy e sem editcap:

    python tests/cut_cicids2017_windows.py --bruto Thursday-WorkingHours.pcap --destino janelas/
    python tests/rederive_trace_metrics.py --janela sqli=janelas/thursday_web_sqli.pcap \
        --janela xss=janelas/thursday_web_xss.pcap --janela bruteforce=janelas/thursday_web_bruteforce.pcap
    python tests/rederive_alert_coverage_by_semantics.py --janela sqli=... --janela xss=... --janela bruteforce=...

O corte só é aceito se pacotes, bytes e extremos de cada janela baterem com o
registro. Os dois estágios seguintes só gravam se o `legacy`, lido de
`output/historical/legacy_header_semantics/`, reproduzir o congelado.

## Reprodutibilidade

Os artefatos em `output/` são reproduzíveis byte a byte a partir do código.
A verificação é comparar os dez artefatos gerados numa cópia isolada com os
versionados.

Os números dos manuscritos são conferidos contra esses artefatos por
`python tests/check_manuscript_numbers.py`, que lista qualquer número dos
`.tex` sem artefato que o sustente.

Os artefatos por perfil ficam em `output/profiles/<perfil>/`. Os logs de
proveniência são versionados; o dump de runtime do BMv2 e as capturas
`.pcap` não, por serem volumosos e regeneráveis.

No rig, `python tests/check_profile_vs_snort.py` confere que as variáveis
do compilador (`config/snort_variables.json`) são as mesmas, com os mesmos
valores, que o Snort usa com `config/snort3_experiment.lua`. O lado do
Snort vem do próprio `snort --dump-config-text`. Uma variável que o Snort
define e o perfil não faria o compilador recusar uma regra que o Snort
aceita. Os códigos de saída são 0 (coincidem), 1 (divergem) e 2 (sem Snort
nesta máquina).

## Documentação

| Arquivo | Conteúdo |
|---|---|
| `docs/semantic_model.md` | modelo semântico: classes, tratamentos, invariantes |
| `docs/snort3_support_matrix.md` | matriz de suporte da linguagem |
| `CODEX_HANDOFF.md` | estado do projeto, resultados congelados, pendências |
| `docs/review/` | auditorias |
| `paper/README.md` | as quatro versões do artigo, como derivam uma da outra, e as auditorias do manuscrito |

## Limitações conhecidas

`EXACT = 0` no ruleset avaliado: toda assinatura real carrega `content`,
`flow` ou `service`, que são delegados ao Snort. A categoria é alcançável,
apenas vazia neste dataset.

Para as 2.931 regras service-based (2.928 com `service:` e 3 cujas opções
DCE dão serviço), o Snort 3 não checa porta nem protocolo do cabeçalho
quando identifica o serviço. Desde 2026-10-05 o compilador mantém só os
endereços delas (sete ficam sem predicado seletivo e passam a UNSUPPORTED).
O custo é de seletividade: a maioria fica só com um endereço em
`HOME_NET`, o strong-discriminator mantém 739 regras elegíveis, e a redução
do conjunto de regras candidatas sobre o ruleset fica limitada a 18,40%. A
compilação anterior, que mantinha porta e protocolo, está arquivada em
`output/historical/legacy_header_semantics/`.

A partição strong-discriminator não é fechada sob flowbits: 24 arestas a
cruzam, todas no flowbit `smb.trans2`.

A avaliação usa um ruleset (snort3-community, 4.017 regras), um perfil e um
dataset (CIC-IDS2017). Não há medição de throughput, latência nem validação
em hardware — só BMv2.

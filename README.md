# Snort-p4

Tradução semântica de regras Snort 3 para um prefilter em P4.

O P4 atua como **marcador de candidatos** para o Snort, não como substituto.
O data plane classifica cada pacote em uma de três categorias e o Snort
continua fazendo a detecção; regras que o compilador não consegue
representar de forma conservadora continuam exigindo fallback.

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

- Roda as mesmas etapas do `build_profile`, da regra ao plano P4Runtime,
  com as variáveis do perfil ativo.
- Grava tudo em `--saida`, com um `proveniencia.json` que registra o ruleset
  (sha256 e número de regras), o commit, cada etapa e o sha256 de cada
  artefato.
- Não valida o ruleset no Snort nem compila o P4. O programa P4 não depende do
  ruleset e é copiado de `output/`.

Os caminhos vêm de `SNORT_P4_RULESET` e `SNORT_P4_OUTPUT_DIR`
(`compiler/paths.py`). Um ruleset diferente do padrão com saída em `output/`
é recusado antes de qualquer escrita, porque ali estão os artefatos
congelados. Com o ruleset padrão, o executor reproduz esses artefatos byte a
byte.

### Semântica de cabeçalho de regras service-based

No Snort 3, quando o serviço identificado no fluxo é um dos da regra, porta
e protocolo do cabeçalho não são checados (os endereços são). O manifesto
tem dois modos:

    python compiler/generate_semantic_manifest.py                                   # legacy, padrão
    python compiler/generate_semantic_manifest.py --service-header-semantics snort3

O `legacy` reproduz os artefatos congelados e trata o cabeçalho de uma regra
service-based (com `service:` ou com serviço dado por opção, como as DCE)
como o de uma regra por porta; o `snort3` delega porta e protocolo dessas
regras. O efeito sem tráfego fica em
`python tests/whatif_service_header_semantics.py`. Detalhes:
`paper/IDS_P4/SERVICE_BASED_HEADER_FINDING.md`.

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
registro. Os dois estágios seguintes só gravam se o `legacy` reproduzir o
congelado.

## Reprodutibilidade

Os artefatos em `output/` são reproduzíveis byte a byte a partir do código,
em qualquer plataforma. A verificação é comparar os dez artefatos gerados
numa cópia isolada com os versionados.

Os artefatos por perfil ficam em `output/profiles/<perfil>/`. Os logs de
proveniência são versionados; o dump de runtime do BMv2 e as capturas
`.pcap` não, por serem volumosos e regeneráveis.

## Documentação

| Arquivo | Conteúdo |
|---|---|
| `docs/semantic_model.md` | modelo semântico: classes, tratamentos, invariantes |
| `docs/snort3_support_matrix.md` | matriz de suporte da linguagem |
| `CODEX_HANDOFF.md` | estado do projeto, resultados congelados, pendências |
| `docs/review/` | auditorias |
| `paper/IDS_P4/` | manuscrito e auditorias do manuscrito |
| `paper/IDS_P4_PT/` | versão curta em português (IEEEtran), derivada do manuscrito |

## Limitações conhecidas

`EXACT = 0` no ruleset avaliado: toda assinatura real carrega `content`,
`flow` ou `service`, que são delegados ao Snort. A categoria é alcançável,
apenas vazia neste dataset.

Para as 2.931 regras service-based (2.928 com `service:` e 3 cujas opções
DCE dão serviço), o predicado congelado restringe porta e protocolo, que o
Snort 3 não checa quando identifica o serviço; ele só é condição necessária
no tráfego avaliado com o cabeçalho inteiro. O plano
global cobre essas regras pelas entradas sem porta; o strong-discriminator,
não.

A avaliação usa um ruleset (snort3-community, 4.017 regras), um perfil e um
dataset (CIC-IDS2017). Não há medição de throughput, latência nem validação
em hardware — só BMv2.

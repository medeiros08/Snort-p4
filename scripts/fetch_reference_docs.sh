#!/usr/bin/env bash
#
# Traz para o disco a documentacao normativa de Snort 3 e P4 que o agente
# consulta em vez de responder de memoria.
#
# O que este script faz e o que NAO faz:
#
#   FAZ    baixa, por sparse checkout raso, apenas as arvores de documentacao
#          de cinco repositorios upstream, cada um fixado num ref explicito,
#          e registra o commit resolvido em docs/vendor/MANIFEST.md.
#
#   NAO    nao instala toolchain, nao compila nada e nao toca em output/.
#          O corpus e material de leitura; nenhum estagio do pipeline depende
#          dele.
#
# Por que copia local e nao busca na web: uma afirmacao sobre semantica de
# opcao do Snort ou sobre um extern do v1model precisa sair de um arquivo com
# commit conhecido, citavel como caminho:linha. Pagina web nao da nem o commit
# nem a linha, e o manuscrito em paper/IDS_P4 afirma coisas sobre a linguagem
# que precisam de fonte verificavel.
#
# Por que ref fixo e nao HEAD: o branch default do p4c, do BMv2 e do
# P4Runtime esta a frente do toolchain que produziu os artefatos. Documentacao
# do tip descreve comportamento que o rig avaliado nao tinha, e citar isso no
# manuscrito e afirmar sobre um ambiente que nao foi medido. Os refs abaixo
# reproduzem o ambiente da secao de metodologia, nao o futuro dele.
#
# Por que sparse e --filter=blob:none: p4c e snort3 inteiros passam de 1 GB
# somados. Baixando so doc/ e p4include/ o corpus fica na casa de dezenas de
# MB. O diretorio docs/vendor/ e ignorado pelo git justamente porque e
# regeneravel por este script; o que fica versionado e o MANIFEST.
#
# Uso:
#   ./scripts/fetch_reference_docs.sh          # baixa, ou realinha ao pin
#   ./scripts/fetch_reference_docs.sh status   # so inspeciona, nao baixa
#
set -euo pipefail

# ------------------------------------------------------------------- fontes
# Cada linha: <nome local>|<url>|<ref fixo>|<caminhos sparse>|<por que este ref>
#
# O toolchain do rig esta registrado em paper/IDS_P4/main.tex (metodologia) e
# veio do ambiente WSL que produziu os artefatos:
#
#   Snort++              3.12.2.0
#   p4c                  1.2.4.2 (SHA 624c6be80, 2023-08-09)
#   simple_switch_grpc   1.15.0  (build 68f4a978, 2025-09-25)
#
# Os pins de p4c e BMv2 sao os SHAs exatos desses dois builds: o corpus passa
# a ser o codigo que de fato compilou o programa e rodou os pacotes.
#
# Os pins de spec sao escolha declarada, nao medicao. Nem a versao da spec
# P4_16 nem a do P4Runtime ficaram registradas no rig; a regra adotada e o
# ultimo release anterior ao build do componente correspondente, que e a
# linguagem que aquele binario tinha como alvo:
#
#   P4-16-v1.2.4 (2023-05-16) precede o build do p4c (2023-08-09)
#   p4runtime v1.4.1 (2024-10-21) precede o build do BMv2 (2025-09-25)
#
# Trocar um pin muda o que o agente le como normativo: mexer aqui e mexer na
# fonte das afirmacoes do manuscrito.
#
# Os caminhos foram escolhidos por conteudo:
#
#   snort3/doc            manual do usuario, referencia completa de opcoes de
#                         regra (doc/reference/snort_reference.text) e o guia
#                         de upgrade 2.x -> 3, que e onde a diferenca de
#                         semantica entre as duas geracoes esta escrita.
#   p4-spec/p4-16/spec    especificacao P4_16 em AsciiDoc mais a gramatica.
#   p4c/p4include         v1model.p4 e core.p4 de verdade: a fonte das
#                         assinaturas de extern que o backend gera.
#   p4c/docs              notas do compilador, incluindo limitacoes de alvo.
#   bmv2/docs             simple_switch.md, JSON_format.md, runtime_CLI.md.
#   bmv2/targets/...      implementacao do simple_switch: onde o comportamento
#                         real do alvo divergir da spec, divergiu aqui.
#   p4runtime/docs/v1     spec do P4Runtime e a orientacao de geracao de
#                         P4Info, que e o formato que install_p4runtime.py le.
#   p4runtime/proto       p4runtime.proto: contrato exato do canal gRPC.

SOURCES='
snort3|https://github.com/snort3/snort3.git|refs/tags/3.12.2.0|doc|tag da versao 3.12.2.0 validada no rig
p4-spec|https://github.com/p4lang/p4-spec.git|refs/tags/P4-16-v1.2.4|p4-16/spec|ultimo release de spec anterior ao build do p4c
p4c|https://github.com/p4lang/p4c.git|624c6be8076881e9af1e2f7d7691bc6c4416f4b1|p4include docs|build exato do p4c 1.2.4.2 do rig
bmv2|https://github.com/p4lang/behavioral-model.git|68f4a978f465fd76e98fcdecb762981843fb7310|docs targets/simple_switch|build exato do simple_switch_grpc 1.15.0 do rig
p4runtime|https://github.com/p4lang/p4runtime.git|refs/tags/v1.4.1|docs/v1 proto|ultimo release anterior ao build do BMv2
'

REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
VENDOR_DIR="$REPO_ROOT/docs/vendor"
MANIFEST="$VENDOR_DIR/MANIFEST.md"

MODE=${1:-fetch}

# ------------------------------------------------------------------- status
# Reporta divergencia entre o que esta no disco e o pin. Um corpus fora do pin
# nao e erro de execucao, e uma afirmacao que pode estar descrevendo outro
# ambiente — por isso a palavra DERIVA aparece explicita.

if [ "$MODE" = status ]; then
    if [ ! -d "$VENDOR_DIR" ]; then
        echo "corpus ausente: rode ./scripts/fetch_reference_docs.sh"
        exit 0
    fi
    echo "$SOURCES" | while IFS='|' read -r name url ref paths why; do
        [ -n "${name:-}" ] || continue
        dir="$VENDOR_DIR/$name"
        if [ ! -d "$dir/.git" ]; then
            printf '%-10s ausente\n' "$name"
            continue
        fi
        head=$(git -C "$dir" rev-parse HEAD)
        want=$(git -C "$dir" rev-parse "$ref" 2>/dev/null || echo "$ref")
        size=$(du -sh "$dir" 2>/dev/null | cut -f1)
        if [ "$head" = "$want" ]; then
            printf '%-10s %s  %-6s alinhado ao pin (%s)\n' "$name" "${head:0:12}" "$size" "${ref#refs/tags/}"
        else
            printf '%-10s %s  %-6s DERIVA: pin e %s\n' "$name" "${head:0:12}" "$size" "$ref"
        fi
    done
    exit 0
fi

if [ "$MODE" != fetch ]; then
    echo "uso: $0 [fetch|status]" >&2
    exit 2
fi

command -v git >/dev/null || { echo "git nao encontrado" >&2; exit 1; }

mkdir -p "$VENDOR_DIR"

# ------------------------------------------------------------------- fetch
# git init + fetch de um ref unico, em vez de clone: e o unico jeito de pegar
# um SHA solto (GitHub aceita fetch por SHA completo, nao por abreviado) com a
# mesma economia do clone raso. A config de sparse-checkout e escrita antes do
# primeiro checkout, para que nenhum blob fora das arvores pedidas seja baixado.

echo "$SOURCES" | while IFS='|' read -r name url ref paths why; do
    [ -n "${name:-}" ] || continue
    dir="$VENDOR_DIR/$name"

    if [ -d "$dir/.git" ] && [ "$(git -C "$dir" rev-parse HEAD 2>/dev/null)" = "$(git -C "$dir" rev-parse "$ref" 2>/dev/null)" ]; then
        echo "== $name: ja no pin"
    else
        if [ ! -d "$dir/.git" ]; then
            echo "== $name: baixando $ref"
            rm -rf "$dir"
            mkdir -p "$dir"
            git -C "$dir" init -q
            git -C "$dir" remote add origin "$url"
        else
            echo "== $name: realinhando ao pin $ref"
            git -C "$dir" remote set-url origin "$url"
        fi

        git -C "$dir" config core.sparseCheckout true
        git -C "$dir" config core.sparseCheckoutCone true
        {
            printf '/*\n!/*/\n'
            for p in $paths; do printf '/%s/\n' "${p%/}"; done
        } > "$dir/.git/info/sparse-checkout"

        # Pin por tag vira ref local (refspec espelhada), para que a acao
        # status consiga resolver o pin e comparar. Sem isso o rev-parse do
        # ref falha, o status cai no literal e reporta DERIVA em corpus que
        # esta correto — um alarme falso pior que nenhum alarme.
        case "$ref" in
            refs/*) git -C "$dir" fetch -q --depth 1 --filter=blob:none origin "+$ref:$ref" ;;
            *)      git -C "$dir" fetch -q --depth 1 --filter=blob:none origin "$ref" ;;
        esac
        git -C "$dir" checkout -q --detach "$(git -C "$dir" rev-parse "$ref" 2>/dev/null || echo FETCH_HEAD)"
    fi
done

# ---------------------------------------------------------------- manifesto
# O manifesto e versionado e serve a mesma funcao dos logs de proveniencia em
# output/: dizer de qual commit saiu cada afirmacao citada, e por que aquele
# commit. Sem ele, "a spec diz X" nao e verificavel seis meses depois.

{
    echo "# Vendored reference corpus"
    echo
    echo "Gerado por \`scripts/fetch_reference_docs.sh\` em $(date -u +%Y-%m-%dT%H:%M:%SZ)."
    echo
    echo "O corpus em si nao e versionado (regeneravel). Este manifesto e,"
    echo "porque fixa o commit de onde cada citacao de documentacao saiu."
    echo
    echo "Os pins reproduzem o toolchain da secao de metodologia — Snort++"
    echo "3.12.2.0, p4c 1.2.4.2 (SHA 624c6be80), simple_switch_grpc 1.15.0"
    echo "(build 68f4a978) — e nao o branch default de cada projeto, que esta"
    echo "a frente do ambiente avaliado."
    echo
    echo "| Fonte | Pin | Commit resolvido | Data do commit | Arvores | Por que este ref |"
    echo "|---|---|---|---|---|---|"
    echo "$SOURCES" | while IFS='|' read -r name url ref paths why; do
        [ -n "${name:-}" ] || continue
        dir="$VENDOR_DIR/$name"
        [ -d "$dir/.git" ] || continue
        sha=$(git -C "$dir" rev-parse HEAD)
        when=$(git -C "$dir" log -1 --format=%cI)
        echo "| [$name]($url) | \`${ref#refs/tags/}\` | \`${sha:0:12}\` | $when | \`$paths\` | $why |"
    done
} > "$MANIFEST"

echo
echo "corpus em docs/vendor/ ; manifesto em docs/vendor/MANIFEST.md"
du -sh "$VENDOR_DIR" 2>/dev/null | cut -f1 | sed 's/^/tamanho total: /'

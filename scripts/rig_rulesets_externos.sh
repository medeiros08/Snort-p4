#!/usr/bin/env bash
#
# Recria, no rig, os rulesets externos do teste de robustez do compilador
# (CODEX_HANDOFF.md §18; tests/analyze_external_rulesets.py os compila).
#
#   snort2_ubuntu             /etc/snort/rules/*.rules do pacote
#                             snort-rules-default do Ubuntu (Snort 2.9),
#                             concatenados em ordem de nome, sintaxe Snort 2
#   snort2_ubuntu_convertido  o mesmo, convertido pelo snort2lua da
#                             instalacao do Snort 3
#   snort3_sensitive_data     sensitive_data.rules da instalacao do Snort 3
#   snort3_file_magic         file_magic.rules da instalacao do Snort 3
#
# Nao precisa de root. Grava em <destino> (padrao: o diretorio de datasets da
# maquina Windows) os quatro .rules e um MANIFESTO.txt com versao do pacote,
# sha256 de cada arquivo e o relatorio de erros do snort2lua.
#
# Uso (no rig):
#   ./scripts/rig_rulesets_externos.sh [destino]
#
set -euo pipefail

DESTINO="${1:-/mnt/c/Users/amede/datasets/rulesets}"
SNORT3="${SNORT3:-$HOME/snort3-install}"
ORIGEM_SNORT2=/etc/snort/rules

[[ -d "$ORIGEM_SNORT2" ]] || { echo "ERRO: $ORIGEM_SNORT2 ausente (pacote snort-rules-default)." >&2; exit 1; }
[[ -x "$SNORT3/bin/snort2lua" ]] || { echo "ERRO: snort2lua ausente em $SNORT3/bin." >&2; exit 1; }

mkdir -p "$DESTINO"
export LD_LIBRARY_PATH="$SNORT3/lib:${LD_LIBRARY_PATH:-}"

# Ordem de nome fixa, para o arquivo concatenado ser sempre o mesmo.
find "$ORIGEM_SNORT2" -maxdepth 1 -name '*.rules' -print0 | sort -z | xargs -0 cat > "$DESTINO/snort2_ubuntu.rules"

# O snort2lua sai com codigo diferente de zero quando alguma regra nao
# converte; o que nao converteu fica comentado na saida e listado em
# snort2lua_erros.txt, entao o codigo nao interrompe o script.
( cd "$DESTINO" && "$SNORT3/bin/snort2lua" -c snort2_ubuntu.rules \
    -r snort2_ubuntu_convertido.rules -o /dev/null -e snort2lua_erros.txt >/dev/null 2>&1 ) || true

cp "$SNORT3/etc/snort/sensitive_data.rules" "$DESTINO/snort3_sensitive_data.rules"
cp "$SNORT3/etc/snort/file_magic.rules" "$DESTINO/snort3_file_magic.rules"

{
    echo "gerado_em=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "pacote=$(dpkg-query -W -f='${Package} ${Version}' snort-rules-default 2>/dev/null || echo desconhecido)"
    echo "arquivos_snort2=$(find "$ORIGEM_SNORT2" -maxdepth 1 -name '*.rules' | wc -l)"
    echo "snort3=$("$SNORT3/bin/snort" -V 2>&1 | grep -o 'Version [0-9.]*' | head -1)"
    for arquivo in snort2_ubuntu snort2_ubuntu_convertido snort3_sensitive_data snort3_file_magic; do
        echo "sha256.$arquivo=$(sha256sum "$DESTINO/$arquivo.rules" | cut -d' ' -f1)"
    done
} > "$DESTINO/MANIFESTO.txt"

cat "$DESTINO/MANIFESTO.txt"

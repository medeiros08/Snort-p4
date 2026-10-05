#!/usr/bin/env bash
#
# Fase B da troca do padrao do compilador para snort3
# (paper/IDS_P4/HEADER_SEMANTICS_DEFAULT_SUPERSESSION.md §6): refaz no BMv2,
# com os planos snort3, as medicoes que hoje sao do plano legacy.
#
#   controlados  os 11 casos do dominio de pacotes e os casos de flags TCP,
#                com o plano global snort3 (235 entradas)
#   replays      contabilidade dos replays com envio dos bytes exatos, nos
#                dois planos snort3 (global 235, strong 225): pacotes de
#                alerta das tres janelas e as tres janelas inteiras
#                (~1 h por plano; o Brute Force sozinho leva ~50 min)
#   campanhas    e2e_1000_v4 e servico_fora_do_cabecalho nos dois planos
#                snort3, com as particoes que mandam as UNSUPPORTED para
#                fallback (output/campaign/particoes_snort3/)
#
# Nada aqui sobrescreve resultado legacy:
#
#   controlados  output/analysis/fase_b_snort3/controlados/ e
#                output/analysis/ipv4_packet_domain_guard_test_snort3.json
#   replays      output/analysis/replay_snort3/{global,strong}/
#   campanhas    arquivos com sufixo _snort3 e _strong_snort3 nos diretorios
#                das campanhas
#
# Os esperados offline ja estao gravados:
#   replays      output/analysis/replay_expected_snort3.json
#   campanhas    precheque*_snort3.json e precheque*_strong_snort3.json
#
# Uso (no rig, na raiz do repositorio; cada etapa pode rodar sozinha):
#   sudo ./scripts/rig_fase_b_snort3.sh controlados
#   sudo ./scripts/rig_fase_b_snort3.sh replays_global
#   sudo ./scripts/rig_fase_b_snort3.sh replays_strong
#   sudo ./scripts/rig_fase_b_snort3.sh campanhas
#   sudo ./scripts/rig_fase_b_snort3.sh tudo
#
set -euo pipefail

RAIZ="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$RAIZ"

[[ ${EUID} -eq 0 ]] || { echo "ERRO: rode com sudo." >&2; exit 1; }

USUARIO="${SUDO_USER:-$(logname 2>/dev/null || echo root)}"
LAR="$(getent passwd "$USUARIO" | cut -d: -f6)"
PY="${PY:-$LAR/.venvs/p4runtime/bin/python}"
[[ -x "$PY" ]] || { echo "ERRO: python do venv nao encontrado em $PY (defina PY=...)." >&2; exit 1; }
export PY

GLOBAL="$RAIZ/output/p4runtime_install_plan.json"
STRONG="$RAIZ/output/campaign/plano_strong_discriminator_snort3/p4runtime_install_plan.json"
PARTICOES="$RAIZ/output/campaign/particoes_snort3"
SAIDA="$RAIZ/output/analysis/fase_b_snort3"

grep -q '"service_header_semantics": "snort3"' output/semantic_manifest.json \
  || { echo "ERRO: output/semantic_manifest.json nao e a compilacao snort3." >&2; exit 1; }
for exigido in "$GLOBAL" "$STRONG" "$PARTICOES/global.json" "$PARTICOES/strong.json"; do
  [[ -f "$exigido" ]] || { echo "ERRO: ausente: $exigido" >&2; exit 1; }
done

switch_novo() {
  local plano="$1" log="$2"
  ./scripts/setup_bmv2.sh down > /dev/null 2>&1 || true
  ./scripts/setup_bmv2.sh up > /dev/null 2>&1
  for iface in veth0 veth1 veth2 veth3; do
    ip link set dev "$iface" txqueuelen 10000
  done
  "$PY" compiler/install_p4runtime.py --plan "$plano" > "$log" 2>&1
}

controlados() {
  local d="$SAIDA/controlados"
  mkdir -p "$d"
  echo; echo "=== controlados (plano global snort3)"
  switch_novo "$GLOBAL" "$d/install_guarda.log"
  local s=0
  "$PY" tests/test_ipv4_packet_domain_guard.py > "$d/guarda.log" 2>&1 || s=$?
  echo "  dominio de pacotes: codigo de saida $s"
  switch_novo "$GLOBAL" "$d/install_flags.log"
  s=0
  "$PY" tests/test_tcp_flag_lowering.py > "$d/flags.log" 2>&1 || s=$?
  echo "  flags TCP:          codigo de saida $s"
  chown -R "$USUARIO" "$d" output/analysis/ipv4_packet_domain_guard_test_snort3.json 2>/dev/null || true
}

replays() {
  local nome="$1" plano="$2"
  echo; echo "=== replays, plano $nome"
  PLANO="$plano" SAIDA="$RAIZ/output/analysis/replay_snort3/$nome" ./scripts/rig_replay_pos_correcao.sh alertas
  PLANO="$plano" SAIDA="$RAIZ/output/analysis/replay_snort3/$nome" ./scripts/rig_replay_pos_correcao.sh janelas
}

campanhas() {
  local nome plano particao sufixo campanha s
  for nome in global strong; do
    if [[ $nome == global ]]; then plano="$GLOBAL"; sufixo=_snort3; else plano="$STRONG"; sufixo=_strong_snort3; fi
    particao="$PARTICOES/$nome.json"
    for campanha in e2e_1000_v4 servico_fora_do_cabecalho; do
      echo; echo "=== campanha $campanha, plano $nome"
      mkdir -p "$SAIDA/campanhas"
      switch_novo "$plano" "$SAIDA/campanhas/install_${campanha}_${nome}.log"
      s=0
      "$PY" tests/run_campaign_bmv2.py --casos "output/campaign/$campanha" \
        --plano "$plano" --particao "$particao" --sufixo "$sufixo" \
        > "$SAIDA/campanhas/${campanha}_${nome}.log" 2>&1 || s=$?
      echo "  codigo de saida $s (1 = alguma VIOLACAO; ver o relatorio)"
      tail -n 12 "$SAIDA/campanhas/${campanha}_${nome}.log"
      chown -R "$USUARIO" "output/campaign/$campanha" "$SAIDA" 2>/dev/null || true
    done
  done
}

case "${1:-}" in
  controlados)     controlados ;;
  replays_global)  replays global "$GLOBAL" ;;
  replays_strong)  replays strong "$STRONG" ;;
  campanhas)       campanhas ;;
  tudo)            controlados; replays global "$GLOBAL"; replays strong "$STRONG"; campanhas ;;
  *)
    echo "uso: sudo $0 controlados|replays_global|replays_strong|campanhas|tudo" >&2
    exit 1
    ;;
esac

./scripts/setup_bmv2.sh down > /dev/null 2>&1 || true
echo
echo "Pronto. Avise para a analise na maquina Windows."

#!/usr/bin/env bash
#
# Medicoes no BMv2 com o programa corrigido (dominio de pacotes de 2026-09-01)
# que faltam para a submissao: CODEX_HANDOFF.md §15, item 3.
#
#   alertas     os pacotes de alerta das tres janelas (150 / 528 / 2.391),
#               medidos antes no BMv2 so com o programa pre-correcao e com
#               sendp do scapy
#   bruteforce  a janela Brute Force inteira (1.108.658 quadros), para trocar
#               o ACCOUNTING_PARTIAL (87 quadros perdidos) por contabilidade
#               exata
#
# Protocolo do §11 do handoff, igual ao das rodadas SQLi e XSS que fecharam:
#
#   1. switch novo e plano de 331 entradas instalado (a instalacao zera os
#      tres contadores)
#   2. auditoria de ociosidade: contadores em t0 e t1, com 10 s entre eles;
#      o delta tem de ser zero
#   3. contadores antes do envio, replay dos bytes capturados com
#      tests/replay_pcap_raw.py (AF_PACKET, sem reserializar), espera para o
#      switch drenar, contadores depois
#
# Nada e medido por valor absoluto: tests/analyze_replay_pos_correcao.py, que
# roda depois na maquina Windows, le os deltas e fecha
#
#   quadros enviados == P4_CANDIDATE + P4_NO_MATCH + PACKET_DOMAIN_FALLBACK
#
# Os 87 quadros perdidos da rodada anterior foram atribuidos a descarte na
# fila da veth a ~789 quadros/s. Esta rodada sobe txqueuelen para 10000 nas
# quatro veth e usa intervalo de 2 ms entre quadros no Brute Force (~40 a
# 60 min).
#
# Saida em output/analysis/replay_pos_correcao/<medicao>/, um diretorio novo:
# os replays congelados em output/analysis/ipv4_packet_domain_correction/
# nao sao tocados.
#
# Uso (no rig, na raiz do repositorio):
#   sudo ./scripts/rig_replay_pos_correcao.sh alertas
#   sudo ./scripts/rig_replay_pos_correcao.sh bruteforce
#   sudo ./scripts/rig_replay_pos_correcao.sh tudo
#
set -euo pipefail

RAIZ="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$RAIZ"

[[ ${EUID} -eq 0 ]] || { echo "ERRO: rode com sudo (cria veth e envia por AF_PACKET)." >&2; exit 1; }

USUARIO="${SUDO_USER:-$(logname 2>/dev/null || echo root)}"
LAR="$(getent passwd "$USUARIO" | cut -d: -f6)"
PY="${PY:-$LAR/.venvs/p4runtime/bin/python}"
[[ -x "$PY" ]] || { echo "ERRO: python do venv nao encontrado em $PY (defina PY=...)." >&2; exit 1; }

SAIDA="$RAIZ/output/analysis/replay_pos_correcao"
JANELAS="${JANELAS:-/mnt/c/Users/amede/datasets/cicids2017/windows}"
TXQUEUELEN=10000
OCIOSIDADE=10
DRENAGEM=10

registrar_ambiente() {
  local destino="$1" pcap="$2" intervalo="$3"
  {
    echo "gerado_em=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "commit=$(git -C "$RAIZ" rev-parse HEAD 2>/dev/null || echo desconhecido)"
    echo "pcap=$pcap"
    echo "pcap_sha256=$(sha256sum "$pcap" | cut -d' ' -f1)"
    echo "programa_sha256=$(sha256sum output/ids_prefilter.json | cut -d' ' -f1)"
    echo "p4info_sha256=$(sha256sum output/ids_prefilter.p4info.txt | cut -d' ' -f1)"
    echo "plano_sha256=$(sha256sum output/p4runtime_install_plan.json | cut -d' ' -f1)"
    echo "intervalo_s=$intervalo"
    echo "txqueuelen=$TXQUEUELEN"
    echo "ociosidade_s=$OCIOSIDADE"
    echo "drenagem_s=$DRENAGEM"
  } > "$destino/ambiente.txt"
}

contadores() {
  "$PY" compiler/read_prefilter_counters.py > "$1"
}

medir() {
  local nome="$1" pcap="$2" intervalo="$3"
  local destino="$SAIDA/$nome"

  [[ -f "$pcap" ]] || { echo "ERRO: pcap ausente: $pcap" >&2; exit 1; }
  mkdir -p "$destino"

  echo
  echo "=== $nome: $(basename "$pcap"), intervalo ${intervalo}s"

  ./scripts/setup_bmv2.sh down > "$destino/setup_down.log" 2>&1 || true
  ./scripts/setup_bmv2.sh up > "$destino/setup_up.log" 2>&1
  for iface in veth0 veth1 veth2 veth3; do
    ip link set dev "$iface" txqueuelen "$TXQUEUELEN"
  done

  "$PY" compiler/install_p4runtime.py > "$destino/install.log" 2>&1
  registrar_ambiente "$destino" "$pcap" "$intervalo"

  contadores "$destino/idle_t0.txt"
  sleep "$OCIOSIDADE"
  contadores "$destino/idle_t1.txt"

  contadores "$destino/before.txt"
  "$PY" tests/replay_pcap_raw.py "$pcap" --interface veth1 --inter "$intervalo" \
    > "$destino/sender.txt" 2> "$destino/sender.stderr"
  sleep "$DRENAGEM"
  contadores "$destino/after.txt"

  tail -n 2 "$destino/sender.txt"
  chown -R "$USUARIO" "$destino" 2>/dev/null || true
}

alertas() {
  for janela in sqli xss bruteforce; do
    medir "alertas_$janela" \
      "output/experiments/cicids2017_thursday_$janela/candidate_alert_packets.pcap" 0.02
  done
}

bruteforce() {
  medir "bruteforce_janela" "$JANELAS/thursday_web_bruteforce.pcap" 0.002
}

case "${1:-}" in
  alertas)    alertas ;;
  bruteforce) bruteforce ;;
  tudo)       alertas; bruteforce ;;
  *)
    echo "uso: sudo $0 alertas|bruteforce|tudo" >&2
    exit 1
    ;;
esac

./scripts/setup_bmv2.sh down > /dev/null 2>&1 || true
echo
echo "Pronto. Na maquina Windows: python tests/analyze_replay_pos_correcao.py"

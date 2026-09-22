#!/usr/bin/env bash
#
# Sobe (ou derruba) o alvo BMv2 usado pelos experimentos.
#
# O que este script faz e o que NAO faz:
#
#   FAZ    cria os pares veth com MTU 65535, desliga o IPv6 neles e sobe o
#          simple_switch_grpc com o programa P4 ja compilado.
#
#   NAO    nao compila o P4 (quem faz isso e compiler/build_profile.py, que
#          invoca p4c-bm2-ss) e nao instala as entradas na tabela (quem faz
#          isso e compiler/install_p4runtime.py).
#
# Por que MTU 65535: o replay escreve quadros grandes no par veth; com a MTU
# padrao de 1500 o envio falha com EMSGSIZE e o experimento perde pacotes sem
# avisar.
#
# Por que desligar o IPv6: a pilha do kernel emite router solicitation e
# multicast nas interfaces recem-criadas. Esses quadros entram no switch, sao
# contados pelos contadores do plano de dados e contaminam as taxas medidas.
#
# Uso:
#   sudo ./scripts/setup_bmv2.sh up       # cria as veth e sobe o switch
#   sudo ./scripts/setup_bmv2.sh down     # mata o switch e remove as veth
#        ./scripts/setup_bmv2.sh status   # so inspeciona, nao precisa de root
#
set -euo pipefail

# ---------------------------------------------------------------- parametros
# Estes valores sao os documentados em CODEX_HANDOFF.md para o rig avaliado.
# Mudar qualquer um deles invalida a comparacao com os artefatos congelados.

DEVICE_ID=0
GRPC_ADDR=127.0.0.1
GRPC_PORT=9559
MTU=65535

# port 0 -> veth0, port 1 -> veth2. O replay costuma usar veth1, que e o par
# de veth0, de modo que o que se escreve em veth1 entra no switch pela porta 0.
PORT0_IF=veth0
PORT0_PEER=veth1
PORT1_IF=veth2
PORT1_PEER=veth3

RAIZ="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
JSON_PADRAO="$RAIZ/output/ids_prefilter.json"
PID_FILE=/tmp/bmv2_simple_switch_grpc.pid
LOG_FILE=/tmp/bmv2_simple_switch_grpc.log

JSON="${BMV2_JSON:-$JSON_PADRAO}"

# ------------------------------------------------------------------ utilidade

erro() { printf '\nERRO: %s\n' "$*" >&2; exit 1; }
info() { printf '  %s\n' "$*"; }

exige_root() {
  if [[ ${EUID} -ne 0 ]]; then
    erro "'$1' precisa de root (cria interfaces de rede). Use: sudo $0 $1"
  fi
}

# /proc/<pid> e nao `kill -0`: o switch sobe sob sudo e pertence a root, e
# `kill -0` de um usuario comum num processo de root falha com EPERM. A acao
# status, que roda sem root, concluia "parado" com o switch no ar e o
# P4Runtime respondendo. /proc/<pid> existe independente do dono.
switch_vivo() {
  [[ -f "$PID_FILE" ]] && [[ -d "/proc/$(cat "$PID_FILE")" ]]
}

# ------------------------------------------------------------------- criar

cria_par() {
  local a="$1" b="$2"

  if ip link show "$a" >/dev/null 2>&1; then
    info "$a e $b ja existem, mantendo"
  else
    ip link add name "$a" type veth peer name "$b"
    info "criado o par $a <-> $b"
  fi

  local iface
  for iface in "$a" "$b"; do
    ip link set dev "$iface" up
    ip link set dev "$iface" mtu "$MTU"

    # Silencia a pilha IPv6 nesta interface para que router solicitation e
    # multicast nao entrem no switch e nao sejam contados.
    sysctl -q -w "net.ipv6.conf.${iface}.disable_ipv6=1" 2>/dev/null || true
    sysctl -q -w "net.ipv6.conf.${iface}.autoconf=0"     2>/dev/null || true
    sysctl -q -w "net.ipv6.conf.${iface}.accept_ra=0"    2>/dev/null || true
  done
}

acao_up() {
  exige_root up

  command -v simple_switch_grpc >/dev/null 2>&1 \
    || erro "simple_switch_grpc nao esta no PATH. Instale o pacote p4lang-bmv2."

  [[ -f "$JSON" ]] \
    || erro "programa P4 compilado nao encontrado em:
       $JSON

  Gere-o antes com:
       python3 compiler/build_profile.py cicids2017

  Ou aponte outro arquivo com a variavel BMV2_JSON."

  if switch_vivo; then
    erro "ja existe um simple_switch_grpc rodando (pid $(cat "$PID_FILE")).
  Derrube antes com: sudo $0 down"
  fi

  echo
  echo "Interfaces"
  cria_par "$PORT0_IF" "$PORT0_PEER"
  cria_par "$PORT1_IF" "$PORT1_PEER"

  echo
  echo "Switch"
  info "programa    $JSON"
  info "device-id   $DEVICE_ID"
  info "P4Runtime   $GRPC_ADDR:$GRPC_PORT"
  info "porta 0     $PORT0_IF   (o replay escreve em $PORT0_PEER)"
  info "porta 1     $PORT1_IF"

  nohup simple_switch_grpc \
    --device-id "$DEVICE_ID" \
    -i "0@${PORT0_IF}" \
    -i "1@${PORT1_IF}" \
    --log-console \
    "$JSON" \
    -- --grpc-server-addr "${GRPC_ADDR}:${GRPC_PORT}" \
    >"$LOG_FILE" 2>&1 &

  echo $! >"$PID_FILE"

  # O gRPC leva um instante para abrir a porta. Espera ativa curta em vez de
  # sleep fixo: falhar rapido e melhor que declarar sucesso cedo demais.
  local tentativa
  for tentativa in $(seq 1 25); do
    if ! kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
      echo
      tail -n 15 "$LOG_FILE" >&2
      rm -f "$PID_FILE"
      erro "o switch morreu ao subir. Log acima, completo em $LOG_FILE"
    fi

    if (exec 3<>"/dev/tcp/${GRPC_ADDR}/${GRPC_PORT}") 2>/dev/null; then
      exec 3>&- 2>/dev/null || true
      echo
      info "no ar em ${GRPC_ADDR}:${GRPC_PORT} (pid $(cat "$PID_FILE"))"
      echo
      echo "Proximo passo: instalar as entradas na tabela"
      echo "    python3 compiler/install_p4runtime.py"
      echo
      return 0
    fi
    sleep 0.4
  done

  echo
  tail -n 15 "$LOG_FILE" >&2
  erro "o processo subiu mas a porta ${GRPC_PORT} nao abriu em 10s.
  Log completo em $LOG_FILE"
}

# ------------------------------------------------------------------- derrubar

acao_down() {
  exige_root down

  echo
  echo "Switch"
  if switch_vivo; then
    local pid
    pid="$(cat "$PID_FILE")"
    kill "$pid" 2>/dev/null || true

    local tentativa
    for tentativa in $(seq 1 20); do
      kill -0 "$pid" 2>/dev/null || break
      sleep 0.25
    done
    kill -9 "$pid" 2>/dev/null || true

    info "encerrado (pid $pid)"
  else
    info "nao estava rodando"
  fi
  rm -f "$PID_FILE"

  echo
  echo "Interfaces"
  # Remover uma ponta remove o par inteiro.
  local iface
  for iface in "$PORT0_IF" "$PORT1_IF"; do
    if ip link show "$iface" >/dev/null 2>&1; then
      ip link delete "$iface"
      info "removido o par de $iface"
    else
      info "$iface nao existia"
    fi
  done
  echo
}

# ------------------------------------------------------------------- estado

acao_status() {
  echo
  echo "Interfaces"
  local iface achou=0
  for iface in "$PORT0_IF" "$PORT0_PEER" "$PORT1_IF" "$PORT1_PEER"; do
    if ip link show "$iface" >/dev/null 2>&1; then
      local mtu estado
      mtu="$(cat "/sys/class/net/${iface}/mtu" 2>/dev/null || echo '?')"
      estado="$(cat "/sys/class/net/${iface}/operstate" 2>/dev/null || echo '?')"
      printf '  %-8s %-8s mtu %s' "$iface" "$estado" "$mtu"
      [[ "$mtu" == "$MTU" ]] || printf '   <- esperado %s' "$MTU"
      printf '\n'
      achou=1
    else
      printf '  %-8s ausente\n' "$iface"
    fi
  done
  [[ $achou -eq 1 ]] || info "(nenhuma criada; rode 'sudo $0 up')"

  echo
  echo "Switch"
  if switch_vivo; then
    info "rodando, pid $(cat "$PID_FILE")"
  else
    info "parado"
  fi

  if (exec 3<>"/dev/tcp/${GRPC_ADDR}/${GRPC_PORT}") 2>/dev/null; then
    exec 3>&- 2>/dev/null || true
    info "P4Runtime responde em ${GRPC_ADDR}:${GRPC_PORT}"
  else
    info "P4Runtime NAO responde em ${GRPC_ADDR}:${GRPC_PORT}"
  fi

  echo
  echo "Programa P4"
  if [[ -f "$JSON" ]]; then
    info "$JSON"
  else
    info "ausente: $JSON"
    info "gere com: python3 compiler/build_profile.py cicids2017"
  fi
  echo
}

# ---------------------------------------------------------------------- main

case "${1:-}" in
  up)     acao_up ;;
  down)   acao_down ;;
  status) acao_status ;;
  *)
    cat <<'AJUDA'

  setup_bmv2.sh — sobe o alvo BMv2 dos experimentos

    sudo ./scripts/setup_bmv2.sh up       cria as veth e sobe o switch
    sudo ./scripts/setup_bmv2.sh down     derruba o switch e remove as veth
         ./scripts/setup_bmv2.sh status   inspeciona sem alterar nada

  Variavel de ambiente:
    BMV2_JSON   caminho do programa P4 compilado
                (padrao: output/ids_prefilter.json)

  Este script nao compila o P4 nem instala as entradas na tabela. Para o
  fluxo completo:

    python3 compiler/build_profile.py cicids2017   # compila tudo
    sudo ./scripts/setup_bmv2.sh up                # sobe o switch
    python3 compiler/install_p4runtime.py          # instala as entradas

AJUDA
    exit 1
    ;;
esac

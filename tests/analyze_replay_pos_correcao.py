#!/usr/bin/env python3
"""Fecha a contabilidade das medicoes de scripts/rig_replay_pos_correcao.sh.

Para cada medicao em output/analysis/replay_pos_correcao/<medicao>/ le os
contadores do BMv2 (idle_t0, idle_t1, before, after) e o numero de quadros
enviados (sender.txt), e decide:

    ACCOUNTING_VALID    ociosidade com delta zero, enviados == soma dos tres
                        deltas, e cada categoria igual ao valor offline
                        esperado
    ACCOUNTING_PARTIAL  ociosidade zero e categorias coerentes, mas a soma
                        dos deltas fica abaixo dos enviados (quadros perdidos
                        antes do switch); nenhum no-match inesperado
    INVALIDA            ociosidade com trafego, soma acima dos enviados, ou
                        categoria que contradiz o esperado

Esperados:

    alertas_*           output/analysis/alert_preservation_offline_post_correction.json
                        (offline_pos_correcao de cada janela)
    bruteforce_janela   classificador offline da janela inteira, pos-correcao:
                        1.101.459 candidatos, 0 no-match, 7.199 fallback
                        (REPLAY_ACCOUNTING_VALIDATION_XSS_BRUTEFORCE.md)

Grava output/analysis/replay_pos_correcao/resultado.json. Sai com 0 se toda
medicao presente for ACCOUNTING_VALID, 1 caso contrario.

Uso:
    python tests/analyze_replay_pos_correcao.py
"""

from __future__ import annotations

import json
import re
import sys

from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BASE = PROJECT_ROOT / "output" / "analysis" / "replay_pos_correcao"
OFFLINE_ALERTAS = PROJECT_ROOT / "output" / "analysis" / "alert_preservation_offline_post_correction.json"

CATEGORIAS = ("P4_CANDIDATE", "P4_NO_MATCH", "PACKET_DOMAIN_FALLBACK")

ESPERADO_BRUTEFORCE = {
    "P4_CANDIDATE": 1_101_459,
    "P4_NO_MATCH": 0,
    "PACKET_DOMAIN_FALLBACK": 7_199,
    "quadros": 1_108_658,
}


def ler_contadores(caminho: Path) -> dict[str, int]:
    """Os tres indices de read_prefilter_counters.py, na ordem do contador.

    A saida traz quatro blocos `Packets`: os indices 0, 1 e 2 e, por ultimo,
    `Totals`, a soma deles. Le os tres primeiros e confere o quarto contra a
    soma, para que uma mudanca de formato do leitor nao passe calada.
    """

    pacotes = [int(n) for n in re.findall(r"^Packets\s*:\s*(\d+)", caminho.read_text(), re.M)]
    if len(pacotes) != 4 or sum(pacotes[:3]) != pacotes[3]:
        raise ValueError(
            f"{caminho}: esperados os 3 indices e o total, lidos {pacotes}"
        )
    return dict(zip(CATEGORIAS, pacotes[:3]))


def delta(depois: dict, antes: dict) -> dict[str, int]:
    return {c: depois[c] - antes[c] for c in CATEGORIAS}


def ler_enviados(caminho: Path) -> int:
    achado = re.search(r"^Input packets:\s*(\d+)", caminho.read_text(), re.M)
    if not achado:
        raise ValueError(f"{caminho}: linha 'Input packets' ausente; o envio terminou?")
    return int(achado.group(1))


def ler_ambiente(caminho: Path) -> dict[str, str]:
    if not caminho.exists():
        return {}
    return dict(
        linha.split("=", 1) for linha in caminho.read_text().splitlines() if "=" in linha
    )


def esperados() -> dict[str, dict]:
    saida = {"bruteforce_janela": ESPERADO_BRUTEFORCE}
    offline = json.loads(OFFLINE_ALERTAS.read_text(encoding="utf-8"))
    for janela, dados in offline["janelas"].items():
        valores = dados["offline_pos_correcao"]
        saida[f"alertas_{janela}"] = {
            **{c: valores[c] for c in CATEGORIAS},
            "quadros": valores["pacotes"],
            "pcap_sha256": dados["pcap_sha256"],
        }
    return saida


def avaliar(nome: str, diretorio: Path, esperado: dict) -> dict:
    ambiente = ler_ambiente(diretorio / "ambiente.txt")
    ociosidade = delta(ler_contadores(diretorio / "idle_t1.txt"), ler_contadores(diretorio / "idle_t0.txt"))
    medido = delta(ler_contadores(diretorio / "after.txt"), ler_contadores(diretorio / "before.txt"))
    enviados = ler_enviados(diretorio / "sender.txt")
    soma = sum(medido.values())

    problemas = []
    if any(ociosidade.values()):
        problemas.append(f"ociosidade com trafego: {ociosidade}")
    if enviados != esperado["quadros"]:
        problemas.append(f"enviados {enviados} != populacao do pcap {esperado['quadros']}")
    if "pcap_sha256" in esperado and ambiente.get("pcap_sha256") not in (None, esperado["pcap_sha256"]):
        problemas.append("sha256 do pcap difere do usado na rederivacao offline")
    if soma > enviados:
        problemas.append(f"switch contou {soma} quadros, mais que os {enviados} enviados")
    if medido["P4_NO_MATCH"] > esperado["P4_NO_MATCH"]:
        problemas.append(f"no-match {medido['P4_NO_MATCH']} acima do esperado {esperado['P4_NO_MATCH']}")

    exato = soma == enviados and all(medido[c] == esperado[c] for c in CATEGORIAS)
    if problemas:
        status = "INVALIDA"
    elif exato:
        status = "ACCOUNTING_VALID"
    else:
        status = "ACCOUNTING_PARTIAL"

    return {
        "status": status,
        "enviados": enviados,
        "contados_pelo_switch": soma,
        "perdidos": enviados - soma,
        "medido": medido,
        "esperado_offline": {c: esperado[c] for c in CATEGORIAS},
        "ociosidade_delta": ociosidade,
        "problemas": problemas,
        "ambiente": ambiente,
    }


def main() -> int:
    if not BASE.is_dir():
        print(f"ERRO: {BASE} nao existe; rode antes scripts/rig_replay_pos_correcao.sh no rig")
        return 1

    alvo = esperados()
    resultado = {
        "analise": "replay_pos_correcao",
        "gerado_em": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "gerador": "tests/analyze_replay_pos_correcao.py",
        "medicoes": {},
    }

    for nome in sorted(alvo):
        diretorio = BASE / nome
        if not (diretorio / "after.txt").exists():
            print(f"  {nome:22s} ausente")
            continue
        try:
            avaliacao = avaliar(nome, diretorio, alvo[nome])
        except ValueError as erro:
            avaliacao = {"status": "INVALIDA", "problemas": [str(erro)]}
        resultado["medicoes"][nome] = avaliacao
        m = avaliacao.get("medido", {})
        print(
            f"  {nome:22s} {avaliacao['status']:19s} "
            f"enviados={avaliacao.get('enviados')} contados={avaliacao.get('contados_pelo_switch')} "
            f"cand={m.get('P4_CANDIDATE')} no-match={m.get('P4_NO_MATCH')} "
            f"fallback={m.get('PACKET_DOMAIN_FALLBACK')}"
        )
        for problema in avaliacao["problemas"]:
            print(f"      ! {problema}")

    (BASE / "resultado.json").write_text(
        json.dumps(resultado, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print(f"\n  {BASE / 'resultado.json'}")

    medidas = resultado["medicoes"].values()
    return 0 if medidas and all(m["status"] == "ACCOUNTING_VALID" for m in medidas) else 1


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Corta as tres janelas web do Thursday-WorkingHours.pcap e confere o corte.

As janelas das metricas de trace (SQLi, XSS, Brute Force) foram cortadas no
rig a partir da captura bruta do CICIDS2017. `output/datasets/cicids2017_thursday_metadata.json`
registra, para a captura e para cada janela, o numero de pacotes e a soma dos
bytes capturados, e para a captura o sha256. Este script le a captura uma vez,
em fluxo (`pcap_stream`), escreve cada janela como pcap classico e so aceita
o corte se os tres numeros baterem com o registro. Sem scapy, sem editcap.

Janela = pacotes com timestamp em [inicio, fim) do intervalo oficial, hora
local de 2017-07-06 em ADT (UTC-03:00), como no registro.

O pcap resultante nao tem o mesmo sha256 do arquivo do rig (formato classico,
nao pcapng); os quadros e timestamps sao os mesmos, e e isso que as metricas
leem. `tests/rederive_trace_metrics.py` confere ainda os valores congelados.

Codigos de saida:
    0   janelas gravadas e conferidas
    1   captura ausente ou corte diferente do registro

Uso:
    python tests/cut_cicids2017_windows.py --bruto Thursday-WorkingHours.pcap --destino DIR
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys

from datetime import datetime, timedelta, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "tests"))

from pcap_stream import EscritorPcap, quadros_com_tempo  # noqa: E402

METADADOS = PROJECT_ROOT / "output" / "datasets" / "cicids2017_thursday_metadata.json"
ADT = timezone(timedelta(hours=-3))
DIA = (2017, 7, 6)

# nome no registro -> nome em tests/rederive_trace_metrics.py
NOMES = {"web_sqli": "sqli", "web_xss": "xss", "web_bruteforce": "bruteforce"}


def intervalo_us(oficial: str) -> tuple[int, int]:
    """'09:20-10:00' -> [inicio, fim) em microssegundos desde a epoca."""

    def instante(hhmm: str) -> int:
        hora, minuto = (int(x) for x in hhmm.split(":"))
        momento = datetime(*DIA, hora, minuto, tzinfo=ADT)
        return int(momento.timestamp()) * 1_000_000

    inicio, fim = oficial.split("-")
    return instante(inicio), instante(fim)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--bruto", required=True, type=Path, help="Thursday-WorkingHours.pcap")
    parser.add_argument("--destino", required=True, type=Path, help="diretorio das janelas")
    argumentos = parser.parse_args()

    if not argumentos.bruto.exists():
        print(f"captura ausente: {argumentos.bruto}", file=sys.stderr)
        return 1
    registro = json.loads(METADADOS.read_text(encoding="utf-8"))
    argumentos.destino.mkdir(parents=True, exist_ok=True)

    janelas = []
    for janela in registro["windows"]:
        inicio, fim = intervalo_us(janela["official_interval"])
        nome = NOMES[janela["name"]]
        janelas.append(
            {
                "nome": nome,
                "inicio": inicio,
                "fim": fim,
                "registro": janela,
                "caminho": argumentos.destino / f"thursday_{janela['name']}.pcap",
                "pacotes": 0,
                "bytes": 0,
                "primeiro": None,
                "ultimo": None,
            }
        )

    escritores = {j["nome"]: EscritorPcap(j["caminho"]) for j in janelas}
    resumo = hashlib.sha256()
    total_pacotes = total_bytes = 0
    try:
        for tempo, quadro in quadros_com_tempo(argumentos.bruto, resumo):
            total_pacotes += 1
            total_bytes += len(quadro)
            for j in janelas:
                if j["inicio"] <= tempo < j["fim"]:
                    escritores[j["nome"]].escrever(tempo, quadro)
                    j["pacotes"] += 1
                    j["bytes"] += len(quadro)
                    j["primeiro"] = tempo if j["primeiro"] is None else min(j["primeiro"], tempo)
                    j["ultimo"] = tempo if j["ultimo"] is None else max(j["ultimo"], tempo)
            if total_pacotes % 1_000_000 == 0:
                print(f"  {total_pacotes:>9,} pacotes lidos", flush=True)
    finally:
        for escritor in escritores.values():
            escritor.fechar()

    def iso(us):
        return None if us is None else datetime.fromtimestamp(us / 1e6, ADT).isoformat()

    conferencia = {
        "captura": {
            "sha256": [resumo.hexdigest(), registro["raw_sha256"]],
            "pacotes": [total_pacotes, registro["packet_count"]],
            "bytes_capturados": [total_bytes, registro["captured_data_bytes"]],
        }
    }
    for j in janelas:
        conferencia[j["nome"]] = {
            "pacotes": [j["pacotes"], j["registro"]["packets"]],
            "bytes_capturados": [j["bytes"], j["registro"]["captured_data_bytes"]],
            "primeiro": [iso(j["primeiro"]), j["registro"]["capture_start"]],
            "ultimo": [iso(j["ultimo"]), j["registro"]["capture_end"]],
        }

    confere = all(
        valores[0] == valores[1]
        for chave, campos in conferencia.items()
        for campo, valores in campos.items()
        if campo not in ("primeiro", "ultimo")
    )
    relatorio = {
        "gerador": "tests/cut_cicids2017_windows.py",
        "gerado_em": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "registro": METADADOS.relative_to(PROJECT_ROOT).as_posix(),
        "criterio": "timestamp em [inicio, fim) do intervalo oficial, ADT",
        "status": "CONFERE" if confere else "DIVERGE",
        "conferencia": conferencia,
        "janelas": {j["nome"]: str(j["caminho"]) for j in janelas},
    }
    (argumentos.destino / "corte.json").write_text(
        json.dumps(relatorio, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )

    for chave, campos in conferencia.items():
        for campo, (obtido, esperado) in campos.items():
            marca = "" if obtido == esperado or campo in ("primeiro", "ultimo") else "  <- DIVERGE"
            print(f"{chave:<11} {campo:<17} {obtido}  (registro {esperado}){marca}")
    print(f"status {relatorio['status']}; janelas em {argumentos.destino}")
    if confere:
        argumento = " ".join(f"--janela {j['nome']}={j['caminho']}" for j in janelas)
        print(f"proximo: python tests/rederive_trace_metrics.py {argumento}")
    return 0 if confere else 1


if __name__ == "__main__":
    sys.exit(main())

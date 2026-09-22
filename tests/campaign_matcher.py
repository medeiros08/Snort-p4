#!/usr/bin/env python3
"""Casa quadro com entrada instalada, offline, reusando o casador do projeto.

Casa unica do acesso ao casador de referencia. Tanto o gerador de casos como
o pre-cheque precisam prever a categoria de um quadro antes de qualquer
execucao no rig, e um casador proprio em cada um deles poderia divergir do que
produziu os numeros de seletividade citados no manuscrito.

Os dois componentes reusados:

    tests/p4_packet_domain.py            espelha o parser do ids_prefilter.p4
    analyze_prefilter_selectivity.py     casador de entrada instalada

Predicao nao substitui medicao. O rig continua sendo quem observa o contador;
o que se obtem aqui e saber, antes de gastar ciclo de rig, se uma divergencia
observada sera do compilador ou do gerador de casos.
"""

from __future__ import annotations

import json
import sys
import types

from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "tests"))

ENTRADAS_INSTALADAS = PROJECT_ROOT / "output" / "p4_install_entries.json"

# analyze_prefilter_selectivity importa scapy no topo e aborta sem ela, mas o
# casador que se usa aqui e aritmetica pura sobre inteiros: nao toca em
# captura. Registrar um marcador para `scapy.utils` quando a scapy nao estiver
# instalada mantem o reuso do casador de referencia na maquina onde o
# repositorio vive, que nao tem scapy nem BMv2. O import real vem primeiro, de
# modo que no rig a scapy de verdade e usada.
try:  # pragma: no cover - depende do ambiente
    import scapy.utils  # noqa: F401
except ImportError:  # pragma: no cover
    _marcador = types.ModuleType("scapy")
    _marcador_utils = types.ModuleType("scapy.utils")
    _marcador_utils.RawPcapReader = None
    _marcador.utils = _marcador_utils
    sys.modules.setdefault("scapy", _marcador)
    sys.modules.setdefault("scapy.utils", _marcador_utils)

from analyze_prefilter_selectivity import (  # noqa: E402
    compile_entry,
    compiled_entry_matches_packet,
)
from p4_packet_domain import classify_frame_for_prefilter  # noqa: E402


def carregar_entradas(caminho: Path | None = None) -> list:
    """Compila as entradas instaladas para consulta repetida."""

    origem = caminho or ENTRADAS_INSTALADAS
    bruto = json.loads(origem.read_text(encoding="utf-8"))
    return [
        compile_entry(entrada, indice)
        for indice, entrada in enumerate(bruto["entries"])
    ]


def predizer(entradas: list, quadro: bytes) -> tuple[str, str]:
    """Devolve (categoria, detalhe) para um quadro Ethernet.

    Mesma decisao de `expected_classification` em
    tests/test_ipv4_packet_domain_guard.py: fora do dominio e fallback; dentro
    do dominio, casar qualquer entrada e candidate; nenhuma, no-match. O
    detalhe carrega a entrada que casou ou o motivo do parser.
    """

    pacote, motivo = classify_frame_for_prefilter(quadro)
    if pacote is None:
        return "PACKET_DOMAIN_FALLBACK", motivo
    for entrada in entradas:
        if compiled_entry_matches_packet(entrada, pacote):
            return "P4_CANDIDATE", entrada["id"]
    return "P4_NO_MATCH", motivo

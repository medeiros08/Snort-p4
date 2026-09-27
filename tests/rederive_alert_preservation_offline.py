#!/usr/bin/env python3
"""Rederiva offline a preservacao de pacotes de alerta sob o dominio imposto.

As colunas P4 da tabela de preservacao de alertas do manuscrito (150 / 528 /
2.391 candidatos, zero no-match) foram medidas no BMv2 antes da correcao do
dominio de pacotes IPv4 de 2026-09-01, e nao foram rederivadas depois
(`paper/IDS_P4/PARSER_DOMAIN_RECONCILIATION.md` §5, "Item requiring
attention"). O argumento de que nada muda — os 16 quadros reclassificados do
held-out continuam candidatos — e provavelmente correto, mas era argumento, nao
medicao.

Este estagio mede. Para cada janela, reclassifica os mesmos pacotes de alerta
(`candidate_alert_packets.pcap`) com os dois componentes de referencia que ja
sustentam os numeros de seletividade:

    tests/p4_packet_domain.py            espelha o parser corrigido do
                                         ids_prefilter.p4, gate de dominio
                                         incluido
    analyze_prefilter_selectivity.py     casador de entrada instalada

contra o plano de 331 entradas, e grava o resultado ao lado dos valores
congelados do BMv2, sem sobrescreve-los.

E rederivacao OFFLINE. Nao substitui o replay no data plane corrigido, que
continua dependendo do rig Linux; o que ela estabelece e que o classificador
de referencia, sob o dominio que o data plane agora impoe, da as mesmas
contagens.

Os pcaps de pacotes de alerta nao sao versionados; o sha256 de cada um fica
registrado no artefato de saida.

Codigos de saida:
    0   rederivacao gravada e igual aos valores congelados
    1   entrada ausente, ou alguma janela diverge dos valores congelados

Uso:
    python tests/rederive_alert_preservation_offline.py
"""

from __future__ import annotations

import hashlib
import json
import sys

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "tests"))

from campaign_matcher import ENTRADAS_INSTALADAS, carregar_entradas, predizer  # noqa: E402
from run_campaign_bmv2 import ler_pcap  # noqa: E402

EXPERIMENTOS = PROJECT_ROOT / "output" / "experiments"
SAIDA = PROJECT_ROOT / "output" / "analysis" / "alert_preservation_offline_post_correction.json"

JANELAS = {
    "sqli": "cicids2017_thursday_sqli",
    "xss": "cicids2017_thursday_xss",
    "bruteforce": "cicids2017_thursday_bruteforce",
}


def _sha256(caminho: Path) -> str:
    return hashlib.sha256(caminho.read_bytes()).hexdigest()


def _congelado(relatorio: dict) -> dict:
    """Le as contagens do BMv2 do report.json, cujas chaves variam por janela."""

    bloco = relatorio["p4_alert_preservation"]
    candidatos = bloco.get("p4_candidate_alert_packets", bloco.get("candidate_packets"))
    no_match = bloco.get("p4_no_match_alert_packets", bloco.get("no_match_packets"))
    pacotes = bloco.get("unique_candidate_alert_packets", bloco.get("unique_alert_packets"))
    return {"pacotes": pacotes, "P4_CANDIDATE": candidatos, "P4_NO_MATCH": no_match}


def main() -> int:
    entradas = carregar_entradas()
    janelas = {}
    divergentes = []

    for nome, diretorio in JANELAS.items():
        base = EXPERIMENTOS / diretorio
        pcap = base / "candidate_alert_packets.pcap"
        relatorio = base / "report.json"
        for caminho in (pcap, relatorio):
            if not caminho.exists():
                print(f"entrada ausente: {caminho}", file=sys.stderr)
                return 1

        quadros = ler_pcap(pcap)
        categorias = Counter(predizer(entradas, quadro)[0] for _s, _u, quadro in quadros)
        congelado = _congelado(json.loads(relatorio.read_text(encoding="utf-8")))

        offline = {
            "pacotes": len(quadros),
            "P4_CANDIDATE": categorias.get("P4_CANDIDATE", 0),
            "P4_NO_MATCH": categorias.get("P4_NO_MATCH", 0),
            "PACKET_DOMAIN_FALLBACK": categorias.get("PACKET_DOMAIN_FALLBACK", 0),
        }
        confere = all(offline[chave] == congelado[chave] for chave in congelado)
        if not confere:
            divergentes.append(nome)

        janelas[nome] = {
            "pcap": base.relative_to(PROJECT_ROOT).as_posix() + "/candidate_alert_packets.pcap",
            "pcap_sha256": _sha256(pcap),
            "bmv2_pre_correcao": congelado,
            "offline_pos_correcao": offline,
            "confere": confere,
        }

    relatorio_saida = {
        "analise": "alert_preservation_offline_post_correction",
        "entradas": {
            "caminho": ENTRADAS_INSTALADAS.relative_to(PROJECT_ROOT).as_posix(),
            "sha256": _sha256(ENTRADAS_INSTALADAS),
            "total": len(entradas),
        },
        "gerado_em": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "gerador": "tests/rederive_alert_preservation_offline.py",
        "janelas": janelas,
        "nota": (
            "Rederivacao offline com o classificador de referencia sob o dominio "
            "imposto; nao substitui replay no BMv2 corrigido."
        ),
        "status": "CONFERE" if not divergentes else "DIVERGE",
    }

    SAIDA.write_text(
        json.dumps(relatorio_saida, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )

    for nome, janela in janelas.items():
        print(
            f"{nome:<11} offline {janela['offline_pos_correcao']}  "
            f"bmv2 {janela['bmv2_pre_correcao']}  {'confere' if janela['confere'] else 'DIVERGE'}"
        )
    print(f"gravado em {SAIDA.relative_to(PROJECT_ROOT).as_posix()}")
    return 0 if not divergentes else 1


if __name__ == "__main__":
    sys.exit(main())

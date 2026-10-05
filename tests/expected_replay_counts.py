#!/usr/bin/env python3
"""Contagens esperadas dos replays no BMv2, por plano e por pcap.

Para cada medicao de scripts/rig_replay_pos_correcao.sh, o analisador
(tests/analyze_replay_pos_correcao.py) compara os deltas dos contadores com o
que o classificador offline preve para o mesmo pcap e o mesmo plano. Este
script grava essas previsoes para os planos da semantica snort3:

    janelas inteiras    lidas de output/analysis/trace_metrics_by_semantics.json
                        (secao snort3): candidato e no-match do plano global e
                        do strong, fallback = quadros - elegiveis
    pacotes de alerta   classificados aqui, quadro a quadro, com o espelho do
                        parser e o casador de entradas (tests/campaign_matcher.py)

Saida: output/analysis/replay_expected_snort3.json

Uso:
    python tests/expected_replay_counts.py
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

from campaign_matcher import carregar_entradas, predizer  # noqa: E402
from run_campaign_bmv2 import ler_pcap  # noqa: E402

METRICAS = PROJECT_ROOT / "output" / "analysis" / "trace_metrics_by_semantics.json"
SAIDA = PROJECT_ROOT / "output" / "analysis" / "replay_expected_snort3.json"
PLANOS = {
    "global": PROJECT_ROOT / "output" / "p4_install_entries.json",
    "strong": PROJECT_ROOT / "output" / "campaign" / "plano_strong_discriminator_snort3" / "p4_install_entries.json",
}
ALERTAS = {
    janela: PROJECT_ROOT / "output" / "experiments" / f"cicids2017_thursday_{janela}" / "candidate_alert_packets.pcap"
    for janela in ("sqli", "xss", "bruteforce")
}
CATEGORIAS = ("P4_CANDIDATE", "P4_NO_MATCH", "PACKET_DOMAIN_FALLBACK")


def _sha256(caminho: Path) -> str:
    return hashlib.sha256(caminho.read_bytes()).hexdigest()


def _rotulo(caminho: Path) -> str:
    return caminho.relative_to(PROJECT_ROOT).as_posix()


def main() -> int:
    metricas = json.loads(METRICAS.read_text(encoding="utf-8"))["snort3"]["janelas"]
    esperado: dict[str, dict] = {}

    for plano in PLANOS:
        for janela, w in metricas.items():
            fallback = w["quadros"] - w["elegiveis"]
            if plano == "global":
                cand, nm = w["global_candidatos"], w["elegiveis"] - w["global_candidatos"]
            else:
                cand, nm = w["strong_candidatos"], w["strong_no_match"]
            esperado[f"{plano}_janela_{janela}"] = {
                "P4_CANDIDATE": cand, "P4_NO_MATCH": nm, "PACKET_DOMAIN_FALLBACK": fallback,
                "quadros": w["quadros"], "fonte": _rotulo(METRICAS),
            }

    for plano, arquivo in PLANOS.items():
        entradas = carregar_entradas(arquivo)
        for janela, pcap in ALERTAS.items():
            contagem = Counter(predizer(entradas, quadro)[0] for _s, _u, quadro in ler_pcap(pcap))
            esperado[f"{plano}_alertas_{janela}"] = {
                **{c: contagem.get(c, 0) for c in CATEGORIAS},
                "quadros": sum(contagem.values()),
                "pcap_sha256": _sha256(pcap),
                "fonte": "classificador offline (tests/campaign_matcher.py)",
            }

    SAIDA.write_text(
        json.dumps(
            {
                "gerado_em": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "gerador": "tests/expected_replay_counts.py",
                "semantica_de_cabecalho": "snort3",
                "planos": {nome: {"entradas": _rotulo(p), "sha256": _sha256(p)} for nome, p in PLANOS.items()},
                "esperado": esperado,
            },
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
        newline="\n",
    )
    for nome, e in sorted(esperado.items()):
        print(f"  {nome:26s} quadros={e['quadros']:>9} cand={e['P4_CANDIDATE']:>9} "
              f"no-match={e['P4_NO_MATCH']:>7} fallback={e['PACKET_DOMAIN_FALLBACK']:>6}")
    print(f"gravado em {_rotulo(SAIDA)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Particoes de regras para as campanhas sob a semantica snort3.

O executor da campanha (tests/run_campaign_bmv2.py --particao) trata como
FALLBACK_OPERACIONAL todo caso cujo sid esteja em `sids_fallback_operacional`:
o Snort inspeciona a regra sem filtro, e o prefilter nao responde por ela.

As amostras das campanhas foram sorteadas entre regras NECESSARY sob a
semantica legacy. Sob snort3, sete delas passaram a UNSUPPORTED (1941, 28852,
29174, 38993, 56583, 56584, 56585); uma regra UNSUPPORTED vai sempre inteira
ao Snort, entao a testemunha dela pode sair no-match sem que isso seja
violacao. Por isso as duas particoes incluem as UNSUPPORTED no fallback:

    global.json   fallback = UNSUPPORTED do manifesto snort3
    strong.json   fallback = UNSUPPORTED + fallback operacional da politica
                  strong_discriminator (plano_strong_discriminator_snort3/)

Saida: output/campaign/particoes_snort3/{global,strong}.json

Uso:
    python tests/build_campaign_partitions.py
"""

from __future__ import annotations

import hashlib
import json
import sys

from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
MANIFESTO = PROJECT_ROOT / "output" / "semantic_manifest.json"
STRONG = PROJECT_ROOT / "output" / "campaign" / "plano_strong_discriminator_snort3" / "particao.json"
DESTINO = PROJECT_ROOT / "output" / "campaign" / "particoes_snort3"


def _sha256(caminho: Path) -> str:
    return hashlib.sha256(caminho.read_bytes()).hexdigest()


def _rotulo(caminho: Path) -> str:
    return caminho.relative_to(PROJECT_ROOT).as_posix()


def main() -> int:
    manifesto = json.loads(MANIFESTO.read_text(encoding="utf-8"))
    semantica = manifesto["summary"].get("service_header_semantics")
    if semantica != "snort3":
        print(f"ERRO: {_rotulo(MANIFESTO)} nao e a compilacao snort3 ({semantica})", file=sys.stderr)
        return 1

    unsupported = sorted(
        (str(r["rule_id"]) for r in manifesto["rules"] if r["classification"] == "UNSUPPORTED"),
        key=int,
    )
    strong = json.loads(STRONG.read_text(encoding="utf-8"))
    operacional = sorted(set(strong["sids_fallback_operacional"]), key=int)

    fontes = {_rotulo(MANIFESTO): _sha256(MANIFESTO), _rotulo(STRONG): _sha256(STRONG)}
    comum = {
        "gerado_em": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "gerador": "tests/build_campaign_partitions.py",
        "semantica_de_cabecalho": "snort3",
        "fontes": fontes,
        "sids_unsupported": unsupported,
    }
    particoes = {
        "global": {**comum, "plano": "output/p4runtime_install_plan.json",
                   "sids_fallback_operacional": unsupported},
        "strong": {**comum, "plano": "output/campaign/plano_strong_discriminator_snort3/p4runtime_install_plan.json",
                   "sids_fallback_operacional": sorted(set(unsupported) | set(operacional), key=int)},
    }

    DESTINO.mkdir(parents=True, exist_ok=True)
    for nome, dados in particoes.items():
        (DESTINO / f"{nome}.json").write_text(
            json.dumps(dados, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n"
        )
        print(f"{nome:7s} fallback {len(dados['sids_fallback_operacional']):5d}  ({len(unsupported)} UNSUPPORTED)")
    print(f"em {_rotulo(DESTINO)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

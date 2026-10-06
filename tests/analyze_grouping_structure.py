#!/usr/bin/env python3
"""Estrutura dos grupos das quatro estrategias de agrupamento, nas duas semanticas.

O candidate set agrupado (tests/rederive_trace_metrics.py) depende de quantos
grupos cada estrategia forma sobre as entradas retidas pelo plano
strong-discriminator, do tamanho do maior grupo e de quantas regras caem em
mais de um grupo. Este estagio registra essa estrutura, que nao depende de
trafego, com a mesma particao e a mesma chave de grupo do rederive:

    legacy   output/historical/legacy_header_semantics/ (322 entradas retidas)
    snort3   raiz de output/ (225 entradas retidas)

Grava output/analysis/grouping_structure_by_semantics.json.

Uso:
    python tests/analyze_grouping_structure.py
"""

from __future__ import annotations

import json
import sys

from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "tests"))

from rederive_trace_metrics import ESTRATEGIAS, LEGADO, configuracao, group_key  # noqa: E402

SAIDA = PROJECT_ROOT / "output" / "analysis" / "grouping_structure_by_semantics.json"
FONTES = {"legacy": LEGADO, "snort3": PROJECT_ROOT / "output"}


def estrutura(base: Path) -> dict:
    conf = configuracao(base)
    saida = {
        "entradas_retidas": len(conf["retidas"]),
        "regras_elegiveis": conf["elegiveis"],
        "estrategias": {},
    }
    for estrategia in ESTRATEGIAS:
        grupos = defaultdict(set)
        for entrada in conf["retidas"]:
            grupos[group_key(entrada, estrategia)].update(entrada["provenance"]["source_rule_ids"])
        multiplicidade = Counter(sid for regras in grupos.values() for sid in regras)
        rotulo, regras = max(grupos.items(), key=lambda item: (len(item[1]), str(item[0])))
        saida["estrategias"][estrategia] = {
            "grupos": len(grupos),
            "maior_grupo": {"rotulo": str(rotulo), "regras": len(regras)},
            "regras_em_mais_de_um_grupo": sum(1 for n in multiplicidade.values() if n > 1),
            "multiplicidade_maxima": max(multiplicidade.values()),
        }
    return saida


def main() -> int:
    resultado = {
        "analise": "grouping_structure_by_semantics",
        "gerado_em": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "gerador": "tests/analyze_grouping_structure.py",
        "semanticas": {nome: estrutura(base) for nome, base in FONTES.items()},
    }
    SAIDA.write_text(json.dumps(resultado, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    for nome, dados in resultado["semanticas"].items():
        print(f"  {nome}: {dados['entradas_retidas']} entradas, {dados['regras_elegiveis']} regras")
        for estrategia, bloco in dados["estrategias"].items():
            print(
                f"    {estrategia:28s} grupos {bloco['grupos']:4d}  maior {bloco['maior_grupo']['regras']:5d} "
                f"({bloco['maior_grupo']['rotulo']})  em >1 grupo {bloco['regras_em_mais_de_um_grupo']:5d} "
                f"(ate {bloco['multiplicidade_maxima']})"
            )
    print(f"\n  {SAIDA.relative_to(PROJECT_ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

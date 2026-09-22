#!/usr/bin/env python3
"""Compara duas campanhas end-to-end, caso a caso.

A campanha e regerada quando o gerador de testemunhas melhora, e comparar
versoes e a unica forma de saber se a melhora foi real: um conserto que
aumenta a efetividade num estrato pode derrubar outro por interferencia
entre casos. Foi o que aconteceu entre a v1 e a v2 — a regra 27086 parou de
alertar porque outro caso da mesma 5-tupla trocou de payload.

Por isso a comparacao e por sid, e nao por agregado: regressao unica em mil
casos desaparece numa media.

O que sai:

    vacuidade por estrato nas duas versoes
    sids que passaram a alertar e sids que pararam
    casos falsificaveis, isto e, nao-TCP com o Snort alertando. Para TCP a
    entrada p4-106 (`protocol == 6` e nada mais) garante candidate por
    construcao, logo esses casos nao podem refutar a propriedade; a fatia
    nao-TCP e a que pode
    vereditos, quando as duas versoes tiverem medicao de plano de dados

Uso:
    python tests/compare_campaigns.py output/campaign/e2e_1000 output/campaign/e2e_1000_v2
"""

from __future__ import annotations

import argparse
import json

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def carregar(diretorio: Path) -> tuple[dict, dict]:
    resultado = {}
    for linha in (diretorio / "resultado.jsonl").read_text(encoding="utf-8").splitlines():
        if linha.strip():
            registro = json.loads(linha)
            resultado[str(registro["sid"])] = registro

    relatorio = json.loads((diretorio / "relatorio.json").read_text(encoding="utf-8"))
    return resultado, relatorio


def falsificaveis(resultado: dict) -> int:
    """Casos nao-TCP em que o Snort alertou.

    Nao-TCP porque p4-106 torna no-match inalcancavel para TCP: la a
    confirmacao e estrutural e o caso nao podia falhar.
    """

    return sum(
        1
        for r in resultado.values()
        if r["snort_alertou"] and not r["estrato"].startswith("tcp")
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("antes")
    parser.add_argument("depois")
    parser.add_argument("--saida", default=None)
    argumentos = parser.parse_args()

    dir_antes = (PROJECT_ROOT / argumentos.antes).resolve()
    dir_depois = (PROJECT_ROOT / argumentos.depois).resolve()

    antes, rel_antes = carregar(dir_antes)
    depois, rel_depois = carregar(dir_depois)

    comuns = sorted(set(antes) & set(depois))
    so_antes = sorted(set(antes) - set(depois))
    so_depois = sorted(set(depois) - set(antes))

    estratos = sorted({r["estrato"] for r in depois.values()})
    tabela = []
    for estrato in estratos:
        casos = sum(1 for r in depois.values() if r["estrato"] == estrato)
        vac_antes = sum(
            1
            for r in antes.values()
            if r["estrato"] == estrato and not r["snort_alertou"]
        )
        vac_depois = sum(
            1
            for r in depois.values()
            if r["estrato"] == estrato and not r["snort_alertou"]
        )
        tabela.append(
            {
                "estrato": estrato,
                "casos": casos,
                "vacuos_antes": vac_antes,
                "vacuos_depois": vac_depois,
            }
        )

    ganhos = [
        sid
        for sid in comuns
        if depois[sid]["snort_alertou"] and not antes[sid]["snort_alertou"]
    ]
    regressoes = [
        sid
        for sid in comuns
        if antes[sid]["snort_alertou"] and not depois[sid]["snort_alertou"]
    ]

    mediu_plano = {
        "antes": rel_antes["parametros"]["bmv2_executado"],
        "depois": rel_depois["parametros"]["bmv2_executado"],
    }

    comparacao = {
        "gerado_em": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "antes": {
            "campanha": rel_antes["campanha"],
            "casos": rel_antes["casos"],
            "quadros": rel_antes["quadros"],
            "vereditos": rel_antes["vereditos"],
            "vacuos": rel_antes["vacuos"],
            "plano_de_dados_medido": mediu_plano["antes"],
        },
        "depois": {
            "campanha": rel_depois["campanha"],
            "casos": rel_depois["casos"],
            "quadros": rel_depois["quadros"],
            "vereditos": rel_depois["vereditos"],
            "vacuos": rel_depois["vacuos"],
            "plano_de_dados_medido": mediu_plano["depois"],
        },
        "amostra_identica": set(antes) == set(depois),
        "sids_so_antes": so_antes,
        "sids_so_depois": so_depois,
        "vacuidade_por_estrato": tabela,
        "ganhos": {"total": len(ganhos), "sids": ganhos},
        "regressoes": {"total": len(regressoes), "sids": regressoes},
        "falsificaveis": {
            "antes": falsificaveis(antes),
            "depois": falsificaveis(depois),
            "nota": "nao-TCP com o Snort alertando; para TCP p4-106 garante candidate por construcao",
        },
        "ressalva": (
            "comparacao de vereditos so e valida quando plano_de_dados_medido e"
            " verdadeiro nas duas versoes; caso contrario compare apenas vacuidade"
        ),
    }

    destino = (
        Path(argumentos.saida)
        if argumentos.saida
        else dir_depois.parent / f"comparacao_{dir_antes.name}_{dir_depois.name}.json"
    )
    destino.write_text(
        json.dumps(comparacao, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )

    print(f"{dir_antes.name} -> {dir_depois.name}")
    print(f"amostra identica     {comparacao['amostra_identica']}")
    print(
        f"plano medido         antes={mediu_plano['antes']} depois={mediu_plano['depois']}"
    )
    print(f"vacuos               {rel_antes['vacuos']} -> {rel_depois['vacuos']}")
    print(f"ganhos               {len(ganhos)}")
    print(f"regressoes           {len(regressoes)}" + (f" {regressoes}" if regressoes else ""))
    print(
        f"falsificaveis        {comparacao['falsificaveis']['antes']} -> "
        f"{comparacao['falsificaveis']['depois']}"
    )
    print()
    print(f"{'estrato':24s} {'casos':>6} {'vac.antes':>10} {'vac.depois':>11}")
    for linha in tabela:
        print(
            f"{linha['estrato']:24s} {linha['casos']:6d} "
            f"{linha['vacuos_antes']:10d} {linha['vacuos_depois']:11d}"
        )

    print(f"\ncomparacao em {destino.relative_to(PROJECT_ROOT)}")

    if regressoes:
        print(
            f"\nATENCAO: {len(regressoes)} regressao(oes). Caso que alertava e "
            "parou nao e ruido: e interferencia entre casos ou perda de "
            "cobertura do gerador."
        )
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

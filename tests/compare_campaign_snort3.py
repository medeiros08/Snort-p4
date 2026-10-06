#!/usr/bin/env python3
"""Confere caso a caso as campanhas da Fase B (snort3) no BMv2.

Para e2e_1000_v4 e servico_fora_do_cabecalho, nos planos global e strong
snort3 (sufixos _snort3 e _strong_snort3), confere:

    precheque     a categoria P4 medida de cada papel (testemunha,
                  negativo_payload, negativo_header) contra a prevista offline
                  em precheque_predicoes<sufixo>.jsonl
    legacy        a transicao de veredito em relacao a rodada legacy do mesmo
                  plano, quando ela existe (resultado<sufixo sem _snort3>.jsonl),
                  e se o Snort alertou nos mesmos casos e nos mesmos pacotes;
                  o Snort nao depende do plano, entao isso deve coincidir
    snort         os alertas do Snort das duas rodadas snort3 (global e strong)
                  devem ser identicos, pelo mesmo motivo

Grava output/analysis/fase_b_snort3/comparacao_campanhas.json. Sai com 0 se
nao houver divergencia de papel nem diferenca nos alertas do Snort.

Uso:
    python tests/compare_campaign_snort3.py
"""

from __future__ import annotations

import json
import sys

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
CAMPANHAS = PROJECT_ROOT / "output" / "campaign"
SAIDA = PROJECT_ROOT / "output" / "analysis" / "fase_b_snort3" / "comparacao_campanhas.json"

RODADAS = {
    "e2e_1000_v4": ("_snort3", "_strong_snort3"),
    "servico_fora_do_cabecalho": ("_snort3", "_strong_snort3"),
}


def ler_jsonl(caminho: Path) -> list[dict]:
    return [json.loads(linha) for linha in caminho.read_text(encoding="utf-8").splitlines() if linha.strip()]


def por_indice(caminho: Path) -> dict[int, dict]:
    return {registro["indice"]: registro for registro in ler_jsonl(caminho)}


def conferir(diretorio: Path, sufixo: str) -> dict:
    previsto = por_indice(diretorio / f"precheque_predicoes{sufixo}.jsonl")
    medido = por_indice(diretorio / f"resultado{sufixo}.jsonl")
    if previsto.keys() != medido.keys():
        raise SystemExit(f"ERRO: {diretorio.name}{sufixo}: indices do precheque e do resultado diferem")

    divergencias = []
    papeis = Counter()
    for indice, caso in sorted(medido.items()):
        for papel, categoria in caso["p4_por_papel"].items():
            papeis[papel] += 1
            esperado = previsto[indice]["previsto"].get(papel)
            if esperado is not None and esperado != categoria:
                divergencias.append(
                    {"indice": indice, "sid": caso["sid"], "papel": papel, "previsto": esperado, "medido": categoria}
                )

    saida = {
        "casos": len(medido),
        "vereditos": dict(Counter(caso["veredito"] for caso in medido.values())),
        "papeis_medidos": dict(papeis),
        "divergencias_do_precheque": divergencias,
        "fallback_operacional_sids": sorted(
            caso["sid"] for caso in medido.values() if caso["veredito"] == "FALLBACK_OPERACIONAL"
        )
        if sufixo == "_snort3"
        else None,
    }

    legacy = diretorio / f"resultado{sufixo.replace('_snort3', '')}.jsonl"
    if legacy.exists():
        anterior = por_indice(legacy)
        saida["legacy"] = {
            "arquivo": str(legacy.relative_to(PROJECT_ROOT)).replace("\\", "/"),
            "transicoes": {
                f"{a} -> {b}": n
                for (a, b), n in sorted(
                    Counter((anterior[i]["veredito"], medido[i]["veredito"]) for i in medido).items()
                )
            },
            "casos_com_snort_alertou_diferente": sum(
                1 for i in medido if anterior[i]["snort_alertou"] != medido[i]["snort_alertou"]
            ),
            "casos_com_pacotes_alertados_diferentes": sum(
                1 for i in medido if anterior[i].get("pkt_num_alertados") != medido[i].get("pkt_num_alertados")
            ),
        }
    return saida


def main() -> int:
    resultado = {
        "analise": "comparacao_campanhas_snort3",
        "gerado_em": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "gerador": "tests/compare_campaign_snort3.py",
        "campanhas": {},
    }
    problemas = 0
    for campanha, sufixos in RODADAS.items():
        diretorio = CAMPANHAS / campanha
        bloco = {sufixo: conferir(diretorio, sufixo) for sufixo in sufixos}
        alertas = [(diretorio / f"snort_alertas{sufixo}.jsonl").read_bytes() for sufixo in sufixos]
        bloco["alertas_snort_identicos_entre_planos"] = alertas[0] == alertas[1]
        resultado["campanhas"][campanha] = bloco

        problemas += not bloco["alertas_snort_identicos_entre_planos"]
        for sufixo in sufixos:
            r = bloco[sufixo]
            problemas += len(r["divergencias_do_precheque"])
            legacy = r.get("legacy", {})
            problemas += legacy.get("casos_com_snort_alertou_diferente", 0)
            problemas += legacy.get("casos_com_pacotes_alertados_diferentes", 0)
            print(f"  {campanha}{sufixo}: {r['vereditos']}; divergencias do precheque {len(r['divergencias_do_precheque'])}")
            if legacy:
                print(f"      legacy -> snort3: {legacy['transicoes']}")
        print(f"  {campanha}: alertas do Snort identicos entre planos: {bloco['alertas_snort_identicos_entre_planos']}")

    SAIDA.parent.mkdir(parents=True, exist_ok=True)
    SAIDA.write_text(json.dumps(resultado, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"\n  {SAIDA.relative_to(PROJECT_ROOT)}")
    return 0 if problemas == 0 else 1


if __name__ == "__main__":
    sys.exit(main())

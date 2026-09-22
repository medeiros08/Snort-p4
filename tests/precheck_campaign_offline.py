#!/usr/bin/env python3
"""Pre-cheque offline da campanha: prediz a categoria de cada quadro.

Roda antes de gastar ciclo de rig. Para cada quadro do pcap da campanha,
prediz a categoria do prefilter usando os mesmos dois componentes que o
projeto ja usa como referencia:

    tests/p4_packet_domain.py            espelha o parser do ids_prefilter.p4
    analyze_prefilter_selectivity.py     casador de entrada instalada que
                                         produziu os numeros de seletividade

Reuso, e nao copia: um casador proprio aqui poderia divergir do que gerou os
resultados citados, e a campanha passaria a medir duas implementacoes
diferentes sem dizer qual esta certa.

O que este pre-cheque decide:

    testemunha predita P4_NO_MATCH      defeito do GERADOR. O header
                                        sintetizado nao casa com nenhuma
                                        entrada instalada — por exemplo porta
                                        escolhida de uma lista que a expansao
                                        nao cobre. No rig isso apareceria como
                                        VIOLACAO e seria lido como defeito do
                                        compilador, que e a ambiguidade que a
                                        campanha existe para eliminar

    negativo_header predito candidate   a porta do controle negativo esta
                                        coberta por alguma entrada; o controle
                                        nao controla nada

    quadro fora do dominio              o gerador produziu quadro que o parser
                                        P4 recusa; ja e verificado na geracao,
                                        conferido aqui de novo sobre os bytes
                                        do pcap

Predicao nao substitui medicao: o rig continua sendo quem observa o contador.
O que este estagio garante e que uma divergencia observada no rig sera
divergencia do compilador, e nao do gerador de casos.

Codigos de saida:
    0   campanha coerente com as entradas instaladas
    1   defeito do gerador ou artefato invalido

Uso:
    python tests/precheck_campaign_offline.py --casos output/campaign/piloto
    python tests/precheck_campaign_offline.py --casos output/campaign/e2e_1000
"""

from __future__ import annotations

import argparse
import json
import sys

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "tests"))

from campaign_matcher import carregar_entradas, predizer  # noqa: E402
from run_campaign_bmv2 import ler_pcap  # noqa: E402

ENTRADAS = PROJECT_ROOT / "output" / "p4_install_entries.json"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--casos", default="output/campaign/e2e_1000")
    argumentos = parser.parse_args()

    destino = (PROJECT_ROOT / argumentos.casos).resolve()
    caminho_casos = destino / "casos.jsonl"
    caminho_pcap = destino / "campanha.pcap"

    for exigido in (caminho_casos, caminho_pcap, ENTRADAS):
        if not exigido.exists():
            print(f"artefato ausente: {exigido}", file=sys.stderr)
            return 1

    casos = [
        json.loads(linha)
        for linha in caminho_casos.read_text(encoding="utf-8").splitlines()
        if linha.strip()
    ]
    quadros = ler_pcap(caminho_pcap)

    entradas_compiladas = carregar_entradas()

    esperados = sum(len(caso["quadros"]) for caso in casos)
    if esperados != len(quadros):
        print(
            f"pcap tem {len(quadros)} quadros e casos.jsonl descreve {esperados}",
            file=sys.stderr,
        )
        return 1

    print(f"campanha             {destino.name}")
    print(f"casos                {len(casos)}")
    print(f"quadros              {len(quadros)}")
    print(f"entradas instaladas  {len(entradas_compiladas)}")

    posicao = 0
    por_papel: Counter = Counter()
    defeitos_do_gerador = []
    controles_fracos = []
    fora_do_dominio = []
    por_estrato_no_match = Counter()
    predicoes = []

    for caso in casos:
        previsto_por_papel = {}
        for quadro_registro in caso["quadros"]:
            papel = quadro_registro["papel"]
            _segundos, _micros, bytes_do_quadro = quadros[posicao]
            categoria, detalhe = predizer(entradas_compiladas, bytes_do_quadro)
            por_papel[(papel, categoria)] += 1
            previsto_por_papel.setdefault(papel, categoria)

            if categoria == "PACKET_DOMAIN_FALLBACK":
                fora_do_dominio.append((caso["sid"], papel, detalhe))

            if papel == "testemunha" and categoria == "P4_NO_MATCH":
                defeitos_do_gerador.append(
                    {
                        "sid": caso["sid"],
                        "estrato": caso["estrato"],
                        "header": caso["header"],
                        "previsto": categoria,
                    }
                )
                por_estrato_no_match[caso["estrato"]] += 1

            if papel == "negativo_header" and categoria == "P4_CANDIDATE":
                # O gerador so emite este quadro quando achou header que
                # nenhuma entrada cobre. Chegar aqui significa que o pcap e de
                # uma geracao anterior as entradas instaladas.
                controles_fracos.append(
                    {
                        "sid": caso["sid"],
                        "entrada_que_casou": detalhe,
                        "header": caso["header"],
                    }
                )

            posicao += 1

        predicoes.append(
            {
                "indice": caso["indice"],
                "sid": caso["sid"],
                "estrato": caso["estrato"],
                "previsto": previsto_por_papel,
            }
        )

    print("\ncategoria prevista por papel:")
    for (papel, categoria), quantos in sorted(por_papel.items()):
        print(f"  {quantos:5d}  {papel:18s} {categoria}")

    relatorio = {
        "gerado_em": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "campanha": destino.name,
        "casos": len(casos),
        "quadros": len(quadros),
        "entradas_instaladas": len(entradas_compiladas),
        "por_papel": {f"{p}/{c}": q for (p, c), q in sorted(por_papel.items())},
        "testemunhas_previstas_no_match": len(defeitos_do_gerador),
        "controles_negativos_fracos": len(controles_fracos),
        "quadros_fora_do_dominio": len(fora_do_dominio),
        "no_match_por_estrato": dict(por_estrato_no_match),
        "amostra_de_defeitos": defeitos_do_gerador[:20],
        "amostra_de_controles_fracos": controles_fracos[:20],
    }

    caminho_relatorio = destino / "precheque.json"
    caminho_relatorio.write_text(
        json.dumps(relatorio, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )

    caminho_predicoes = destino / "precheque_predicoes.jsonl"
    with open(caminho_predicoes, "w", encoding="utf-8", newline="\n") as saida:
        for registro in predicoes:
            saida.write(json.dumps(registro, ensure_ascii=False, sort_keys=True) + "\n")

    print(f"\n  relatorio  {caminho_relatorio.relative_to(PROJECT_ROOT)}")
    print(f"  predicoes  {caminho_predicoes.relative_to(PROJECT_ROOT)}")

    falhou = False

    if fora_do_dominio:
        print(
            f"\nFALHA: {len(fora_do_dominio)} quadro(s) fora do dominio do parser.",
            file=sys.stderr,
        )
        falhou = True

    if defeitos_do_gerador:
        print(
            f"\nFALHA: {len(defeitos_do_gerador)} testemunha(s) predita(s) "
            "P4_NO_MATCH — defeito do gerador, nao do compilador.",
            file=sys.stderr,
        )
        for defeito in defeitos_do_gerador[:8]:
            print(
                f"  sid {defeito['sid']} ({defeito['estrato']}): "
                f"{defeito['header']}",
                file=sys.stderr,
            )
        print("\n  no_match por estrato:", dict(por_estrato_no_match), file=sys.stderr)
        falhou = True

    if controles_fracos:
        print(
            f"\nFALHA: {len(controles_fracos)} controle(s) negativo(s) coberto(s) "
            "por entrada instalada; regenere os casos.",
            file=sys.stderr,
        )
        for fraco in controles_fracos[:5]:
            print(
                f"  sid {fraco['sid']}: casou {fraco['entrada_que_casou']}",
                file=sys.stderr,
            )
        falhou = True

    if falhou:
        return 1

    print("\nPRE-CHEQUE OK: campanha coerente com as entradas instaladas.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

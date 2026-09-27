#!/usr/bin/env python3
"""Atribuicao offline da campanha: que entrada instalada casa cada testemunha.

O veredito CONFIRMADO diz que o Snort alertou e que o BMv2 marcou a
testemunha como candidate. Nao diz POR QUE ela foi candidate. Sob o plano
completo, `p4-106` casa todo TCP do dominio suportado, entao a testemunha de
uma regra TCP e candidate mesmo que o rebaixamento da propria regra estivesse
errado: o caso confirma, mas nao tinha como reprovar.

Este estagio mede esse poder de reprovacao. Para cada caso, lista todas as
entradas do plano que casam a testemunha e separa pela proveniencia:

    so_propria        so entradas cujo `source_rule_ids` contem o sid do caso.
                      Um defeito no rebaixamento desta regra teria virado
                      VIOLACAO: e o caso que de fato testa a regra
    propria_e_outras  a regra casa, mas outra entrada tambem casaria
    so_outras         a testemunha e candidate so por entradas de outras
                      regras
    nenhuma           nenhuma entrada casa; a testemunha e no-match

Tambem confronta, quadro a quadro, a categoria que o casador offline prediz
com a que o contador do BMv2 registrou em `resultado*.jsonl`. E o mesmo
casador que produziu os numeros de seletividade do manuscrito, entao a
concordancia aqui e evidencia sobre ele, nao so sobre a campanha.

Reusa os componentes de referencia, como o pre-cheque:

    tests/p4_packet_domain.py            espelha o parser do ids_prefilter.p4
    analyze_prefilter_selectivity.py     casador de entrada instalada

Precisa do `campanha.pcap` da rodada. O pcap nao e versionado; o gerador de
casos o recria byte a byte no commit que produziu a rodada, e o sha256 em
`proveniencia.json` confere.

Codigos de saida:
    0   atribuicao gravada
    1   artefato de entrada ausente ou incoerente

Uso:
    python tests/analyze_campaign_attribution.py --casos output/campaign/e2e_1000_v2
    python tests/analyze_campaign_attribution.py --casos output/campaign/e2e_1000_v4 \\
        --entradas output/campaign/plano_strong_discriminator/p4_install_entries.json \\
        --resultado resultado_strong.jsonl --saida atribuicao_strong.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "tests"))

from campaign_matcher import (  # noqa: E402
    ENTRADAS_INSTALADAS,
    carregar_entradas,
    predizer,
)
from analyze_prefilter_selectivity import compiled_entry_matches_packet  # noqa: E402
from p4_packet_domain import classify_frame_for_prefilter  # noqa: E402
from run_campaign_bmv2 import PAPEIS_DE_ANDAIME, ler_pcap  # noqa: E402


def _sha256(caminho: Path) -> str:
    return hashlib.sha256(caminho.read_bytes()).hexdigest()


def _relativo(caminho: Path) -> str:
    try:
        return caminho.resolve().relative_to(PROJECT_ROOT).as_posix()
    except ValueError:
        return str(caminho)


def cobertura(sid: str, casadas: list[int], proveniencia: list[set[str]]) -> str:
    """Classifica as entradas que casam a testemunha pela proveniencia."""

    proprias = [i for i in casadas if sid in proveniencia[i]]
    outras = [i for i in casadas if sid not in proveniencia[i]]
    if not casadas:
        return "nenhuma"
    if proprias and not outras:
        return "so_propria"
    if proprias:
        return "propria_e_outras"
    return "so_outras"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--casos", required=True, help="diretorio de uma rodada da campanha")
    parser.add_argument(
        "--entradas",
        default=None,
        help="p4_install_entries do plano medido (padrao: o da raiz)",
    )
    parser.add_argument("--resultado", default="resultado.jsonl")
    parser.add_argument("--saida", default="atribuicao.json")
    argumentos = parser.parse_args()

    destino = (PROJECT_ROOT / argumentos.casos).resolve()
    caminho_casos = destino / "casos.jsonl"
    caminho_pcap = destino / "campanha.pcap"
    caminho_resultado = destino / argumentos.resultado
    caminho_entradas = (
        (PROJECT_ROOT / argumentos.entradas).resolve() if argumentos.entradas else ENTRADAS_INSTALADAS
    )

    for caminho in (caminho_casos, caminho_pcap, caminho_resultado, caminho_entradas):
        if not caminho.exists():
            print(f"entrada ausente: {caminho}", file=sys.stderr)
            if caminho == caminho_pcap:
                print(
                    "o pcap nao e versionado: rode tests/generate_campaign_cases.py "
                    "no commit que produziu a rodada",
                    file=sys.stderr,
                )
            return 1

    casos = [
        json.loads(linha)
        for linha in caminho_casos.read_text(encoding="utf-8").splitlines()
        if linha.strip()
    ]
    resultados = {
        registro["indice"]: registro
        for registro in (
            json.loads(linha)
            for linha in caminho_resultado.read_text(encoding="utf-8").splitlines()
            if linha.strip()
        )
    }
    quadros = ler_pcap(caminho_pcap)

    esperados = sum(len(caso["quadros"]) for caso in casos)
    if esperados != len(quadros) or len(resultados) != len(casos):
        print(
            f"pcap com {len(quadros)} quadros, casos descrevem {esperados}, "
            f"resultado tem {len(resultados)} de {len(casos)} casos: "
            "artefatos de rodadas diferentes",
            file=sys.stderr,
        )
        return 1

    proveniencia_pcap = destino / "proveniencia.json"
    if proveniencia_pcap.exists():
        registrado = json.loads(proveniencia_pcap.read_text(encoding="utf-8")).get("pcap_sha256")
        if registrado and registrado != _sha256(caminho_pcap):
            print(
                "o pcap local nao e o da rodada: sha256 difere do registrado em "
                "proveniencia.json",
                file=sys.stderr,
            )
            return 1

    bruto = json.loads(caminho_entradas.read_text(encoding="utf-8"))["entries"]
    compiladas = carregar_entradas(caminho_entradas)
    proveniencia = [set(entrada["provenance"]["source_rule_ids"]) for entrada in bruto]
    identificadores = [entrada["install_entry_id"] for entrada in bruto]

    por_veredito: dict[str, Counter] = {}
    so_propria: list[str] = []
    concordancia = Counter()
    divergencias = []

    posicao = 0
    for caso in casos:
        sid = str(caso["sid"])
        resultado = resultados[caso["indice"]]
        observado_por_papel = resultado.get("p4_por_papel", {})
        tipo = "sem_testemunha"

        for quadro in caso["quadros"]:
            papel = quadro["papel"]
            bytes_do_quadro = quadros[posicao][2]
            posicao += 1

            if papel not in PAPEIS_DE_ANDAIME and papel in observado_por_papel:
                previsto, _detalhe = predizer(compiladas, bytes_do_quadro)
                observado = observado_por_papel[papel]
                concordancia[previsto == observado] += 1
                if previsto != observado:
                    divergencias.append(
                        {"sid": sid, "papel": papel, "previsto": previsto, "observado": observado}
                    )

            if papel == "testemunha":
                pacote, _motivo = classify_frame_for_prefilter(bytes_do_quadro)
                if pacote is None:
                    tipo = "fora_do_dominio"
                    continue
                casadas = [
                    indice
                    for indice, entrada in enumerate(compiladas)
                    if compiled_entry_matches_packet(entrada, pacote)
                ]
                tipo = cobertura(sid, casadas, proveniencia)

        veredito = resultado["veredito"]
        por_veredito.setdefault(veredito, Counter())[tipo] += 1
        if veredito == "CONFIRMADO" and tipo == "so_propria":
            so_propria.append(sid)

    relatorio = {
        "campanha": destino.name,
        "casos": len(casos),
        "concordancia_predicao_medicao": {
            "quadros_comparados": sum(concordancia.values()),
            "concordam": concordancia[True],
            "divergem": concordancia[False],
            "divergencias": divergencias,
            "nota": "papeis de andaime ficam fora: o resultado nao registra categoria para eles",
        },
        "confirmados_so_propria": {
            "total": len(so_propria),
            "sids": sorted(so_propria, key=int),
        },
        "cobertura_da_testemunha_por_veredito": {
            veredito: dict(sorted(contagem.items()))
            for veredito, contagem in sorted(por_veredito.items())
        },
        "entradas": {
            "caminho": _relativo(caminho_entradas),
            "sha256": _sha256(caminho_entradas),
            "total": len(bruto),
        },
        "gerado_em": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "gerador": "tests/analyze_campaign_attribution.py",
        "pcap_sha256": _sha256(caminho_pcap),
        "resultado": _relativo(caminho_resultado),
    }

    saida = destino / argumentos.saida
    saida.write_text(
        json.dumps(relatorio, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )

    print(f"campanha             {destino.name}")
    print(f"plano                {_relativo(caminho_entradas)} ({len(bruto)} entradas)")
    for veredito, contagem in sorted(por_veredito.items()):
        print(f"  {veredito:<22} {dict(sorted(contagem.items()))}")
    print(f"confirmados so_propria  {len(so_propria)}")
    print(
        f"predicao x medicao      {concordancia[True]}/{sum(concordancia.values())} concordam"
    )
    print(f"gravado em {_relativo(saida)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

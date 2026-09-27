#!/usr/bin/env python3
"""Casos de campanha com a testemunha HTTP fora da porta do cabecalho.

Teste de `paper/IDS_P4/SERVICE_BASED_HEADER_FINDING.md`. No Snort 3.12.2.0,
regra com `service:` nao tem porta nem protocolo checados quando o servico
identificado no fluxo e um dos dela (`src/detection/detection_options.cc`,
`rtn_checks.cc`). O compilador, porem, poe a porta do cabecalho no predicado
P4. A campanha normal nunca viu isso porque sintetiza cada testemunha numa
porta do proprio cabecalho.

Aqui cada caso e o mesmo fluxo HTTP da campanha — handshake, aquecimento,
resposta do servidor que faz o wizard identificar o servico, testemunha,
flush — para uma regra HTTP com `service:http`, mas com a porta de destino
trocada por uma que NENHUMA entrada da propria regra casa. E o criterio: o
predicado da regra, `p_r`, e falso na testemunha por construcao, e isso e
conferido com o casador de referencia na geracao.

O que a rodada no rig decide, com `tests/run_campaign_bmv2.py`:

    Snort alerta          o cabecalho nao foi avaliado: r(x) sem p_r(x).
                          Sob o plano global o veredito sai CONFIRMADO,
                          porque p4-40 / p4-106 cobrem a testemunha; sob o
                          strong-discriminator a testemunha e no-match e o
                          veredito sai VIOLACAO para as regras que o plano
                          ainda prefiltra
    Snort nao alerta      VACUO; se TODOS saem vacuos, a leitura do codigo
                          nao se confirma nesta instalacao e o achado precisa
                          ser revisto

A amostra, a escolha de porta e a categoria prevista em cada plano ficam no
`proveniencia.json` e em cada caso, para comparar com o que o rig medir.

Uso:
    python tests/generate_offport_service_cases.py
    python tests/generate_offport_service_cases.py --n 200 --porta 8000
"""

from __future__ import annotations

import argparse
import json
import random
import sys

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "tests"))

# campaign_matcher primeiro: ele registra o marcador de scapy de que o casador
# de referencia precisa na maquina sem scapy.
from campaign_matcher import carregar_entradas, predizer  # noqa: E402
from analyze_prefilter_selectivity import compiled_entry_matches_packet  # noqa: E402
from campaign_witness import MANIFESTO_SEMANTICO, sintetizar_caso  # noqa: E402
from generate_campaign_cases import _escrever_pcap, montar  # noqa: E402
from p4_packet_domain import classify_frame_for_prefilter  # noqa: E402

SAIDA_BASE = PROJECT_ROOT / "output" / "campaign"
ENTRADAS_GLOBAL = PROJECT_ROOT / "output" / "p4_install_entries.json"
ENTRADAS_STRONG = (
    PROJECT_ROOT / "output" / "campaign" / "plano_strong_discriminator" / "p4_install_entries.json"
)
PARTICAO_STRONG = PROJECT_ROOT / "output" / "campaign" / "plano_strong_discriminator" / "particao.json"

# Portas tentadas, em ordem. Nenhuma esta em HTTP_PORTS (80 8080) do perfil.
# 8000 esta coberta por entradas de outras regras (p4-123, p4-273), entao vem
# depois das que nenhuma entrada cobre: com ela a testemunha seria candidate
# tambem no strong e o teste nao discriminaria o plano.
PORTAS_FORA = (18080, 28080, 38080, 8181, 9090, 8000)


def _servicos(regra: dict) -> list[str]:
    return [
        s.strip()
        for o in regra["parsed_rule"]["options"]
        if o["name"] == "service"
        for s in o["value"].split(",")
    ]


def _proprias(sid: str, entradas_brutas: list[dict]) -> list[int]:
    return [
        indice
        for indice, entrada in enumerate(entradas_brutas)
        if sid in entrada["provenance"]["source_rule_ids"]
    ]


def _testemunha(registro: dict, itens: list) -> bytes:
    for quadro, (_s, _u, bytes_do_quadro) in zip(registro["quadros"], itens):
        if quadro["papel"] == "testemunha":
            return bytes_do_quadro
    raise ValueError("caso sem testemunha")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--n", type=int, default=200)
    parser.add_argument("--semente", type=int, default=20260927)
    parser.add_argument("--nome", default="servico_fora_do_cabecalho")
    argumentos = parser.parse_args()

    brutas_global = json.loads(ENTRADAS_GLOBAL.read_text(encoding="utf-8"))["entries"]
    global_ = carregar_entradas(ENTRADAS_GLOBAL)
    strong = carregar_entradas(ENTRADAS_STRONG)
    fallback_strong = set(
        json.loads(PARTICAO_STRONG.read_text(encoding="utf-8"))["sids_fallback_operacional"]
    )

    manifesto = json.loads(MANIFESTO_SEMANTICO.read_text(encoding="utf-8"))

    elegiveis = []
    recusas = Counter()
    for regra in manifesto["rules"]:
        if regra.get("classification") != "NECESSARY" or "http" not in _servicos(regra):
            continue
        caso = sintetizar_caso(regra)
        if not caso["utilizavel"]:
            recusas["nao_sintetizavel"] += 1
            continue
        header = caso["header"]
        if header["protocolo"] != "tcp" or caso["direcao"] != "to_server":
            recusas["nao_tcp_to_server"] += 1
            continue
        if header.get("dst_port_livre"):
            recusas["porta_de_destino_livre"] += 1
            continue
        if not caso["detalhe_payload"].get("http"):
            recusas["payload_nao_http"] += 1
            continue
        elegiveis.append(caso)

    elegiveis.sort(key=lambda c: int(c["rule_id"]))
    escolhidos = random.Random(argumentos.semente).sample(
        elegiveis, min(argumentos.n, len(elegiveis))
    )
    escolhidos.sort(key=lambda c: int(c["rule_id"]))

    destino = SAIDA_BASE / argumentos.nome
    destino.mkdir(parents=True, exist_ok=True)

    registros = []
    todos_itens = []
    previsao = Counter()
    sem_porta_fora = []

    for indice, caso in enumerate(escolhidos):
        sid = str(caso["rule_id"])
        proprias = _proprias(sid, brutas_global)
        porta_original = caso["header"]["dst_port"]

        # Primeira porta em que o predicado da propria regra e falso; entre
        # essas, prefere a que o strong nao cobre por outra entrada, porque e
        # ela que torna o plano strong testavel.
        montado = None
        for porta in PORTAS_FORA:
            tentativa = dict(caso)
            tentativa["header"] = dict(caso["header"], dst_port=porta, dst_port_livre=False)
            registro, itens = montar(tentativa, indice, global_)
            testemunha = _testemunha(registro, itens)
            pacote, _motivo = classify_frame_for_prefilter(testemunha)
            if pacote is None:
                continue
            if any(compiled_entry_matches_packet(global_[i], pacote) for i in proprias):
                continue
            if montado is None:
                montado = (porta, registro, itens, pacote)
            if predizer(strong, testemunha)[0] == "P4_NO_MATCH":
                montado = (porta, registro, itens, pacote)
                break
        if montado is None:
            sem_porta_fora.append(sid)
            continue

        porta, registro, itens, _pacote = montado
        # O indice e o segundo do caso seguem a posicao no pcap final, que
        # e o que a atribuicao do runner usa.
        testemunha = _testemunha(registro, itens)
        categoria_global, detalhe_global = predizer(global_, testemunha)
        categoria_strong, detalhe_strong = predizer(strong, testemunha)
        previsao[(categoria_global, categoria_strong)] += 1

        registro["servico_fora_do_cabecalho"] = {
            "porta_do_cabecalho": porta_original,
            "porta_usada": porta,
            "casa_entrada_propria": False,
            "p4_global_previsto": categoria_global,
            "p4_global_detalhe": detalhe_global,
            "p4_strong_previsto": categoria_strong,
            "p4_strong_detalhe": detalhe_strong,
            "fallback_operacional_no_strong": sid in fallback_strong,
        }
        registro["esperado"]["testemunha"]["p4"] = categoria_global
        registros.append(registro)
        todos_itens.extend(itens)

    # Reindexa para posicao contigua: casos sem porta fora ficaram de fora.
    # O segundo de cada caso vem do indice original e continua unico, que e
    # o que a atribuicao por timestamp precisa.
    for posicao, registro in enumerate(registros):
        registro["indice"] = posicao

    caminho_pcap = destino / "campanha.pcap"
    sha_pcap = _escrever_pcap(caminho_pcap, todos_itens)

    with open(destino / "casos.jsonl", "w", encoding="utf-8", newline="\n") as saida:
        for registro in registros:
            saida.write(json.dumps(registro, ensure_ascii=False, sort_keys=True) + "\n")

    proveniencia = {
        "achado": "paper/IDS_P4/SERVICE_BASED_HEADER_FINDING.md",
        "casos": len(registros),
        "elegiveis": len(elegiveis),
        "gerado_em": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "gerador": "tests/generate_offport_service_cases.py",
        "manifesto_semantico": MANIFESTO_SEMANTICO.relative_to(PROJECT_ROOT).as_posix(),
        "pcap_sha256": sha_pcap,
        "portas_tentadas": list(PORTAS_FORA),
        "previsao_global_x_strong": {f"{g}|{s}": n for (g, s), n in sorted(previsao.items())},
        "quadros": len(todos_itens),
        "recusas": dict(recusas),
        "semente": argumentos.semente,
        "sem_porta_fora_do_cabecalho": sem_porta_fora,
        "expectativa": {
            "se_o_snort_pula_a_porta": (
                "global: CONFIRMADO (a testemunha e candidate por entrada de outra "
                "regra); strong: VIOLACAO nos casos que o Snort alertar. O runner sai "
                "com codigo 1 e o precheck acusa testemunha no-match no strong: "
                "e o resultado que confirma o achado, nao defeito do gerador"
            ),
            "se_o_snort_avalia_a_porta": "VACUO em todos os casos, nos dois planos",
        },
        "uso_no_rig": [
            f"python tests/run_campaign_bmv2.py --casos output/campaign/{argumentos.nome}",
            (
                f"python tests/run_campaign_bmv2.py --casos output/campaign/{argumentos.nome} "
                "--plano output/campaign/plano_strong_discriminator/p4runtime_install_plan.json "
                "--particao output/campaign/plano_strong_discriminator/particao.json --sufixo _strong"
            ),
        ],
    }
    (destino / "proveniencia.json").write_text(
        json.dumps(proveniencia, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )

    print(f"regras HTTP service-based elegiveis   {len(elegiveis)}  (recusas {dict(recusas)})")
    print(f"casos gerados                         {len(registros)}")
    print(f"quadros                               {len(todos_itens)}")
    print("previsao da testemunha (global | strong):")
    for (g, s), n in sorted(previsao.items()):
        print(f"  {g:<14} | {s:<14} {n}")
    if sem_porta_fora:
        print(f"sem porta fora do cabecalho: {len(sem_porta_fora)}")
    print(f"gravado em {destino.relative_to(PROJECT_ROOT).as_posix()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

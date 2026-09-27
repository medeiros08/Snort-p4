#!/usr/bin/env python3
"""Metricas de trace sob a semantica legacy e sob a do Snort 3. Roda no rig.

Recalcula, sobre as tres janelas do CICIDS2017, as taxas de candidato do
plano global e do strong-discriminator e os candidate sets por pacote, uma
vez com os artefatos congelados (legacy) e outra com o compilador em
`--service-header-semantics snort3` (paper/IDS_P4/SERVICE_BASED_HEADER_FINDING.md).
Acrescenta a metrica que o estudo de agrupamento nao media (achado C1/F-05):
o candidate set de um prefilter agrupado, que envia ao Snort todas as regras
de cada grupo ativado, ao lado do candidate set por entrada.

O calculo reusa o codigo que produziu os numeros congelados — parser P4
espelhado (`parse_frame_like_p4`), casador de entrada, estatisticas,
`group_key` e a particao de `simulate_operational_policy.py` — e, no modo
legacy, tem de reproduzir os valores congelados pos-correcao
(`output/analysis/ipv4_packet_domain_correction/` e
`output/analysis/grouped_prefilter_feasibility.json`). Se nao reproduzir,
nada e gravado: um calculo que nao bate com o congelado nao mede o snort3.

Reducao de candidate set, como no manuscrito: contra a base P4-elegivel e
contra o ruleset inteiro, contando as regras em fallback (operacional e
UNSUPPORTED) como aplicaveis a todo pacote.

Fora do rig, as janelas saem da captura bruta com
`tests/cut_cicids2017_windows.py`, que confere o corte com o registro.

Uso (no rig, com os pcaps das janelas):
    python tests/rederive_trace_metrics.py
    python tests/rederive_trace_metrics.py --janela sqli=/caminho/sqli.pcap ...
    python tests/rederive_trace_metrics.py --semantica legacy
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import statistics
import sys

from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "tests"))

# campaign_matcher primeiro: registra o marcador de scapy quando a scapy nao
# esta instalada. No rig, a scapy real e usada.
import campaign_matcher  # noqa: E402,F401
from analyze_grouped_prefilter_feasibility import group_key, stats  # noqa: E402
from analyze_prefilter_selectivity import (  # noqa: E402
    compile_entry,
    compiled_entry_matches_packet,
    parse_frame_like_p4,
)
from pcap_stream import quadros_com_tempo  # noqa: E402
from simulate_operational_policy import (  # noqa: E402
    simulate_rule_partition,
    summarize_semantic_rules,
)
from whatif_service_header_semantics import EstagioFalhou, saida_snort3  # noqa: E402

SAIDA = PROJECT_ROOT / "output" / "analysis" / "trace_metrics_by_semantics.json"
HOME_NET = ipaddress.ip_network("192.168.10.0/24")
RULESET = 4017

JANELAS_PADRAO = {
    "sqli": "/home/arthur/datasets/cicids2017/windows/thursday_web_sqli.pcap",
    "xss": "/home/arthur/datasets/cicids2017/windows/thursday_web_xss.pcap",
    "bruteforce": "/home/arthur/datasets/cicids2017/windows/thursday_web_bruteforce.pcap",
}

ESTRATEGIAS = ("protocol", "protocol_direction", "protocol_service", "protocol_direction_service")

# Valores congelados pos-correcao que o modo legacy tem de reproduzir.
CONGELADO = {
    "sqli": {"elegiveis": 34924, "global_candidatos": 34924, "strong_candidatos": 34580,
             "media_candidate_set": 179.2847898293437},
    "xss": {"elegiveis": 189076, "global_candidatos": 189076, "strong_candidatos": 186938,
            "media_candidate_set": 140.48995641964078},
    "bruteforce": {"elegiveis": 1101459, "global_candidatos": 1101459, "strong_candidatos": 1089805,
                   "media_candidate_set": 324.5227720686834},
}


def quadros(caminho: Path):
    """Quadros do pcap: scapy no rig, leitor proprio em fluxo (pcap classico ou
    pcapng, `pcap_stream`) fora dele."""

    try:
        from scapy.utils import RawPcapReader
    except ImportError:  # pragma: no cover
        RawPcapReader = None
    if RawPcapReader is not None:
        with RawPcapReader(str(caminho)) as leitor:
            for quadro, _metadados in leitor:
                yield quadro
        return
    for _tempo, quadro in quadros_com_tempo(caminho):
        yield quadro


def configuracao(saida: Path) -> dict:
    manifesto = json.loads((saida / "semantic_manifest.json").read_text(encoding="utf-8"))
    entradas = json.loads((saida / "p4_install_entries.json").read_text(encoding="utf-8"))["entries"]
    particao = simulate_rule_partition(
        entradas, summarize_semantic_rules(manifesto), "strong_discriminator", HOME_NET
    )
    retidas = [entrada for _indice, entrada, _registro in particao["retained_entries"]]
    return {
        "entradas": entradas,
        "retidas": retidas,
        "elegiveis": len(particao["eligible_sids"]),
        "fallback": len(particao["fallback_sids"]),
        "unsupported": manifesto["summary"]["classification"]["UNSUPPORTED"],
    }


def _por_protocolo(compiladas: list) -> tuple[list, dict]:
    curinga, por_protocolo = [], defaultdict(list)
    for indice, entrada in enumerate(compiladas):
        if entrada["protocol"] is None:
            curinga.append(indice)
        else:
            por_protocolo[int(entrada["protocol"])].append(indice)
    return curinga, por_protocolo


def medir(caminho: Path, conf: dict) -> dict:
    global_ = [compile_entry(e, i) for i, e in enumerate(conf["entradas"])]
    strong = [compile_entry(e, i) for i, e in enumerate(conf["retidas"])]
    g_curinga, g_proto = _por_protocolo(global_)
    s_curinga, s_proto = _por_protocolo(strong)

    rotulos = {est: [group_key(e, est) for e in conf["retidas"]] for est in ESTRATEGIAS}
    regras_do_grupo = {}
    for est in ESTRATEGIAS:
        grupos = defaultdict(set)
        for indice, rotulo in enumerate(rotulos[est]):
            grupos[rotulo].update(conf["retidas"][indice]["provenance"]["source_rule_ids"])
        regras_do_grupo[est] = grupos

    total = elegiveis = 0
    global_candidatos = strong_candidatos = 0
    tamanhos = []
    agrupados = {est: [] for est in ESTRATEGIAS}

    for quadro in quadros(caminho):
        total += 1
        pacote, _motivo = parse_frame_like_p4(quadro)
        if pacote is None:
            continue
        elegiveis += 1
        protocolo = pacote["protocol"]
        if any(
            compiled_entry_matches_packet(global_[i], pacote)
            for i in g_curinga + g_proto.get(protocolo, [])
        ):
            global_candidatos += 1
        casadas = [
            i for i in s_curinga + s_proto.get(protocolo, [])
            if compiled_entry_matches_packet(strong[i], pacote)
        ]
        if casadas:
            strong_candidatos += 1
        regras = set()
        for indice in casadas:
            regras.update(conf["retidas"][indice]["provenance"]["source_rule_ids"])
        tamanhos.append(len(regras))
        for est in ESTRATEGIAS:
            ativos = {rotulos[est][i] for i in casadas}
            uniao = set()
            for rotulo in ativos:
                uniao |= regras_do_grupo[est][rotulo]
            agrupados[est].append(len(uniao))

    base = conf["elegiveis"]
    sempre = conf["fallback"] + conf["unsupported"]
    media = statistics.fmean(tamanhos) if tamanhos else 0.0

    def reducao(valores):
        media_valores = statistics.fmean(valores) if valores else 0.0
        return {
            "sobre_elegiveis_pct": 100.0 * (1 - media_valores / base) if base else 0.0,
            "sobre_ruleset_pct": 100.0 * (1 - (media_valores + sempre) / RULESET),
        }

    return {
        "quadros": total,
        "elegiveis": elegiveis,
        "global_candidatos": global_candidatos,
        "global_candidato_pct": 100.0 * global_candidatos / elegiveis if elegiveis else 0.0,
        "strong_candidatos": strong_candidatos,
        "strong_no_match": elegiveis - strong_candidatos,
        "strong_candidato_pct": 100.0 * strong_candidatos / elegiveis if elegiveis else 0.0,
        "candidate_set_por_entrada": {**stats(tamanhos), "reducao": reducao(tamanhos)},
        "candidate_set_agrupado": {
            est: {**stats(valores), "reducao": reducao(valores)} for est, valores in agrupados.items()
        },
        "media_candidate_set": media,
    }


def reproduz(nome: str, medido: dict) -> list[str]:
    esperado = CONGELADO.get(nome)
    if esperado is None:
        return []
    divergencias = []
    for chave, valor in esperado.items():
        if isinstance(valor, float):
            if abs(medido[chave] - valor) > 1e-9:
                divergencias.append(f"{nome}.{chave}: {medido[chave]} != {valor}")
        elif medido[chave] != valor:
            divergencias.append(f"{nome}.{chave}: {medido[chave]} != {valor}")
    return divergencias


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--janela", action="append", default=[], help="nome=caminho.pcap")
    parser.add_argument("--semantica", choices=("legacy", "snort3", "ambas"), default="ambas")
    parser.add_argument(
        "--sem-validacao",
        action="store_true",
        help="nao exige reproduzir o congelado (so para exercitar o codigo com outro pcap)",
    )
    parser.add_argument("--saida", type=Path, default=SAIDA)
    argumentos = parser.parse_args()

    janelas = dict(JANELAS_PADRAO)
    if argumentos.janela:
        janelas = dict(item.split("=", 1) for item in argumentos.janela)
    for nome, caminho in janelas.items():
        if not Path(caminho).exists():
            print(f"pcap ausente: {nome} = {caminho}", file=sys.stderr)
            return 1

    relatorio = {
        "analise": "trace_metrics_by_semantics",
        "gerado_em": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "gerador": "tests/rederive_trace_metrics.py",
        "janelas": janelas,
        "validacao_contra_congelado": not argumentos.sem_validacao,
    }

    if argumentos.semantica in ("legacy", "ambas"):
        conf = configuracao(PROJECT_ROOT / "output")
        medidas = {nome: medir(Path(caminho), conf) for nome, caminho in janelas.items()}
        if not argumentos.sem_validacao:
            divergencias = [d for nome, m in medidas.items() for d in reproduz(nome, m)]
            if divergencias:
                print("legacy nao reproduz o congelado; nada gravado:", file=sys.stderr)
                for linha in divergencias:
                    print(f"  {linha}", file=sys.stderr)
                return 1
        relatorio["legacy"] = {
            "particao": {k: conf[k] for k in ("elegiveis", "fallback", "unsupported")},
            "janelas": medidas,
        }

    if argumentos.semantica in ("snort3", "ambas"):
        try:
            with saida_snort3() as saida:
                conf = configuracao(saida)
                medidas = {nome: medir(Path(caminho), conf) for nome, caminho in janelas.items()}
        except EstagioFalhou as erro:
            print(f"estagio do pipeline snort3 falhou: {erro}", file=sys.stderr)
            return 1
        relatorio["snort3"] = {
            "particao": {k: conf[k] for k in ("elegiveis", "fallback", "unsupported")},
            "janelas": medidas,
        }

    argumentos.saida.write_text(
        json.dumps(relatorio, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )

    for semantica in ("legacy", "snort3"):
        if semantica not in relatorio:
            continue
        print(f"== {semantica}  particao {relatorio[semantica]['particao']}")
        for nome, m in relatorio[semantica]["janelas"].items():
            entrada = m["candidate_set_por_entrada"]
            protocolo = m["candidate_set_agrupado"]["protocol"]
            print(
                f"  {nome:<11} strong {m['strong_candidato_pct']:.3f}%  "
                f"C(x) media {entrada['mean']:.2f} "
                f"(reducao {entrada['reducao']['sobre_elegiveis_pct']:.2f}% / "
                f"{entrada['reducao']['sobre_ruleset_pct']:.2f}% do ruleset)  "
                f"agrupado por protocolo {protocolo['mean']:.2f}"
            )
    print(f"gravado em {argumentos.saida}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Cobertura dos alertas observados pelo plano strong, sob legacy e snort3.

O manuscrito relata, para o Brute Force held-out, que o plano
strong-discriminator cobre os 2.391 alertas do Snort FULL: 2.289 eventos de
regras P4-elegiveis, todos com a SID do alerta no candidate set do pacote, e
102 de regras em fallback
(`output/experiments/cicids2017_thursday_bruteforce/strong_discriminator_alert_audit.json`,
`candidate_set_alert_membership.json`). Isso foi medido com os predicados
congelados. Este estagio refaz a auditoria sobre as janelas e a repete com o
compilador em `--service-header-semantics snort3`
(paper/IDS_P4/SERVICE_BASED_HEADER_FINDING.md).

Para cada alerta de `baseline_full.jsonl` (sid, pkt_num), o pacote e o
`pkt_num`-esimo quadro da janela. Antes de contar, confere que os enderecos
do quadro sao os do alerta: e isso que garante que a numeracao do Snort e a
do pcap cortado coincidem. Depois classifica o evento:

    fallback     a SID esta no fallback operacional ou e UNSUPPORTED: o Snort
                 a avalia em todo pacote
    coberto      a SID e P4-elegivel e esta no candidate set do pacote (uniao
                 da proveniencia das entradas retidas que casam)
    dominio      o quadro esta fora do dominio suportado: candidato por
                 fail-open
    faltando     nenhum dos tres

No legacy, o Brute Force tem de reproduzir 2.289 / 102 / 0; se nao
reproduzir, nada e gravado.

E auditoria OFFLINE de pertinencia por evento, como a congelada: nao executa
o Snort com candidate sets e nao da garantia sobre estado entre pacotes.

Codigos de saida:
    0   auditoria gravada
    1   entrada ausente, enderecos divergentes, estagio snort3 falhou ou o
        legacy nao reproduz o congelado

Uso:
    python tests/rederive_alert_coverage_by_semantics.py --janela sqli=... --janela xss=... --janela bruteforce=...
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import sys

from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "tests"))

import campaign_matcher  # noqa: E402,F401  (marcador de scapy fora do rig)
from analyze_prefilter_selectivity import (  # noqa: E402
    compile_entry,
    compiled_entry_matches_packet,
    parse_frame_like_p4,
)
from rederive_trace_metrics import quadros, sha256_do_arquivo  # noqa: E402
from simulate_operational_policy import (  # noqa: E402
    simulate_rule_partition,
    summarize_semantic_rules,
)
from whatif_service_header_semantics import EstagioFalhou, _git, saida_snort3  # noqa: E402

SAIDA = PROJECT_ROOT / "output" / "analysis" / "alert_coverage_by_semantics.json"
EXPERIMENTOS = PROJECT_ROOT / "output" / "experiments"

# Artefatos do pipeline sob a semantica legacy. Ate 2026-10-05 eram a raiz
# de output/; desde a troca do padrao para snort3 estao arquivados aqui
# (paper/IDS_P4/HEADER_SEMANTICS_DEFAULT_SUPERSESSION.md).
LEGADO = PROJECT_ROOT / "output" / "historical" / "legacy_header_semantics"
HOME_NET = ipaddress.ip_network("192.168.10.0/24")
EXPERIMENTO = {
    "sqli": "cicids2017_thursday_sqli",
    "xss": "cicids2017_thursday_xss",
    "bruteforce": "cicids2017_thursday_bruteforce",
}

# Auditoria congelada do held-out que o legacy tem de reproduzir.
CONGELADO = {"bruteforce": {"elegiveis": 2289, "fallback": 102, "cobertos": 2289, "faltando": 0}}


def configuracao(saida: Path) -> dict:
    manifesto = json.loads((saida / "semantic_manifest.json").read_text(encoding="utf-8"))
    entradas = json.loads((saida / "p4_install_entries.json").read_text(encoding="utf-8"))["entries"]
    particao = simulate_rule_partition(
        entradas, summarize_semantic_rules(manifesto), "strong_discriminator", HOME_NET
    )
    retidas = [entrada for _indice, entrada, _registro in particao["retained_entries"]]
    unsupported = {
        str(r["rule_id"]) for r in manifesto["rules"] if r["classification"] == "UNSUPPORTED"
    }
    return {
        "global": [compile_entry(e, i) for i, e in enumerate(entradas)],
        "retidas": retidas,
        "strong": [compile_entry(e, i) for i, e in enumerate(retidas)],
        "elegiveis": {str(s) for s in particao["eligible_sids"]},
        "sempre": {str(s) for s in particao["fallback_sids"]} | unsupported,
    }


def alertas(nome: str) -> list[dict]:
    caminho = EXPERIMENTOS / EXPERIMENTO[nome] / "baseline_full.jsonl"
    return [json.loads(linha) for linha in caminho.read_text(encoding="utf-8").splitlines() if linha.strip()]


def pacotes_dos_alertas(caminho: Path, eventos: list[dict]) -> dict[int, bytes]:
    """pkt_num -> quadro, para os pacotes que tem alerta (numeracao do Snort, 1-based)."""

    alvo = {e["pkt_num"] for e in eventos}
    ultimo = max(alvo)
    achados = {}
    for numero, quadro in enumerate(quadros(caminho), start=1):
        if numero in alvo:
            achados[numero] = quadro
        if numero >= ultimo:
            break
    return achados


def auditar(eventos: list[dict], pacotes: dict[int, bytes], conf: dict) -> dict:
    contagem = Counter()
    por_sid = defaultdict(Counter)
    global_candidato = 0
    for evento in eventos:
        sid = str(evento["sid"])
        pacote, _motivo = parse_frame_like_p4(pacotes[evento["pkt_num"]])
        if pacote is None or any(compiled_entry_matches_packet(e, pacote) for e in conf["global"]):
            global_candidato += 1
        if sid in conf["sempre"]:
            classe = "fallback"
        elif sid not in conf["elegiveis"]:
            classe = "sid_desconhecida"
        elif pacote is None:
            classe = "dominio"
        else:
            candidatas = set()
            for entrada, compilada in zip(conf["retidas"], conf["strong"]):
                if compiled_entry_matches_packet(compilada, pacote):
                    candidatas.update(str(s) for s in entrada["provenance"]["source_rule_ids"])
            classe = "cobertos" if sid in candidatas else "faltando"
        contagem[classe] += 1
        por_sid[sid][classe] += 1
    return {
        "alertas": len(eventos),
        "elegiveis": len(eventos) - contagem["fallback"] - contagem["sid_desconhecida"],
        "fallback": contagem["fallback"],
        "cobertos": contagem["cobertos"],
        "dominio": contagem["dominio"],
        "faltando": contagem["faltando"],
        "sid_desconhecida": contagem["sid_desconhecida"],
        "global_candidato": global_candidato,
        "por_sid": {sid: dict(c) for sid, c in sorted(por_sid.items(), key=lambda t: int(t[0]))},
    }


def conferir_enderecos(eventos: list[dict], pacotes: dict[int, bytes]) -> tuple[list[str], list[dict]]:
    """Divergencias de endereco e eventos em sentido inverso.

    Um alerta de dados remontados pelo stream sai com o pkt_num do quadro que
    provocou o flush, em geral o ACK do sentido oposto: mesmos enderecos,
    trocados. Isso e aceito e registrado; qualquer outra diferenca invalida a
    numeracao.
    """

    divergencias, inversos = [], []
    for evento in eventos:
        quadro = pacotes.get(evento["pkt_num"])
        if quadro is None:
            divergencias.append(f"pkt_num {evento['pkt_num']} ausente")
            continue
        pacote, _motivo = parse_frame_like_p4(quadro)
        if pacote is None:
            continue
        origem = str(ipaddress.ip_address(pacote["src_ip"]))
        destino = str(ipaddress.ip_address(pacote["dst_ip"]))
        alerta = (evento["src_addr"], evento["dst_addr"])
        if (origem, destino) == alerta:
            continue
        if (destino, origem) == alerta:
            inversos.append({"pkt_num": evento["pkt_num"], "sid": evento["sid"]})
            continue
        divergencias.append(
            f"pkt_num {evento['pkt_num']}: quadro {origem}->{destino}, "
            f"alerta {evento['src_addr']}->{evento['dst_addr']}"
        )
    return divergencias, inversos


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--janela", action="append", required=True, help="nome=caminho.pcap")
    parser.add_argument("--saida", type=Path, default=SAIDA)
    argumentos = parser.parse_args()
    janelas = dict(item.split("=", 1) for item in argumentos.janela)
    for nome, caminho in janelas.items():
        if nome not in EXPERIMENTO or not Path(caminho).exists():
            print(f"janela invalida ou pcap ausente: {nome} = {caminho}", file=sys.stderr)
            return 1

    eventos = {nome: alertas(nome) for nome in janelas}
    pacotes = {nome: pacotes_dos_alertas(Path(c), eventos[nome]) for nome, c in janelas.items()}
    inversos = {}
    for nome in janelas:
        divergencias, inversos[nome] = conferir_enderecos(eventos[nome], pacotes[nome])
        if divergencias:
            print(f"{nome}: numeracao do pcap nao coincide com a do Snort:", file=sys.stderr)
            for linha in divergencias[:10]:
                print(f"  {linha}", file=sys.stderr)
            return 1

    relatorio = {
        "analise": "alert_coverage_by_semantics",
        "commit": _git("rev-parse", "HEAD"),
        "gerado_em": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "gerador": "tests/rederive_alert_coverage_by_semantics.py",
        "janelas": janelas,
        "janelas_sha256": {nome: sha256_do_arquivo(Path(c)) for nome, c in janelas.items()},
        "alertas_no_quadro_de_sentido_inverso": inversos,
        "nota": (
            "Pertinencia por evento, offline: parser espelhado do P4 e casador de "
            "entradas. Enderecos de cada alerta conferidos com o quadro de mesmo pkt_num; "
            "alertas de dados remontados saem no quadro do sentido oposto e sao listados."
        ),
    }

    legacy = configuracao(LEGADO)
    relatorio["legacy"] = {nome: auditar(eventos[nome], pacotes[nome], legacy) for nome in janelas}
    for nome, esperado in CONGELADO.items():
        if nome not in relatorio["legacy"]:
            continue
        medido = relatorio["legacy"][nome]
        diverge = {k: (medido[k], v) for k, v in esperado.items() if medido[k] != v}
        if diverge:
            print(f"legacy nao reproduz o congelado em {nome}: {diverge}; nada gravado", file=sys.stderr)
            return 1

    try:
        with saida_snort3() as saida:
            snort3 = configuracao(saida)
            relatorio["snort3"] = {nome: auditar(eventos[nome], pacotes[nome], snort3) for nome in janelas}
    except EstagioFalhou as erro:
        print(f"estagio do pipeline snort3 falhou: {erro}", file=sys.stderr)
        return 1

    argumentos.saida.write_text(
        json.dumps(relatorio, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    for semantica in ("legacy", "snort3"):
        print(f"== {semantica}")
        for nome, m in relatorio[semantica].items():
            print(
                f"  {nome:<11} alertas {m['alertas']:>5}  elegiveis {m['elegiveis']:>5}  "
                f"cobertos {m['cobertos']:>5}  fallback {m['fallback']:>5}  dominio {m['dominio']}  "
                f"faltando {m['faltando']}  global {m['global_candidato']}  por sid {m['por_sid']}"
            )
    print(f"gravado em {argumentos.saida}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

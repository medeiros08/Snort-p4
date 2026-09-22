#!/usr/bin/env python3
"""Gera os casos da campanha end-to-end: pcap, expectativas e proveniencia.

Cada caso simula um uso real do prefilter de ponta a ponta para uma regra do
ruleset: um fluxo TCP completo com a testemunha que deve fazer o Snort
alertar, mais dois vizinhos negativos que medem o que o prefilter faz quando a
regra **nao** se aplica.

    handshake          SYN / SYN-ACK / ACK na direcao que o `flow` da regra
                       exige
    testemunha         pacote que satisfaz header e content da regra
    negativo_payload   mesma 5-tupla, payload sem o content da regra. O Snort
                       nao deve alertar e o P4 ainda deve marcar candidate,
                       porque o prefilter decide por header: e exatamente o
                       excesso conservador que a seletividade operacional mede
    negativo_header    porta de destino fora do dominio das entradas
                       instaladas. Nem Snort nem P4 devem reagir; e o controle
                       negativo do proprio prefilter

Atribuicao de alerta a caso e por tempo: cada caso ocupa um segundo distinto
no pcap, e os quadros do caso variam so em microssegundos. Assim o alerta do
Snort casa com o caso pelo par (segundo, sid), sem depender de numeracao de
pacote, que muda se o replay reordenar.

O veredito por caso e do orquestrador que roda no rig. Aqui so se produz
entrada reproduzivel: mesma semente, mesmos bytes.

Uso:
    python tests/generate_campaign_cases.py --n 1000
    python tests/generate_campaign_cases.py --n 50 --nome piloto
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import struct
import sys

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "tests"))

from campaign_matcher import carregar_entradas, predizer  # noqa: E402
from campaign_witness import (  # noqa: E402
    MANIFESTO_SEMANTICO,
    quadros_com_papel,
    quadros_do_caso,
    sintetizar_caso,
)
from p4_packet_domain import classify_frame_for_prefilter  # noqa: E402


SAIDA_BASE = PROJECT_ROOT / "output" / "campaign"

# Variantes tentadas para o controle negativo de header, em ordem. Trocar so
# a porta de destino NAO basta: das 331 entradas instaladas, muitas nao
# restringem dst_port, e 53 casam apenas protocolo mais src_ip/src_port. A
# segunda variante tira os dois enderecos da HOME_NET, porque p4-40 e p4-138
# casam qualquer pacote que toque 192.168.10.0/24.
#
# Para TCP nao existe variante que escape: p4-106 casa `protocol == 6` e nada
# mais, entao todo pacote TCP no dominio suportado e candidate por
# construcao. Nesse caso o quadro nao e emitido e o caso registra a
# impossibilidade com a entrada que a causa.
PORTA_NEGATIVA = 63001
IP_EXTERNO_A = "198.51.100.7"
IP_EXTERNO_B = "203.0.113.9"

# Base de tempo fixa: a campanha precisa de bytes reproduziveis, e timestamp
# de geracao entraria no pcap como ruido que muda a cada execucao.
EPOCA_BASE = 1_700_000_000


def _escrever_pcap(caminho: Path, itens: list[tuple[int, int, bytes]]) -> str:
    """Escreve o pcap e devolve o sha256 do arquivo.

    Formato classico, link-type Ethernet, sem dependencia de terceiros — o
    gerador roda na maquina Windows onde o repositorio vive, sem scapy.
    """

    digest = hashlib.sha256()

    with open(caminho, "wb") as destino:
        cabecalho = struct.pack("!IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        destino.write(cabecalho)
        digest.update(cabecalho)

        for segundos, micros, quadro in itens:
            registro = struct.pack(
                "!IIII", segundos, micros, len(quadro), len(quadro)
            ) + quadro
            destino.write(registro)
            digest.update(registro)

    return digest.hexdigest()


def _endereco_por_indice(indice: int) -> str:
    """Endereco distinto por caso, fora da HOME_NET avaliada.

    Faixa 100.64.0.0/10 (CGNAT): nao colide com 192.168.10.0/24, cabe em
    qualquer `any` de regra e da 65 mil enderecos, folga de sobra para mil
    casos.
    """

    return f"100.64.{(indice // 256) % 256}.{indice % 256}"


def _payload_negativo(caso: dict) -> bytes:
    """Payload que nao contem nenhum content da regra.

    Para caso HTTP mantem um request bem-formado, senao o http_inspect nem
    preenche buffer e o negativo deixaria de exercitar o mesmo caminho de
    inspecao que a testemunha exercita.
    """

    if caso["detalhe_payload"].get("http"):
        return (
            b"GET /index.html HTTP/1.1\r\n"
            b"Host: campanha.local\r\n"
            b"User-Agent: campanha-e2e/1\r\n"
            b"Connection: close\r\n\r\n"
        )
    return b"campanha-negativo-sem-content"


def _estrato(caso: dict) -> str:
    protocolo = caso["header"]["protocolo"]
    http = "http" if caso["detalhe_payload"].get("http") else "cru"
    return f"{protocolo}/{http}/{caso['direcao']}"


def selecionar(casos: list[dict], quantos: int, semente: int) -> list[dict]:
    """Amostra estratificada e deterministica.

    Estratifica por (protocolo, buffer http ou cru, direcao do flow) para que a
    campanha nao vire mil variacoes do mesmo caminho: sem isso a amostra fica
    dominada por HTTP to_server, que e a maioria do ruleset, e os caminhos de
    UDP, ICMP e to_client quase desaparecem.
    """

    por_estrato: dict[str, list[dict]] = {}
    for caso in casos:
        por_estrato.setdefault(_estrato(caso), []).append(caso)

    for lista in por_estrato.values():
        lista.sort(key=lambda c: int(c["rule_id"]) if str(c["rule_id"]).isdigit() else 0)

    aleatorio = random.Random(semente)
    escolhidos: list[dict] = []

    # Rodada proporcional: cada estrato contribui na proporcao do seu tamanho,
    # com pelo menos um caso quando houver.
    total = sum(len(v) for v in por_estrato.values())
    restante = quantos

    for chave in sorted(por_estrato):
        lista = por_estrato[chave]
        cota = max(1, round(quantos * len(lista) / total))
        cota = min(cota, len(lista), restante)
        if cota <= 0:
            continue
        escolhidos.extend(aleatorio.sample(lista, cota))
        restante -= cota

    # Completa com o que sobrou, se o arredondamento deixou folga.
    if restante > 0:
        ja = {id(c) for c in escolhidos}
        sobra = [c for c in casos if id(c) not in ja]
        sobra.sort(key=lambda c: int(c["rule_id"]) if str(c["rule_id"]).isdigit() else 0)
        escolhidos.extend(aleatorio.sample(sobra, min(restante, len(sobra))))

    escolhidos.sort(key=lambda c: int(c["rule_id"]) if str(c["rule_id"]).isdigit() else 0)
    return escolhidos[:quantos]


def _negativo_de_header(caso: dict, header: dict, entradas: list):
    """Procura um header que nenhuma entrada instalada cubra.

    Devolve (quadro, variante, None) quando acha, ou (None, None, entrada) com
    a entrada que impede o escape. Verificado contra o casador de referencia
    na propria geracao: controle negativo que casa nao controla nada, e
    descobrir isso no rig custaria um ciclo inteiro.
    """

    payload = _payload_negativo(caso)

    variantes = [
        {**header, "dst_port": PORTA_NEGATIVA},
        {
            **header,
            "src_ip": IP_EXTERNO_A,
            "dst_ip": IP_EXTERNO_B,
            "src_port": 0 if header["protocolo"] == "icmp" else PORTA_NEGATIVA,
            "dst_port": 0 if header["protocolo"] == "icmp" else PORTA_NEGATIVA + 1,
        },
    ]

    ultimo_detalhe = None
    for variante in variantes:
        quadro = quadros_do_caso(
            variante, payload, False, caso["direcao"], False, caso.get("icmp")
        )[-1]
        categoria, detalhe = predizer(entradas, quadro)
        if categoria == "P4_NO_MATCH":
            return quadro, variante, None
        ultimo_detalhe = detalhe

    return None, None, ultimo_detalhe


def montar(
    caso: dict, indice: int, entradas: list
) -> tuple[dict, list[tuple[int, int, bytes]]]:
    """Monta os quadros de um caso e o registro de expectativa."""

    payload = bytes.fromhex(caso["payload_hex"])
    http = bool(caso["detalhe_payload"].get("http"))

    # 5-tupla propria por caso, usando o primeiro campo que a regra deixa
    # livre. Isso nao e cosmetico: casos que compartilham a tupla caem na
    # mesma sessao do Snort e passam a interferir um no outro. Medido — a
    # regra 27086, que casa conteudo cru em `$HTTP_PORTS -> any`, parou de
    # alertar quando outro caso da mesma tupla trocou o payload por uma
    # resposta HTTP, porque o http_inspect passou a reassemblar aquele stream.
    # Interferencia entre casos destroi a independencia da medicao, que e a
    # premissa de contar veredito por caso.
    header = dict(caso["header"])
    if header.get("src_port_livre"):
        header["src_port"] = 20000 + (indice % 40000)
    elif header.get("src_ip_livre"):
        header["src_ip"] = _endereco_por_indice(indice)
    elif header.get("dst_ip_livre"):
        header["dst_ip"] = _endereco_por_indice(indice)
    elif header.get("dst_port_livre"):
        header["dst_port"] = 20000 + (indice % 40000)
    else:
        header["tupla_compartilhada"] = True

    com_papel = quadros_com_papel(
        header, payload, caso["com_handshake"], caso["direcao"], http, caso.get("icmp")
    )

    negativo_payload = quadros_do_caso(
        header, _payload_negativo(caso), False, caso["direcao"], False, caso.get("icmp")
    )[-1]
    com_papel = com_papel + [("negativo_payload", negativo_payload)]

    negativo_header, variante, coberto_por = _negativo_de_header(caso, header, entradas)
    if negativo_header is not None:
        com_papel = com_papel + [("negativo_header", negativo_header)]

    papeis = [papel for papel, _ in com_papel]
    quadros = [quadro for _, quadro in com_papel]

    segundos = EPOCA_BASE + indice
    itens: list[tuple[int, int, bytes]] = []
    registros_quadro = []

    for posicao, (papel, quadro) in enumerate(zip(papeis, quadros)):
        micros = posicao * 1000
        itens.append((segundos, micros, quadro))
        pacote, motivo = classify_frame_for_prefilter(quadro)
        previsto, detalhe = predizer(entradas, quadro)
        registros_quadro.append(
            {
                "papel": papel,
                "ts_s": segundos,
                "ts_us": micros,
                "bytes": len(quadro),
                "dominio_p4": "SUPORTADO" if pacote is not None else motivo,
                "p4_previsto": previsto,
                "p4_previsto_detalhe": detalhe,
            }
        )

    registro = {
        "indice": indice,
        "sid": caso["rule_id"],
        "ts_s": segundos,
        "header": header,
        "quadros_no_caso": len(quadros),
        "direcao": caso["direcao"],
        "flow": caso["flow"],
        "com_handshake": caso["com_handshake"],
        "icmp": caso.get("icmp"),
        "payload_bytes": caso["payload_bytes"],
        "estrato": _estrato(caso),
        "quadros": registros_quadro,
        "esperado": {
            "testemunha": {
                "snort_alerta_sid": True,
                "p4": "P4_CANDIDATE",
            },
            "negativo_payload": {
                "snort_alerta_sid": False,
                "p4": "P4_CANDIDATE",
                "nota": "prefilter decide por header; candidate sem alerta e o excesso conservador medido",
            },
            "negativo_header": (
                {"snort_alerta_sid": False, "p4": "P4_NO_MATCH"}
                if negativo_header is not None
                else {
                    "p4": "IMPOSSIVEL",
                    "coberto_por": coberto_por,
                    "motivo": "nenhum header escapa das entradas instaladas para este protocolo",
                }
            ),
        },
    }

    return registro, itens


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--n", type=int, default=1000, help="numero de casos")
    parser.add_argument("--semente", type=int, default=20260918)
    parser.add_argument("--nome", default=None, help="nome do diretorio da campanha")
    argumentos = parser.parse_args()

    if not MANIFESTO_SEMANTICO.exists():
        print(f"manifesto ausente: {MANIFESTO_SEMANTICO}", file=sys.stderr)
        return 1

    entradas = carregar_entradas()

    bruto = MANIFESTO_SEMANTICO.read_bytes()
    manifesto = json.loads(bruto.decode("utf-8"))
    regras = manifesto["rules"]

    utilizaveis = []
    recusas = Counter()
    for regra in regras:
        caso = sintetizar_caso(regra)
        if caso["utilizavel"]:
            utilizaveis.append(caso)
        else:
            for motivo in caso["motivos_de_recusa"]:
                recusas[motivo.split(":")[0]] += 1

    if len(utilizaveis) < argumentos.n:
        print(
            f"casos utilizaveis ({len(utilizaveis)}) menores que o pedido "
            f"({argumentos.n}); gerando {len(utilizaveis)}",
            file=sys.stderr,
        )

    escolhidos = selecionar(utilizaveis, min(argumentos.n, len(utilizaveis)), argumentos.semente)

    nome = argumentos.nome or f"e2e_{len(escolhidos)}"
    destino = SAIDA_BASE / nome
    destino.mkdir(parents=True, exist_ok=True)

    registros = []
    itens: list[tuple[int, int, bytes]] = []
    for indice, caso in enumerate(escolhidos):
        registro, quadros = montar(caso, indice, entradas)
        registros.append(registro)
        itens.extend(quadros)

    caminho_pcap = destino / "campanha.pcap"
    sha_pcap = _escrever_pcap(caminho_pcap, itens)

    caminho_casos = destino / "casos.jsonl"
    with open(caminho_casos, "w", encoding="utf-8", newline="\n") as saida:
        for registro in registros:
            saida.write(json.dumps(registro, ensure_ascii=False, sort_keys=True) + "\n")

    fora_do_dominio = [
        (r["sid"], q["papel"], q["dominio_p4"])
        for r in registros
        for q in r["quadros"]
        if q["dominio_p4"] != "SUPORTADO"
    ]

    estratos = Counter(r["estrato"] for r in registros)

    tuplas_compartilhadas = sum(
        1 for r in registros if r["header"].get("tupla_compartilhada")
    )
    negativo_impossivel = sum(
        1
        for r in registros
        if r["esperado"]["negativo_header"].get("p4") == "IMPOSSIVEL"
    )
    testemunhas_no_match = sum(
        1
        for r in registros
        for q in r["quadros"]
        if q["papel"] == "testemunha" and q.get("p4_previsto") != "P4_CANDIDATE"
    )
    cobertura_do_impossivel = Counter(
        r["esperado"]["negativo_header"].get("coberto_por")
        for r in registros
        if r["esperado"]["negativo_header"].get("p4") == "IMPOSSIVEL"
    )

    proveniencia = {
        "gerado_em": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "gerador": "tests/generate_campaign_cases.py",
        "semente": argumentos.semente,
        "casos": len(registros),
        "quadros": len(itens),
        "pcap_sha256": sha_pcap,
        "manifesto_semantico": {
            "caminho": str(MANIFESTO_SEMANTICO.relative_to(PROJECT_ROOT)).replace("\\", "/"),
            "sha256": hashlib.sha256(bruto).hexdigest(),
            "regras": len(regras),
            "ruleset": manifesto.get("ruleset"),
        },
        "regras_utilizaveis": len(utilizaveis),
        "recusas": dict(recusas),
        "estratos": dict(estratos),
        "quadros_fora_do_dominio_p4": len(fora_do_dominio),
        "porta_negativa": PORTA_NEGATIVA,
        "entradas_instaladas": len(entradas),
        "casos_com_tupla_compartilhada": tuplas_compartilhadas,
        "negativo_header_impossivel": negativo_impossivel,
        "negativo_header_coberto_por": dict(cobertura_do_impossivel),
        "testemunhas_previstas_fora_de_candidate": testemunhas_no_match,
    }

    caminho_prov = destino / "proveniencia.json"
    caminho_prov.write_text(
        json.dumps(proveniencia, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )

    print(f"casos gerados        {len(registros)}")
    print(f"quadros no pcap      {len(itens)}")
    print(f"pcap                 {caminho_pcap.relative_to(PROJECT_ROOT)}")
    print(f"sha256 do pcap       {sha_pcap[:16]}...")
    print(f"casos.jsonl          {caminho_casos.relative_to(PROJECT_ROOT)}")
    print(f"proveniencia         {caminho_prov.relative_to(PROJECT_ROOT)}")
    print(f"tupla compartilhada  {tuplas_compartilhadas} caso(s)")
    print(f"negativo impossivel  {negativo_impossivel} caso(s)")
    print(f"testemunha fora de candidate  {testemunhas_no_match} caso(s)")
    print("\nestratos:")
    for chave, quantos in sorted(estratos.items()):
        print(f"  {quantos:5d}  {chave}")

    if fora_do_dominio:
        print(
            f"\nFALHA: {len(fora_do_dominio)} quadro(s) fora do dominio do parser P4.",
            file=sys.stderr,
        )
        for sid, papel, motivo in fora_do_dominio[:5]:
            print(f"  sid {sid} ({papel}): {motivo}", file=sys.stderr)
        return 1

    print("\nGERACAO OK: todo quadro cai no dominio suportado do parser.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

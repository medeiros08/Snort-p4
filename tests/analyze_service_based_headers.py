#!/usr/bin/env python3
"""Exposicao das regras service-based ao cabecalho que o Snort 3 nao avalia.

O compilador assume que um alerta do Snort implica o cabecalho da regra:
`r(x) => H_r(x)`, e deriva `p_r` de `H_r`. No Snort 3.12.2.0 isso nao vale
para regra service-based quando o servico do fluxo casa com o da regra:

    src/detection/detection_options.cc   se o snort_protocol_id do pacote e
                                         um dos servicos da regra,
                                         check_ports = 0; se o servico e
                                         conhecido e nao e da regra, a regra
                                         e rejeitada
    src/detection/rtn_checks.cc          com check_ports = 0, CheckSrcPort*/
                                         CheckDstPort* passam direto e
                                         CheckProto devolve 1; CheckSrcIP e
                                         CheckDstIP rodam sempre
    src/parser/parse_rule.cc             SetupRTNFuncList encadeia porta de
                                         destino, porta de origem, IP de
                                         origem, IP de destino e, por ultimo,
                                         protocolo
    docs/vendor/snort3/doc/user/concepts.txt:290-296
                                         "For a service-based rule,
                                         evaluation of the header is skipped"

Logo, para uma regra com `service:`, so as condicoes de IP sao necessarias:
porta e protocolo do cabecalho deixam de ser condicao do alerta quando o
servico e identificado, por exemplo pelo wizard, que o `snort.lua` padrao
incluido por `config/snort3_experiment.lua` liga. Um predicado P4 que
restringe porta ou protocolo pode ser falso num pacote em que a regra
alerta.

Este estagio mede o tamanho disso sobre os artefatos atuais, sem alterar
nenhum:

    regras NECESSARY com `service:` explicito, e quantas delas tem porta,
    protocolo ou flags nos predicados seletivos
    cobertura no plano: a regiao {IPs da regra} x {qualquer porta} x
    {qualquer protocolo} esta contida em alguma entrada instalada sem porta
    nem protocolo? Se so a parte TCP e coberta (por uma entrada de protocolo
    6 sem porta), registra a parte coberta
    o que sobraria de H_r mantendo so as condicoes de IP

Regras que usam opcao especifica de servico (http_*, file_data...) sem
`service:` explicito sao contadas a parte e ficam fora das contagens
principais: o corpus diz que tambem viram service-based, mas o mecanismo nao
foi confirmado no codigo.

Codigos de saida:
    0   artefato gravado
    1   entrada ausente

Uso:
    python tests/analyze_service_based_headers.py
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import sys

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

MANIFESTO = PROJECT_ROOT / "output" / "semantic_manifest.json"
PLANOS = {
    "global": PROJECT_ROOT / "output" / "p4_install_entries.json",
    "strong_discriminator": PROJECT_ROOT
    / "output"
    / "campaign"
    / "plano_strong_discriminator"
    / "p4_install_entries.json",
}
PARTICAO_STRONG = PROJECT_ROOT / "output" / "campaign" / "plano_strong_discriminator" / "particao.json"
SAIDA = PROJECT_ROOT / "output" / "analysis" / "service_based_header_exposure.json"

CAMPOS_NAO_IP = {"src_port", "dst_port", "protocol", "tcp_flags", "flags"}
CAMPOS_IP = {"src_ip", "dst_ip"}

# Opcoes que o corpus trata como especificas de servico. So entram na
# contagem separada de regras implicitas.
OPCAO_DE_SERVICO = re.compile(
    r"^(http_|file_data$|dce_|dnp3_|modbus_|sip_|ssl_state$|ssl_version$|gtp_|cip_"
    r"|s7commplus_|iec104_|mms_|opcua_|js_data$|vba_data$|script_data$)"
)

EVIDENCIA = {
    "snort_versao": "3.12.2.0",
    "codigo": [
        "https://github.com/snort3/snort3/blob/3.12.2.0/src/detection/detection_options.cc",
        "https://github.com/snort3/snort3/blob/3.12.2.0/src/detection/rtn_checks.cc",
        "https://github.com/snort3/snort3/blob/3.12.2.0/src/parser/parse_rule.cc",
    ],
    "documentacao": "docs/vendor/snort3/doc/user/concepts.txt:290-296",
}


def _sha256(caminho: Path) -> str:
    return hashlib.sha256(caminho.read_bytes()).hexdigest()


def _redes(valor):
    """Conjunto de redes de um endereco resolvido; None significa any."""

    if valor in (None, "any"):
        return None
    valores = valor if isinstance(valor, list) else [valor]
    redes = []
    for item in valores:
        texto = str(item)
        if texto.startswith("!"):
            return "NEGADO"
        try:
            redes.append(ipaddress.ip_network(texto, strict=False))
        except ValueError:
            return "NAO_RESOLVIDO"
    return redes


def _rede_da_entrada(campo) -> ipaddress.IPv4Network:
    return ipaddress.ip_network(f"{campo['value']}/{campo['prefix_len']}")


def _entradas_sem_porta(caminho: Path) -> list[dict]:
    """Entradas que restringem no maximo IP e protocolo."""

    entradas = json.loads(caminho.read_text(encoding="utf-8"))["entries"]
    return [e["match"] for e in entradas if set(e["match"]) <= CAMPOS_IP | {"protocol"}]


def _contida(origem, destino, entradas: list[dict], so_tcp: bool) -> bool:
    for match in entradas:
        if "protocol" in match and not (so_tcp and match["protocol"] == 6):
            continue
        cabe = True
        for campo, regiao in (("src_ip", origem), ("dst_ip", destino)):
            if campo not in match:
                continue
            rede = _rede_da_entrada(match[campo])
            if not isinstance(regiao, list) or not all(r.subnet_of(rede) for r in regiao):
                cabe = False
                break
        if cabe:
            return True
    return False


def cobertura(origem, destino, bidirecional: bool, entradas: list[dict]) -> str:
    def cobre(so_tcp: bool) -> bool:
        ida = _contida(origem, destino, entradas, so_tcp)
        if bidirecional:
            return ida and _contida(destino, origem, entradas, so_tcp)
        return ida

    if cobre(False):
        return "qualquer_protocolo"
    if cobre(True):
        return "so_tcp"
    return "nenhuma"


def main() -> int:
    for caminho in (MANIFESTO, PARTICAO_STRONG, *PLANOS.values()):
        if not caminho.exists():
            print(f"entrada ausente: {caminho}", file=sys.stderr)
            return 1

    regras = json.loads(MANIFESTO.read_text(encoding="utf-8"))["rules"]
    elegiveis_strong = set(
        json.loads(PARTICAO_STRONG.read_text(encoding="utf-8"))["sids_no_prefilter"]
    )
    sem_porta = {nome: _entradas_sem_porta(caminho) for nome, caminho in PLANOS.items()}

    necessarias = [r for r in regras if r["classification"] == "NECESSARY"]
    com_servico = []
    implicitas = 0
    for regra in necessarias:
        opcoes = regra["parsed_rule"]["options"]
        servicos = [
            s.strip() for o in opcoes if o["name"] == "service" for s in o["value"].split(",")
        ]
        if servicos:
            com_servico.append((regra, servicos))
        elif any(OPCAO_DE_SERVICO.match(o["name"]) for o in opcoes):
            implicitas += 1

    expostas = []
    servicos_expostos = Counter()
    campos_de_h = Counter()
    so_ip_restante = Counter()
    cobertura_por_plano = {nome: Counter() for nome in PLANOS}
    nao_cobertas_global = []

    for regra, servicos in com_servico:
        seletivos = {p["field"] for p in regra["selective_predicates"]}
        if not seletivos & CAMPOS_NAO_IP:
            continue
        sid = str(regra["rule_id"])
        expostas.append(sid)
        for servico in servicos:
            servicos_expostos[servico] += 1
        campos_de_h[",".join(sorted(seletivos))] += 1
        so_ip_restante["com_ip_seletivo" if seletivos & CAMPOS_IP else "sem_predicado_seletivo"] += 1

        resolvida = regra["resolved_rule"]
        origem = _redes(resolvida["source"]["address"])
        destino = _redes(resolvida["destination"]["address"])
        bidirecional = resolvida["direction"] == "<>"
        for nome, entradas in sem_porta.items():
            tipo = cobertura(origem, destino, bidirecional, entradas)
            cobertura_por_plano[nome][tipo] += 1
            if nome == "global" and tipo != "qualquer_protocolo":
                nao_cobertas_global.append(
                    {
                        "sid": sid,
                        "servicos": servicos,
                        "protocolo_do_cabecalho": resolvida["protocol"],
                        "origem": resolvida["source"]["address"],
                        "destino": resolvida["destination"]["address"],
                        "cobertura": tipo,
                    }
                )

    relatorio = {
        "analise": "service_based_header_exposure",
        "evidencia": EVIDENCIA,
        "gerado_em": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "gerador": "tests/analyze_service_based_headers.py",
        "manifesto_sha256": _sha256(MANIFESTO),
        "necessarias": len(necessarias),
        "necessarias_com_service_explicito": len(com_servico),
        "necessarias_so_com_opcao_de_servico_nao_verificadas": implicitas,
        "expostas": {
            "definicao": "NECESSARY com service: explicito e porta, protocolo ou flags entre os predicados seletivos",
            "total": len(expostas),
            "elegiveis_no_strong_discriminator": len(set(expostas) & elegiveis_strong),
            "campos_de_h_r": dict(campos_de_h.most_common()),
            "servicos": dict(servicos_expostos.most_common()),
            "mantendo_so_condicoes_de_ip": dict(so_ip_restante),
            "sids": sorted(expostas, key=int),
        },
        "cobertura_da_regiao_sem_porta_e_protocolo": {
            "definicao": (
                "regiao {IPs da regra} x {qualquer porta} x {qualquer protocolo} contida "
                "numa entrada instalada sem porta; so_tcp quando apenas uma entrada de "
                "protocolo 6 sem porta a cobre"
            ),
            "por_plano": {nome: dict(contagem) for nome, contagem in cobertura_por_plano.items()},
            "global_sem_cobertura_total": nao_cobertas_global,
        },
        "planos": {nome: {"caminho": c.relative_to(PROJECT_ROOT).as_posix(), "sha256": _sha256(c)} for nome, c in PLANOS.items()},
    }

    SAIDA.write_text(
        json.dumps(relatorio, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )

    print(f"NECESSARY                          {len(necessarias)}")
    print(f"  com service: explicito           {len(com_servico)}")
    print(f"  expostas (porta/proto/flags em H) {len(expostas)}")
    print(f"    elegiveis no strong            {len(set(expostas) & elegiveis_strong)}")
    print(f"    mantendo so IP                 {dict(so_ip_restante)}")
    for nome, contagem in cobertura_por_plano.items():
        print(f"  cobertura no plano {nome:<21} {dict(contagem)}")
    print(f"  so opcao de servico, nao verificadas {implicitas}")
    print(f"gravado em {SAIDA.relative_to(PROJECT_ROOT).as_posix()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

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

Regras sem `service:` explicito sao separadas em dois grupos, com o
mecanismo do Snort 3.12.2.0:

    protocolo de servico no cabecalho   `alert http ...`: parse_rule.cc poe o
                                        servico na regra e a marca USER_MODE;
                                        fp_eval_rtn (fp_detect.cc) forca
                                        check_ports = 1, entao o cabecalho e
                                        checado por inteiro e nao ha exposicao
    servico implicito                   cabecalho de protocolo IP e opcao que
                                        validate_services (fp_utils.cc) usa
                                        para acrescentar servico: buffer
                                        registrado por inspetor ou prefixo de
                                        guess_service. Mesma exposicao das
                                        regras com `service:`, medida a parte

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

sys.path.insert(0, str(PROJECT_ROOT / "compiler"))
from target_capability import (  # noqa: E402
    IP_HEADER_PROTOCOLS,
    SNORT3_GUESSED_SERVICE_PREFIXES,
    SNORT3_SERVICE_BUFFERS,
)

# Servicos que os buffers DCE acrescentam: dce_tcp e dce_udp registram
# dce_iface e dce_stub_data com o servico dcerpc, dce_smb com netbios-ssn
# (src/service_inspectors/dce_rpc/dce_tcp.cc, dce_udp.cc, dce_smb.cc).
SERVICOS_DE_BUFFER = {
    "dce_iface": ["dcerpc", "netbios-ssn"],
    "dce_stub_data": ["dcerpc", "netbios-ssn"],
}


def opcoes_que_implicam_servico(nomes) -> list[str]:
    return sorted(
        {
            n
            for n in nomes
            if n in SNORT3_SERVICE_BUFFERS or n.startswith(SNORT3_GUESSED_SERVICE_PREFIXES)
        }
    )

EVIDENCIA = {
    "snort_versao": "3.12.2.0",
    "codigo": [
        "https://github.com/snort3/snort3/blob/3.12.2.0/src/detection/detection_options.cc",
        "https://github.com/snort3/snort3/blob/3.12.2.0/src/detection/rtn_checks.cc",
        "https://github.com/snort3/snort3/blob/3.12.2.0/src/parser/parse_rule.cc",
        "https://github.com/snort3/snort3/blob/3.12.2.0/src/detection/fp_detect.cc",
        "https://github.com/snort3/snort3/blob/3.12.2.0/src/detection/fp_utils.cc",
        "https://github.com/snort3/snort3/blob/3.12.2.0/src/managers/inspector_manager.cc",
        "https://github.com/snort3/snort3/blob/3.12.2.0/src/service_inspectors/dce_rpc/dce_tcp.cc",
        "https://github.com/snort3/snort3/blob/3.12.2.0/src/service_inspectors/dce_rpc/dce_udp.cc",
        "https://github.com/snort3/snort3/blob/3.12.2.0/src/service_inspectors/dce_rpc/dce_smb.cc",
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


def medir(regras_com_servicos, elegiveis_strong: set, sem_porta: dict) -> dict:
    """Exposicao e cobertura de um grupo de regras service-based."""

    expostas = []
    servicos_expostos = Counter()
    campos_de_h = Counter()
    so_ip_restante = Counter()
    cobertura_por_plano = {nome: Counter() for nome in sem_porta}
    nao_cobertas_global = []

    for regra, servicos in regras_com_servicos:
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

    return {
        "sids": sorted(expostas, key=int),
        "elegiveis_no_strong_discriminator": len(set(expostas) & elegiveis_strong),
        "campos_de_h_r": dict(campos_de_h.most_common()),
        "servicos": dict(servicos_expostos.most_common()),
        "mantendo_so_condicoes_de_ip": dict(so_ip_restante),
        "cobertura_por_plano": {nome: dict(c) for nome, c in cobertura_por_plano.items()},
        "global_sem_cobertura_total": nao_cobertas_global,
    }


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
    implicitas = []
    user_mode = []
    for regra in necessarias:
        opcoes = regra["parsed_rule"]["options"]
        servicos = [
            s.strip() for o in opcoes if o["name"] == "service" for s in o["value"].split(",")
        ]
        protocolo = str(regra["parsed_rule"]["protocol"]).lower()
        if servicos:
            com_servico.append((regra, servicos))
        elif protocolo not in IP_HEADER_PROTOCOLS:
            user_mode.append(str(regra["rule_id"]))
        else:
            implicantes = opcoes_que_implicam_servico(o["name"] for o in opcoes)
            if implicantes:
                # validate_services so recorre ao guess_service quando nenhum
                # buffer acrescentou servico.
                servicos = sorted(
                    {s for n in implicantes for s in SERVICOS_DE_BUFFER.get(n, [])}
                ) or ["nao_rastreado"]
                implicitas.append((regra, servicos))

    medida_explicita = medir(com_servico, elegiveis_strong, sem_porta)
    medida_implicita = medir(implicitas, elegiveis_strong, sem_porta)
    expostas = medida_explicita["sids"]
    so_ip_restante = medida_explicita["mantendo_so_condicoes_de_ip"]
    cobertura_por_plano = medida_explicita["cobertura_por_plano"]

    relatorio = {
        "analise": "service_based_header_exposure",
        "evidencia": EVIDENCIA,
        "gerado_em": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "gerador": "tests/analyze_service_based_headers.py",
        "manifesto_sha256": _sha256(MANIFESTO),
        "necessarias": len(necessarias),
        "necessarias_com_service_explicito": len(com_servico),
        "necessarias_com_protocolo_de_servico_no_cabecalho": {
            "definicao": (
                "sem service:, cabecalho com protocolo de servico: USER_MODE, portas "
                "checadas (fp_detect.cc, fp_eval_rtn); nao expostas"
            ),
            "total": len(user_mode),
            "sids": sorted(user_mode, key=int),
        },
        "expostas": {
            "definicao": "NECESSARY com service: explicito e porta, protocolo ou flags entre os predicados seletivos",
            "total": len(expostas),
            "elegiveis_no_strong_discriminator": medida_explicita["elegiveis_no_strong_discriminator"],
            "campos_de_h_r": medida_explicita["campos_de_h_r"],
            "servicos": medida_explicita["servicos"],
            "mantendo_so_condicoes_de_ip": so_ip_restante,
            "sids": expostas,
        },
        "expostas_por_servico_implicito": {
            "definicao": (
                "NECESSARY sem service:, cabecalho de protocolo IP, com opcao pela qual "
                "validate_services (fp_utils.cc) acrescenta servico, e porta, protocolo "
                "ou flags entre os predicados seletivos"
            ),
            "total": len(medida_implicita["sids"]),
            "opcoes": {
                str(r["rule_id"]): opcoes_que_implicam_servico(
                    o["name"] for o in r["parsed_rule"]["options"]
                )
                for r, _ in implicitas
            },
            "elegiveis_no_strong_discriminator": medida_implicita["elegiveis_no_strong_discriminator"],
            "campos_de_h_r": medida_implicita["campos_de_h_r"],
            "servicos": medida_implicita["servicos"],
            "mantendo_so_condicoes_de_ip": medida_implicita["mantendo_so_condicoes_de_ip"],
            "cobertura_por_plano": medida_implicita["cobertura_por_plano"],
            "sids": medida_implicita["sids"],
        },
        "service_based_total": len(expostas) + len(medida_implicita["sids"]),
        "cobertura_da_regiao_sem_porta_e_protocolo": {
            "definicao": (
                "regiao {IPs da regra} x {qualquer porta} x {qualquer protocolo} contida "
                "numa entrada instalada sem porta; so_tcp quando apenas uma entrada de "
                "protocolo 6 sem porta a cobre. So as regras com service: explicito"
            ),
            "por_plano": cobertura_por_plano,
            "global_sem_cobertura_total": medida_explicita["global_sem_cobertura_total"],
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
    print(f"    elegiveis no strong            {medida_explicita['elegiveis_no_strong_discriminator']}")
    print(f"    mantendo so IP                 {so_ip_restante}")
    for nome, contagem in cobertura_por_plano.items():
        print(f"  cobertura no plano {nome:<21} {contagem}")
    print(f"  protocolo de servico no cabecalho {len(user_mode)} (USER_MODE, nao expostas)")
    print(f"  servico implicito, expostas      {len(medida_implicita['sids'])} {medida_implicita['sids']}")
    print(f"    cobertura                      {medida_implicita['cobertura_por_plano']}")
    print(f"gravado em {SAIDA.relative_to(PROJECT_ROOT).as_posix()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

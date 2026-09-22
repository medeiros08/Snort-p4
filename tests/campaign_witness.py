#!/usr/bin/env python3
"""Sintetiza o fluxo testemunha de uma regra a partir da IR semantica.

Um caso da campanha end-to-end precisa de um pacote que o **Snort** alerte,
nao de um pacote que apenas case com a entrada P4. A diferenca nao e detalhe:
`tests/send_prefilter_test_packets.py` constroi pacote a partir da entrada
instalada, satisfazendo so o predicado de header; como toda regra real do
ruleset carrega `content`, `flow` ou `service` (e por isso que EXACT = 0), o
Snort nao alerta nesse pacote e o caso passa vazio — sem alerta do oraculo
nao ha implicacao Snort => P4_candidato para testar.

Este modulo sintetiza a testemunha a partir dos predicados da regra:

    header      protocolo, IPs e portas que satisfazem o header da regra
    content     bytes no buffer que a regra inspeciona (default, http_uri,
                http_header, http_method, http_client_body)
    flow        handshake TCP completo antes do request, porque 6250 dos
                predicados de flow do ruleset pedem `established` e sem
                handshake o Snort nao considera o fluxo estabelecido
    service     porta de servico coerente, para o wizard do Snort ligar o
                inspetor (4436 predicados pedem `service: http`)

Fora do escopo, declarado por caso em `motivos_de_recusa`: `pcre`,
`byte_test`, `byte_jump`, `flowbits`, `isdataat`, `file_data` e afins. Sao
1643 das 4003 regras NECESSARY; as outras 2360 admitem testemunha, folga de
mais de 2x para uma campanha de 1000 casos.

Sem dependencia de terceiros, de proposito: o mesmo motivo do compilador. O
gerador roda na maquina Windows onde o repositorio vive, sem scapy e sem
BMv2, e so o replay precisa do rig.

Uso:
    python tests/campaign_witness.py --autoteste
    python tests/campaign_witness.py --autoteste --limite 300
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import struct
import sys

from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]

MANIFESTO_SEMANTICO = PROJECT_ROOT / "output" / "semantic_manifest.json"


# Opcoes que tornam a testemunha nao sintetizavel por construcao direta.
# Cada uma exige inspecao com estado, aritmetica sobre o proprio payload ou
# reconstrucao de arquivo — coisas que nao se resolvem escolhendo bytes.
OPCOES_BLOQUEANTES = frozenset(
    {
        "pcre",
        "byte_jump",
        "byte_test",
        "byte_extract",
        "byte_math",
        "flowbits",
        "base64_decode",
        "base64_data",
        "asn1",
        "dce_iface",
        "dce_opnum",
        "dce_stub_data",
        "ssl_state",
        "ssl_version",
        "isdataat",
        "file_data",
        "detection_filter",
        "threshold",
        "stream_size",
        "cvs",
        "sip_method",
        "sip_header",
        "sip_body",
        "dsize",
        "urilen",
    }
)

# Buffers de content que este modulo sabe preencher. `default` e `pkt_data`
# vao no payload cru; os `http_*` exigem request bem-formado, senao o
# http_inspect nao preenche o buffer que a regra inspeciona.
BUFFERS_SUPORTADOS = frozenset(
    {
        None,
        "default",
        "pkt_data",
        "raw_data",
        "http_uri",
        "http_raw_uri",
        "http_header",
        "http_method",
        "http_client_body",
        "http_cookie",
    }
)

BUFFERS_HTTP = frozenset(
    {
        "http_uri",
        "http_raw_uri",
        "http_header",
        "http_method",
        "http_client_body",
        "http_cookie",
    }
)

PROTO_NUMERO = {"tcp": 6, "udp": 17, "icmp": 1}

# Enchimento usado para alcancar `offset`/`distance`. Letra unica e sem
# significado em protocolo nenhum, para nao casar acidentalmente com outro
# content da mesma regra.
ENCHIMENTO = b"A"


# ============================================================
# Padrao de content
# ============================================================


def parse_content_pattern(padrao: str) -> bytes:
    """Converte o padrao de `content` do Snort em bytes.

    A sintaxe alterna texto literal e blocos hexadecimais delimitados por
    `|`: ``"2|00 00 00 06|Drives"`` e o byte '2', quatro bytes binarios e a
    palavra 'Drives'. Dentro do texto, `\\;`, `\\"` e `\\\\` escapam o
    proprio caractere.
    """

    saida = bytearray()
    dentro_hex = False
    i = 0

    while i < len(padrao):
        c = padrao[i]

        if c == "|":
            dentro_hex = not dentro_hex
            i += 1
            continue

        if dentro_hex:
            if c.isspace():
                i += 1
                continue
            par = padrao[i : i + 2]
            if len(par) < 2:
                raise ValueError(f"bloco hex incompleto em {padrao!r}")
            saida.append(int(par, 16))
            i += 2
            continue

        if c == "\\" and i + 1 < len(padrao):
            saida.append(ord(padrao[i + 1]))
            i += 2
            continue

        saida.append(ord(c))
        i += 1

    if dentro_hex:
        raise ValueError(f"bloco hex nao fechado em {padrao!r}")

    return bytes(saida)


# ============================================================
# Header da regra
# ============================================================


def _primeiro_inteiro(valor) -> int | None:
    """Extrai uma porta utilizavel de int, lista, ou string tipo '[80, 8080]'."""

    if isinstance(valor, bool):
        return None
    if isinstance(valor, int):
        return valor
    if isinstance(valor, (list, tuple)):
        for item in valor:
            porta = _primeiro_inteiro(item)
            if porta is not None:
                return porta
        return None
    if isinstance(valor, str):
        achados = re.findall(r"\d+", valor)
        if achados:
            return int(achados[0])
    return None


def _eh_curinga(valor) -> bool:
    """Diz se o campo de endereco ficou sem restricao na regra."""

    if valor is None:
        return True
    if isinstance(valor, str):
        return valor.strip().lower() in ("", "any")
    return False


def _endereco_de(valor, padrao: str, deslocamento: int = 10) -> str | None:
    """Escolhe um host concreto a partir de CIDR, IP literal ou lista.

    Host .10 da rede, e nao o endereco de rede: endereco de rede e broadcast
    tem tratamento especial em pilha e em inspetor, e um caso da campanha nao
    deveria depender disso.
    """

    if valor is None:
        return padrao

    if isinstance(valor, (list, tuple)):
        for item in valor:
            endereco = _endereco_de(item, padrao, deslocamento)
            if endereco:
                return endereco
        return padrao

    if not isinstance(valor, str):
        return padrao

    texto = valor.strip()
    if not texto or texto.lower() == "any":
        return padrao
    if texto.startswith("!"):
        return None

    try:
        if "/" in texto:
            rede = ipaddress.ip_network(texto, strict=False)
            if rede.version != 4:
                return None
            if rede.num_addresses >= 16:
                return str(rede.network_address + deslocamento)
            return str(rede.network_address + 1)
        return str(ipaddress.ip_address(texto))
    except ValueError:
        return None


CAMPOS_ICMP = ("itype", "icode", "icmp_id", "icmp_seq")

# Echo request com id e seq 1: o que usar quando a regra nao diz nada.
ICMP_PADRAO = {"tipo": 8, "codigo": 0, "ident": 1, "seq": 1}


def _valor_icmp(texto) -> int | None:
    """Resolve o valor de uma opcao numerica de ICMP.

    No ruleset avaliado so aparecem duas formas: digito exato e `>N`, esta
    ultima so em icode (`>0`, `>1`, `>2`, `>3`, `>15`). Para `>N` o menor
    valor que satisfaz e N+1, e e ele que a testemunha carrega. Qualquer outra
    forma devolve None, e o caso fica com o padrao — declarado, nao adivinhado.
    """

    if texto is None:
        return None
    texto = str(texto).strip()
    if texto.isdigit():
        valor = int(texto)
    elif texto.startswith(">") and texto[1:].strip().isdigit():
        valor = int(texto[1:].strip()) + 1
    else:
        return None
    return valor if 0 <= valor <= 65535 else None


def campos_icmp(regra: dict) -> dict:
    """Le itype, icode, icmp_id e icmp_seq da regra.

    Sem isto a testemunha ICMP era sempre echo request com id e seq 1, e toda
    regra que exige outro tipo ou outro codigo passava vacua: 40 dos 54 casos
    ICMP da campanha de 1000. ICMP e UDP sao justamente a fatia falsificavel
    da campanha, porque para TCP a entrada p4-106 garante candidate por
    construcao — melhorar ICMP melhora o que a campanha e capaz de refutar.
    """

    campos = dict(ICMP_PADRAO)

    vistos = {}
    for lista in (
        "selective_predicates",
        "preserved",
        "expanded",
        "delegated",
        "fallback",
        "unassessed",
        "detection_predicates",
    ):
        for predicado in regra.get(lista) or []:
            nome = predicado.get("field")
            if nome in CAMPOS_ICMP and nome not in vistos:
                valor = _valor_icmp(predicado.get("value"))
                if valor is not None:
                    vistos[nome] = valor

    if "itype" in vistos:
        campos["tipo"] = vistos["itype"] & 0xFF
    if "icode" in vistos:
        campos["codigo"] = vistos["icode"] & 0xFF
    if "icmp_id" in vistos:
        campos["ident"] = vistos["icmp_id"] & 0xFFFF
    if "icmp_seq" in vistos:
        campos["seq"] = vistos["icmp_seq"] & 0xFFFF

    return campos


# ============================================================
# Campos de cabecalho TCP e IP
# ============================================================

# Letras de `flags`, como em src/ips_options/ips_flags.cc:186-230 do Snort
# 3.12.2.0 instalado no rig. `1` e `2` sao os antigos bits reservados, hoje
# CWR e ECE.
BITS_DE_FLAG = {
    "F": 0x01,
    "S": 0x02,
    "R": 0x04,
    "P": 0x08,
    "A": 0x10,
    "U": 0x20,
    "E": 0x40,
    "2": 0x40,
    "C": 0x80,
    "1": 0x80,
}


def _ler_flags(texto: str) -> tuple[str, int, int] | None:
    """Devolve (modo, bits testados, mascara) de `flags:<teste>[,<mascara>]`.

    O modificador pode aparecer em qualquer posicao e o ultimo vence; `0`
    zera o que veio antes. E o laco de flags_parse_test, nao uma leitura
    livre da sintaxe.
    """

    teste, _, mascara = str(texto).strip().partition(",")
    modo, bits = "normal", 0
    for letra in teste.strip().upper():
        if letra == "0":
            bits = 0
        elif letra in BITS_DE_FLAG:
            bits |= BITS_DE_FLAG[letra]
        elif letra in "!*+":
            modo = {"!": "not", "*": "any", "+": "all"}[letra]
        else:
            return None

    bits_mascara = 0
    for letra in mascara.strip().upper():
        if letra not in BITS_DE_FLAG:
            return None
        bits_mascara |= BITS_DE_FLAG[letra]

    return modo, bits, bits_mascara


def flags_satisfazem(texto: str, flags_do_pacote: int) -> bool:
    """Avalia `flags` contra um pacote como TcpFlagOption::eval (ips_flags.cc:124-152)."""

    lido = _ler_flags(texto)
    if lido is None:
        return False
    modo, bits, mascara = lido
    observados = flags_do_pacote & (0xFF ^ mascara)
    if modo == "normal":
        return observados == bits
    if modo == "all":
        return observados & bits == bits
    if modo == "not":
        return observados & bits == 0
    return observados & bits != 0


def _flags_da_testemunha(texto: str) -> int | None:
    """Flags que a testemunha carrega para satisfazer `flags:<texto>`.

    PSH+ACK e o que toda testemunha TCP ja usava; se ele satisfaz a regra,
    fica, e o caso nao muda. Senao: nos modos normal, `+` e `*`, os proprios
    bits testados satisfazem; em `!`, PSH+ACK sem os bits proibidos.
    """

    if flags_satisfazem(texto, PSH_ACK):
        return PSH_ACK
    lido = _ler_flags(texto)
    if lido is None:
        return None
    modo, bits, _mascara = lido
    candidato = PSH_ACK & ~bits if modo == "not" else bits
    return candidato if flags_satisfazem(texto, candidato) else None


def _menor_valor_do_intervalo(texto, maximo: int) -> int | None:
    """Menor valor que satisfaz uma opcao de intervalo (seq, ack, id, ttl).

    As quatro usam RangeCheck. No ruleset avaliado so aparecem digito exato e
    `>N`; as demais formas simples sao aceitas, e qualquer outra devolve None.
    """

    texto = str(texto).strip().replace(" ", "")
    achado = re.fullmatch(r"(<=|>=|<|>|=)?(\d+)", texto)
    if achado:
        operador, valor = achado.group(1) or "=", int(achado.group(2))
        valor = {"=": valor, ">": valor + 1, ">=": valor, "<": 0, "<=": 0}[operador]
    else:
        achado = re.fullmatch(r"(\d+)(<>|<=>)(\d+)", texto)
        if not achado:
            return None
        valor = int(achado.group(1)) + (1 if achado.group(2) == "<>" else 0)
    return valor if 0 <= valor <= maximo else None


def campos_de_cabecalho(regra: dict) -> tuple[dict, list[str]]:
    """Le flags, seq, ack, id e ttl da regra.

    Devolve (campos, recusados). Sem isto a testemunha TCP era sempre PSH+ACK
    com seq 1000 e TTL 64, e toda regra que testa o cabecalho — varredura com
    SYN+FIN, pacote com seq fixo de ferramenta de ataque, traceroute com TTL
    1 — passava vacua por defeito do gerador. Sao as regras em que `flags` e
    PRESERVED, isto e, as que o prefilter casa pelo bit: vacuidade ali
    escondia justamente a parte do rebaixamento que testa flags.
    """

    campos: dict = {}
    recusados: list[str] = []
    for lista in (
        "preserved",
        "expanded",
        "delegated",
        "fallback",
        "unassessed",
        "detection_predicates",
    ):
        for predicado in regra.get(lista) or []:
            opcao = predicado.get("source_option")
            valor = predicado.get("value")
            if opcao == "flags" and "flags" not in campos:
                bits = _flags_da_testemunha(valor)
                if bits is None:
                    recusados.append(f"flags:{valor}")
                else:
                    campos["flags"] = bits
            elif opcao in ("seq", "ack", "id", "ttl"):
                chave = "ip_id" if opcao == "id" else opcao
                if chave in campos:
                    continue
                maximo = {"seq": 0xFFFFFFFF, "ack": 0xFFFFFFFF, "ip_id": 0xFFFF, "ttl": 0xFF}[chave]
                resolvido = _menor_valor_do_intervalo(valor, maximo)
                if resolvido is None:
                    recusados.append(f"{opcao}:{valor}")
                else:
                    campos[chave] = resolvido
    return campos, sorted(set(recusados))


PORTAS_DE_TENTATIVA = (45678, 20000, 80, 1024, 60000)


def _porta_da_regra(texto) -> int | None:
    """Uma porta que satisfaz a sintaxe de porta do header do Snort.

    `N`, `N:M`, `N:`, `:M`, `!spec` e listas `[a,b:c,...]`. Devolve None para
    `any`, variavel nao resolvida ou forma desconhecida.
    """

    texto = str(texto).strip().replace(" ", "")
    if not texto or texto.lower() == "any" or "$" in texto:
        return None

    def intervalos(spec: str) -> list[tuple[int, int]] | None:
        spec = spec.strip("[]")
        saida = []
        for parte in spec.split(","):
            if not parte or parte.startswith("!"):
                continue
            achado = re.fullmatch(r"(\d*):(\d*)|(\d+)", parte)
            if not achado:
                return None
            if achado.group(3):
                baixo = alto = int(achado.group(3))
            else:
                baixo = int(achado.group(1) or 1)
                alto = int(achado.group(2) or 65535)
            saida.append((baixo, alto))
        return saida

    if texto.startswith("!"):
        proibidos = intervalos(texto[1:])
        if proibidos is None:
            return None
        for porta in PORTAS_DE_TENTATIVA:
            if not any(baixo <= porta <= alto for baixo, alto in proibidos):
                return porta
        return None

    permitidos = intervalos(texto)
    if not permitidos:
        return None
    porta = permitidos[0][0]
    return porta if 0 < porta < 65536 else None


def resolver_header(regra: dict) -> dict | None:
    """Monta protocolo, IPs e portas que satisfazem o header da regra."""

    campos = {}
    for predicado in regra.get("selective_predicates") or []:
        if predicado.get("kind") == "HEADER":
            campos[predicado.get("field")] = predicado.get("value")

    # Porta que o compilador mandou para fallback (faixa `135:139`, negacao)
    # nao aparece em selective_predicates: o prefilter nao a testa. O Snort
    # testa. Ler so os predicados seletivos fazia a testemunha tratar a porta
    # como livre e sair com a 80, e a regra passava vacua por defeito do
    # gerador. 13 dos 77 vacuos da v2 tinham porta assim; com a porta certa,
    # 6 voltaram a alertar (1257 tambem precisou de flags). A porta que a
    # testemunha usa vem entao da regra resolvida, que e o que o oraculo
    # avalia.
    resolvida = regra.get("resolved_rule") or {}
    portas_da_regra = {}
    for lado, campo in (("source", "src_port"), ("destination", "dst_port")):
        if campo in campos:
            continue
        texto = (resolvida.get(lado) or {}).get("port")
        if texto is not None and str(texto).strip().lower() != "any":
            portas_da_regra[campo] = _porta_da_regra(texto)

    protocolo = campos.get("protocol")
    if isinstance(protocolo, str):
        protocolo = protocolo.strip().lower()
    if protocolo not in PROTO_NUMERO:
        return None

    # dst primeiro, e o default de src vem do lado oposto: 2887 regras
    # apontam dst para $HOME_NET e nao declaram src, entao um default interno
    # colidiria com o dst e descartaria a regra por "header nao resolvivel".
    # Campo livre e campo que a regra nao restringe: pode variar por caso sem
    # deixar de satisfazer a regra. E o que permite dar 5-tupla propria a cada
    # caso, e disso depende a independencia das medicoes.
    src_ip_livre = _eh_curinga(campos.get("src_ip"))
    dst_ip_livre = _eh_curinga(campos.get("dst_ip"))
    dst_port_livre = (
        _primeiro_inteiro(campos.get("dst_port")) is None and "dst_port" not in portas_da_regra
    )

    dst_ip = _endereco_de(campos.get("dst_ip"), "203.0.113.10")
    if not dst_ip:
        return None

    interno = ipaddress.ip_address(dst_ip) in ipaddress.ip_network("192.168.10.0/24")
    src_ip = _endereco_de(
        campos.get("src_ip"),
        "203.0.113.10" if interno else "192.168.10.10",
    )
    if not src_ip:
        return None

    # Mesma sub-rede nos dois lados (src e dst ambos $HOME_NET): desloca o
    # src para outro host, em vez de recusar o caso.
    if src_ip == dst_ip:
        src_ip = _endereco_de(campos.get("src_ip"), src_ip, deslocamento=11)
        if not src_ip or src_ip == dst_ip:
            return None

    src_port = _primeiro_inteiro(campos.get("src_port"))
    dst_port = _primeiro_inteiro(campos.get("dst_port"))
    # Porta de forma nao interpretavel fica com o padrao, como antes: recusar
    # a regra mudaria o conjunto utilizavel e, com ele, a amostra inteira.
    if portas_da_regra.get("src_port") is not None:
        src_port = portas_da_regra["src_port"]
    if portas_da_regra.get("dst_port") is not None:
        dst_port = portas_da_regra["dst_port"]

    # Porta de origem livre pode ser trocada por caso. Isso importa: quando
    # varios casos compartilham a 5-tupla, o Snort junta tudo numa sessao so
    # e os handshakes seguintes viram retransmissao — medido com
    # total_sessions = 1 para quatro fluxos identicos.
    src_port_livre = src_port is None and "src_port" not in portas_da_regra
    if protocolo == "icmp":
        src_port = dst_port = 0
        src_port_livre = False
    else:
        if src_port is None:
            src_port = 45678
        if dst_port is None:
            dst_port = 80
        if not (0 < src_port < 65536) or not (0 < dst_port < 65536):
            return None

    return {
        "protocolo": protocolo,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "src_port_livre": src_port_livre,
        "dst_port_livre": dst_port_livre and protocolo != "icmp",
        "src_ip_livre": src_ip_livre,
        "dst_ip_livre": dst_ip_livre,
    }


# ============================================================
# Payload
# ============================================================


def _modificadores(predicado: dict) -> dict:
    saida = {}
    for mod in predicado.get("modifiers") or []:
        saida[mod.get("name")] = mod.get("value")
    return saida


def _colocar(buffer: bytearray, dados: bytes, offset: int | None) -> None:
    """Escreve `dados` no buffer, enchendo ate `offset` quando exigido."""

    if offset is not None and offset > len(buffer):
        buffer.extend(ENCHIMENTO * (offset - len(buffer)))
    buffer.extend(dados)


def _percent_encode(dados: bytes) -> str:
    """Codifica so o que a linha de request nao aceita literal.

    Codificacao minima, e nao total. O buffer http_uri e "a URI normalizada
    com todos os percent encodings removidos"
    (docs/vendor/snort3/doc/user/http_inspect.txt:416, pin 3.12.2.0), entao
    codificar tudo tambem funcionaria em teoria — mas a forma literal e a que
    esta verificada contra o Snort desta instalacao, e ela nao depende de
    quais normalizacoes estao ligadas. Ficam literais os caracteres de caminho
    (`/`, `.`, `-`, `_`, `~`, `:`, `@`, `!`, `$`, `&`, `(`, `)`, `*`, `,`,
    `;`, `=`, `'`), e sao codificados espaco, controle, `%`, `#`, `?`, `+` e
    qualquer byte nao ASCII. `+` entra na lista porque plus_to_space e ligado
    por padrao e transformaria um `+` literal do content em espaco.
    """

    literais = set(
        b"abcdefghijklmnopqrstuvwxyz"
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        b"0123456789"
        b"-_.~/:@!$&()*,;='"
    )
    saida = []
    for byte in dados:
        if byte in literais:
            saida.append(chr(byte))
        else:
            saida.append(f"%{byte:02X}")
    return "".join(saida)


def montar_payload(regra: dict, direcao: str = "to_server") -> tuple[bytes, dict] | None:
    """Monta o payload que satisfaz os `content` da regra.

    Devolve (payload, detalhe) ou None quando algum content nao e
    representavel. `detalhe` registra buffer por buffer o que foi escrito, de
    modo que o relatorio da campanha possa dizer por que um caso alertou.
    """

    # O mesmo content aparece em mais de uma lista da IR (preserved e
    # delegated, por exemplo). Sem deduplicar por origem, o payload sai com o
    # padrao repetido — o que ainda casaria, mas mediria outra coisa.
    contents = {}
    for lista in ("preserved", "expanded", "delegated", "fallback", "unassessed", "detection_predicates"):
        for predicado in regra.get(lista) or []:
            if predicado.get("source_option") != "content":
                continue
            valor = predicado.get("value") or {}
            chave = (
                predicado.get("source_index"),
                predicado.get("buffer"),
                valor.get("pattern"),
            )
            contents.setdefault(chave, predicado)

    contents = sorted(contents.values(), key=lambda p: p.get("source_index") or 0)

    buffers: dict[str, bytearray] = {}
    negados: list[bytes] = []
    detalhe: dict[str, list] = {}

    for predicado in contents:
        buffer = predicado.get("buffer")
        if buffer not in BUFFERS_SUPORTADOS:
            return None

        valor = predicado.get("value") or {}
        padrao = valor.get("pattern")
        if not isinstance(padrao, str) or not padrao:
            return None

        try:
            dados = parse_content_pattern(padrao)
        except ValueError:
            return None
        if not dados:
            return None

        if valor.get("negated"):
            negados.append(dados)
            continue

        chave = buffer if buffer in BUFFERS_HTTP else "corpo"
        mods = _modificadores(predicado)

        # `offset` e absoluto no buffer; `distance` e relativo ao fim do
        # match anterior. Colocar o mais cedo possivel satisfaz `depth` e
        # `within` automaticamente, que sao limites superiores.
        offset = mods.get("offset")
        distance = mods.get("distance")
        destino = buffers.setdefault(chave, bytearray())

        if isinstance(distance, int) and distance > 0:
            destino.extend(ENCHIMENTO * distance)
            _colocar(destino, dados, None)
        else:
            _colocar(destino, dados, offset if isinstance(offset, int) else None)

        detalhe.setdefault(chave, []).append(
            {
                "padrao": padrao,
                "bytes": len(dados),
                "modificadores": mods,
            }
        )

    if not buffers:
        # Regra sem content: o header e a testemunha inteira. Vale como caso,
        # e e justamente onde EXACT poderia aparecer.
        payload = b""
        if negados and any(n in payload for n in negados):
            return None
        return payload, {"buffers": {}, "negados": len(negados)}

    usa_http = any(chave in BUFFERS_HTTP for chave in buffers)

    if not usa_http:
        payload = bytes(buffers.get("corpo", bytearray()))
    elif direcao == "to_client":
        # Regra to_client inspeciona a RESPOSTA do servidor. Mandar um
        # `GET ... HTTP/1.1` saindo do servidor nao e resposta, e o
        # http_inspect nao preenche buffer nenhum — era o que deixava os
        # quatro casos tcp/http/to_client vacuos. Os contents vao nos
        # cabecalhos da resposta: casamento de content e por substring, entao
        # prefixar com um nome de cabecalho proprio nao impede o match.
        linhas = [b"HTTP/1.1 200 OK"]
        linhas.append(b"Server: campanha")

        cabecalho_extra = bytes(buffers.get("http_header", bytearray()))
        if cabecalho_extra:
            if b"\r" in cabecalho_extra or b"\n" in cabecalho_extra:
                return None
            linhas.append(b"X-Campanha: " + cabecalho_extra)

        corpo = bytes(
            buffers.get("corpo", buffers.get("http_client_body", bytearray()))
        )
        linhas.append(b"Content-Length: %d" % len(corpo or b"ok"))
        linhas.append(b"Connection: close")
        payload = b"\r\n".join(linhas) + b"\r\n\r\n" + (corpo or b"ok")
    else:
        metodo = bytes(buffers.get("http_method", bytearray())) or b"GET"
        uri_bytes = bytes(
            buffers.get("http_uri", buffers.get("http_raw_uri", bytearray()))
        )
        if uri_bytes:
            codificada = _percent_encode(uri_bytes)
            # Content que ja comeca com barra nao leva outra: `//cfdocs/...`
            # muda o caminho normalizado e foi uma das formas que o Snort
            # desta instalacao nao casou.
            uri = codificada if codificada.startswith("/") else "/" + codificada
        else:
            uri = "/index.html"

        linhas = [b"%s %s HTTP/1.1" % (metodo, uri.encode("ascii"))]
        linhas.append(b"Host: campanha.local")
        linhas.append(b"User-Agent: campanha-e2e/1")

        cabecalho_extra = bytes(buffers.get("http_header", bytearray()))
        if cabecalho_extra:
            if b"\r" in cabecalho_extra or b"\n" in cabecalho_extra:
                return None
            linhas.append(b"X-Campanha: " + cabecalho_extra)

        cookie = bytes(buffers.get("http_cookie", bytearray()))
        if cookie:
            if b"\r" in cookie or b"\n" in cookie:
                return None
            linhas.append(b"Cookie: " + cookie)

        corpo = bytes(
            buffers.get("http_client_body", buffers.get("corpo", bytearray()))
        )
        if corpo:
            linhas.append(b"Content-Length: %d" % len(corpo))

        linhas.append(b"Connection: close")
        payload = b"\r\n".join(linhas) + b"\r\n\r\n" + corpo

    for negado in negados:
        if negado in payload:
            return None

    return payload, {
        "buffers": {k: v for k, v in detalhe.items()},
        "negados": len(negados),
        "http": usa_http,
    }


# ============================================================
# Quadros
# ============================================================


def _soma_internet(dados: bytes) -> int:
    if len(dados) % 2:
        dados += b"\x00"
    total = 0
    for i in range(0, len(dados), 2):
        total += (dados[i] << 8) + dados[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _ipv4(
    src: str, dst: str, protocolo: int, corpo: bytes, ident: int, ttl: int = 64
) -> bytes:
    cabecalho = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(corpo),
        ident,
        0,
        ttl,
        protocolo,
        0,
        ipaddress.ip_address(src).packed,
        ipaddress.ip_address(dst).packed,
    )
    soma = _soma_internet(cabecalho)
    cabecalho = cabecalho[:10] + struct.pack("!H", soma) + cabecalho[12:]
    return cabecalho + corpo


def _tcp(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    seq: int,
    ack: int,
    flags: int,
    payload: bytes,
) -> bytes:
    cabecalho = struct.pack(
        "!HHIIBBHHH",
        src_port,
        dst_port,
        seq,
        ack,
        (5 << 4),
        flags,
        65535,
        0,
        0,
    )
    pseudo = (
        ipaddress.ip_address(src_ip).packed
        + ipaddress.ip_address(dst_ip).packed
        + struct.pack("!BBH", 0, 6, len(cabecalho) + len(payload))
    )
    soma = _soma_internet(pseudo + cabecalho + payload)
    cabecalho = cabecalho[:16] + struct.pack("!H", soma) + cabecalho[18:]
    return cabecalho + payload


def _udp(
    src_ip: str, dst_ip: str, src_port: int, dst_port: int, payload: bytes
) -> bytes:
    cabecalho = struct.pack("!HHHH", src_port, dst_port, 8 + len(payload), 0)
    pseudo = (
        ipaddress.ip_address(src_ip).packed
        + ipaddress.ip_address(dst_ip).packed
        + struct.pack("!BBH", 0, 17, 8 + len(payload))
    )
    soma = _soma_internet(pseudo + cabecalho + payload) or 0xFFFF
    return cabecalho[:6] + struct.pack("!H", soma) + payload


def _icmp(payload: bytes, campos: dict | None = None) -> bytes:
    """Monta o ICMP com tipo, codigo, id e sequencia que a regra exige."""

    valores = campos or ICMP_PADRAO
    cabecalho = struct.pack(
        "!BBHHH",
        valores.get("tipo", 8),
        valores.get("codigo", 0),
        0,
        valores.get("ident", 1),
        valores.get("seq", 1),
    )
    soma = _soma_internet(cabecalho + payload)
    return cabecalho[:2] + struct.pack("!H", soma) + cabecalho[4:] + payload


def _ether(corpo: bytes) -> bytes:
    return (
        b"\x02\x00\x00\x00\x00\x02"
        + b"\x02\x00\x00\x00\x00\x01"
        + b"\x08\x00"
        + corpo
    )


PEDIDO_DE_AQUECIMENTO = (
    b"GET /aquecimento.html HTTP/1.1\r\n"
    b"Host: campanha.local\r\n"
    b"User-Agent: campanha-e2e/1\r\n"
    b"\r\n"
)

RESPOSTA_DO_SERVIDOR = (
    b"HTTP/1.1 200 OK\r\n"
    b"Server: campanha\r\n"
    b"Content-Length: 2\r\n"
    b"\r\n"
    b"ok"
)

SYN = 0x02
SYN_ACK = 0x12
ACK = 0x10
PSH_ACK = 0x18


class _Sessao:
    """Monta uma sessao TCP mantendo seq e ack coerentes.

    Coerencia importa: o Snort so avalia `flow:established` e so entrega os
    buffers http quando o stream aceita a sessao. Numero fora de ordem faz a
    regra nao disparar, e o caso viraria vacuo por defeito do gerador.
    """

    def __init__(self, abre_ip, abre_porta, aceita_ip, aceita_porta):
        self.abre_ip = abre_ip
        self.abre_porta = abre_porta
        self.aceita_ip = aceita_ip
        self.aceita_porta = aceita_porta
        self.seq_abre = 1000
        self.seq_aceita = 5000
        self.ident = 1
        self.quadros: list[tuple[str, bytes]] = []

    def _emite(
        self, papel, origem, destino, porta_origem, porta_destino, seq, ack, flags, payload, campos
    ):
        quadro = _ether(
            _ipv4(
                origem,
                destino,
                6,
                _tcp(origem, destino, porta_origem, porta_destino, seq, ack, flags, payload),
                campos.get("ip_id", self.ident),
                campos.get("ttl", 64),
            )
        )
        self.ident += 1
        self.quadros.append((papel, quadro))

    # `campos` so chega preenchido na testemunha: sao os valores que a regra
    # exige no cabecalho (seq, ack, id, ttl). O contador de seq segue o valor
    # emitido, para que o quadro seguinte da sessao continue coerente com ele.
    def de_quem_abre(self, papel, flags, payload=b"", campos=None):
        campos = campos or {}
        seq = campos.get("seq", self.seq_abre)
        self._emite(
            papel,
            self.abre_ip,
            self.aceita_ip,
            self.abre_porta,
            self.aceita_porta,
            seq,
            campos.get("ack", self.seq_aceita),
            flags,
            payload,
            campos,
        )
        self.seq_abre = seq + len(payload) + (1 if flags & SYN else 0)

    def de_quem_aceita(self, papel, flags, payload=b"", campos=None):
        campos = campos or {}
        seq = campos.get("seq", self.seq_aceita)
        self._emite(
            papel,
            self.aceita_ip,
            self.abre_ip,
            self.aceita_porta,
            self.abre_porta,
            seq,
            campos.get("ack", self.seq_abre),
            flags,
            payload,
            campos,
        )
        self.seq_aceita = seq + len(payload) + (1 if flags & SYN else 0)

    def handshake(self):
        self.de_quem_abre("handshake", SYN)
        self.de_quem_aceita("handshake", SYN_ACK)
        self.de_quem_abre("handshake", ACK)


def quadros_com_papel(
    header: dict,
    payload: bytes,
    com_handshake: bool,
    direcao: str = "to_server",
    http: bool = False,
    icmp: dict | None = None,
    cabecalho: dict | None = None,
) -> list[tuple[str, bytes]]:
    """Monta os quadros do caso, cada um com seu papel.

    Para caso HTTP o fluxo tem cinco etapas, e nenhuma e decorativa. Verificado
    contra o Snort 3.12.2.0 desta instalacao com a regra 912 do ruleset, que
    passava vacua com um request solto:

        handshake            sem ele nao ha `flow:established`
        aquecimento          primeiro request do cliente
        resposta_servidor    e ela que faz o wizard identificar o fluxo como
                             http; sem resposta, `alert http` e os buffers
                             http_* nunca sao preenchidos
        testemunha           o request que carrega o content da regra
        flush                ACK do servidor depois da testemunha. A inspecao
                             do request so acontece quando a mensagem e
                             descarregada, e isso exige um pacote seguinte; o
                             alerta sai atribuido a ESTE pacote, nao ao
                             request

    Para caso nao-HTTP basta handshake e o pacote com o payload: regra que
    inspeciona payload cru dispara no proprio pacote.

    `cabecalho` traz o que a regra exige de flags, seq, ack, id e ttl
    (campos_de_cabecalho). Vale so na testemunha: os quadros de andaime
    existem para montar a sessao e seguem os valores dela.
    """

    cabecalho = cabecalho or {}
    ip_id = cabecalho.get("ip_id")
    ttl = cabecalho.get("ttl", 64)
    protocolo = header["protocolo"]
    src_ip, dst_ip = header["src_ip"], header["dst_ip"]
    src_port, dst_port = header["src_port"], header["dst_port"]

    if protocolo == "udp":
        quadros: list[tuple[str, bytes]] = []

        if direcao == "to_client":
            # UDP nao tem handshake, e o Snort decide quem e o cliente pelo
            # PRIMEIRO pacote do fluxo. Sem escorva, quem manda a testemunha e
            # tratado como cliente e `flow:to_client` nunca casa — era o que
            # deixava vacuos os quatro casos udp/cru/to_client, incluindo a
            # resposta de DNS do sid 253.
            quadros.append(
                (
                    "aquecimento",
                    _ether(
                        _ipv4(
                            dst_ip,
                            src_ip,
                            17,
                            _udp(dst_ip, src_ip, dst_port, src_port, b"campanha-escorva"),
                            1,
                        )
                    ),
                )
            )

        quadros.append(
            (
                "testemunha",
                _ether(
                    _ipv4(
                        src_ip,
                        dst_ip,
                        17,
                        _udp(src_ip, dst_ip, src_port, dst_port, payload or b"X"),
                        len(quadros) + 1 if ip_id is None else ip_id,
                        ttl,
                    )
                ),
            )
        )
        return quadros

    if protocolo == "icmp":
        return [
            (
                "testemunha",
                _ether(
                    _ipv4(
                        src_ip,
                        dst_ip,
                        1,
                        _icmp(payload or b"X", icmp),
                        1 if ip_id is None else ip_id,
                        ttl,
                    )
                ),
            )
        ]

    # Em to_client quem abre e o lado oposto ao que envia a testemunha.
    if direcao == "to_client":
        sessao = _Sessao(dst_ip, dst_port, src_ip, src_port)
        envia_testemunha = sessao.de_quem_aceita
        responde = sessao.de_quem_abre
    else:
        sessao = _Sessao(src_ip, src_port, dst_ip, dst_port)
        envia_testemunha = sessao.de_quem_abre
        responde = sessao.de_quem_aceita

    if com_handshake:
        sessao.handshake()

    flags = cabecalho.get("flags", PSH_ACK)

    if http:
        if direcao == "to_client":
            # Testemunha e resposta de servidor: o aquecimento vem do cliente,
            # que aqui e quem abre.
            responde("aquecimento", PSH_ACK, PEDIDO_DE_AQUECIMENTO)
            envia_testemunha("resposta_servidor", PSH_ACK, RESPOSTA_DO_SERVIDOR)
            responde("aquecimento", PSH_ACK, PEDIDO_DE_AQUECIMENTO)
            envia_testemunha("testemunha", flags, payload or b"X", cabecalho)
            responde("flush", ACK)
        else:
            envia_testemunha("aquecimento", PSH_ACK, PEDIDO_DE_AQUECIMENTO)
            responde("resposta_servidor", PSH_ACK, RESPOSTA_DO_SERVIDOR)
            envia_testemunha("testemunha", flags, payload or b"X", cabecalho)
            responde("flush", ACK)
    else:
        envia_testemunha("testemunha", flags, payload or b"X", cabecalho)

    return sessao.quadros


def quadros_do_caso(
    header: dict,
    payload: bytes,
    com_handshake: bool,
    direcao: str = "to_server",
    http: bool = False,
    icmp: dict | None = None,
    cabecalho: dict | None = None,
) -> list[bytes]:
    """So os quadros, sem papel. Mantido para uso direto e para o autoteste."""

    return [
        quadro
        for _papel, quadro in quadros_com_papel(
            header, payload, com_handshake, direcao, http, icmp, cabecalho
        )
    ]


def escrever_pcap(caminho: Path, quadros: list[bytes]) -> None:
    """Escreve pcap classico, link-type Ethernet, sem dependencia externa."""

    with open(caminho, "wb") as destino:
        destino.write(
            struct.pack("!IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        )
        for indice, quadro in enumerate(quadros):
            destino.write(
                struct.pack(
                    "!IIII",
                    1_700_000_000 + indice // 1000,
                    (indice % 1000) * 1000,
                    len(quadro),
                    len(quadro),
                )
            )
            destino.write(quadro)


# ============================================================
# Caso
# ============================================================


def opcoes_da_regra(regra: dict) -> set[str]:
    nomes = set()
    for lista in (
        "preserved",
        "expanded",
        "delegated",
        "fallback",
        "unassessed",
        "detection_predicates",
        "metadata_predicates",
    ):
        for predicado in regra.get(lista) or []:
            nome = predicado.get("source_option")
            if nome:
                nomes.add(nome)
    return nomes


def sintetizar_caso(regra: dict) -> dict:
    """Devolve o caso da campanha, ou o motivo de recusa.

    Recusa nao e falha: e a fronteira do que este gerador sabe exercitar, e
    entra no relatorio para que a cobertura da campanha seja auditavel em vez
    de presumida.
    """

    motivos = []

    if regra.get("classification") != "NECESSARY":
        motivos.append(f"classificacao {regra.get('classification')}")

    bloqueantes = sorted(opcoes_da_regra(regra) & OPCOES_BLOQUEANTES)
    if bloqueantes:
        motivos.append("opcao nao sintetizavel: " + ", ".join(bloqueantes))

    header = resolver_header(regra)
    if header is None:
        motivos.append("header nao resolvivel")

    if motivos:
        return {
            "rule_id": regra.get("rule_id"),
            "utilizavel": False,
            "motivos_de_recusa": motivos,
        }

    # Direcao do flow decide quem abre a conexao e, no HTTP, se a testemunha
    # e request ou resposta — por isso e resolvida antes de montar o payload.
    # Uma regra `flow:to_client,established` descreve pacote do servidor para
    # o cliente: se o handshake partir do lado que envia a testemunha, o Snort
    # classifica o pacote como to_server, a regra nao dispara e o caso sai
    # vacuo por defeito do gerador, nao do compilador.
    estados_de_flow = []
    for lista in ("preserved", "delegated", "detection_predicates"):
        for predicado in regra.get(lista) or []:
            if predicado.get("source_option") != "flow":
                continue
            estado = str(predicado.get("value") or "")
            if estado and estado not in estados_de_flow:
                estados_de_flow.append(estado)
    texto_flow = ",".join(estados_de_flow)

    precisa_handshake = bool(estados_de_flow) and "stateless" not in texto_flow
    direcao = "to_client" if "to_client" in texto_flow else "to_server"

    montado = montar_payload(regra, direcao)
    if montado is None:
        return {
            "rule_id": regra.get("rule_id"),
            "utilizavel": False,
            "motivos_de_recusa": ["content nao representavel"],
        }

    payload, detalhe = montado
    cabecalho, cabecalho_recusado = campos_de_cabecalho(regra)

    return {
        "rule_id": regra.get("rule_id"),
        "utilizavel": True,
        "header": header,
        "payload_hex": payload.hex(),
        "payload_bytes": len(payload),
        "com_handshake": bool(precisa_handshake) and header["protocolo"] == "tcp",
        "direcao": direcao,
        "flow": texto_flow or None,
        "icmp": campos_icmp(regra) if header["protocolo"] == "icmp" else None,
        "cabecalho": cabecalho or None,
        "cabecalho_nao_sintetizado": cabecalho_recusado or None,
        "detalhe_payload": detalhe,
        "classificacao": regra.get("classification"),
        "prefilter_candidate": regra.get("prefilter_candidate"),
    }


# ============================================================
# Autoteste
# ============================================================


def autoteste(limite: int | None) -> int:
    """Sintetiza casos do manifesto e confere cada testemunha offline.

    A conferencia usa `tests/p4_packet_domain.py`, que espelha o parser do
    `ids_prefilter.p4`: testemunha que cair fora do dominio suportado nao
    serve para medir seletividade, porque o alvo a marcaria como fallback
    conservador por motivo de parser, nao por causa da regra.
    """

    sys.path.insert(0, str(PROJECT_ROOT / "tests"))
    from p4_packet_domain import classify_frame_for_prefilter

    if not MANIFESTO_SEMANTICO.exists():
        print(f"manifesto ausente: {MANIFESTO_SEMANTICO}", file=sys.stderr)
        return 1

    regras = json.loads(MANIFESTO_SEMANTICO.read_text(encoding="utf-8"))["rules"]
    if limite:
        regras = regras[:limite]

    utilizaveis = 0
    recusados = 0
    motivos = {}
    fora_do_dominio = []
    exemplos = []

    for regra in regras:
        caso = sintetizar_caso(regra)
        if not caso["utilizavel"]:
            recusados += 1
            for motivo in caso["motivos_de_recusa"]:
                chave = motivo.split(":")[0]
                motivos[chave] = motivos.get(chave, 0) + 1
            continue

        utilizaveis += 1
        quadros = quadros_do_caso(
            caso["header"],
            bytes.fromhex(caso["payload_hex"]),
            caso["com_handshake"],
            caso.get("direcao", "to_server"),
            bool(caso["detalhe_payload"].get("http")),
            caso.get("icmp"),
        )

        # O ultimo quadro e o que carrega a testemunha.
        # Contrato de classify_frame_for_prefilter: (pacote, motivo). Pacote
        # None e fallback de dominio; pacote presente e o dominio suportado.
        pacote, motivo = classify_frame_for_prefilter(quadros[-1])
        if pacote is None:
            fora_do_dominio.append((caso["rule_id"], motivo))

        if len(exemplos) < 3:
            exemplos.append(caso)

    print(f"regras avaliadas          {len(regras)}")
    print(f"casos utilizaveis         {utilizaveis}")
    print(f"recusados                 {recusados}")
    print("\nmotivos de recusa:")
    for motivo, quantos in sorted(motivos.items(), key=lambda kv: -kv[1]):
        print(f"  {quantos:5d}  {motivo}")

    print(f"\ntestemunhas fora do dominio do parser P4: {len(fora_do_dominio)}")
    for rule_id, categoria in fora_do_dominio[:5]:
        print(f"  regra {rule_id}: {categoria}")

    print("\nexemplos de testemunha:")
    for caso in exemplos:
        payload = bytes.fromhex(caso["payload_hex"])
        print(
            f"  regra {caso['rule_id']}: {caso['header']['protocolo']} "
            f"{caso['header']['src_ip']}:{caso['header']['src_port']} -> "
            f"{caso['header']['dst_ip']}:{caso['header']['dst_port']}, "
            f"handshake={caso['com_handshake']}, payload={len(payload)}B"
        )
        print(f"    {payload[:90]!r}")

    if fora_do_dominio:
        print(
            "\nFALHA: testemunha fora do dominio suportado do parser.",
            file=sys.stderr,
        )
        return 1

    if utilizaveis == 0:
        print("\nFALHA: nenhum caso utilizavel.", file=sys.stderr)
        return 1

    print("\nAUTOTESTE OK")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--autoteste", action="store_true")
    parser.add_argument("--limite", type=int, default=None)
    argumentos = parser.parse_args()

    if argumentos.autoteste:
        return autoteste(argumentos.limite)

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())

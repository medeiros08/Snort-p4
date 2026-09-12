"""Testes de compiler/target_capability.py.

Este modulo decide, para cada predicado de cabecalho, se o alvo P4 consegue
representa-lo (PRESERVED/EXPANDED), se precisa ser delegado ao Snort
(DELEGATED) ou se o predicado deve ser abandonado por seguranca (FALLBACK).
E, junto com semantic_classifier.py, o que determina EXACT / NECESSARY /
UNSUPPORTED — e ate aqui nao tinha um unico teste.

Os casos cobrem deliberadamente as formas que o ruleset avaliado NAO
exercita: negacao de endereco, listas de IP, range aberto a esquerda e a
direcao "<-". Sao justamente os caminhos sem nenhuma evidencia empirica.

Onde o comportamento atual e uma limitacao conhecida — e nao o ideal — o
teste documenta o comportamento real e diz por que, para que qualquer
mudanca futura apareca como decisao deliberada e nao como regressao.

A direcao de seguranca importa mais que o rotulo: FALLBACK e DELEGATED
descartam o predicado, o que so ALARGA o conjunto de pacotes candidatos e
preserva Snort(r,p) => P4_candidato(r,p). Nenhum caminho pode ESTREITAR.
"""

import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "compiler"))

from semantic_ir import make_header_predicate
from target_capability import (
    assess_direction,
    assess_flags,
    assess_future_header,
    assess_ip,
    assess_port,
    assess_protocol,
    is_exact_port,
    is_ipv4_or_cidr,
    is_port_range,
)

# Tratamentos que descartam o predicado e portanto alargam o candidato.
ALARGAM = {"DELEGATED", "FALLBACK"}

# Tratamentos que mantem o predicado na tabela.
RESTRINGEM = {"PRESERVED", "EXPANDED"}


def predicado(campo, valor):
    return make_header_predicate(
        field=campo,
        operator="exact",
        value=valor,
    )


def trata(avaliador, campo, valor):
    return avaliador(predicado(campo, valor))


# ------------------------------------------------------------------
# protocolo
# ------------------------------------------------------------------


def test_protocolo_l3_suportado():
    for valor in ("tcp", "udp", "icmp"):
        tratamento, razao = trata(assess_protocol, "protocol", valor)
        assert tratamento == "PRESERVED", valor
        assert razao == "supported_ip_protocol"


def test_protocolo_e_normalizado_antes_de_comparar():
    for valor in ("TCP", "  tcp  ", "Tcp"):
        tratamento, _ = trata(assess_protocol, "protocol", valor)
        assert tratamento == "PRESERVED", valor


def test_protocolo_ip_e_wildcard_e_nao_restringe():
    tratamento, razao = trata(assess_protocol, "protocol", "ip")
    assert tratamento == "PRESERVED"
    assert razao == "protocol_wildcard"


def test_protocolo_de_aplicacao_e_delegado():
    for valor in ("http", "ssl", "dns", "gre", "ipv6"):
        tratamento, razao = trata(assess_protocol, "protocol", valor)
        assert tratamento == "DELEGATED", valor
        assert razao == "application_or_unsupported_protocol"


# ------------------------------------------------------------------
# endereco
# ------------------------------------------------------------------


def test_ip_wildcard():
    tratamento, razao = trata(assess_ip, "src_ip", "any")
    assert tratamento == "PRESERVED"
    assert razao == "wildcard"


def test_ip_literal_e_cidr():
    for valor in ("192.168.10.5", "192.168.10.0/24", "10.0.0.0/8", "0.0.0.0/0"):
        tratamento, razao = trata(assess_ip, "dst_ip", valor)
        assert tratamento == "PRESERVED", valor
        assert razao == "ipv4_or_cidr_supported"


def test_ip_variavel_nao_resolvida_fica_pendente():
    tratamento, razao = trata(assess_ip, "src_ip", "$HOME_NET")
    assert tratamento == "UNASSESSED"
    assert razao == "requires_variable_resolution"


def test_ip_negado_cai_em_fallback():
    # Forma nunca exercitada pelo ruleset avaliado (zero ocorrencias).
    for valor in ("!192.168.10.0/24", "!$HOME_NET", "![10.0.0.0/8]"):
        tratamento, razao = trata(assess_ip, "src_ip", valor)
        assert tratamento == "FALLBACK", valor
        assert razao == "negated_address_not_supported"
        assert tratamento in ALARGAM


def test_ip_lista_homogenea_expande():
    tratamento, _ = trata(
        assess_ip, "dst_ip", ["192.168.10.0/24", "10.0.0.0/8"]
    )
    assert tratamento == "EXPANDED"


def test_ip_lista_textual_expande():
    tratamento, _ = trata(
        assess_ip, "dst_ip", "[192.168.10.0/24,10.0.0.0/8]"
    )
    assert tratamento == "EXPANDED"


def test_ip_lista_com_item_invalido_nao_expande_parcialmente():
    # O item ruim contamina a lista inteira: nao se instala meia lista, o
    # que produziria predicado mais ESTREITO que a regra.
    tratamento, _ = trata(
        assess_ip, "dst_ip", ["192.168.10.0/24", "nao-e-um-endereco"]
    )
    assert tratamento in ALARGAM


def test_ip_expressao_sem_sentido_cai_em_fallback():
    tratamento, razao = trata(assess_ip, "src_ip", "banana")
    assert tratamento == "FALLBACK"
    assert razao == "unsupported_address_expression"


# ------------------------------------------------------------------
# porta
# ------------------------------------------------------------------


def test_porta_exata():
    for valor in ("80", 80, "443"):
        tratamento, razao = trata(assess_port, "dst_port", valor)
        assert tratamento == "PRESERVED", valor
        assert razao == "exact_port_supported"


def test_porta_wildcard():
    tratamento, razao = trata(assess_port, "src_port", "any")
    assert tratamento == "PRESERVED"
    assert razao == "wildcard"


def test_porta_variavel_fica_pendente():
    tratamento, razao = trata(assess_port, "dst_port", "$HTTP_PORTS")
    assert tratamento == "UNASSESSED"
    assert razao == "requires_variable_resolution"


def test_porta_lista_exata_expande():
    tratamento, _ = trata(assess_port, "dst_port", ["80", "443", "8080"])
    assert tratamento == "EXPANDED"


def test_range_de_porta_cai_em_fallback():
    # Limitacao conhecida: a chave da tabela e ternary e comportaria a
    # decomposicao de um range, mas o backend ainda nao a implementa.
    # 75 regras do ruleset avaliado perdem o predicado de porta por isto.
    for valor in ("12345:12346", "1024:", "6666:7000", ":1024"):
        tratamento, razao = trata(assess_port, "dst_port", valor)
        assert tratamento == "FALLBACK", valor
        assert razao == "port_range_not_supported"
        assert tratamento in ALARGAM


def test_lista_com_range_contamina_a_lista_inteira():
    tratamento, razao = trata(
        assess_port, "dst_port", ["135", "139", "1024:"]
    )
    assert tratamento == "FALLBACK"
    assert razao == "port_list_contains_range"


def test_porta_negada_cai_em_fallback():
    tratamento, razao = trata(assess_port, "src_port", "!21:23")
    assert tratamento == "FALLBACK"
    assert razao == "negated_port_not_supported"


def test_porta_fora_de_faixa_nao_e_exata():
    assert is_exact_port("65536") is False
    assert is_exact_port("-1") is False
    assert is_exact_port("0") is True
    assert is_exact_port("65535") is True


# ------------------------------------------------------------------
# direcao
# ------------------------------------------------------------------


def test_direcao_forward():
    tratamento, razao = trata(assess_direction, "direction", "->")
    assert tratamento == "PRESERVED"
    assert razao == "forward_direction_supported"


def test_direcao_bidirecional_expande():
    tratamento, razao = trata(assess_direction, "direction", "<>")
    assert tratamento == "EXPANDED"
    assert razao == "bidirectional_requires_expansion"


def test_direcao_invertida_cai_em_fallback():
    # "<-" nao e operador valido no Snort 3 (parse_rule.cc emite
    # ParseError), mas parser.py o aceita. Enquanto aceitar, o unico
    # tratamento seguro aqui e FALLBACK.
    tratamento, razao = trata(assess_direction, "direction", "<-")
    assert tratamento == "FALLBACK"
    assert razao == "unsupported_direction"


# ------------------------------------------------------------------
# flags TCP
# ------------------------------------------------------------------


def test_flags_simples_sao_preservadas():
    for valor in ("S", "SA", "FPS", "A+", "U+", "FRS*"):
        tratamento, _ = trata(assess_flags, "flags", valor)
        assert tratamento == "PRESERVED", valor


def test_flags_com_digito_caem_em_fallback():
    # 1 = CWR e 2 = ECE na sintaxe do Snort. Sao representaveis na chave
    # ternary, mas a heuristica atual e conservadora e manda tudo que tem
    # digito para fallback. Quatro regras do ruleset avaliado.
    for valor in ("AS,12", "12FS", "12AP", "12FSU"):
        tratamento, razao = trata(assess_flags, "flags", valor)
        assert tratamento == "FALLBACK", valor
        assert razao == "unsupported_flags_encoding"


def test_flags_invalidas_sem_digito_sao_aceitas_aqui():
    # LIMITACAO CONHECIDA, nao comportamento desejado.
    #
    # assess_flags so filtra por digito, entao lixo sem digito passa como
    # PRESERVED. O erro so aparece tres estagios depois, em
    # normalize_p4_entries.normalize_tcp_flags, que levanta ValueError; a
    # entrada e entao descartada e registrada em "failures".
    #
    # A direcao continua segura (a regra perde o predicado, nao ganha um
    # predicado errado), mas a camada que se chama "analise de capacidade
    # do alvo" esta afirmando uma capacidade que o alvo nao tem.
    tratamento, _ = trata(assess_flags, "flags", "ZZ")
    assert tratamento == "PRESERVED"


# ------------------------------------------------------------------
# campos de cabecalho ainda nao implementados no backend
# ------------------------------------------------------------------


def test_campos_futuros_sao_sempre_delegados():
    # itype/icode/ip_proto sao triviais em P4 e o parser ja extrai o
    # cabecalho ICMP; simplesmente nao estao na chave da tabela. Delegar e
    # seguro (alarga), mas custa seletividade: 237 decisoes no manifesto.
    for campo in (
        "ttl",
        "id",
        "ip_proto",
        "seq",
        "ack",
        "itype",
        "icode",
        "icmp_id",
        "icmp_seq",
        "fragbits",
    ):
        tratamento, razao = trata(assess_future_header, campo, "8")
        assert tratamento == "DELEGATED", campo
        assert razao == "p4_candidate_not_implemented_in_current_backend"
        assert tratamento in ALARGAM


# ------------------------------------------------------------------
# auxiliares de reconhecimento
# ------------------------------------------------------------------


def test_reconhecimento_de_range():
    assert is_port_range("1024:") is True
    assert is_port_range(":1024") is True
    assert is_port_range("1:1024") is True
    assert is_port_range("80") is False


def test_reconhecimento_de_ipv4():
    assert is_ipv4_or_cidr("192.168.10.5") is True
    assert is_ipv4_or_cidr("192.168.10.0/24") is True
    assert is_ipv4_or_cidr("999.1.1.1") is False
    assert is_ipv4_or_cidr("nao-e-um-ip") is False


# ------------------------------------------------------------------
# invariante transversal
# ------------------------------------------------------------------


def test_nenhum_avaliador_produz_tratamento_fora_do_dominio():
    dominio = RESTRINGEM | ALARGAM | {"UNASSESSED"}

    casos = [
        (assess_protocol, "protocol", ["tcp", "ip", "http", "", "   ", "42"]),
        (assess_ip, "src_ip", ["any", "$X", "!a", "1.2.3.4", "[1.2.3.4]", "", "lixo"]),
        (assess_port, "dst_port", ["any", "$X", "!80", "80", "1:2", "[80,443]", "", "lixo"]),
        (assess_direction, "direction", ["->", "<>", "<-", "", "xx"]),
        (assess_flags, "flags", ["S", "12", "", "ZZ"]),
    ]

    for avaliador, campo, valores in casos:
        for valor in valores:
            tratamento, razao = trata(avaliador, campo, valor)
            assert tratamento in dominio, (avaliador.__name__, valor, tratamento)
            assert isinstance(razao, str) and razao, (avaliador.__name__, valor)


def main():
    testes = [
        (nome, objeto)
        for nome, objeto in sorted(globals().items())
        if nome.startswith("test_") and callable(objeto)
    ]

    falhas = []

    for nome, funcao in testes:
        try:
            funcao()
        except AssertionError as erro:
            falhas.append((nome, erro))

    for nome, erro in falhas:
        print(f"FALHOU: {nome}: {erro}")

    print(
        f"target_capability: {len(testes) - len(falhas)}/{len(testes)} "
        f"testes passaram."
    )

    if falhas:
        sys.exit(1)


if __name__ == "__main__":
    main()

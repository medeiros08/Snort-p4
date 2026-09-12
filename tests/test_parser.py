"""Testes de compiler/parser.py.

Cobrem o contrato de saida do parser e as duas formas que ele passou a
rejeitar por serem formas que o proprio Snort 3 rejeita.

O criterio adotado e: o parser nao deve aceitar regra que o Snort nao
carrega. Aceitar era pior que rejeitar, porque a regra entrava no manifesto
como candidata e o predicado gerado nao correspondia a nenhuma regra viva.
"""

import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "compiler"))

from parser import (
    RegraMalformada,
    extract_sid,
    parse_options,
    parse_rule,
    split_options,
)


# ------------------------------------------------------------------
# contrato de saida
# ------------------------------------------------------------------


def test_regra_tradicional_tem_a_forma_esperada():
    r = parse_rule(
        'alert tcp $EXTERNAL_NET any -> $HOME_NET 80 '
        '( msg:"exemplo"; content:"/x"; sid:1234; rev:2; )'
    )

    assert r["rule_type"] == "TRADITIONAL"
    assert r["action"] == "alert"
    assert r["protocol"] == "tcp"
    assert r["source"] == {"address": "$EXTERNAL_NET", "port": "any"}
    assert r["destination"] == {"address": "$HOME_NET", "port": "80"}
    assert r["direction"] == "->"
    assert r["sid"] == 1234
    assert [o["name"] for o in r["options"]] == ["msg", "content", "sid", "rev"]


def test_regra_de_servico_nao_fabrica_cabecalho():
    r = parse_rule('alert http ( msg:"servico"; content:"/x"; sid:42; )')

    assert r["rule_type"] == "SERVICE"
    assert r["service"] == "http"
    assert r["source"] is None
    assert r["destination"] is None
    assert r["direction"] is None


def test_ordem_e_duplicatas_das_opcoes_sao_preservadas():
    r = parse_rule(
        'alert tcp any any -> any any '
        '( content:"a"; content:"b"; content:"a"; sid:7; )'
    )
    nomes = [o["name"] for o in r["options"]]
    assert nomes == ["content", "content", "content", "sid"]
    assert [o["value"] for o in r["options"][:3]] == ["a", "b", "a"]


def test_ponto_e_virgula_dentro_de_aspas_nao_separa_opcao():
    r = parse_rule(
        'alert tcp any any -> any any ( content:"a;b;c"; sid:8; )'
    )
    assert len(r["options"]) == 2
    assert r["options"][0]["value"] == "a;b;c"


def test_opcao_sem_valor():
    opcoes = parse_options("nocase; sid:9;")
    assert opcoes[0] == {"name": "nocase", "value": None}


def test_sid_ausente_nao_e_erro():
    r = parse_rule('alert tcp any any -> any any ( msg:"sem sid"; )')
    assert r["sid"] is None


def test_extract_sid_converte_para_inteiro():
    assert extract_sid([{"name": "sid", "value": "2001"}]) == 2001


# ------------------------------------------------------------------
# direcao
# ------------------------------------------------------------------


def test_direcoes_validas_do_snort3():
    for seta in ("->", "<>"):
        r = parse_rule(
            f'alert tcp any any {seta} any any ( sid:10; )'
        )
        assert r["direction"] == seta


def test_direcao_invertida_e_rejeitada():
    # O Snort 3 emite ParseError("illegal direction specifier") para
    # qualquer operador que nao seja "->" ou "<>" (parse_rule_dir, em
    # src/parser/parse_rule.cc). Aceitar "<-" produzia predicado com
    # orientacao invertida para uma regra que o Snort sequer carrega.
    try:
        parse_rule(
            'alert tcp 10.0.0.0/8 any <- 192.168.10.0/24 80 ( sid:11; )'
        )
    except ValueError:
        return
    raise AssertionError("'<-' deveria ter sido rejeitado")


# ------------------------------------------------------------------
# aspas
# ------------------------------------------------------------------


def test_aspa_impar_e_rejeitada():
    # Sem esta checagem, o msg absorvia content e sid: a regra ficava com
    # uma opcao em vez de tres, sem sid, e sem nenhum predicado de
    # deteccao — o que a fazia sair classificada EXACT, a unica classe que
    # autoriza o data plane a decidir a deteccao sozinho.
    try:
        parse_rule(
            'alert tcp any any -> any 80 '
            '( msg:"quote " here"; content:"/x"; sid:12; )'
        )
    except RegraMalformada:
        return
    raise AssertionError("aspa desbalanceada deveria ter sido rejeitada")


def test_aspas_pares_mal_posicionadas_continuam_validas():
    # Forma que o Snort aceita e que ocorre no ruleset real; nao pode ser
    # confundida com string aberta.
    r = parse_rule(
        'alert tcp any any -> any 80 '
        '( msg:"SERVER-WEBAPP "admin" login"; content:"/x"; sid:13; )'
    )
    assert len(r["options"]) == 3
    assert r["sid"] == 13


def test_aspa_escapada_nao_conta_para_o_balanceamento():
    r = parse_rule(
        'alert tcp any any -> any any ( content:"diz \\" aspas"; sid:14; )'
    )
    assert r["sid"] == 14


def test_malformada_e_subclasse_de_value_error():
    # Os chamadores existentes capturam ValueError; a nova excecao precisa
    # continuar sendo pega por eles, para que a regra va para "failures"
    # em vez de derrubar o estagio com traceback.
    assert issubclass(RegraMalformada, ValueError)


# ------------------------------------------------------------------
# rejeicao geral
# ------------------------------------------------------------------


def test_linhas_que_nao_sao_regra_sao_rejeitadas():
    for texto in (
        "",
        "isto nao e uma regra",
        "alert tcp any any -> any any sem parenteses",
    ):
        try:
            parse_rule(texto)
        except ValueError:
            continue
        raise AssertionError(f"deveria ter rejeitado: {texto!r}")


def test_split_options_respeita_aspas():
    partes = split_options('msg:"a; b"; sid:1;')
    assert len(partes) == 2


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

    print(f"parser: {len(testes) - len(falhas)}/{len(testes)} testes passaram.")

    if falhas:
        sys.exit(1)


if __name__ == "__main__":
    main()

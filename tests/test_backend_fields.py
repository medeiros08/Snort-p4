"""Testes do vocabulario de campos e da colisao de campo no backend.

Cobrem dois defeitos latentes de contrato entre p4_backend.py e
expand_p4_entries.py, nenhum dos quais o ruleset avaliado exercita — e por
isso nenhum deles tinha como aparecer nos artefatos congelados.
"""

import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "compiler"))

import backend_fields
import p4_backend
from build_semantic_ir import build_semantic_ir
from parser import parse_rule
from semantic_classifier import classify_assessed_rule
from semantic_manifest import build_manifest_record
from target_capability import assess_rule


def entrada_de(texto):
    regra = parse_rule(texto)
    ir = build_semantic_ir(regra)
    avaliada = assess_rule(ir)

    if isinstance(avaliada, tuple):
        objeto, razoes = avaliada
    else:
        objeto, razoes = avaliada, []

    classificacao = classify_assessed_rule(objeto)

    registro = build_manifest_record(
        regra, regra, objeto, objeto, classificacao, razoes, []
    )

    return p4_backend.build_p4_entry(registro)


# ------------------------------------------------------------------
# vocabulario
# ------------------------------------------------------------------


def test_o_unico_campo_que_muda_de_nome_e_flags():
    divergentes = [
        semantico
        for semantico, backend in backend_fields.SEMANTICO_PARA_BACKEND.items()
        if semantico != backend
    ]
    assert divergentes == ["flags"]
    assert backend_fields.nome_de_backend("flags") == "tcp_flags"


def test_mapa_cobre_todos_os_campos_de_match():
    # Se alguem acrescentar um campo a MATCH_FIELDS sem decidir seu nome de
    # backend, este teste reprova — que e o ponto.
    assert p4_backend.MATCH_FIELDS == set(
        backend_fields.SEMANTICO_PARA_BACKEND
    )


def test_campo_desconhecido_volta_inalterado():
    assert backend_fields.nome_de_backend("campo_novo") == "campo_novo"


def test_expansiveis_usam_nomes_de_backend():
    # Todo nome expansivel tem de ser um nome de backend valido, senao o
    # expansor procura por um nome que o match nunca carrega.
    nomes_de_backend = set(backend_fields.SEMANTICO_PARA_BACKEND.values())
    assert backend_fields.EXPANSIVEIS <= nomes_de_backend


def test_expansor_usa_a_fonte_unica():
    import expand_p4_entries

    assert expand_p4_entries.EXPANDABLE_FIELDS is backend_fields.EXPANSIVEIS


def test_expansion_fields_sai_com_nome_de_backend():
    # Lista de portas -> EXPANDED. O nome tem de ser o do match.
    entrada = entrada_de(
        'alert tcp any any -> any [80,443] ( content:"x"; sid:1; )'
    )
    assert "dst_port" in entrada["match"]
    assert entrada["expansion_fields"] == ["dst_port"]


def test_flags_expandido_sairia_com_o_nome_do_match():
    # O bug latente: antes desta correcao, um predicado `flags` marcado
    # EXPANDED produziria expansion_fields=["flags"], nome ausente do
    # vocabulario do expansor, e a entrada nunca seria expandida enquanto o
    # match carregaria uma lista em "tcp_flags".
    #
    # assess_flags nunca devolve EXPANDED hoje, entao o caminho e exercitado
    # diretamente sobre a traducao.
    assert backend_fields.nome_de_backend("flags") in backend_fields.EXPANSIVEIS


# ------------------------------------------------------------------
# colisao de campo
# ------------------------------------------------------------------


def test_regra_normal_nao_ganha_a_chave_de_colisao():
    # A chave so aparece quando ha colisao, para nao alterar os artefatos de
    # um ruleset que nao a exercita. Nenhuma das 4.017 regras avaliadas
    # repete um campo de cabecalho.
    entrada = entrada_de(
        'alert tcp any any -> any 80 ( flags:S; content:"x"; sid:2; )'
    )
    assert "field_collisions" not in entrada


def test_campo_repetido_e_registrado_em_vez_de_sumir():
    entrada = entrada_de(
        'alert tcp any any -> any 80 ( flags:S; flags:A; content:"x"; sid:3; )'
    )

    colisoes = entrada.get("field_collisions")
    assert colisoes, "a colisao deveria ter sido registrada"
    assert len(colisoes) == 1
    assert colisoes[0]["field"] == "flags"

    # Manter uma das condicoes conjuntas e relaxacao segura: A e S implica
    # A. O que nao pode e o descarte ser invisivel.
    assert colisoes[0]["kept"] == "A"
    assert colisoes[0]["discarded"] == "S"
    assert entrada["match"]["tcp_flags"] == "A"


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
        f"backend_fields: {len(testes) - len(falhas)}/{len(testes)} "
        f"testes passaram."
    )

    if falhas:
        sys.exit(1)


if __name__ == "__main__":
    main()

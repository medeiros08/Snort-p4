"""Testes da verificacao do contrato do P4Info.

A versao anterior de verify_p4info_text procurava fragmentos SOLTOS por
substring, incluindo 'id: 1' ate 'id: 6'. Esses literais aparecem em
praticamente qualquer P4Info, e a adjacencia entre um id e o nome do campo
correspondente nunca era conferida — de modo que um P4 recompilado com os
campos trocados de id passava pelo gate.

Isso importa porque o codificador usa FIELD_INFO para decidir em qual
field_id gravar cada campo do match. Com src_port e dst_port trocados no
P4Info, toda entrada instalada teria as portas invertidas: uma regra para a
porta de destino 80 casaria a porta de ORIGEM 80. Isso nao e perda de
precisao, e predicado errado — quebraria Snort(r,p) => P4_candidato(r,p).
"""

import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "compiler"))

from generate_p4runtime_install import (
    ACTION_ID,
    ACTION_NAME,
    FIELD_INFO,
    TABLE_ID,
    TABLE_NAME,
    verify_p4info_text,
)

P4INFO = RAIZ / "output" / "ids_prefilter.p4info.txt"


def texto_real():
    return P4INFO.read_text(encoding="utf-8")


def rejeita(texto):
    """Devolve a mensagem de erro, ou None se o texto foi aceito."""
    try:
        verify_p4info_text(texto)
    except ValueError as erro:
        return str(erro)
    return None


def test_aceita_o_p4info_real():
    assert rejeita(texto_real()) is None


def test_rejeita_campos_trocados_de_id():
    # O caso que a verificacao por substring aceitava: todas as strings
    # continuam presentes, so a adjacencia id<->name muda.
    mutado = texto_real().replace(
        'id: 4\n    name: "meta.l4_src_port"',
        'id: 4\n    name: "meta.l4_dst_port"',
    ).replace(
        'id: 5\n    name: "meta.l4_dst_port"',
        'id: 5\n    name: "meta.l4_src_port"',
    )

    assert mutado != texto_real(), "a mutacao nao foi aplicada"

    erro = rejeita(mutado)
    assert erro is not None, "campos trocados deveriam ser rejeitados"
    assert "src_port" in erro and "dst_port" in erro


def test_rejeita_bitwidth_diferente():
    mutado = texto_real().replace(
        'name: "hdr.ipv4.protocol"\n    bitwidth: 8',
        'name: "hdr.ipv4.protocol"\n    bitwidth: 16',
    )
    erro = rejeita(mutado)
    assert erro is not None
    assert "bitwidth" in erro


def test_rejeita_match_type_que_nao_seja_ternary():
    # O codificador monta value/mask para todo campo; um campo EXACT nao
    # aceitaria mascara.
    mutado = texto_real().replace(
        'name: "hdr.ipv4.srcAddr"\n    bitwidth: 32\n    match_type: TERNARY',
        'name: "hdr.ipv4.srcAddr"\n    bitwidth: 32\n    match_type: LPM',
    )
    erro = rejeita(mutado)
    assert erro is not None
    assert "TERNARY" in erro


def test_rejeita_tabela_ausente():
    mutado = texto_real().replace(TABLE_NAME, "MyIngress.outra_tabela")
    erro = rejeita(mutado)
    assert erro is not None
    assert TABLE_NAME in erro


def test_rejeita_id_de_tabela_diferente():
    mutado = texto_real().replace(f"id: {TABLE_ID}", "id: 99999999", 1)
    erro = rejeita(mutado)
    assert erro is not None
    assert "table id" in erro


def test_rejeita_acao_fora_dos_action_refs():
    mutado = texto_real().replace(
        f"  action_refs {{\n    id: {ACTION_ID}\n  }}\n",
        "",
        1,
    )
    assert mutado != texto_real()
    erro = rejeita(mutado)
    assert erro is not None
    assert "action_refs" in erro


def test_rejeita_campo_de_match_ausente():
    mutado = texto_real().replace(
        '  match_fields {\n    id: 6\n    name: "meta.tcp_flags"\n'
        "    bitwidth: 8\n    match_type: TERNARY\n  }\n",
        "",
        1,
    )
    assert mutado != texto_real()
    erro = rejeita(mutado)
    assert erro is not None
    assert "ausente" in erro


def test_contrato_declarado_bate_com_o_p4info():
    # Guarda contra FIELD_INFO e P4Info divergirem sem ninguem notar.
    texto = texto_real()
    for campo, info in FIELD_INFO.items():
        assert info["p4_name"] in texto, campo
    assert ACTION_NAME in texto


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
        f"p4info_contract: {len(testes) - len(falhas)}/{len(testes)} "
        f"testes passaram."
    )

    if falhas:
        sys.exit(1)


if __name__ == "__main__":
    main()

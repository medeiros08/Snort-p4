"""Testes de limpar_ruleset (compiler/run_static_pipeline.py, --limpar).

A limpeza deixa so as regras ativas, para que a divisao das regras aceite
rulesets distribuidos em pacote. Para gid:sid repetido ela tem de fazer o que
o Snort 3.12.2.0 faz ao carregar o ruleset (src/parser/parse_rule.cc,
mergeDuplicateOtn): ficar com a revisao maior, com a mais recente no
empate, e recusar quando as ocorrencias diferem em acao ou protocolo.
Qualquer outra escolha compilaria uma regra que o Snort nao usa.
"""

import sys
import tempfile
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "compiler"))

from run_static_pipeline import limpar_ruleset  # noqa: E402


def _regra(sid, rev, msg, gid=None, acao="alert", proto="tcp"):
    gid_texto = f" gid:{gid};" if gid is not None else ""
    return (
        f'{acao} {proto} any any -> any 80 ( msg:"{msg}"; content:"x";'
        f"{gid_texto} sid:{sid}; rev:{rev}; )"
    )


def _limpar(texto):
    with tempfile.TemporaryDirectory() as tmp:
        origem = Path(tmp) / "entrada.rules"
        destino = Path(tmp) / "saida.rules"
        origem.write_text(texto, encoding="utf-8")
        relatorio = limpar_ruleset(origem, destino)
        return relatorio, destino.read_text(encoding="utf-8").splitlines()


def test_remove_comentarios_regras_comentadas_e_sem_sid():
    texto = "\n".join(
        [
            "# Copyright 2001-2005 Sourcefire, Inc.",
            "",
            "# " + _regra(10, 1, "comentada"),
            'alert tcp any any -> any any ( msg:"sem sid"; content:"y"; )',
            _regra(11, 1, "ativa"),
        ]
    )
    relatorio, regras = _limpar(texto)
    assert relatorio["comentarios"] == 1
    assert relatorio["regras_comentadas"] == 1
    assert relatorio["linhas_vazias"] == 1
    assert len(relatorio["sem_sid"]) == 1
    assert relatorio["sem_sid"][0]["linha"] == 4
    assert regras == [_regra(11, 1, "ativa")]


def test_duplicada_fica_a_revisao_maior():
    # A nova tem revisao menor: o Snort mantem a original.
    relatorio, regras = _limpar(
        "\n".join([_regra(20, 5, "rev5"), _regra(20, 3, "rev3")])
    )
    assert regras == [_regra(20, 5, "rev5")]
    assert relatorio["duplicadas"][0]["mantida"] == 1

    # A nova tem revisao maior: o Snort troca pela nova.
    relatorio, regras = _limpar(
        "\n".join([_regra(21, 3, "rev3"), _regra(21, 5, "rev5")])
    )
    assert regras == [_regra(21, 5, "rev5")]
    assert relatorio["duplicadas"][0]["mantida"] == 2


def test_duplicada_com_mesma_revisao_fica_a_mais_recente():
    relatorio, regras = _limpar(
        "\n".join([_regra(30, 2, "primeira"), _regra(30, 2, "segunda")])
    )
    assert regras == [_regra(30, 2, "segunda")]
    assert relatorio["duplicadas"][0]["revisoes"] == [2, 2]


def test_mesmo_sid_com_gid_diferente_nao_e_duplicata():
    # A identidade no Snort e gid:sid, com gid 1 quando ausente.
    texto = "\n".join(
        [_regra(40, 1, "gid1"), _regra(40, 1, "gid1 explicito", gid=1), _regra(40, 1, "gid3", gid=3)]
    )
    relatorio, regras = _limpar(texto)
    assert len(relatorio["duplicadas"]) == 1
    assert relatorio["regras_mantidas"] == 2
    assert _regra(40, 1, "gid3", gid=3) in regras


def test_duplicada_com_protocolo_diferente_e_recusada():
    texto = "\n".join([_regra(50, 1, "tcp"), _regra(50, 2, "udp", proto="udp")])
    try:
        _limpar(texto)
    except ValueError as erro:
        assert "sid 50" in str(erro)
    else:
        raise AssertionError("o Snort recusa este ruleset; a limpeza tambem deveria")


def test_regra_em_varias_linhas_e_juntada():
    texto = 'alert tcp any any -> any 80 ( msg:"quebrada"; \\\n    content:"z"; sid:60; rev:1; )\n'
    relatorio, regras = _limpar(texto)
    assert relatorio["regras_mantidas"] == 1
    assert len(regras) == 1
    assert "sid:60;" in regras[0] and 'content:"z";' in regras[0]
    assert "\\" not in regras[0]


def test_ruleset_do_projeto_passa_intacto():
    # O ruleset padrao ja e limpo: a limpeza nao pode alterar uma regra.
    origem = RAIZ / "rules" / "snort3-community.rules"
    with tempfile.TemporaryDirectory() as tmp:
        destino = Path(tmp) / "limpo.rules"
        relatorio = limpar_ruleset(origem, destino)
        original = [l.strip() for l in origem.read_text(encoding="utf-8").splitlines() if l.strip()]
        assert destino.read_text(encoding="utf-8").splitlines() == original
    assert relatorio["duplicadas"] == [] and relatorio["sem_sid"] == []
    assert relatorio["regras_mantidas"] == 4017


if __name__ == "__main__":
    test_remove_comentarios_regras_comentadas_e_sem_sid()
    test_duplicada_fica_a_revisao_maior()
    test_duplicada_com_mesma_revisao_fica_a_mais_recente()
    test_mesmo_sid_com_gid_diferente_nao_e_duplicata()
    test_duplicada_com_protocolo_diferente_e_recusada()
    test_regra_em_varias_linhas_e_juntada()
    test_ruleset_do_projeto_passa_intacto()
    print("Limpeza de ruleset: testes passaram.")

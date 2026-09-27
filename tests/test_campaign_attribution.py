import json
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
TESTS_DIR = PROJECT_ROOT / "tests"
CAMPANHAS = PROJECT_ROOT / "output" / "campaign"

sys.path.insert(
    0,
    str(TESTS_DIR)
)


from analyze_campaign_attribution import cobertura


PROVENIENCIA = [
    {"105"},
    {"105", "200"},
    {"300"},
]


def test_so_a_propria_regra_casa():
    assert cobertura("105", [0], PROVENIENCIA) == "so_propria"
    # Entrada deduplicada que carrega o sid do caso ainda e da propria regra.
    assert cobertura("105", [0, 1], PROVENIENCIA) == "so_propria"


def test_propria_com_outras():
    assert cobertura("105", [0, 2], PROVENIENCIA) == "propria_e_outras"


def test_so_outras_regras():
    assert cobertura("105", [2], PROVENIENCIA) == "so_outras"


def test_nenhuma_entrada():
    assert cobertura("105", [], PROVENIENCIA) == "nenhuma"


def _confere_com_relatorio(atribuicao_nome, relatorio_nome, rodada):
    atribuicao = json.loads(
        (CAMPANHAS / rodada / atribuicao_nome).read_text(encoding="utf-8")
    )
    relatorio = json.loads(
        (CAMPANHAS / rodada / relatorio_nome).read_text(encoding="utf-8")
    )

    por_veredito = atribuicao["cobertura_da_testemunha_por_veredito"]
    somas = {
        veredito: sum(contagem.values())
        for veredito, contagem in por_veredito.items()
    }
    assert somas == relatorio["vereditos"]

    confirmados = por_veredito.get("CONFIRMADO", {})
    assert atribuicao["confirmados_so_propria"]["total"] == confirmados.get("so_propria", 0)
    assert len(atribuicao["confirmados_so_propria"]["sids"]) == confirmados.get("so_propria", 0)

    # Todo CONFIRMADO tem a testemunha casada por entrada da propria regra:
    # "so_outras" ou "nenhuma" num confirmado seria atribuicao sem sentido.
    assert "so_outras" not in confirmados
    assert "nenhuma" not in confirmados

    concordancia = atribuicao["concordancia_predicao_medicao"]
    assert concordancia["divergem"] == 0
    assert concordancia["concordam"] == concordancia["quadros_comparados"]

    return atribuicao


def test_rodada_v4_strong_coerente_com_o_relatorio():
    atribuicao = _confere_com_relatorio(
        "atribuicao_strong.json", "relatorio_strong.json", "e2e_1000_v4"
    )
    assert atribuicao["confirmados_so_propria"]["total"] == 153


def test_rodada_v2_global_coerente_com_o_relatorio():
    atribuicao = _confere_com_relatorio(
        "atribuicao.json", "relatorio.json", "e2e_1000_v2"
    )
    # Sob o plano completo nenhuma confirmacao isola a propria regra.
    assert atribuicao["confirmados_so_propria"]["total"] == 0


if __name__ == "__main__":

    test_so_a_propria_regra_casa()
    test_propria_com_outras()
    test_so_outras_regras()
    test_nenhuma_entrada()
    test_rodada_v4_strong_coerente_com_o_relatorio()
    test_rodada_v2_global_coerente_com_o_relatorio()

    print(
        "Campaign attribution tests passed."
    )

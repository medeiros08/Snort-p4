"""Testes do detector de sintaxe Snort 2 (compiler/snort2_syntax.py).

Duas garantias: nenhuma regra valida em Snort 3 e acusada (o ruleset do
projeto inteiro passa limpo), e cada forma que o Snort 3.12.2.0 deixou de
aceitar e acusada, segundo docs/vendor/snort3/doc/upgrade/snort_upgrade.text.
A lista de opcoes gravada no modulo e conferida contra o manual de
referencia quando o corpus fixado esta presente.
"""

import re
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "compiler"))

from parser import parse_rule  # noqa: E402
from snort2_syntax import OPCOES_DO_SNORT3, analisar_ruleset, marcas_da_regra  # noqa: E402

MANUAL = RAIZ / "docs" / "vendor" / "snort3" / "doc" / "reference" / "snort_reference.text"


def _marcas(regra):
    return marcas_da_regra(parse_rule(regra))


def test_lista_de_opcoes_confere_com_o_manual():
    if not MANUAL.exists():
        print("  corpus fixado ausente: conferencia da lista pulada")
        return
    texto = MANUAL.read_text(encoding="utf-8")
    do_manual = set(re.findall(r"^\s*\*\s*ips_option::(\w+):", texto, re.M))
    assert do_manual == set(OPCOES_DO_SNORT3)
    assert len(OPCOES_DO_SNORT3) == 144


def test_ruleset_do_projeto_passa_limpo():
    resumo = analisar_ruleset(RAIZ / "rules" / "snort3-community.rules")
    assert resumo["regras_lidas"] == 4017
    assert resumo["regras_com_sintaxe_snort2"] == 0


def test_sintaxe_snort3_valida_nao_e_acusada():
    validas = [
        'alert tcp any any -> any 80 ( msg:"a"; flow:to_server,established; '
        'http_uri; content:"/x",nocase,fast_pattern; content:"y",distance 0,within 10; '
        'pcre:"/a+b/ism"; service:http; metadata:policy balanced-ips drop; sid:1; rev:1; )',
        'alert udp any any -> any 53 ( msg:"b"; content:"|00 01|",depth 2,offset 2; '
        'bufferlen:>10; sid:2; rev:1; )',
    ]
    for regra in validas:
        assert _marcas(regra) == [], regra


def test_cada_forma_do_snort2_e_acusada():
    casos = {
        # snort_upgrade.text:458
        'alert tcp any any -> any 80 ( msg:"u"; uricontent:"/x"; sid:10; )': "opcao_inexistente:uricontent",
        # :449, subopcao separada por ;
        'alert tcp any any -> any 80 ( msg:"n"; content:"x"; nocase; sid:11; )': "opcao_inexistente:nocase",
        # :451, offset com dois-pontos
        'alert tcp any any -> any 80 ( msg:"o"; content:"x"; offset:5; sid:12; )': "opcao_inexistente:offset",
        # :443
        'alert tcp any any -> any 80 ( msg:"f"; content:"x"; fast_pattern:only; sid:13; )': "opcao_inexistente:fast_pattern",
        # :398
        'alert tcp any any -> any 80 ( msg:"t"; content:"x"; threshold:type limit,track by_src,count 1,seconds 60; sid:14; )': "opcao_inexistente:threshold",
        # :438
        'alert tcp any any -> any 80 ( msg:"m"; content:"x"; metadata:service http; sid:15; )': "metadata_service",
        # :456
        'alert tcp any any -> any 80 ( msg:"p"; pcre:"/cmd\\.exe/Ui"; sid:16; )': "pcre_flag_removida:U",
    }
    for regra, esperada in casos.items():
        assert esperada in _marcas(regra), (regra, _marcas(regra))


def test_pcre_negado_e_flags_permitidas():
    assert _marcas('alert tcp any any -> any 80 ( msg:"p"; pcre:!"/x/smi"; sid:20; )') == []
    assert _marcas('alert tcp any any -> any 80 ( msg:"p"; pcre:!"/x/B"; sid:21; )') == ["pcre_flag_removida:B"]


if __name__ == "__main__":
    test_lista_de_opcoes_confere_com_o_manual()
    test_ruleset_do_projeto_passa_limpo()
    test_sintaxe_snort3_valida_nao_e_acusada()
    test_cada_forma_do_snort2_e_acusada()
    test_pcre_negado_e_flags_permitidas()
    print("Sintaxe Snort 2: testes passaram.")

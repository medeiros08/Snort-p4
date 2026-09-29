"""Testes offline da comparacao de tests/check_profile_vs_snort.py.

A checagem de verdade roda no rig, contra `snort --dump-config-text`. Aqui
fica a logica de comparacao, com os casos que ela tem de separar: variavel so
de um lado, valor diferente, e porta em forma que o compilador nao
representa (faixa, negacao), que nunca pode passar como igual.
"""

import json
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "tests"))

from check_profile_vs_snort import comparar, portas_do_snort  # noqa: E402


def test_portas_do_snort():
    assert portas_do_snort("80 8080") == [80, 8080]
    assert portas_do_snort(" 110 143") == [110, 143]
    assert portas_do_snort("[8080, 80]") == [80, 8080]
    assert portas_do_snort("!80") is None
    assert portas_do_snort("1024:") is None


def test_iguais_nao_divergem():
    snort = {
        "HOME_NET": ("nets", "192.168.10.0/24"),
        "HTTP_PORTS": ("ports", "8080 80"),
    }
    compilador = {"HOME_NET": "192.168.10.0/24", "HTTP_PORTS": [80, 8080]}
    assert comparar(snort, compilador) == []


def test_variavel_so_no_snort_e_a_do_bug_de_origem():
    # O caso que motivou a checagem: o Snort define, o compilador nao.
    divergencias = comparar({"DNS_SERVERS": ("nets", "any")}, {})
    assert divergencias == [{"variavel": "DNS_SERVERS", "tipo": "so_no_snort", "snort": "any"}]


def test_variavel_so_no_compilador():
    divergencias = comparar({}, {"AIM_SERVERS": "any"})
    assert divergencias[0]["tipo"] == "so_no_compilador"


def test_valor_diferente():
    divergencias = comparar(
        {"HOME_NET": ("nets", "10.0.0.0/24"), "HTTP_PORTS": ("ports", "80")},
        {"HOME_NET": "192.168.10.0/24", "HTTP_PORTS": [80, 8080]},
    )
    assert {d["variavel"] for d in divergencias} == {"HOME_NET", "HTTP_PORTS"}
    assert all(d["tipo"] == "valor_diferente" for d in divergencias)


def test_porta_nao_representavel_nunca_passa():
    divergencias = comparar({"SHELLCODE_PORTS": ("ports", "!80")}, {"SHELLCODE_PORTS": [80]})
    assert divergencias[0]["tipo"] == "valor_diferente"


def test_perfil_ativo_tem_as_variaveis_que_o_snort_define():
    # Os 17 nomes que `snort --dump-config-text` listou no rig para
    # config/snort3_experiment.lua (2026-09-29). A comparacao de valores so
    # roda no rig; a presenca dos nomes vale conferir em qualquer maquina.
    do_snort = {
        "DNS_SERVERS", "EXTERNAL_NET", "FTP_SERVERS", "HOME_NET",
        "HTTP_SERVERS", "SIP_SERVERS", "SMTP_SERVERS", "SQL_SERVERS",
        "SSH_SERVERS", "TELNET_SERVERS", "FILE_DATA_PORTS", "FTP_PORTS",
        "HTTP_PORTS", "MAIL_PORTS", "ORACLE_PORTS", "SIP_PORTS", "SSH_PORTS",
    }
    compilador = json.loads((RAIZ / "config" / "snort_variables.json").read_text(encoding="utf-8"))
    assert set(compilador) == do_snort


if __name__ == "__main__":
    test_portas_do_snort()
    test_iguais_nao_divergem()
    test_variavel_so_no_snort_e_a_do_bug_de_origem()
    test_variavel_so_no_compilador()
    test_valor_diferente()
    test_porta_nao_representavel_nunca_passa()
    test_perfil_ativo_tem_as_variaveis_que_o_snort_define()
    print("Perfil x Snort: testes passaram.")

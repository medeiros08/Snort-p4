"""Testes do round-trip da codificacao P4Runtime.

Nenhum validador do repositorio comparava o que o codificador EMITE com o
que ele deveria emitir. validate_encoded_entries confere largura de hex,
mascara nao nula e canonicidade (value & ~mask == 0) — propriedades que uma
codificacao errada satisfaz sem esforco. E validate_backend.py recalcula
match_key com a mesma funcao de lower_p4_entries, o que e tautologico.

A verificacao inversa — decodificar e comparar com a origem — tem poder de
teste real porque decodificar e uma operacao independente de codificar.
"""

import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "compiler"))

from generate_p4runtime_install import (
    decode_ternary_field,
    encode_entry,
    verify_round_trip,
)


def campo(field_id, valor_hex, mascara_hex):
    return {
        "field_id": field_id,
        "ternary": {
            "value_hex": valor_hex,
            "mask_hex": mascara_hex,
        },
    }


# ------------------------------------------------------------------
# decodificacao
# ------------------------------------------------------------------


def test_decodifica_protocolo():
    nome, valor = decode_ternary_field(campo(1, "06", "ff"))
    assert nome == "protocol"
    assert valor == 6


def test_decodifica_ipv4_com_prefixo():
    nome, valor = decode_ternary_field(campo(2, "c0a80a00", "ffffff00"))
    assert nome == "src_ip"
    assert valor == {"value": "192.168.10.0", "prefix_len": 24}


def test_decodifica_porta():
    nome, valor = decode_ternary_field(campo(5, "0050", "ffff"))
    assert nome == "dst_port"
    assert valor == 80


def test_decodifica_flags_como_valor_e_mascara():
    nome, valor = decode_ternary_field(campo(6, "10", "10"))
    assert nome == "tcp_flags"
    assert valor == {"value": 16, "mask": 16}


def test_field_id_fora_do_contrato():
    nome, valor = decode_ternary_field(campo(99, "00", "ff"))
    assert nome is None and valor is None


# ------------------------------------------------------------------
# round-trip
# ------------------------------------------------------------------


def origem(match):
    return {"install_entry_id": "p4-teste", "match": match}


def codificada(campos):
    return {"install_entry_id": "p4-teste", "match": campos}


def test_round_trip_limpo_nao_reporta_nada():
    problemas = verify_round_trip(
        origem({
            "protocol": 6,
            "dst_ip": {"value": "192.168.10.0", "prefix_len": 24},
            "dst_port": 80,
        }),
        codificada([
            campo(1, "06", "ff"),
            campo(3, "c0a80a00", "ffffff00"),
            campo(5, "0050", "ffff"),
        ]),
    )
    assert problemas == []


def test_pega_prefixo_errado():
    # O off-by-one classico. Largura do hex continua certa e
    # value & ~mask == 0 continua valendo, entao as checagens anteriores
    # nao veem nada.
    problemas = verify_round_trip(
        origem({"dst_ip": {"value": "192.168.10.0", "prefix_len": 24}}),
        codificada([campo(3, "c0a80a00", "fffffe00")]),
    )
    assert len(problemas) == 1
    assert "prefix_len" in problemas[0]["message"]


def test_pega_campo_gravado_no_field_id_errado():
    # src_port escrito no slot de dst_port. Inverteria a porta de toda
    # entrada instalada.
    problemas = verify_round_trip(
        origem({"src_port": 1234}),
        codificada([campo(5, "04d2", "ffff")]),
    )
    assert problemas
    mensagens = " ".join(p["message"] for p in problemas)
    assert "src_port" in mensagens and "dst_port" in mensagens


def test_pega_campo_ausente_na_codificacao():
    problemas = verify_round_trip(
        origem({"protocol": 6, "dst_port": 80}),
        codificada([campo(1, "06", "ff")]),
    )
    assert len(problemas) == 1
    assert "dst_port" in problemas[0]["message"]
    assert "ausente" in problemas[0]["message"]


def test_pega_campo_sobrando_na_codificacao():
    problemas = verify_round_trip(
        origem({"protocol": 6}),
        codificada([campo(1, "06", "ff"), campo(5, "0050", "ffff")]),
    )
    assert len(problemas) == 1
    assert "dst_port" in problemas[0]["message"]


def test_pega_valor_trocado():
    problemas = verify_round_trip(
        origem({"dst_port": 80}),
        codificada([campo(5, "01bb", "ffff")]),
    )
    assert len(problemas) == 1
    assert "443" in problemas[0]["message"] or "80" in problemas[0]["message"]


def test_round_trip_sobre_a_codificacao_real():
    # Fecha o ciclo usando o codificador de verdade, nao hex escrito a mao.
    fonte = {
        "install_entry_id": "p4-real",
        "table": "ids_prefilter",
        "action": {"name": "send_to_ids"},
        "match": {
            "protocol": 6,
            "src_ip": {"value": "10.0.0.0", "prefix_len": 8},
            "dst_port": 443,
            "tcp_flags": {"value": 2, "mask": 255},
        },
    }

    assert verify_round_trip(fonte, encode_entry(fonte)) == []


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
        except Exception as erro:  # erro de contrato tambem reprova
            falhas.append((nome, f"{type(erro).__name__}: {erro}"))

    for nome, erro in falhas:
        print(f"FALHOU: {nome}: {erro}")

    print(
        f"roundtrip_encoding: {len(testes) - len(falhas)}/{len(testes)} "
        f"testes passaram."
    )

    if falhas:
        sys.exit(1)


if __name__ == "__main__":
    main()

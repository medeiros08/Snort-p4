"""Testes da semantica de cabecalho de regras service-based.

No Snort 3.12.2.0, quando o servico identificado no fluxo e um dos da regra,
porta e protocolo do cabecalho nao sao checados; os enderecos sao
(paper/IDS_P4/SERVICE_BASED_HEADER_FINDING.md). O modo "snort3" de
assess_rule segue isso; o modo "legacy", padrao, reproduz os artefatos
congelados e trata o cabecalho como o de uma regra por porta.

Direcao de seguranca: delegar porta e protocolo so ALARGA o predicado, entao
o modo snort3 nunca pode excluir um pacote que o legacy incluia.
"""

import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "compiler"))

from build_semantic_ir import build_semantic_ir
from parser import parse_rule
from semantic_classifier import classify_assessed_rule
from target_capability import SERVICE_SKIPPED_HEADER_FIELDS, assess_rule


COM_SERVICO = (
    'alert tcp any any -> 192.168.10.0/24 21 ( msg:"ftp"; '
    'flow:to_server,established; content:"USER"; service:ftp; sid:9201; )'
)

SEM_SERVICO = (
    'alert tcp any any -> 192.168.10.0/24 21 ( msg:"ftp"; '
    'flow:to_server,established; content:"USER"; sid:9202; )'
)

SO_PORTA_COM_SERVICO = (
    'alert tcp any any -> any 80 ( msg:"http"; '
    'flow:to_server,established; content:"GET"; service:http; sid:9203; )'
)


def avaliar(texto, semantica):
    ir = build_semantic_ir(parse_rule(texto))
    avaliada, razoes = assess_rule(ir, semantica)
    return avaliada, razoes, classify_assessed_rule(avaliada)


def tratamentos(avaliada):
    return {
        p.field: p.backend_treatment
        for p in avaliada.predicates
        if p.kind == "HEADER"
    }


def test_padrao_e_legacy():
    ir = build_semantic_ir(parse_rule(COM_SERVICO))
    padrao, _ = assess_rule(ir)
    legacy, _ = assess_rule(ir, "legacy")
    assert tratamentos(padrao) == tratamentos(legacy)


def test_legacy_preserva_porta_e_protocolo_da_regra_com_servico():
    avaliada, _, _ = avaliar(COM_SERVICO, "legacy")
    t = tratamentos(avaliada)
    assert t["protocol"] == "PRESERVED"
    assert t["dst_port"] == "PRESERVED"


def test_snort3_delega_porta_e_protocolo_e_mantem_enderecos():
    avaliada, razoes, classificacao = avaliar(COM_SERVICO, "snort3")
    t = tratamentos(avaliada)
    for campo in SERVICE_SKIPPED_HEADER_FIELDS:
        assert t[campo] == "DELEGATED", campo
    assert t["dst_ip"] == "PRESERVED"
    assert t["src_ip"] == "PRESERVED"
    motivos = {r["field"]: r["reason"] for r in razoes}
    assert motivos["dst_port"] == "service_based_header_not_checked_on_service_match"
    # O endereco de destino ainda e seletivo: a regra continua NECESSARY.
    assert classificacao.classification == "NECESSARY"


def test_snort3_nao_muda_regra_sem_servico():
    legacy, _, _ = avaliar(SEM_SERVICO, "legacy")
    snort3, _, _ = avaliar(SEM_SERVICO, "snort3")
    assert tratamentos(legacy) == tratamentos(snort3)


def test_snort3_sem_endereco_seletivo_vira_unsupported():
    # So a porta 80 restringia o cabecalho; sem ela nada seletivo sobra.
    _, _, legacy = avaliar(SO_PORTA_COM_SERVICO, "legacy")
    _, _, snort3 = avaliar(SO_PORTA_COM_SERVICO, "snort3")
    assert legacy.classification == "NECESSARY"
    assert snort3.classification == "UNSUPPORTED"


def test_snort3_so_alarga():
    # Nenhum predicado restritivo aparece no snort3 que nao estivesse no legacy.
    for texto in (COM_SERVICO, SEM_SERVICO, SO_PORTA_COM_SERVICO):
        legacy = tratamentos(avaliar(texto, "legacy")[0])
        snort3 = tratamentos(avaliar(texto, "snort3")[0])
        for campo, tratamento in snort3.items():
            if tratamento in {"PRESERVED", "EXPANDED"}:
                assert legacy[campo] == tratamento, (texto, campo)


def test_semantica_desconhecida_e_recusada():
    ir = build_semantic_ir(parse_rule(COM_SERVICO))
    try:
        assess_rule(ir, "snort2")
    except ValueError:
        return
    raise AssertionError("semantica desconhecida deveria falhar")


if __name__ == "__main__":

    test_padrao_e_legacy()
    test_legacy_preserva_porta_e_protocolo_da_regra_com_servico()
    test_snort3_delega_porta_e_protocolo_e_mantem_enderecos()
    test_snort3_nao_muda_regra_sem_servico()
    test_snort3_sem_endereco_seletivo_vira_unsupported()
    test_snort3_so_alarga()
    test_semantica_desconhecida_e_recusada()

    print(
        "Service header semantics tests passed."
    )

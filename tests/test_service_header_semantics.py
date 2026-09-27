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


COM_SERVICO_E_FLAGS = (
    'alert tcp any any -> 192.168.10.0/24 80 ( msg:"http"; '
    'flow:to_server,established; flags:S; content:"GET"; service:http; sid:9204; )'
)


def test_snort3_mantem_protocolo_quando_ha_flags():
    # flags so casa em pacote com cabecalho TCP (ips_flags.cc), entao o
    # protocolo continua necessario mesmo com o servico casando.
    avaliada, _, _ = avaliar(COM_SERVICO_E_FLAGS, "snort3")
    t = tratamentos(avaliada)
    assert t["protocol"] == "PRESERVED"
    assert t["dst_port"] == "DELEGATED"
    assert t["flags"] in {"PRESERVED", "EXPANDED"}


def test_semantica_desconhecida_e_recusada():
    ir = build_semantic_ir(parse_rule(COM_SERVICO))
    try:
        assess_rule(ir, "snort2")
    except ValueError:
        return
    raise AssertionError("semantica desconhecida deveria falhar")


def test_whatif_gravado_e_coerente():
    import json

    caminho = RAIZ / "output" / "analysis" / "service_header_semantics_whatif.json"
    relatorio = json.loads(caminho.read_text(encoding="utf-8"))

    legacy = relatorio["legacy"]
    snort3 = relatorio["snort3"]

    # O calculo reproduz a particao strong congelada antes de medir o snort3.
    assert legacy["strong_discriminator"] == {
        "elegiveis": 3611,
        "fallback_operacional": 392,
        "entradas_retidas": 322,
    }
    for modo in (legacy, snort3):
        classes = modo["classificacao"]
        assert sum(classes.values()) == 4017
        particao = modo["strong_discriminator"]
        assert particao["elegiveis"] + particao["fallback_operacional"] == classes["NECESSARY"]

    # Delegar porta e protocolo so alarga: nenhuma regra ganha elegibilidade.
    assert snort3["strong_discriminator"]["elegiveis"] <= legacy["strong_discriminator"]["elegiveis"]
    assert snort3["classificacao"]["UNSUPPORTED"] >= legacy["classificacao"]["UNSUPPORTED"]


# Sem service:, mas com opcoes DCE: validate_services (fp_utils.cc) acrescenta
# os servicos que dce_tcp, dce_udp e dce_smb registram para esses buffers.
DCE_SEM_SERVICO = (
    'alert tcp $EXTERNAL_NET any -> 192.168.10.0/24 135 ( msg:"dce"; '
    'flow:to_server,established; dce_iface:uuid 4b324fc8-1670-01d3-1278-5a47bf6ee188; '
    'dce_opnum:"15"; dce_stub_data; content:"|00 00 00 00|"; sid:9205; )'
)

# Cabecalho com protocolo de servico: USER_MODE, portas continuam checadas
# (fp_eval_rtn forca check_ports = 1).
HTTP_NO_CABECALHO = (
    'alert http 192.168.20.0/24 any -> 192.168.10.0/24 8080 ( msg:"http"; '
    'flow:to_server,established; http_uri; content:"/x"; sid:9206; )'
)

HTTP_NO_CABECALHO_COM_SERVICO = (
    'alert http 192.168.20.0/24 any -> 192.168.10.0/24 8080 ( msg:"http"; '
    'flow:to_server,established; http_uri; content:"/x"; service:http; sid:9207; )'
)


def test_snort3_delega_regra_com_servico_implicito():
    legacy, _, _ = avaliar(DCE_SEM_SERVICO, "legacy")
    snort3, _, classificacao = avaliar(DCE_SEM_SERVICO, "snort3")
    assert tratamentos(legacy)["dst_port"] == "PRESERVED"
    t = tratamentos(snort3)
    assert t["protocol"] == "DELEGATED"
    assert t["dst_port"] == "DELEGATED"
    assert t["dst_ip"] == "PRESERVED"
    assert classificacao.classification == "NECESSARY"


def test_snort3_mantem_portas_com_protocolo_de_servico_no_cabecalho():
    for texto in (HTTP_NO_CABECALHO, HTTP_NO_CABECALHO_COM_SERVICO):
        legacy = tratamentos(avaliar(texto, "legacy")[0])
        snort3 = tratamentos(avaliar(texto, "snort3")[0])
        assert snort3 == legacy, texto
        assert snort3["dst_port"] == "PRESERVED", texto


def test_opcoes_do_ruleset_classificadas():
    # Toda opcao de uma regra NECESSARY sem service: no ruleset avaliado ou
    # implica servico (e e detectada) ou e opcao do nucleo, sem buffer de
    # inspetor e sem prefixo de guess_service. Opcao nova no ruleset tem de
    # ser classificada aqui antes de o modo snort3 ser confiavel.
    import json

    from target_capability import (
        SNORT3_GUESSED_SERVICE_PREFIXES,
        SNORT3_SERVICE_BUFFERS,
    )

    nucleo = {
        "msg", "sid", "rev", "gid", "classtype", "reference", "metadata",
        "content", "pcre", "flow", "flowbits", "byte_test", "byte_jump",
        "byte_extract", "isdataat", "dsize", "itype", "icode", "icmp_id",
        "icmp_seq", "flags", "fragbits", "id", "ttl", "ack", "seq",
        "ip_proto", "stream_size", "detection_filter",
    }
    manifesto = json.loads(
        (RAIZ / "output" / "semantic_manifest.json").read_text(encoding="utf-8")
    )
    implicitas = set()
    for regra in manifesto["rules"]:
        nomes = [o["name"] for o in regra["parsed_rule"]["options"]]
        if regra["classification"] != "NECESSARY" or "service" in nomes:
            continue
        for nome in nomes:
            implica = nome in SNORT3_SERVICE_BUFFERS or nome.startswith(
                SNORT3_GUESSED_SERVICE_PREFIXES
            )
            assert implica or nome in nucleo, (regra["rule_id"], nome)
            if implica and regra["parsed_rule"]["protocol"] in {"tcp", "udp", "icmp", "ip"}:
                implicitas.add(regra["rule_id"])
    assert implicitas == {"529", "3238", "3239"}


def test_metricas_de_trace_gravadas_e_coerentes():
    # O artefato medido offline sobre as janelas tem de concordar com o
    # congelado (legacy), com o what-if estrutural (snort3) e com o limite.
    import json

    sys.path.insert(0, str(RAIZ / "tests"))
    from rederive_trace_metrics import CONGELADO, RULESET

    trace = json.loads(
        (RAIZ / "output" / "analysis" / "trace_metrics_by_semantics.json").read_text(encoding="utf-8")
    )
    whatif = json.loads(
        (RAIZ / "output" / "analysis" / "service_header_semantics_whatif.json").read_text(encoding="utf-8")
    )
    assert trace["validacao_contra_congelado"] is True
    for janela, esperado in CONGELADO.items():
        medido = trace["legacy"]["janelas"][janela]
        for chave, valor in esperado.items():
            assert abs(medido[chave] - valor) < 1e-9, (janela, chave)

    particao = trace["snort3"]["particao"]
    estrutural = whatif["snort3"]["strong_discriminator"]
    assert particao["elegiveis"] == estrutural["elegiveis"]
    assert particao["fallback"] == estrutural["fallback_operacional"]
    limite = 100.0 * (1 - (particao["fallback"] + particao["unsupported"]) / RULESET)
    for janela, medido in trace["snort3"]["janelas"].items():
        assert medido["global_candidato_pct"] == 100.0, janela
        reducao = medido["candidate_set_por_entrada"]["reducao"]["sobre_ruleset_pct"]
        assert reducao <= limite + 1e-9, janela
        # Agrupar nunca encolhe o conjunto por entrada.
        for agrupado in medido["candidate_set_agrupado"].values():
            assert agrupado["mean"] >= medido["candidate_set_por_entrada"]["mean"] - 1e-9


def test_cobertura_de_alertas_gravada_e_coerente():
    import json

    relatorio = json.loads(
        (RAIZ / "output" / "analysis" / "alert_coverage_by_semantics.json").read_text(encoding="utf-8")
    )
    congelado = json.loads(
        (
            RAIZ / "output" / "experiments" / "cicids2017_thursday_bruteforce"
            / "strong_discriminator_alert_audit.json"
        ).read_text(encoding="utf-8")
    )
    bf = relatorio["legacy"]["bruteforce"]
    assert bf["elegiveis"] == congelado["eligible_alert_events"]
    assert bf["fallback"] == congelado["fallback_alert_events"]
    assert bf["cobertos"] == congelado["p4_covered_eligible_alert_events"]
    for semantica in ("legacy", "snort3"):
        for janela, medido in relatorio[semantica].items():
            assert medido["faltando"] == 0 and medido["sid_desconhecida"] == 0, (semantica, janela)
            assert medido["cobertos"] + medido["fallback"] + medido["dominio"] == medido["alertas"]
            assert medido["global_candidato"] == medido["alertas"]


def test_tetos_de_precisao_de_cabecalho():
    import json

    sys.path.insert(0, str(RAIZ / "tests"))
    from analyze_header_precision_bounds import prefixos

    # Decomposicao em prefixos: [1024, 65535] = 6 prefixos; porta unica = 1.
    assert prefixos(1024, 65535) == 6
    assert prefixos(12345, 12346) == 1 + 1
    assert prefixos(80, 80) == 1

    tetos = json.loads(
        (RAIZ / "output" / "analysis" / "header_precision_bounds.json").read_text(encoding="utf-8")
    )
    for chave in ("h12_faixas_de_porta", "m1_itype_icode", "m2_ip_proto"):
        bloco = tetos[chave]
        assert bloco["fora_do_strong"] <= bloco["regras"] == len(bloco["sids"])
        assert abs(bloco["teto_pontos_sobre_ruleset"] - 100.0 * bloco["fora_do_strong"] / 4017) < 1e-3
    assert tetos["m2_ip_proto"]["sids"] == ["2462", "2463", "2464"]


if __name__ == "__main__":

    test_padrao_e_legacy()
    test_legacy_preserva_porta_e_protocolo_da_regra_com_servico()
    test_snort3_delega_porta_e_protocolo_e_mantem_enderecos()
    test_snort3_nao_muda_regra_sem_servico()
    test_snort3_sem_endereco_seletivo_vira_unsupported()
    test_snort3_so_alarga()
    test_snort3_mantem_protocolo_quando_ha_flags()
    test_semantica_desconhecida_e_recusada()
    test_whatif_gravado_e_coerente()
    test_snort3_delega_regra_com_servico_implicito()
    test_snort3_mantem_portas_com_protocolo_de_servico_no_cabecalho()
    test_opcoes_do_ruleset_classificadas()
    test_metricas_de_trace_gravadas_e_coerentes()
    test_cobertura_de_alertas_gravada_e_coerente()
    test_tetos_de_precisao_de_cabecalho()

    print(
        "Service header semantics tests passed."
    )

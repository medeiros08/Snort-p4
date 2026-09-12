"""Testes de compiler/semantic_classifier.py.

Este modulo decide a classe semantica de cada regra — EXACT, NECESSARY ou
UNSUPPORTED — e, com ela, se a regra vira candidata a prefiltro e quem toma
a decisao de deteccao (data plane ou Snort). E o ultimo estagio antes do
manifesto, e ate aqui nao tinha um unico teste.

Cuidado ao ler: tests/test_semantic_model.py exercita compiler/classifier.py,
que e o classificador LEGADO e nao participa do pipeline oficial. A
existencia daquele arquivo dava impressao de cobertura que nao existia.

As implicacoes fixas que os testes ancoram:

    EXACT        -> candidato, deteccao no DATA_PLANE
    NECESSARY    -> candidato, deteccao no SNORT
    UNSUPPORTED  -> nao candidato, deteccao no SNORT

E a regra de seletividade: so predicado PRESERVED ou EXPANDED pode
contribuir, e `direction` nunca conta, por ser estrutural.
"""

import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "compiler"))

from semantic_ir import (
    SemanticRuleIR,
    make_header_predicate,
    make_metadata_predicate,
    make_payload_predicate,
)
from semantic_classifier import (
    classify_assessed_rule,
    direction_is_selective,
    is_selective_predicate,
    port_is_selective,
    protocol_is_selective,
)


def cabecalho(campo, valor, tratamento="PRESERVED"):
    return make_header_predicate(
        field=campo,
        operator="exact",
        value=valor,
        backend_treatment=tratamento,
    )


def regra(predicados, rule_id="1000", tipo="TRADITIONAL"):
    return SemanticRuleIR(
        rule_id=rule_id,
        action="alert",
        rule_type=tipo,
        raw_rule="alert tcp any any -> any any ( sid:1000; )",
        predicates=list(predicados),
        metadata={},
    )


# ------------------------------------------------------------------
# seletividade por campo
# ------------------------------------------------------------------


def test_so_preserved_e_expanded_contribuem():
    for tratamento in ("PRESERVED", "EXPANDED"):
        assert is_selective_predicate(
            cabecalho("dst_port", "80", tratamento)
        ) is True, tratamento

    for tratamento in ("DELEGATED", "FALLBACK", "UNASSESSED", "OUT_OF_SCOPE"):
        assert is_selective_predicate(
            cabecalho("dst_port", "80", tratamento)
        ) is False, tratamento


def test_protocolo_concreto_e_seletivo_mas_ip_nao():
    for valor in ("tcp", "udp", "icmp", "TCP"):
        assert protocol_is_selective(cabecalho("protocol", valor)) is True, valor

    # "ip" e representado como wildcard: nao reduz o conjunto de pacotes.
    assert protocol_is_selective(cabecalho("protocol", "ip")) is False


def test_wildcard_nao_e_seletivo():
    for campo in ("src_ip", "dst_ip", "src_port", "dst_port"):
        assert is_selective_predicate(cabecalho(campo, "any")) is False, campo
        assert is_selective_predicate(cabecalho(campo, "ANY")) is False, campo
        assert is_selective_predicate(cabecalho(campo, "  any  ")) is False, campo


def test_lista_vazia_nao_e_seletiva():
    assert port_is_selective(cabecalho("dst_port", [])) is False
    assert port_is_selective(cabecalho("dst_port", ["80"])) is True


def test_direcao_nunca_e_seletiva():
    # Decisao deliberada e correta: direcao e estrutural. Uma seta para a
    # frente sozinha nao reduz o conjunto de pacotes se enderecos e portas
    # sao wildcard.
    for valor in ("->", "<>", "<-"):
        assert direction_is_selective(cabecalho("direction", valor)) is False, valor
        assert is_selective_predicate(cabecalho("direction", valor)) is False, valor


def test_campo_desconhecido_nao_e_seletivo():
    for campo in ("itype", "ttl", "ip_proto", "campo_inventado"):
        assert is_selective_predicate(cabecalho(campo, "8")) is False, campo


# ------------------------------------------------------------------
# classificacao
# ------------------------------------------------------------------


def test_exact_quando_tudo_e_representavel():
    # Regra so de cabecalho, sem nada delegado: o data plane decide sozinho.
    resultado = classify_assessed_rule(
        regra([
            cabecalho("protocol", "tcp"),
            cabecalho("src_ip", "192.168.1.1"),
            cabecalho("dst_port", "80"),
            make_metadata_predicate("sid", "1000"),
        ])
    )

    assert resultado.classification == "EXACT"
    assert resultado.exact_semantics is True
    assert resultado.prefilter_candidate is True
    assert resultado.final_detection == "DATA_PLANE"


def test_metadata_nao_impede_exact():
    # METADATA e OUT_OF_SCOPE e deliberadamente ignorado no teste de
    # exatidao; msg/sid/rev nao sao predicados de deteccao.
    resultado = classify_assessed_rule(
        regra([
            cabecalho("protocol", "tcp"),
            cabecalho("dst_port", "80"),
            make_metadata_predicate("msg", "qualquer coisa"),
            make_metadata_predicate("rev", "1"),
        ])
    )
    assert resultado.classification == "EXACT"


def test_necessary_quando_ha_predicado_delegado():
    # O caso real de 4.003 das 4.017 regras: sobra content/flow/pcre para o
    # Snort, mas o cabecalho ainda restringe.
    resultado = classify_assessed_rule(
        regra([
            cabecalho("protocol", "tcp"),
            cabecalho("dst_ip", "192.168.10.0/24"),
            make_payload_predicate("content", {"pattern": "evil"}),
        ])
    )

    assert resultado.classification == "NECESSARY"
    assert resultado.exact_semantics is False
    assert resultado.prefilter_candidate is True
    assert resultado.final_detection == "SNORT"
    assert resultado.has_selective_predicate is True


def test_fallback_tambem_tira_a_exatidao():
    resultado = classify_assessed_rule(
        regra([
            cabecalho("protocol", "tcp"),
            cabecalho("dst_port", "1024:", "FALLBACK"),
        ])
    )
    assert resultado.exact_semantics is False
    assert resultado.classification == "NECESSARY"


def test_unsupported_quando_nada_restringe():
    # Todo cabecalho wildcard e so conteudo: nao sobra predicado seletivo.
    resultado = classify_assessed_rule(
        regra([
            cabecalho("protocol", "ip"),
            cabecalho("src_ip", "any"),
            cabecalho("dst_ip", "any"),
            cabecalho("src_port", "any"),
            cabecalho("dst_port", "any"),
            make_payload_predicate("content", {"pattern": "evil"}),
        ])
    )

    assert resultado.classification == "UNSUPPORTED"
    assert resultado.prefilter_candidate is False
    assert resultado.final_detection == "SNORT"
    assert resultado.has_selective_predicate is False


def test_exact_nao_exige_seletividade():
    # LACUNA DE MODELAGEM encontrada por este teste.
    #
    # Uma regra cujo cabecalho e todo wildcard e que nao tem nenhuma opcao
    # de deteccao satisfaz exact_semantics VACUAMENTE: nao ha predicado
    # DELEGATED, FALLBACK nem UNASSESSED porque nao ha predicado de
    # deteccao nenhum. O ramo EXACT e testado antes de qualquer checagem de
    # seletividade, entao a regra sai EXACT, candidata e com a deteccao
    # atribuida ao DATA_PLANE — com zero predicados seletivos.
    #
    # Nao quebra Snort(r,p) => P4_candidato(r,p): o predicado resultante e
    # "tudo", que e a super-aproximacao maxima. Mas o backend emite para ela
    # uma entrada com match vazio, que o P4Runtime nao consegue instalar.
    # Ate o Gate 1 isso passava silenciosamente (a entrada ia para
    # encoding_failures e o estagio terminava com codigo 0); hoje o gate de
    # generate_p4runtime_install reprova o build.
    #
    # Nenhuma regra do ruleset avaliado cai aqui: as quatro regras
    # `alert ip any any -> any any` tem content, que e DELEGATED, e por isso
    # caem corretamente em UNSUPPORTED.
    resultado = classify_assessed_rule(
        regra([
            cabecalho("protocol", "ip"),
            cabecalho("direction", "->"),
            cabecalho("src_ip", "any"),
            cabecalho("dst_ip", "any"),
        ])
    )

    assert resultado.classification == "EXACT"
    assert resultado.exact_semantics is True
    assert resultado.has_selective_predicate is False
    assert resultado.selective_predicates == []
    assert resultado.final_detection == "DATA_PLANE"


def test_direcao_nao_salva_regra_que_tem_conteudo_delegado():
    # Com uma opcao de deteccao presente, exact_semantics cai e a ausencia
    # de predicado seletivo leva corretamente a UNSUPPORTED. E o caminho
    # real das quatro regras `alert ip any any -> any any` do ruleset.
    resultado = classify_assessed_rule(
        regra([
            cabecalho("protocol", "ip"),
            cabecalho("direction", "->"),
            cabecalho("src_ip", "any"),
            cabecalho("dst_ip", "any"),
            make_payload_predicate("content", {"pattern": "evil"}),
        ])
    )
    assert resultado.classification == "UNSUPPORTED"
    assert resultado.prefilter_candidate is False


def test_protocolo_isolado_hoje_basta_para_ser_candidata():
    # LIMITACAO CONHECIDA, nao comportamento desejado.
    #
    # `alert tcp any any -> any any` tem como unico predicado seletivo
    # protocol=tcp, e isso a torna NECESSARY. No ruleset avaliado quatro
    # regras nessa forma geram a entrada p4-106 = {protocol: 6}, que casa
    # todo pacote TCP e sozinha subsume 246 das 331 entradas.
    #
    # O argumento aplicado a `direction` — estrutural, nao reduz o conjunto
    # quando o resto e wildcard — vale identicamente aqui. Enquanto esta
    # decisao nao for revista, o teste fixa o comportamento atual.
    resultado = classify_assessed_rule(
        regra([
            cabecalho("protocol", "tcp"),
            cabecalho("src_ip", "any"),
            cabecalho("dst_ip", "any"),
            cabecalho("src_port", "any"),
            cabecalho("dst_port", "any"),
            make_payload_predicate("content", {"pattern": "evil"}),
        ])
    )
    assert resultado.classification == "NECESSARY"
    assert resultado.prefilter_candidate is True


def test_regra_service_nunca_e_candidata():
    # Regras SERVICE nao recebem predicado de cabecalho tradicional, e
    # is_selective_predicate so reconhece campos HEADER. Sao as 10 regras
    # SERVICE do ruleset, 10 das 14 UNSUPPORTED.
    from semantic_ir import make_application_predicate

    resultado = classify_assessed_rule(
        regra(
            [
                make_application_predicate("service_header", "http"),
                make_payload_predicate("content", {"pattern": "evil"}),
            ],
            tipo="SERVICE",
        )
    )

    assert resultado.classification == "UNSUPPORTED"
    assert resultado.prefilter_candidate is False


# ------------------------------------------------------------------
# invariantes
# ------------------------------------------------------------------


def test_invariantes_das_implicacoes_fixas():
    casos = [
        [cabecalho("protocol", "tcp"), cabecalho("dst_port", "80")],
        [cabecalho("protocol", "tcp"), make_payload_predicate("content", {"p": 1})],
        [cabecalho("protocol", "ip"), cabecalho("dst_ip", "any")],
        [cabecalho("dst_ip", "10.0.0.0/8", "EXPANDED")],
        [cabecalho("dst_port", "1024:", "FALLBACK")],
    ]

    for predicados in casos:
        r = classify_assessed_rule(regra(predicados))

        assert r.classification in {"EXACT", "NECESSARY", "UNSUPPORTED"}

        # candidato <=> nao e UNSUPPORTED
        assert r.prefilter_candidate == (r.classification != "UNSUPPORTED")

        # has_selective <=> lista de seletivos nao vazia
        assert r.has_selective_predicate == (len(r.selective_predicates) > 0)

        # NECESSARY exige pelo menos um predicado seletivo
        if r.classification == "NECESSARY":
            assert r.has_selective_predicate is True

        # so EXACT autoriza o data plane a decidir sozinho
        esperado = "DATA_PLANE" if r.classification == "EXACT" else "SNORT"
        assert r.final_detection == esperado

        # rule_id sempre string no resultado
        assert isinstance(r.rule_id, str)


def test_rule_id_e_coagido_para_string():
    r = classify_assessed_rule(
        regra([cabecalho("protocol", "tcp")], rule_id=2001)
    )
    assert r.rule_id == "2001"


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
        f"semantic_classifier: {len(testes) - len(falhas)}/{len(testes)} "
        f"testes passaram."
    )

    if falhas:
        sys.exit(1)


if __name__ == "__main__":
    main()

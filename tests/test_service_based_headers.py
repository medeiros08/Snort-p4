import ipaddress
import json
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
TESTS_DIR = PROJECT_ROOT / "tests"
ANALISES = PROJECT_ROOT / "output" / "analysis"

sys.path.insert(
    0,
    str(TESTS_DIR)
)


from analyze_service_based_headers import cobertura


HOME = [ipaddress.ip_network("192.168.10.0/24")]

DESTINO_HOME = {"dst_ip": {"value": "192.168.10.0", "prefix_len": 24}}
ORIGEM_HOME = {"src_ip": {"value": "192.168.10.0", "prefix_len": 24}}
SO_TCP = {"protocol": 6}


def test_destino_home_coberto_por_entrada_sem_porta():
    assert cobertura(None, HOME, False, [DESTINO_HOME]) == "qualquer_protocolo"


def test_origem_qualquer_nao_cabe_em_origem_home():
    assert cobertura(None, HOME, False, [ORIGEM_HOME]) == "nenhuma"


def test_so_protocolo_cobre_apenas_a_parte_tcp():
    assert cobertura(None, None, False, [SO_TCP]) == "so_tcp"


def test_bidirecional_exige_as_duas_orientacoes():
    # <> com HOME_NET num lado: a orientacao inversa poe HOME_NET na origem.
    assert cobertura(None, HOME, True, [DESTINO_HOME]) == "nenhuma"
    assert cobertura(None, HOME, True, [DESTINO_HOME, ORIGEM_HOME]) == "qualquer_protocolo"


def test_entrada_com_porta_fica_fora_do_filtro(tmp_path=None):
    import tempfile

    from analyze_service_based_headers import _entradas_sem_porta

    entradas = {
        "entries": [
            {"match": dict(DESTINO_HOME, dst_port=80)},
            {"match": dict(DESTINO_HOME, protocol=6)},
            {"match": DESTINO_HOME},
        ]
    }
    with tempfile.TemporaryDirectory() as diretorio:
        caminho = Path(diretorio) / "entradas.json"
        caminho.write_text(json.dumps(entradas), encoding="utf-8")
        filtradas = _entradas_sem_porta(caminho)

    # A entrada com porta nao pode cobrir a regiao de porta arbitraria.
    assert dict(DESTINO_HOME, dst_port=80) not in filtradas
    assert len(filtradas) == 2
    assert cobertura(None, HOME, False, filtradas) == "qualquer_protocolo"


def test_artefato_de_exposicao_coerente():
    relatorio = json.loads(
        (ANALISES / "service_based_header_exposure.json").read_text(encoding="utf-8")
    )
    expostas = relatorio["expostas"]
    total = expostas["total"]

    assert total == len(expostas["sids"])
    assert total <= relatorio["necessarias_com_service_explicito"] <= relatorio["necessarias"]
    assert sum(expostas["mantendo_so_condicoes_de_ip"].values()) == total

    por_plano = relatorio["cobertura_da_regiao_sem_porta_e_protocolo"]["por_plano"]
    for plano, contagem in por_plano.items():
        assert sum(contagem.values()) == total, plano

    # O plano strong removeu justamente as entradas sem porta.
    assert por_plano["strong_discriminator"] == {"nenhuma": total}


def test_rederivacao_da_preservacao_confere():
    relatorio = json.loads(
        (ANALISES / "alert_preservation_offline_post_correction.json").read_text(encoding="utf-8")
    )
    assert relatorio["status"] == "CONFERE"
    for nome, janela in relatorio["janelas"].items():
        offline = janela["offline_pos_correcao"]
        assert janela["confere"], nome
        assert offline["P4_NO_MATCH"] == 0, nome
        assert offline["PACKET_DOMAIN_FALLBACK"] == 0, nome
        assert offline["P4_CANDIDATE"] == offline["pacotes"], nome


if __name__ == "__main__":

    test_destino_home_coberto_por_entrada_sem_porta()
    test_origem_qualquer_nao_cabe_em_origem_home()
    test_so_protocolo_cobre_apenas_a_parte_tcp()
    test_bidirecional_exige_as_duas_orientacoes()
    test_entrada_com_porta_fica_fora_do_filtro()
    test_artefato_de_exposicao_coerente()
    test_rederivacao_da_preservacao_confere()

    print(
        "Service-based header tests passed."
    )

"""Testes do leitor em fluxo de pcap classico e pcapng (tests/pcap_stream.py).

Os pcapng sao montados aqui bloco a bloco, nas duas ordens de bytes, com
interfaces de resolucao diferente, para que o leitor seja conferido contra a
especificacao e nao contra ele mesmo.
"""

import struct
import sys
import tempfile

from datetime import datetime, timezone
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "tests"))

from cut_cicids2017_windows import intervalo_us  # noqa: E402
from pcap_stream import EscritorPcap, PcapInvalido, quadros_com_tempo  # noqa: E402
from run_campaign_bmv2 import ler_pcap  # noqa: E402

QUADRO_A = bytes(range(60))
QUADRO_B = b"\xaa" * 61  # comprimento nao multiplo de 4: exige padding


def _bloco(ordem, tipo, corpo):
    corpo = corpo + b"\x00" * (-len(corpo) % 4)
    tamanho = 12 + len(corpo)
    return struct.pack(ordem + "II", tipo, tamanho) + corpo + struct.pack(ordem + "I", tamanho)


def _shb(ordem):
    corpo = struct.pack(ordem + "IHHq", 0x1A2B3C4D, 1, 0, -1)
    return _bloco(ordem, 0x0A0D0D0A, corpo)


def _idb(ordem, tsresol=None, link=1):
    corpo = struct.pack(ordem + "HHI", link, 0, 262144)
    if tsresol is not None:
        corpo += struct.pack(ordem + "HH", 9, 1) + bytes([tsresol]) + b"\x00" * 3
        corpo += struct.pack(ordem + "HH", 0, 0)
    return _bloco(ordem, 1, corpo)


def _epb(ordem, interface, ticks, quadro):
    corpo = struct.pack(ordem + "IIIII", interface, ticks >> 32, ticks & 0xFFFFFFFF, len(quadro), len(quadro))
    return _bloco(ordem, 6, corpo + quadro)


def _pb(ordem, interface, ticks, quadro):
    corpo = struct.pack(
        ordem + "HHIIII", interface, 0, ticks >> 32, ticks & 0xFFFFFFFF, len(quadro), len(quadro)
    )
    return _bloco(ordem, 2, corpo + quadro)


def _gravar(conteudo):
    arquivo = tempfile.NamedTemporaryFile(delete=False, suffix=".pcapng")
    arquivo.write(conteudo)
    arquivo.close()
    return Path(arquivo.name)


T0 = 1499341200_000123  # 2017-07-06T11:40:00.000123Z, em microssegundos


def test_pcapng_duas_ordens_e_duas_resolucoes():
    for ordem in ("<", ">"):
        conteudo = (
            _shb(ordem)
            + _idb(ordem)  # padrao: microssegundos
            + _idb(ordem, tsresol=9)  # nanossegundos
            + _epb(ordem, 0, T0, QUADRO_A)
            + _bloco(ordem, 5, b"estatistica")  # bloco desconhecido: pulado
            + _epb(ordem, 1, T0 * 1000 + 999, QUADRO_B)
            + _pb(ordem, 0, T0 + 1, QUADRO_A)
        )
        caminho = _gravar(conteudo)
        try:
            lidos = list(quadros_com_tempo(caminho))
        finally:
            caminho.unlink()
        assert lidos == [(T0, QUADRO_A), (T0, QUADRO_B), (T0 + 1, QUADRO_A)], ordem


def test_pcapng_com_duas_secoes():
    # Uma nova secao zera as interfaces e pode trocar a ordem de bytes.
    conteudo = (
        _shb("<") + _idb("<") + _epb("<", 0, T0, QUADRO_A)
        + _shb(">") + _idb(">") + _epb(">", 0, T0 + 5, QUADRO_B)
    )
    caminho = _gravar(conteudo)
    try:
        assert list(quadros_com_tempo(caminho)) == [(T0, QUADRO_A), (T0 + 5, QUADRO_B)]
    finally:
        caminho.unlink()


def test_pcapng_recusa_link_nao_ethernet_e_interface_ausente():
    for conteudo in (
        _shb("<") + _idb("<", link=101) + _epb("<", 0, T0, QUADRO_A),
        _shb("<") + _idb("<") + _epb("<", 3, T0, QUADRO_A),
        _shb("<") + _idb("<") + _epb("<", 0, T0, QUADRO_A)[:-6],
    ):
        caminho = _gravar(conteudo)
        try:
            list(quadros_com_tempo(caminho))
        except PcapInvalido:
            continue
        finally:
            caminho.unlink()
        raise AssertionError("pcapng invalido aceito")


def test_escritor_classico_ida_e_volta():
    with tempfile.TemporaryDirectory() as diretorio:
        caminho = Path(diretorio) / "janela.pcap"
        with EscritorPcap(caminho) as escritor:
            escritor.escrever(T0, QUADRO_A)
            escritor.escrever(T0 + 2_500_000, QUADRO_B)
        assert list(quadros_com_tempo(caminho)) == [(T0, QUADRO_A), (T0 + 2_500_000, QUADRO_B)]
        # O leitor da campanha le o mesmo arquivo.
        segundos, micros = divmod(T0, 1_000_000)
        assert ler_pcap(caminho)[0] == (segundos, micros, QUADRO_A)


def test_intervalo_das_janelas_em_adt():
    inicio, fim = intervalo_us("09:20-10:00")
    esperado = datetime(2017, 7, 6, 12, 20, tzinfo=timezone.utc)
    assert inicio == int(esperado.timestamp()) * 1_000_000
    assert fim - inicio == 40 * 60 * 1_000_000


if __name__ == "__main__":
    test_pcapng_duas_ordens_e_duas_resolucoes()
    test_pcapng_com_duas_secoes()
    test_pcapng_recusa_link_nao_ethernet_e_interface_ausente()
    test_escritor_classico_ida_e_volta()
    test_intervalo_das_janelas_em_adt()
    print("pcap stream tests passed.")

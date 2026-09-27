"""Leitura em fluxo de pcap classico e pcapng, sem dependencia externa.

As capturas do CICIDS2017 sao pcapng (`output/datasets/cicids2017_thursday_metadata.json`)
e a janela Brute Force tem 1,2 GB, entao ler o arquivo inteiro na memoria,
como faz `run_campaign_bmv2.ler_pcap` com os pcaps pequenos da campanha, nao
serve. Este modulo le bloco a bloco e entrega `(timestamp_us, quadro)`.

pcapng: Section Header Block (0x0A0D0D0A) fixa a ordem de bytes pela magica
0x1A2B3C4D; Interface Description Block (1) da o link type e a resolucao do
timestamp (`if_tsresol`, opcao 9, padrao 10^-6); Enhanced Packet Block (6) e
o Packet Block obsoleto (2) trazem interface, timestamp de 64 bits e o
quadro. Simple Packet Block (3) nao tem timestamp e e recusado, porque o
corte por janela depende dele. Os demais blocos sao pulados.
"""

from __future__ import annotations

import struct

from pathlib import Path
from typing import BinaryIO, Iterator

LINKTYPE_ETHERNET = 1

_PCAP_MAGICAS = {
    0xA1B2C3D4: (">", 1),
    0xD4C3B2A1: ("<", 1),
    0xA1B23C4D: (">", 1000),  # nanossegundos
    0x4D3CB2A1: ("<", 1000),
}
_PCAPNG_SHB = 0x0A0D0D0A
_PCAPNG_ORDEM = 0x1A2B3C4D


class PcapInvalido(ValueError):
    pass


def _ler_exato(arquivo: BinaryIO, n: int) -> bytes:
    dados = arquivo.read(n)
    if len(dados) != n:
        raise PcapInvalido(f"fim inesperado: esperava {n} bytes, li {len(dados)}")
    return dados


def _classico(arquivo: BinaryIO, cabecalho: bytes) -> Iterator[tuple[int, bytes]]:
    magica = struct.unpack(">I", cabecalho[:4])[0]
    ordem, divisor = _PCAP_MAGICAS[magica]
    link = struct.unpack(ordem + "I", cabecalho[20:24])[0]
    if link != LINKTYPE_ETHERNET:
        raise PcapInvalido(f"link type {link} nao e Ethernet")
    while True:
        registro = arquivo.read(16)
        if not registro:
            return
        if len(registro) != 16:
            raise PcapInvalido("registro de pacote truncado")
        segundos, fracao, capturados, _originais = struct.unpack(ordem + "IIII", registro)
        yield segundos * 1_000_000 + fracao // divisor, _ler_exato(arquivo, capturados)


def _resolucao(opcoes: bytes, ordem: str) -> tuple[int, int]:
    """(numerador, denominador) de um tick em microssegundos, de if_tsresol."""

    posicao = 0
    while posicao + 4 <= len(opcoes):
        codigo, tamanho = struct.unpack(ordem + "HH", opcoes[posicao : posicao + 4])
        valor = opcoes[posicao + 4 : posicao + 4 + tamanho]
        if codigo == 0:
            break
        if codigo == 9 and tamanho >= 1:
            v = valor[0]
            if v & 0x80:
                return 1_000_000, 2 ** (v & 0x7F)
            return 1_000_000, 10 ** v
        posicao += 4 + tamanho + (-tamanho % 4)
    return 1, 1


def _pcapng(arquivo: BinaryIO, inicio: bytes) -> Iterator[tuple[int, bytes]]:
    interfaces: list[tuple[int, int, int]] = []
    ordem = "<"
    pendente = inicio
    while True:
        cabeca = pendente + arquivo.read(8 - len(pendente))
        pendente = b""
        if not cabeca:
            return
        if len(cabeca) != 8:
            raise PcapInvalido("cabecalho de bloco truncado")
        tipo_bruto = cabeca[:4]
        if struct.unpack(">I", tipo_bruto)[0] == _PCAPNG_SHB:
            magica = _ler_exato(arquivo, 4)
            if struct.unpack("<I", magica)[0] == _PCAPNG_ORDEM:
                ordem = "<"
            elif struct.unpack(">I", magica)[0] == _PCAPNG_ORDEM:
                ordem = ">"
            else:
                raise PcapInvalido("magica de ordem de bytes do SHB desconhecida")
            tamanho = struct.unpack(ordem + "I", cabeca[4:8])[0]
            _ler_exato(arquivo, tamanho - 12)
            interfaces = []
            continue

        tipo, tamanho = struct.unpack(ordem + "II", cabeca)
        if tamanho < 12 or tamanho % 4:
            raise PcapInvalido(f"tamanho de bloco invalido: {tamanho}")
        corpo = _ler_exato(arquivo, tamanho - 12)
        _ler_exato(arquivo, 4)

        if tipo == 1:
            link, _reservado, _snap = struct.unpack(ordem + "HHI", corpo[:8])
            numerador, denominador = _resolucao(corpo[8:], ordem)
            interfaces.append((link, numerador, denominador))
        elif tipo in (6, 2):
            if tipo == 6:
                interface, alto, baixo, capturados, _orig = struct.unpack(ordem + "IIIII", corpo[:20])
                dados = corpo[20 : 20 + capturados]
            else:
                interface, _drops, alto, baixo, capturados, _orig = struct.unpack(
                    ordem + "HHIIII", corpo[:20]
                )
                dados = corpo[20 : 20 + capturados]
            if interface >= len(interfaces):
                raise PcapInvalido(f"pacote de interface nao declarada: {interface}")
            link, numerador, denominador = interfaces[interface]
            if link != LINKTYPE_ETHERNET:
                raise PcapInvalido(f"link type {link} nao e Ethernet")
            ticks = (alto << 32) | baixo
            yield ticks * numerador // denominador, dados
        elif tipo == 3:
            raise PcapInvalido("Simple Packet Block nao tem timestamp")


class _ComResumo:
    """Arquivo cujo conteudo lido alimenta um hash: sha256 na mesma passada."""

    def __init__(self, arquivo: BinaryIO, resumo):
        self._arquivo = arquivo
        self._resumo = resumo

    def read(self, n: int) -> bytes:
        dados = self._arquivo.read(n)
        self._resumo.update(dados)
        return dados


def quadros_com_tempo(caminho: Path, resumo=None) -> Iterator[tuple[int, bytes]]:
    """(timestamp em microssegundos desde a epoca, quadro Ethernet), em fluxo.

    Com `resumo` (um objeto de hashlib), cada byte lido do arquivo entra nele;
    ao fim da iteracao o hash cobre o arquivo inteiro.
    """

    with open(caminho, "rb", buffering=1 << 20) as bruto:
        arquivo = _ComResumo(bruto, resumo) if resumo is not None else bruto
        inicio = arquivo.read(4)
        if len(inicio) != 4:
            raise PcapInvalido(f"arquivo vazio: {caminho}")
        magica = struct.unpack(">I", inicio)[0]
        if magica in _PCAP_MAGICAS:
            yield from _classico(arquivo, inicio + _ler_exato(arquivo, 20))
        elif magica == _PCAPNG_SHB:
            yield from _pcapng(arquivo, inicio)
        else:
            raise PcapInvalido(f"formato desconhecido: magica 0x{magica:08x}")


class EscritorPcap:
    """pcap classico, microssegundos, Ethernet: o que o leitor acima e o
    `run_campaign_bmv2.ler_pcap` leem. O comprimento original gravado e o
    capturado; as metricas so usam os bytes do quadro."""

    def __init__(self, caminho: Path):
        self._arquivo = open(caminho, "wb")
        self._arquivo.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, LINKTYPE_ETHERNET))

    def escrever(self, timestamp_us: int, quadro: bytes) -> None:
        segundos, micros = divmod(timestamp_us, 1_000_000)
        self._arquivo.write(struct.pack("<IIII", segundos, micros, len(quadro), len(quadro)))
        self._arquivo.write(quadro)

    def fechar(self) -> None:
        self._arquivo.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.fechar()

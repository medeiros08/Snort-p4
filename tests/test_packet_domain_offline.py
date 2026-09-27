"""Classes de fallback do dominio de pacotes, offline, sem gRPC.

A suite de guarda (test_ipv4_packet_domain_guard.py) confere onze casos no
BMv2, mas importa grpc no topo e nao roda sem o ambiente do rig. E nenhum dos
onze e das classes que dominam o fallback medido nas tres janelas: ARP
(125 / 1.660 / 4.074 quadros), IPv6 (195 / 820 / 2.523) e LLDP. Tambem nao
cobre VLAN, truncamento de UDP e de ICMP, nem IPv4 com protocolo fora de
TCP/UDP/ICMP (achado M9 da revisao de 2026-09-11).

Estes casos conferem o classificador offline (tests/p4_packet_domain.py),
que e o que produz os numeros de fallback do manuscrito, contra o que o
parser de p4/ids_prefilter.p4 faz:

    etherType != 0x0800      parse_ethernet vai para accept sem IPv4 valido
                             -> packet_domain_fallback (VLAN 0x8100 incluida:
                             o parser nao tem estado de VLAN)
    UDP com menos de 8 bytes extract de udp_t (8 bytes) falha -> parser_error
    ICMP com menos de 4      extract de icmp_t (4 bytes) falha -> parser_error
    IPv4 protocolo 47        parse_l4 vai para accept: dentro do dominio, sem
                             portas; a tabela e aplicada

A contraparte no data plane continua sendo do rig.
"""

import struct
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "tests"))

from p4_packet_domain import classify_frame_for_prefilter


MAC = b"\x02\x00\x00\x00\x00\x01" + b"\x02\x00\x00\x00\x00\x02"


def ether(ethertype, corpo):
    return MAC + struct.pack("!H", ethertype) + corpo


def ipv4(protocolo, carga, flags_frag=0x0000):
    total = 20 + len(carga)
    cabecalho = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total,
        1,
        flags_frag,
        64,
        protocolo,
        0,
        bytes([192, 168, 10, 10]),
        bytes([203, 0, 113, 10]),
    )
    return cabecalho + carga


def fallback(quadro):
    pacote, motivo = classify_frame_for_prefilter(quadro)
    assert pacote is None, motivo
    return motivo


def test_arp_e_fallback():
    arp = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1) + b"\x00" * 20
    assert fallback(ether(0x0806, arp)) == "ethertype_0x0806"


def test_ipv6_e_fallback():
    ipv6 = b"\x60" + b"\x00" * 39
    assert fallback(ether(0x86DD, ipv6)) == "ethertype_0x86dd"


def test_lldp_e_fallback():
    assert fallback(ether(0x88CC, b"\x02\x07\x04" + b"\x00" * 20)) == "ethertype_0x88cc"


def test_vlan_e_fallback_mesmo_com_ipv4_dentro():
    tcp = struct.pack("!HHIIBBHHH", 45678, 80, 0, 0, 0x50, 0x02, 1024, 0, 0)
    marcado = struct.pack("!HH", 10, 0x0800) + ipv4(6, tcp)
    assert fallback(ether(0x8100, marcado)) == "ethertype_0x8100"


def test_udp_truncado_e_fallback():
    assert fallback(ether(0x0800, ipv4(17, b"\x00" * 7))) == "truncated_udp"


def test_icmp_truncado_e_fallback():
    assert fallback(ether(0x0800, ipv4(1, b"\x08\x00\x00"))) == "truncated_icmp"


def test_udp_e_icmp_completos_estao_no_dominio():
    udp = struct.pack("!HHHH", 5353, 53, 8, 0)
    pacote, motivo = classify_frame_for_prefilter(ether(0x0800, ipv4(17, udp)))
    assert pacote is not None, motivo
    assert (pacote["src_port"], pacote["dst_port"]) == (5353, 53)

    icmp = struct.pack("!BBH", 8, 0, 0)
    pacote, motivo = classify_frame_for_prefilter(ether(0x0800, ipv4(1, icmp)))
    assert pacote is not None, motivo


def test_gre_esta_no_dominio_sem_portas():
    # parse_l4 aceita protocolo desconhecido sem extrair L4: o pacote segue
    # para a tabela, com portas zeradas, e nao e fallback.
    pacote, motivo = classify_frame_for_prefilter(ether(0x0800, ipv4(47, b"\x00" * 8)))
    assert pacote is not None, motivo
    assert pacote["protocol"] == 47
    assert (pacote["src_port"], pacote["dst_port"], pacote["tcp_flags"]) == (0, 0, 0)


def test_df_esta_no_dominio_e_mf_nao():
    tcp = struct.pack("!HHIIBBHHH", 45678, 80, 0, 0, 0x50, 0x10, 1024, 0, 0)
    df = ether(0x0800, ipv4(6, tcp, flags_frag=0x4000))
    pacote, motivo = classify_frame_for_prefilter(df)
    assert pacote is not None, motivo

    mf = ether(0x0800, ipv4(6, tcp, flags_frag=0x2000))
    assert fallback(mf) == "ipv4_fragmented_or_reserved_flags"


def test_ethernet_truncado_e_fallback():
    assert fallback(b"\x00" * 13) == "truncated_ethernet"


if __name__ == "__main__":

    test_arp_e_fallback()
    test_ipv6_e_fallback()
    test_lldp_e_fallback()
    test_vlan_e_fallback_mesmo_com_ipv4_dentro()
    test_udp_truncado_e_fallback()
    test_icmp_truncado_e_fallback()
    test_udp_e_icmp_completos_estao_no_dominio()
    test_gre_esta_no_dominio_sem_portas()
    test_df_esta_no_dominio_e_mf_nao()
    test_ethernet_truncado_e_fallback()

    print(
        "Offline packet-domain tests passed."
    )

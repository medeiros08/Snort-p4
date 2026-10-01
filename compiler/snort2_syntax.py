#!/usr/bin/env python3
"""Detecta sintaxe de regra do Snort 2 num ruleset que deveria ser Snort 3.

O compilador le sintaxe Snort 3. Um ruleset do Snort 2 passa pelo parser sem
erro, e isso e o problema: em `content:"x"; http_uri;` o Snort 2 aplica
http_uri ao content anterior, o Snort 3 ao seguinte, e a IR atribui o buffer
errado sem avisar. O proprio Snort 3 recusaria o ruleset. Medido com o
snort-rules-default 2.9.15.1 do Ubuntu (CODEX_HANDOFF.md §18).

O aviso so acusa o que o Snort 3.12.2.0 nao aceita, segundo o corpus fixado:

    opcao_inexistente   nome de opcao fora das 144 que o Snort 3 registra
                        (OPCOES_DO_SNORT3, lista `ips_option::` do manual de
                        referencia). Pega uricontent, threshold, urilen e as
                        subopcoes de content separadas por `;` (nocase;,
                        offset:5;, fast_pattern;), que deixaram de existir
                        como opcao (snort_upgrade.text:443-462)
    metadata_service    `metadata:service X`, que virou `service:X`
                        (snort_upgrade.text:438)
    pcre_flag_removida  flags de pcre B, U, P, H, M, C, I, D, K, S, Y,
                        substituidas por sticky buffers (snort_upgrade.text:456)
    acao_removida       regras activate e dynamic (snort_upgrade.text:434)

So avisa: nao altera o manifesto nem recusa o ruleset. Quem roda o executor
estatico ve o aviso e a contagem vai para proveniencia.json.

Uso:
    python compiler/snort2_syntax.py arquivo.rules
"""

from __future__ import annotations

import re
import sys

from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from parser import parse_rule  # noqa: E402


# Os 144 nomes registrados como `ips_option::<nome>` em
# docs/vendor/snort3/doc/reference/snort_reference.text (pin 3.12.2.0, a
# partir da linha 18086). Gravados aqui porque o corpus nao e versionado;
# tests/test_snort2_syntax.py confere a lista contra o manual quando o corpus
# esta presente.
OPCOES_DO_SNORT3 = frozenset(
    {
        "ack", "appids", "base64_data", "base64_decode", "ber_data", "ber_skip",
        "bufferlen", "byte_extract", "byte_jump", "byte_math", "byte_test",
        "cip_attribute", "cip_class", "cip_conn_path_class", "cip_instance",
        "cip_req", "cip_rsp", "cip_service", "cip_status", "classtype", "content",
        "cvs", "dce_iface", "dce_opnum", "dce_stub_data", "detection_filter",
        "dnp3_data", "dnp3_func", "dnp3_ind", "dnp3_obj", "dsize", "enable",
        "enip_command", "enip_req", "enip_rsp", "file_data", "file_meta",
        "file_type", "flags", "flow", "flowbits", "fragbits", "fragoffset", "gid",
        "gtp_info", "gtp_type", "gtp_version", "http2_frame_data",
        "http2_frame_header", "http_client_body", "http_cookie", "http_decoded_uri",
        "http_header", "http_header_test", "http_max_header_line",
        "http_max_trailer_line", "http_method", "http_num_cookies",
        "http_num_headers", "http_num_trailers", "http_param", "http_raw_body",
        "http_raw_cookie", "http_raw_header", "http_raw_request", "http_raw_status",
        "http_raw_trailer", "http_raw_uri", "http_stat_code", "http_stat_msg",
        "http_trailer", "http_trailer_test", "http_true_ip", "http_uri",
        "http_version", "http_version_match", "icmp_id", "icmp_seq", "icode", "id",
        "iec104_apci_type", "iec104_asdu_func", "ip_proto", "ipopts", "isdataat",
        "itype", "js_data", "md5", "metadata", "mms_data", "mms_func",
        "modbus_data", "modbus_func", "modbus_unit", "msg", "mss",
        "opcua_msg_service", "opcua_msg_type", "opcua_node_id",
        "opcua_node_namespace_index", "pcre", "pkt_data", "pkt_num", "priority",
        "raw_data", "reference", "regex", "rem", "replace", "rev", "rpc",
        "s7commplus_content", "s7commplus_func", "s7commplus_opcode", "sd_pattern",
        "seq", "service", "sha256", "sha512", "sid", "sip_body", "sip_header",
        "sip_method", "sip_stat_code", "so", "socks_address_type", "socks_command",
        "socks_remote_address", "socks_remote_port", "socks_state", "socks_version",
        "soid", "ssl_state", "ssl_version", "stream_reassemble", "stream_size",
        "tag", "target", "tos", "ttl", "urg", "vba_data", "window", "wscale",
    }
)

FLAGS_DE_PCRE_REMOVIDAS = frozenset("BUPHMCIDKSY")

ACOES_REMOVIDAS = frozenset({"activate", "dynamic"})


def _flags_de_pcre(valor: str) -> str:
    """Flags depois da ultima barra de `pcre:"/.../flags"`, com ou sem `!`."""

    texto = str(valor or "").strip().lstrip("!").strip().strip('"')
    if not texto.startswith("/") or texto.count("/") < 2:
        return ""
    return texto[texto.rfind("/") + 1 :]


def marcas_da_regra(regra: dict) -> list[str]:
    """Marcas de sintaxe Snort 2 numa regra ja lida por parser.parse_rule."""

    marcas = []
    if str(regra.get("action", "")).lower() in ACOES_REMOVIDAS:
        marcas.append(f"acao_removida:{regra['action']}")
    for opcao in regra.get("options") or []:
        nome = str(opcao.get("name") or "").strip()
        valor = opcao.get("value")
        if nome not in OPCOES_DO_SNORT3:
            marcas.append(f"opcao_inexistente:{nome}")
        elif nome == "metadata" and re.search(r"(^|,)\s*service\s", str(valor or "")):
            marcas.append("metadata_service")
        elif nome == "pcre":
            removidas = sorted(set(_flags_de_pcre(valor)) & FLAGS_DE_PCRE_REMOVIDAS)
            if removidas:
                marcas.append("pcre_flag_removida:" + "".join(removidas))
    return marcas


def analisar_ruleset(caminho: Path, exemplos: int = 10) -> dict:
    """Conta as regras com marcas de Snort 2 e devolve um resumo."""

    contagem: Counter = Counter()
    com_marca = 0
    lidas = 0
    amostra = []
    for linha in Path(caminho).read_text(encoding="utf-8", errors="replace").splitlines():
        texto = linha.strip()
        if not texto or texto.startswith("#"):
            continue
        try:
            regra = parse_rule(texto)
        except ValueError:
            continue
        lidas += 1
        marcas = marcas_da_regra(regra)
        if not marcas:
            continue
        com_marca += 1
        contagem.update(marcas)
        if len(amostra) < exemplos:
            amostra.append({"sid": regra.get("sid"), "marcas": marcas})
    return {
        "regras_lidas": lidas,
        "regras_com_sintaxe_snort2": com_marca,
        "marcas": dict(contagem.most_common()),
        "exemplos": amostra,
    }


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__.split("Uso:")[1].strip())
        return 2
    resumo = analisar_ruleset(Path(sys.argv[1]))
    print(f"regras lidas            {resumo['regras_lidas']}")
    print(f"com sintaxe do Snort 2  {resumo['regras_com_sintaxe_snort2']}")
    for marca, n in resumo["marcas"].items():
        print(f"  {n:6d}  {marca}")
    return 1 if resumo["regras_com_sintaxe_snort2"] else 0


if __name__ == "__main__":
    sys.exit(main())

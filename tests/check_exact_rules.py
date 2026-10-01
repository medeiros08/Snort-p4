#!/usr/bin/env python3
"""Confere no Snort as regras que o compilador classifica como EXACT.

EXACT afirma que o predicado P4 da regra e equivalente a ela dentro do
dominio de pacotes D: o pacote casa o predicado se e so se o Snort alerta a
regra. O ruleset avaliado no artigo nao tem nenhuma regra EXACT; o
snort-rules-default do Ubuntu, convertido pelo snort2lua, tem 10, todas so
de cabecalho (paper/IDS_P4/EXTERNAL_RULESETS_ROBUSTNESS.md §6). Esta e a
primeira verificacao das duas direcoes:

    Snort alerta  =>  P4 candidate pela entrada da propria regra   (necessaria)
    P4 candidate  =>  Snort alerta                                 (suficiente)

Para cada regra, quadros positivos (casam o cabecalho; nos dois sentidos
quando a regra e `<>`) e negativos que mudam um campo so (porta, endereco,
protocolo ou sentido). Todos dentro de D: IPv4 sem opcoes, sem fragmento.

Lado P4: o casador de referencia (tests/campaign_matcher.py), sobre as
entradas que o compilador gera para as 10 regras, filtradas por
proveniencia — cada regra so com as proprias entradas. Esse casador bateu com
o contador do BMv2 em todos os quadros das rodadas da campanha. Lado Snort: o
Snort 3.12.2.0 do rig sobre o pcap, com a configuracao dos experimentos e so
estas 10 regras.

Precisa do rig (Snort). Saida: 0 se todo par (quadro, regra) concorda, 1 se
algum discorda, 2 sem Snort. Relatorio em output/analysis/exact_rules_check.json.

Uso (no rig):
    python3 tests/check_exact_rules.py
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile

from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "tests"))

# campaign_matcher primeiro: registra o marcador de scapy de que o casador
# de referencia precisa.
from campaign_matcher import carregar_entradas, predizer  # noqa: E402
from campaign_witness import _ether, _icmp, _ipv4, _tcp, _udp, escrever_pcap  # noqa: E402
from run_campaign_bmv2 import SNORT_CONFIG, aborta_por_ambiente, ambiente_do_snort, lar_do_usuario  # noqa: E402

SAIDA = PROJECT_ROOT / "output" / "analysis" / "exact_rules_check.json"

# As 10 regras EXACT do snort-rules-default 2.9.15.1 convertido, como o
# snort2lua as escreveu, sem reference/classtype (metadado, nao afeta o
# cabecalho nem a classificacao).
REGRAS = {
    "151": 'alert udp $EXTERNAL_NET 60000 -> $HOME_NET 2140 ( msg:"DeepThroat client"; sid:151; rev:5; )',
    "164": 'alert udp $EXTERNAL_NET 2140 -> $HOME_NET 60000 ( msg:"DeepThroat server"; sid:164; rev:5; )',
    "525": 'alert udp $EXTERNAL_NET any <> $HOME_NET 0 ( msg:"udp port 0"; sid:525; rev:9; )',
    "528": 'alert ip any any <> 127.0.0.0/8 any ( msg:"loopback"; sid:528; rev:5; )',
    "1415": 'alert udp any any -> 255.255.255.255 161 ( msg:"SNMP broadcast request"; sid:1415; rev:9; )',
    "1416": 'alert udp any any -> 255.255.255.255 162 ( msg:"SNMP broadcast trap"; sid:1416; rev:9; )',
    "1417": 'alert udp $EXTERNAL_NET any -> $HOME_NET 161 ( msg:"SNMP request"; sid:1417; rev:9; )',
    "1419": 'alert udp $EXTERNAL_NET any -> $HOME_NET 162 ( msg:"SNMP trap"; sid:1419; rev:9; )',
    "1429": 'alert ip 66.151.158.177 any -> $HOME_NET any ( msg:"gotomypc"; sid:1429; rev:3; )',
    "1791": 'alert ip any any -> 216.80.99.202 any ( msg:"fragroute"; sid:1791; rev:2; )',
}

H = "192.168.10.10"  # dentro de HOME_NET do perfil cicids2017
E = "203.0.113.10"  # fora; EXTERNAL_NET e any no perfil
FORA_DE_HOME = "10.0.0.1"


def udp(src, sport, dst, dport):
    return _ether(_ipv4(src, dst, 17, _udp(src, dst, sport, dport, b"campanha-exact"), 1))


def tcp(src, sport, dst, dport):
    return _ether(_ipv4(src, dst, 6, _tcp(src, dst, sport, dport, 1000, 0, 0x02, b""), 1))


def icmp(src, dst):
    return _ether(_ipv4(src, dst, 1, _icmp(b"campanha-exact"), 1))


# (rotulo, quadro, sids cujo cabecalho o quadro casa)
QUADROS = [
    ("151 positivo", udp(E, 60000, H, 2140), {"151"}),
    ("151 sport errado", udp(E, 60001, H, 2140), set()),
    ("151 dport errado", udp(E, 60000, H, 2141), set()),
    ("151 sentido inverso", udp(H, 2140, E, 60000), set()),
    ("151 em tcp", tcp(E, 60000, H, 2140), set()),
    ("151 dst fora de HOME", udp(E, 60000, FORA_DE_HOME, 2140), set()),
    ("164 positivo", udp(E, 2140, H, 60000), {"164"}),
    ("164 dport errado", udp(E, 2140, H, 60001), set()),
    ("525 positivo ida", udp(E, 5000, H, 0), {"525"}),
    ("525 positivo volta (<>)", udp(H, 0, E, 5000), {"525"}),
    ("525 dport 1", udp(E, 5000, H, 1), set()),
    ("525 em tcp", tcp(E, 5000, H, 0), set()),
    ("528 positivo ida (udp)", udp(E, 4000, "127.0.0.1", 4001), {"528"}),
    ("528 positivo volta (<>, tcp)", tcp("127.0.0.1", 4002, E, 4003), {"528"}),
    ("528 positivo icmp", icmp(E, "127.0.0.5"), {"528"}),
    ("528 fora de 127/8", udp(E, 4000, "128.0.0.1", 4001), set()),
    ("1415 positivo", udp(E, 5555, "255.255.255.255", 161), {"1415"}),
    ("1415 porta 160", udp(E, 5555, "255.255.255.255", 160), set()),
    ("1415 dst .254", udp(E, 5555, "255.255.255.254", 161), set()),
    ("1415 em tcp", tcp(E, 5555, "255.255.255.255", 161), set()),
    ("1416 positivo", udp(E, 5556, "255.255.255.255", 162), {"1416"}),
    ("1417 positivo", udp(E, 5557, H, 161), {"1417"}),
    ("1417 dst fora de HOME", udp(E, 5557, FORA_DE_HOME, 161), set()),
    ("1417 em tcp", tcp(E, 5557, H, 161), set()),
    ("1419 positivo", udp(E, 5558, H, 162), {"1419"}),
    ("1419 porta 163", udp(E, 5558, H, 163), set()),
    ("1429 positivo udp", udp("66.151.158.177", 7000, H, 7001), {"1429"}),
    ("1429 positivo tcp", tcp("66.151.158.177", 7002, H, 7003), {"1429"}),
    ("1429 positivo icmp", icmp("66.151.158.177", H), {"1429"}),
    ("1429 src .178", udp("66.151.158.178", 7000, H, 7001), set()),
    ("1429 dst fora de HOME", udp("66.151.158.177", 7000, FORA_DE_HOME, 7001), set()),
    ("1791 positivo udp", udp(E, 8000, "216.80.99.202", 8001), {"1791"}),
    ("1791 positivo icmp", icmp(E, "216.80.99.202"), {"1791"}),
    ("1791 dst .203", udp(E, 8000, "216.80.99.203", 8001), set()),
]


def compilar(regras: Path, saida: Path) -> dict[str, list]:
    """Entradas P4 finais por regra, do executor estatico."""

    env = dict(os.environ)
    for nome in ("SNORT_P4_RULESET", "SNORT_P4_OUTPUT_DIR", "SNORT_P4_VARIABLES"):
        env.pop(nome, None)
    resultado = subprocess.run(
        [sys.executable, str(PROJECT_ROOT / "compiler" / "run_static_pipeline.py"),
         "--ruleset", str(regras), "--saida", str(saida)],
        cwd=PROJECT_ROOT, env=env, capture_output=True, text=True,
    )
    if resultado.returncode != 0:
        print(resultado.stdout[-3000:])
        raise SystemExit("compilacao das 10 regras falhou")
    manifesto = json.loads((saida / "semantic_manifest.json").read_text(encoding="utf-8"))
    classes = {str(r["rule_id"]): r["classification"] for r in manifesto["rules"]}
    dados = json.loads((saida / "p4_install_entries.json").read_text(encoding="utf-8"))
    entradas = dados["entries"] if isinstance(dados, dict) else dados
    por_regra: dict[str, list] = {sid: [] for sid in REGRAS}
    for entrada in entradas:
        for sid in entrada["provenance"]["source_rule_ids"]:
            por_regra[str(sid)].append(entrada)
    return {"classes": classes, "entradas": por_regra, "bruto": dados}


def casadores(compilado: dict, base: Path) -> dict:
    """Um casador por regra, so com as entradas dela."""

    saida = {}
    for sid, entradas in compilado["entradas"].items():
        arquivo = base / f"entradas_{sid}.json"
        documento = dict(compilado["bruto"], entries=entradas) if isinstance(compilado["bruto"], dict) else entradas
        arquivo.write_text(json.dumps(documento), encoding="utf-8")
        saida[sid] = carregar_entradas(arquivo)
    return saida


def snort(pcap: Path, regras: Path, destino: Path) -> dict[int, set[str]]:
    raiz = lar_do_usuario() / "snort3-install"
    if not (raiz / "bin" / "snort").exists():
        aborta_por_ambiente(f"Snort nao encontrado em {raiz}", "rode no rig")
    saida = destino / "alertas.jsonl"
    with open(saida, "w") as arquivo:
        resultado = subprocess.run(
            [str(raiz / "bin" / "snort"), "-q", "-c", str(SNORT_CONFIG), "-R", str(regras),
             "-r", str(pcap), "-A", "alert_json", "--lua",
             "alert_json = { fields = 'pkt_num sid' }; event_queue = { max_queue = 64, log = 64 }"],
            stdout=arquivo, stderr=subprocess.PIPE, env=ambiente_do_snort(raiz), text=True,
        )
    if resultado.returncode != 0:
        print(resultado.stderr[-2000:])
        raise SystemExit("Snort falhou")
    por_quadro: dict[int, set[str]] = {}
    for linha in saida.read_text(errors="ignore").splitlines():
        if linha.strip():
            alerta = json.loads(linha)
            por_quadro.setdefault(int(alerta["pkt_num"]), set()).add(str(alerta["sid"]))
    return por_quadro


def main() -> int:
    with tempfile.TemporaryDirectory() as temporario:
        base = Path(temporario)
        regras = base / "exact10.rules"
        regras.write_text("\n".join(REGRAS.values()) + "\n", encoding="utf-8")

        compilado = compilar(regras, base / "compilado")
        nao_exact = {sid: c for sid, c in compilado["classes"].items() if c != "EXACT"}

        pcap = base / "exact.pcap"
        escrever_pcap(pcap, [quadro for _rotulo, quadro, _esperado in QUADROS])
        alertas = snort(pcap, regras, base)
        casa = casadores(compilado, base)

        pares, discordancias, desenho = 0, [], []
        for numero, (rotulo, quadro, esperado) in enumerate(QUADROS, start=1):
            do_snort = alertas.get(numero, set())
            if do_snort != esperado:
                desenho.append({"quadro": rotulo, "esperado": sorted(esperado), "snort": sorted(do_snort)})
            for sid in REGRAS:
                pares += 1
                p4 = predizer(casa[sid], quadro)[0] == "P4_CANDIDATE"
                alertou = sid in do_snort
                if p4 != alertou:
                    discordancias.append({"quadro": rotulo, "sid": sid, "snort_alertou": alertou, "p4_candidate": p4})

    status = "OK" if not discordancias and not nao_exact else "DIVERGENTE"
    relatorio = {
        "gerado_em": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "gerador": "tests/check_exact_rules.py",
        "regras": len(REGRAS),
        "classificacao_nao_exact": nao_exact,
        "entradas_por_regra": {sid: len(e) for sid, e in compilado["entradas"].items()},
        "quadros": len(QUADROS),
        "pares_quadro_regra": pares,
        "discordancias_snort_x_p4": discordancias,
        "quadros_em_que_o_snort_fugiu_do_esperado": desenho,
        "status": status,
    }
    SAIDA.parent.mkdir(parents=True, exist_ok=True)
    SAIDA.write_text(json.dumps(relatorio, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    print(f"regras {len(REGRAS)}, quadros {len(QUADROS)}, pares {pares}")
    print(f"nao EXACT na compilacao: {nao_exact or 'nenhuma'}")
    print(f"Snort fora do esperado pelo desenho: {len(desenho)}")
    for d in desenho:
        print(f"   {d}")
    print(f"discordancias Snort x P4: {len(discordancias)}")
    for d in discordancias:
        print(f"   {d}")
    print(f"{status}  relatorio {SAIDA.relative_to(PROJECT_ROOT).as_posix()}")
    return 0 if status == "OK" else 1


if __name__ == "__main__":
    sys.exit(main())

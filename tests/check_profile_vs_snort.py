#!/usr/bin/env python3
"""Confere as variaveis do compilador contra as que o Snort efetivamente usa.

O compilador resolve as variaveis das regras por config/snort_variables.json;
o Snort, pelo ips.variables que resulta de config/snort3_experiment.lua, que
inclui o snort.lua padrao e so entao aplica o perfil. Os dois sao gerados do
mesmo perfil por compiler/select_profile.py, mas nada garantia que
coincidissem, e ja houve diferenca:

    variavel so no Snort     o compilador recusa uma regra que o Snort
                             aceita (predicado UNASSESSED e manifesto
                             recusado). Era o caso de DNS_SERVERS,
                             FTP_SERVERS, SSH_SERVERS e MAIL_PORTS
    valor diferente          o predicado P4 descreve outro conjunto que o do
                             Snort, e r => p_r deixa de ser verificavel
    variavel so no compilador   regra que usa a variavel e aceita pelo
                             compilador e recusada pelo Snort

A fonte do lado do Snort e o proprio Snort: `snort --dump-config-text`
(docs/vendor/snort3/doc/user/dump_config.txt), que valida a configuracao e
imprime os valores efetivos. Reproduzir a avaliacao do Lua aqui erraria no
caso que motivou isto: o snort_defaults.lua atribui HOME_NET a DNS_SERVERS
quando HOME_NET ainda vale 'any'.

Precisa do rig (Snort instalado). Saida:
    0  perfil e Snort coincidem
    1  ha divergencia (listada)
    2  ambiente: sem Snort nesta maquina

Uso:
    python tests/check_profile_vs_snort.py
    python tests/check_profile_vs_snort.py --relatorio output/analysis/perfil_vs_snort.json
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys

from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "tests"))

from run_campaign_bmv2 import (  # noqa: E402
    SNORT_CONFIG,
    aborta_por_ambiente,
    ambiente_do_snort,
    lar_do_usuario,
)

VARIAVEIS_DO_COMPILADOR = PROJECT_ROOT / "config" / "snort_variables.json"

LINHA_DE_VARIAVEL = re.compile(r'^ips\.variables\.(nets|ports)\.([A-Za-z0-9_]+)="(.*)"$')


def variaveis_do_snort(raiz: Path) -> dict[str, tuple[str, str]]:
    """{nome: (tipo, valor)} de ips.variables.nets e .ports, como o Snort os ve."""

    binario = raiz / "bin" / "snort"
    if not binario.exists():
        aborta_por_ambiente(
            f"Snort nao encontrado em {binario}",
            "rode no rig, onde esta a instalacao do Snort 3",
        )

    resultado = subprocess.run(
        [str(binario), "-c", str(SNORT_CONFIG), "--dump-config-text"],
        capture_output=True,
        text=True,
        env=ambiente_do_snort(raiz),
    )
    if resultado.returncode != 0:
        print(resultado.stderr[-2000:], file=sys.stderr)
        aborta_por_ambiente(
            f"snort --dump-config-text terminou com codigo {resultado.returncode}",
            "verifique config/snort3_experiment.lua",
        )

    variaveis = {}
    for linha in resultado.stdout.splitlines():
        achado = LINHA_DE_VARIAVEL.match(linha.strip())
        if achado:
            tipo, nome, valor = achado.groups()
            variaveis[nome] = (tipo, valor)
    return variaveis


def portas_do_snort(valor: str) -> list[int] | None:
    """Lista de portas se o valor for so portas avulsas; None para faixa ou negacao."""

    tokens = [t for t in re.split(r"[\s,\[\]]+", valor) if t]
    if tokens and all(t.isdigit() for t in tokens):
        return sorted(int(t) for t in tokens)
    return None


def comparar(snort: dict, compilador: dict) -> list[dict]:
    divergencias = []

    for nome in sorted(set(snort) | set(compilador)):
        if nome not in compilador:
            divergencias.append(
                {"variavel": nome, "tipo": "so_no_snort", "snort": snort[nome][1]}
            )
            continue
        if nome not in snort:
            divergencias.append(
                {"variavel": nome, "tipo": "so_no_compilador", "compilador": compilador[nome]}
            )
            continue

        tipo, valor = snort[nome]
        do_compilador = compilador[nome]

        if tipo == "ports":
            portas = portas_do_snort(valor)
            iguais = (
                portas is not None
                and isinstance(do_compilador, list)
                and portas == sorted(do_compilador)
            )
        else:
            iguais = " ".join(valor.split()) == " ".join(str(do_compilador).split())

        if not iguais:
            divergencias.append(
                {
                    "variavel": nome,
                    "tipo": "valor_diferente",
                    "snort": valor,
                    "compilador": do_compilador,
                }
            )

    return divergencias


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--raiz-snort", default=None, help="instalacao do Snort 3")
    parser.add_argument("--relatorio", default=None, help="grava o resultado em JSON")
    argumentos = parser.parse_args()

    raiz = Path(argumentos.raiz_snort) if argumentos.raiz_snort else lar_do_usuario() / "snort3-install"

    snort = variaveis_do_snort(raiz)
    compilador = json.loads(VARIAVEIS_DO_COMPILADOR.read_text(encoding="utf-8"))
    divergencias = comparar(snort, compilador)

    print(f"Snort       {len(snort)} variaveis (ips.variables.nets e .ports)")
    print(f"compilador  {len(compilador)} variaveis ({VARIAVEIS_DO_COMPILADOR.relative_to(PROJECT_ROOT).as_posix()})")
    print()
    for d in divergencias:
        print(f"  DIVERGE  {d['variavel']:16s} {d['tipo']:18s} snort={d.get('snort')!r} compilador={d.get('compilador')!r}")

    if argumentos.relatorio:
        destino = (PROJECT_ROOT / argumentos.relatorio).resolve()
        destino.parent.mkdir(parents=True, exist_ok=True)
        destino.write_text(
            json.dumps(
                {
                    "gerado_em": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    "configuracao_snort": SNORT_CONFIG.relative_to(PROJECT_ROOT).as_posix(),
                    "variaveis_do_compilador": VARIAVEIS_DO_COMPILADOR.relative_to(PROJECT_ROOT).as_posix(),
                    "snort": {nome: valor for nome, (_tipo, valor) in sorted(snort.items())},
                    "compilador": compilador,
                    "divergencias": divergencias,
                    "status": "OK" if not divergencias else "DIVERGENTE",
                },
                indent=2,
                ensure_ascii=False,
            )
            + "\n",
            encoding="utf-8",
        )
        print(f"\nrelatorio   {destino}")

    if divergencias:
        print(f"\nPERFIL DIVERGENTE: {len(divergencias)} variavel(is)")
        return 1
    print("PERFIL OK: o compilador e o Snort usam as mesmas variaveis, com os mesmos valores.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

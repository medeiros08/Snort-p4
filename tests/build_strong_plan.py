#!/usr/bin/env python3
"""Materializa a politica strong_discriminator como plano instalavel.

A politica existe hoje so como simulacao offline
(`tests/simulate_operational_policy.py`): ela decide quais regras ficam no
prefilter e quais viram OPERATIONAL_FALLBACK, e o manuscrito reporta as taxas
"strong" a partir dessa simulacao. Nunca houve tabela com essas entradas
instalada num alvo.

Este script produz o plano que a simulacao descreve, sem recalcular a
politica: le as entradas removidas e a particao de regras direto do artefato
da simulacao, e filtra os planos da raiz por `install_entry_id`. Recalcular
aqui abriria a porta para divergir do que o manuscrito cita.

Por que este plano importa para a campanha. No plano completo, a entrada p4-106
casa `protocol == 6` e nada mais, entao toda testemunha TCP vira candidate
por causa dela, e nao necessariamente pela entrada da propria regra. Sem
p4-106, cada regra mantida precisa ser coberta pela sua propria entrada: se o
compilador tiver rebaixado mal algum header, a falha deixa de estar mascarada
e aparece como violacao. E esse o experimento que da poder de refutacao aos
casos TCP.

Saida em output/campaign/plano_strong_discriminator/:

    p4_install_entries.json        formato de output/p4_install_entries.json,
                                   so as entradas retidas; e o que o casador
                                   offline le
    p4runtime_install_plan.json    formato do plano da raiz, so as retidas; e o
                                   que compiler/install_p4runtime.py --plan
                                   instala
    particao.json                  sids mantidos no prefilter e sids em
                                   fallback operacional, com a procedencia

Semantica de cabecalho. Desde 2026-10-05 o pipeline da raiz usa a semantica
snort3, e o plano strong dela vai para plano_strong_discriminator_snort3/. O
plano legacy, em plano_strong_discriminator/, e o das campanhas e2e_1000_v2
a v4; --semantica legacy o reproduz a partir de
output/historical/legacy_header_semantics/. Os ids de entrada (p4-N) sao
posicionais: o p4-106 de uma semantica nao e o da outra, e por isso
simulacao, entradas e plano vem sempre da mesma semantica.

Uso:
    python tests/build_strong_plan.py
    python tests/build_strong_plan.py --semantica legacy
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys

from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

LEGADO = PROJECT_ROOT / "output" / "historical" / "legacy_header_semantics"

FONTES = {
    "snort3": {
        "simulacao": PROJECT_ROOT / "output" / "analysis" / "operational_policy_simulation_snort3.json",
        "entradas": PROJECT_ROOT / "output" / "p4_install_entries.json",
        "plano": PROJECT_ROOT / "output" / "p4runtime_install_plan.json",
        "destino": PROJECT_ROOT / "output" / "campaign" / "plano_strong_discriminator_snort3",
    },
    "legacy": {
        "simulacao": PROJECT_ROOT / "output" / "analysis" / "operational_policy_simulation.json",
        "entradas": LEGADO / "p4_install_entries.json",
        "plano": LEGADO / "p4runtime_install_plan.json",
        "destino": PROJECT_ROOT / "output" / "campaign" / "plano_strong_discriminator",
    },
}

POLITICA = "strong_discriminator"


def _sha256(caminho: Path) -> str:
    return hashlib.sha256(caminho.read_bytes()).hexdigest()


def _escreve(caminho: Path, dados: dict) -> None:
    caminho.write_text(
        json.dumps(dados, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def main() -> int:
    global SIMULACAO, ENTRADAS, PLANO, DESTINO

    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--semantica", choices=tuple(FONTES), default="snort3")
    argumentos = parser.parse_args()
    fontes = FONTES[argumentos.semantica]
    SIMULACAO, ENTRADAS, PLANO, DESTINO = (
        fontes["simulacao"], fontes["entradas"], fontes["plano"], fontes["destino"]
    )

    for exigido in (SIMULACAO, ENTRADAS, PLANO):
        if not exigido.exists():
            print(f"artefato ausente: {exigido}", file=sys.stderr)
            return 1

    simulacao = json.loads(SIMULACAO.read_text(encoding="utf-8"))
    politica = simulacao["policies"][POLITICA]
    removidas = set(politica["install_entries"]["removed_entry_ids"])
    retidas_esperadas = politica["install_entries"]["retained"]
    particao = politica["rule_partition"]

    entradas = json.loads(ENTRADAS.read_text(encoding="utf-8"))
    plano = json.loads(PLANO.read_text(encoding="utf-8"))

    entradas_retidas = [
        e for e in entradas["entries"] if e["install_entry_id"] not in removidas
    ]
    plano_retido = [
        e for e in plano["entries"] if e["install_entry_id"] not in removidas
    ]

    # Conferencias. Qualquer divergencia aqui significa que a simulacao e os
    # planos da raiz sao de geracoes diferentes, e o plano produzido nao seria
    # o que o manuscrito descreve.
    erros = []
    if len(entradas_retidas) != retidas_esperadas:
        erros.append(
            f"entradas retidas {len(entradas_retidas)} != {retidas_esperadas} da simulacao"
        )
    if len(plano_retido) != retidas_esperadas:
        erros.append(
            f"plano retido {len(plano_retido)} != {retidas_esperadas} da simulacao"
        )
    ids_existentes = {e["install_entry_id"] for e in entradas["entries"]}
    fantasmas = removidas - ids_existentes
    if fantasmas:
        erros.append(f"entradas removidas que nao existem no plano: {sorted(fantasmas)}")

    # Nenhuma entrada retida pode vir so de regra em fallback operacional: a
    # politica decide por regra, e uma regra rejeitada perde TODAS as suas
    # entradas.
    fallback = set(particao["operational_fallback_sids"])
    mantidas = set(particao["p4_eligible_sids"])
    orfas = [
        e["install_entry_id"]
        for e in entradas_retidas
        if not (set(e["provenance"]["source_rule_ids"]) & mantidas)
    ]
    if orfas:
        erros.append(
            f"{len(orfas)} entrada(s) retida(s) sem nenhuma regra mantida: {orfas[:5]}"
        )

    if erros:
        for erro in erros:
            print(f"FALHA: {erro}", file=sys.stderr)
        return 1

    DESTINO.mkdir(parents=True, exist_ok=True)

    procedencia = {
        "gerado_em": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "gerador": "tests/build_strong_plan.py",
        "politica": POLITICA,
        "semantica_de_cabecalho": argumentos.semantica,
        "definicao": politica.get("definition"),
        "fontes": {
            str(SIMULACAO.relative_to(PROJECT_ROOT)).replace("\\", "/"): _sha256(SIMULACAO),
            str(ENTRADAS.relative_to(PROJECT_ROOT)).replace("\\", "/"): _sha256(ENTRADAS),
            str(PLANO.relative_to(PROJECT_ROOT)).replace("\\", "/"): _sha256(PLANO),
        },
        "entradas_originais": len(entradas["entries"]),
        "entradas_retidas": len(entradas_retidas),
        "entradas_removidas": sorted(removidas),
    }

    entradas_saida = dict(entradas)
    entradas_saida["entries"] = entradas_retidas
    entradas_saida["final_install_entries"] = len(entradas_retidas)
    entradas_saida["politica_operacional"] = procedencia
    _escreve(DESTINO / "p4_install_entries.json", entradas_saida)

    plano_saida = dict(plano)
    plano_saida["entries"] = plano_retido
    plano_saida["encoded_entries"] = len(plano_retido)
    plano_saida["politica_operacional"] = procedencia
    _escreve(DESTINO / "p4runtime_install_plan.json", plano_saida)

    _escreve(
        DESTINO / "particao.json",
        {
            **procedencia,
            "sids_no_prefilter": sorted(mantidas, key=lambda s: int(s) if s.isdigit() else 0),
            "sids_fallback_operacional": sorted(
                fallback, key=lambda s: int(s) if s.isdigit() else 0
            ),
            "nota": (
                "Regra em fallback operacional nao e prefiltrada: o Snort a "
                "inspeciona sem filtro. P4_NO_MATCH na testemunha dela nao "
                "viola nada, porque o prefilter nao responde por ela."
            ),
        },
    )

    print(f"politica             {POLITICA}")
    print(f"entradas             {len(entradas['entries'])} -> {len(entradas_retidas)}")
    print(f"removidas            {', '.join(sorted(removidas))}")
    print(f"regras no prefilter  {len(mantidas)}")
    print(f"fallback operacional {len(fallback)}")
    print(f"\nplano em {DESTINO.relative_to(PROJECT_ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

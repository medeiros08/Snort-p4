#!/usr/bin/env python3
"""Auditoria de flowbits das duas particoes do ruleset, nas duas semanticas.

    semantica  candidatas (NECESSARY) e UNSUPPORTED: a particao dos runs de
               split semantico do Snort
    strong     P4-elegiveis e fallback (operacional ou UNSUPPORTED) da
               politica strong-discriminator

Se uma regra de um lado ligasse um flowbit que uma regra do outro lado le,
dividir o ruleset por essa particao poderia mudar a deteccao. Este estagio
conta as arestas produtor -> consumidor de flowbits por lado da particao.

    legacy   manifesto arquivado e operational_policy_simulation.json; deve
             reproduzir os congelados: output/rule_dependency_audit.json
             (particao semantica) e output/experiments/
             cicids2017_thursday_bruteforce/dependency_audit_strong_discriminator.json
             (strong), ambos 636 / 0 / 0 / 0
    snort3   manifesto da raiz e operational_policy_simulation_snort3.json

Reusa o leitor de flowbits de compiler/analyze_rule_dependencies.py.

Grava output/analysis/flowbit_partition_audit.json. Sai com 1 se o legacy
nao reproduzir os congelados.

Uso:
    python tests/audit_flowbit_partition.py
"""

from __future__ import annotations

import json
import sys

from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "compiler"))

from analyze_rule_dependencies import normalized_sid, parse_flowbit_option  # noqa: E402

ANALISE = PROJECT_ROOT / "output" / "analysis"
LEGADO = PROJECT_ROOT / "output" / "historical" / "legacy_header_semantics"
CONGELADO_STRONG = (
    PROJECT_ROOT / "output" / "experiments" / "cicids2017_thursday_bruteforce"
    / "dependency_audit_strong_discriminator.json"
)
CONGELADO_SEMANTICA = PROJECT_ROOT / "output" / "rule_dependency_audit.json"
SAIDA = ANALISE / "flowbit_partition_audit.json"

FONTES = {
    "legacy": (LEGADO / "semantic_manifest.json", ANALISE / "operational_policy_simulation.json"),
    "snort3": (PROJECT_ROOT / "output" / "semantic_manifest.json", ANALISE / "operational_policy_simulation_snort3.json"),
}


def arestas_por_lado(regras: list[dict], lado: dict[str, str], nomes: tuple[str, str]) -> dict:
    produtores = defaultdict(set)
    consumidores = defaultdict(set)
    for regra in regras:
        sid = normalized_sid(regra["rule_id"])
        for opcao in (regra.get("parsed_rule") or {}).get("options", []):
            if str(opcao.get("name", "")).strip().lower() != "flowbits":
                continue
            _, variaveis, papel = parse_flowbit_option(opcao.get("value"))
            for variavel in variaveis:
                if papel == "producer":
                    produtores[variavel].add(sid)
                elif papel == "consumer":
                    consumidores[variavel].add(sid)

    arestas = Counter({f"{a}_to_{b}": 0 for a in nomes for b in nomes})
    cruzadas = []
    for variavel in sorted(set(produtores) | set(consumidores)):
        for produtor in sorted(produtores[variavel], key=int):
            for consumidor in sorted(consumidores[variavel], key=int):
                arestas[f"{lado[produtor]}_to_{lado[consumidor]}"] += 1
                if lado[produtor] != lado[consumidor]:
                    cruzadas.append(
                        {
                            "variavel": variavel,
                            "produtor": produtor,
                            "lado_produtor": lado[produtor],
                            "consumidor": consumidor,
                            "lado_consumidor": lado[consumidor],
                        }
                    )

    return {
        "partition": dict(Counter(lado.values())),
        "flowbit_edges": {**dict(arestas), "cross_partition": len(cruzadas)},
        "cross_partition_edges": cruzadas,
        "status": "SAFE_FOR_INDEPENDENT_RULESET_SPLIT" if not cruzadas else "CROSS_PARTITION_DEPENDENCY",
    }


def auditar(manifesto: Path, simulacao: Path) -> dict:
    regras = json.loads(manifesto.read_text(encoding="utf-8"))["rules"]
    particao = json.loads(simulacao.read_text(encoding="utf-8"))["policies"]["strong_discriminator"]["rule_partition"]
    elegiveis = {normalized_sid(s) for s in particao["p4_eligible_sids"]}

    semantica = {
        normalized_sid(r["rule_id"]): ("candidate" if r["prefilter_candidate"] else "unsupported") for r in regras
    }
    strong = {
        normalized_sid(r["rule_id"]): ("eligible" if normalized_sid(r["rule_id"]) in elegiveis else "fallback")
        for r in regras
    }
    return {
        "semantica": arestas_por_lado(regras, semantica, ("candidate", "unsupported")),
        "strong": arestas_por_lado(regras, strong, ("eligible", "fallback")),
    }


def main() -> int:
    resultado = {
        "analise": "flowbit_partition_audit",
        "gerado_em": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "gerador": "tests/audit_flowbit_partition.py",
        "semanticas": {nome: auditar(*fontes) for nome, fontes in FONTES.items()},
    }

    legacy = resultado["semanticas"]["legacy"]
    congelado = json.loads(CONGELADO_STRONG.read_text(encoding="utf-8"))["flowbit_edges"]
    reproduz = all(legacy["strong"]["flowbit_edges"][k] == v for k, v in congelado.items())
    congelado = json.loads(CONGELADO_SEMANTICA.read_text(encoding="utf-8"))
    reproduz = reproduz and all(
        legacy["semantica"]["flowbit_edges"][f"{a}_to_{b}"] == congelado[f"{a}_to_{b}_edges"]
        for a in ("candidate", "unsupported")
        for b in ("candidate", "unsupported")
    )
    resultado["legacy_reproduz_congelados"] = reproduz

    SAIDA.write_text(json.dumps(resultado, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    for nome, dados in resultado["semanticas"].items():
        for particao, bloco in dados.items():
            print(f"  {nome:7s} {particao:9s} {bloco['partition']}  {bloco['flowbit_edges']}  {bloco['status']}")
    print(f"  legacy reproduz os congelados: {reproduz}")
    print(f"\n  {SAIDA.relative_to(PROJECT_ROOT)}")
    return 0 if reproduz else 1


if __name__ == "__main__":
    sys.exit(main())

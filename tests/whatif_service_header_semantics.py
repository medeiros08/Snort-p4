#!/usr/bin/env python3
"""O que muda se o compilador seguir a semantica service-based do Snort 3.

Roda o pipeline do compilador com `--service-header-semantics snort3` numa
worktree temporaria do commit atual, sem tocar em `output/` do repositorio, e
compara com os artefatos congelados (modo legacy):

    classificacao semantica            EXACT / NECESSARY / UNSUPPORTED
    backend                            instancias, matches unicos, entradas
                                       finais, entradas so de endereco
    particao strong-discriminator      mesma politica e mesmo codigo de
                                       tests/simulate_operational_policy.py

A politica e aplicada primeiro aos artefatos legacy, e o resultado tem de
reproduzir a particao congelada (3.611 elegiveis, 392 em fallback
operacional, 322 entradas retidas). So entao o numero do modo snort3 e
gravado: um calculo que nao reproduz o congelado nao mede nada.

Nada aqui usa trafego. Taxas de candidato e candidate sets sobre os traces
continuam dependendo do rig.

Codigos de saida:
    0   comparacao gravada
    1   estagio do pipeline falhou, ou a politica nao reproduz o congelado

Uso:
    python tests/whatif_service_header_semantics.py
"""

from __future__ import annotations

import ipaddress
import json
import subprocess
import sys
import tempfile

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "tests"))

# campaign_matcher primeiro: registra o marcador de scapy que o simulador de
# politica exige no import, na maquina sem scapy.
import campaign_matcher  # noqa: E402,F401
from simulate_operational_policy import (  # noqa: E402
    simulate_rule_partition,
    summarize_semantic_rules,
)

SAIDA = PROJECT_ROOT / "output" / "analysis" / "service_header_semantics_whatif.json"
HOME_NET = ipaddress.ip_network("192.168.10.0/24")

ESTAGIOS = [
    ["generate_semantic_manifest.py", "--service-header-semantics", "snort3"],
    ["validate_semantic_manifest.py"],
    ["generate_snort_experiment_rules.py"],
    ["generate_p4_entries.py"],
    ["expand_p4_entries.py"],
    ["normalize_p4_entries.py"],
    ["validate_backend.py"],
    ["lower_p4_entries.py"],
    ["generate_p4runtime_install.py"],
]

CONGELADO_STRONG = {"elegiveis": 3611, "fallback_operacional": 392, "entradas_retidas": 322}


def _git(*argumentos: str) -> str:
    return subprocess.run(
        ["git", "-C", str(PROJECT_ROOT), *argumentos],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _ler(caminho: Path) -> dict:
    return json.loads(caminho.read_text(encoding="utf-8"))


def resumo(saida: Path) -> dict:
    manifesto = _ler(saida / "semantic_manifest.json")
    instalacao = _ler(saida / "p4_install_entries.json")
    entradas = instalacao["entries"]

    campos = Counter(",".join(sorted(e["match"])) for e in entradas)
    so_endereco = sum(
        1 for e in entradas if set(e["match"]) <= {"src_ip", "dst_ip"}
    )

    particao = simulate_rule_partition(
        entradas,
        summarize_semantic_rules(manifesto),
        "strong_discriminator",
        HOME_NET,
    )

    return {
        "classificacao": manifesto["summary"]["classification"],
        "backend": {
            "instancias_de_predicado": instalacao["source_entries"],
            "matches_unicos_antes_das_flags": instalacao["unique_matches_before_flag_lowering"],
            "entradas_finais": instalacao["final_install_entries"],
            "entradas_so_de_endereco": so_endereco,
            "campos_por_entrada": dict(campos.most_common()),
        },
        "strong_discriminator": {
            "elegiveis": len(particao["eligible_sids"]),
            "fallback_operacional": len(particao["fallback_sids"]),
            "entradas_retidas": len(particao["retained_entries"]),
        },
    }


def main() -> int:
    legacy = resumo(PROJECT_ROOT / "output")
    if legacy["strong_discriminator"] != CONGELADO_STRONG:
        print(
            "a politica nao reproduz a particao congelada: "
            f"{legacy['strong_discriminator']} != {CONGELADO_STRONG}",
            file=sys.stderr,
        )
        return 1

    commit = _git("rev-parse", "HEAD")
    with tempfile.TemporaryDirectory() as temporario:
        worktree = Path(temporario) / "snort3"
        _git("worktree", "add", "--detach", str(worktree), commit)
        try:
            for estagio in ESTAGIOS:
                resultado = subprocess.run(
                    [sys.executable, str(worktree / "compiler" / estagio[0]), *estagio[1:]],
                    cwd=worktree,
                    capture_output=True,
                    text=True,
                )
                if resultado.returncode != 0:
                    print(f"estagio falhou: {' '.join(estagio)}", file=sys.stderr)
                    print(resultado.stdout[-2000:], file=sys.stderr)
                    return 1
            snort3 = resumo(worktree / "output")
        finally:
            _git("worktree", "remove", "--force", str(worktree))

    relatorio = {
        "analise": "service_header_semantics_whatif",
        "achado": "paper/IDS_P4/SERVICE_BASED_HEADER_FINDING.md",
        "commit": commit,
        "gerado_em": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "gerador": "tests/whatif_service_header_semantics.py",
        "legacy": legacy,
        "nota": (
            "Sem trafego. O legacy reproduz a particao strong congelada; o snort3 e "
            "o pipeline com --service-header-semantics snort3."
        ),
        "snort3": snort3,
    }
    SAIDA.write_text(
        json.dumps(relatorio, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )

    for nome, dados in (("legacy", legacy), ("snort3", snort3)):
        print(f"== {nome}")
        print(f"  classificacao           {dados['classificacao']}")
        backend = dados["backend"]
        print(
            f"  backend                 {backend['instancias_de_predicado']} instancias, "
            f"{backend['matches_unicos_antes_das_flags']} unicos, "
            f"{backend['entradas_finais']} finais, "
            f"{backend['entradas_so_de_endereco']} so de endereco"
        )
        print(f"  strong-discriminator    {dados['strong_discriminator']}")
    print(f"gravado em {SAIDA.relative_to(PROJECT_ROOT).as_posix()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

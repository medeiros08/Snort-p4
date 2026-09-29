#!/usr/bin/env python3
"""Roda o pipeline estatico do compilador sobre um ruleset qualquer.

Estatico quer dizer: da regra ao plano P4Runtime, sem Snort, sem p4c e sem
BMv2. Sao as mesmas etapas de `build_profile.py` (PYTHON_STEPS, depois
generate_p4runtime_install.py), na mesma ordem, e por isso roda na maquina
Windows onde o repositorio vive. O que fica de fora e so o que exige o rig:
validar o ruleset no Snort, compilar o programa P4 e instalar no switch.

Duas garantias:

    saida isolada   tudo e gravado em --saida, nunca em output/. Os
                    artefatos da raiz de output/ sao os congelados que
                    sustentam o artigo; a mesma trava existe em paths.py

    proveniencia    --saida/proveniencia.json registra o ruleset (sha256 e
                    numero de regras), o perfil de variaveis, o commit, o
                    resultado de cada etapa e o sha256 de cada artefato

O programa P4 compilado (ids_prefilter.json e .p4info.txt) nao depende do
ruleset: e copiado de output/, onde o `build_profile` o deixou, porque
generate_p4runtime_install.py le os ids de tabela e de campo do p4info.

As regras usam as variaveis do perfil ativo (config/snort_variables.json).
Variavel que o perfil nao define fica sem resolver: o campo sai UNASSESSED,
e validate_semantic_manifest.py recusa o manifesto inteiro, porque nenhum
predicado pode chegar ao backend sem decisao de capacidade. Isso vale tambem
para variaveis que o snort_defaults.lua do Snort define e o perfil nao, como
$SHELLCODE_PORTS e $AIM_SERVERS, usadas por rulesets antigos: o ruleset
precisa de um perfil que as defina.

Uso:
    python compiler/run_static_pipeline.py \\
        --ruleset rules/outro.rules --saida output/rulesets/outro
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys

from datetime import datetime, timezone
from pathlib import Path

COMPILER_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(COMPILER_DIR))

import paths  # noqa: E402
from build_profile import PYTHON_STEPS  # noqa: E402

ETAPAS = [nome for nome, _descricao in PYTHON_STEPS] + [
    "generate_p4runtime_install.py"
]

PROGRAMA_P4 = ("ids_prefilter.json", "ids_prefilter.p4info.txt")


def sha256(caminho: Path) -> str:
    return hashlib.sha256(caminho.read_bytes()).hexdigest()


def rotulo(caminho: Path) -> str:
    """Caminho relativo ao projeto, ou so o nome se estiver fora dele."""

    try:
        return caminho.relative_to(paths.PROJECT_ROOT).as_posix()
    except ValueError:
        return caminho.name


def contar_regras(caminho: Path) -> int:
    return sum(
        1
        for linha in caminho.read_text(encoding="utf-8", errors="ignore").splitlines()
        if linha.strip() and not linha.lstrip().startswith("#")
    )


def commit_atual() -> dict:
    def git(*argumentos):
        resultado = subprocess.run(
            ["git", *argumentos],
            cwd=paths.PROJECT_ROOT,
            capture_output=True,
            text=True,
        )
        return resultado.stdout.strip() if resultado.returncode == 0 else None

    return {
        "commit": git("rev-parse", "HEAD"),
        "arvore_modificada": bool(git("status", "--porcelain", "--", "compiler")),
    }


def perfil_ativo() -> str | None:
    arquivo = paths.CONFIG_DIR / "active_profile.json"
    try:
        dados = json.loads(arquivo.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return dados.get("profile") or dados.get("name")


def contagem(arquivo: Path) -> int | None:
    try:
        dados = json.loads(arquivo.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if isinstance(dados, list):
        return len(dados)
    for chave in ("entries", "install_entries", "updates"):
        if isinstance(dados.get(chave), list):
            return len(dados[chave])
    return None


def resumo(saida: Path) -> dict:
    manifesto = saida / "semantic_manifest.json"
    try:
        classificacao = json.loads(manifesto.read_text(encoding="utf-8"))["summary"][
            "classification"
        ]
    except (OSError, ValueError, KeyError):
        classificacao = None
    return {
        "classificacao": classificacao,
        "entradas_p4_finais": contagem(saida / "p4_install_entries.json"),
        "plano_p4runtime": contagem(saida / "p4runtime_install_plan.json"),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--ruleset", required=True, help="arquivo .rules em sintaxe Snort 3")
    parser.add_argument("--saida", required=True, help="diretorio dos artefatos gerados")
    argumentos = parser.parse_args()

    ruleset = Path(argumentos.ruleset).expanduser().resolve()
    saida = Path(argumentos.saida).expanduser().resolve()

    if not ruleset.is_file():
        print(f"ERRO: ruleset nao encontrado: {ruleset}")
        return 1
    if saida == paths.SAIDA_PADRAO:
        print(
            f"ERRO: --saida nao pode ser {paths.SAIDA_PADRAO}: ali estao os "
            "artefatos congelados. Para o ruleset padrao em output/, use "
            "build_profile.py no rig."
        )
        return 1

    faltando = [nome for nome in PROGRAMA_P4 if not (paths.SAIDA_PADRAO / nome).is_file()]
    if faltando:
        print(
            "ERRO: programa P4 compilado ausente em output/: "
            + ", ".join(faltando)
            + ". Gere-o no rig com build_profile.py."
        )
        return 1

    saida.mkdir(parents=True, exist_ok=True)
    logs = saida / "logs"
    logs.mkdir(exist_ok=True)
    for nome in PROGRAMA_P4:
        shutil.copy2(paths.SAIDA_PADRAO / nome, saida / nome)

    proveniencia = {
        "gerado_em": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "gerador": "compiler/run_static_pipeline.py",
        "ruleset": {
            "arquivo": rotulo(ruleset),
            "sha256": sha256(ruleset),
            "regras": contar_regras(ruleset),
            "padrao": ruleset == paths.RULESET_PADRAO,
        },
        "perfil_de_variaveis": perfil_ativo(),
        **commit_atual(),
        "programa_p4": {
            nome: {"copiado_de": f"output/{nome}", "sha256": sha256(saida / nome)}
            for nome in PROGRAMA_P4
        },
        "etapas": [],
    }

    ambiente = dict(
        os.environ,
        **{paths.VAR_RULESET: str(ruleset), paths.VAR_SAIDA: str(saida)},
    )

    print(f"ruleset  {rotulo(ruleset)}  ({proveniencia['ruleset']['regras']} regras)")
    print(f"saida    {saida}")
    print()

    status = 0
    for numero, etapa in enumerate(ETAPAS, start=1):
        log = logs / f"{numero:02d}_{Path(etapa).stem}.log"
        with open(log, "w", encoding="utf-8") as destino:
            resultado = subprocess.run(
                [sys.executable, str(COMPILER_DIR / etapa)],
                cwd=COMPILER_DIR,
                env=ambiente,
                stdout=destino,
                stderr=subprocess.STDOUT,
                text=True,
            )
        proveniencia["etapas"].append(
            {"etapa": etapa, "codigo_de_saida": resultado.returncode, "log": rotulo(log)}
        )
        print(f"  {numero:02d} {etapa:40s} {'ok' if resultado.returncode == 0 else 'FALHOU'}")
        if resultado.returncode != 0:
            print()
            print(log.read_text(encoding="utf-8", errors="ignore")[-2000:])
            status = 1
            break

    proveniencia["artefatos"] = {
        arquivo.name: sha256(arquivo)
        for arquivo in sorted(saida.iterdir())
        if arquivo.is_file() and arquivo.name != "proveniencia.json"
    }
    proveniencia["resumo"] = resumo(saida)
    proveniencia["status"] = "ok" if status == 0 else "falhou"

    (saida / "proveniencia.json").write_text(
        json.dumps(proveniencia, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )

    print()
    print(f"resumo   {json.dumps(proveniencia['resumo'], ensure_ascii=False)}")
    print(f"proveniencia  {saida / 'proveniencia.json'}")
    return status


if __name__ == "__main__":
    sys.exit(main())

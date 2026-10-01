#!/usr/bin/env python3
"""Compila rulesets de fora do projeto e resume o que o compilador faz com eles.

Teste de robustez, nao de deteccao: so o pipeline estatico
(compiler/run_static_pipeline.py --limpar), sem Snort e sem BMv2. As entradas
vem de scripts/rig_rulesets_externos.sh, que as recria no rig e grava o
sha256 de cada uma em MANIFESTO.txt; aqui o sha256 e conferido de novo.

Para cada ruleset:

    1. compila com --limpar
    2. se a validacao recusa o manifesto por predicado UNASSESSED, registra as
       regras e as variaveis indefinidas que o causam, remove essas regras e
       compila de novo. A recusa e o comportamento certo — o Snort 3 tambem
       recusa variavel indefinida (FATAL: PortVar Lookup failed) — e a
       segunda rodada mede o resto do ruleset
    3. compara a versao Snort 2 crua com a convertida pelo snort2lua, regra a
       regra: classificacao e conjunto de entradas P4 das regras comuns

Os artefatos completos de cada rodada (manifestos de dezenas de MB) ficam num
diretorio temporario; versionado so vai o resumo,
output/analysis/rulesets_externos.json.

Uso:
    python tests/analyze_external_rulesets.py [--entradas C:/Users/amede/datasets/rulesets]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tempfile

from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
EXECUTOR = PROJECT_ROOT / "compiler" / "run_static_pipeline.py"
SAIDA = PROJECT_ROOT / "output" / "analysis" / "rulesets_externos.json"

RULESETS = (
    "snort3_sensitive_data",
    "snort3_file_magic",
    "snort2_ubuntu_convertido",
    "snort2_ubuntu",
)


def sha256(caminho: Path) -> str:
    return hashlib.sha256(caminho.read_bytes()).hexdigest()


def manifesto_do_rig(entradas: Path) -> dict:
    registro = {}
    arquivo = entradas / "MANIFESTO.txt"
    if arquivo.exists():
        for linha in arquivo.read_text(encoding="utf-8").splitlines():
            chave, _, valor = linha.partition("=")
            registro[chave.strip()] = valor.strip()
    return registro


def compilar(ruleset: Path, saida: Path) -> dict:
    resultado = subprocess.run(
        [sys.executable, str(EXECUTOR), "--ruleset", str(ruleset), "--saida", str(saida), "--limpar"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )
    arquivo = saida / "proveniencia.json"
    if not arquivo.exists():
        # O executor recusou antes de compilar: hoje so a limpeza faz isso,
        # quando gid:sid repetido difere em acao ou protocolo (o Snort 3
        # tambem recusa).
        return {
            "codigo_de_saida": resultado.returncode,
            "status": "recusado_na_limpeza",
            "motivo": resultado.stdout.strip().splitlines()[-1] if resultado.stdout.strip() else None,
            "etapa_que_falhou": None,
            "resumo": None,
        }
    proveniencia = json.loads(arquivo.read_text(encoding="utf-8"))
    falhou = next((e for e in proveniencia["etapas"] if e["codigo_de_saida"] != 0), None)
    return {
        "codigo_de_saida": resultado.returncode,
        "status": proveniencia["status"],
        "etapa_que_falhou": falhou["etapa"] if falhou else None,
        "limpeza": {
            chave: (len(valor) if isinstance(valor, list) else valor)
            for chave, valor in (proveniencia.get("limpeza") or {}).items()
            if chave not in ("arquivo_limpo", "sha256")
        },
        "sintaxe_snort2": {
            "regras": proveniencia["sintaxe_snort2"]["regras_com_sintaxe_snort2"],
            "marcas": proveniencia["sintaxe_snort2"]["marcas"],
        },
        "resumo": proveniencia["resumo"],
    }


def manifesto(saida: Path) -> list[dict]:
    arquivo = saida / "semantic_manifest.json"
    if not arquivo.exists():
        return []
    return json.loads(arquivo.read_text(encoding="utf-8")).get("rules", [])


def falhas_de_parse(saida: Path) -> int | None:
    arquivo = saida / "semantic_manifest.json"
    if not arquivo.exists():
        return None
    return json.loads(arquivo.read_text(encoding="utf-8"))["summary"].get("failures")


VARIAVEIS_DO_PERFIL = PROJECT_ROOT / "config" / "snort_variables.json"


def indefinidas(arquivo: Path) -> tuple[set[str], dict[str, int]]:
    """Regras ativas que usam variavel que o perfil nao define, pelo texto.

    O texto entre aspas sai antes da busca, porque content e pcre podem conter
    `$` literal (o ruleset do projeto tem `$_POST` e `$IFS` em content).
    """

    definidas = set(json.loads(VARIAVEIS_DO_PERFIL.read_text(encoding="utf-8")))
    sids, variaveis = set(), {}
    for linha in arquivo.read_text(encoding="utf-8", errors="replace").splitlines():
        texto = linha.strip()
        achado = re.search(r"\bsid\s*:\s*(\d+)\s*;", texto)
        if not texto or texto.startswith("#") or not achado:
            continue
        fora_das_aspas = re.sub(r'"(?:[^"\\]|\\.)*"', '""', texto)
        usadas = set(re.findall(r"\$([A-Za-z_][A-Za-z0-9_]*)", fora_das_aspas)) - definidas
        if usadas:
            sids.add(achado.group(1))
            for nome in usadas:
                variaveis["$" + nome] = variaveis.get("$" + nome, 0) + 1
    return sids, variaveis


def sem_as_regras(origem: Path, sids: set[str], destino: Path) -> int:
    removidas = 0
    linhas = []
    for linha in origem.read_text(encoding="utf-8", errors="replace").splitlines():
        achado = re.search(r"\bsid\s*:\s*(\d+)\s*;", linha)
        if achado and achado.group(1) in sids and not linha.lstrip().startswith("#"):
            removidas += 1
            continue
        linhas.append(linha)
    destino.write_text("\n".join(linhas) + "\n", encoding="utf-8")
    return removidas


def entradas_por_regra(saida: Path) -> dict[str, set[str]]:
    dados = json.loads((saida / "p4_install_entries.json").read_text(encoding="utf-8"))
    entradas = dados["entries"] if isinstance(dados, dict) else dados
    por_regra: dict[str, set[str]] = {}
    for entrada in entradas:
        chave = json.dumps(entrada["match"], sort_keys=True)
        for sid in entrada["provenance"]["source_rule_ids"]:
            por_regra.setdefault(str(sid), set()).add(chave)
    return por_regra


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--entradas", default="C:/Users/amede/datasets/rulesets")
    argumentos = parser.parse_args()

    entradas = Path(argumentos.entradas)
    do_rig = manifesto_do_rig(entradas)
    relatorio = {
        "gerado_em": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "gerador": "tests/analyze_external_rulesets.py",
        "entradas_geradas_por": "scripts/rig_rulesets_externos.sh",
        "pacote_snort2": do_rig.get("pacote"),
        "snort3": do_rig.get("snort3"),
        "rulesets": {},
    }

    with tempfile.TemporaryDirectory() as temporario:
        base = Path(temporario)
        saidas_finais: dict[str, Path] = {}

        for nome in RULESETS:
            arquivo = entradas / f"{nome}.rules"
            if not arquivo.exists():
                print(f"  {nome}: ausente em {entradas}; rode scripts/rig_rulesets_externos.sh no rig")
                continue
            registro = {
                "sha256": sha256(arquivo),
                "sha256_confere_com_o_rig": sha256(arquivo) == do_rig.get(f"sha256.{nome}"),
            }

            saida = base / nome
            registro["rodada"] = compilar(arquivo, saida)
            registro["rodada"]["falhas_de_parse"] = falhas_de_parse(saida)
            saidas_finais[nome] = saida

            sids, variaveis = indefinidas(arquivo)
            if registro["rodada"]["status"] != "ok" and sids:
                reduzido = base / f"{nome}.sem_indefinidas.rules"
                removidas = sem_as_regras(arquivo, sids, reduzido)
                saida_reduzida = base / f"{nome}_sem_indefinidas"
                registro["variaveis_indefinidas"] = dict(sorted(variaveis.items()))
                registro["regras_com_variavel_indefinida"] = len(sids)
                registro["linhas_removidas"] = removidas
                registro["rodada_sem_indefinidas"] = compilar(reduzido, saida_reduzida)
                saidas_finais[nome] = saida_reduzida

            relatorio["rulesets"][nome] = registro
            final = registro.get("rodada_sem_indefinidas", registro["rodada"])
            print(
                f"  {nome:26s} {registro['rodada']['status']:7s} "
                f"-> {final['status']:7s} {json.dumps(final['resumo'], ensure_ascii=False)}"
            )

        cru, convertido = saidas_finais.get("snort2_ubuntu"), saidas_finais.get("snort2_ubuntu_convertido")
        if cru and convertido and (cru / "p4_install_entries.json").exists() and (convertido / "p4_install_entries.json").exists():
            classe_cru = {str(r["rule_id"]): r["classification"] for r in manifesto(cru)}
            classe_conv = {str(r["rule_id"]): r["classification"] for r in manifesto(convertido)}
            comuns = sorted(set(classe_cru) & set(classe_conv))
            entradas_cru, entradas_conv = entradas_por_regra(cru), entradas_por_regra(convertido)
            relatorio["cru_x_convertido"] = {
                "regras_comuns": len(comuns),
                "so_no_cru": len(set(classe_cru) - set(classe_conv)),
                "so_no_convertido": len(set(classe_conv) - set(classe_cru)),
                "classificacao_diferente": sum(classe_cru[s] != classe_conv[s] for s in comuns),
                "entradas_p4_diferentes": sum(
                    entradas_cru.get(s, set()) != entradas_conv.get(s, set()) for s in comuns
                ),
            }
            print(f"  cru x convertido: {json.dumps(relatorio['cru_x_convertido'])}")

    SAIDA.parent.mkdir(parents=True, exist_ok=True)
    SAIDA.write_text(json.dumps(relatorio, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"\nrelatorio  {SAIDA.relative_to(PROJECT_ROOT).as_posix()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

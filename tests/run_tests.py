"""Executa a suite de testes e devolve um veredito unico.

Ate aqui o projeto nao tinha como responder "a suite passa?". Os testes sao
scripts autonomos, nao havia runner, nao havia pytest.ini, e os tres que
exigem BMv2 importam grpc no topo do arquivo — logo uma coleta ingenua do
pytest aborta nesses arquivos em qualquer maquina sem o ambiente pesado.

Este runner executa cada teste em subprocesso e separa tres desfechos:

    PASSA     exit 0
    FALHA     exit != 0 por motivo proprio
    AMBIENTE  exit != 0 por dependencia ausente (grpc, scapy, p4, protobuf)
              ou por artefato/pcap que nao acompanha o repositorio

So FALHA reprova a suite. AMBIENTE e reportado e contado, nunca escondido:
um teste que nao roda nao e um teste que passa.

Uso:
    python tests/run_tests.py            # todos
    python tests/run_tests.py -v         # mostra a saida de cada falha
"""

import argparse
import subprocess
import sys
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = TESTS_DIR.parent
COMPILER_DIR = PROJECT_ROOT / "compiler"

# Modulos cuja ausencia caracteriza limitacao de ambiente, nao defeito.
MODULOS_DE_AMBIENTE = (
    "grpc",
    "scapy",
    "p4",
    "google.protobuf",
    "google",
    "pytest",
)

TIMEOUT_SEGUNDOS = 300


def arquivos_de_teste():
    arquivos = sorted(TESTS_DIR.glob("test_*.py"))
    arquivos += sorted(COMPILER_DIR.glob("test_*.py"))
    return arquivos


def e_falta_de_ambiente(saida):
    if "ModuleNotFoundError" not in saida and "ImportError" not in saida:
        return None
    for modulo in MODULOS_DE_AMBIENTE:
        alvo = modulo.split(".")[0]
        if f"No module named '{alvo}'" in saida:
            return alvo
    return None


def executa(caminho, verboso):
    ambiente_path = [str(COMPILER_DIR), str(TESTS_DIR)]

    import os

    env = dict(os.environ)
    anterior = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = os.pathsep.join(ambiente_path + ([anterior] if anterior else []))
    env["PYTHONDONTWRITEBYTECODE"] = "1"

    try:
        resultado = subprocess.run(
            [sys.executable, "-B", str(caminho)],
            capture_output=True,
            text=True,
            timeout=TIMEOUT_SEGUNDOS,
            cwd=str(PROJECT_ROOT),
            env=env,
        )
    except subprocess.TimeoutExpired:
        return "FALHA", f"tempo esgotado ({TIMEOUT_SEGUNDOS}s)", ""

    saida = (resultado.stdout or "") + (resultado.stderr or "")

    if resultado.returncode == 0:
        return "PASSA", "", saida

    faltante = e_falta_de_ambiente(saida)
    if faltante:
        return "AMBIENTE", f"falta {faltante}", saida

    ultima = ""
    for linha in reversed(saida.strip().splitlines()):
        if linha.strip():
            ultima = linha.strip()[:70]
            break
    return "FALHA", f"exit {resultado.returncode}: {ultima}", saida


def main():
    analisador = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    analisador.add_argument(
        "-v",
        "--verboso",
        action="store_true",
        help="mostra a saida completa de cada teste que falhou",
    )
    argumentos = analisador.parse_args()

    arquivos = arquivos_de_teste()

    if not arquivos:
        print("Nenhum arquivo test_*.py encontrado.")
        return 1

    contagem = {"PASSA": 0, "FALHA": 0, "AMBIENTE": 0}
    falhas = []
    ambiente = []

    largura = max(len(str(p.relative_to(PROJECT_ROOT))) for p in arquivos)

    for caminho in arquivos:
        rotulo = str(caminho.relative_to(PROJECT_ROOT))
        print(f"  {rotulo:<{largura}}  ", end="", flush=True)

        desfecho, detalhe, saida = executa(caminho, argumentos.verboso)
        contagem[desfecho] += 1

        if desfecho == "PASSA":
            print("PASSA")
        elif desfecho == "AMBIENTE":
            print(f"AMBIENTE  ({detalhe})")
            ambiente.append((rotulo, detalhe))
        else:
            print(f"FALHA     ({detalhe})")
            falhas.append((rotulo, detalhe, saida))

    print()
    print("-" * (largura + 34))
    print(
        f"  {contagem['PASSA']} passam | "
        f"{contagem['FALHA']} falham | "
        f"{contagem['AMBIENTE']} nao executam por ambiente"
    )

    if ambiente:
        print()
        print("  Nao executados (dependencia ausente):")
        for rotulo, detalhe in ambiente:
            print(f"    {rotulo} — {detalhe}")
        print()
        print("    Para habilitar: pip install -e .[experiments,p4runtime]")
        print("    Os bindings p4.v1/p4.config.v1 nao estao no PyPI; vem de")
        print("    p4lang/PI ou p4runtime-shell.")

    if falhas and argumentos.verboso:
        for rotulo, _, saida in falhas:
            print()
            print("=" * (largura + 34))
            print(f"  {rotulo}")
            print("=" * (largura + 34))
            print(saida.rstrip())

    print()

    if falhas:
        print(f"SUITE REPROVADA — {len(falhas)} teste(s) falharam.")
        return 1

    print("SUITE APROVADA.")
    if ambiente:
        print(
            f"Atencao: {len(ambiente)} teste(s) nao foram executados; "
            "isso nao e o mesmo que passar."
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())

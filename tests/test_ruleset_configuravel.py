"""Testes do ruleset e da saida configuraveis (compiler/paths.py).

O pipeline le o ruleset de SNORT_P4_RULESET e grava em SNORT_P4_OUTPUT_DIR.
Tres propriedades importam:

    padrao intacto   sem as variaveis, os caminhos e o rotulo do manifesto
                     sao os de sempre, e o pipeline reproduz os artefatos
                     congelados byte a byte

    trava            ruleset diferente do padrao com a saida em output/ e
                     recusado antes de qualquer escrita, porque os estagios
                     gravam na raiz de output/, onde estao os congelados

    rotulo           o manifesto grava o ruleset sem vazar o diretorio de
                     instalacao

Cada caso roda em subprocesso, porque paths.py le o ambiente ao ser
importado, e com as duas variaveis limpas, para nao depender do terminal de
quem roda a suite.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
COMPILADOR = RAIZ / "compiler"

LER_PATHS = (
    "import json, paths; print(json.dumps({"
    "'ruleset': str(paths.RULESET_FILE), 'saida': str(paths.OUTPUT_DIR), "
    "'padrao': paths.RULESET_E_PADRAO, 'rotulo': paths.ruleset_label()}))"
)


def _ambiente(**variaveis):
    env = dict(os.environ)
    env.pop("SNORT_P4_RULESET", None)
    env.pop("SNORT_P4_OUTPUT_DIR", None)
    env.update({chave: str(valor) for chave, valor in variaveis.items()})
    return env


def _paths(**variaveis):
    resultado = subprocess.run(
        [sys.executable, "-B", "-c", LER_PATHS],
        cwd=COMPILADOR,
        env=_ambiente(**variaveis),
        capture_output=True,
        text=True,
    )
    return resultado


def test_sem_variaveis_e_o_padrao_de_sempre():
    resultado = _paths()
    assert resultado.returncode == 0, resultado.stderr
    lido = json.loads(resultado.stdout)
    assert Path(lido["ruleset"]) == RAIZ / "rules" / "snort3-community.rules"
    assert Path(lido["saida"]) == RAIZ / "output"
    assert lido["padrao"] is True
    assert lido["rotulo"] == "../rules/snort3-community.rules"


def test_ruleset_padrao_explicito_mantem_o_rotulo(tmp):
    # E o que run_static_pipeline faz com o ruleset padrao: o manifesto tem
    # de sair identico ao congelado, entao o rotulo nao pode mudar.
    resultado = _paths(
        SNORT_P4_RULESET=RAIZ / "rules" / "snort3-community.rules",
        SNORT_P4_OUTPUT_DIR=tmp,
    )
    assert resultado.returncode == 0, resultado.stderr
    lido = json.loads(resultado.stdout)
    assert lido["padrao"] is True
    assert lido["rotulo"] == "../rules/snort3-community.rules"
    assert Path(lido["saida"]) == Path(tmp).resolve()


def test_outro_ruleset_com_saida_em_output_e_recusado():
    resultado = _paths(SNORT_P4_RULESET=RAIZ / "rules" / "test.rules")
    assert resultado.returncode != 0
    assert "SNORT_P4_OUTPUT_DIR" in (resultado.stdout + resultado.stderr)


def test_rotulo_de_ruleset_dentro_do_projeto_e_relativo(tmp):
    resultado = _paths(
        SNORT_P4_RULESET=RAIZ / "rules" / "test.rules",
        SNORT_P4_OUTPUT_DIR=tmp,
    )
    assert resultado.returncode == 0, resultado.stderr
    lido = json.loads(resultado.stdout)
    assert lido["padrao"] is False
    assert lido["rotulo"] == "../rules/test.rules"


def test_rotulo_de_ruleset_fora_do_projeto_e_so_o_nome(tmp):
    fora = Path(tmp) / "meu_ruleset.rules"
    fora.write_text("", encoding="utf-8")
    resultado = _paths(SNORT_P4_RULESET=fora, SNORT_P4_OUTPUT_DIR=Path(tmp) / "saida")
    assert resultado.returncode == 0, resultado.stderr
    assert json.loads(resultado.stdout)["rotulo"] == "meu_ruleset.rules"


def test_outras_variaveis_com_saida_em_output_sao_recusadas():
    # Mesma trava do ruleset: outro perfil gravaria por cima do congelado.
    resultado = _paths(SNORT_P4_VARIABLES=RAIZ / "config" / "profiles" / "controlled.json")
    assert resultado.returncode != 0
    assert "SNORT_P4_OUTPUT_DIR" in (resultado.stdout + resultado.stderr)


def test_rotulo_das_variaveis(tmp):
    leitura = (
        "import json, paths; print(json.dumps({'padrao': paths.VARIAVEIS_E_PADRAO, "
        "'rotulo': paths.variables_label()}))"
    )

    def ler(**variaveis):
        resultado = subprocess.run(
            [sys.executable, "-B", "-c", leitura],
            cwd=COMPILADOR,
            env=_ambiente(**variaveis),
            capture_output=True,
            text=True,
        )
        assert resultado.returncode == 0, resultado.stderr
        return json.loads(resultado.stdout)

    assert ler() == {"padrao": True, "rotulo": "../config/snort_variables.json"}
    explicito = ler(
        SNORT_P4_VARIABLES=RAIZ / "config" / "snort_variables.json",
        SNORT_P4_OUTPUT_DIR=tmp,
    )
    assert explicito == {"padrao": True, "rotulo": "../config/snort_variables.json"}
    fora = Path(tmp) / "variaveis_x.json"
    fora.write_text("{}", encoding="utf-8")
    assert ler(SNORT_P4_VARIABLES=fora, SNORT_P4_OUTPUT_DIR=tmp) == {
        "padrao": False,
        "rotulo": "variaveis_x.json",
    }


def test_executor_recusa_perfil_inexistente(tmp):
    resultado = subprocess.run(
        [
            sys.executable,
            "-B",
            str(COMPILADOR / "run_static_pipeline.py"),
            "--ruleset",
            str(RAIZ / "rules" / "test.rules"),
            "--saida",
            str(tmp),
            "--perfil",
            "perfil_que_nao_existe",
        ],
        cwd=RAIZ,
        env=_ambiente(),
        capture_output=True,
        text=True,
    )
    assert resultado.returncode == 1
    assert "perfil nao encontrado" in resultado.stdout


def test_executor_recusa_saida_em_output():
    resultado = subprocess.run(
        [
            sys.executable,
            "-B",
            str(COMPILADOR / "run_static_pipeline.py"),
            "--ruleset",
            str(RAIZ / "rules" / "test.rules"),
            "--saida",
            str(RAIZ / "output"),
        ],
        cwd=RAIZ,
        env=_ambiente(),
        capture_output=True,
        text=True,
    )
    assert resultado.returncode == 1
    assert "congelados" in resultado.stdout


def _executor(ruleset, saida):
    return subprocess.run(
        [
            sys.executable,
            "-B",
            str(COMPILADOR / "run_static_pipeline.py"),
            "--ruleset",
            str(ruleset),
            "--saida",
            str(saida),
        ],
        cwd=RAIZ,
        env=_ambiente(),
        capture_output=True,
        text=True,
    )


def test_saida_reaproveitada_nao_herda_artefatos_da_execucao_anterior(tmp):
    # Segunda execucao na mesma --saida para na etapa 01. Os artefatos das
    # etapas seguintes ainda sao os da primeira, de outro ruleset: nao podem
    # entrar no resumo nem na proveniencia desta.
    boa = Path(tmp) / "boa.rules"
    boa.write_text(
        'alert tcp any any -> 10.0.0.1 [80,443] (msg:"a"; flags:S; sid:1;)\n',
        encoding="utf-8",
    )
    quebrada = Path(tmp) / "quebrada.rules"
    quebrada.write_text("isto nao e uma regra (sid:2;)\n", encoding="utf-8")
    saida = Path(tmp) / "saida"

    primeira = _executor(boa, saida)
    assert primeira.returncode == 0, primeira.stdout[-2000:]
    assert json.loads((saida / "proveniencia.json").read_text(encoding="utf-8"))[
        "resumo"
    ]["entradas_p4_finais"] == 2

    segunda = _executor(quebrada, saida)
    assert segunda.returncode == 1, segunda.stdout[-2000:]
    proveniencia = json.loads((saida / "proveniencia.json").read_text(encoding="utf-8"))
    assert proveniencia["status"] == "falhou"
    assert proveniencia["resumo"]["entradas_p4_finais"] is None, proveniencia["resumo"]
    assert proveniencia["resumo"]["plano_p4runtime"] is None, proveniencia["resumo"]
    assert "p4_install_entries.json" not in proveniencia["artefatos"]
    assert "semantic_manifest.json" in proveniencia["artefatos"]
    assert "ids_prefilter.p4info.txt" in proveniencia["artefatos"]


def test_build_profile_recusa_as_variaveis(tmp):
    # Sai antes do preflight de toolchain, entao roda sem Snort e sem p4c.
    resultado = subprocess.run(
        [sys.executable, "-B", str(COMPILADOR / "build_profile.py"), "cicids2017"],
        cwd=RAIZ,
        env=_ambiente(SNORT_P4_OUTPUT_DIR=tmp),
        capture_output=True,
        text=True,
    )
    assert resultado.returncode == 1
    assert "nenhum arquivo foi modificado" in resultado.stdout
    assert "run_static_pipeline" in resultado.stdout


def _manifesto_legacy(**variaveis):
    return subprocess.run(
        [
            sys.executable,
            "-B",
            str(COMPILADOR / "generate_semantic_manifest.py"),
            "--service-header-semantics",
            "legacy",
        ],
        cwd=RAIZ,
        env=_ambiente(**variaveis),
        capture_output=True,
        text=True,
    )


def test_manifesto_legacy_com_saida_em_output_e_recusado():
    # O manifesto congelado em output/ e o da semantica snort3. Um manifesto
    # legacy gravado ali por cima o trocaria pelo do arquivo historico. Se a
    # trava falhar, o teste devolve o congelado antes de reprovar.
    congelado = RAIZ / "output" / "semantic_manifest.json"
    antes = congelado.read_bytes()
    try:
        resultado = _manifesto_legacy()
    finally:
        depois = congelado.read_bytes()
        if depois != antes:
            congelado.write_bytes(antes)
    assert depois == antes, "o manifesto congelado foi sobrescrito"
    assert resultado.returncode == 1
    assert "SNORT_P4_OUTPUT_DIR" in resultado.stdout


def test_manifesto_legacy_com_outra_saida_reproduz_o_arquivo(tmp):
    resultado = _manifesto_legacy(SNORT_P4_OUTPUT_DIR=tmp)
    assert resultado.returncode == 0, resultado.stdout[-2000:]
    arquivado = (
        RAIZ / "output" / "historical" / "legacy_header_semantics"
        / "semantic_manifest.json"
    )
    gerado = Path(tmp) / "semantic_manifest.json"
    assert gerado.read_bytes() == arquivado.read_bytes()


if __name__ == "__main__":
    import tempfile

    test_sem_variaveis_e_o_padrao_de_sempre()
    test_outro_ruleset_com_saida_em_output_e_recusado()
    test_outras_variaveis_com_saida_em_output_sao_recusadas()
    test_executor_recusa_saida_em_output()
    test_manifesto_legacy_com_saida_em_output_e_recusado()
    for teste in (
        test_rotulo_das_variaveis,
        test_executor_recusa_perfil_inexistente,
        test_ruleset_padrao_explicito_mantem_o_rotulo,
        test_rotulo_de_ruleset_dentro_do_projeto_e_relativo,
        test_rotulo_de_ruleset_fora_do_projeto_e_so_o_nome,
        test_saida_reaproveitada_nao_herda_artefatos_da_execucao_anterior,
        test_build_profile_recusa_as_variaveis,
        test_manifesto_legacy_com_outra_saida_reproduz_o_arquivo,
    ):
        with tempfile.TemporaryDirectory() as tmp:
            teste(tmp)

    print("Ruleset configuravel: testes passaram.")

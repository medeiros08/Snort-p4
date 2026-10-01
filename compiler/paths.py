"""Caminhos do projeto, ancorados na localizacao deste arquivo.

Antes deste modulo, os estagios do pipeline usavam constantes relativas ao
diretorio de trabalho ("../output/...", "../config/...", "../rules/...").
O pipeline so funcionava com cwd=compiler/, condicao que nao estava
declarada em lugar nenhum e que `build_profile.py` satisfazia passando
cwd=COMPILER_DIR ao subprocess.

As consequencias praticas eram duas. Reexecutar um estagio isolado a partir
da raiz do repositorio — o gesto natural de quem depura — resolvia o caminho
para fora do projeto e imprimia "not found" terminando com codigo 0. E
`tests/test_variable_resolver.py` falhava com FileNotFoundError apontando
C:\\Users\\...\\Desktop\\config\\snort_variables.json, um diretorio que nao
existe, porque `variable_resolver.py` procurava "../config/..." a partir da
raiz.

Ancorando em __file__, os estagios passam a funcionar a partir de qualquer
diretorio de trabalho.

Nota sobre artefatos: alguns artefatos gravam o caminho de origem como dado.
Quando esse valor e o caminho relativo completo (o caso de
semantic_manifest.json), ele NAO deve virar absoluto — isso mudaria o
conteudo do artefato e vazaria o diretorio de instalacao do repositorio.
Esses casos usam constantes de rotulo separadas, mantidas literais. Os
demais artefatos gravam apenas o basename, que e estavel.
"""

import os

from pathlib import Path

COMPILER_DIR = Path(__file__).resolve().parent

PROJECT_ROOT = COMPILER_DIR.parent

CONFIG_DIR = PROJECT_ROOT / "config"

RULES_DIR = PROJECT_ROOT / "rules"

P4_DIR = PROJECT_ROOT / "p4"


# ============================================================
# Ruleset e diretorio de saida
# ============================================================
#
# O ruleset avaliado e a saida do pipeline vem destas duas variaveis de
# ambiente; sem elas, os valores sao os de sempre, e o pipeline reproduz os
# artefatos congelados byte a byte. Variavel de ambiente, e nao argumento de
# cada estagio, porque os estagios rodam como subprocessos encadeados e
# todos precisam ver o mesmo par; quem define as duas e
# `run_static_pipeline.py`, pelos argumentos --ruleset e --saida.
#
# Ruleset diferente do padrao com a saida em output/ e recusado: todos os
# estagios gravam na raiz de OUTPUT_DIR, e os artefatos que estao ali sao os
# congelados que sustentam o artigo.

VAR_RULESET = "SNORT_P4_RULESET"

VAR_SAIDA = "SNORT_P4_OUTPUT_DIR"

# Arquivo de variaveis do perfil. O padrao e o que compiler/select_profile.py
# grava para o perfil ativo; run_static_pipeline.py --perfil aponta para outro
# perfil sem reescrever config/.
VAR_VARIAVEIS = "SNORT_P4_VARIABLES"

RULESET_PADRAO = RULES_DIR / "snort3-community.rules"

SAIDA_PADRAO = PROJECT_ROOT / "output"

VARIAVEIS_PADRAO = CONFIG_DIR / "snort_variables.json"

# Rotulos gravados no manifesto para os arquivos padrao. Literais e
# relativos, como antes, para que o artefato nao dependa de onde o
# repositorio esta.
ROTULO_RULESET_PADRAO = "../rules/snort3-community.rules"

ROTULO_VARIAVEIS_PADRAO = "../config/snort_variables.json"


def _caminho_do_ambiente(nome, padrao):
    valor = os.environ.get(nome, "").strip()
    return Path(valor).expanduser().resolve() if valor else padrao


RULESET_FILE = _caminho_do_ambiente(VAR_RULESET, RULESET_PADRAO)

OUTPUT_DIR = _caminho_do_ambiente(VAR_SAIDA, SAIDA_PADRAO)

VARIABLES_FILE = _caminho_do_ambiente(VAR_VARIAVEIS, VARIAVEIS_PADRAO)

RULESET_E_PADRAO = RULESET_FILE == RULESET_PADRAO

VARIAVEIS_E_PADRAO = VARIABLES_FILE == VARIAVEIS_PADRAO

if (not RULESET_E_PADRAO or not VARIAVEIS_E_PADRAO) and OUTPUT_DIR == SAIDA_PADRAO:
    alterado = (
        f"{VAR_RULESET} aponta para {RULESET_FILE}"
        if not RULESET_E_PADRAO
        else f"{VAR_VARIAVEIS} aponta para {VARIABLES_FILE}"
    )
    raise SystemExit(
        f"ERRO: {alterado}, mas a saida continua em {SAIDA_PADRAO}, onde "
        f"estao os artefatos congelados. Defina {VAR_SAIDA} com outro "
        f"diretorio, ou use compiler/run_static_pipeline.py com --saida."
    )


def _rotulo(arquivo, e_padrao, rotulo_padrao):
    if e_padrao:
        return rotulo_padrao
    try:
        relativo = arquivo.relative_to(PROJECT_ROOT)
    except ValueError:
        return arquivo.name
    return "../" + relativo.as_posix()


def ruleset_label():
    """Rotulo do ruleset gravado no manifesto.

    O padrao mantem o literal de sempre. Outro ruleset dentro do projeto
    grava o caminho relativo no mesmo estilo; fora do projeto, so o nome do
    arquivo, para nao vazar o diretorio de instalacao no artefato.
    """

    return _rotulo(RULESET_FILE, RULESET_E_PADRAO, ROTULO_RULESET_PADRAO)


def variables_label():
    """Rotulo do arquivo de variaveis gravado no manifesto, na mesma regra."""

    return _rotulo(VARIABLES_FILE, VARIAVEIS_E_PADRAO, ROTULO_VARIAVEIS_PADRAO)

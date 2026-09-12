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

from pathlib import Path

COMPILER_DIR = Path(__file__).resolve().parent

PROJECT_ROOT = COMPILER_DIR.parent

CONFIG_DIR = PROJECT_ROOT / "config"

OUTPUT_DIR = PROJECT_ROOT / "output"

RULES_DIR = PROJECT_ROOT / "rules"

P4_DIR = PROJECT_ROOT / "p4"

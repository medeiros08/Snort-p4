"""Gate de falha compartilhado dos estagios do pipeline.

Antes deste modulo nenhum estagio do pipeline chamava sys.exit. Cada um
gravava um artefato registrando suas proprias falhas e terminava com codigo
0, de modo que `build_profile.py` (que so checa returncode) prosseguia para
o estagio seguinte, e este consumia o artefato do build ANTERIOR.

O gate le o artefato que o estagio acabou de gravar e falha com codigo 1 se
o proprio artefato declarar erro. Ler o artefato, em vez de inspecionar
variaveis internas, tem duas vantagens: o criterio de falha fica num lugar
so, e o gate tambem pega o caso em que o estagio calculou o erro
corretamente mas nao o refletiu no estado que retornaria.

Campos que NAO sao falha e nao devem ser gateados:

    p4_entries.json / skipped_rules
        As regras UNSUPPORTED (14 no ruleset avaliado) sao puladas por
        desenho. Gatear nisto reprovaria todo build valido.

    *_by_classification
        Distribuicoes, nao erros.
"""

import json
import sys
from pathlib import Path


# Por artefato: caminho da chave (tupla) -> significa falha se for
# inteiro != 0 ou colecao nao vazia.
CAMPOS_DE_FALHA = {
    "semantic_manifest.json": [
        ("summary", "failures"),
    ],
    "snort_experiment_split.json": [
        ("manifest_failures",),
        ("validation_errors",),
    ],
    "p4_entries.json": [
        ("failed_rules",),
    ],
    "p4_entries_expanded.json": [
        ("unresolved_list_values",),
    ],
    "p4runtime_entries.json": [
        ("failed_entries",),
        ("failures",),
    ],
    "backend_validation.json": [
        ("validation_errors",),
        ("errors",),
    ],
    "p4_install_entries.json": [
        ("validation_errors",),
    ],
    "p4runtime_install_plan.json": [
        ("encoding_failures",),
        ("validation_errors",),
    ],
}

# Por artefato: chave de status cujo valor nao pode conter "INVALID".
CAMPOS_DE_STATUS = {
    "backend_validation.json": "backend_status",
}


def _busca(dados, caminho):
    atual = dados
    for chave in caminho:
        if not isinstance(atual, dict) or chave not in atual:
            return None
        atual = atual[chave]
    return atual


def _e_falha(valor):
    if valor is None:
        return False
    if isinstance(valor, bool):
        return valor
    if isinstance(valor, int):
        return valor != 0
    if isinstance(valor, (list, tuple, dict, str)):
        return len(valor) > 0
    return False


def _descreve(valor, limite=3):
    if isinstance(valor, int):
        return str(valor)
    if isinstance(valor, list):
        amostra = ", ".join(
            json.dumps(item, ensure_ascii=False)[:100] for item in valor[:limite]
        )
        resto = "" if len(valor) <= limite else f" (+{len(valor) - limite})"
        return f"{len(valor)} item(s): {amostra}{resto}"
    return json.dumps(valor, ensure_ascii=False)[:200]


def aplicar(caminho_artefato):
    """Falha com codigo 1 se o artefato declarar erro.

    Retorna None quando o artefato esta limpo, para poder ser chamado como
    ultima instrucao de main().
    """
    caminho = Path(caminho_artefato)
    nome = caminho.name

    if not caminho.exists():
        print()
        print(f"GATE: FALHOU — artefato nao foi gravado: {caminho}")
        sys.exit(1)

    try:
        dados = json.loads(caminho.read_text(encoding="utf-8"))
    except (ValueError, OSError) as erro:
        print()
        print(f"GATE: FALHOU — artefato ilegivel: {caminho}")
        print(f"       {type(erro).__name__}: {erro}")
        sys.exit(1)

    problemas = []

    for chave_caminho in CAMPOS_DE_FALHA.get(nome, []):
        valor = _busca(dados, chave_caminho)
        if _e_falha(valor):
            problemas.append((".".join(chave_caminho), _descreve(valor)))

    chave_status = CAMPOS_DE_STATUS.get(nome)
    if chave_status:
        status = dados.get(chave_status)
        if isinstance(status, str) and "INVALID" in status.upper():
            problemas.append((chave_status, status))

    if not problemas:
        return None

    print()
    print(f"GATE: FALHOU — {nome} declara erro:")
    for campo, detalhe in problemas:
        print(f"       {campo}: {detalhe}")
    print()
    print("O estagio nao pode ser considerado bem-sucedido. Saindo com 1 para")
    print("impedir que o estagio seguinte consuma um artefato invalido ou que")
    print("o build prossiga com o artefato da execucao anterior.")
    sys.exit(1)

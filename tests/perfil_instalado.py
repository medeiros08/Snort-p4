"""Verifica qual perfil esta instalado na tabela do switch.

Dois testes deste repositorio dependem de perfis DIFERENTES e mutuamente
exclusivos:

    test_alert_preservation_bmv2.py   exige o perfil `controlled`
                                      (HOME_NET 10.0.0.0/24), porque o pcap
                                      manda pacotes para 10.0.0.10 e 10.0.0.11

    test_ipv4_packet_domain_guard.py  exige que a tabela instalada seja a de
                                      output/p4_install_entries.json, de onde
                                      ele calcula a classificacao esperada

Nao existe estado do switch em que os dois passem na mesma execucao. Isso e
uma propriedade do experimento, nao um defeito — mas precisa ser DITO. Antes
desta verificacao, o perfil errado se manifestava como contador que nao
incrementa, um numero que parece defeito do compilador e nao e.

A mensagem emitida carrega o marcador PERFIL_INCOMPATIVEL, que run_tests.py
reconhece para classificar o desfecho como limitacao de ambiente em vez de
falha. Um teste que nao pode rodar no estado atual do switch nao esta
reprovando; ele nao esta rodando.
"""

import json
import sys
from pathlib import Path

from p4.v1 import p4runtime_pb2

RAIZ = Path(__file__).resolve().parents[1]
DIRETORIO_DE_PERFIS = RAIZ / "output" / "profiles"
PLANO_DA_RAIZ = RAIZ / "output" / "p4runtime_install_plan.json"

MARCADOR = "PERFIL_INCOMPATIVEL"


def _chaves(pares):
    """Normaliza um conjunto de campos de casamento.

    Compara valor e mascara como INTEIRO, nunca como string hexadecimal: o
    P4Runtime devolve os bytes canonicos, sem zeros a esquerda, entao o switch
    responde "15" onde o plano registra "0015".
    """

    return tuple(sorted(pares))


def chaves_do_plano(caminho):
    """Conjunto de chaves de casamento declaradas por um plano."""

    plano = json.loads(
        Path(caminho).read_text(encoding="utf-8")
    )

    conjunto = set()

    for entrada in plano.get("entries", []):

        campos = []

        for campo in entrada.get("match", []):

            ternary = campo.get("ternary", {})

            campos.append(
                (
                    campo.get("field_id"),
                    int(ternary.get("value_hex") or "0", 16),
                    int(ternary.get("mask_hex") or "0", 16),
                )
            )

        conjunto.add(_chaves(campos))

    return conjunto


def chaves_instaladas(stub, device_id, table_id):
    """Conjunto de chaves de casamento realmente instaladas no switch."""

    request = p4runtime_pb2.ReadRequest()
    request.device_id = device_id

    entity = request.entities.add()
    entity.table_entry.table_id = table_id

    conjunto = set()

    for response in stub.Read(request):

        for result in response.entities:

            if not result.HasField("table_entry"):
                continue

            campos = []

            for campo in result.table_entry.match:

                campos.append(
                    (
                        campo.field_id,
                        int.from_bytes(campo.ternary.value, "big"),
                        int.from_bytes(campo.ternary.mask, "big"),
                    )
                )

            conjunto.add(_chaves(campos))

    return conjunto


def _identifica(instaladas):
    """Nome do perfil cujo plano corresponde ao que esta no switch."""

    # A raiz e sempre copia de algum perfil, entao procurar entre os perfis
    # nomeia melhor do que dizer "a raiz".
    if DIRETORIO_DE_PERFIS.is_dir():

        for diretorio in sorted(DIRETORIO_DE_PERFIS.iterdir()):

            plano = diretorio / "artifacts" / "p4runtime_install_plan.json"

            if plano.exists() and instaladas == chaves_do_plano(plano):
                return diretorio.name

    return "desconhecido"


def _aborta(exigido, instalado, comando):
    print()
    print(f"{MARCADOR}: a tabela instalada no switch nao serve a este teste.")
    print(f"  exigido   : {exigido}")
    print(f"  instalado : {instalado}")
    print()
    print("  Instale o perfil correto e rode de novo:")
    print(f"    {comando}")
    print()
    print("  Os testes de plano de dados deste repositorio exigem perfis")
    print("  diferentes; nao ha estado do switch em que todos passem de uma")
    print("  vez. Rode um perfil por vez.")
    sys.exit(1)


def exige_perfil(stub, device_id, table_id, perfil):
    """Aborta se a tabela instalada nao for a do perfil nomeado."""

    plano = (
        DIRETORIO_DE_PERFIS / perfil / "artifacts" / "p4runtime_install_plan.json"
    )

    if not plano.exists():
        return

    instaladas = chaves_instaladas(stub, device_id, table_id)

    if not instaladas:
        _aborta(
            f"{perfil} (nenhuma entrada instalada)",
            "tabela vazia",
            "python3 compiler/install_p4runtime.py --plan "
            f"output/profiles/{perfil}/artifacts/p4runtime_install_plan.json",
        )

    if instaladas == chaves_do_plano(plano):
        return

    _aborta(
        perfil,
        _identifica(instaladas),
        "python3 compiler/install_p4runtime.py --plan "
        f"output/profiles/{perfil}/artifacts/p4runtime_install_plan.json",
    )


def exige_plano_da_raiz(stub, device_id, table_id):
    """Aborta se a tabela instalada nao for a de output/.

    Usado pelos testes que calculam o resultado esperado a partir dos
    artefatos da raiz: se o switch tiver outra tabela, o esperado e o
    observado vem de mundos diferentes.
    """

    if not PLANO_DA_RAIZ.exists():
        return

    instaladas = chaves_instaladas(stub, device_id, table_id)

    if not instaladas:
        _aborta(
            "a tabela de output/ (nenhuma entrada instalada)",
            "tabela vazia",
            "python3 compiler/install_p4runtime.py",
        )

    if instaladas == chaves_do_plano(PLANO_DA_RAIZ):
        return

    _aborta(
        f"a tabela de output/ ({_identifica(chaves_do_plano(PLANO_DA_RAIZ))})",
        _identifica(instaladas),
        "python3 compiler/install_p4runtime.py",
    )

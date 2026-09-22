#!/usr/bin/env python3
"""Roda a campanha end-to-end no rig: Snort como oraculo, BMv2 como alvo.

Consome o que `tests/generate_campaign_cases.py` produziu e emite o veredito
por caso. Cada caso e uma regra do ruleset exercitada de ponta a ponta: o
Snort le o pcap e diz se a regra dispara; o BMv2 recebe os mesmos quadros e
diz em que categoria o prefilter os coloca.

Veredito por caso, sobre o quadro testemunha:

    CONFIRMADO    Snort alertou o sid e o prefilter marcou P4_CANDIDATE.
                  E a propriedade conservadora observada: Snort(regra,pkt)
                  => P4_candidato(regra,pkt)

    CONSERVADOR   Snort alertou e o prefilter respondeu
                  PACKET_DOMAIN_FALLBACK. Mais permissivo, logo dentro da
                  propriedade

    VIOLACAO      Snort alertou e o prefilter respondeu P4_NO_MATCH. E o
                  unico desfecho que reprova a campanha: o data plane
                  descartaria um pacote que a regra original alerta

    VACUO         o Snort nao alertou. O caso nao testou a implicacao, porque
                  o oraculo ficou calado — testemunha que nao dispara a regra
                  nao e evidencia de nada. Contado a parte, nunca como
                  sucesso, pelo mesmo motivo que run_tests.py conta AMBIENTE
                  a parte de PASSA

Os dois vizinhos negativos de cada caso nao tem poder de reprovar. O
`negativo_payload` mede o excesso conservador do prefilter (mesma 5-tupla sem
o content: o Snort silencia e o prefilter, que decide por header, continua
marcando candidate). O `negativo_header` e o controle do proprio prefilter.

Taxas de candidato e no-match usam **apenas o dominio suportado** como
denominador, e o fallback e reportado separado. Colapsar o fallback em
no-match superestimaria a seletividade.

Codigos de saida:

    0   campanha concluida sem violacao
    1   ao menos uma VIOLACAO, ou artefato de entrada invalido
    2   limitacao de ambiente: bindings ausentes, BMv2 fora do ar, perfil
        instalado incompativel, falta de privilegio para socket raw

Uso (no rig, com o BMv2 no ar e as entradas instaladas):
    python tests/run_campaign_bmv2.py --casos output/campaign/piloto
    python tests/run_campaign_bmv2.py --casos output/campaign/e2e_1000
    python tests/run_campaign_bmv2.py --casos output/campaign/piloto --pular-snort
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import struct
import subprocess
import sys
import time

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "tests"))

P4INFO_FILE = PROJECT_ROOT / "output" / "ids_prefilter.p4info.txt"
SNORT_CONFIG = PROJECT_ROOT / "config" / "snort3_experiment.lua"
FULL_RULES = PROJECT_ROOT / "rules" / "snort3-community.rules"

# Indices do prefilter_counter, na ordem documentada no README.
CATEGORIAS = {
    0: "P4_CANDIDATE",
    1: "P4_NO_MATCH",
    2: "PACKET_DOMAIN_FALLBACK",
}

MARCADOR_AMBIENTE = "LIMITACAO_DE_AMBIENTE"


def aborta_por_ambiente(mensagem: str, comando: str | None = None) -> None:
    """Sai com codigo 2 dizendo o que fazer.

    Cada uma destas condicoes ja se manifestou neste projeto como numero que
    parece defeito do compilador: contador que nao incrementa, conexao
    recusada, PermissionError cru. Ambiente que falta nao e defeito, mas
    precisa ser dito com o nome certo.
    """

    print(f"\n{MARCADOR_AMBIENTE}: {mensagem}", file=sys.stderr)
    if comando:
        print(f"  {comando}", file=sys.stderr)
    sys.exit(2)


# ============================================================
# pcap
# ============================================================


def ler_pcap(caminho: Path) -> list[tuple[int, int, bytes]]:
    """Le o pcap classico gerado pela campanha, sem dependencia externa.

    O gerador escreve o arquivo; nao ha motivo para pedir scapy de volta so
    para reler o que este repositorio mesmo produziu.
    """

    dados = caminho.read_bytes()
    if len(dados) < 24:
        raise ValueError(f"pcap truncado: {caminho}")

    magica = struct.unpack("!I", dados[:4])[0]
    if magica == 0xA1B2C3D4:
        ordem = "!"
    elif magica == 0xD4C3B2A1:
        ordem = "<"
    else:
        raise ValueError(f"magica de pcap desconhecida: 0x{magica:08x}")

    quadros = []
    posicao = 24
    while posicao + 16 <= len(dados):
        segundos, micros, capturados, _originais = struct.unpack(
            ordem + "IIII", dados[posicao : posicao + 16]
        )
        posicao += 16
        quadros.append((segundos, micros, dados[posicao : posicao + capturados]))
        posicao += capturados

    return quadros


# ============================================================
# Snort
# ============================================================


def lar_do_usuario() -> Path:
    """Home do usuario que chamou, e nao o de root quando ha sudo.

    O estagio de replay exige sudo por causa do CAP_NET_RAW, e sob sudo
    Path.home() devolve /root — onde o Snort do projeto nao esta. O caminho
    tem de sair do usuario original, senao o estagio aborta dizendo que falta
    um arquivo que existe.
    """

    invocador = os.environ.get("SUDO_USER")
    if invocador:
        try:
            import pwd  # noqa: PLC0415 - existe so em POSIX

            return Path(pwd.getpwnam(invocador).pw_dir)
        except (ImportError, KeyError):
            pass
    return Path.home()


def ambiente_do_snort(raiz: Path) -> dict:
    """Ambiente do processo do Snort: HOME do usuario e libs da instalacao.

    HOME importa tanto quanto o caminho do binario. `config/snort3_experiment.lua`
    resolve a instalacao com `os.getenv('HOME') .. '/snort3-install'`, e sob
    sudo o HOME e /root — o Lua entao tenta abrir
    /root/snort3-install/etc/snort/snort.lua, falha, e as variaveis $HOME_NET
    e $EXTERNAL_NET do ruleset ficam indefinidas. Corrigir so o caminho do
    binario nao resolve: o arquivo de configuracao faz a sua propria busca.
    """

    ambiente = dict(os.environ)
    ambiente["HOME"] = str(raiz.parent)
    lib = raiz / "lib"
    anterior = ambiente.get("LD_LIBRARY_PATH", "")
    ambiente["LD_LIBRARY_PATH"] = f"{lib}:{anterior}" if anterior else str(lib)
    return ambiente


def rodar_snort(
    pcap: Path, destino: Path, raiz: Path | None = None, sufixo: str = ""
) -> Path:
    """Roda o Snort sobre o pcap da campanha com o ruleset completo.

    Ruleset completo, e nao a particao de candidatos: o oraculo tem de ser o
    Snort que o operador rodaria, senao a campanha mede o compilador contra
    uma versao dele mesmo.

    `timestamp` e `pkt_num` nos campos do alert_json dao as duas atribuicoes
    de alerta a caso (docs/vendor/snort3/doc/reference/snort_reference.text
    :9700 lista os campos disponiveis no pin 3.12.2.0); a campanha usa
    pkt_num e confere com timestamp.
    """

    raiz_snort = raiz or (lar_do_usuario() / "snort3-install")
    binario = raiz_snort / "bin" / "snort"

    for exigido in (binario, SNORT_CONFIG, FULL_RULES):
        if not exigido.exists():
            aborta_por_ambiente(
                f"arquivo exigido pelo Snort ausente: {exigido}",
                "aponte a instalacao com --raiz-snort /caminho/snort3-install",
            )

    alertas = destino / f"snort_alertas{sufixo}.jsonl"
    comando = [
        str(binario),
        "-q",
        "-c",
        str(SNORT_CONFIG),
        "-R",
        str(FULL_RULES),
        "-r",
        str(pcap),
        "-A",
        "alert_json",
        "--lua",
        "alert_json = { fields = 'timestamp pkt_num gid sid rev msg src_ap dst_ap' }",
    ]

    print(f"  snort: {' '.join(comando[:6])} ...")
    with open(alertas, "w", encoding="utf-8") as saida:
        resultado = subprocess.run(
            comando,
            stdout=saida,
            stderr=subprocess.PIPE,
            env=ambiente_do_snort(raiz_snort),
            text=True,
        )

    if resultado.returncode != 0:
        print(resultado.stderr[:2000], file=sys.stderr)
        aborta_por_ambiente(
            f"Snort terminou com codigo {resultado.returncode}",
            "verifique config/snort3_experiment.lua e o ruleset",
        )

    return alertas


def indexar_alertas(caminho: Path) -> tuple[dict[int, set[str]], dict[str, set[str]]]:
    """Indexa os alertas por numero de pacote e por marca de tempo local."""

    por_pacote: dict[int, set[str]] = {}
    por_marca: dict[str, set[str]] = {}

    for linha in caminho.read_text(encoding="utf-8", errors="ignore").splitlines():
        linha = linha.strip()
        if not linha:
            continue
        try:
            alerta = json.loads(linha)
        except json.JSONDecodeError:
            continue

        sid = str(alerta.get("sid", "")).strip()
        if not sid:
            continue

        numero = alerta.get("pkt_num")
        if numero is not None:
            try:
                por_pacote.setdefault(int(numero), set()).add(sid)
            except (TypeError, ValueError):
                pass

        # O alert_json emite hora local sem ano, no formato
        # "11/14-19:13:21.000000". Nao ha epoch para ler: a conferencia
        # compara o prefixo "%m/%d-%H:%M:%S" renderizado a partir do segundo
        # que o gerador deu ao caso. Ler os digitos como epoch, como esta
        # verificacao fazia antes, produzia divergencia em todo caso que
        # alertou — alarme falso vindo do conferente, nao do medido.
        marca = str(alerta.get("timestamp", "")).strip()
        if marca:
            por_marca.setdefault(marca[:14], set()).add(sid)

    return por_pacote, por_marca


# ============================================================
# BMv2
# ============================================================


def conectar(endereco: str):
    try:
        import grpc  # noqa: PLC0415
        from google.protobuf import text_format  # noqa: PLC0415
        from p4.config.v1 import p4info_pb2  # noqa: PLC0415
        from p4.v1 import p4runtime_pb2, p4runtime_pb2_grpc  # noqa: PLC0415
    except ImportError as erro:
        aborta_por_ambiente(
            f"dependencia ausente: {erro.name}",
            "pip install -e .[experiments,p4runtime] ; os bindings p4.v1 vem "
            "de p4lang/PI ou p4runtime-shell",
        )

    if not P4INFO_FILE.exists():
        aborta_por_ambiente(
            f"P4Info ausente: {P4INFO_FILE}",
            "python compiler/build_profile.py <perfil>",
        )

    p4info = p4info_pb2.P4Info()
    text_format.Merge(
        P4INFO_FILE.read_text(encoding="utf-8", errors="ignore"), p4info
    )

    canal = grpc.insecure_channel(endereco)
    stub = p4runtime_pb2_grpc.P4RuntimeStub(canal)

    return stub, p4info, p4runtime_pb2, grpc


def achar_contador(p4info) -> int:
    for contador in p4info.counters:
        if contador.preamble.alias == "prefilter_counter" or contador.preamble.name.endswith(
            "prefilter_counter"
        ):
            return contador.preamble.id
    aborta_por_ambiente(
        "prefilter_counter nao existe no P4Info instalado",
        "confirme que output/ids_prefilter.p4info.txt e do programa no switch",
    )
    return 0


def achar_tabela(p4info) -> int:
    for tabela in p4info.tables:
        if tabela.preamble.alias == "ids_prefilter" or tabela.preamble.name.endswith(
            "ids_prefilter"
        ):
            return tabela.preamble.id
    aborta_por_ambiente("tabela ids_prefilter nao existe no P4Info instalado")
    return 0


def ler_contadores(stub, p4runtime_pb2, grpc, contador_id: int, device_id: int) -> dict:
    """Le os tres indices do prefilter_counter numa requisicao."""

    pedido = p4runtime_pb2.ReadRequest()
    pedido.device_id = device_id
    for indice in CATEGORIAS:
        entidade = pedido.entities.add()
        entidade.counter_entry.counter_id = contador_id
        entidade.counter_entry.index.index = indice

    valores = {nome: 0 for nome in CATEGORIAS.values()}

    try:
        for resposta in stub.Read(pedido):
            for entidade in resposta.entities:
                if not entidade.HasField("counter_entry"):
                    continue
                indice = entidade.counter_entry.index.index
                nome = CATEGORIAS.get(indice)
                if nome is not None:
                    valores[nome] = entidade.counter_entry.data.packet_count
    except grpc.RpcError as erro:
        aborta_por_ambiente(
            f"P4Runtime inacessivel: {erro.code().name}",
            "sudo ./scripts/setup_bmv2.sh up ; python compiler/install_p4runtime.py",
        )

    return valores


def abrir_socket(interface: str):
    try:
        bruto = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        bruto.bind((interface, 0))
        return bruto
    except AttributeError:
        aborta_por_ambiente(
            "AF_PACKET nao existe nesta plataforma",
            "este estagio roda no rig Linux; no Windows so o gerador roda",
        )
    except PermissionError:
        aborta_por_ambiente(
            "sem privilegio para abrir socket raw (CAP_NET_RAW)",
            "sudo python tests/run_campaign_bmv2.py ...",
        )
    except OSError as erro:
        aborta_por_ambiente(
            f"nao foi possivel usar a interface {interface}: {erro}",
            "sudo ./scripts/setup_bmv2.sh up cria veth0..veth3",
        )
    return None


# ============================================================
# Campanha
# ============================================================


def classificar_quadros(
    quadros: list[tuple[int, int, bytes]],
    interface: str,
    intervalo: float,
    endereco: str,
    device_id: int,
    plano: Path | None = None,
) -> list[str]:
    """Envia cada quadro e devolve a categoria observada, na ordem do pcap.

    Um quadro por vez, com leitura de contador depois de cada envio: e a
    unica forma de atribuir categoria a quadro, porque o contador do plano de
    dados e agregado por categoria e nao carrega identidade de pacote.
    """

    stub, p4info, p4runtime_pb2, grpc = conectar(endereco)
    contador_id = achar_contador(p4info)
    tabela_id = achar_tabela(p4info)

    # A tabela instalada tem de ser a do plano contra o qual as expectativas
    # foram calculadas; outra tabela produziria contador parado ou categoria
    # trocada, que parece defeito do compilador e nao e.
    try:
        if plano is None:
            from perfil_instalado import exige_plano_da_raiz  # noqa: PLC0415

            exige_plano_da_raiz(stub, device_id, tabela_id)
        else:
            from perfil_instalado import (  # noqa: PLC0415
                MARCADOR,
                chaves_do_plano,
                chaves_instaladas,
            )

            instaladas = chaves_instaladas(stub, device_id, tabela_id)
            esperadas = chaves_do_plano(plano)
            if instaladas != esperadas:
                aborta_por_ambiente(
                    f"{MARCADOR}: tabela instalada tem {len(instaladas)} entradas "
                    f"e o plano {plano.name} declara {len(esperadas)}",
                    f"python compiler/install_p4runtime.py --plan {plano}",
                )
            print(f"  tabela confere com {plano.name}: {len(instaladas)} entradas")
    except ImportError:
        print("  aviso: perfil_instalado.py ausente, perfil nao verificado")

    bruto = abrir_socket(interface)
    anterior = ler_contadores(stub, p4runtime_pb2, grpc, contador_id, device_id)

    categorias: list[str] = []
    total = len(quadros)

    try:
        for posicao, (_segundos, _micros, quadro) in enumerate(quadros):
            bruto.send(quadro)
            time.sleep(intervalo)
            atual = ler_contadores(stub, p4runtime_pb2, grpc, contador_id, device_id)

            deltas = {
                nome: atual[nome] - anterior[nome] for nome in atual
            }
            anterior = atual

            mexeram = [nome for nome, valor in deltas.items() if valor > 0]
            if len(mexeram) == 1:
                categorias.append(mexeram[0])
            elif not mexeram:
                categorias.append("SEM_INCREMENTO")
            else:
                categorias.append("AMBIGUO:" + "+".join(sorted(mexeram)))

            if (posicao + 1) % 250 == 0:
                print(f"  {posicao + 1}/{total} quadros classificados")
    finally:
        bruto.close()

    return categorias


def marca_do_caso(segundos: int) -> str:
    """Renderiza o segundo do caso como o alert_json o imprime.

    Hora local da maquina, porque e assim que o Snort formata; o pcap foi
    escrito com epoch fixo, entao a conversao e deterministica na maquina que
    roda a campanha.
    """

    return time.strftime("%m/%d-%H:%M:%S", time.localtime(segundos))


# Quadros que so existem para montar a sessao. Eles nao casam o header da
# regra — o ACK de flush, por exemplo, vai no sentido oposto —, entao o
# prefilter nao tem motivo para marca-los por causa desta regra.
PAPEIS_DE_ANDAIME = frozenset({"handshake", "aquecimento", "resposta_servidor", "flush"})


def veredito_do_caso(
    categorias: dict[str, str],
    alertou: bool,
    alertados: list[tuple[str, str]],
    em_fallback_operacional: bool = False,
) -> str:
    """Veredito sobre a testemunha e sobre os quadros em que o Snort alertou.

    `alertados` traz (papel, categoria P4) de cada quadro em que o Snort
    emitiu alerta deste sid. Tres situacoes diferentes, que nao podem ser
    colapsadas:

        VIOLACAO               um quadro que CASA o header da regra (a
                               testemunha, ou um negativo que alertou) saiu
                               P4_NO_MATCH. O prefilter recusou o pacote que a
                               regra descreve: defeito de rebaixamento

        DEPENDENCIA_DE_ESTADO  a testemunha e candidate, mas o alerta caiu num
                               quadro de andaime — em HTTP, o ACK de flush que
                               vai do servidor ao cliente — e esse quadro saiu
                               P4_NO_MATCH. O compilador cobriu o pacote da
                               regra; o que falta e o prefilter, que decide
                               pacote a pacote, entregar o pacote do sentido
                               oposto de que a deteccao de stream depende.
                               Sob o plano completo isto nunca aparecia porque
                               p4-138 cobria todo pacote saindo da HOME_NET;
                               e a lacuna de execucao stateful tornada medida

        CONFIRMADO             todos candidate

    Regra em fallback operacional e inspecionada pelo Snort sem filtro: o
    prefilter nao responde por ela.
    """

    if not alertou:
        return "VACUO"
    if em_fallback_operacional:
        return "FALLBACK_OPERACIONAL"

    da_regra = [categorias.get("testemunha", "SEM_INCREMENTO")] + [
        categoria for papel, categoria in alertados if papel not in PAPEIS_DE_ANDAIME
    ]
    de_andaime = [categoria for papel, categoria in alertados if papel in PAPEIS_DE_ANDAIME]

    if any(c == "P4_NO_MATCH" for c in da_regra):
        return "VIOLACAO"
    # Categoria fora das tres que o contador conhece: SEM_INCREMENTO, AMBIGUO
    # ou NAO_OBSERVADO. Nao da para julgar, e P4_NO_MATCH NAO entra aqui: ele e
    # categoria valida, e em quadro de andaime decide DEPENDENCIA_DE_ESTADO.
    validas = ("P4_CANDIDATE", "P4_NO_MATCH", "PACKET_DOMAIN_FALLBACK")
    if any(c not in validas for c in da_regra + de_andaime):
        return "INDETERMINADO"
    if any(c == "P4_NO_MATCH" for c in de_andaime):
        return "DEPENDENCIA_DE_ESTADO"
    if any(c == "PACKET_DOMAIN_FALLBACK" for c in da_regra + de_andaime):
        return "CONSERVADOR"
    return "CONFIRMADO"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--casos",
        default="output/campaign/e2e_1000",
        help="diretorio gerado por generate_campaign_cases.py",
    )
    parser.add_argument("--interface", default="veth1")
    parser.add_argument("--intervalo", type=float, default=0.10)
    parser.add_argument("--endereco", default="127.0.0.1:9559")
    parser.add_argument("--device-id", type=int, default=0)
    parser.add_argument(
        "--raiz-snort",
        default=None,
        help="diretorio da instalacao do Snort (padrao: ~/snort3-install do "
        "usuario que chamou, mesmo sob sudo)",
    )
    parser.add_argument(
        "--plano",
        default=None,
        help="p4runtime_install_plan alternativo contra o qual a tabela instalada "
        "e verificada (padrao: o da raiz)",
    )
    parser.add_argument(
        "--particao",
        default=None,
        help="particao.json de politica operacional; regras em fallback viram "
        "FALLBACK_OPERACIONAL em vez de CONFIRMADO ou VIOLACAO",
    )
    parser.add_argument(
        "--sufixo",
        default="",
        help="sufixo dos arquivos de saida, para nao sobrescrever outra rodada "
        "sobre o mesmo pcap",
    )
    parser.add_argument("--pular-snort", action="store_true")
    parser.add_argument("--pular-bmv2", action="store_true")
    argumentos = parser.parse_args()

    destino = (PROJECT_ROOT / argumentos.casos).resolve()
    caminho_casos = destino / "casos.jsonl"
    caminho_pcap = destino / "campanha.pcap"

    if not caminho_casos.exists() or not caminho_pcap.exists():
        print(
            f"entrada ausente em {destino}\n"
            "gere primeiro: python tests/generate_campaign_cases.py --n 1000",
            file=sys.stderr,
        )
        return 1

    casos = [
        json.loads(linha)
        for linha in caminho_casos.read_text(encoding="utf-8").splitlines()
        if linha.strip()
    ]
    quadros = ler_pcap(caminho_pcap)

    plano = (PROJECT_ROOT / argumentos.plano).resolve() if argumentos.plano else None
    fallback_operacional: set[str] = set()
    if argumentos.particao:
        particao = json.loads(
            (PROJECT_ROOT / argumentos.particao).resolve().read_text(encoding="utf-8")
        )
        fallback_operacional = set(particao["sids_fallback_operacional"])

    esperados = sum(len(caso["quadros"]) for caso in casos)
    if esperados != len(quadros):
        print(
            f"pcap tem {len(quadros)} quadros e casos.jsonl descreve {esperados}: "
            "artefatos de geracoes diferentes",
            file=sys.stderr,
        )
        return 1

    print(f"campanha             {destino.name}")
    print(f"casos                {len(casos)}")
    print(f"quadros              {len(quadros)}")

    # ---- Snort
    por_pacote: dict[int, set[str]] = {}
    por_marca: dict[str, set[str]] = {}
    if not argumentos.pular_snort:
        print("\n[1/3] Snort sobre o pcap da campanha")
        alertas = rodar_snort(
            caminho_pcap,
            destino,
            Path(argumentos.raiz_snort) if argumentos.raiz_snort else None,
            argumentos.sufixo,
        )
        por_pacote, por_marca = indexar_alertas(alertas)
        print(
            f"  alertas indexados: {sum(len(v) for v in por_pacote.values())} "
            f"em {len(por_pacote)} pacote(s)"
        )
    else:
        print("\n[1/3] Snort pulado por opcao")

    # ---- BMv2
    categorias: list[str] = []
    if not argumentos.pular_bmv2:
        print("\n[2/3] BMv2: um quadro por vez, com leitura de contador")
        categorias = classificar_quadros(
            quadros,
            argumentos.interface,
            argumentos.intervalo,
            argumentos.endereco,
            argumentos.device_id,
            plano,
        )
    else:
        print("\n[2/3] BMv2 pulado por opcao")
        categorias = ["NAO_OBSERVADO"] * len(quadros)

    # ---- Veredito
    print("\n[3/3] veredito por caso")

    posicao = 0
    resultados = []
    contagem = Counter()
    categoria_por_papel = Counter()
    divergencia_de_atribuicao = 0

    for caso in casos:
        papeis = {}
        for quadro in caso["quadros"]:
            papel = quadro["papel"]
            observado = categorias[posicao]
            quadro["pkt_num"] = posicao + 1
            if papel not in ("handshake", "aquecimento", "resposta_servidor", "flush"):
                papeis[papel] = observado
                categoria_por_papel[(papel, observado)] += 1
                quadro["p4_observado"] = observado
            posicao += 1

        # Atribuicao pela FAIXA de quadros do caso, e nao pelo pkt_num exato
        # da testemunha: a inspecao de request HTTP so acontece quando a
        # mensagem e descarregada, e o Snort atribui o alerta ao pacote que
        # provoca o flush — o ACK seguinte, nao o request. Como cada caso
        # ocupa um bloco contiguo de quadros e um segundo proprio, a faixa
        # atribui sem ambiguidade. O timestamp confere.
        numeros = [q["pkt_num"] for q in caso["quadros"] if "pkt_num" in q]
        indice_testemunha = next(
            (q["pkt_num"] for q in caso["quadros"] if q["papel"] == "testemunha"),
            None,
        )
        sid = str(caso["sid"])
        alertou_por_pacote = any(
            sid in por_pacote.get(numero, set())
            for numero in range(min(numeros), max(numeros) + 1)
        ) if numeros else False
        alertou_por_marca = sid in por_marca.get(marca_do_caso(caso["ts_s"]), set())
        if alertou_por_pacote != alertou_por_marca:
            divergencia_de_atribuicao += 1

        alertou = alertou_por_pacote or alertou_por_marca

        # Quadros em que o Snort alertou este sid, e a categoria P4 de cada.
        alertados = [
            numero
            for numero in (range(min(numeros), max(numeros) + 1) if numeros else [])
            if sid in por_pacote.get(numero, set())
        ]
        papel_por_numero = {q["pkt_num"]: q["papel"] for q in caso["quadros"]}
        categorias_alertadas = [categorias[numero - 1] for numero in alertados]
        papeis_alertados = [papel_por_numero[numero] for numero in alertados]

        veredito = veredito_do_caso(
            papeis,
            alertou,
            list(zip(papeis_alertados, categorias_alertadas)),
            sid in fallback_operacional,
        )
        contagem[veredito] += 1

        resultados.append(
            {
                "indice": caso["indice"],
                "sid": sid,
                "estrato": caso["estrato"],
                "veredito": veredito,
                "snort_alertou": alertou,
                "pkt_num_testemunha": indice_testemunha,
                "pkt_num_alertados": alertados,
                "p4_nos_alertados": categorias_alertadas,
                "papeis_alertados": papeis_alertados,
                "fallback_operacional": sid in fallback_operacional,
                "atribuicao": {
                    "por_pkt_num": alertou_por_pacote,
                    "por_timestamp": alertou_por_marca,
                },
                "p4_por_papel": papeis,
                "esperado": caso["esperado"],
            }
        )

    caminho_resultado = destino / f"resultado{argumentos.sufixo}.jsonl"
    with open(caminho_resultado, "w", encoding="utf-8", newline="\n") as saida:
        for registro in resultados:
            saida.write(json.dumps(registro, ensure_ascii=False, sort_keys=True) + "\n")

    # Taxas so sobre o dominio suportado, com o fallback reportado a parte:
    # colapsar fallback em no-match superestima a seletividade.
    testemunhas = Counter(
        observado for (papel, observado) in categoria_por_papel.elements() if papel == "testemunha"
    )
    negativos_payload = Counter(
        observado
        for (papel, observado) in categoria_por_papel.elements()
        if papel == "negativo_payload"
    )
    negativos_header = Counter(
        observado
        for (papel, observado) in categoria_por_papel.elements()
        if papel == "negativo_header"
    )

    def taxa(contagens: Counter, nome: str) -> float | None:
        dominio = contagens["P4_CANDIDATE"] + contagens["P4_NO_MATCH"]
        if dominio == 0:
            return None
        return round(contagens[nome] / dominio, 6)

    relatorio = {
        "gerado_em": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "campanha": destino.name,
        "casos": len(casos),
        "quadros": len(quadros),
        "vereditos": dict(contagem),
        "efetivos": contagem["CONFIRMADO"] + contagem["CONSERVADOR"] + contagem["VIOLACAO"],
        "fallback_operacional": contagem["FALLBACK_OPERACIONAL"],
        "dependencia_de_estado": contagem["DEPENDENCIA_DE_ESTADO"],
        "plano": str(plano.relative_to(PROJECT_ROOT)).replace("\\", "/") if plano else None,
        "particao": argumentos.particao,
        "vacuos": contagem["VACUO"],
        "divergencia_de_atribuicao": divergencia_de_atribuicao,
        "testemunha": {
            "categorias": dict(testemunhas),
            "taxa_candidato_dominio_suportado": taxa(testemunhas, "P4_CANDIDATE"),
        },
        "negativo_payload": {
            "categorias": dict(negativos_payload),
            "taxa_candidato_dominio_suportado": taxa(negativos_payload, "P4_CANDIDATE"),
            "nota": "candidate sem alerta e o excesso conservador do prefilter",
        },
        "negativo_header": {
            "categorias": dict(negativos_header),
            "taxa_no_match_dominio_suportado": taxa(negativos_header, "P4_NO_MATCH"),
        },
        "parametros": {
            "interface": argumentos.interface,
            "intervalo": argumentos.intervalo,
            "endereco": argumentos.endereco,
            "device_id": argumentos.device_id,
            "snort_executado": not argumentos.pular_snort,
            "bmv2_executado": not argumentos.pular_bmv2,
        },
    }

    caminho_relatorio = destino / f"relatorio{argumentos.sufixo}.json"
    caminho_relatorio.write_text(
        json.dumps(relatorio, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )

    print()
    for veredito in (
        "CONFIRMADO",
        "CONSERVADOR",
        "VIOLACAO",
        "DEPENDENCIA_DE_ESTADO",
        "FALLBACK_OPERACIONAL",
        "VACUO",
        "INDETERMINADO",
    ):
        if contagem[veredito]:
            print(f"  {contagem[veredito]:5d}  {veredito}")

    print(f"\n  efetivos {relatorio['efetivos']} | vacuos {relatorio['vacuos']}")
    if divergencia_de_atribuicao:
        print(
            f"  atencao: {divergencia_de_atribuicao} caso(s) com atribuicao "
            "divergente entre pkt_num e timestamp"
        )
    print(f"\n  resultado  {caminho_resultado.relative_to(PROJECT_ROOT)}")
    print(f"  relatorio  {caminho_relatorio.relative_to(PROJECT_ROOT)}")

    if contagem["VIOLACAO"]:
        print(
            f"\nCAMPANHA REPROVADA: {contagem['VIOLACAO']} violacao(oes) da "
            "propriedade conservadora.",
            file=sys.stderr,
        )
        return 1

    print("\nCAMPANHA SEM VIOLACAO.")
    if contagem["VACUO"]:
        print(
            f"Atencao: {contagem['VACUO']} caso(s) vacuo(s); isso nao e o "
            "mesmo que confirmar."
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())

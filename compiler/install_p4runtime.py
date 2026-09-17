import argparse
import json
import queue
import sys
import time

from pathlib import Path

import grpc

from google.protobuf import text_format

from p4.v1 import p4runtime_pb2
from p4.v1 import p4runtime_pb2_grpc
from p4.config.v1 import p4info_pb2


# ============================================================
# Configuration
# ============================================================


PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parents[1]
)


INSTALL_PLAN_FILE = (
    PROJECT_ROOT
    / "output"
    / "p4runtime_install_plan.json"
)


P4INFO_FILE = (
    PROJECT_ROOT
    / "output"
    / "ids_prefilter.p4info.txt"
)


DEVICE_CONFIG_FILE = (
    PROJECT_ROOT
    / "output"
    / "ids_prefilter.json"
)


GRPC_ADDRESS = "127.0.0.1:9559"

DEVICE_ID = 0


# Election ID used for P4Runtime mastership.
ELECTION_ID_HIGH = 0
ELECTION_ID_LOW = 1


# ============================================================
# Utilities
# ============================================================


def load_json(path):

    with open(
        path,
        "r",
        encoding="utf-8",
    ) as file:

        return json.load(
            file
        )


def load_p4info(path):

    p4info = (
        p4info_pb2.P4Info()
    )

    text = path.read_text(
        encoding="utf-8",
        errors="ignore",
    )

    text_format.Merge(
        text,
        p4info,
    )

    return p4info


def election_id():

    return p4runtime_pb2.Uint128(
        high=ELECTION_ID_HIGH,
        low=ELECTION_ID_LOW,
    )


# ============================================================
# StreamChannel / master arbitration
# ============================================================


class StreamRequestIterator:

    def __init__(self):

        self.requests = (
            queue.Queue()
        )

    def put(
        self,
        request,
    ):

        self.requests.put(
            request
        )

    def close(self):

        self.requests.put(
            None
        )

    def __iter__(self):

        return self

    def __next__(self):

        request = (
            self.requests.get()
        )

        if request is None:

            raise StopIteration

        return request


def establish_mastership(
    stub
):
    """
    Open the P4Runtime StreamChannel and become primary
    controller for DEVICE_ID.
    """

    request_iterator = (
        StreamRequestIterator()
    )

    stream = stub.StreamChannel(
        iter(
            request_iterator
        )
    )

    arbitration_request = (
        p4runtime_pb2
        .StreamMessageRequest()
    )

    arbitration_request.arbitration.device_id = (
        DEVICE_ID
    )

    arbitration_request.arbitration.election_id.CopyFrom(
        election_id()
    )

    request_iterator.put(
        arbitration_request
    )

    try:

        response = next(
            stream
        )

    except Exception as error:

        request_iterator.close()

        raise RuntimeError(
            "Failed to receive P4Runtime "
            "arbitration response"
        ) from error

    if not response.HasField(
        "arbitration"
    ):

        request_iterator.close()

        raise RuntimeError(
            "First StreamChannel response "
            "was not arbitration"
        )

    arbitration = (
        response.arbitration
    )

    status = arbitration.status

    if status.code != 0:

        request_iterator.close()

        raise RuntimeError(
            "Controller did not obtain "
            "P4Runtime mastership: "
            f"code={status.code}, "
            f"message={status.message}"
        )

    print(
        "Master arbitration      : OK"
    )

    return (
        request_iterator,
        stream,
    )


# ============================================================
# Pipeline configuration
# ============================================================


def set_pipeline(
    stub,
    p4info,
    device_config_path,
):
    """
    Install the compiled P4 pipeline into BMv2.
    """

    request = (
        p4runtime_pb2
        .SetForwardingPipelineConfigRequest()
    )

    request.device_id = (
        DEVICE_ID
    )

    request.election_id.CopyFrom(
        election_id()
    )

    request.action = (
        p4runtime_pb2
        .SetForwardingPipelineConfigRequest
        .VERIFY_AND_COMMIT
    )

    request.config.p4info.CopyFrom(
        p4info
    )

    request.config.p4_device_config = (
        device_config_path
        .read_bytes()
    )

    stub.SetForwardingPipelineConfig(
        request
    )

    print(
        "Pipeline configuration  : OK"
    )


# ============================================================
# P4Runtime TableEntry construction
# ============================================================


def hex_to_bytes(
    value
):
    return bytes.fromhex(
        value
    )


def build_table_entry(
    plan_entry
):
    """
    Convert one JSON install-plan entry into a real
    P4Runtime TableEntry protobuf.
    """

    table_info = (
        plan_entry[
            "table"
        ]
    )

    action_info = (
        plan_entry[
            "action"
        ]
    )

    entry = (
        p4runtime_pb2
        .TableEntry()
    )

    entry.table_id = int(
        table_info[
            "id"
        ]
    )

    entry.priority = int(
        plan_entry[
            "priority"
        ]
    )

    # --------------------------------------------------------
    # Match fields
    # --------------------------------------------------------

    for field in plan_entry.get(
        "match",
        [],
    ):

        field_match = (
            entry.match.add()
        )

        field_match.field_id = int(
            field[
                "field_id"
            ]
        )

        ternary = field[
            "ternary"
        ]

        field_match.ternary.value = (
            hex_to_bytes(
                ternary[
                    "value_hex"
                ]
            )
        )

        field_match.ternary.mask = (
            hex_to_bytes(
                ternary[
                    "mask_hex"
                ]
            )
        )

    # --------------------------------------------------------
    # Action
    # --------------------------------------------------------

    entry.action.action.action_id = int(
        action_info[
            "id"
        ]
    )

    return entry


# ============================================================
# Write
# ============================================================


def write_entries(
    stub,
    plan_entries,
):
    """
    Install all generated table entries using one WriteRequest.

    With 331 entries this is small enough for the BMv2
    prototype and keeps the test simple and deterministic.
    """

    request = (
        p4runtime_pb2
        .WriteRequest()
    )

    request.device_id = (
        DEVICE_ID
    )

    request.election_id.CopyFrom(
        election_id()
    )

    request.atomicity = (
        p4runtime_pb2
        .WriteRequest
        .CONTINUE_ON_ERROR
    )

    for plan_entry in (
        plan_entries
    ):

        update = (
            request.updates.add()
        )

        update.type = (
            p4runtime_pb2
            .Update
            .INSERT
        )

        table_entry = (
            build_table_entry(
                plan_entry
            )
        )

        update.entity.table_entry.CopyFrom(
            table_entry
        )

    stub.Write(
        request
    )

    print(
        f"WriteRequest entries    : "
        f"{len(plan_entries)}"
    )


# ============================================================
# Read table
# ============================================================


def read_table_entries(
    stub,
    table_id,
):
    """
    Read every entry currently installed in the target table.
    """

    request = (
        p4runtime_pb2
        .ReadRequest()
    )

    request.device_id = (
        DEVICE_ID
    )

    entity = (
        request.entities.add()
    )

    entity.table_entry.table_id = (
        int(
            table_id
        )
    )

    responses = stub.Read(
        request
    )

    entries = []

    for response in responses:

        for entity in (
            response.entities
        ):

            if entity.HasField(
                "table_entry"
            ):

                entries.append(
                    entity.table_entry
                )

    return entries


# ============================================================
# gRPC error display
# ============================================================


def print_grpc_error(
    error
):
    print()

    print(
        "P4Runtime gRPC ERROR"
    )

    print(
        "=" * 70
    )

    try:

        print(
            f"Status  : "
            f"{error.code()}"
        )

        print(
            f"Details : "
            f"{error.details()}"
        )

    except Exception:

        print(
            repr(
                error
            )
        )


# ============================================================
# Main
# ============================================================


def rotulo_do_plano():
    """Caminho do plano relativo a raiz, para identificar o perfil.

    O nome do arquivo e o mesmo em todos os perfis; o que distingue e o
    diretorio. Imprimir so o nome nao diria nada.
    """

    try:
        return str(
            INSTALL_PLAN_FILE.resolve().relative_to(
                PROJECT_ROOT
            )
        )
    except ValueError:
        return str(INSTALL_PLAN_FILE)


def analisa_argumentos():
    """Le a linha de comando.

    O padrao continua sendo o plano na raiz de output/, para nao mudar o
    comportamento de quem ja chamava o script sem argumento.
    """

    analisador = argparse.ArgumentParser(
        description=(
            "Instala as entradas da tabela "
            "de prefiltro no alvo BMv2 via "
            "P4Runtime."
        )
    )

    analisador.add_argument(
        "--plan",
        type=Path,
        default=INSTALL_PLAN_FILE,
        help=(
            "plano de instalacao a usar. "
            "Padrao: output/"
            "p4runtime_install_plan.json. "
            "Para um perfil especifico: "
            "output/profiles/<perfil>/"
            "artifacts/"
            "p4runtime_install_plan.json"
        ),
    )

    analisador.add_argument(
        "--address",
        default=GRPC_ADDRESS,
        help=(
            "endereco do servidor P4Runtime "
            f"(padrao: {GRPC_ADDRESS})"
        ),
    )

    return analisador.parse_args()


def main():

    global INSTALL_PLAN_FILE
    global GRPC_ADDRESS

    argumentos = analisa_argumentos()

    INSTALL_PLAN_FILE = argumentos.plan
    GRPC_ADDRESS = argumentos.address

    print()
    print(
        "=== P4Runtime BMv2 Installation ==="
    )
    print()

    # --------------------------------------------------------
    # Files
    # --------------------------------------------------------

    required_files = [
        INSTALL_PLAN_FILE,
        P4INFO_FILE,
        DEVICE_CONFIG_FILE,
    ]

    for path in required_files:

        if not path.exists():

            print(
                "ERROR: Missing file:"
            )

            print(
                path
            )

            sys.exit(
                1
            )

    plan = load_json(
        INSTALL_PLAN_FILE
    )

    plan_entries = (
        plan.get(
            "entries",
            [],
        )
    )

    if not plan_entries:

        print(
            "ERROR: Install plan "
            "contains no entries."
        )

        sys.exit(
            1
        )

    table_id = (
        plan[
            "table"
        ][
            "id"
        ]
    )

    print(
        f"Plan                   : "
        f"{rotulo_do_plano()}"
    )

    print(
        f"Target                 : "
        f"{GRPC_ADDRESS}"
    )

    print(
        f"Device ID              : "
        f"{DEVICE_ID}"
    )

    print(
        f"Planned entries        : "
        f"{len(plan_entries)}"
    )

    print(
        f"Table ID               : "
        f"{table_id}"
    )

    print()

    # --------------------------------------------------------
    # P4Info
    # --------------------------------------------------------

    p4info = load_p4info(
        P4INFO_FILE
    )

    # --------------------------------------------------------
    # Connect
    # --------------------------------------------------------

    channel = grpc.insecure_channel(
        GRPC_ADDRESS
    )

    try:

        grpc.channel_ready_future(
            channel
        ).result(
            timeout=5
        )

    except grpc.FutureTimeoutError:

        print(
            "ERROR: Could not connect "
            f"to {GRPC_ADDRESS}"
        )

        print(
            "Is simple_switch_grpc running?"
        )

        sys.exit(
            1
        )

    print(
        "gRPC connection         : OK"
    )

    stub = (
        p4runtime_pb2_grpc
        .P4RuntimeStub(
            channel
        )
    )

    request_iterator = None
    stream = None

    try:

        # ----------------------------------------------------
        # Mastership
        # ----------------------------------------------------

        (
            request_iterator,
            stream,
        ) = establish_mastership(
            stub
        )

        # ----------------------------------------------------
        # Pipeline
        # ----------------------------------------------------

        set_pipeline(
            stub,
            p4info,
            DEVICE_CONFIG_FILE,
        )

        # Give BMv2 a brief moment after pipeline commit.
        time.sleep(
            0.5
        )

        # ----------------------------------------------------
        # Write 331 entries
        # ----------------------------------------------------

        write_entries(
            stub,
            plan_entries,
        )

        # ----------------------------------------------------
        # Read back
        # ----------------------------------------------------

        installed_entries = (
            read_table_entries(
                stub,
                table_id,
            )
        )

        installed_count = len(
            installed_entries
        )

        expected_count = len(
            plan_entries
        )

        print(
            f"Entries read back       : "
            f"{installed_count}"
        )

        print()

        if installed_count == expected_count:

            print(
                "Installation status     : VALID"
            )

        else:

            print(
                "Installation status     : "
                "COUNT_MISMATCH"
            )

            print(
                f"Expected                : "
                f"{expected_count}"
            )

            print(
                f"Observed                : "
                f"{installed_count}"
            )

        print()

        print(
            "P4Runtime installation complete."
        )

    except grpc.RpcError as error:

        print_grpc_error(
            error
        )

        sys.exit(
            1
        )

    except Exception as error:

        print()
        print(
            "ERROR"
        )
        print(
            "=" * 70
        )

        print(
            repr(
                error
            )
        )

        sys.exit(
            1
        )

    finally:

        if request_iterator is not None:

            request_iterator.close()

        channel.close()


if __name__ == "__main__":
    main()
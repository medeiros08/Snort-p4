import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
COMPILER_DIR = PROJECT_ROOT / "compiler"

sys.path.insert(
    0,
    str(COMPILER_DIR)
)


from variable_resolver import resolve_value


VARIABLES = {
    "HTTP_PORTS": [
        80,
        8080,
    ],

    "HOME_NET": (
        "10.0.0.0/24"
    ),
}


def test_complete_variable():
    value, changed = resolve_value(
        "$HOME_NET",
        VARIABLES,
    )

    assert changed is True

    assert (
        value
        == "10.0.0.0/24"
    )


def test_port_variable():
    value, changed = resolve_value(
        "$HTTP_PORTS",
        VARIABLES,
    )

    assert changed is True

    assert value == [
        80,
        8080,
    ]


def test_variable_inside_list():
    value, changed = resolve_value(
        "[$HTTP_PORTS,443]",
        VARIABLES,
    )

    assert changed is True

    assert value == [
        80,
        8080,
        443,
    ]


def test_variable_inside_larger_list():
    value, changed = resolve_value(
        (
            "[$HTTP_PORTS,"
            "3000,5156,7218]"
        ),
        VARIABLES,
    )

    assert changed is True

    assert value == [
        80,
        8080,
        3000,
        5156,
        7218,
    ]


def test_unknown_variable_inside_list():
    value, changed = resolve_value(
        "[$UNKNOWN_PORTS,443]",
        VARIABLES,
    )

    assert changed is False

    assert value == [
        "$UNKNOWN_PORTS",
        443,
    ]


if __name__ == "__main__":

    test_complete_variable()

    test_port_variable()

    test_variable_inside_list()

    test_variable_inside_larger_list()

    test_unknown_variable_inside_list()

    print(
        "Nested variable resolution tests passed."
    )
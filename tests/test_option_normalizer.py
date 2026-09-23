import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
COMPILER_DIR = PROJECT_ROOT / "compiler"

sys.path.insert(
    0,
    str(COMPILER_DIR)
)


from option_normalizer import normalize_content


def test_simple_content():
    result = normalize_content(
        "USER root"
    )

    assert result["pattern"] == "USER root"
    assert result["negated"] is False
    assert result["modifiers"] == []


def test_content_with_nocase():
    result = normalize_content(
        'USER",nocase'
    )

    assert result["pattern"] == "USER"

    assert (
        result["modifiers"][0]["name"]
        == "nocase"
    )

    assert (
        result["modifiers"][0]["value"]
        is True
    )


def test_depth_offset():
    result = normalize_content(
        '|81 80|",depth 4,offset 2'
    )

    assert result["pattern"] == "|81 80|"

    modifiers = {
        item["name"]: item["value"]
        for item in result["modifiers"]
    }

    assert modifiers["depth"] == 4
    assert modifiers["offset"] == 2


def test_relative_content():
    result = normalize_content(
        '!"|00|",within 100,distance 2'
    )

    assert result["negated"] is True
    assert result["pattern"] == "|00|"

    modifiers = {
        item["name"]: item["value"]
        for item in result["modifiers"]
    }

    assert modifiers["within"] == 100
    assert modifiers["distance"] == 2


def test_fast_pattern():
    result = normalize_content(
        '1234",fast_pattern,nocase'
    )

    modifiers = {
        item["name"]: item["value"]
        for item in result["modifiers"]
    }

    assert modifiers["fast_pattern"] is True
    assert modifiers["nocase"] is True


def test_fast_pattern_window():
    result = normalize_content(
        'abcdefghij",fast_pattern_offset 2,fast_pattern_length 5'
    )

    modifiers = {
        item["name"]: item["value"]
        for item in result["modifiers"]
    }

    assert modifiers[
        "fast_pattern_offset"
    ] == 2

    assert modifiers[
        "fast_pattern_length"
    ] == 5


def test_comma_inside_content():
    result = normalize_content(
        'Cinco Network, Inc.",depth 32'
    )

    assert (
        result["pattern"]
        == "Cinco Network, Inc."
    )

    assert (
        result["modifiers"][0]["name"]
        == "depth"
    )

    assert (
        result["modifiers"][0]["value"]
        == 32
    )


def test_whitespace_inside_quotes_is_content():
    # O parser ja tirou o espaco de fora das aspas; o que sobra e conteudo.
    # A campanha e2e mostrou o efeito: com o espaco cortado, a testemunha de
    # sid 1789 saiu `USERHOST` e o Snort, que exige `USERHOST `, nao alertou.
    sem_modificador = normalize_content(
        "USERHOST "
    )
    assert sem_modificador["pattern"] == "USERHOST "

    inicial_com_modificador = normalize_content(
        ' |3A|.DCC SEND",distance 0,fast_pattern,nocase'
    )
    assert (
        inicial_com_modificador["pattern"]
        == " |3A|.DCC SEND"
    )

    dos_dois_lados = normalize_content(
        ' 302 '
    )
    assert dos_dois_lados["pattern"] == " 302 "

    negado = normalize_content(
        '!" abc ",depth 5'
    )
    assert negado["pattern"] == " abc "
    assert negado["negated"] is True


def test_bang_inside_quotes_is_content():
    # `!` fora das aspas e negacao; dentro delas e conteudo. Na campanha e2e
    # a regra 28982 (`content:"!dl http://"`) saiu com o content negado na
    # IR, a testemunha nao o carregou e o Snort nao alertou.
    literal = normalize_content(
        '!dl http://",fast_pattern,nocase'
    )
    assert literal["pattern"] == "!dl http://"
    assert literal["negated"] is False

    literal_sem_modificador = normalize_content(
        "!@|23|"
    )
    assert literal_sem_modificador["pattern"] == "!@|23|"
    assert literal_sem_modificador["negated"] is False

    negado = normalize_content(
        '!"|00|",within 100'
    )
    assert negado["pattern"] == "|00|"
    assert negado["negated"] is True

    negado_sem_modificador = normalize_content(
        '!"Accept'
    )
    assert negado_sem_modificador["pattern"] == "Accept"
    assert negado_sem_modificador["negated"] is True


if __name__ == "__main__":

    test_simple_content()
    test_whitespace_inside_quotes_is_content()
    test_bang_inside_quotes_is_content()
    test_content_with_nocase()
    test_depth_offset()
    test_relative_content()
    test_fast_pattern()
    test_fast_pattern_window()
    test_comma_inside_content()

    print(
        "Option normalizer tests passed."
    )
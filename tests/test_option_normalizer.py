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


if __name__ == "__main__":

    test_simple_content()
    test_content_with_nocase()
    test_depth_offset()
    test_relative_content()
    test_fast_pattern()
    test_fast_pattern_window()
    test_comma_inside_content()

    print(
        "Option normalizer tests passed."
    )
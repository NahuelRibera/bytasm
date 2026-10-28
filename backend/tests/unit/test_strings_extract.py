"""The built-in strings extractor and the parent's validation of its result.

Inputs are bytes written in these tests or Bytasm's committed fixtures. The
extractor only matches byte patterns; nothing is executed.
"""

import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from conftest import ALL_FIXTURES, ELF_X86_64, PE_X86_64_EXE

from bytasm.adapters.strings_extract import extract
from bytasm.adapters.strings_result import MAX_CHARS, MAX_STRINGS, MIN_LENGTH
from bytasm.jobs.strings_step import parse_strings_result, strings_are_consistent
from bytasm.runner.child import EXIT_INPUT_MISMATCH
from bytasm.runner.limits import DEFAULT_LIMITS, MAX_INPUT_BYTES


def values(result: dict[str, Any]) -> list[tuple[int, str, str]]:
    return [(s["offset"], s["encoding"], s["value"]) for s in result["strings"]]


def test_ascii_strings_with_exact_offsets() -> None:
    data = b"\x00\x01hello world\x00\xffbytasm!\x02"
    result = extract(data)
    assert values(result) == [(2, "ascii", "hello world"), (15, "ascii", "bytasm!")]
    first = result["strings"][0]
    assert first["length_chars"] == first["byte_length"] == 11
    assert data[2:13] == b"hello world"


def test_utf16le_strings_with_exact_offsets() -> None:
    wide = "Wide text 42".encode("utf-16le")
    data = b"\x90\x91\x92" + wide + b"\x00\x00\x93"
    result = extract(data)
    assert values(result) == [(3, "utf-16le", "Wide text 42")]
    item = result["strings"][0]
    assert item["length_chars"] == 12 and item["byte_length"] == 24
    assert data[3 : 3 + 24].decode("utf-16le") == "Wide text 42"


def test_utf16le_strings_are_found_at_odd_offsets() -> None:
    data = b"\x01" + "odd-aligned".encode("utf-16le")
    assert values(extract(data)) == [(1, "utf-16le", "odd-aligned")]


def test_minimum_length_is_six_characters() -> None:
    assert MIN_LENGTH == 6
    data = b"\x00abcde\x00abcdef\x01" + "abcde".encode("utf-16le") + b"\x01\x01"
    data += "abcdef".encode("utf-16le")
    assert values(extract(data)) == [
        (7, "ascii", "abcdef"),
        (26, "utf-16le", "abcdef"),
    ]


def test_tabs_are_printable_and_other_control_or_high_bytes_end_a_run() -> None:
    data = b"col1\tcol2\nline-two-x\rcarriage\x7fdelete-me\xe9accented-text"
    assert values(extract(data)) == [
        (0, "ascii", "col1\tcol2"),
        (10, "ascii", "line-two-x"),
        (21, "ascii", "carriage"),
        (30, "ascii", "delete-me"),
        (40, "ascii", "accented-text"),
    ]


def test_utf16_text_outside_ascii_is_not_extracted() -> None:
    data = "ñandú-pájaro".encode("utf-16le") + b"\x00\x00" + "日本語のテキスト".encode("utf-16le")
    result = extract(data)
    assert result["strings"] == [] or all(s["encoding"] == "utf-16le" for s in result["strings"])
    # Only runs of >= 6 ASCII code units could match; none exist here.
    assert result["total_found"] == 0


def test_encodings_are_searched_independently() -> None:
    # An ASCII run followed by NUL bytes can also start a UTF-16LE run.
    data = b"\x01abcdefg\x00" + "hijklm".encode("utf-16le") + b"\x01"
    assert values(extract(data)) == [
        (1, "ascii", "abcdefg"),
        (7, "utf-16le", "ghijklm"),
    ]


def test_empty_input_and_no_strings() -> None:
    for data in (b"", bytes(range(0, 32)) * 4, b"\xff" * 100):
        result = extract(data)
        assert result["strings"] == [] and result["total_found"] == 0
        assert result["truncated"] is False


def test_long_values_are_cut_but_their_length_is_reported() -> None:
    data = b"A" * (MAX_CHARS + 50)
    (item,) = extract(data)["strings"]
    assert item["value"] == "A" * MAX_CHARS
    assert item["value_truncated"] is True
    assert item["length_chars"] == item["byte_length"] == MAX_CHARS + 50


def test_number_of_strings_is_capped_and_the_total_still_counted() -> None:
    data = b"\x00".join(b"str%05d" % i for i in range(30)) + b"\x00"
    data += "wide-one".encode("utf-16le")
    result = extract(data, max_strings=10)
    assert len(result["strings"]) == 10
    assert result["total_found"] == 31
    assert result["found_by_encoding"] == {"ascii": 30, "utf-16le": 1}
    assert result["truncated"] is True
    # The first ten by offset are kept.
    assert [s["value"] for s in result["strings"]] == [f"str{i:05d}" for i in range(10)]


def test_order_is_by_offset_then_encoding_and_deterministic() -> None:
    data = b"zzzzzzzz\x01" + "middle".encode("utf-16le") + b"\x01aaaaaaaa"
    first = extract(data)
    assert [(s["offset"], s["encoding"]) for s in first["strings"]] == [
        (0, "ascii"),
        (9, "utf-16le"),
        (22, "ascii"),
    ]
    assert json.dumps(extract(data), sort_keys=True) == json.dumps(first, sort_keys=True)


@pytest.mark.parametrize("fixture", ALL_FIXTURES, ids=lambda p: p.name)
def test_every_extracted_string_is_what_the_file_holds(fixture: Path) -> None:
    data = fixture.read_bytes()
    result = extract(data)
    for item in result["strings"]:
        width = 1 if item["encoding"] == "ascii" else 2
        raw = data[item["offset"] : item["offset"] + item["byte_length"]]
        decoded = raw.decode("ascii") if width == 1 else raw.decode("utf-16le")
        assert decoded[:MAX_CHARS] == item["value"]
        assert len(decoded) == item["length_chars"] >= MIN_LENGTH
    assert result["total_found"] >= len(result["strings"])


def test_fixture_strings_include_the_known_text() -> None:
    ascii_values = [s["value"] for s in extract(ELF_X86_64.read_bytes())["strings"]]
    assert "bytasm fixture v1: https://example.invalid/help" in ascii_values
    pe = extract(PE_X86_64_EXE.read_bytes())
    assert any("cannot be run in DOS mode" in s["value"] for s in pe["strings"])


# --- the child process and the parent's validation ----------------------------


def run_child(tmp_path: Path, data: bytes, expected_sha256: str) -> tuple[int, Path]:
    (tmp_path / "upload.bin").write_bytes(data)
    out = tmp_path / "result.json"
    completed = subprocess.run(
        [
            sys.executable,
            "-I",
            "-m",
            "bytasm.adapters.strings_extract",
            "--input",
            "upload.bin",
            "--expected-sha256",
            expected_sha256,
            "--out",
            "result.json",
            "--max-input-bytes",
            str(MAX_INPUT_BYTES),
            "--min-length",
            str(MIN_LENGTH),
            "--max-strings",
            str(MAX_STRINGS),
            "--max-chars",
            str(MAX_CHARS),
            "--rlimit-as",
            str(DEFAULT_LIMITS.address_space_bytes),
            "--rlimit-cpu",
            str(DEFAULT_LIMITS.cpu_seconds),
            "--rlimit-fsize",
            str(DEFAULT_LIMITS.file_size_bytes),
        ],
        cwd=tmp_path,
        capture_output=True,
        timeout=60,
        check=False,
    )
    return completed.returncode, out


def test_child_refuses_bytes_that_do_not_match_the_admitted_hash(tmp_path: Path) -> None:
    data = ELF_X86_64.read_bytes()
    code, out = run_child(tmp_path, data, hashlib.sha256(b"something else").hexdigest())
    assert code == EXIT_INPUT_MISMATCH
    assert not out.exists()


def test_child_result_validates_and_matches_the_file(tmp_path: Path) -> None:
    data = ELF_X86_64.read_bytes()
    sha = hashlib.sha256(data).hexdigest()
    code, out = run_child(tmp_path, data, sha)
    assert code == 0
    result = parse_strings_result(out.read_bytes(), sha)
    assert result is not None and strings_are_consistent(result, data)
    # About other bytes, the same result is refused.
    assert parse_strings_result(out.read_bytes(), "0" * 64) is None
    assert not strings_are_consistent(result, data[:-1])


def _tampered(document: dict[str, Any], change: str) -> dict[str, Any]:
    items = document["strings"]
    if change == "value":
        items[0]["value"] = "X" + items[0]["value"][1:]
    elif change == "offset":
        items[0]["offset"] += 1
    elif change == "past_end":
        items[-1]["offset"] = document["input"]["size_bytes"]
    elif change == "order":
        items[0], items[1] = items[1], items[0]
    elif change == "length":
        items[0]["length_chars"] += 1
        items[0]["byte_length"] += 1
    elif change == "count":
        document["total_found"] += 1
    elif change == "truncated_flag":
        document["truncated"] = not document["truncated"]
    elif change == "extra_field":
        items[0]["suspicious"] = True
    elif change == "min_length":
        document["params"]["min_length"] = 4
    return document


@pytest.mark.parametrize(
    "change",
    [
        "value",
        "offset",
        "past_end",
        "order",
        "length",
        "count",
        "truncated_flag",
        "extra_field",
        "min_length",
    ],
)
def test_parent_rejects_any_result_that_does_not_match_the_file(
    tmp_path: Path, change: str
) -> None:
    data = ELF_X86_64.read_bytes()
    sha = hashlib.sha256(data).hexdigest()
    _, out = run_child(tmp_path, data, sha)
    document = _tampered(json.loads(out.read_bytes()), change)
    result = parse_strings_result(json.dumps(document).encode(), sha)
    assert result is None or not strings_are_consistent(result, data)


def test_large_input_stays_within_the_caps() -> None:
    # 4 MiB of short printable runs: far more strings than are kept.
    data = (b"abcdefgh\x00" * (4 * 1024 * 1024 // 9))[: 4 * 1024 * 1024]
    result = extract(data)
    assert len(result["strings"]) == MAX_STRINGS
    assert result["total_found"] == data.count(b"abcdefgh")
    assert result["truncated"] is True
    assert len(json.dumps(result)) < 2 * 1024 * 1024

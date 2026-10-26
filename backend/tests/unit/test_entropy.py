"""Entropy is checked against an independent implementation and known values."""

import math

import pytest
from conftest import independent_entropy

from bytasm.adapters.entropy import shannon_entropy


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        (b"\x00" * 1000, 0.0),
        (b"\x00\xff" * 500, 1.0),
        (bytes(range(4)) * 25, 2.0),
        (bytes(range(256)), 8.0),
        (bytes(range(256)) * 7, 8.0),
    ],
)
def test_known_values(data: bytes, expected: float) -> None:
    assert shannon_entropy(data) == expected


def test_matches_independent_implementation() -> None:
    samples = [b"bytasm", b"aab", bytes(range(200)) + b"x" * 300, b"\x01" * 3 + b"\x02"]
    for data in samples:
        assert shannon_entropy(data) == pytest.approx(independent_entropy(data), abs=1e-6)


def test_result_is_never_negative_zero() -> None:
    assert math.copysign(1.0, shannon_entropy(b"\x07" * 10)) == 1.0


def test_empty_data_is_rejected() -> None:
    with pytest.raises(ValueError):
        shannon_entropy(b"")

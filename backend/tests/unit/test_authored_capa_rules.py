"""Authored fixtures are API features, not executable or extractor fixtures."""

from pathlib import Path

import pytest

from bytasm.capa_rules import RULES_DIR, snapshot


@pytest.mark.parametrize(
    ("filename", "api"),
    [
        ("create-process.yml", "kernel32.CreateProcess"),
        ("send-http-request.yml", "winhttp.WinHttpSendRequest"),
        ("read-file.yml", "kernel32.ReadFile"),
        ("read-configuration.yml", "kernel32.GetPrivateProfileString"),
        ("load-library.yml", "kernel32.LoadLibrary"),
    ],
)
def test_authored_rule_positive_and_benign_negative(filename: str, api: str) -> None:
    import capa.engine  # type: ignore[import-untyped]
    import capa.rules  # type: ignore[import-untyped]
    from capa.features.address import AbsoluteVirtualAddress  # type: ignore[import-untyped]
    from capa.features.insn import API  # type: ignore[import-untyped]

    rule = capa.rules.Rule.from_yaml(Path(RULES_DIR, filename).read_text())
    address = AbsoluteVirtualAddress(0x1000)
    _, positive = capa.engine.match([rule], {API(api.split(".")[-1]): {address}}, address)
    assert rule.name in positive
    _, negative = capa.engine.match([rule], {API("kernel32.GetTickCount"): {address}}, address)
    assert rule.name not in negative
    assert snapshot()[0]


def test_authored_interpretations_are_bound_to_curated_digest() -> None:
    from bytasm.review import AUTHORED_CAPA, CAPA_CURATED_SHA, CAPA_SHA, explanation

    assert snapshot()[1] == CAPA_CURATED_SHA
    for name in AUTHORED_CAPA:
        assert (
            "There is no reviewed" not in explanation("capa", "10.0.0", name, CAPA_CURATED_SHA)[1]
        )
        assert "There is no reviewed" in explanation("capa", "10.0.0", name, CAPA_SHA)[1]
    for sha in (CAPA_SHA, CAPA_CURATED_SHA):
        assert (
            "There is no reviewed"
            not in explanation("capa", "10.0.0", "query environment variable", sha)[1]
        )

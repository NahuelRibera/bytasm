"""Fixed notices shown in the UI and included in every report (blueprint 2 J2, 8.2)."""

from typing import Final

AUTHORIZATION_NOTICE: Final = (
    "The authorisation statement is a self-attestation recorded for accountability. "
    "Bytasm does not verify it. It is not proof of permission and not a legal "
    "determination that the analysis is lawful."
)

INPUT_POLICY_NOTICE: Final = (
    "This version is for Bytasm's test fixtures and programs you compiled yourself from "
    "your own source. Do not import downloaded, received, third-party, or suspicious "
    "files. v0.1 has no isolation boundary for them, and a crafted file could exploit a "
    "parser bug. Bytasm never runs the files it imports."
)

REPORT_LIMITATIONS: Final = (
    "Static analysis only: Bytasm did not execute this file.",
    "Header values (architecture, entry point, timestamps, flags, declared_header) are "
    "what the file declares about itself. Bytasm does not verify them.",
    "Entropy is a descriptive measurement in bits per byte (0-8). It is not a verdict "
    "and does not by itself indicate packing, encryption, or malicious intent.",
    "This report contains no verdict, score, or claim that the file is safe or malicious.",
    "v0.1 accepts self-authored inputs only (Bytasm's fixtures, or the operator's own "
    "builds in the opt-in self_built mode). It is not suitable for third-party, "
    "downloaded, received, or suspicious files.",
    "The parser ran in a separate, resource-limited process. That is not a security sandbox.",
)

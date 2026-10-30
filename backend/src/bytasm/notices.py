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

# Shown next to every set of YARA-X findings, and with a run that matched
# nothing (blueprint 7.5, 10).
FINDING_NOTICES: Final = (
    "A match means a rule matched static features read from the file. It is an observation "
    "that needs human interpretation, not a conclusion.",
    "A match does not by itself show that a file is malicious, and Bytasm gives no verdict, "
    "score, or severity.",
    "No match does not show that a file is safe: it only means none of these rules matched.",
    "Bytasm inspected the stored bytes statically. It did not execute the file.",
)

# Shown with every list of extracted strings (blueprint 3.1, 6: strings are observations).
STRINGS_NOTICES: Final = (
    "Strings are runs of at least 6 printable ASCII characters, stored as ASCII or UTF-16LE "
    "in the file. They are observations, not findings: Bytasm does not label any string "
    "suspicious or meaningful.",
    "String values are untrusted text taken from the file. Each is shown as plain text and "
    "cut to its first 256 characters; at most 5,000 strings are kept per run.",
    "Bytasm read the stored bytes statically. It did not execute the file.",
)

# Added to a report's limitations when it includes an analysis run (v0.2).
PATTERN_REPORT_LIMITATIONS: Final = (
    "Pattern matches (YARA-X with Bytasm rules; capa with its attributed subset) need "
    "interpretation. A match is not a verdict, and no match does not show that the file "
    "is safe.",
    "Strings are listed as counts only in this report; the values stay in Bytasm.",
)

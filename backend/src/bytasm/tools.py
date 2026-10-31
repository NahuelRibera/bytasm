"""Read-only tool registry and built-in profile descriptions; never reads samples."""

from importlib.metadata import PackageNotFoundError, version

from bytasm import __version__
from bytasm.capa_rules import VERSION, snapshot
from bytasm.rules import RuleSetError, load_rule_set

PROFILES = [
    {
        "id": "default-static",
        "name": "Quick static review",
        "steps": ["strings", "yara-x"],
        "limitations": "Metadata was read at import. Does not run capa.",
    },
    {
        "id": "full-static",
        "name": "Full static review",
        "steps": ["strings", "yara-x", "capa"],
        "limitations": (
            "capa supports native PE x86/x64 only; other formats retain Quick "
            "results and a partial status."
        ),
    },
]


def installed(package: str) -> str | None:
    try:
        return version(package)
    except PackageNotFoundError:
        return None


def registry() -> list[dict[str, object]]:
    try:
        yara_sha = load_rule_set().sha256
    except (OSError, ValueError, RuleSetError):
        yara_sha = None
    try:
        _, capa_sha = snapshot()
    except (OSError, ValueError):
        capa_sha = None
    tools: list[dict[str, object]] = [
        {
            "tool": "lief",
            "version": installed("lief"),
            "adapter": "metadata_lief",
            "adapter_version": "0.1.0",
            "formats": ["PE", "ELF"],
            "rules_sha256": None,
            "limitations": "Declared headers, not verified claims. Runs during import.",
        },
        {
            "tool": "strings",
            "version": __version__,
            "adapter": "strings_extract",
            "adapter_version": "0.1.0",
            "formats": ["PE", "ELF"],
            "rules_sha256": None,
            "limitations": (
                "ASCII / ASCII-subset UTF-16LE, minimum 6 characters; 5,000 rows "
                "and 256 characters per value."
            ),
        },
        {
            "tool": "yara-x",
            "version": installed("yara-x"),
            "adapter": "yara_x_scan",
            "adapter_version": "0.1.0",
            "formats": ["PE", "ELF"],
            "rules_sha256": yara_sha,
            "limitations": (
                "Five descriptive bundled rules. No match does not establish absence of behavior."
            ),
        },
        {
            "tool": "capa",
            "version": installed("flare-capa"),
            "adapter": "capa_scan",
            "adapter_version": "0.1.0",
            "formats": ["PE x86", "PE x64"],
            "rules_sha256": capa_sha,
            "limitations": (
                "capa 10.0.0, two upstream and five Bytasm-authored rules, "
                "vivisect, no library signatures."
                " Packed files, installers and wrappers can produce incomplete or "
                "misleading results."
            ),
        },
    ]

    for tool in tools:
        tool["available"] = (
            tool["version"] is not None
            and (tool["tool"] != "capa" or tool["version"] == VERSION)
            and (tool["tool"] not in ("capa", "yara-x") or tool["rules_sha256"] is not None)
        )
    return tools

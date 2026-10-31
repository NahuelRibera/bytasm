"""Reviewed labels and reading order shared by live and pinned views.

Historical report views retain source-order-v1 and their original explanation
contract; only live run presentation opts in to this ranking.
"""

from bytasm.review import ReviewOut, explanation

# The score chooses reading order, never threat probability. Rules group by ID
# within one selected invocation: repeated matching locations add no weight.
DETAILS = {
    "query environment variable": (
        "Code refers to reading environment settings",
        "Configuration and environment",
        "Environment settings can select configuration or working directories.",
        "Ordinary programs read settings for locale, diagnostics and configuration.",
        30,
    ),
    "set environment variable": (
        "Code refers to changing environment settings",
        "Configuration and environment",
        "Environment settings can affect later operations and child processes.",
        "Build tools and installers commonly configure their environment.",
        30,
    ),
    "url_reference": (
        "Web address text is present",
        "Network-related text",
        "A destination string can be useful context when reviewing network-related code.",
        "Documentation, license text and unused configuration can contain web addresses.",
        20,
    ),
    "upx_style_section_name": (
        "Section declarations resemble UPX names",
        "Reconstruction limits",
        "Section layout may deserve attention when reconstruction is limited.",
        "Section names are arbitrary declarations and may be copied or misleading.",
        15,
    ),
    "pe_kernel32_import_name": (
        "Windows library-name text is present",
        "File declarations and structure",
        "The retained text can be checked against actual library import records.",
        "This common library name can occur as unused text.",
        5,
    ),
    "pe_dos_stub_message": (
        "Conventional PE stub text is present",
        "File declarations and structure",
        "The text is consistent with a common executable header convention.",
        "Many unrelated Windows executables contain the same conventional stub.",
        1,
    ),
    "elf_dynamic_loader_path": (
        "Linux loader-path text is present",
        "File declarations and structure",
        "The string can be checked against a declared interpreter record.",
        "A path can appear in documentation or unused data.",
        5,
    ),
}


DETAILS.update(
    {
        "create process via Windows API": (
            "Code refers to creating a process",
            "Processes",
            "Process creation can start a helper application.",
            "Launchers, installers and ordinary tools start child processes.",
            35,
        ),
        "send HTTP request via Windows API": (
            "Code refers to sending an HTTP request",
            "Network communication",
            "An HTTP request can contact a service; no traffic was observed.",
            "Clients, updaters and telemetry libraries commonly send HTTP requests.",
            35,
        ),
        "read file via Windows API": (
            "Code refers to reading a file",
            "Files",
            "File reads can supply application data or configuration.",
            "File reads are routine in ordinary applications.",
            25,
        ),
        "read INI configuration via Windows API": (
            "Code refers to reading INI settings",
            "Configuration and environment",
            "INI queries can select application settings.",
            "Desktop applications commonly read INI configuration.",
            30,
        ),
        "load library via Windows API": (
            "Code refers to loading a library",
            "Dynamic loading",
            "Dynamic loading can select code modules at runtime.",
            "Plugin hosts and applications routinely load optional libraries.",
            35,
        ),
    }
)


def rank_live_review(review: ReviewOut) -> None:
    weights: dict[str, int] = {}
    for item in review.observations:
        _, hypothesis = explanation(item.tool, item.tool_version, item.rule_id, item.rule_sha256)
        reviewed = (
            not hypothesis.startswith("There is no reviewed") and item.adapter_version == "0.1.0"
        )
        details = DETAILS.get(item.rule_id) if reviewed else None
        item.title = details[0] if details else "Static rule match needs review"
        weights[item.key] = details[4] if details else 0
    review.observations.sort(
        key=lambda item: (-weights[item.key], item.tool, item.rule_id, item.key)
    )
    review.selection_policy = "relevance-v1"
    review.selection_explanation = (
        "Reviewed code features precede text and structural context, then unreviewed matches. "
        "Repeated matching locations add no weight; reading order is not threat probability."
    )

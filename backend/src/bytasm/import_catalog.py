"""Curated import-presence interpretations; never call paths or observed behavior.

Self-authored Bytasm catalog. No upstream rule collection or third-party license
is added. Exact LIEF 1.0.0 / metadata_lief 0.1.0/0.2.0 semantics only. No approximate
name matching, demangling, resolved dependency claims or process execution.
"""

import hashlib
import json
from typing import Any

VERSION = "imports-1"
CATALOG = {
    "process": {
        "title": "Imports refer to starting other programs",
        "symbols": [
            "CreateProcessA",
            "CreateProcessW",
            "posix_spawn",
            "posix_spawnp",
            "execve",
            "fork",
        ],
        "alternative": "Launchers, build utilities and desktop applications start helper programs.",
        "next_step": "Inspect exact code references and any retained command arguments.",
    },
    "shell": {
        "title": "Imports refer to command execution interfaces",
        "symbols": ["system", "popen", "_popen", "ShellExecuteA", "ShellExecuteW"],
        "alternative": (
            "Automation and maintenance utilities can use shell interfaces legitimately."
        ),
        "next_step": (
            "Find retained references and command text; import presence does not reveal arguments."
        ),
    },
    "http": {
        "title": "Imports refer to HTTP or download interfaces",
        "symbols": [
            "WinHttpConnect",
            "WinHttpOpenRequest",
            "InternetOpenA",
            "InternetOpenW",
            "URLDownloadToFileW",
            "curl_easy_perform",
        ],
        "alternative": "Updaters, online features and ordinary clients use these interfaces.",
        "next_step": (
            "Inspect function references and destination text without contacting destinations."
        ),
    },
    "sockets": {
        "title": "Imports refer to socket interfaces",
        "symbols": ["socket", "connect", "send", "recv", "WSAStartup"],
        "alternative": "Local communication, games and ordinary network clients use sockets.",
        "next_step": (
            "Inspect address setup and call references; no destination or connection was observed."
        ),
    },
    "files": {
        "title": "Imports refer to opening or writing files",
        "symbols": ["fopen", "fwrite", "open", "write", "CreateFileW", "CreateFileA", "WriteFile"],
        "alternative": "Logging, document editing and configuration storage require file access.",
        "next_step": (
            "Inspect verified code references and path "
            "context; imports do not establish access mode."
        ),
    },
    "directories": {
        "title": "Imports refer to directory enumeration",
        "symbols": ["opendir", "readdir", "FindFirstFileW", "FindNextFileW"],
        "alternative": "File managers, search tools and installers enumerate directories.",
        "next_step": "Inspect referenced paths and code context before describing traversal scope.",
    },
    "environment": {
        "title": "Imports refer to environment settings",
        "symbols": [
            "getenv",
            "setenv",
            "_putenv",
            "GetEnvironmentVariableA",
            "GetEnvironmentVariableW",
        ],
        "alternative": (
            "Locale, user preferences and build configuration commonly use environment values."
        ),
        "next_step": (
            "Look for retained references naming specific settings; missing names remain unknown."
        ),
    },
    "configuration": {
        "title": "Imports refer to Windows configuration interfaces",
        "symbols": [
            "RegOpenKeyExW",
            "RegQueryValueExW",
            "RegSetValueExW",
            "GetPrivateProfileStringW",
        ],
        "alternative": "Applications and installers use the registry and INI files for settings.",
        "next_step": "Inspect key/path references and read-versus-write operations in code.",
    },
    "libraries": {
        "title": "Imports refer to loading libraries dynamically",
        "symbols": ["dlopen", "dlsym", "LoadLibraryA", "LoadLibraryW", "GetProcAddress"],
        "alternative": "Plugins and optional platform features load libraries dynamically.",
        "next_step": (
            "Inspect target library text; dynamically resolved targets may remain unavailable."
        ),
    },
    "cryptography": {
        "title": "Imports refer to cryptographic interfaces",
        "symbols": [
            "BCryptEncrypt",
            "BCryptDecrypt",
            "CryptEncrypt",
            "CryptDecrypt",
            "EVP_EncryptInit_ex",
        ],
        "alternative": (
            "Transport security, document protection and credential storage use cryptography."
        ),
        "next_step": (
            "Inspect algorithm and key-handling context; the import does not establish purpose."
        ),
    },
    "services": {
        "title": "Imports refer to Windows service interfaces",
        "symbols": [
            "CreateServiceW",
            "OpenSCManagerW",
            "StartServiceW",
            "StartServiceCtrlDispatcherW",
        ],
        "alternative": (
            "System administration and legitimate background services use these interfaces."
        ),
        "next_step": (
            "Inspect service configuration references; persistence has not been established."
        ),
    },
    "memory": {
        "title": "Imports refer to changing memory mappings or protection",
        "symbols": ["VirtualAlloc", "VirtualProtect", "mmap", "mprotect"],
        "alternative": "JIT runtimes, emulators and ordinary memory managers use these interfaces.",
        "next_step": (
            "Inspect protection arguments; executable memory cannot be inferred from an import."
        ),
    },
    "debugging": {
        "title": "Imports refer to debugging or process inspection interfaces",
        "symbols": ["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "ptrace"],
        "alternative": "Diagnostics, crash handling and development tools inspect debugging state.",
        "next_step": (
            "Inspect the code relationship; an import is not proof of an anti-analysis check."
        ),
    },
}
SHA256 = hashlib.sha256(json.dumps(CATALOG, sort_keys=True).encode()).hexdigest()


def classify_imports(
    symbols: list[str], tool_version: str, adapter_version: str
) -> list[dict[str, Any]]:
    if len(symbols) > 100_000 or any(not isinstance(s, str) or len(s) > 4096 for s in symbols):
        raise ValueError("Import inventory exceeds the metadata contract")
    if tool_version != "1.0.0" or adapter_version not in {"0.1.0", "0.2.0"}:
        return []
    result = []
    for category, record in CATALOG.items():
        indices = [i for i, name in enumerate(symbols) if name in record["symbols"]]
        if indices:
            result.append(
                {
                    "category": category,
                    "title": record["title"],
                    "observation": (
                        "The retained import-name inventory contains a catalogued interface name."
                    ),
                    "alternative": record["alternative"],
                    "next_step": record["next_step"],
                    "pointers": [f"/metadata/imports/functions/{i}" for i in indices[:8]],
                    "supporting_names": sorted({symbols[i] for i in indices})[:8],
                    "matches_retained": len(indices),
                    "locations_capped": len(indices) > 8,
                    "catalog_version": VERSION,
                    "catalog_sha256": SHA256,
                    "source": "self-authored Bytasm import catalog",
                    "limitation": (
                        "Import presence does not establish execution, "
                        "a static reference or a call path."
                    ),
                }
            )
    return result

# Third-party notices: v0.4 additions

Bytasm integrates **capa**, the FLARE/Mandiant static capability tool. Bytasm
did not create or rename it. This inventory covers v0.4 additions; installed
wheel licenses and the lockfile retain complete dependency details.

## Tool and rules (checked 2026-10-30)

- `flare-capa==10.0.0`: [official release](https://github.com/mandiant/capa/releases/tag/v10.0.0),
  Apache-2.0; original license in `rules/capa/CAPA-LICENSE.txt`.
- [capa-rules v10.0.0](https://github.com/mandiant/capa-rules/tree/v10.0.0), commit
  `805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5`, Apache-2.0; original license
  in `rules/capa/LICENSE.txt`. Only the two unmodified environment-variable
  rules listed in `rules/capa/ruleset.json` are bundled. Original paths,
  hashes and author metadata are preserved (Michael Hunhoff and @_re_fox).
- Snapshot SHA-256:
  `c78c7ff8ad97ba7e6f2b74060e425bbcc830ea30c5fb5b2594acc9365d78d3a6`.
- No upstream example binaries, signatures, documentation images or samples
  are redistributed. Rule-supplied ATT&CK/MBC strings are attributed metadata,
  not a separately redistributed technique corpus or ATT&CK matrix.
- Jinja2 3.1.6: BSD license included in the installed distribution.

The locked installation preserves wheel license/copyright files; the image
build does not strip them. Some IDA helper Python packages are unconditional
upstream capa dependencies. Bytasm neither enables them nor installs/runs the
proprietary IDA application, IDA plugins or Ghidra. Their presence grants no
IDA license. The only selected backend is vivisect.

## Newly locked distributions

Labels below come from installed metadata/classifiers; a generic BSD classifier
is not a substitute for the precise terms in the included license text.

| Distribution | Version | Declared license |
|---|---|---|
| cxxfilt | 0.3.0 | BSD License |
| dncil | 1.0.2 | Apache Software License |
| dnfile | 0.18.0 | MIT License |
| flare-capa | 10.0.0 | Apache Software License |
| funcy | 2.1 | BSD License |
| humanize | 4.16.0 | MIT |
| ida-hcli | 0.27.3 | MIT |
| ida-netnode | 3.0 | Apache Software License |
| ida-settings | 3.5.2 | NOT SPECIFIED |
| idapro | 0.0.12 | MIT License |
| intervaltree | 3.2.1 | Apache-2.0 |
| jinja2 | 3.1.6 | BSD License |
| msgspec | 0.22.0 | BSD-3-Clause |
| networkx | 3.7 | BSD-3-Clause |
| pefile | 2024.8.26 | MIT |
| prompt-toolkit | 3.0.53 | BSD License |
| protobuf | 7.36.2 | 3-Clause BSD License |
| pyasn1 | 0.6.5 | BSD-2-Clause |
| pyasn1-modules | 0.4.2 | BSD License |
| pycparser | 3.12 | BSD-3-Clause |
| pyelftools | 0.33 | Public Domain |
| python-flirt | 0.10.2 | Apache Software License |
| pyyaml | 6.0.3 | MIT License |
| questionary | 2.1.1 | MIT License |
| rich-click | 1.9.9 | MIT License |
| ruamel-yaml | 0.19.1 | MIT License |
| semantic-version | 2.10.0 | BSD License |
| six | 1.17.0 | MIT License |
| tenacity | 9.2.1 | Apache-2.0 |
| truststore | 0.10.5 | MIT |
| viv-utils | 0.8.1 | Apache Software License |
| vivisect | 1.3.2 | Apache Software License |
| wcwidth | 0.9.4 | MIT License |
| xmltodict | 1.0.4 | MIT |

## Outstanding redistribution clarification

`ida-settings` 3.5.2 has neither a license field nor a license file in its wheel.
Its [release source pyproject](https://github.com/williballenthin/ida-settings/blob/de9901594e20f44fa083ca66e7140b4021fd4e4d/pyproject.toml)
also omits the license. The same repository's
[editor plugin descriptor](https://github.com/williballenthin/ida-settings/blob/de9901594e20f44fa083ca66e7140b4021fd4e4d/ida-plugin.json)
says Apache 2.0 for that plugin; this is insufficient evidence to silently
assign that license to the separately packaged Python library. This is an
explicit **redistribution blocker** pending upstream clarification or a reviewed
packaging correction. Do not describe the dependency chain as license-cleared
or publish the image as a cleared distribution. Local implementation/testing
and owner release approval are distinct. No upstream issue, message or PR was
opened on the owner's behalf.

## Optional Ghidra proposal (not bundled)

The metadata diagnostic references Ghidra 12.2 and JDK 25; no distribution,
plugin, upstream script, REA/MCP package, Java runtime or new dependency is added.
[Official Ghidra LICENSE](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.2_build/LICENSE)
is Apache-2.0. Its [NOTICE](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.2_build/NOTICE)
requires attention to per-module third-party notices and separately licensed GPL
support programs. The exact binary distribution and its bundled payload are not
available for inspection here, so no binary redistribution clearance is claimed.
Caller ownership of an installation does not replace that review if packaging
is proposed later. The existing ida-settings blocker above is unchanged.

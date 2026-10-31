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
- Historical two-rule snapshot SHA-256:
  `c78c7ff8ad97ba7e6f2b74060e425bbcc830ea30c5fb5b2594acc9365d78d3a6`.
- Five additional API-feature rules are authored by Bytasm contributors under
  Apache-2.0, authored subset version 1.0.0; see `rules/capa/README.md`.
  Current mixed seven-rule snapshot SHA-256:
  `9a7dbb7813c3e4c4bec1f991e821439ea60fa0210663aedbe5ae96242919ee62`.
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

## Optional Ghidra provider (not bundled)

Ghidra 12.2 and 64-bit JDK 25 remain caller-installed optional tools. No binary,
Java runtime, upstream script, REA/MCP package or new runtime dependency is added
to Bytasm. Its fixed Java extraction/health scripts are self-authored.

The official release archive ghidra_12.2_PUBLIC_20261016.zip was downloaded only
for temporary local verification. SHA-256 matched the published release digest:
2c2cd776db3c1f6a097ba418922378ac3649cadd5e844a6f5f088ae628a7be67.
[Official release](https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.2_build),
[versioned requirements](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.2_build/GhidraDocs/GettingStarted.md),
[LICENSE](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.2_build/LICENSE),
[NOTICE](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.2_build/NOTICE).

The actual archive has an Apache2.0 top-level LICENSE, 37 files under licenses/,
a CycloneDX bom.json with 209 component entries, and separately licensed GPL
support programs. The BOM component entries inspected do not supply license
identifiers; it is not license clearance. The extracted binary archive has no
root NOTICE file; upstream NOTICE and per-module/license files remain relevant.
The Linux ARM64 decompiler was built for testing from the verified archive's
included C++ source using GCC 14.2; no sample was compiled as a helper or run.

Temporary test Java: Adoptium Temurin 25.0.5+8 Linux AArch64, downloaded through
the official Adoptium asset API/release. SHA-256 matched its published API digest:
bb5b2ded252f21c6090cf780b0a408ad0d83bbb557e702955643557f13231880.
[Exact official asset](https://github.com/adoptium/temurin25-binaries/releases/download/jdk-25.0.5%2B8/OpenJDK25U-jdk_aarch64_linux_hotspot_25.0.5_8.tar.gz).
It is not bundled or redistributed with Bytasm. Review its own included legal/
notices before any proposed distribution.

The pinned ida-settings3.5.2 source pyproject and installed metadata were
rechecked; they still do not establish a library license. The existing
redistribution blocker is unchanged. No package/image distribution clearance is
claimed and no upstream communication was sent.

## v0.6 function workbench

No runtime or frontend dependency, third-party script, rule or tool distribution
is added. inventory_many.c and its static ELF fixture are self-authored for
Bytasm; BUILD_INFO.txt records the existing pinned cross-toolchain and two-build
reproducibility. Earlier fixtures remain unchanged. The Java extraction changes
are self-authored against the same caller-installed Ghidra 12.2 API.

Temporary verification reuses the exact Ghidra and Temurin archive digests above.
The Linux ARM64 native decompiler is compiled from that verified archive's
included source outside the repository; it is not bundled in an application
image or repository. Component-specific licensing and the unresolved ida-settings
distribution blocker remain unchanged. Neither a vulnerability audit nor local
tool verification resolves license or redistribution permission.

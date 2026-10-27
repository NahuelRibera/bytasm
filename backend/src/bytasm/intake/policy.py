"""The input policy: which bytes may reach a parser at all (blueprint 3.4).

`fixtures` (default): only files whose SHA-256 is in fixtures/MANIFEST.sha256.
`self_built` (local opt-in, set by server configuration at start-up only):
also files the operator attests they compiled from source they wrote.
Bytasm cannot verify that attestation; it is recorded, not checked.

Neither mode makes parsing safe. Third-party, downloaded, received, or
suspicious files are never admitted by any mode before isolation gate I1.
"""

from dataclasses import dataclass
from typing import Literal

from bytasm.intake.manifest import Manifest

AdmittedUnder = Literal["fixture_manifest", "self_built_optin"]


@dataclass(frozen=True)
class Admission:
    admitted_under: AdmittedUnder
    manifest_entry: str | None


@dataclass(frozen=True)
class InputPolicy:
    mode: Literal["fixtures", "self_built"]
    manifest: Manifest

    def admit(self, sha256: str) -> Admission | None:
        """Decide from the SHA-256 alone. None means: refuse, never parse.

        A file listed in the manifest is recorded as `fixture_manifest` in
        either mode, so provenance says which control actually admitted it.
        """
        entry = self.manifest.lookup(sha256)
        if entry is not None:
            return Admission("fixture_manifest", entry)
        if self.mode == "self_built":
            return Admission("self_built_optin", None)
        return None

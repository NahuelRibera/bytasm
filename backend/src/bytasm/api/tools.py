"""Read-only tool versions, provenance and built-in profile registry."""

from fastapi import APIRouter, Request
from pydantic import BaseModel

from bytasm.ghidra import GhidraDiagnostic
from bytasm.ghidra_health import effective_diagnostic
from bytasm.tools import PROFILES, registry

router = APIRouter()


class ToolOut(BaseModel):
    tool: str
    available: bool
    version: str | None
    adapter: str
    adapter_version: str
    formats: list[str]
    rules_sha256: str | None
    limitations: str


class ProfileOut(BaseModel):
    id: str
    name: str
    steps: list[str]
    limitations: str


class ToolsOut(BaseModel):
    tools: list[ToolOut]
    profiles: list[ProfileOut]
    optional_providers: list[GhidraDiagnostic]


@router.get("/tools", response_model=ToolsOut)
async def tools(request: Request) -> ToolsOut:
    diagnostic = await effective_diagnostic(request.app.state.ctx.settings)
    profiles = list(PROFILES)
    if diagnostic.available and diagnostic.analysis_enabled:
        profiles.append(
            {
                "id": "ghidra-static",
                "name": "Ghidra function review",
                "steps": ["ghidra"],
                "limitations": (
                    "Up to 1024 inventory entries and first 16 function details; "
                    "explicit sets of up to 8 can be inspected in a new bounded run. "
                    "Static evidence, not runtime behavior. Requires the configured offline worker."
                ),
            }
        )
    return ToolsOut.model_validate(
        {
            "tools": registry(),
            "profiles": profiles,
            "optional_providers": [diagnostic],
        }
    )

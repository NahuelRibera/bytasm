"""Read-only tool versions, provenance and built-in profile registry."""

from fastapi import APIRouter, Request
from pydantic import BaseModel

from bytasm.ghidra import GhidraDiagnostic, diagnose
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
def tools(request: Request) -> ToolsOut:
    return ToolsOut.model_validate(
        {
            "tools": registry(),
            "profiles": PROFILES,
            "optional_providers": [diagnose(request.app.state.ctx.settings.ghidra)],
        }
    )

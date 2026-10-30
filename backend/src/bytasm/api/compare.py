"""Read-only structural comparison endpoint."""

from typing import Annotated

from fastapi import APIRouter, Query, Request
from fastapi.responses import JSONResponse

from bytasm.api.problems import problem
from bytasm.compare import CompareError, CompareOut, compare_versions

router = APIRouter()


@router.get("/compare", response_model=CompareOut)
def compare(
    request: Request,
    a: Annotated[str, Query(pattern=r"^[0-9a-f]{32}$")],
    b: Annotated[str, Query(pattern=r"^[0-9a-f]{32}$")],
    category: str | None = None,
    offset: Annotated[int, Query(ge=0, le=1_000_000)] = 0,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> CompareOut | JSONResponse:
    with request.app.state.ctx.sessions() as session:
        try:
            return compare_versions(session, a, b, category=category, offset=offset, limit=limit)
        except CompareError as error:
            return problem(error.code, detail=error.detail, request_id=request.state.request_id)

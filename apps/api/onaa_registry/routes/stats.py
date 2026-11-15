"""Public, anonymous usage statistics (how many agents use ONAA, through which doors)."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session

from ..db import get_session
from ..traffic import usage_report

router = APIRouter(tags=["meta"])


@router.get("/v1/stats/usage", summary=("Anonymous daily usage counts split into external, ours and probes, by "
                                         "agent class, path, MCP tool and store check"))
def usage(request: Request, days: Annotated[int, Query(ge=1, le=90)] = 14,
          session: Session = Depends(get_session)):
    request.app.state.usage.flush()
    return usage_report(session, days)

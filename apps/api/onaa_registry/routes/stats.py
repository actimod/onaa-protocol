"""Public, anonymous usage statistics (how many agents use ONAA, through which doors)."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session

from ..db import get_session
from ..traffic import hourly_report, usage_report, weekly_report

router = APIRouter(tags=["meta"])


@router.get("/v1/stats/usage", summary=("Anonymous daily usage counts split into external, ours and probes, by "
                                         "agent class, path, MCP tool and store check"))
def usage(request: Request, days: Annotated[int, Query(ge=1, le=90)] = 14,
          session: Session = Depends(get_session)):
    request.app.state.usage.flush()
    return usage_report(session, days)


@router.get("/v1/stats/usage/hourly", summary="The same anonymous counts per UTC hour (last 30 days at most)")
def usage_hourly(request: Request, hours: Annotated[int, Query(ge=1, le=720)] = 48,
                 session: Session = Depends(get_session)):
    request.app.state.usage.flush()
    return hourly_report(session, hours)


@router.get("/v1/stats/usage/weekly",
            summary="Third-party use per week with running totals: crawlers, store data fetched, MCP use")
def usage_weekly(request: Request, weeks: Annotated[int, Query(ge=1, le=104)] = 12,
                 session: Session = Depends(get_session)):
    request.app.state.usage.flush()
    return weekly_report(session, weeks)

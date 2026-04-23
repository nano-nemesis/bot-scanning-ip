import math
from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse

from db import get_ip_detail_any, get_ips_paginated, get_latest_done_session, search_ip_across_sessions
from web.auth import require_auth
from web.config import web_config

router = APIRouter()

PER_PAGE_OPTIONS = [25, 50, 100]


@router.get("/ips", response_class=HTMLResponse)
async def ip_list(
    request: Request,
    user: str = Depends(require_auth),
    session: int | None = None,
    page: int = 1,
    per_page: int = 50,
    min_score: int | None = None,
    max_score: int | None = None,
    country: str | None = None,
    search_ip: str | None = None,
    sort_by: str = "abuse_score",
    sort_dir: str = "DESC",
):
    templates = request.app.state.templates

    if per_page not in PER_PAGE_OPTIONS:
        per_page = 50

    current_session = await get_latest_done_session() if session is None else None
    if session is None and current_session:
        session_id = current_session["id"]
    elif session is not None:
        session_id = session
    else:
        session_id = None

    ips, total = [], 0
    if session_id:
        ips, total = await get_ips_paginated(
            session_id=session_id,
            page=page,
            per_page=per_page,
            min_score=min_score,
            max_score=max_score,
            country=country,
            search_ip=search_ip,
            sort_by=sort_by,
            sort_dir=sort_dir,
        )

    total_pages = max(1, math.ceil(total / per_page))

    ctx = {
        "request": request,
        "current_user": user,
        "active_page": "ips",
        "ips": ips,
        "total": total,
        "page": page,
        "per_page": per_page,
        "total_pages": total_pages,
        "per_page_options": PER_PAGE_OPTIONS,
        "session_id": session_id,
        "min_score": min_score,
        "max_score": max_score,
        "country": country or "",
        "search_ip": search_ip or "",
        "sort_by": sort_by,
        "sort_dir": sort_dir,
        "as_number": web_config.as_number,
        "alert_threshold": web_config.alert_threshold,
    }

    # HTMX partial request — hanya kembalikan tbody
    if request.headers.get("HX-Request"):
        return templates.TemplateResponse("partials/ip_rows.html", ctx)

    return templates.TemplateResponse("ips.html", ctx)


@router.get("/ips/{ip_address}", response_class=HTMLResponse)
async def ip_detail(
    request: Request, ip_address: str, user: str = Depends(require_auth)
):
    templates = request.app.state.templates

    ip_data = await get_ip_detail_any(ip_address)
    history = await search_ip_across_sessions(ip_address, limit=20)

    return templates.TemplateResponse(
        "ip_detail.html",
        {
            "request": request,
            "current_user": user,
            "active_page": "ips",
            "ip": ip_data,
            "ip_address": ip_address,
            "history": history,
            "as_number": web_config.as_number,
            "alert_threshold": web_config.alert_threshold,
        },
    )

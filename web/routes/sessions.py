from fastapi import APIRouter, Depends, Request

from db import (
    get_category_breakdown,
    get_high_score_ips,
    get_session_history,
    get_session_prefix_stats,
    get_session_summary,
    get_top_offenders,
)
from web.auth import require_auth
from web.config import web_config
import aiosqlite
import json

router = APIRouter()


async def _get_session_by_id(session_id: int) -> dict | None:
    async with aiosqlite.connect(web_config.db_path) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT * FROM scan_sessions WHERE id=?", (session_id,)
        )
        row = await cursor.fetchone()
        return dict(row) if row else None


@router.get("/sessions")
async def sessions_list(request: Request, user: str = Depends(require_auth)):
    templates = request.app.state.templates
    sessions = await get_session_history(limit=100)
    return templates.TemplateResponse(
        "sessions.html",
        {
            "request": request,
            "current_user": user,
            "active_page": "sessions",
            "sessions": sessions,
            "as_number": web_config.as_number,
        },
    )


@router.get("/sessions/{session_id}")
async def session_detail(
    request: Request, session_id: int, user: str = Depends(require_auth)
):
    templates = request.app.state.templates

    session = await _get_session_by_id(session_id)
    if not session:
        return templates.TemplateResponse(
            "sessions.html",
            {
                "request": request,
                "current_user": user,
                "active_page": "sessions",
                "sessions": [],
                "error": f"Session #{session_id} tidak ditemukan.",
                "as_number": web_config.as_number,
            },
            status_code=404,
        )

    summary = await get_session_summary(session_id)
    categories = await get_category_breakdown(session_id)
    offenders = await get_top_offenders(session_id, 25)
    alerts = await get_high_score_ips(session_id, web_config.alert_threshold, limit=50)
    prefixes = await get_session_prefix_stats(session_id)

    cat_labels_json = json.dumps([c["category_name"] for c in categories[:8]])
    cat_counts_json = json.dumps([c["ip_count"] for c in categories[:8]])

    return templates.TemplateResponse(
        "session_detail.html",
        {
            "request": request,
            "current_user": user,
            "active_page": "sessions",
            "session": session,
            "summary": summary,
            "offenders": offenders,
            "alerts": alerts,
            "prefixes": prefixes,
            "as_number": web_config.as_number,
            "alert_threshold": web_config.alert_threshold,
            "cat_labels_json": cat_labels_json,
            "cat_counts_json": cat_counts_json,
        },
    )

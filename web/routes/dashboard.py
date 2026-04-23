import json
from fastapi import APIRouter, Depends, Request

from db import (
    get_category_breakdown,
    get_latest_done_session,
    get_session_summary,
    get_top_offenders,
    get_weekly_stats,
)
from web.auth import require_auth
from web.config import web_config

router = APIRouter()


@router.get("/")
async def dashboard(request: Request, user: str = Depends(require_auth)):
    templates = request.app.state.templates

    session = await get_latest_done_session()
    if not session:
        return templates.TemplateResponse(
            "dashboard.html",
            {
                "request": request,
                "current_user": user,
                "active_page": "dashboard",
                "session": None,
                "as_number": web_config.as_number,
            },
        )

    sid = session["id"]
    summary, categories, offenders, weekly = (
        await get_session_summary(sid),
        await get_category_breakdown(sid),
        await get_top_offenders(sid, 10),
        await get_weekly_stats(),
    )

    # Chart.js data — weekly trend
    weekly_labels = [w["week_label"] for w in reversed(weekly)]
    weekly_reported = [int(w.get("reported_ips") or 0) for w in reversed(weekly)]
    weekly_avg = [float(w.get("avg_score") or 0) for w in reversed(weekly)]

    # Chart.js data — categories (top 8)
    cat_labels = [c["category_name"] for c in categories[:8]]
    cat_counts = [c["ip_count"] for c in categories[:8]]

    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "current_user": user,
            "active_page": "dashboard",
            "session": session,
            "summary": summary,
            "offenders": offenders,
            "weekly": weekly,
            "as_number": web_config.as_number,
            "alert_threshold": web_config.alert_threshold,
            "weekly_labels_json": json.dumps(weekly_labels),
            "weekly_reported_json": json.dumps(weekly_reported),
            "weekly_avg_json": json.dumps(weekly_avg),
            "cat_labels_json": json.dumps(cat_labels),
            "cat_counts_json": json.dumps(cat_counts),
        },
    )

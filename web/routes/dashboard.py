import json
from fastapi import APIRouter, Depends, Request

from db import (
    get_category_breakdown,
    get_latest_done_session,
    get_session_history,
    get_session_summary,
    get_top_offenders,
    get_weekly_stats,
)
from web.auth import require_auth
from web.config import web_config

router = APIRouter()


def _trend(current, previous) -> dict:
    """Return {value, direction, pct} comparing two numbers."""
    if not previous or previous == 0:
        return {"value": 0, "pct": 0.0, "direction": "neutral"}
    diff = current - previous
    pct = diff / previous * 100
    return {
        "value": diff,
        "pct": round(pct, 1),
        "direction": "up" if diff > 0 else ("down" if diff < 0 else "neutral"),
    }


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
                "node_name": web_config.node_name,
                "node_location": web_config.node_location,
            },
        )

    sid = session["id"]
    summary, categories, offenders, weekly = (
        await get_session_summary(sid),
        await get_category_breakdown(sid),
        await get_top_offenders(sid, 10),
        await get_weekly_stats(),
    )

    # Previous session for trend comparison
    trend_total_ips = trend_reported = trend_avg = trend_max = {}
    history = await get_session_history(limit=10)
    full_sessions = [s for s in history if s.get("session_type") == "full" and s["id"] != sid]
    if full_sessions:
        prev = full_sessions[0]
        prev_summary = await get_session_summary(prev["id"])
        trend_total_ips = _trend(session.get("total_ips", 0), prev.get("total_ips", 0))
        trend_reported  = _trend(summary.get("total_reported_ips") or 0, prev_summary.get("total_reported_ips") or 0)
        trend_avg       = _trend(round(summary.get("avg_score") or 0, 1), round(prev_summary.get("avg_score") or 0, 1))
        trend_max       = _trend(summary.get("max_score") or 0, prev_summary.get("max_score") or 0)

    # Chart data — weekly trend
    weekly_rev = list(reversed(weekly))
    weekly_labels   = json.dumps([w["week_label"] for w in weekly_rev])
    weekly_reported = json.dumps([int(w.get("reported_ips") or 0) for w in weekly_rev])
    weekly_avg      = json.dumps([float(w.get("avg_score") or 0) for w in weekly_rev])

    # Chart data — categories donut (top 6 + other)
    top_cats   = categories[:6]
    other_sum  = sum(c["ip_count"] for c in categories[6:])
    cat_labels = [c["category_name"] for c in top_cats]
    cat_counts = [c["ip_count"] for c in top_cats]
    if other_sum:
        cat_labels.append("Other")
        cat_counts.append(other_sum)

    total_ips = session.get("total_ips", 0)
    reported  = summary.get("total_reported_ips") or 0
    pct       = round(reported / total_ips * 100, 2) if total_ips else 0

    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "current_user": user,
            "active_page": "dashboard",
            "session": session,
            "summary": summary,
            "offenders": offenders,
            "as_number": web_config.as_number,
            "node_name": web_config.node_name,
            "node_location": web_config.node_location,
            "alert_threshold": web_config.alert_threshold,
            "total_ips": total_ips,
            "reported": reported,
            "pct": pct,
            "avg_score": round(summary.get("avg_score") or 0, 1),
            "max_score": summary.get("max_score") or 0,
            "trend_total_ips": trend_total_ips,
            "trend_reported": trend_reported,
            "trend_avg": trend_avg,
            "trend_max": trend_max,
            "weekly_labels_json": weekly_labels,
            "weekly_reported_json": weekly_reported,
            "weekly_avg_json": weekly_avg,
            "cat_labels_json": json.dumps(cat_labels),
            "cat_counts_json": json.dumps(cat_counts),
        },
    )

import json
import logging
from datetime import datetime, timezone

from config import config
from db import (
    get_category_breakdown,
    get_latest_session,
    get_session_summary,
    get_top_offenders,
)
from scanner import CATEGORY_NAMES

logger = logging.getLogger(__name__)

MAX_MESSAGE_LEN = 4096


def _fmt_datetime(iso: str | None) -> str:
    if not iso:
        return "N/A"
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        wib_offset = 7 * 3600
        wib_ts = dt.timestamp() + wib_offset
        wib_dt = datetime.utcfromtimestamp(wib_ts)
        return wib_dt.strftime("%d %b %Y %H:%M WIB")
    except Exception:
        return iso


def _recommended_action(score: int) -> str:
    if score >= 80:
        return "🚫 BLOCK"
    if score >= 50:
        return "⚠️ MONITOR"
    return "✅ OK"


def format_summary_block(session: dict, summary: dict) -> str:
    total_ips = session.get("total_ips", 0)
    reported = summary.get("total_reported_ips") or 0
    total_reports = summary.get("total_reports") or 0
    avg_score = summary.get("avg_score") or 0
    pct = (reported / total_ips * 100) if total_ips else 0

    lines = [
        f"📊 *AS{session.get('as_number', config.as_number.replace('AS',''))} Abuse Scan Report*",
        f"📅 Scan: {_fmt_datetime(session.get('started_at'))} | Sesi #{session.get('id')}",
        "",
        f"Total IP di-scan   : `{total_ips:,}`",
        f"IP ada laporan     : `{reported:,}` ({pct:.2f}%)",
        f"Rata-rata score    : `{avg_score:.1f}`",
        f"Total laporan      : `{int(total_reports):,}`",
        f"Prefix di-scan     : `{session.get('total_prefixes', 0)}`",
    ]
    return "\n".join(lines)


def format_category_block(categories: list[dict]) -> str:
    if not categories:
        return "📂 *Kategori Laporan*\n_(tidak ada data kategori)_"

    lines = ["📂 *Kategori Laporan Terbanyak:*"]
    shown = categories[:8]
    for cat in shown:
        cat_id = cat.get("category_id", 0)
        name = cat.get("category_name") or CATEGORY_NAMES.get(cat_id, f"Cat {cat_id}")
        count = cat.get("ip_count", 0)
        lines.append(f"• {name} ({cat_id}): `{count}` IP")

    if len(categories) > 8:
        rest = sum(c.get("ip_count", 0) for c in categories[8:])
        lines.append(f"• Lainnya: `{rest}` IP")

    return "\n".join(lines)


def format_offenders_block(offenders: list[dict]) -> str:
    if not offenders:
        return "🔴 *Top IP Bermasalah*\n_(tidak ada IP yang dilaporkan)_"

    lines = [f"🔴 *Top {len(offenders)} IP Terburuk:*"]
    for ip in offenders:
        try:
            cats = json.loads(ip.get("categories") or "[]")
        except Exception:
            cats = []
        cat_names = ", ".join(CATEGORY_NAMES.get(c, str(c)) for c in cats[:3]) or "-"
        action = _recommended_action(ip.get("abuse_score", 0))
        line = (
            f"`{ip['ip_address']}` | Score:{ip.get('abuse_score',0)} "
            f"| Rep:{ip.get('num_reports',0)} | {ip.get('country_code','-')} "
            f"| {cat_names} | {action}"
        )
        lines.append(line)

    return "\n".join(lines)


def _parse_list_field(value) -> list:
    if isinstance(value, list):
        return value
    try:
        return json.loads(value or "[]")
    except Exception:
        return []


def format_actionable_ip(ip: dict) -> str:
    cats = _parse_list_field(ip.get("categories"))
    cat_names = "\n".join(
        f"  • {CATEGORY_NAMES.get(c, f'Cat {c}')}" for c in cats
    ) or "  -"

    vtags = _parse_list_field(ip.get("voidip_tags"))

    action = _recommended_action(ip.get("abuse_score", 0))

    return (
        f"🔍 *Detail IP: `{ip['ip_address']}`*\n"
        f"AbuseIPDB Score  : `{ip.get('abuse_score', 0)}`\n"
        f"Jumlah Laporan   : `{ip.get('num_reports', 0)}`\n"
        f"Terakhir Laporan : {_fmt_datetime(ip.get('last_reported'))}\n"
        f"Negara           : `{ip.get('country_code', '-')}`\n"
        f"Prefix           : `{ip.get('prefix', '-')}`\n"
        f"Kategori:\n{cat_names}\n"
        f"VoidIP Score     : `{ip.get('voidip_score', 0)}`\n"
        f"VoidIP Tags      : `{', '.join(vtags) or '-'}`\n"
        f"Rekomendasi      : {action}"
    )


def split_message(text: str, max_len: int = MAX_MESSAGE_LEN) -> list[str]:
    if len(text) <= max_len:
        return [text]
    chunks = []
    current = ""
    for line in text.split("\n"):
        candidate = current + "\n" + line if current else line
        if len(candidate) > max_len:
            if current:
                chunks.append(current)
            current = line
        else:
            current = candidate
    if current:
        chunks.append(current)
    return chunks


async def build_daily_report(session_id: int | None = None) -> list[str]:
    if session_id is None:
        session = await get_latest_session()
    else:
        from db import get_any_session
        session = await get_latest_session()

    if not session:
        return ["⚠️ Belum ada data scan yang selesai. Gunakan /scan untuk memulai."]

    sid = session["id"]
    summary = await get_session_summary(sid)
    categories = await get_category_breakdown(sid)
    offenders = await get_top_offenders(sid, config.top_offenders_count)

    parts = [
        format_summary_block(session, summary),
        "",
        format_category_block(categories),
        "",
        format_offenders_block(offenders),
    ]
    full_text = "\n".join(parts)
    return split_message(full_text)

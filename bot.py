import asyncio
import logging
import re

from telegram import Update
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
)

from config import config
from db import get_any_session, get_ip_detail, get_latest_session, get_session_history
from reporter import build_daily_report, format_actionable_ip
from scanner import scan_single_ip
from scheduler import handle_approval, run_scan

_IP_RE = re.compile(
    r"^(\d{1,3}\.){3}\d{1,3}$"
    r"|^[0-9a-fA-F:]{2,39}$"
)

logger = logging.getLogger(__name__)


def _is_admin(user_id: int) -> bool:
    return not config.admin_user_ids or user_id in config.admin_user_ids


async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    text = (
        "👋 *AS211407 IP Abuse Scanner Bot*\n\n"
        "Perintah tersedia:\n"
        "/scan — Trigger scan manual (admin)\n"
        "/soloscan `<IP>` — Scan 1 IP secara langsung\n"
        "/report — Kirim laporan terbaru\n"
        "/status — Status sesi scan terakhir\n"
        "/check `<IP>` — Cek detail IP dari DB\n"
        "/history — 7 sesi scan terakhir\n"
    )
    await update.message.reply_text(text, parse_mode="Markdown")


async def cmd_scan(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user = update.effective_user
    if not _is_admin(user.id):
        await update.message.reply_text("⛔ Perintah ini hanya untuk admin.")
        return

    await update.message.reply_text("🔄 Memulai scan manual...")
    asyncio.get_event_loop().create_task(run_scan(context.bot))


async def cmd_report(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text("⏳ Mengambil laporan...")
    chunks = await build_daily_report()
    for chunk in chunks:
        await update.message.reply_text(chunk, parse_mode="Markdown")


async def cmd_status(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    session = await get_any_session()
    if not session:
        await update.message.reply_text("ℹ️ Belum ada sesi scan.")
        return

    status_icon = {
        "done": "✅",
        "running": "🔄",
        "failed": "❌",
    }.get(session.get("status", ""), "❓")

    text = (
        f"*Status Sesi Terakhir* (#{session['id']})\n"
        f"Status    : {status_icon} {session.get('status','?')}\n"
        f"Mulai     : `{session.get('started_at','?')}`\n"
        f"Selesai   : `{session.get('finished_at') or 'Belum selesai'}`\n"
        f"Prefix    : `{session.get('total_prefixes', 0)}`\n"
        f"Total IP  : `{session.get('total_ips', 0):,}`"
    )
    await update.message.reply_text(text, parse_mode="Markdown")


async def cmd_check(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    args = context.args
    if not args:
        await update.message.reply_text("Penggunaan: /check `<IP>`", parse_mode="Markdown")
        return

    ip = args[0].strip()
    session = await get_latest_session()
    if not session:
        await update.message.reply_text("⚠️ Belum ada data scan selesai.")
        return

    ip_data = await get_ip_detail(session["id"], ip)
    if not ip_data:
        await update.message.reply_text(
            f"ℹ️ IP `{ip}` tidak ditemukan dalam sesi #{session['id']}.\n"
            f"IP tersebut kemungkinan bersih (tidak ada laporan).",
            parse_mode="Markdown",
        )
        return

    text = format_actionable_ip(ip_data)
    await update.message.reply_text(text, parse_mode="Markdown")


async def cmd_history(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    sessions = await get_session_history(7)
    if not sessions:
        await update.message.reply_text("ℹ️ Belum ada riwayat scan.")
        return

    lines = ["📋 *7 Sesi Scan Terakhir:*\n"]
    for s in sessions:
        icon = {"done": "✅", "running": "🔄", "failed": "❌"}.get(s.get("status",""), "❓")
        lines.append(
            f"{icon} #{s['id']} | {s.get('started_at','?')[:10]} | "
            f"IP:{s.get('total_ips',0):,} | {s.get('status','?')}"
        )

    await update.message.reply_text("\n".join(lines), parse_mode="Markdown")


async def cmd_solo_scan(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not context.args:
        await update.message.reply_text(
            "Penggunaan: `/soloscan <IP>`\nContoh: `/soloscan 1.2.3.4`",
            parse_mode="Markdown",
        )
        return

    ip = context.args[0].strip()
    if not _IP_RE.match(ip):
        await update.message.reply_text(
            f"⚠️ Format IP tidak valid: `{ip}`", parse_mode="Markdown"
        )
        return

    await update.message.reply_text(f"🔍 Scanning IP `{ip}`\\.\\.\\.", parse_mode="MarkdownV2")

    result = await scan_single_ip(ip)
    if result is None:
        await update.message.reply_text(
            f"❌ Gagal mengambil data untuk `{ip}`\\. Cek API key atau coba lagi\\.",
            parse_mode="MarkdownV2",
        )
        return

    await update.message.reply_text(format_actionable_ip(result), parse_mode="Markdown")


async def callback_approval(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    await query.answer()

    if not _is_admin(query.from_user.id):
        await query.answer("⛔ Hanya admin yang bisa approve.", show_alert=True)
        return

    status_text = await handle_approval(
        context.bot, query.data, query.message.message_id
    )

    try:
        await query.edit_message_text(text=status_text)
    except Exception:
        pass


def register_handlers(app: Application) -> None:
    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("scan", cmd_scan))
    app.add_handler(CommandHandler("soloscan", cmd_solo_scan))
    app.add_handler(CommandHandler("report", cmd_report))
    app.add_handler(CommandHandler("status", cmd_status))
    app.add_handler(CommandHandler("check", cmd_check))
    app.add_handler(CommandHandler("history", cmd_history))
    app.add_handler(CallbackQueryHandler(callback_approval, pattern="^(approve_scan|skip_scan)$"))


def create_application(token: str) -> Application:
    app = Application.builder().token(token).build()
    register_handlers(app)
    return app

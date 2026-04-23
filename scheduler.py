import asyncio
import logging

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from telegram import Bot, InlineKeyboardButton, InlineKeyboardMarkup

from config import config
from db import (
    create_session,
    finish_session,
    get_high_score_ips,
    save_category_stats,
    save_ip_results,
    save_prefix_result,
)
from reporter import build_daily_report
from ripe import count_total_ips, fetch_prefixes
from scanner import aggregate_categories, scan_all_prefixes, validate_abuseipdb_token

logger = logging.getLogger(__name__)

# Global state for approval flow
_pending_scan: dict = {}   # keys: "message_id", "task"


async def run_scan(bot: Bot) -> None:
    """Execute a full scan and save results. Called by scheduler or approval callback."""
    logger.info("Starting AS%s scan", config.as_number)
    session_id = await create_session()

    try:
        await bot.send_message(
            chat_id=config.telegram_chat_id,
            text=f"🔄 Scan dimulai... (Sesi #{session_id})",
        )

        prefixes = await fetch_prefixes(config.as_number)
        total_ips = count_total_ips(prefixes)
        results = await scan_all_prefixes(prefixes)

        for result in results:
            await save_prefix_result(
                session_id,
                result.prefix,
                {
                    "total_reports": result.total_reports,
                    "reported_ips": result.reported_ips,
                    "max_score": result.max_score,
                    "raw": result.raw_json,
                },
            )
            if result.ip_list:
                await save_ip_results(session_id, result.prefix, result.ip_list)

        cat_stats = aggregate_categories(results)
        await save_category_stats(session_id, cat_stats)

        success_count = sum(1 for r in results if r.success)
        await finish_session(session_id, len(prefixes), total_ips, "done")
        logger.info("Scan done: %d/%d prefixes succeeded", success_count, len(prefixes))

        await bot.send_message(
            chat_id=config.telegram_chat_id,
            text=(
                f"✅ Scan selesai! Sesi #{session_id}\n"
                f"Prefix: {len(prefixes)} | IP: {total_ips:,} | "
                f"Berhasil: {success_count}/{len(prefixes)}"
            ),
        )

        # Alert jika ada IP di atas threshold
        if config.alert_threshold > 0:
            alerts = await get_high_score_ips(session_id, config.alert_threshold, limit=15)
            if alerts:
                alert_lines = [
                    f"🚨 *{len(alerts)} IP dengan score ≥ {config.alert_threshold} ditemukan!*\n"
                ]
                for ip in alerts[:10]:
                    action = "🚫 BLOCK" if ip["abuse_score"] >= 80 else "⚠️ MONITOR"
                    alert_lines.append(
                        f"`{ip['ip_address']}` | Score:{ip['abuse_score']} "
                        f"| {ip.get('country_code', '-')} | {action}"
                    )
                if len(alerts) > 10:
                    alert_lines.append(
                        f"\n_...dan {len(alerts) - 10} IP lainnya. "
                        f"Gunakan /nullroute untuk daftar lengkap._"
                    )
                await bot.send_message(
                    chat_id=config.telegram_chat_id,
                    text="\n".join(alert_lines),
                    parse_mode="Markdown",
                )

    except Exception as exc:
        logger.exception("Scan failed: %s", exc)
        await finish_session(session_id, 0, 0, "failed")
        await bot.send_message(
            chat_id=config.telegram_chat_id,
            text=f"❌ Scan gagal: {exc}",
        )


async def job_midnight_notify(bot: Bot) -> None:
    """Send approval notification at midnight WIB. Auto-scan after 30 minutes if no response."""
    global _pending_scan

    token_ok = await validate_abuseipdb_token()
    token_status = "✅ Valid" if token_ok else "❌ Invalid"

    text = (
        f"🔔 *Scan AS{config.as_number} Siap Dimulai*\n\n"
        f"Token AbuseIPDB : {token_status}\n"
        f"VoidIP          : ⚠️ Mock (API belum tersedia)\n\n"
        f"Klik *Approve* untuk scan sekarang, atau scan akan otomatis dimulai "
        f"dalam *30 menit* jika tidak ada respons."
    )
    keyboard = InlineKeyboardMarkup([
        [
            InlineKeyboardButton("✅ Approve Scan", callback_data="approve_scan"),
            InlineKeyboardButton("⏭ Skip Scan", callback_data="skip_scan"),
        ]
    ])

    msg = await bot.send_message(
        chat_id=config.telegram_chat_id,
        text=text,
        parse_mode="Markdown",
        reply_markup=keyboard,
    )

    # Schedule auto-scan fallback after 30 minutes
    loop = asyncio.get_event_loop()
    task = loop.create_task(_auto_scan_fallback(bot, msg.message_id))
    _pending_scan = {"message_id": msg.message_id, "task": task}


async def _auto_scan_fallback(bot: Bot, message_id: int) -> None:
    """Wait 30 min then auto-scan if no manual response."""
    await asyncio.sleep(30 * 60)

    global _pending_scan
    if not _pending_scan:
        return

    _pending_scan = {}
    logger.info("Auto-scan triggered after 30-minute timeout")

    try:
        await bot.edit_message_text(
            chat_id=config.telegram_chat_id,
            message_id=message_id,
            text="⏰ Tidak ada respons 30 menit — scan otomatis dimulai...",
        )
    except Exception:
        pass

    await run_scan(bot)


async def handle_approval(bot: Bot, callback_data: str, message_id: int) -> str:
    """Called by bot.py callback handler. Returns status string."""
    global _pending_scan

    task = _pending_scan.get("task")
    _pending_scan = {}

    if task and not task.done():
        task.cancel()

    if callback_data == "approve_scan":
        asyncio.create_task(run_scan(bot))
        return "✅ Scan diapprove — dimulai sekarang!"
    else:
        return "⏭ Scan dibatalkan untuk malam ini."


async def job_morning_report(bot: Bot) -> None:
    """Send daily report at 09:00 WIB."""
    logger.info("Sending morning report")
    try:
        chunks = await build_daily_report()
        for chunk in chunks:
            await bot.send_message(
                chat_id=config.telegram_chat_id,
                text=chunk,
                parse_mode="Markdown",
            )
    except Exception as exc:
        logger.exception("Morning report failed: %s", exc)
        await bot.send_message(
            chat_id=config.telegram_chat_id,
            text=f"❌ Gagal kirim laporan pagi: {exc}",
        )


def setup_scheduler(bot: Bot) -> AsyncIOScheduler:
    loop = asyncio.get_running_loop()
    scheduler = AsyncIOScheduler(timezone="Asia/Jakarta")

    scheduler.add_job(
        lambda: asyncio.run_coroutine_threadsafe(job_midnight_notify(bot), loop),
        trigger=CronTrigger(hour=0, minute=0, timezone="Asia/Jakarta"),
        id="midnight_notify",
        replace_existing=True,
    )
    scheduler.add_job(
        lambda: asyncio.run_coroutine_threadsafe(job_morning_report(bot), loop),
        trigger=CronTrigger(hour=9, minute=0, timezone="Asia/Jakarta"),
        id="morning_report",
        replace_existing=True,
    )

    return scheduler

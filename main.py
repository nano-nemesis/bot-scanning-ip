import asyncio
import logging

from telegram.ext import Application

from bot import register_handlers
from config import config
from db import init_db
from scheduler import setup_scheduler


async def post_init(application: Application) -> None:
    await init_db()
    scheduler = setup_scheduler(application.bot)
    scheduler.start()
    logging.getLogger(__name__).info("Scheduler started. Bot is running.")


def main() -> None:
    logging.basicConfig(
        level=config.log_level,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    app = (
        Application.builder()
        .token(config.telegram_bot_token)
        .post_init(post_init)
        .build()
    )
    register_handlers(app)

    app.run_polling(drop_pending_updates=True)


if __name__ == "__main__":
    main()

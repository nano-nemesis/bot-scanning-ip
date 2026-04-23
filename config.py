from dataclasses import dataclass
from dotenv import load_dotenv
import os


@dataclass(frozen=True)
class Config:
    telegram_bot_token: str
    telegram_chat_id: str
    abuseipdb_api_key: str
    admin_user_ids: list
    as_number: str
    db_path: str
    max_age_days: int
    top_offenders_count: int
    scan_concurrency: int
    log_level: str
    alert_threshold: int
    nullroute_min_score: int


def load_config() -> Config:
    load_dotenv()

    required = ["TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID", "ABUSEIPDB_API_KEY"]
    missing = [k for k in required if not os.getenv(k)]
    if missing:
        raise ValueError(
            f"Missing required env vars: {', '.join(missing)}. Check your .env file."
        )

    raw_admins = os.getenv("ADMIN_USER_IDS", "")
    admin_ids = [int(x.strip()) for x in raw_admins.split(",") if x.strip().isdigit()]

    return Config(
        telegram_bot_token=os.environ["TELEGRAM_BOT_TOKEN"],
        telegram_chat_id=os.environ["TELEGRAM_CHAT_ID"],
        abuseipdb_api_key=os.environ["ABUSEIPDB_API_KEY"],
        admin_user_ids=admin_ids,
        as_number=os.getenv("AS_NUMBER", "AS211407"),
        db_path=os.getenv("DB_PATH", "data/scanner.db"),
        max_age_days=int(os.getenv("MAX_AGE_DAYS", "30")),
        top_offenders_count=int(os.getenv("TOP_OFFENDERS_COUNT", "20")),
        scan_concurrency=int(os.getenv("SCAN_CONCURRENCY", "3")),
        log_level=os.getenv("LOG_LEVEL", "INFO"),
        alert_threshold=int(os.getenv("ALERT_THRESHOLD", "80")),
        nullroute_min_score=int(os.getenv("NULLROUTE_MIN_SCORE", "50")),
    )


config = load_config()

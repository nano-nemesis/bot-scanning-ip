from dataclasses import dataclass
from dotenv import load_dotenv
import os


@dataclass(frozen=True)
class WebConfig:
    db_path: str
    admin_username: str
    admin_password_hash: str
    secret_key: str
    session_max_age: int
    host: str
    port: int
    debug: bool
    alert_threshold: int
    nullroute_min_score: int
    as_number: str


def load_web_config() -> WebConfig:
    load_dotenv()

    secret_key = os.getenv("WEB_SECRET_KEY", "")
    if not secret_key:
        raise ValueError(
            "WEB_SECRET_KEY is required. "
            "Generate with: python3 -c \"import secrets; print(secrets.token_hex(32))\""
        )

    return WebConfig(
        db_path=os.getenv("DB_PATH", "data/scanner.db"),
        admin_username=os.getenv("WEB_ADMIN_USERNAME", "admin"),
        admin_password_hash=os.getenv("WEB_ADMIN_PASSWORD_HASH", ""),
        secret_key=secret_key,
        session_max_age=int(os.getenv("WEB_SESSION_MAX_AGE", "86400")),
        host=os.getenv("WEB_HOST", "127.0.0.1"),
        port=int(os.getenv("WEB_PORT", "8080")),
        debug=os.getenv("WEB_DEBUG", "false").lower() == "true",
        alert_threshold=int(os.getenv("ALERT_THRESHOLD", "80")),
        nullroute_min_score=int(os.getenv("NULLROUTE_MIN_SCORE", "50")),
        as_number=os.getenv("AS_NUMBER", "AS211407"),
    )


web_config = load_web_config()

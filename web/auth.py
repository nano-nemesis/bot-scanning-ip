from fastapi import Request
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature

from web.config import web_config


class NotAuthenticated(Exception):
    pass


_serializer = URLSafeTimedSerializer(web_config.secret_key)


def create_session_token(username: str) -> str:
    return _serializer.dumps({"user": username})


def verify_session_token(token: str) -> str | None:
    try:
        data = _serializer.loads(token, max_age=web_config.session_max_age)
        return data.get("user")
    except (SignatureExpired, BadSignature, Exception):
        return None


async def require_auth(request: Request) -> str:
    token = request.cookies.get("session")
    if token:
        user = verify_session_token(token)
        if user:
            return user
    raise NotAuthenticated()


async def get_current_user(request: Request) -> str | None:
    token = request.cookies.get("session")
    if not token:
        return None
    return verify_session_token(token)

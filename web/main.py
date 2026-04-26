import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from db import init_db, init_web_users
from web.auth import NotAuthenticated
from web.config import web_config
from web.limiter import limiter
from web.routes import auth as auth_routes
from web.routes import dashboard as dashboard_routes
from web.routes import ips as ips_routes
from web.routes import sessions as sessions_routes
from web.routes import settings as settings_routes

_BASE = os.path.dirname(__file__)


def _register_filters(templates: Jinja2Templates) -> None:
    from datetime import datetime, timezone, timedelta

    def to_wib(iso_str: str | None) -> str:
        if not iso_str:
            return "—"
        try:
            wib = timezone(timedelta(hours=7))
            dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
            return dt.astimezone(wib).strftime("%d %b %Y, %H:%M WIB")
        except Exception:
            return str(iso_str)[:16]

    def country_flag(code: str | None) -> str:
        if not code or len(code) != 2:
            return "🌐"
        try:
            return "".join(chr(ord(c.upper()) - ord("A") + 0x1F1E6) for c in code)
        except Exception:
            return code

    import json as _json
    templates.env.filters["to_wib"] = to_wib
    templates.env.filters["country_flag"] = country_flag
    templates.env.filters["parse_json"] = lambda s: _json.loads(s) if s else []


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    await init_web_users(web_config.admin_username, web_config.admin_password_hash)
    yield


def create_app() -> FastAPI:
    app = FastAPI(
        title="IP Scanner Dashboard",
        docs_url=None,
        redoc_url=None,
        lifespan=lifespan,
    )

    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

    @app.exception_handler(NotAuthenticated)
    async def not_authenticated(_req: Request, _exc: NotAuthenticated):
        return RedirectResponse(url="/login", status_code=303)

    templates = Jinja2Templates(directory=os.path.join(_BASE, "templates"))
    _register_filters(templates)
    app.state.templates = templates

    static_dir = os.path.join(_BASE, "static")
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

    app.include_router(auth_routes.router)
    app.include_router(dashboard_routes.router)
    app.include_router(sessions_routes.router)
    app.include_router(ips_routes.router)
    app.include_router(settings_routes.router)

    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "web.main:app",
        host=web_config.host,
        port=web_config.port,
        reload=web_config.debug,
        proxy_headers=True,
        forwarded_allow_ips="127.0.0.1",
    )

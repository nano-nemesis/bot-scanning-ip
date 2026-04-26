import bcrypt
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse

from db import get_web_user_by_username
from web.auth import create_session_token, get_current_user
from web.config import web_config
from web.limiter import limiter

router = APIRouter()


@router.get("/login")
async def login_page(request: Request, user: str | None = Depends(get_current_user)):
    if user:
        return RedirectResponse(url="/", status_code=303)
    templates = request.app.state.templates
    msg = request.query_params.get("msg")
    return templates.TemplateResponse("login.html", {"request": request, "info": msg})


@router.post("/login")
@limiter.limit("5/15minutes")
async def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    templates = request.app.state.templates

    user_row = await get_web_user_by_username(username)
    valid = False
    if user_row:
        try:
            valid = bcrypt.checkpw(password.encode(), user_row["password_hash"].encode())
        except Exception:
            valid = False

    if valid:
        response = RedirectResponse(url="/", status_code=303)
        token = create_session_token(username)
        response.set_cookie(
            key="session",
            value=token,
            max_age=web_config.session_max_age,
            httponly=True,
            secure=web_config.cookie_secure,
            samesite="lax",
        )
        return response

    return templates.TemplateResponse(
        "login.html",
        {"request": request, "error": "Username atau password salah."},
        status_code=401,
    )


@router.post("/logout")
async def logout():
    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie("session")
    return response

import bcrypt
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse

from db import (
    count_web_users,
    create_web_user,
    delete_web_user,
    get_web_user_by_username,
    get_web_user_by_id,
    get_web_users,
    update_web_user_password,
    update_web_user_username,
)
from web.auth import create_session_token, require_auth
from web.config import web_config

router = APIRouter(prefix="/settings")


def _hash(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(12)).decode()


def _verify(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode(), hashed.encode())
    except Exception:
        return False


def _redirect(msg: str, ok: bool = True) -> RedirectResponse:
    kind = "ok" if ok else "err"
    return RedirectResponse(url=f"/settings?{kind}={msg}", status_code=303)


@router.get("")
async def settings_page(request: Request, user: str = Depends(require_auth)):
    templates = request.app.state.templates
    users = await get_web_users()
    current = await get_web_user_by_username(user)
    ok  = request.query_params.get("ok")
    err = request.query_params.get("err")
    return templates.TemplateResponse("settings.html", {
        "request": request,
        "current_user": user,
        "active_page": "settings",
        "as_number": web_config.as_number,
        "users": users,
        "current_id": current["id"] if current else None,
        "ok": ok,
        "err": err,
    })


@router.post("/change-password")
async def change_password(
    request: Request,
    current_password: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...),
    user: str = Depends(require_auth),
):
    user_row = await get_web_user_by_username(user)
    if not user_row:
        return _redirect("User+tidak+ditemukan", ok=False)

    if not _verify(current_password, user_row["password_hash"]):
        return _redirect("Password+lama+salah", ok=False)

    if len(new_password) < 8:
        return _redirect("Password+minimal+8+karakter", ok=False)

    if new_password != confirm_password:
        return _redirect("Konfirmasi+password+tidak+cocok", ok=False)

    await update_web_user_password(user_row["id"], _hash(new_password))
    return _redirect("Password+berhasil+diubah")


@router.post("/change-username")
async def change_username(
    request: Request,
    new_username: str = Form(...),
    password_confirm: str = Form(...),
    user: str = Depends(require_auth),
):
    user_row = await get_web_user_by_username(user)
    if not user_row:
        return _redirect("User+tidak+ditemukan", ok=False)

    if not _verify(password_confirm, user_row["password_hash"]):
        return _redirect("Password+salah", ok=False)

    new_username = new_username.strip()
    if len(new_username) < 3:
        return _redirect("Username+minimal+3+karakter", ok=False)

    if new_username == user:
        return _redirect("Username+tidak+berubah", ok=False)

    existing = await get_web_user_by_username(new_username)
    if existing:
        return _redirect("Username+sudah+dipakai", ok=False)

    ok = await update_web_user_username(user_row["id"], new_username)
    if not ok:
        return _redirect("Gagal+mengubah+username", ok=False)

    # Refresh session cookie dengan username baru
    response = _redirect("Username+berhasil+diubah")
    token = create_session_token(new_username)
    response.set_cookie(
        key="session", value=token,
        max_age=web_config.session_max_age,
        httponly=True, secure=web_config.cookie_secure, samesite="lax",
    )
    return response


@router.post("/add-user")
async def add_user(
    request: Request,
    new_username: str = Form(...),
    new_user_password: str = Form(...),
    user: str = Depends(require_auth),
):
    new_username = new_username.strip()
    if len(new_username) < 3:
        return _redirect("Username+minimal+3+karakter", ok=False)

    if len(new_user_password) < 8:
        return _redirect("Password+minimal+8+karakter", ok=False)

    existing = await get_web_user_by_username(new_username)
    if existing:
        return _redirect("Username+sudah+dipakai", ok=False)

    await create_web_user(new_username, _hash(new_user_password))
    return _redirect(f"User+%27{new_username}%27+berhasil+ditambahkan")


@router.post("/delete-user/{user_id}")
async def delete_user(
    request: Request,
    user_id: int,
    user: str = Depends(require_auth),
):
    target = await get_web_user_by_id(user_id)
    if not target:
        return _redirect("User+tidak+ditemukan", ok=False)

    if target["username"] == user:
        return _redirect("Tidak+bisa+hapus+akun+sendiri", ok=False)

    total = await count_web_users()
    if total <= 1:
        return _redirect("Minimal+harus+ada+1+user", ok=False)

    await delete_web_user(user_id)
    return _redirect(f"User+%27{target['username']}%27+dihapus")

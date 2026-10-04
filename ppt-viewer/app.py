"""PX4X — متعدد المستخدمين.

FastAPI backend with accounts:
  POST /api/register  {username, password}  -> create account + login
  POST /api/login     {username, password}  -> login
  POST /api/logout                       -> logout
  GET  /api/me                           -> current user
  GET  /api/files                        -> my files
  POST /api/upload                       -> upload to my space
  DELETE /api/files/{name}               -> delete my file
  GET  /files/{name}                     -> serve my file (login required)
  GET  /view?name=...                    -> viewer page (login required)
  POST /api/share/{name}                 -> create public share link
  GET  /s/{token}                        -> open shared file (no login)
"""
import hashlib
import json
import os
import re
import secrets
import sqlite3
import time
import urllib.parse
import urllib.request
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import quote

from fastapi import Cookie, FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

BASE = Path(__file__).parent
UPLOADS = BASE / "uploads"
UPLOADS.mkdir(exist_ok=True)
DB_PATH = BASE / "users.db"

ALLOWED = {".ppt", ".pptx", ".pdf", ".odp"}
MAX_BYTES = 200 * 1024 * 1024
SESSION_DAYS = 30

# Google OAuth (optional — set these as environment variables on Render)
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "").strip()
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "").strip()
_GOOGLE_STATES: dict[str, float] = {}  # state -> expiry timestamp

app = FastAPI(title="PX4X")

SAFE = re.compile(r"[^A-Za-z0-9\u0600-\u06FF _.\-()+]+")


# ------------------------------------------------------------------ database
def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute(
        """CREATE TABLE IF NOT EXISTS users(
             id INTEGER PRIMARY KEY AUTOINCREMENT,
             username TEXT UNIQUE NOT NULL,
             pw_hash TEXT NOT NULL,
             salt TEXT NOT NULL,
             created_at TEXT NOT NULL)"""
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS sessions(
             token TEXT PRIMARY KEY,
             user_id INTEGER NOT NULL,
             created_at TEXT NOT NULL,
             expires_at TEXT NOT NULL)"""
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS shares(
             token TEXT PRIMARY KEY,
             user_id INTEGER NOT NULL,
             filename TEXT NOT NULL,
             created_at TEXT NOT NULL)"""
    )
    return conn


def hash_pw(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 200_000).hex()


def user_dir(user_id: int) -> Path:
    d = UPLOADS / f"u_{user_id}"
    d.mkdir(exist_ok=True)
    return d


def get_user(session: str | None) -> dict | None:
    if not session:
        return None
    conn = db()
    try:
        row = conn.execute(
            "SELECT s.user_id, s.expires_at, u.username FROM sessions s "
            "JOIN users u ON u.id=s.user_id WHERE s.token=?",
            (session,),
        ).fetchone()
        if not row:
            return None
        if datetime.fromisoformat(row["expires_at"]) < datetime.utcnow():
            conn.execute("DELETE FROM sessions WHERE token=?", (session,))
            conn.commit()
            return None
        return {"id": row["user_id"], "username": row["username"]}
    finally:
        conn.close()


def require_user(session: str | None) -> dict:
    user = get_user(session)
    if not user:
        raise HTTPException(401, "سجّل الدخول أولاً")
    return user


def safe_name(name: str) -> str:
    name = os.path.basename(name)
    name = SAFE.sub("", name).strip().strip(".") or "file"
    return name[:150]


def human(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def file_info(p: Path) -> dict:
    st = p.stat()
    return {
        "name": p.name,
        "size": st.st_size,
        "size_h": human(st.st_size),
        "uploaded_at": time.strftime("%Y-%m-%d %H:%M", time.localtime(st.st_mtime)),
        "ext": p.suffix.lower(),
    }


# ------------------------------------------------------------------ auth API
class AuthBody(BaseModel):
    username: str
    password: str


def _new_session(conn, user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    now = datetime.utcnow()
    conn.execute(
        "INSERT INTO sessions(token,user_id,created_at,expires_at) VALUES(?,?,?,?)",
        (token, user_id, now.isoformat(), (now + timedelta(days=SESSION_DAYS)).isoformat()),
    )
    conn.commit()
    return token


@app.post("/api/register")
async def register(body: AuthBody):
    username = body.username.strip()
    if not (3 <= len(username) <= 60) or not re.fullmatch(r"[A-Za-z0-9_.@\u0600-\u06FF-]+", username):
        raise HTTPException(400, "اسم المستخدم: 3-60 حرف (أحرف/أرقام فقط)")
    if not (4 <= len(body.password) <= 72):
        raise HTTPException(400, "كلمة المرور: 4 أحرف على الأقل")
    salt = secrets.token_hex(16)
    conn = db()
    try:
        try:
            cur = conn.execute(
                "INSERT INTO users(username,pw_hash,salt,created_at) VALUES(?,?,?,?)",
                (username, hash_pw(body.password, salt), salt, datetime.utcnow().isoformat()),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            raise HTTPException(409, "اسم المستخدم موجود — جرّب اسماً ثانياً")
        user_id = cur.lastrowid
        token = _new_session(conn, user_id)
    finally:
        conn.close()
    from fastapi.responses import JSONResponse

    resp = JSONResponse({"ok": True, "username": username})
    resp.set_cookie("session", token, max_age=SESSION_DAYS * 86400, httponly=True, samesite="lax")
    return resp


@app.post("/api/login")
async def login(body: AuthBody):
    conn = db()
    try:
        row = conn.execute("SELECT * FROM users WHERE username=?", (body.username.strip(),)).fetchone()
        if not row or hash_pw(body.password, row["salt"]) != row["pw_hash"]:
            raise HTTPException(401, "اسم المستخدم أو كلمة المرور غلط")
        token = _new_session(conn, row["id"])
    finally:
        conn.close()
    from fastapi.responses import JSONResponse

    resp = JSONResponse({"ok": True, "username": row["username"]})
    resp.set_cookie("session", token, max_age=SESSION_DAYS * 86400, httponly=True, samesite="lax")
    return resp


@app.post("/api/logout")
async def logout(session: str | None = Cookie(default=None)):
    if session:
        conn = db()
        try:
            conn.execute("DELETE FROM sessions WHERE token=?", (session,))
            conn.commit()
        finally:
            conn.close()
    from fastapi.responses import JSONResponse

    resp = JSONResponse({"ok": True})
    resp.delete_cookie("session")
    return resp


@app.get("/api/me")
async def me(session: str | None = Cookie(default=None)):
    user = get_user(session)
    if not user:
        raise HTTPException(401, "guest")
    return {"username": user["username"]}


@app.get("/api/config")
async def config():
    return {"google_enabled": bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET)}


# ------------------------------------------------------------------ Google OAuth
def _google_redirect_uri(request: Request) -> str:
    return str(request.base_url).rstrip("/") + "/auth/google/callback"


@app.get("/auth/google")
async def google_login(request: Request):
    if not (GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET):
        raise HTTPException(400, "تسجيل الدخول بـ Google غير مفعّل")
    state = secrets.token_urlsafe(24)
    _GOOGLE_STATES[state] = time.time() + 600
    params = {
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": _google_redirect_uri(request),
        "response_type": "code",
        "scope": "openid email profile",
        "state": state,
        "prompt": "select_account",
    }
    url = "https://accounts.google.com/o/oauth2/v2/auth?" + urllib.parse.urlencode(params)
    return RedirectResponse(url)


@app.get("/auth/google/callback")
async def google_callback(request: Request, code: str = "", state: str = ""):
    if not (GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET):
        raise HTTPException(400, "تسجيل الدخول بـ Google غير مفعّل")
    exp = _GOOGLE_STATES.pop(state, 0)
    if not state or exp < time.time():
        raise HTTPException(400, "انتهت صلاحية الطلب — حاول مجدداً")
    if not code:
        raise HTTPException(400, "تم إلغاء تسجيل الدخول")

    # exchange code for tokens
    data = urllib.parse.urlencode(
        {
            "code": code,
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "redirect_uri": _google_redirect_uri(request),
            "grant_type": "authorization_code",
        }
    ).encode()
    try:
        req = urllib.request.Request("https://oauth2.googleapis.com/token", data=data)
        token_res = json.loads(urllib.request.urlopen(req, timeout=20).read())
        access = token_res.get("access_token")
        if not access:
            raise ValueError("no access token")
        ureq = urllib.request.Request(
            "https://www.googleapis.com/oauth2/v2/userinfo",
            headers={"Authorization": f"Bearer {access}"},
        )
        profile = json.loads(urllib.request.urlopen(ureq, timeout=20).read())
        email = (profile.get("email") or "").strip().lower()
        if not email:
            raise ValueError("no email")
    except Exception:
        raise HTTPException(502, "فشل التواصل مع Google — حاول مجدداً")

    conn = db()
    try:
        row = conn.execute("SELECT * FROM users WHERE username=?", (email,)).fetchone()
        if row:
            user_id = row["id"]
        else:
            salt = secrets.token_hex(16)
            cur = conn.execute(
                "INSERT INTO users(username,pw_hash,salt,created_at) VALUES(?,?,?,?)",
                (email, hash_pw(secrets.token_urlsafe(32), salt), salt, datetime.utcnow().isoformat()),
            )
            conn.commit()
            user_id = cur.lastrowid
        token = _new_session(conn, user_id)
    finally:
        conn.close()

    resp = RedirectResponse("/", status_code=302)
    resp.set_cookie("session", token, max_age=SESSION_DAYS * 86400, httponly=True, samesite="lax")
    return resp


# ------------------------------------------------------------------ files API
@app.get("/api/files")
async def list_files(session: str | None = Cookie(default=None)):
    user = require_user(session)
    d = user_dir(user["id"])
    files = sorted(
        (p for p in d.glob("*") if p.is_file() and not p.name.startswith(".")),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    return {"files": [file_info(p) for p in files]}


@app.post("/api/upload")
async def upload(session: str | None = Cookie(default=None), file: UploadFile = File(...)):
    user = require_user(session)
    ext = os.path.splitext(file.filename or "")[1].lower()
    if ext not in ALLOWED:
        raise HTTPException(400, f"صيغة غير مدعومة. المسموح: {', '.join(sorted(ALLOWED))}")
    name = safe_name(file.filename or "file")
    d = user_dir(user["id"])
    dest = d / name
    if dest.exists():
        stem, suffix = os.path.splitext(name)
        i = 2
        while (d / f"{stem} ({i}){suffix}").exists():
            i += 1
        name = f"{stem} ({i}){suffix}"
        dest = d / name
    size = 0
    with dest.open("wb") as out:
        while True:
            chunk = await file.read(1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > MAX_BYTES:
                dest.unlink(missing_ok=True)
                raise HTTPException(413, "الملف أكبر من 200MB")
            out.write(chunk)
    return {"ok": True, "file": file_info(dest)}


@app.delete("/api/files/{name}")
async def delete_file(name: str, session: str | None = Cookie(default=None)):
    user = require_user(session)
    target = user_dir(user["id"]) / safe_name(name)
    if not target.exists() or not target.is_file():
        raise HTTPException(404, "الملف غير موجود")
    target.unlink()
    conn = db()
    try:
        conn.execute("DELETE FROM shares WHERE user_id=? AND filename=?", (user["id"], target.name))
        conn.commit()
    finally:
        conn.close()
    return {"ok": True}


@app.get("/files/{name}")
async def serve_file(name: str, session: str | None = Cookie(default=None)):
    user = require_user(session)
    target = user_dir(user["id"]) / safe_name(name)
    if not target.exists() or not target.is_file():
        raise HTTPException(404, "الملف غير موجود")
    return FileResponse(target)


# ------------------------------------------------------------------ sharing
@app.post("/api/share/{name}")
async def create_share(name: str, session: str | None = Cookie(default=None)):
    user = require_user(session)
    target = user_dir(user["id"]) / safe_name(name)
    if not target.exists() or not target.is_file():
        raise HTTPException(404, "الملف غير موجود")
    token = secrets.token_urlsafe(16)
    conn = db()
    try:
        conn.execute(
            "INSERT INTO shares(token,user_id,filename,created_at) VALUES(?,?,?,?)",
            (token, user["id"], target.name, datetime.utcnow().isoformat()),
        )
        conn.commit()
    finally:
        conn.close()
    return {"ok": True, "token": token}


@app.get("/s/{token}", response_class=HTMLResponse)
async def open_share(token: str, request: Request):
    conn = db()
    try:
        row = conn.execute("SELECT * FROM shares WHERE token=?", (token,)).fetchone()
    finally:
        conn.close()
    if not row:
        raise HTTPException(404, "رابط المشاركة غير صالح")
    target = user_dir(row["user_id"]) / row["filename"]
    if not target.exists():
        raise HTTPException(404, "الملف غير موجود")
    base = str(request.base_url).rstrip("/")
    file_url = f"{base}/dl/{token}/{quote(target.name)}"
    viewer = "https://view.officeapps.live.com/op/embed.aspx?src=" + quote(file_url, safe="")
    return f"""<!DOCTYPE html>
<html lang="ar" dir="rtl"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>مشاركة: {target.name}</title>
<style>*{{box-sizing:border-box;font-family:"Segoe UI",Tahoma,Arial,sans-serif}}
body{{margin:0;background:#0f1420;color:#f1f4fa;height:100vh;display:flex;flex-direction:column}}
header{{background:#1a2233;padding:12px 16px;display:flex;align-items:center;gap:12px}}
header span{{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
header a{{color:#fff;text-decoration:none;background:#7b2ff7;padding:8px 16px;border-radius:8px}}
iframe{{flex:1;border:0;width:100%}}</style></head>
<body>
<header><span>🔗 {target.name}</span>
<a href="/dl/{token}/{quote(target.name)}" download>⬇ تحميل</a></header>
<iframe src="{viewer}" allowfullscreen></iframe>
</body></html>"""


@app.get("/dl/{token}/{name}")
async def download_share(token: str, name: str):
    conn = db()
    try:
        row = conn.execute("SELECT * FROM shares WHERE token=?", (token,)).fetchone()
    finally:
        conn.close()
    if not row:
        raise HTTPException(404, "رابط المشاركة غير صالح")
    target = user_dir(row["user_id"]) / row["filename"]
    if not target.exists():
        raise HTTPException(404, "الملف غير موجود")
    return FileResponse(target, filename=target.name)


# ------------------------------------------------------------------ viewer
@app.get("/view", response_class=HTMLResponse)
async def view_page(request: Request, name: str, session: str | None = Cookie(default=None)):
    user = require_user(session)
    target = user_dir(user["id"]) / safe_name(name)
    if not target.exists() or not target.is_file():
        raise HTTPException(404, "الملف غير موجود")
    base = str(request.base_url).rstrip("/")
    file_url = f"{base}/files/{quote(target.name)}"
    viewer = "https://view.officeapps.live.com/op/embed.aspx?src=" + quote(file_url, safe="")
    return f"""<!DOCTYPE html>
<html lang="ar" dir="rtl"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>عرض: {target.name}</title>
<style>*{{box-sizing:border-box;font-family:"Segoe UI",Tahoma,Arial,sans-serif}}
body{{margin:0;background:#0f1420;color:#f1f4fa;height:100vh;display:flex;flex-direction:column}}
header{{background:#1a2233;padding:10px 16px;display:flex;align-items:center;gap:12px}}
header a{{color:#f1f4fa;text-decoration:none;background:#33405c;padding:8px 16px;border-radius:8px}}
header span{{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
iframe{{flex:1;border:0;width:100%}}
.note{{padding:6px 16px;font-size:12px;color:#9aa7c2;background:#141b2c}}</style></head>
<body>
<header><a href="/">⬅ رجوع</a><span>📊 {target.name}</span>
<a href="/files/{quote(target.name)}" download>⬇ تحميل</a></header>
<iframe src="{viewer}" allowfullscreen></iframe>
<div class="note">المعاينة عبر عارض Microsoft — تحتاج اتصال إنترنت ورابطاً عاماً (على Render تعمل، وعلى جهازك المحلي قد لا تظهر).</div>
</body></html>"""


@app.get("/api/health")
async def health():
    return {"ok": True}


static_dir = BASE / "static"
if static_dir.exists():
    app.mount("/", StaticFiles(directory=str(static_dir), html=True), name="static")

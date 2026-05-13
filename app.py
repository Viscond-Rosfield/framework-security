"""
Framework de Seguranca - Aplicacao FastAPI.

Como rodar localmente:
    uvicorn app:app --reload --host 0.0.0.0 --port 8000

Em producao (Render): start command = uvicorn app:app --host 0.0.0.0 --port $PORT
"""
from __future__ import annotations

import secrets
import uuid
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Request, UploadFile, File, HTTPException, Depends, status
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import aiofiles

import config
from core.aggregator import scan_file


app = FastAPI(
    title="Framework de Seguranca",
    description="Analisa arquivos contra multiplos servicos de deteccao de malware.",
    version="0.1.0",
)

BASE_DIR = Path(__file__).resolve().parent
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=BASE_DIR / "templates")


# ---- Autenticacao HTTP Basic ----
security = HTTPBasic(auto_error=False)


def authenticate(credentials: Optional[HTTPBasicCredentials] = Depends(security)) -> str:
    if not config.AUTH_ENABLED:
        return "anonymous"
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciais necessarias",
            headers={"WWW-Authenticate": "Basic"},
        )
    ok_user = secrets.compare_digest(credentials.username, config.APP_USERNAME)
    ok_pass = secrets.compare_digest(credentials.password, config.APP_PASSWORD)
    if not (ok_user and ok_pass):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciais invalidas",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username


async def _save_upload(file: UploadFile) -> Path:
    if not file.filename:
        raise HTTPException(400, "Arquivo invalido")
    unique_id = uuid.uuid4().hex
    safe_name = f"{unique_id}_{Path(file.filename).name}"
    dest = config.UPLOAD_DIR / safe_name
    total = 0
    async with aiofiles.open(dest, "wb") as out:
        while chunk := await file.read(1024 * 1024):
            total += len(chunk)
            if total > config.MAX_FILE_SIZE_BYTES:
                await out.close()
                dest.unlink(missing_ok=True)
                raise HTTPException(413, f"Arquivo excede {config.MAX_FILE_SIZE_MB} MB.")
            await out.write(chunk)
    return dest


@app.get("/", response_class=HTMLResponse)
async def index(request: Request, user: str = Depends(authenticate)):
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "scanners": config.scanner_status(),
            "max_size_mb": config.MAX_FILE_SIZE_MB,
            "user": user,
        },
    )


@app.post("/scan", response_class=HTMLResponse)
async def scan(request: Request, file: UploadFile = File(...), user: str = Depends(authenticate)):
    dest = await _save_upload(file)
    try:
        report = await scan_file(dest, original_name=file.filename)
    finally:
        dest.unlink(missing_ok=True)
    return templates.TemplateResponse(
        "results.html",
        {"request": request, "report": report, "user": user},
    )


@app.post("/api/scan")
async def api_scan(file: UploadFile = File(...), user: str = Depends(authenticate)):
    dest = await _save_upload(file)
    try:
        report = await scan_file(dest, original_name=file.filename)
    finally:
        dest.unlink(missing_ok=True)
    return JSONResponse(report)


@app.get("/healthz")
async def health():
    return {
        "status": "ok",
        "scanners": config.scanner_status(),
        "auth_enabled": config.AUTH_ENABLED,
    }

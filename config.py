"""
Configuracoes centrais do Framework de Seguranca.
Carrega variaveis do .env e expoe constantes para o resto do projeto.
"""
import os
from pathlib import Path
from dotenv import load_dotenv

# Carrega o .env (se existir) na raiz do projeto
BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")


# ---------------------------------------------------------------------------
# Chaves de API
# ---------------------------------------------------------------------------
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
METADEFENDER_API_KEY = os.getenv("METADEFENDER_API_KEY", "").strip()


# ---------------------------------------------------------------------------
# Autenticacao (HTTP Basic)
# ---------------------------------------------------------------------------
APP_USERNAME = os.getenv("APP_USERNAME", "admin").strip()
APP_PASSWORD = os.getenv("APP_PASSWORD", "").strip()
# Em producao exigimos senha. Em dev, se ficar vazio, a auth e desabilitada.
AUTH_ENABLED = bool(APP_PASSWORD)


# ---------------------------------------------------------------------------
# Configuracoes gerais
# ---------------------------------------------------------------------------
MAX_FILE_SIZE_MB = int(os.getenv("MAX_FILE_SIZE_MB", "32"))
MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024

UPLOAD_DIR = BASE_DIR / os.getenv("UPLOAD_DIR", "uploads")
UPLOAD_DIR.mkdir(exist_ok=True)

# Timeout padrao (segundos) para requisicoes HTTP
HTTP_TIMEOUT = 30


# ---------------------------------------------------------------------------
# Cache / Historico (SQLite)
# ---------------------------------------------------------------------------
# Em Render free tier o disco e efemero -> reseta no deploy. Para persistir,
# upgrade para plan starter e adicione disco, ou migre para Postgres.
DATABASE_PATH = Path(os.getenv("DATABASE_PATH", str(BASE_DIR / "data" / "scans.db")))
DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)

# TTL do cache em horas (0 = desabilita o cache, sempre re-scaneia)
CACHE_TTL_HOURS = int(os.getenv("CACHE_TTL_HOURS", "24"))


# ---------------------------------------------------------------------------
# LLM Analyst (Claude via Anthropic API) - opcional
# ---------------------------------------------------------------------------
# Quando configurado, o app envia o relatorio agregado para Claude e recebe
# de volta uma analise em prosa em portugues, com recomendacoes.
# Modelo padrao: Claude Haiku (rapido e barato, ~$0.003 por scan).
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "").strip()
LLM_MODEL = os.getenv("LLM_MODEL", "claude-haiku-4-5-20251001").strip()
LLM_ENABLED = bool(ANTHROPIC_API_KEY)
LLM_MAX_TOKENS = int(os.getenv("LLM_MAX_TOKENS", "1500"))


def scanner_status() -> dict:
    """Retorna quais scanners estao habilitados (com base nas chaves configuradas)."""
    return {
        "virustotal": bool(VIRUSTOTAL_API_KEY),
        "metadefender": bool(METADEFENDER_API_KEY),
        "local": True,
    }

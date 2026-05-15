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
# Autenticacao (HTTP Basic - suporta multi-user)
# ---------------------------------------------------------------------------
# Modo simples (1 usuario): APP_USERNAME + APP_PASSWORD
# Modo multi-user: APP_USERS no formato "user1:pass1,user2:pass2,user3:pass3"
APP_USERNAME = os.getenv("APP_USERNAME", "admin").strip()
APP_PASSWORD = os.getenv("APP_PASSWORD", "").strip()
APP_USERS_RAW = os.getenv("APP_USERS", "").strip()


def _parse_users() -> dict[str, str]:
    """Combina APP_USERS + APP_USERNAME/APP_PASSWORD num unico dict."""
    users: dict[str, str] = {}
    # 1) Parsing de APP_USERS (multi-user)
    if APP_USERS_RAW:
        for pair in APP_USERS_RAW.split(","):
            pair = pair.strip()
            if ":" in pair:
                u, p = pair.split(":", 1)
                u = u.strip()
                p = p.strip()
                if u and p:
                    users[u] = p
    # 2) Backwards compat: APP_USERNAME + APP_PASSWORD entra como mais 1 user
    if APP_PASSWORD and APP_USERNAME:
        users.setdefault(APP_USERNAME, APP_PASSWORD)
    return users


APP_USERS = _parse_users()
# Em producao exigimos pelo menos 1 user. Em dev (sem nenhum), auth desabilitada.
AUTH_ENABLED = bool(APP_USERS)


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

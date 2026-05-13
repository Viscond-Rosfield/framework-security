"""
Configurações centrais do Framework de Segurança.
Carrega variáveis do .env e expõe constantes para o resto do projeto.
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
HYBRID_ANALYSIS_API_KEY = os.getenv("HYBRID_ANALYSIS_API_KEY", "").strip()


# ---------------------------------------------------------------------------
# Autenticação (HTTP Basic)
# ---------------------------------------------------------------------------
APP_USERNAME = os.getenv("APP_USERNAME", "admin").strip()
APP_PASSWORD = os.getenv("APP_PASSWORD", "").strip()
# Em produção exigimos senha. Em dev, se ficar vazio, a auth é desabilitada.
AUTH_ENABLED = bool(APP_PASSWORD)


# ---------------------------------------------------------------------------
# Configurações gerais
# ---------------------------------------------------------------------------
MAX_FILE_SIZE_MB = int(os.getenv("MAX_FILE_SIZE_MB", "32"))
MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024

UPLOAD_DIR = BASE_DIR / os.getenv("UPLOAD_DIR", "uploads")
UPLOAD_DIR.mkdir(exist_ok=True)

# Timeout padrão (segundos) para requisições HTTP
HTTP_TIMEOUT = 30


def scanner_status() -> dict:
    """Retorna quais scanners estão habilitados (com base nas chaves configuradas)."""
    return {
        "virustotal": bool(VIRUSTOTAL_API_KEY),
        "metadefender": bool(METADEFENDER_API_KEY),
        "hybrid_analysis": bool(HYBRID_ANALYSIS_API_KEY),
        "local": True,  # análise local sempre disponível
    }

"""
Extracao de strings printaveis + deteccao de IOCs (Indicators of Compromise).

Funciona pra QUALQUER tipo de arquivo, nao so PE.
"""
from __future__ import annotations
import re
from typing import Iterable


# Regexes pra extrair strings printaveis
_ASCII_RE   = re.compile(rb"[\x20-\x7e]{4,}")        # ASCII >= 4 chars
_UTF16_RE   = re.compile(rb"(?:[\x20-\x7e]\x00){4,}") # UTF-16-LE >= 4 chars

# Regexes de IOCs
_URL_RE       = re.compile(r"\b(?:https?|ftp)://[^\s\"'<>]{4,200}", re.IGNORECASE)
_IPV4_RE      = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN_RE    = re.compile(r"\b(?:[a-z0-9-]{1,63}\.){1,4}[a-z]{2,24}\b", re.IGNORECASE)
_EMAIL_RE     = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_PATH_WIN_RE  = re.compile(r"\b[A-Z]:\\\\?(?:[^\\\\/:*?\"<>|\r\n]+\\\\?){1,8}", re.IGNORECASE)
_REGISTRY_RE  = re.compile(r"\b(?:HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT)\\\\[^\s\"'<>]{3,200}", re.IGNORECASE)
_MUTEX_RE     = re.compile(r"\b(?:Global|Local)\\\\[A-Za-z0-9_\-]{3,60}\b")

# Filtros pra evitar falsos positivos
_PRIVATE_IP_NETWORKS = (
    "0.", "10.", "127.", "169.254.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.",
    "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "192.168.", "224.", "255.",
)

_BENIGN_DOMAINS = {
    "microsoft.com", "windows.com", "msdn.com", "msftncsi.com",
    "schemas.microsoft.com", "schemas.openxmlformats.org",
    "w3.org", "verisign.com", "digicert.com", "sectigo.com", "symantec.com",
}


def extract_strings(data: bytes, max_strings: int = 5000) -> list[str]:
    """Extrai strings ASCII e UTF-16-LE de >=4 chars do conteudo bruto."""
    out: list[str] = []
    for m in _ASCII_RE.finditer(data):
        out.append(m.group().decode("ascii", errors="replace"))
        if len(out) >= max_strings:
            return out
    for m in _UTF16_RE.finditer(data):
        try:
            s = m.group().decode("utf-16-le", errors="replace").rstrip("\x00")
            if s:
                out.append(s)
        except Exception:
            continue
        if len(out) >= max_strings:
            return out
    return out


def extract_iocs(strings: Iterable[str]) -> dict[str, list[str]]:
    """Recebe lista de strings e retorna IOCs unicos por categoria."""
    urls: set[str] = set()
    ips: set[str] = set()
    domains: set[str] = set()
    emails: set[str] = set()
    paths: set[str] = set()
    registry: set[str] = set()
    mutex: set[str] = set()

    for s in strings:
        for m in _URL_RE.findall(s):
            urls.add(m)
        for m in _IPV4_RE.findall(s):
            if _is_interesting_ip(m):
                ips.add(m)
        for m in _DOMAIN_RE.findall(s):
            d = m.lower()
            if _is_interesting_domain(d):
                domains.add(d)
        for m in _EMAIL_RE.findall(s):
            emails.add(m)
        for m in _PATH_WIN_RE.findall(s):
            paths.add(m)
        for m in _REGISTRY_RE.findall(s):
            registry.add(m)
        for m in _MUTEX_RE.findall(s):
            mutex.add(m)

    # Limites pra nao explodir UI
    return {
        "urls":     sorted(urls)[:50],
        "ips":      sorted(ips)[:50],
        "domains":  sorted(domains)[:50],
        "emails":   sorted(emails)[:30],
        "paths":    sorted(paths)[:30],
        "registry": sorted(registry)[:30],
        "mutex":    sorted(mutex)[:20],
    }


def _is_interesting_ip(ip: str) -> bool:
    """Filtra IPs invalidos (octeto >255) ou privados/reservados."""
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        if any(int(p) > 255 for p in parts):
            return False
    except ValueError:
        return False
    for prefix in _PRIVATE_IP_NETWORKS:
        if ip.startswith(prefix):
            return False
    return True


_KNOWN_TLDS = {
    "com", "net", "org", "io", "co", "ai", "dev", "app", "info", "biz",
    "br", "us", "uk", "ca", "de", "fr", "ru", "cn", "jp", "in", "au",
    "eu", "mx", "es", "it", "nl", "ch", "se", "no", "fi", "dk", "pl",
    "tr", "kr", "tw", "hk", "sg", "id", "vn", "th", "ph", "my", "ae",
    "sa", "za", "ng", "ke", "eg", "il", "ar", "cl", "co", "pe", "ve",
    "gov", "edu", "mil", "int", "xyz", "online", "site", "tech", "shop",
    "store", "blog", "cloud", "host", "press", "agency", "global",
    "to", "ly", "tv", "me", "cc", "ws", "fm", "tk", "ml", "ga", "cf",
    "club", "today", "world", "life", "live", "media", "design",
    "academy", "support", "solutions", "services", "systems",
}

def _is_interesting_domain(d: str) -> bool:
    """Filtra TLDs falsos e dominios obviamente benignos."""
    if d in _BENIGN_DOMAINS:
        return False
    tld = d.rsplit(".", 1)[-1].lower()
    # TLD precisa estar na whitelist (filtra ruido como .dll, .vth, .tmp)
    if tld not in _KNOWN_TLDS:
        return False
    # Dominio precisa ter pelo menos 4 chars antes do TLD
    label = d[: -(len(tld) + 1)]
    if len(label) < 3 or "." in label and len(label.replace(".", "")) < 4:
        return False
    return True

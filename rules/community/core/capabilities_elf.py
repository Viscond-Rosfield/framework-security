"""
Mapeia symbols importados de ELFs (Linux/BSD binaries) em capacidades.

Diferente de Win32, Linux usa:
- libc (glibc/musl) - funcoes core
- pthread - threading
- libssl/libcrypto - crypto
- libcurl - networking
- syscalls diretos (raros mas suspeitos)
"""
from __future__ import annotations
from typing import Iterable


# Mapeamento simbolo Linux -> capacidade
CAPABILITY_FUNCTIONS = {
    # ---------- Network ----------
    "network": {
        # libc socket API
        "socket", "connect", "send", "recv", "sendto", "recvfrom",
        "bind", "listen", "accept", "accept4", "shutdown",
        "setsockopt", "getsockopt", "getsockname", "getpeername",
        # DNS
        "gethostbyname", "getaddrinfo", "res_query", "res_search",
        # libcurl
        "curl_easy_init", "curl_easy_setopt", "curl_easy_perform",
        # libssl
        "SSL_connect", "SSL_write", "SSL_read",
        # raw send
        "sendfile",
    },

    # ---------- Process injection / control ----------
    "process_injection": {
        # ptrace - usado pra inject em outro processo (e anti-debug)
        "ptrace",
        # shared memory pra inject
        "shmget", "shmat", "shmdt",
        # mmap com PROT_EXEC eh suspeito quando combinado
        "mprotect",  # muda permissoes (RWX)
    },

    # ---------- Dynamic loading ----------
    "dynamic_loading": {
        "dlopen", "dlsym", "dlclose", "dlmopen",
        "__libc_dlopen_mode",
    },

    # ---------- Persistence ----------
    "persistence_filesystem": {
        # cron / systemd
        "system",  # frequentemente usado pra executar shell
        "popen",
    },

    # ---------- Anti-debug ----------
    "anti_debug": {
        "ptrace",  # PTRACE_TRACEME e detect tecnica classica
        "personality",
        "prctl",  # pode setar PR_SET_DUMPABLE=0
    },

    # ---------- Filesystem ----------
    "filesystem": {
        "open", "openat", "creat", "close",
        "read", "write", "readv", "writev",
        "unlink", "unlinkat", "rmdir",
        "rename", "renameat",
        "chmod", "fchmod", "chown", "fchown",
        "stat", "fstat", "lstat", "stat64",
        "mkdir", "mkdirat",
        "opendir", "readdir", "closedir",
    },

    # ---------- Process management ----------
    "process_management": {
        "fork", "vfork", "clone", "clone3",
        "execve", "execv", "execvp", "execvpe", "execl", "execle", "execlp",
        "exit", "_exit", "exit_group",
        "wait", "waitpid", "wait3", "wait4",
        "kill", "tgkill", "tkill",
        "system", "popen",
        "setsid", "setpgid", "setpgrp",  # daemon tricks
        "daemon",
    },

    # ---------- Crypto ----------
    "crypto": {
        # openssl
        "EVP_EncryptInit_ex", "EVP_EncryptUpdate", "EVP_EncryptFinal_ex",
        "EVP_DecryptInit_ex", "EVP_DecryptUpdate", "EVP_DecryptFinal_ex",
        "EVP_CIPHER_CTX_new", "EVP_CipherInit_ex",
        "RSA_new", "RSA_generate_key_ex",
        "AES_set_encrypt_key", "AES_encrypt", "AES_cbc_encrypt",
        "SHA256_Init", "SHA256_Update", "SHA256_Final",
        # libcrypto rand
        "RAND_bytes",
    },

    # ---------- Keystrokes / input ----------
    "keystrokes": {
        # X11 keyloggers
        "XOpenDisplay", "XQueryKeymap", "XSelectInput", "XGrabKeyboard",
        # libinput / evdev (newer)
        "libinput_dispatch", "libinput_get_event",
    },

    # ---------- Privileges ----------
    "privileges": {
        "setuid", "setgid", "seteuid", "setegid",
        "setresuid", "setresgid",
        "setcap", "capset", "capget",
        "chroot",
    },

    # ---------- Memory manipulation ----------
    "memory_manipulation": {
        "mmap", "mmap64", "munmap", "mprotect", "mremap",
        "memfd_create",  # usado pra fileless attacks
        "ftruncate",
    },

    # ---------- Anti-VM (heuristicas) ----------
    "anti_vm": {
        # checa /sys/class/dmi/* via fopen
        "uname",
        "sysinfo",
    },

    # ---------- Kernel modules ----------
    "kernel_module": {
        "init_module", "delete_module", "finit_module",
        "create_module",
    },
}


CAPABILITY_META = {
    "network": {
        "label": "Comunicação de rede",
        "severity": "medium",
        "description": "Faz I/O de rede via sockets, libcurl ou SSL. Pode ser benigno ou C2 de malware.",
    },
    "process_injection": {
        "label": "Manipulação de processos via ptrace / SHM",
        "severity": "high",
        "description": "Usa ptrace ou shared memory — técnicas para injetar código em processos vivos. Comum em rootkits Linux.",
    },
    "dynamic_loading": {
        "label": "Carregamento dinâmico (dlopen)",
        "severity": "medium",
        "description": "Carrega bibliotecas em runtime — pode esconder imports da análise estática.",
    },
    "persistence_filesystem": {
        "label": "Execução de shell / system",
        "severity": "medium",
        "description": "Usa system()/popen() para executar comandos do shell. Frequente em droppers.",
    },
    "anti_debug": {
        "label": "Anti-debugging (ptrace tricks)",
        "severity": "high",
        "description": "Usa ptrace ou prctl para detectar/bloquear debuggers. Indicativo forte de malware.",
    },
    "filesystem": {
        "label": "Operações de arquivo",
        "severity": "low",
        "description": "Lê, escreve, lista arquivos. Quase todo programa faz — útil em conjunto.",
    },
    "process_management": {
        "label": "Gerenciamento de processos",
        "severity": "medium",
        "description": "Cria/mata processos (fork, execve, kill). Comum em malware multi-stage.",
    },
    "crypto": {
        "label": "Criptografia (OpenSSL)",
        "severity": "medium",
        "description": "Usa APIs de criptografia. Ransomware Linux ou C2 cifrado.",
    },
    "keystrokes": {
        "label": "Captura de teclado (X11)",
        "severity": "high",
        "description": "Hooks de teclado via X11. Característica de keylogger Linux.",
    },
    "privileges": {
        "label": "Manipulação de privilégios / chroot",
        "severity": "high",
        "description": "Altera UID/GID/capabilities ou usa chroot. Tentativa de escalada ou sandbox escape.",
    },
    "memory_manipulation": {
        "label": "Manipulação avançada de memória",
        "severity": "medium",
        "description": "Aloca memória executável (mmap+mprotect), memfd_create para fileless. Suspeito em binários simples.",
    },
    "anti_vm": {
        "label": "Detecção de ambiente",
        "severity": "low",
        "description": "Inspeciona sistema (uname/sysinfo) — pode ser anti-VM ou só info gathering.",
    },
    "kernel_module": {
        "label": "Carregamento de módulo kernel",
        "severity": "high",
        "description": "Tenta inserir módulo no kernel — rootkit clássico Linux.",
    },
}


def detect_capabilities_elf(imported_symbols: Iterable[str]) -> list[dict]:
    """Recebe symbols ELF e devolve lista de capacidades, ordenada por severidade."""
    syms = set(imported_symbols)
    detected = []

    sev_order = {"high": 0, "medium": 1, "low": 2}

    for cap_id, signature in CAPABILITY_FUNCTIONS.items():
        matched = sorted(syms & signature)
        if not matched:
            continue
        meta = CAPABILITY_META.get(cap_id, {})
        detected.append({
            "id": cap_id,
            "label": meta.get("label", cap_id),
            "severity": meta.get("severity", "low"),
            "description": meta.get("description", ""),
            "matched_functions": matched,
            "match_count": len(matched),
        })

    detected.sort(key=lambda c: (sev_order[c["severity"]], -c["match_count"]))
    return detected

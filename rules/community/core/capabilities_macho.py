"""
Capabilities para Mach-O binaries (macOS).

Mac usa muito framework de alto nivel:
- Foundation (NSString, NSURL, NSTask, etc.)
- AppKit (UI)
- CoreServices (filesystem, launch)
- Security (keychain, crypto)
- CoreGraphics (screen capture, eventos)
- IOKit (hardware)
- libSystem (libc + posix)

Detectamos via symbols importados e via dylib names usados.
"""
from __future__ import annotations
from typing import Iterable


CAPABILITY_FUNCTIONS = {
    # ---------- Network ----------
    "network": {
        # BSD sockets
        "socket", "connect", "send", "recv", "sendto", "recvfrom",
        "bind", "listen", "accept",
        # libcurl
        "curl_easy_init", "curl_easy_setopt", "curl_easy_perform",
        # CFNetwork
        "CFReadStreamCreateWithFTPURL", "CFHTTPMessageCreateRequest",
        "CFHTTPMessageSetBody",
        # NSURLSession / NSURLConnection
        "NSURLSession", "NSURLConnection", "NSURLRequest",
        "dataTaskWithRequest", "downloadTaskWithRequest",
        # Resolver
        "gethostbyname", "getaddrinfo",
    },

    # ---------- Process injection / control ----------
    "process_injection": {
        # task_for_pid - acesso ao espaco de outro processo
        "task_for_pid", "task_for_pid_with_audit_token",
        # mach_vm_* - memoria de outro processo
        "mach_vm_read", "mach_vm_write", "mach_vm_allocate",
        "mach_vm_protect", "mach_vm_deallocate",
        "mach_vm_remap", "mach_thread_set_state",
        # ptrace
        "ptrace",
        # thread creation em outro processo
        "thread_create", "thread_create_running",
    },

    # ---------- Dynamic loading ----------
    "dynamic_loading": {
        "dlopen", "dlsym", "dlclose",
        "NSAddImage", "NSLookupSymbolInImage",
        "_dyld_register_func_for_add_image",
    },

    # ---------- Persistence (LaunchAgents / Daemons) ----------
    "persistence_launch": {
        # LaunchServices - login items
        "LSSharedFileListInsertItemURL", "LSSharedFileListCreate",
        # ScriptingBridge / AppleScript pra adicionar login items
        "NSAppleScript",
    },

    # ---------- Anti-debug ----------
    "anti_debug": {
        "ptrace",
        "sysctlbyname",  # detecta debugger via sysctl
        "sysctl",
        "mach_task_self",
        "task_get_exception_ports",  # checa exception ports - tecnica anti-debug
    },

    # ---------- Anti-VM ----------
    "anti_vm": {
        "IORegistryEntryCreateCFProperty",
        "IOServiceMatching",
    },

    # ---------- Filesystem ----------
    "filesystem": {
        "open", "openat", "close", "read", "write",
        "unlink", "rename", "stat", "fstat", "lstat",
        "chmod", "chown", "fopen", "fclose", "fread", "fwrite",
        # NSFileManager
        "NSFileManager",
        # Foundation
        "writeToFile", "createFileAtPath",
    },

    # ---------- Process management ----------
    "process_management": {
        "fork", "vfork", "execve", "exec",
        "posix_spawn", "posix_spawnp",
        "system", "popen",
        # NSTask
        "NSTask", "launchPath",
        # waitpid
        "wait", "waitpid",
        "kill",
    },

    # ---------- Crypto ----------
    "crypto": {
        # CommonCrypto
        "CCCryptorCreate", "CCCryptorUpdate", "CCCryptorFinal",
        "CCCrypt", "CCHmac",
        # Security framework
        "SecKeyCreateWithData", "SecKeyEncryptedData",
        "SecKeychainAddInternetPassword", "SecItemCopyMatching",
        # CommonHash
        "CC_SHA256_Init", "CC_MD5_Init",
    },

    # ---------- Keystrokes (keylogger) ----------
    "keystrokes": {
        # CGEvent
        "CGEventTapCreate", "CGEventTapEnable",
        "CGEventGetIntegerValueField",
        # IOHIDManager
        "IOHIDManagerCreate", "IOHIDManagerRegisterInputValueCallback",
        # NSEvent
        "NSEventModifierFlagCommand",
    },

    # ---------- Screen capture ----------
    "screen_capture": {
        "CGWindowListCreateImage", "CGDisplayCreateImage",
        "CGDisplayCreateImageForRect",
    },

    # ---------- Clipboard ----------
    "clipboard": {
        "NSPasteboard", "PBPasteboardRef",
        "writeObjects", "readObjectsForClasses",
    },

    # ---------- Code injection via DYLD ----------
    "code_injection_dyld": {
        "dyld_dynamic_interpose",
        # nao tem symbol direto, mas presenca de "DYLD_INSERT_LIBRARIES" nas strings indica
    },

    # ---------- Privileges ----------
    "privileges": {
        # Authorization Services - elevacao de privilegio
        "AuthorizationCreate", "AuthorizationCopyRights",
        "AuthorizationExecuteWithPrivileges",
        # POSIX
        "setuid", "setgid", "seteuid", "setegid",
        "setresuid",
    },

    # ---------- System info / fingerprinting ----------
    "system_info": {
        "sysctlbyname", "sysctl",
        "Gestalt",
        "_NSGetExecutablePath",
        # IOKit - hardware fingerprint
        "IOServiceMatching", "IOServiceGetMatchingServices",
    },

    # ---------- Kernel extensions (kext) ----------
    "kext_loading": {
        "KextManagerLoadKextWithURL",
        "KextManagerCreateLoadedKextInfo",
    },
}


CAPABILITY_META = {
    "network": {
        "label": "Comunicação de rede",
        "severity": "medium",
        "description": "Usa BSD sockets, libcurl, CFNetwork ou NSURLSession para comunicação de rede.",
    },
    "process_injection": {
        "label": "Injeção em processos (task_for_pid / mach_vm)",
        "severity": "high",
        "description": "Usa Mach APIs pra ler/escrever memória de outros processos. Técnica clássica de injection no macOS — exige privilégio (root + entitlement).",
    },
    "dynamic_loading": {
        "label": "Carregamento dinâmico (dlopen)",
        "severity": "medium",
        "description": "Carrega bibliotecas em runtime. Pode esconder imports da análise estática.",
    },
    "persistence_launch": {
        "label": "Persistência (LaunchServices / login items)",
        "severity": "high",
        "description": "Manipula LaunchAgents/login items. Técnica clássica de persistência em macOS.",
    },
    "anti_debug": {
        "label": "Anti-debugging (ptrace / sysctl)",
        "severity": "high",
        "description": "Usa ptrace PT_DENY_ATTACH ou sysctl pra detectar/bloquear debuggers.",
    },
    "anti_vm": {
        "label": "Detecção de ambiente (IORegistry)",
        "severity": "medium",
        "description": "Inspeciona IORegistry pra detectar VMware/VirtualBox/Parallels.",
    },
    "filesystem": {
        "label": "Operações de arquivo",
        "severity": "low",
        "description": "Lê, escreve, lista arquivos. Quase todo programa faz.",
    },
    "process_management": {
        "label": "Gerenciamento de processos (NSTask / posix_spawn)",
        "severity": "medium",
        "description": "Lança ou termina outros processos. Comum em droppers e multi-stage.",
    },
    "crypto": {
        "label": "Criptografia (CommonCrypto / Security)",
        "severity": "medium",
        "description": "Usa APIs de criptografia. Em malware: ransomware ou C2 cifrado.",
    },
    "keystrokes": {
        "label": "Captura de teclado (CGEvent / IOHID)",
        "severity": "high",
        "description": "Hooks de teclado via CGEventTap ou IOHIDManager. Característica de keylogger macOS.",
    },
    "screen_capture": {
        "label": "Captura de tela (CGWindowListCreateImage)",
        "severity": "high",
        "description": "Tira screenshots do desktop. Spyware/RAT clássico.",
    },
    "clipboard": {
        "label": "Acesso ao clipboard (NSPasteboard)",
        "severity": "medium",
        "description": "Lê/escreve área de transferência. Usado para roubar credenciais coladas ou clipboard hijacking.",
    },
    "code_injection_dyld": {
        "label": "DYLD injection",
        "severity": "high",
        "description": "Tenta injetar dylib via DYLD_INSERT_LIBRARIES ou dyld_dynamic_interpose. Técnica antiga mas ainda funcional.",
    },
    "privileges": {
        "label": "Elevação de privilégio (Authorization Services)",
        "severity": "high",
        "description": "Usa Authorization Services pra pedir privilégios elevados. Visto em malware que pede senha admin.",
    },
    "system_info": {
        "label": "Coleta de informação do sistema",
        "severity": "low",
        "description": "Coleta info via sysctl/IOKit. Pode ser fingerprint ou anti-VM.",
    },
    "kext_loading": {
        "label": "Carregamento de kernel extension",
        "severity": "high",
        "description": "Tenta carregar kext (módulo kernel). Rootkit clássico — exige assinatura no macOS moderno.",
    },
}


def detect_capabilities_macho(symbols: Iterable[str]) -> list[dict]:
    """Mapeia symbols Mach-O em capacidades."""
    syms = set(symbols)
    detected = []
    sev_order = {"high": 0, "medium": 1, "low": 2}

    for cap_id, sig in CAPABILITY_FUNCTIONS.items():
        matched = sorted(syms & sig)
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

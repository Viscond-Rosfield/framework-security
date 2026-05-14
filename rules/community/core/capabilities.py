"""
Mapeia imports de PE (funcoes da Win32 API) em CAPACIDADES amigaveis.

A ideia: em vez de mostrar "VirtualAlloc, WriteProcessMemory, CreateRemoteThread",
mostrar "[ALTA] Process injection".

Cada capacidade tem:
- id: chave interna (ex: process_injection)
- label: texto amigavel em portugues
- severity: low|medium|high
- description: o que isso significa
- matched_functions: as funcoes encontradas no binario
"""
from __future__ import annotations
from typing import Iterable


# Mapeamento de funcao Win32 -> categoria de capacidade
# Mantemos como dict {capability_id: set_of_function_names}
CAPABILITY_FUNCTIONS = {
    "process_injection": {
        "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
        "WriteProcessMemory", "ReadProcessMemory",
        "CreateRemoteThread", "CreateRemoteThreadEx", "NtCreateThreadEx",
        "RtlCreateUserThread", "QueueUserAPC", "NtQueueApcThread",
        "SetWindowsHookExA", "SetWindowsHookExW",
        "SetThreadContext", "GetThreadContext", "SuspendThread", "ResumeThread",
        "OpenProcess", "ZwUnmapViewOfSection", "NtUnmapViewOfSection",
    },
    "dynamic_loading": {
        "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW",
        "GetProcAddress", "LdrLoadDll", "LdrGetProcedureAddress",
    },
    "network": {
        "InternetOpenA", "InternetOpenW", "InternetOpenUrlA", "InternetOpenUrlW",
        "InternetReadFile", "InternetWriteFile", "InternetConnectA", "InternetConnectW",
        "HttpOpenRequestA", "HttpOpenRequestW", "HttpSendRequestA", "HttpSendRequestW",
        "URLDownloadToFileA", "URLDownloadToFileW",
        "WinHttpOpen", "WinHttpConnect", "WinHttpOpenRequest", "WinHttpSendRequest",
        "socket", "connect", "send", "recv", "bind", "listen", "accept",
        "WSAStartup", "WSASocketA", "WSASocketW",
        "gethostbyname", "getaddrinfo", "inet_addr", "htons",
        "DnsQuery_A", "DnsQuery_W",
    },
    "persistence_registry": {
        "RegSetValueExA", "RegSetValueExW",
        "RegCreateKeyExA", "RegCreateKeyExW",
        "RegOpenKeyExA", "RegOpenKeyExW",
        "RegDeleteValueA", "RegDeleteValueW",
        "RegDeleteKeyA", "RegDeleteKeyW",
    },
    "persistence_service": {
        "CreateServiceA", "CreateServiceW",
        "OpenSCManagerA", "OpenSCManagerW",
        "ChangeServiceConfigA", "ChangeServiceConfigW",
        "StartServiceA", "StartServiceW",
    },
    "anti_debug": {
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess", "NtSetInformationThread",
        "OutputDebugStringA", "OutputDebugStringW",
        "GetTickCount", "GetTickCount64", "QueryPerformanceCounter",
        "FindWindowA", "FindWindowW",  # comum buscar janelas de debuggers
    },
    "anti_vm": {
        "GetSystemFirmwareTable",  # busca tabelas BIOS pra detectar VM
        "CPUID",  # via inline assembly tambem detecta VM
    },
    "filesystem": {
        "CreateFileA", "CreateFileW",
        "WriteFile", "ReadFile",
        "DeleteFileA", "DeleteFileW",
        "CopyFileA", "CopyFileW", "MoveFileA", "MoveFileW",
        "FindFirstFileA", "FindFirstFileW", "FindNextFileA", "FindNextFileW",
        "GetTempPathA", "GetTempPathW",
        "SetFileAttributesA", "SetFileAttributesW",
    },
    "process_management": {
        "CreateProcessA", "CreateProcessW",
        "CreateProcessAsUserA", "CreateProcessAsUserW",
        "OpenProcess", "TerminateProcess",
        "EnumProcesses", "Process32First", "Process32Next",
        "ShellExecuteA", "ShellExecuteW", "ShellExecuteExA", "ShellExecuteExW",
        "WinExec",
    },
    "crypto": {
        "CryptEncrypt", "CryptDecrypt",
        "CryptDeriveKey", "CryptGenKey", "CryptImportKey", "CryptExportKey",
        "CryptHashData", "CryptCreateHash",
        "CryptAcquireContextA", "CryptAcquireContextW",
        "BCryptEncrypt", "BCryptDecrypt", "BCryptDeriveKey", "BCryptGenerateSymmetricKey",
    },
    "keystrokes": {
        "GetAsyncKeyState", "GetKeyState", "GetKeyboardState",
        "SetWindowsHookExA", "SetWindowsHookExW",  # WH_KEYBOARD_LL
        "RegisterHotKey",
    },
    "screen_capture": {
        "BitBlt", "CreateCompatibleBitmap", "CreateCompatibleDC",
        "GetDC", "GetWindowDC", "GetDesktopWindow",
    },
    "clipboard": {
        "OpenClipboard", "GetClipboardData", "SetClipboardData",
    },
    "privileges": {
        "AdjustTokenPrivileges", "OpenProcessToken", "LookupPrivilegeValueA",
        "LookupPrivilegeValueW", "ImpersonateLoggedOnUser",
    },
}


# Descricoes amigaveis (mostradas na UI)
CAPABILITY_META = {
    "process_injection": {
        "label": "Injeção de processo",
        "severity": "high",
        "description": "O arquivo possui APIs típicas de injeção de código em outros processos — técnica usada por trojans, RATs e ransomware pra rodar código dentro de processos legítimos e escapar de detecção.",
    },
    "dynamic_loading": {
        "label": "Carregamento dinâmico de DLLs",
        "severity": "medium",
        "description": "Carrega bibliotecas em runtime via LoadLibrary/GetProcAddress. Pode ser benigno (plugins) ou usado para esconder imports suspeitos da análise estática.",
    },
    "network": {
        "label": "Comunicação de rede",
        "severity": "medium",
        "description": "Faz requisições HTTP/sockets. Pode ser legítimo (instalador, updater) ou C2 de malware.",
    },
    "persistence_registry": {
        "label": "Persistência via registry",
        "severity": "medium",
        "description": "Modifica chaves do registro do Windows. Comum em malware pra rodar no startup via Run, RunOnce, etc.",
    },
    "persistence_service": {
        "label": "Persistência via serviços",
        "severity": "high",
        "description": "Cria ou manipula serviços do Windows. Técnica avançada de persistência, normalmente requer privilégio elevado.",
    },
    "anti_debug": {
        "label": "Anti-debugging",
        "severity": "high",
        "description": "Tenta detectar se está sendo analisado (debugger, sandbox). Indicativo forte de malware tentando esconder comportamento.",
    },
    "anti_vm": {
        "label": "Anti-VM",
        "severity": "high",
        "description": "Tenta identificar se está rodando em máquina virtual. Malware avançado costuma encerrar se detectar VM.",
    },
    "filesystem": {
        "label": "Operações de arquivo",
        "severity": "low",
        "description": "Cria, modifica ou apaga arquivos no disco. Quase todo programa faz isso — útil junto com outros sinais.",
    },
    "process_management": {
        "label": "Gerenciamento de processos",
        "severity": "medium",
        "description": "Cria, lista ou termina outros processos. Comum em malware pra lançar payloads ou matar processos de AV.",
    },
    "crypto": {
        "label": "Criptografia",
        "severity": "medium",
        "description": "Usa APIs de criptografia. Em malware, frequentemente associado a ransomware (criptografar vítimas) ou ofuscação de comunicação C2.",
    },
    "keystrokes": {
        "label": "Captura de teclado",
        "severity": "high",
        "description": "Monitora teclas pressionadas. Característica clássica de keylogger.",
    },
    "screen_capture": {
        "label": "Captura de tela",
        "severity": "high",
        "description": "Tira screenshots do desktop. Usado por spyware e RATs.",
    },
    "clipboard": {
        "label": "Acesso ao clipboard",
        "severity": "medium",
        "description": "Lê ou escreve no área de transferência. Usado para roubar senhas/carteiras coladas, ou para 'clipboard hijacking' (substituir endereços de cripto).",
    },
    "privileges": {
        "label": "Manipulação de privilégios",
        "severity": "high",
        "description": "Eleva ou ajusta privilégios do token. Indica tentativa de escalada de privilégios.",
    },
}


def detect_capabilities(imported_functions: Iterable[str]) -> list[dict]:
    """
    Recebe um iterável de nomes de funções importadas e retorna a lista
    de capacidades detectadas, ordenadas por severidade (high -> low).
    """
    funcs = set(imported_functions)
    detected = []

    severity_order = {"high": 0, "medium": 1, "low": 2}

    for cap_id, signature_funcs in CAPABILITY_FUNCTIONS.items():
        matched = sorted(funcs & signature_funcs)
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

    detected.sort(key=lambda c: (severity_order[c["severity"]], -c["match_count"]))
    return detected

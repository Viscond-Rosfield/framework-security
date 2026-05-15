"""
Mapeia Android permissions em capacidades de alto nivel.

Permissions sao a interface central de seguranca no Android. Cada uma
representa um poder concedido ao app pelo usuario / sistema.
"""
from __future__ import annotations
from typing import Iterable


# Permission -> (capability_id, label, severity)
# Severity considera o contexto de malware (banking trojans, spyware, RATs):
PERMISSION_MAP = {
    # ----- SMS hijacking (2FA bypass, banking trojan) -----
    "android.permission.READ_SMS":     ("sms_hijacking",  "Ler SMS",     "high"),
    "android.permission.SEND_SMS":     ("sms_hijacking",  "Enviar SMS",  "high"),
    "android.permission.RECEIVE_SMS":  ("sms_hijacking",  "Receber SMS", "high"),
    "android.permission.READ_MMS":     ("sms_hijacking",  "Ler MMS",     "medium"),
    "android.permission.RECEIVE_MMS":  ("sms_hijacking",  "Receber MMS", "medium"),
    "android.permission.RECEIVE_WAP_PUSH": ("sms_hijacking", "Receber WAP push (operadora)", "high"),

    # ----- Calls -----
    "android.permission.READ_CALL_LOG":    ("phone_spy", "Ler historico de chamadas", "medium"),
    "android.permission.WRITE_CALL_LOG":   ("phone_spy", "Modificar historico de chamadas", "high"),
    "android.permission.CALL_PHONE":       ("phone_spy", "Fazer chamadas (premium SMS)", "high"),
    "android.permission.PROCESS_OUTGOING_CALLS": ("phone_spy", "Interceptar chamadas saindo", "high"),
    "android.permission.READ_PHONE_STATE":  ("phone_spy", "Ler estado do telefone (IMEI, numero)", "medium"),
    "android.permission.READ_PHONE_NUMBERS": ("phone_spy", "Ler numero do telefone", "medium"),
    "android.permission.ANSWER_PHONE_CALLS": ("phone_spy", "Atender chamadas", "high"),

    # ----- Spyware / data theft -----
    "android.permission.RECORD_AUDIO":  ("spyware_audio", "Gravar audio (microfone)", "high"),
    "android.permission.CAMERA":        ("spyware_camera","Acessar camera", "high"),
    "android.permission.ACCESS_FINE_LOCATION":   ("spyware_location", "Localizacao GPS precisa",  "high"),
    "android.permission.ACCESS_COARSE_LOCATION": ("spyware_location", "Localizacao aproximada",   "medium"),
    "android.permission.ACCESS_BACKGROUND_LOCATION": ("spyware_location", "Localizacao em background", "high"),

    # ----- Contacts, accounts -----
    "android.permission.READ_CONTACTS":  ("data_theft", "Ler contatos",   "high"),
    "android.permission.WRITE_CONTACTS": ("data_theft", "Modificar contatos", "high"),
    "android.permission.GET_ACCOUNTS":   ("data_theft", "Listar contas do dispositivo", "medium"),

    # ----- Storage -----
    "android.permission.READ_EXTERNAL_STORAGE":  ("filesystem", "Ler armazenamento externo", "medium"),
    "android.permission.WRITE_EXTERNAL_STORAGE": ("filesystem", "Escrever armazenamento externo", "medium"),
    "android.permission.MANAGE_EXTERNAL_STORAGE": ("filesystem", "Gerenciar todo armazenamento", "high"),
    "android.permission.READ_MEDIA_IMAGES":     ("filesystem", "Ler imagens", "medium"),
    "android.permission.READ_MEDIA_VIDEO":      ("filesystem", "Ler videos", "medium"),
    "android.permission.READ_MEDIA_AUDIO":      ("filesystem", "Ler audios", "medium"),

    # ----- Overlay attacks (banking trojan classico) -----
    "android.permission.SYSTEM_ALERT_WINDOW":   ("overlay_attack", "Desenhar sobre outros apps", "high"),

    # ----- Accessibility abuse (banker classico) -----
    "android.permission.BIND_ACCESSIBILITY_SERVICE": ("accessibility_abuse", "Servico de Acessibilidade", "high"),
    "android.permission.GET_TASKS":                  ("accessibility_abuse", "Listar apps abertos (legacy)", "medium"),

    # ----- Notifications -----
    "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE": ("notif_spy", "Ler todas notificacoes", "high"),
    "android.permission.POST_NOTIFICATIONS": ("notif_spy", "Postar notificacoes", "low"),

    # ----- Persistence -----
    "android.permission.RECEIVE_BOOT_COMPLETED":  ("persistence", "Rodar ao boot",          "medium"),
    "android.permission.WAKE_LOCK":               ("persistence", "Impedir dormir",         "low"),
    "android.permission.FOREGROUND_SERVICE":      ("persistence", "Servico em foreground",  "low"),
    "android.permission.SCHEDULE_EXACT_ALARM":    ("persistence", "Alarmes precisos",       "low"),

    # ----- Device admin (anti-removal) -----
    "android.permission.BIND_DEVICE_ADMIN":   ("device_admin", "Device admin (impede uninstall)", "high"),

    # ----- Install other APKs -----
    "android.permission.INSTALL_PACKAGES":         ("install_apps", "Instalar APKs (sistema)", "high"),
    "android.permission.REQUEST_INSTALL_PACKAGES": ("install_apps", "Pedir pra instalar APKs", "high"),
    "android.permission.DELETE_PACKAGES":          ("install_apps", "Desinstalar apps",        "high"),
    "android.permission.REQUEST_DELETE_PACKAGES":  ("install_apps", "Pedir desinstalar apps",  "medium"),

    # ----- Query apps installed (detection evasion) -----
    "android.permission.QUERY_ALL_PACKAGES":  ("recon", "Listar todos apps instalados", "medium"),

    # ----- Network -----
    "android.permission.INTERNET":             ("network", "Acesso a internet", "low"),
    "android.permission.ACCESS_NETWORK_STATE": ("network", "Estado da rede",    "low"),
    "android.permission.ACCESS_WIFI_STATE":   ("network", "Estado do Wi-Fi",   "low"),
    "android.permission.CHANGE_WIFI_STATE":   ("network", "Mudar Wi-Fi",       "medium"),
    "android.permission.CHANGE_NETWORK_STATE": ("network", "Mudar rede",       "medium"),

    # ----- Critical privileged -----
    "android.permission.WRITE_SECURE_SETTINGS": ("privileged", "Modificar configuracoes seguras", "high"),
    "android.permission.WRITE_SETTINGS":        ("privileged", "Modificar configuracoes",        "medium"),
    "android.permission.MOUNT_UNMOUNT_FILESYSTEMS": ("privileged", "Mount/unmount FS",            "high"),
    "android.permission.REBOOT":                ("privileged", "Reiniciar dispositivo",          "high"),
    "android.permission.SHUTDOWN":              ("privileged", "Desligar dispositivo",           "high"),

    # ----- VPN / connect -----
    "android.permission.BIND_VPN_SERVICE": ("vpn", "Criar conexao VPN (pode interceptar trafego)", "high"),
}


CAPABILITY_DESCRIPTIONS = {
    "sms_hijacking":  "Permissoes de SMS - clássico em banking trojans pra interceptar 2FA.",
    "phone_spy":      "Acesso a dados de telefonia (chamadas, IMEI, etc). Stalkerware/spyware.",
    "spyware_audio":  "Pode gravar audio do microfone - spyware/RAT clássico.",
    "spyware_camera": "Pode tirar fotos/video sem indicacao - spyware/RAT.",
    "spyware_location": "Rastreia localizacao GPS - stalkerware/tracking.",
    "data_theft":     "Acesso a contatos/contas - exfiltracao de dados pessoais.",
    "filesystem":     "Acesso a armazenamento - pode ler/exfiltrar arquivos.",
    "overlay_attack": "Pode desenhar sobre outros apps - banking trojans usam pra criar telas falsas.",
    "accessibility_abuse": "Servico de Acessibilidade - poder TOTAL (clicar, ler tela). Banker classico no Brasil.",
    "notif_spy":      "Le todas notificacoes - intercepta 2FA, mensagens.",
    "persistence":    "Mecanismos de persistencia (boot, foreground, alarmes).",
    "device_admin":   "Device Admin - impede desinstalacao normal. Ransomware mobile.",
    "install_apps":   "Pode instalar/desinstalar outros APKs - dropper.",
    "recon":          "Lista todos apps instalados - detecta AVs, decide proxima acao.",
    "network":        "Acesso a rede - basico mas necessario pra C2.",
    "privileged":     "Modifica configuracoes do sistema - exige privilegio elevado.",
    "vpn":            "Cria VPN - pode interceptar todo trafego do dispositivo.",
}


CAPABILITY_SEVERITY = {
    "sms_hijacking":        "high",
    "phone_spy":            "high",
    "spyware_audio":        "high",
    "spyware_camera":       "high",
    "spyware_location":     "high",
    "data_theft":           "high",
    "filesystem":           "medium",
    "overlay_attack":       "high",
    "accessibility_abuse":  "high",
    "notif_spy":            "high",
    "persistence":          "medium",
    "device_admin":         "high",
    "install_apps":         "high",
    "recon":                "medium",
    "network":              "low",
    "privileged":           "high",
    "vpn":                  "high",
}


def detect_capabilities_android(permissions: Iterable[str]) -> list[dict]:
    """Agrupa permissions por categoria, com severidade do grupo."""
    grouped = {}

    for perm in permissions:
        if perm in PERMISSION_MAP:
            cap_id, label, sev = PERMISSION_MAP[perm]
            grouped.setdefault(cap_id, []).append({
                "permission": perm,
                "label": label,
                "severity": sev,
            })

    detected = []
    sev_order = {"high": 0, "medium": 1, "low": 2}
    for cap_id, perms in grouped.items():
        detected.append({
            "id": cap_id,
            "label": cap_id.replace("_", " ").title(),
            "severity": CAPABILITY_SEVERITY.get(cap_id, "medium"),
            "description": CAPABILITY_DESCRIPTIONS.get(cap_id, ""),
            "permissions": perms,
            "match_count": len(perms),
        })

    detected.sort(key=lambda c: (sev_order[c["severity"]], -c["match_count"]))
    return detected

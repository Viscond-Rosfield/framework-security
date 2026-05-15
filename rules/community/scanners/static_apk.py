"""
Static analysis para APK (Android applications).

APK = arquivo ZIP com layout especifico:
- AndroidManifest.xml  (binary AXML)
- classes.dex          (Dalvik bytecode)
- resources.arsc
- META-INF/            (assinatura)
- lib/                 (native .so libraries)
- res/                 (resources)

Usamos androguard pra parsear AXML (formato binario propio).
"""
from __future__ import annotations
import zipfile
from pathlib import Path
from typing import Any

from core.capabilities_android import detect_capabilities_android


async def scan_static_apk(file_path: str | Path) -> dict[str, Any]:
    file_path = Path(file_path)

    try:
        with open(file_path, "rb") as f:
            head = f.read(4)
    except Exception as e:
        return {"status": "error", "error": f"Falha ao ler: {e}"}

    # APK comeca com PK (ZIP). Filtro inicial.
    if not head.startswith(b"PK"):
        return {"status": "skipped", "reason": "Nao e ZIP/APK"}

    # Eh ZIP, mas eh APK? Checa pela presenca de AndroidManifest.xml
    try:
        with zipfile.ZipFile(str(file_path)) as zf:
            names = zf.namelist()
    except Exception as e:
        return {"status": "error", "error": f"Zip invalido: {e}"}

    if "AndroidManifest.xml" not in names:
        return {"status": "skipped", "reason": "ZIP sem AndroidManifest.xml (nao e APK)"}

    try:
        from androguard.core.apk import APK
    except ImportError:
        return {"status": "error", "error": "androguard nao instalado"}

    try:
        apk = APK(str(file_path))
    except Exception as e:
        return {"status": "error", "error": f"APK parse: {e}"}

    return _analyze(apk, names)


def _analyze(apk, zip_names: list) -> dict[str, Any]:
    # Metadata basico
    package = apk.get_package() or ""
    app_name = apk.get_app_name() or ""
    main_activity = apk.get_main_activity() or ""

    try:
        version_code = apk.get_androidversion_code()
        version_name = apk.get_androidversion_name()
    except Exception:
        version_code = None
        version_name = None

    try:
        min_sdk = apk.get_min_sdk_version()
        target_sdk = apk.get_target_sdk_version()
        max_sdk = apk.get_max_sdk_version()
    except Exception:
        min_sdk = target_sdk = max_sdk = None

    # Permissions
    permissions = list(apk.get_permissions() or [])

    # Activities, services, receivers, providers
    activities = list(apk.get_activities() or [])
    services   = list(apk.get_services() or [])
    receivers  = list(apk.get_receivers() or [])
    providers  = list(apk.get_providers() or [])

    # Native libs
    native_libs = sorted({n for n in zip_names if n.startswith("lib/") and n.endswith(".so")})

    # DEX files (multi-dex apk pode ter classes.dex + classes2.dex + ...)
    dex_files = sorted([n for n in zip_names if n.endswith(".dex")])

    # Assets (frequente em packers)
    asset_files = [n for n in zip_names if n.startswith("assets/")][:20]

    # Certificate info
    cert_info = []
    try:
        for cert in apk.get_certificates_der_v2() or []:
            cert_info.append({"version": "v2", "len": len(cert)})
    except Exception:
        pass
    try:
        for cert in (apk.get_certificates() or []):
            cert_info.append({
                "subject": str(getattr(cert, 'subject', '')),
                "issuer":  str(getattr(cert, 'issuer', '')),
            })
    except Exception:
        pass

    # Detecta packers Android conhecidos por nomes de classes/libs
    detected_packers = []
    packer_signatures = {
        "libsecexe.so":     "Bangcle (Tencent)",
        "libsecmain.so":    "Bangcle (Tencent)",
        "libDexHelper.so":  "Bangcle/Secshell",
        "libjiagu.so":      "Qihoo 360 Jiagu",
        "libjiagu_a64.so":  "Qihoo 360 Jiagu",
        "libapkprotect2.so":"ApkProtect",
        "libnsecure.so":    "Naga Cipher",
    }
    for lib in native_libs:
        for sig, packer in packer_signatures.items():
            if sig in lib:
                detected_packers.append(packer)
    detected_packers = sorted(set(detected_packers))

    # Capabilities
    capabilities = detect_capabilities_android(permissions)

    # Flags
    flags = []
    if len(dex_files) > 1:
        flags.append(f"Multi-DEX ({len(dex_files)} arquivos) - comum em apps grandes mas tb em bankers/packers")
    if detected_packers:
        flags.append(f"Packer Android detectado: {', '.join(detected_packers)}")
    if "android.permission.BIND_ACCESSIBILITY_SERVICE" in permissions:
        flags.append("ACESSIBILIDADE: permissao usada por bankers BR (Brata, BasBanke) pra automacao na vitima")
    if "android.permission.SYSTEM_ALERT_WINDOW" in permissions and any(
        p in permissions for p in ("android.permission.READ_SMS", "android.permission.BIND_ACCESSIBILITY_SERVICE")
    ):
        flags.append("Combinacao OVERLAY + SMS/ACESSIBILIDADE = banking trojan classico")
    if "android.permission.REQUEST_INSTALL_PACKAGES" in permissions:
        flags.append("Pode instalar outros APKs - dropper")
    if "android.permission.BIND_DEVICE_ADMIN" in permissions:
        flags.append("Pede Device Admin - tipico de ransomware mobile")

    # Scoring
    high_caps   = [c for c in capabilities if c["severity"] == "high"]
    medium_caps = [c for c in capabilities if c["severity"] == "medium"]

    detections = 0
    suspicious = len(high_caps) + len(medium_caps)
    if detected_packers:
        suspicious += 1

    summary = _summarize(capabilities, flags, package)

    return {
        "status": "ok",
        "found": True,
        "package":         package,
        "app_name":        app_name,
        "version_code":    version_code,
        "version_name":    version_name,
        "min_sdk":         min_sdk,
        "target_sdk":      target_sdk,
        "max_sdk":         max_sdk,
        "main_activity":   main_activity,
        "permissions":     permissions,
        "permissions_count": len(permissions),
        "activities":      activities[:30],
        "activities_count": len(activities),
        "services":        services[:20],
        "receivers":       receivers[:20],
        "providers":       providers[:10],
        "native_libs":     native_libs[:30],
        "dex_files":       dex_files,
        "asset_files":     asset_files,
        "certificates":    cert_info[:5],
        "detected_packers": detected_packers,
        "capabilities":    capabilities,
        "flags":           flags,
        "_summary":        summary,
        "detections":      detections,
        "suspicious":      suspicious,
        "engines":         1,
    }


def _summarize(capabilities, flags, package) -> str:
    if flags:
        # Pega o flag mais informativo
        for keyword in ("banking", "ACESSIBILIDADE", "dropper", "ransomware", "Packer"):
            for f in flags:
                if keyword.lower() in f.lower():
                    return f
        return flags[0]
    high = [c["label"] for c in capabilities if c["severity"] == "high"]
    if high:
        return f"APK {package} - capacidades de alto risco: {', '.join(high[:3])}"
    return f"APK {package} - sem indicadores criticos"

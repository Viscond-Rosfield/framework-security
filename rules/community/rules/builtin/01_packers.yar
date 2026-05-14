/*
   Deteccao de packers conhecidos em PE.
   Packing nao eh malicioso por si so, mas e indicador.
*/

rule Packer_UPX {
    meta:
        author = "ThreatLens"
        description = "UPX packer signature"
        severity = "medium"
        category = "packer"

    strings:
        $upx0 = "UPX0"
        $upx1 = "UPX1"
        $upx_ver = "UPX!" ascii

    condition:
        uint16(0) == 0x5A4D and  // PE
        (any of ($upx0, $upx1) or $upx_ver)
}

rule Packer_ASPack {
    meta:
        author = "ThreatLens"
        description = "ASPack packer signature"
        severity = "medium"
        category = "packer"

    strings:
        $aspack = ".aspack"
        $adata  = ".adata"

    condition:
        uint16(0) == 0x5A4D and any of them
}

rule Packer_Themida_WinLicense {
    meta:
        author = "ThreatLens"
        description = "Themida or WinLicense protector"
        severity = "high"
        category = "packer"

    strings:
        $themida  = ".themida"
        $winlice  = ".winlice"

    condition:
        uint16(0) == 0x5A4D and any of them
}

rule Packer_VMProtect {
    meta:
        author = "ThreatLens"
        description = "VMProtect protector"
        severity = "high"
        category = "packer"

    strings:
        $v0 = ".vmp0"
        $v1 = ".vmp1"
        $v2 = ".vmp2"

    condition:
        uint16(0) == 0x5A4D and any of them
}

rule Packer_MPRESS {
    meta:
        author = "ThreatLens"
        description = "MPRESS packer"
        severity = "medium"
        category = "packer"

    strings:
        $m1 = ".mpress1"
        $m2 = ".mpress2"

    condition:
        uint16(0) == 0x5A4D and any of them
}

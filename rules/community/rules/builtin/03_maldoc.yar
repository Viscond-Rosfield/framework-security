/*
   Padroes de Office malware.
   Strings comuns em macros maliciosas.
*/

rule Maldoc_PowerShell_Encoded {
    meta:
        author = "ThreatLens"
        description = "PowerShell -EncodedCommand em documento Office"
        severity = "high"
        category = "maldoc"

    strings:
        $ps = "powershell" nocase
        $enc = /-[eE][nN]?[cC]?[oO]?[dD]?[eE]?[dD]?[cC]?[oO]?[mM]?[mM]?[aA]?[nN]?[dD]?\s/

    condition:
        all of them
}

rule Maldoc_Suspicious_AutoExec {
    meta:
        author = "ThreatLens"
        description = "Auto-execucao + download/shell em VBA"
        severity = "high"
        category = "maldoc"

    strings:
        $autoopen = "AutoOpen" nocase
        $docopen  = "Document_Open" nocase
        $wbopen   = "Workbook_Open" nocase
        $shell    = "Shell" nocase
        $wsh      = "WScript.Shell" nocase
        $dl       = "URLDownloadToFile" nocase
        $http     = "MSXML2.XMLHTTP" nocase

    condition:
        any of ($autoopen, $docopen, $wbopen) and
        any of ($shell, $wsh, $dl, $http)
}

rule Maldoc_DDE {
    meta:
        author = "ThreatLens"
        description = "DDE (Dynamic Data Exchange) - tecnica antiga mas ainda usada"
        severity = "medium"
        category = "maldoc"

    strings:
        $dde1 = "DDEAUTO" nocase
        $dde2 = " DDE " nocase

    condition:
        any of them
}

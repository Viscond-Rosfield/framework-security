/*
   Padroes suspeitos gerais.
*/

rule Suspicious_Mimikatz_Strings {
    meta:
        author = "ThreatLens"
        description = "Strings caracteristicas do Mimikatz"
        severity = "high"
        category = "credential_dumper"
        reference = "https://github.com/gentilkiwi/mimikatz"

    strings:
        $s1 = "sekurlsa" ascii
        $s2 = "logonpasswords" ascii nocase
        $s3 = "kerberos::list" ascii
        $s4 = "lsadump::sam" ascii nocase
        $s5 = "mimikatz" ascii nocase

    condition:
        2 of them
}

rule Suspicious_Ransom_Note_Markers {
    meta:
        author = "ThreatLens"
        description = "Marcadores tipicos de nota de resgate"
        severity = "high"
        category = "ransomware"

    strings:
        $s1 = "your files have been encrypted" nocase
        $s2 = "decrypt your files" nocase
        $s3 = "bitcoin" nocase
        $s4 = "ransom" nocase
        $s5 = "READ_ME" ascii
        $s6 = "HOW_TO_DECRYPT" ascii nocase
        $tor = ".onion"

    condition:
        2 of them or $tor
}

rule Suspicious_Base64_Payload {
    meta:
        author = "ThreatLens"
        description = "Bloco base64 muito longo (provavel payload embebido)"
        severity = "medium"
        category = "obfuscation"

    strings:
        // Base64 contiguo de >500 chars
        $b64 = /[A-Za-z0-9+\/]{500,}={0,2}/

    condition:
        $b64
}

rule Suspicious_Reverse_Shell_Patterns {
    meta:
        author = "ThreatLens"
        description = "Padroes de reverse shell (ncat, bash -i, etc.)"
        severity = "high"
        category = "rat"

    strings:
        $s1 = "bash -i" ascii
        $s2 = "/dev/tcp/" ascii
        $s3 = "nc -e" ascii
        $s4 = "ncat" ascii
        $s5 = "socket.socket" ascii
        $s6 = "/bin/sh -i" ascii

    condition:
        any of them
}

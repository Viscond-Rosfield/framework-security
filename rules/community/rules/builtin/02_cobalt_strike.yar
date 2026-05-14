/*
   Cobalt Strike beacon - ferramenta de pentest abusada por atacantes.
   Baseado em padroes publicos conhecidos (sinkholing comunidade).
*/
rule CobaltStrike_Beacon_Config {
    meta:
        author = "ThreatLens"
        description = "Possible Cobalt Strike Beacon config string"
        severity = "high"
        category = "rat"
        reference = "https://www.cobaltstrike.com/"

    strings:
        $s1 = "%s as %s\\%s: %d" ascii
        $s2 = "beacon_" ascii
        $s3 = "%s.4%08x%08x%08x%08x%08x.%s" ascii
        $s4 = "ReflectiveLoader" ascii
        $watermark = "%c%c%c%c.exe" ascii

    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule CobaltStrike_MZ_Header {
    meta:
        author = "ThreatLens"
        description = "Classic Cobalt Strike beacon MZ stub"
        severity = "high"
        category = "rat"

    strings:
        // MZARUH magic da stub default do Cobalt Strike
        $mzaruh = { 4D 5A 41 52 55 48 }

    condition:
        $mzaruh at 0
}

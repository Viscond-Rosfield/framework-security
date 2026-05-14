/*
   EICAR - arquivo padrao de teste antivirus.
   Inofensivo, mas todo AV deve detectar.
*/
rule EICAR_Test_File {
    meta:
        author = "ThreatLens"
        description = "EICAR antivirus test file"
        severity = "high"
        category = "test"
        reference = "https://www.eicar.org/"

    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

    condition:
        $eicar
}

// Example rules showing the metadata silkscan understands. Put your own rules in this directory
// (any *.yar / *.yara file is compiled). They are illustrations, not detection content.
//
//   severity = "low" | "medium" | "high" | "critical"   default: checks[].params.default_severity
//   effect   = "evidence" | "force_malicious"          force_malicious only applies if allow_force: true
//   tags     = "comma,separated"                       reported in the verdict; "ransomware", "backdoor",
//                                                       "stealer", ... raise the priority to P1 when malicious

rule EICAR_Test_File
{
    meta:
        description = "EICAR anti-malware test string (harmless, used to test the pipeline)"
        severity = "high"
        effect = "force_malicious"
        tags = "test"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

rule PE_UPX_Section_Names
{
    meta:
        description = "PE file with UPX section names (packed; common in benign tools too)"
        severity = "low"
        tags = "packer,upx"
    strings:
        $upx0 = "UPX0" ascii
        $upx1 = "UPX1" ascii
    condition:
        uint16(0) == 0x5A4D and $upx0 in (0..1024) and $upx1 in (0..1024)
}

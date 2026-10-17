"""SilkShield AI / RAG Layer -- MITRE ATT&CK Knowledge Base & Retrieval.

Provides grounded defensive context, actionable mitigations, and detection
guidance from the MITRE ATT&CK Enterprise matrix without external vector
database dependencies, ensuring zero-latency execution on IBM LinuxONE (s390x).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class MitreTechnique:
    """Enterprise MITRE ATT&CK technique with defensive mitigations."""
    id: str
    name: str
    tactic: str
    description: str
    mitigations: List[str] = field(default_factory=list)
    detection_guidance: str = ""


# ─── MITRE ATT&CK Knowledge Base ────────────────────────────── #

MITRE_KNOWLEDGE_BASE: Dict[str, MitreTechnique] = {
    # Phishing & Initial Access
    "T1566.002": MitreTechnique(
        id="T1566.002",
        name="Spearphishing Link",
        tactic="Initial Access",
        description="Adversaries send spearphishing emails with malicious links to lure targets to credential harvesting or exploit sites.",
        mitigations=[
            "M1021: Restrict Web-Based Content -- Block user access to newly observed/registered domains and known phishing categories at the Secure Web Gateway (SWG).",
            "M1054: Software Configuration -- Enable multi-factor authentication (FIDO2/WebAuthn) to render harvested credentials useless against internal portals.",
            "M1049: Antivirus/Antimalware -- Deploy endpoint protection with real-time browser sandbox inspection.",
        ],
        detection_guidance="Monitor proxy and DNS logs for outbound connections following email delivery. Flag newly registered domains (<30 days old).",
    ),
    "T1566.001": MitreTechnique(
        id="T1566.001",
        name="Spearphishing Attachment",
        tactic="Initial Access",
        description="Adversaries attach weaponized files (macros, executables, ISOs) to emails to execute code on target systems.",
        mitigations=[
            "M1031: Network Intrusion Prevention -- Inspect and block email attachments containing executable payloads or macro-enabled documents at the email gateway.",
            "M1049: Antivirus/Antimalware -- Enforce endpoint antimalware and cloud detonation of suspicious attachments.",
        ],
        detection_guidance="Correlate email gateway attachment hash telemetry with endpoint process spawning (e.g. Word launching PowerShell/cmd.exe).",
    ),
    "T1598": MitreTechnique(
        id="T1598",
        name="Phishing for Information",
        tactic="Reconnaissance",
        description="Adversaries send phishing messages to elicit sensitive technical or personnel information without necessarily dropping malware.",
        mitigations=[
            "M1017: User Training -- Train personnel to spot spoofed sender domains and urgent financial/credential verification requests.",
            "M1021: Restrict Web-Based Content -- Block credential-submission forms on unvetted external sites.",
        ],
        detection_guidance="Inspect inbound email headers for SPF/DKIM/DMARC failures and lookalike domain permutations.",
    ),

    # Malware & Execution
    "T1204.002": MitreTechnique(
        id="T1204.002",
        name="User Execution: Malicious File",
        tactic="Execution",
        description="Adversaries rely on users executing a malicious file delivered via download, phishing, or removable media.",
        mitigations=[
            "M1038: Execution Prevention -- Use AppLocker / Software Restriction Policies to prevent execution of unapproved binaries and scripts from temp/user directories.",
            "M1040: Behavior Prevention on Endpoint -- Employ EDR solutions configured to block process injection, parent-child anomalies, and unauthorized memory modifications.",
        ],
        detection_guidance="Monitor process creation events (Sysmon Event ID 1) for processes executed from Downloads, AppData, or Temp folders.",
    ),
    "T1059": MitreTechnique(
        id="T1059",
        name="Command and Scripting Interpreter",
        tactic="Execution",
        description="Adversaries abuse command shells (PowerShell, Bash, Python, CMD) to execute malicious scripts or commands.",
        mitigations=[
            "M1038: Execution Prevention -- Enforce PowerShell Constrained Language Mode and script block logging across all endpoints.",
            "M1026: Privileged Account Management -- Restrict administrative scripting capabilities to authorized accounts with just-in-time access.",
        ],
        detection_guidance="Enable PowerShell ScriptBlock Logging (Event ID 4104) and look for obfuscated commands, Base64 strings, or download cradles.",
    ),

    # Command and Control (C2)
    "T1071.001": MitreTechnique(
        id="T1071.001",
        name="Application Layer Protocol: Web Protocols",
        tactic="Command and Control",
        description="Adversaries communicate using application layer protocols (HTTP/HTTPS) to blend C2 traffic with normal web browsing.",
        mitigations=[
            "M1031: Network Intrusion Prevention -- Enforce SSL/TLS decryption and deep packet inspection (DPI) at the perimeter firewall to inspect payload patterns.",
            "M1037: Filter Network Traffic -- Restrict outbound egress traffic to approved destinations; block direct IP-based web requests that bypass DNS resolution.",
        ],
        detection_guidance="Analyze beaconing periodicity (jitter), unusual HTTP User-Agents, and high volumes of data POSTed to uncategorized IP endpoints.",
    ),
    "T1573": MitreTechnique(
        id="T1573",
        name="Encrypted Channel",
        tactic="Command and Control",
        description="Adversaries employ asymmetric/symmetric encryption within C2 channels to evade signature-based network intrusion detection.",
        mitigations=[
            "M1031: Network Intrusion Prevention -- Inspect TLS handshakes, SNI values, and JA3/JA4 cryptographic fingerprints for known adversary frameworks (e.g. Cobalt Strike).",
        ],
        detection_guidance="Flag TLS sessions with self-signed certificates, missing SNI headers, or anomalies in certificate issuer chains.",
    ),

    # Reconnaissance & Suspicious Activity
    "T1595": MitreTechnique(
        id="T1595",
        name="Active Scanning",
        tactic="Reconnaissance",
        description="Adversaries scan public-facing infrastructure (IP blocks, subnets, ports, web applications) to discover vulnerable services.",
        mitigations=[
            "M1037: Filter Network Traffic -- Deploy rate-limiting, geo-blocking, and Web Application Firewalls (WAF) to drop reconnaissance scans.",
            "M1047: Audit -- Continuously monitor external attack surface management (ASM) for exposed services.",
        ],
        detection_guidance="Detect port scans and URI fuzzing patterns in firewall and edge gateway access logs.",
    ),
}

# Mapping classifications and IOC indicators to primary techniques
_CLASSIFICATION_TECHNIQUE_MAP: Dict[str, List[str]] = {
    "PHISHING": ["T1566.002", "T1598"],
    "MALWARE": ["T1204.002", "T1059"],
    "COMMAND_AND_CONTROL": ["T1071.001", "T1573"],
    "SUSPICIOUS": ["T1595"],
    "BENIGN": [],
}


# ─── Retrieval Engine ────────────────────────────────────────── #

def retrieve_mitre_context(
    *,
    classification: str,
    ioc_type: str,
    risk_score: int,
    evidence: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Retrieve grounded MITRE ATT&CK techniques, descriptions, and mitigations.

    Args:
        classification: Detected classification (PHISHING, MALWARE, etc.)
        ioc_type: domain, url, ip, or hash
        risk_score: 0-100 score
        evidence: Extracted threat telemetry evidence lines

    Returns:
        Structured context dictionary containing techniques, mitigations, and prompt injection text.
    """
    if risk_score < 30:
        return {
            "technique_ids": [],
            "techniques": [],
            "mitigations": ["Continue standard baseline monitoring. No high-confidence ATT&CK techniques indicated."],
            "detection_guidance": [],
            "context_prompt": "Indicator assessed as benign or low risk. Standard security monitoring applies.",
        }

    # Match primary technique IDs based on classification
    tech_ids: List[str] = list(_CLASSIFICATION_TECHNIQUE_MAP.get(classification.upper(), ["T1595"]))

    # Tailor based on IOC type nuances
    if ioc_type == "hash" and "T1204.002" not in tech_ids:
        tech_ids.insert(0, "T1204.002")
    elif ioc_type == "url" and classification == "PHISHING" and "T1566.002" not in tech_ids:
        tech_ids.insert(0, "T1566.002")
    elif ioc_type == "ip" and risk_score >= 70 and "T1071.001" not in tech_ids:
        tech_ids.append("T1071.001")

    # Resolve technique objects
    techniques_data: List[Dict[str, Any]] = []
    all_mitigations: List[str] = []
    detection_tips: List[str] = []

    for tid in tech_ids:
        t = MITRE_KNOWLEDGE_BASE.get(tid)
        if t:
            techniques_data.append({
                "id": t.id,
                "name": t.name,
                "tactic": t.tactic,
                "description": t.description,
                "mitigations": t.mitigations,
            })
            all_mitigations.extend(t.mitigations)
            if t.detection_guidance:
                detection_tips.append(f"{t.id} ({t.name}): {t.detection_guidance}")

    # Deduplicate mitigations while preserving order
    seen_mit = set()
    unique_mitigations: List[str] = []
    for m in all_mitigations:
        code = m.split(":")[0] if ":" in m else m
        if code not in seen_mit:
            seen_mit.add(code)
            unique_mitigations.append(m)

    # Format text suitable for LLM RAG prompt injection
    prompt_lines = ["\n─── RETRIEVED MITRE ATT&CK GROUNDING ─────────────────"]
    for t in techniques_data:
        prompt_lines.append(f"• Technique {t['id']} -- {t['name']} (Tactic: {t['tactic']})")
        prompt_lines.append(f"  Description: {t['description']}")
        prompt_lines.append("  Defensive Mitigations:")
        for mit in t["mitigations"]:
            prompt_lines.append(f"    - {mit}")
    prompt_lines.append("──────────────────────────────────────────────────────")

    return {
        "technique_ids": [t["id"] for t in techniques_data],
        "techniques": techniques_data,
        "mitigations": unique_mitigations[:4],  # Top 4 most relevant mitigations
        "detection_guidance": detection_tips[:2],
        "context_prompt": "\n".join(prompt_lines),
    }

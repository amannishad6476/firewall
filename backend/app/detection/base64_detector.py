import base64
import re
from typing import Dict, Any, List

# Regex pattern for Base64 sequences (minimum length 16 characters to avoid false positives on random tokens)
BASE64_PATTERN = re.compile(r'(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?')

SUSPICIOUS_KEYWORDS = [
    r"ignore (?:all )?(?:previous|prior) instructions",
    r"system prompt",
    r"delete_file",
    r"send_email",
    r"execute_sql",
    r"rm -rf",
    r"confidential",
    r"attacker@",
    r"exfiltrate",
    r"password",
    r"api[_-]?key",
    r"authorization",
    r"override",
    r"drop table",
    r"curl\s+",
    r"wget\s+",
    r"powershell",
    r"cmd\.exe"
]

def scan_base64_payloads(text: str) -> Dict[str, Any]:
    """
    Identifies Base64 candidates in text, attempts decoding, and rescans
    the decoded payload for embedded attacks and commands.
    """
    matches = BASE64_PATTERN.findall(text)
    decoded_payloads: List[Dict[str, Any]] = []
    suspicious_findings: List[Dict[str, Any]] = []
    
    for candidate in matches:
        if len(candidate) < 16:
            continue
        try:
            # Handle padding
            padded = candidate + "=" * (-len(candidate) % 4)
            decoded_bytes = base64.b64decode(padded, validate=True)
            
            # Check if payload is printable ASCII/UTF-8 text
            try:
                decoded_str = decoded_bytes.decode('utf-8')
            except UnicodeDecodeError:
                continue

            # Verify that decoded content is largely printable
            printable_ratio = sum(c.isprintable() or c.isspace() for c in decoded_str) / max(len(decoded_str), 1)
            if printable_ratio < 0.85:
                continue

            payload_info = {
                "encoded": candidate,
                "decoded_preview": decoded_str[:120],
                "length": len(decoded_str)
            }
            decoded_payloads.append(payload_info)
            
            # Rescan decoded payload for malicious directives
            lowered = decoded_str.lower()
            triggered_keywords = []
            for pattern in SUSPICIOUS_KEYWORDS:
                if re.search(pattern, lowered, re.IGNORECASE):
                    triggered_keywords.append(pattern)
            
            # Check for nested Base64
            nested_matches = [m for m in BASE64_PATTERN.findall(decoded_str) if len(m) >= 16]
            
            if triggered_keywords or nested_matches:
                suspicious_findings.append({
                    "encoded_snippet": candidate[:40] + ("..." if len(candidate) > 40 else ""),
                    "decoded_snippet": decoded_str[:100],
                    "triggered_keywords": triggered_keywords,
                    "has_nested_base64": len(nested_matches) > 0
                })
        except Exception:
            continue

    detected = len(suspicious_findings) > 0
    evidence = []
    for finding in suspicious_findings:
        kw = ", ".join(finding["triggered_keywords"]) if finding["triggered_keywords"] else "nested obfuscation"
        evidence.append(
            f"Base64 obfuscated instruction found (Decoded: '{finding['decoded_snippet']}...') triggering: {kw}"
        )

    return {
        "detected": detected,
        "total_candidates": len(matches),
        "valid_decoded_count": len(decoded_payloads),
        "suspicious_count": len(suspicious_findings),
        "findings": suspicious_findings,
        "evidence": evidence
    }

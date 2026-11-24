import re
from typing import Dict, Any, List

# CSS hidden text patterns
CSS_HIDDEN_PATTERNS = [
    (r"display\s*:\s*none", "CSS display:none hiding text"),
    (r"visibility\s*:\s*hidden", "CSS visibility:hidden hiding text"),
    (r"font-size\s*:\s*(?:0(?:px|em|rem|pt)?|0\.[0-9]+(?:px|em|rem|pt)?|1px)", "CSS near-zero font size hiding text"),
    (r"color\s*:\s*(?:#ffffff|white|rgba?\(\s*255\s*,\s*255\s*,\s*255\s*(?:,\s*1(?:\.0)?)?\s*\)|transparent)", "CSS white/transparent text (potential white-on-white)"),
    (r"opacity\s*:\s*0(?:\.0+)?(?:\s*;|\s*\}|\s*$)", "CSS opacity:0 making text invisible"),
    (r"filter\s*:\s*opacity\(\s*0(?:\.0+)?\s*\)", "CSS filter opacity:0 hiding element"),
    (r"text-indent\s*:\s*-[0-9]{3,}px", "CSS extreme negative text-indent (off-screen injection)"),
    (r"(?:position\s*:\s*absolute|fixed)[^;}]*?(?:left|top)\s*:\s*-[0-9]{3,}px", "CSS absolute off-screen positioning"),
    (r"clip\s*:\s*rect\(\s*0(?:px)?\s*,\s*0(?:px)?\s*,\s*0(?:px)?\s*,\s*0(?:px)?\s*\)", "CSS clip rect zeroing element"),
    (r"transform\s*:\s*scale\(\s*0(?:\.0+)?\s*\)", "CSS transform scale(0) shrinking text to invisible"),
    (r"<[a-zA-Z0-9]+[^>]*\bhidden\b[^>]*>", "HTML hidden attribute concealing text"),
    (r"aria-hidden\s*=\s*['\"]true['\"]", "ARIA hidden element concealing instructions"),
]

# Prompt injection & System instruction override patterns
PROMPT_INJECTION_PATTERNS = [
    (r"ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?", "Direct instruction override: ignore previous instructions"),
    (r"disregard\s+(?:all\s+)?(?:prior|previous|initial)\s+prompts?", "Direct instruction override: disregard prior prompts"),
    (r"system\s+(?:override|reboot|prompt\s+reset|directive)", "System prompt manipulation: system override directive"),
    (r"you\s+are\s+now\s+(?:in\s+)?(?:developer\s+mode|dan|unrestricted|god\s+mode)", "Persona hijack: developer/DAN jailbreak mode"),
    (r"(?:from\s+now\s+on|starting\s+now)[,\s]+you\s+must", "Constraint modification: from now on you must"),
    (r"(?:new\s+priority\s+instructions?|override\s+code\s*[:=])", "Priority elevation injection"),
    (r"bypass\s+(?:safety|security|policy|content)\s+filters?", "Explicit security bypass attempt"),
    (r"(?:read|reveal|print|exfiltrate|leak)\s+(?:the\s+)?(?:system\s+prompt|confidential\s+files?|api[_-]?keys?|passwords?)", "Sensitive data extraction command"),
    (r"send\s+(?:them|data|files?|secrets?|credentials?)\s+to\s+[\w\.-]+@[\w\.-]+", "Exfiltration directive to external email"),
    (r"(?:format\s+drive|rm\s+-rf|drop\s+database|delete\s+all\s+records)", "Destructive command injection"),
    (r"<!\s*--.*?ignore.*?instructions.*?-->", "HTML comment containing hidden instruction override"),
    (r"\[\s*system\s*[:\s].*?\]", "Simulated system turn injection"),
]

def scan_css_hidden_text(content: str) -> Dict[str, Any]:
    """
    Detects attempts to hide malicious text using CSS attributes, HTML styling,
    white-on-white text, or invisible elements.
    """
    findings = []
    lowered = content.lower()
    
    for pattern, description in CSS_HIDDEN_PATTERNS:
        matches = re.findall(pattern, lowered)
        if matches:
            findings.append({
                "rule": description,
                "matches_count": len(matches),
                "sample": matches[0][:80]
            })

    detected = len(findings) > 0
    evidence = [f"{f['rule']} (found {f['matches_count']} instance(s))" for f in findings]
    
    return {
        "detected": detected,
        "findings": findings,
        "evidence": evidence
    }

def scan_prompt_injection(content: str) -> Dict[str, Any]:
    """
    Detects prompt injection, system instruction overrides, persona hijacking,
    and jailbreak attempts in incoming text.
    """
    findings = []
    lowered = content.lower()
    
    for pattern, description in PROMPT_INJECTION_PATTERNS:
        matches = list(re.finditer(pattern, lowered, re.IGNORECASE))
        if matches:
            samples = [m.group(0) for m in matches[:3]]
            findings.append({
                "rule": description,
                "pattern": pattern,
                "matches_count": len(matches),
                "samples": samples
            })

    detected = len(findings) > 0
    evidence = [f"{f['rule']} (Sample: '{f['samples'][0]}')" for f in findings]
    
    return {
        "detected": detected,
        "findings": findings,
        "evidence": evidence
    }

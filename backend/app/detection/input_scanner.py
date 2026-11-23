from typing import Dict, Any, List
from .unicode_inspector import inspect_unicode
from .base64_detector import scan_base64_payloads
from .rules import scan_css_hidden_text, scan_prompt_injection
from ..schemas.firewall_schemas import ThreatCategory, ThreatSeverity, InputScanResult, OriginType

class InputScanner:
    """
    Core security scanner analyzing incoming web pages, files, user inputs,
    and tool outputs for obfuscated content, hidden instructions, and prompt injection attacks.
    """

    def scan(self, content: str, source_type: OriginType = OriginType.WEBPAGE, strict_mode: bool = False) -> InputScanResult:
        if not content:
            return InputScanResult(
                detected=False,
                threat_category=ThreatCategory.NONE,
                severity=ThreatSeverity.LOW,
                evidence=[],
                explanation="Empty content analyzed - no threat detected.",
                raw_findings={}
            )

        evidence: List[str] = []
        raw_findings: Dict[str, Any] = {}
        detected_categories: List[ThreatCategory] = []
        severities: List[ThreatSeverity] = []

        # 1. Unicode & Zero-width inspection
        unicode_res = inspect_unicode(content)
        raw_findings["unicode_analysis"] = unicode_res
        if unicode_res["detected"]:
            detected_categories.append(ThreatCategory.ZERO_WIDTH_ATTACK)
            severities.append(ThreatSeverity.HIGH if unicode_res["total_zero_width_count"] > 3 else ThreatSeverity.MEDIUM)
            evidence.extend(unicode_res["evidence"])

        # Clean text for downstream scanning if zero-width characters were present
        effective_text = unicode_res.get("clean_text", content)

        # 2. CSS / HTML hidden text inspection
        css_res = scan_css_hidden_text(effective_text)
        raw_findings["css_hidden_analysis"] = css_res
        if css_res["detected"]:
            detected_categories.append(ThreatCategory.HIDDEN_INSTRUCTION)
            severities.append(ThreatSeverity.HIGH)
            evidence.extend(css_res["evidence"])

        # 3. Base64 payload detection & recursive rescanning
        b64_res = scan_base64_payloads(effective_text)
        raw_findings["base64_analysis"] = b64_res
        if b64_res["detected"]:
            detected_categories.append(ThreatCategory.BASE64_OBFUSCATION)
            severities.append(ThreatSeverity.HIGH)
            evidence.extend(b64_res["evidence"])

        # 4. Prompt injection & override inspection
        injection_res = scan_prompt_injection(effective_text)
        raw_findings["prompt_injection_analysis"] = injection_res
        if injection_res["detected"]:
            detected_categories.append(ThreatCategory.PROMPT_INJECTION)
            # If prompt injection is coupled with hidden CSS or zero-width, it is CRITICAL
            if ThreatCategory.HIDDEN_INSTRUCTION in detected_categories or ThreatCategory.ZERO_WIDTH_ATTACK in detected_categories:
                severities.append(ThreatSeverity.CRITICAL)
            else:
                severities.append(ThreatSeverity.HIGH)
            evidence.extend(injection_res["evidence"])

        # Synthesize final classification
        if not detected_categories:
            return InputScanResult(
                detected=False,
                threat_category=ThreatCategory.NONE,
                severity=ThreatSeverity.LOW,
                evidence=[],
                explanation="Content scanned cleanly. No prompt injection, hidden text, or obfuscated payloads detected.",
                raw_findings=raw_findings
            )

        # Determine dominant threat category and highest severity
        severity_rank = {
            ThreatSeverity.LOW: 1,
            ThreatSeverity.MEDIUM: 2,
            ThreatSeverity.HIGH: 3,
            ThreatSeverity.CRITICAL: 4
        }
        highest_severity = max(severities, key=lambda s: severity_rank.get(s, 1))

        # Prioritize categorization
        if ThreatCategory.PROMPT_INJECTION in detected_categories:
            primary_category = ThreatCategory.PROMPT_INJECTION
        elif ThreatCategory.HIDDEN_INSTRUCTION in detected_categories:
            primary_category = ThreatCategory.HIDDEN_INSTRUCTION
        elif ThreatCategory.BASE64_OBFUSCATION in detected_categories:
            primary_category = ThreatCategory.BASE64_OBFUSCATION
        elif ThreatCategory.ZERO_WIDTH_ATTACK in detected_categories:
            primary_category = ThreatCategory.ZERO_WIDTH_ATTACK
        else:
            primary_category = detected_categories[0]

        explanation = (
            f"Security Threat Detected: [{primary_category.value}] at severity [{highest_severity.value}]. "
            f"Found {len(evidence)} suspicious security indicators inside incoming {source_type.value} content."
        )

        return InputScanResult(
            detected=True,
            threat_category=primary_category,
            severity=highest_severity,
            evidence=evidence,
            explanation=explanation,
            raw_findings=raw_findings
        )

scanner = InputScanner()

import re
import csv
import io
import zlib
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field

from .input_scanner import scanner
from ..schemas.firewall_schemas import OriginType, ThreatCategory, ThreatSeverity, InputScanResult

class FileScanResult(BaseModel):
    filename: str
    file_type: str
    file_size_bytes: int
    detected: bool
    threat_category: ThreatCategory = ThreatCategory.NONE
    severity: ThreatSeverity = ThreatSeverity.LOW
    evidence: List[str] = Field(default_factory=list)
    secrets_found: List[str] = Field(default_factory=list)
    extracted_text_preview: str = ""
    explanation: str = "File scanned cleanly."
    raw_findings: Dict[str, Any] = Field(default_factory=dict)

# High-entropy & sensitive secret / PII patterns
SECRET_PATTERNS = {
    "AWS Access Key": r"\bAKIA[0-9A-Z]{16}\b",
    "Private SSH/RSA Key": r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    "Generic API Token / Bearer": r"(?i)\b(?:api_key|apikey|secret_key|access_token|bearer)\b\s*[:=]\s*['\"]([a-zA-Z0-9_\-\.]{16,})['\"]",
    "Database Connection String": r"(?i)(?:postgres|mysql|mongodb|redis):\/\/[a-zA-Z0-9_\-\.]+:[^@]+@[a-zA-Z0-9_\-\.]+",
    "OpenAI / Anthropic Key": r"\b(?:sk-[a-zA-Z0-9]{20,}|sk-ant-[a-zA-Z0-9\-]{20,})\b",
    "GitHub Token": r"\b(?:ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{82})\b",
    "Social Security Number (PII)": r"\b\d{3}-\d{2}-\d{4}\b",
    "Payment Card Number (PII)": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b"
}

def scan_text_for_secrets(text: str) -> List[str]:
    secrets_found = []
    for secret_type, pattern in SECRET_PATTERNS.items():
        matches = re.finditer(pattern, text)
        for m in matches:
            matched_val = m.group(0)
            # Redact middle characters for safe reporting
            if len(matched_val) > 8:
                redacted = matched_val[:4] + "*" * (len(matched_val) - 8) + matched_val[-4:]
            else:
                redacted = "****"
            secrets_found.append(f"{secret_type}: {redacted}")
    return secrets_found

def extract_pdf_text_streams(data: bytes) -> str:
    """
    Pure-Python robust PDF stream text extractor for .pdf files.
    Decodes FlateDecode compressed streams and uncompressed literal strings.
    """
    text_chunks: List[str] = []
    
    # 1. Uncompressed literal strings: (text) Tj
    for match in re.finditer(rb'\((.*?)\)\s*Tj', data, re.DOTALL):
        try:
            decoded = match.group(1).decode("latin1", errors="ignore")
            if decoded.strip():
                text_chunks.append(decoded)
        except Exception:
            pass

    # Uncompressed array strings: [(t1) 12 (t2)] TJ
    for match in re.finditer(rb'\[(.*?)\]\s*TJ', data, re.DOTALL):
        for submatch in re.findall(rb'\((.*?)\)', match.group(1), re.DOTALL):
            try:
                decoded = submatch.decode("latin1", errors="ignore")
                if decoded.strip():
                    text_chunks.append(decoded)
            except Exception:
                pass

    # 2. Decompress Flate streams
    for match in re.finditer(rb'stream[\r\n]+(.*?)[\r\n]+endstream', data, re.DOTALL):
        stream_bytes = match.group(1)
        try:
            decomp = zlib.decompress(stream_bytes)
            for m in re.finditer(rb'\((.*?)\)\s*Tj', decomp, re.DOTALL):
                text_chunks.append(m.group(1).decode("latin1", errors="ignore"))
            for m in re.finditer(rb'\[(.*?)\]\s*TJ', decomp, re.DOTALL):
                for sm in re.findall(rb'\((.*?)\)', m.group(1), re.DOTALL):
                    text_chunks.append(sm.decode("latin1", errors="ignore"))
        except Exception:
            # Not a zlib stream or raw data
            pass

    # 3. Fallback: extract ASCII-like strings if structured PDF extraction yielded little
    if not text_chunks:
        ascii_matches = re.findall(rb'[a-zA-Z0-9\s.,!?:;\-_/\\\'"]{4,}', data)
        for am in ascii_matches:
            text_chunks.append(am.decode("latin1", errors="ignore"))

    return " ".join(text_chunks)

def extract_csv_text(content_str: str) -> str:
    """
    Extracts text and checks CSV cells for injection or CSV formula injection (=, +, -, @).
    """
    lines = []
    try:
        reader = csv.reader(io.StringIO(content_str))
        for row in reader:
            row_cells = []
            for cell in row:
                cell_stripped = cell.strip()
                # Check for DDE / CSV Formula injection
                if cell_stripped.startswith(("=", "+", "-", "@")) and len(cell_stripped) > 1:
                    row_cells.append(f"[FORMULA_INJECTION_RISK: {cell_stripped}]")
                else:
                    row_cells.append(cell)
            lines.append(" ".join(row_cells))
    except Exception:
        return content_str
    return "\n".join(lines)

class FileSecurityScanner:
    """
    Scans files and uploaded attachments (.txt, .pdf, .csv, code files)
    for prompt injection, covert steganography, formula injection, and secrets.
    """

    SUPPORTED_EXTENSIONS = {
        ".txt": "text/plain",
        ".pdf": "application/pdf",
        ".csv": "text/csv",
        ".py": "text/x-python",
        ".js": "text/javascript",
        ".ts": "text/typescript",
        ".json": "application/json",
        ".md": "text/markdown",
        ".html": "text/html",
        ".sh": "text/x-shellscript",
        ".sql": "text/x-sql",
        ".yaml": "text/yaml",
        ".yml": "text/yaml"
    }

    def scan_file(
        self,
        filename: str,
        file_bytes: bytes,
        mime_type: Optional[str] = None
    ) -> FileScanResult:
        file_size = len(file_bytes)
        ext = ""
        if "." in filename:
            ext = "." + filename.rsplit(".", 1)[-1].lower()

        # 1. Extract text according to file extension
        extracted_text = ""
        is_pdf = (ext == ".pdf") or (file_bytes.startswith(b"%PDF-"))

        if is_pdf:
            extracted_text = extract_pdf_text_streams(file_bytes)
            file_type = "application/pdf"
        elif ext == ".csv":
            try:
                raw_str = file_bytes.decode("utf-8", errors="replace")
                extracted_text = extract_csv_text(raw_str)
            except Exception:
                extracted_text = file_bytes.decode("latin1", errors="ignore")
            file_type = "text/csv"
        else:
            try:
                extracted_text = file_bytes.decode("utf-8")
            except UnicodeDecodeError:
                extracted_text = file_bytes.decode("latin1", errors="ignore")
            file_type = self.SUPPORTED_EXTENSIONS.get(ext, mime_type or "text/plain")

        # 2. Check for secrets/credentials
        secrets_found = scan_text_for_secrets(extracted_text)

        # 3. Run multi-layer input scanner (CSS, Unicode, Base64, Prompt Injection)
        scan_res = scanner.scan(extracted_text, source_type=OriginType.FILE)

        # Combine results
        evidence = list(scan_res.evidence)
        detected_categories = []
        severities = []

        if scan_res.detected:
            detected_categories.append(scan_res.threat_category)
            severities.append(scan_res.severity)

        if secrets_found:
            detected_categories.append(ThreatCategory.SENSITIVE_DATA_LEAK)
            severities.append(ThreatSeverity.HIGH)
            for sec in secrets_found:
                evidence.append(f"Secret Detected: {sec}")

        if "[FORMULA_INJECTION_RISK:" in extracted_text:
            detected_categories.append(ThreatCategory.UNAUTHORIZED_COMMAND)
            severities.append(ThreatSeverity.HIGH)
            evidence.append("CSV formula injection pattern detected (=, +, -, or @ prefix in cells)")

        has_threat = len(detected_categories) > 0
        primary_threat = detected_categories[0] if detected_categories else ThreatCategory.NONE
        
        severity_rank = {
            ThreatSeverity.LOW: 1,
            ThreatSeverity.MEDIUM: 2,
            ThreatSeverity.HIGH: 3,
            ThreatSeverity.CRITICAL: 4
        }
        highest_severity = max(severities, key=lambda s: severity_rank.get(s, 1)) if severities else ThreatSeverity.LOW

        preview = extracted_text[:400] + ("..." if len(extracted_text) > 400 else "")

        if has_threat:
            explanation = (
                f"File Security Alert: [{primary_threat.value}] detected in '{filename}' at severity [{highest_severity.value}]. "
                f"Evidence: {len(evidence)} suspicious indicators found."
            )
        else:
            explanation = f"File '{filename}' ({file_size} bytes) scanned cleanly with zero threats or secrets found."

        return FileScanResult(
            filename=filename,
            file_type=file_type,
            file_size_bytes=file_size,
            detected=has_threat,
            threat_category=primary_threat,
            severity=highest_severity,
            evidence=evidence,
            secrets_found=secrets_found,
            extracted_text_preview=preview,
            explanation=explanation,
            raw_findings={
                "secrets_count": len(secrets_found),
                "scanner_findings": scan_res.raw_findings,
                "text_length": len(extracted_text)
            }
        )

file_scanner = FileSecurityScanner()

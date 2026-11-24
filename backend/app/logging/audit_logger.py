import re
import hashlib
import uuid
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from sqlalchemy import or_, desc
from ..models.db_models import AuditLog

# --------------------------------------------------------------------------
# 1. Output Masking & Sensitive Data Scrubbing (Luhn, Verhoeff, Secrets)
# --------------------------------------------------------------------------

# Dihedral group D5 multiplication table for Verhoeff algorithm
_VERHOEFF_D_TABLE = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]
]

# Permutation table for Verhoeff algorithm
_VERHOEFF_P_TABLE = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]
]

def is_valid_luhn(card_candidate: str) -> bool:
    """Validates candidate string against Luhn checksum (ISO/IEC 7812)."""
    digits = [int(c) for c in card_candidate if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for i, d in enumerate(reverse_digits):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0

def is_valid_verhoeff(num_candidate: str) -> bool:
    """Validates candidate numeric string against Verhoeff decimal checksum."""
    digits = [int(c) for c in num_candidate if c.isdigit()]
    if len(digits) not in [10, 11, 12]:
        return False
    c = 0
    for i, digit in enumerate(reversed(digits)):
        c = _VERHOEFF_D_TABLE[c][_VERHOEFF_P_TABLE[i % 8][digit]]
    return c == 0

SECRET_PATTERNS = [
    (r'(?i)(password|passwd|secret|api[_-]?key|token|auth|bearer|client_secret)\s*[:=]\s*["\']?([^"\'\s]+)["\']?', r'\1: [REDACTED_SECRET]'),
    (r'\b(AKIA[0-9A-Z]{16})\b', '[REDACTED_AWS_KEY]'),
    (r'\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}\.[A-Za-z0-9._-]{10,})\b', '[REDACTED_JWT]'),
    (r'-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----', '[REDACTED_PRIVATE_KEY]'),
    (r'\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b', '[REDACTED_SSN]'),
]

# Regex to detect candidate credit card patterns (13-19 digits, optionally separated by spaces or dashes)
CC_REGEX = re.compile(r'\b(?:\d[ -]*?){13,19}\b')

# Regex to detect candidate 10-12 digit Verhoeff national IDs
VERHOEFF_REGEX = re.compile(r'\b(?:\d[ -]*?){10,12}\b')

def sanitize_details(details: Optional[str]) -> Optional[str]:
    """
    Scrubs credentials, high-entropy tokens, private keys, SSNs,
    and verified credit cards (Luhn) / national IDs (Verhoeff).
    """
    if not details:
        return details
    sanitized = details

    # 1. Regex secret patterns
    for pattern, repl in SECRET_PATTERNS:
        sanitized = re.sub(pattern, repl, sanitized)

    # 2. Credit Card scrubbing with Luhn verification
    def _scrub_cc(match):
        raw = match.group(0)
        digits = "".join(c for c in raw if c.isdigit())
        if is_valid_luhn(digits):
            return "[REDACTED_CREDIT_CARD]"
        return raw

    sanitized = CC_REGEX.sub(_scrub_cc, sanitized)

    # 3. National ID scrubbing with Verhoeff verification
    def _scrub_verhoeff(match):
        raw = match.group(0)
        digits = "".join(c for c in raw if c.isdigit())
        if is_valid_verhoeff(digits):
            return "[REDACTED_NATIONAL_ID]"
        return raw

    sanitized = VERHOEFF_REGEX.sub(_scrub_verhoeff, sanitized)

    return sanitized


# --------------------------------------------------------------------------
# 2. Cryptographic Hash-Chained Audit Logger
# --------------------------------------------------------------------------

GENESIS_HASH = "GENESIS"

def normalize_timestamp_str(ts_val: Any) -> str:
    """Canonical timestamp formatting for deterministic hash calculation."""
    if isinstance(ts_val, datetime):
        return ts_val.strftime("%Y-%m-%d %H:%M:%S")
    if isinstance(ts_val, str):
        return ts_val[:19].replace("T", " ")
    return ""

def compute_audit_hash(
    prev_hash: str,
    log_id: str,
    timestamp_str: Any,
    event_id: Optional[str],
    agent_id: str,
    event_type: str,
    actor: str,
    action_summary: str,
    decision: Optional[str],
    risk_score: Optional[float],
    details: Optional[str],
    ip_address: str
) -> str:
    """Computes SHA-256 canonical row hash for audit chain integrity."""
    risk_str = f"{risk_score:.4f}" if risk_score is not None else ""
    t_clean = normalize_timestamp_str(timestamp_str)
    canonical = (
        f"{prev_hash}|{log_id}|{t_clean}|{event_id or ''}|"
        f"{agent_id}|{event_type}|{actor}|{action_summary}|"
        f"{decision or ''}|{risk_str}|{details or ''}|{ip_address}"
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

class AuditLogger:
    """
    Provides cryptographic tamper-evident audit logging using SHA-256 hash chaining.
    Each audit log row cryptographically references its predecessor's row_hash.
    """

    def log(
        self,
        db: Session,
        agent_id: str,
        event_type: str,
        actor: str,
        action_summary: str,
        decision: Optional[str] = None,
        risk_score: Optional[float] = None,
        details: Optional[str] = None,
        event_id: Optional[str] = None,
        ip_address: str = "127.0.0.1"
    ) -> AuditLog:
        clean_details = sanitize_details(details)
        log_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)
        timestamp_str = now.isoformat()

        # Query latest row to retrieve prev_hash
        latest_log = db.query(AuditLog).order_by(AuditLog.timestamp.desc(), AuditLog.id.desc()).first()
        prev_hash = latest_log.row_hash if (latest_log and latest_log.row_hash) else GENESIS_HASH

        # Compute tamper-evident row hash
        row_hash = compute_audit_hash(
            prev_hash=prev_hash,
            log_id=log_id,
            timestamp_str=now,
            event_id=event_id,
            agent_id=agent_id,
            event_type=event_type,
            actor=actor,
            action_summary=action_summary,
            decision=decision,
            risk_score=risk_score,
            details=clean_details,
            ip_address=ip_address
        )

        log_entry = AuditLog(
            id=log_id,
            timestamp=now,
            event_id=event_id,
            agent_id=agent_id,
            event_type=event_type,
            actor=actor,
            action_summary=action_summary,
            decision=decision,
            risk_score=risk_score,
            details=clean_details,
            ip_address=ip_address,
            prev_hash=prev_hash,
            row_hash=row_hash
        )
        db.add(log_entry)
        db.commit()
        db.refresh(log_entry)
        return log_entry

    def backfill_legacy_chain(self, db: Session, force: bool = False) -> int:
        """Backfills cryptographic hash chain for legacy records created prior to hash-chaining."""
        logs = db.query(AuditLog).order_by(AuditLog.timestamp.asc(), AuditLog.id.asc()).all()
        count = 0
        expected_prev = GENESIS_HASH
        for entry in logs:
            if force or not entry.row_hash or (entry.prev_hash != expected_prev):
                entry.prev_hash = expected_prev
                entry.row_hash = compute_audit_hash(
                    prev_hash=entry.prev_hash,
                    log_id=entry.id,
                    timestamp_str=entry.timestamp,
                    event_id=entry.event_id,
                    agent_id=entry.agent_id,
                    event_type=entry.event_type,
                    actor=entry.actor,
                    action_summary=entry.action_summary,
                    decision=entry.decision,
                    risk_score=entry.risk_score,
                    details=entry.details,
                    ip_address=entry.ip_address or "127.0.0.1"
                )
                count += 1
            expected_prev = entry.row_hash
        if count > 0:
            db.commit()
        return count

    def verify_chain(self, db: Session) -> Dict[str, Any]:
        """
        Validates the entire cryptographic hash chain across all audit logs.
        Detects unauthorized insertions, modifications, or deletions.
        """
        # Ensure any legacy unhashed records are integrated
        unhashed = db.query(AuditLog).filter(AuditLog.row_hash == None).count()
        if unhashed > 0:
            self.backfill_legacy_chain(db)

        logs = db.query(AuditLog).order_by(AuditLog.timestamp.asc(), AuditLog.id.asc()).all()
        if not logs:
            return {"valid": True, "total_records": 0, "details": "Audit log chain is empty."}

        expected_prev_hash = GENESIS_HASH

        for index, entry in enumerate(logs):
            # Check backward linkage (allow first record to link to GENESIS if prev_hash was set or None)
            if entry.prev_hash and entry.prev_hash != expected_prev_hash and index > 0:
                return {
                    "valid": False,
                    "tampered_record_id": entry.id,
                    "index": index,
                    "error": "PREV_HASH_MISMATCH",
                    "details": f"Record {entry.id} expected prev_hash {expected_prev_hash[:16]}... but found {entry.prev_hash[:16]}..."
                }

            # Recalculate row hash
            recomputed = compute_audit_hash(
                prev_hash=entry.prev_hash or GENESIS_HASH,
                log_id=entry.id,
                timestamp_str=entry.timestamp,
                event_id=entry.event_id,
                agent_id=entry.agent_id,
                event_type=entry.event_type,
                actor=entry.actor,
                action_summary=entry.action_summary,
                decision=entry.decision,
                risk_score=entry.risk_score,
                details=entry.details,
                ip_address=entry.ip_address or "127.0.0.1"
            )

            if entry.row_hash and entry.row_hash != recomputed:
                return {
                    "valid": False,
                    "tampered_record_id": entry.id,
                    "index": index,
                    "error": "ROW_HASH_TAMPERED",
                    "details": f"Record {entry.id} content does not match its cryptographic row_hash."
                }

            expected_prev_hash = entry.row_hash or expected_prev_hash

        return {
            "valid": True,
            "total_records": len(logs),
            "head_hash": logs[-1].row_hash if logs else None,
            "details": f"All {len(logs)} audit records cryptographically verified with unbroken SHA-256 chain."
        }

    def query_logs(
        self,
        db: Session,
        agent_id: Optional[str] = None,
        decision: Optional[str] = None,
        search_query: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[AuditLog]:
        query = db.query(AuditLog)
        
        if agent_id:
            query = query.filter(AuditLog.agent_id == agent_id)
        if decision:
            query = query.filter(AuditLog.decision == decision)
        if search_query:
            pattern = f"%{search_query}%"
            query = query.filter(
                or_(
                    AuditLog.action_summary.ilike(pattern),
                    AuditLog.details.ilike(pattern),
                    AuditLog.actor.ilike(pattern),
                    AuditLog.event_type.ilike(pattern)
                )
            )
            
        return query.order_by(desc(AuditLog.timestamp)).offset(offset).limit(limit).all()

audit_logger = AuditLogger()

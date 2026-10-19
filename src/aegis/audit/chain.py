from __future__ import annotations

import hashlib
import json
from pathlib import Path

from aegis.core.models import AuditEventType, AuditRecord


class AuditChain:
    """Append-only, hash-linked audit log for agent actions."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else None
        self._prev_hash = "0" * 64
        if self.path and self.path.exists():
            self._prev_hash = self._tail_hash()

    def append(
        self,
        event_type: AuditEventType,
        session_id: str,
        tenant_id: str,
        payload: dict,
    ) -> AuditRecord:
        body = {
            "event_type": event_type,
            "session_id": session_id,
            "tenant_id": tenant_id,
            "payload": payload,
            "prev_hash": self._prev_hash,
        }
        record_hash = _hash_body(body)
        record = AuditRecord(
            event_type=event_type,
            session_id=session_id,
            tenant_id=tenant_id,
            payload=payload,
            prev_hash=self._prev_hash,
            record_hash=record_hash,
        )
        self._prev_hash = record_hash
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(record.model_dump_json() + "\n")
        return record

    def verify(self) -> tuple[bool, str]:
        if not self.path or not self.path.exists():
            return True, "empty"
        prev = "0" * 64
        for line_no, line in enumerate(self.path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            data = json.loads(line)
            expected_prev = data["prev_hash"]
            if expected_prev != prev:
                return False, f"chain break at line {line_no}"
            body = {
                "event_type": data["event_type"],
                "session_id": data["session_id"],
                "tenant_id": data["tenant_id"],
                "payload": data["payload"],
                "prev_hash": data["prev_hash"],
            }
            if _hash_body(body) != data["record_hash"]:
                return False, f"hash mismatch at line {line_no}"
            prev = data["record_hash"]
        return True, "ok"

    def _tail_hash(self) -> str:
        last = "0" * 64
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                last = json.loads(line)["record_hash"]
        return last


def _hash_body(body: dict) -> str:
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

"""Small, deterministic and serializable detection model."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
import json

SEVERITIES = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str
    path: str
    line: int
    trigger: str
    title: str
    evidence: str
    why: str
    advice: str
    fingerprint: str
    analysis_command: str = field(default="", repr=False, compare=False)

    @classmethod
    def make(cls, *, rule: str, severity: str, path: str, line: int,
             trigger: str, title: str, evidence: str, why: str, advice: str,
             identity: str, analysis_command: str = "") -> "Finding":
        fingerprint = hashlib.sha256(
            json.dumps([rule, path, trigger, identity], ensure_ascii=True,
                       separators=(",", ":")).encode("utf-8")
        ).hexdigest()[:24]
        return cls(rule, severity, path, max(1, line), trigger, title,
                   evidence, why, advice, fingerprint, analysis_command)

    def to_dict(self) -> dict:
        result = asdict(self)
        result.pop("analysis_command")
        return result

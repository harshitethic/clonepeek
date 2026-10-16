"""Parser and output codecs. No repo code is executed."""
from __future__ import annotations

import json
from pathlib import Path
import re

from . import __version__
from .models import Finding, SEVERITIES


def jsonc_to_json(text: str) -> str:
    """Remove JSONC comments/trailing commas, preserving character offsets.

    Preserving offsets keeps location hints stable. Strings are never edited.
    """
    chars = list(text)
    i, n = 0, len(chars)
    in_string = False
    while i < n:
        c = chars[i]
        if in_string:
            if c == "\\":
                i += 2
                continue
            if c == '"':
                in_string = False
            i += 1
            continue
        if c == '"':
            in_string = True
            i += 1
            continue
        if c == "/" and i + 1 < n and chars[i + 1] in ("/", "*"):
            block = chars[i + 1] == "*"
            start = i
            i += 2
            if block:
                while i + 1 < n and not (chars[i] == "*" and chars[i + 1] == "/"):
                    i += 1
                i = min(n, i + 2)
            else:
                while i < n and chars[i] != "\n":
                    i += 1
            for j in range(start, i):
                if chars[j] != "\n":
                    chars[j] = " "
            continue
        i += 1
    in_string = False
    i = 0
    while i < n:
        if chars[i] == '"':
            in_string = not in_string
            i += 1
            while in_string and i < n:
                if chars[i] == "\\":
                    i += 2
                elif chars[i] == '"':
                    in_string = False
                    i += 1
                else:
                    i += 1
            continue
        if chars[i] == ",":
            j = i + 1
            while j < n and chars[j].isspace():
                j += 1
            if j < n and chars[j] in "}]":
                chars[i] = " "
        i += 1
    return "".join(chars)


def load_json(text: str, jsonc: bool = False):
    """Parse bounded-depth config even on Python versions with high JSON recursion limits."""
    prepared = jsonc_to_json(text) if jsonc else text
    depth = 0
    in_string = escaped = False
    for char in prepared:
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
        elif char == '"':
            in_string = True
        elif char in "{[":
            depth += 1
            if depth > 128:
                raise ValueError("Configuration nesting exceeds 128 levels")
        elif char in "]}":
            depth = max(0, depth - 1)
    return json.loads(prepared)


def redact(value: str, length: int = 240) -> str:
    """Best-effort masking in scanner evidence; review reports before sharing."""
    value = re.sub(r"(?i)(gh[pousr]_[A-Za-z0-9_]{12,}|github_pat_[A-Za-z0-9_]{12,}|sk-[A-Za-z0-9_-]{16,}|AKIA[0-9A-Z]{16})", "[REDACTED]", value)

    # Quoted assignments may contain spaces; mask the whole credential.
    value = re.sub(
        r"""(?i)\b(?P<key>password|token|api[_-]?key|secret)\s*[=:]\s*(?P<quote>['"])(?P<secret>.*?)(?P=quote)""",
        lambda m: f"{m['key']}={m['quote']}[REDACTED]{m['quote']}",
        value,
    )
    value = re.sub(
        r"""(?i)\b(?P<key>password|token|api[_-]?key|secret)\s*[=:]\s*(?P<secret>[^\s,;'"\\]+)""",
        lambda m: f"{m['key']}=[REDACTED]",
        value,
    )

    # Agent/MCP launch arguments often pass credentials as a separate value.
    option = r"--(?:api[-_]?key|access[-_]?token|auth[-_]?token|client[-_]?secret|password|passwd|secret|token)"
    value = re.sub(
        rf"""(?i)(?P<flag>{option})(?P<sep>\s+|=)(?P<quote>['"])(?P<secret>.*?)(?P=quote)""",
        lambda m: f"{m['flag']}{m['sep']}{m['quote']}[REDACTED]{m['quote']}",
        value,
    )
    value = re.sub(
        rf"""(?i)(?P<flag>{option})(?P<sep>\s+|=)(?P<secret>[^\s,;'"\\]+)""",
        lambda m: f"{m['flag']}{m['sep']}[REDACTED]",
        value,
    )
    value = re.sub(
        r"""(?i)(\bauthorization\s*[:=]\s*bearer\s+)([^\s"';,]+)""",
        r"\1[REDACTED]", value,
    )
    value = re.sub(r"https?://[^\s/@]+:[^\s/@]+@", "https://[REDACTED]@", value)
    value = value.replace("\r", " ").replace("\n", " ").strip()
    return value[:length] + ("…" if len(value) > length else "")


def line_for(text: str, needle: str, start: int = 0) -> int:
    position = text.find(needle, start)
    return 1 + text.count("\n", 0, position) if position >= 0 else 1


def render_text(findings: list[Finding], scanned: int, skipped: int,
                known: set[str] | None = None) -> str:
    counts = {key: sum(f.severity == key for f in findings) for key in SEVERITIES}
    pieces = [f"ClonePeek · {scanned} inspected · {skipped} skipped · {len(findings)} execution surfaces",
              " · ".join(f"{counts[s]} {s}" for s in ("critical", "high", "medium", "low", "info"))]
    if known is not None:
        pieces.append(f"New: {sum(f.fingerprint not in known for f in findings)} · Known: {sum(f.fingerprint in known for f in findings)}")
    for f in findings:
        state = " [known]" if known is not None and f.fingerprint in known else ""
        pieces.append(f"\n[{f.severity.upper()}] {f.title}{state}\n  {f.path}:{f.line} · {f.trigger}\n  {f.evidence}\n  Why: {f.why}\n  Next: {f.advice}")
    if not findings:
        pieces.append("No modeled execution surfaces found. This is NOT a safety guarantee.")
    return "\n".join(pieces)


def sarif(findings: list[Finding]) -> dict:
    rules = sorted({f.rule for f in findings})
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {"name": "ClonePeek", "version": __version__, "informationUri": "https://github.com/harshitethic/clonepeek",
                                "rules": [{"id": r, "name": r} for r in rules]}},
            "results": [{
                "ruleId": f.rule,
                "level": "error" if SEVERITIES[f.severity] >= 3 else "warning" if SEVERITIES[f.severity] >= 2 else "note",
                "message": {"text": f"{f.title}. Trigger: {f.trigger}. {f.why} Advice: {f.advice}"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.path},
                                                    "region": {"startLine": f.line}}}],
                "partialFingerprints": {"clonepeek/v1": f.fingerprint},
                "properties": {"severity": f.severity, "evidence": f.evidence},
            } for f in findings],
        }],
    }


def load_baseline(path: Path) -> set[str]:
    obj = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(obj, dict) or obj.get("schema") != "clonepeek-baseline-v1" or not isinstance(obj.get("fingerprints"), list):
        raise ValueError("Not a ClonePeek v1 baseline")
    if not all(isinstance(x, str) for x in obj["fingerprints"]):
        raise ValueError("Baseline fingerprints must be strings")
    return set(obj["fingerprints"])


def baseline(findings: list[Finding]) -> dict:
    return {"schema": "clonepeek-baseline-v1", "fingerprints": sorted({f.fingerprint for f in findings})}

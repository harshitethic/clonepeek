"""Conservative first-hop review of explicit, repo-local shell script references.

Never imports, starts a shell, resolves commands, evaluates expressions or
interprets scripts. Only literal invocations of a .sh file are followed.
"""
from __future__ import annotations

import re
from pathlib import Path, PurePosixPath

from .detectors import assess
from .formats import redact
from .models import Finding, SEVERITIES

MAX_SCRIPT_BYTES = 128 * 1024
MAX_SCRIPT_LINES = 2000
MAX_REFERENCES = 32

# sh scripts/setup.sh, bash ./scripts/setup.sh, or a direct ./scripts/setup.sh.
# No absolute paths, dollar substitutions, environment expansions or options
# accepting inline code. This narrow matcher trades coverage for predictable
# resolution of readable local paths.
SCRIPT_CALL = re.compile(
    r"(?<![\w./$])(?:sh|bash|zsh)\s+(?:-[a-bd-zA-BD-Z]+\s+){0,2}"
    r"['\"]?((?:\./)?[a-zA-Z0-9_./-]+\.sh)['\"]?(?=$|[\s;&|])"
    r"|(?<![\w/$])((?:\./)[a-zA-Z0-9_./-]+\.sh)(?=$|[\s;&|])"
)


def literal_script_refs(command: str) -> list[str]:
    """Extract only literal .sh arguments; never expand user input."""
    refs: list[str] = []
    for match in SCRIPT_CALL.finditer(command):
        value = match.group(1) or match.group(2)
        if value not in refs:
            refs.append(value)
    return refs


def safe_script_path(root: Path, config: str, reference: str) -> tuple[str, Path] | None:
    """Refuse path escapes and symlinked components before opening a script."""
    parts = PurePosixPath(reference).parts
    if not parts or any(p == ".." for p in parts) or reference.startswith("/"):
        return None
    if any(p in (".git", "node_modules", "vendor", ".venv") for p in parts):
        return None
    # Scripts in package.json are relative to its directory. For editor/agent
    # configs, hook execution is generally rooted at the workspace.
    config_path = PurePosixPath(config)
    base = config_path.parent if config_path.name == "package.json" else PurePosixPath(".")
    rel = base.joinpath(reference)
    pieces = [p for p in rel.parts if p != "."]
    if not pieces or len(pieces) > 16:
        return None
    candidate = root.joinpath(*pieces)
    pointer = root
    for piece in pieces:
        pointer = pointer / piece
        if pointer.is_symlink():
            return None
    return PurePosixPath(*pieces).as_posix(), candidate


def review_script(*, root: Path, source: Finding, reference: str,
                  reader) -> list[Finding]:
    """Return a coverage warning or findings for suspicious literal lines."""
    target = safe_script_path(root, source.path, reference)
    if target is None:
        reason = "Reference is outside the approved literal local-script scope."
        return [_skipped(source, reference, reason)]
    relative, candidate = target
    try:
        if not candidate.exists():
            return [_skipped(source, reference, "Referenced script does not exist at this path.")]
        data = reader(candidate, MAX_SCRIPT_BYTES)
        if data is None:
            return [_skipped(source, reference, "Script exceeds the 128 KiB inspection limit.")]
        content = data.decode("utf-8-sig")
    except (OSError, UnicodeError) as exc:
        return [_skipped(source, reference, f"Script could not be read: {type(exc).__name__}.")]
    result: list[Finding] = []
    pending = ""
    start_line = 1
    for lineno, raw_line in enumerate(content.splitlines(), 1):
        if lineno > MAX_SCRIPT_LINES:
            result.append(_skipped(source, reference, "Script exceeds the 2,000-line analysis limit."))
            break
        if not pending:
            start_line = lineno
        trailing = len(raw_line) - len(raw_line.rstrip("\\"))
        if trailing % 2:
            pending += raw_line[:-1]
            continue
        line = (pending + raw_line).strip()
        pending = ""
        if not line or line.startswith("#"):
            continue
        severity, why, advice = assess(line, "low")
        if SEVERITIES[severity] < SEVERITIES["high"]:
            continue
        result.append(Finding.make(
            rule="referenced-shell-risk", severity=severity, path=relative,
            line=start_line, trigger=f"Referenced by {source.path}:{source.line} ({source.rule})",
            title="Potentially risky command in referenced local shell script",
            evidence=redact(line),
            why="This line is inside an explicitly referenced .sh file. " + why,
            advice=advice + " This is a static heuristic, not verified execution.",
            identity=f"{source.fingerprint}:{reference}:{start_line}:{line}",
        ))
    return result


def _skipped(source: Finding, reference: str, reason: str) -> Finding:
    return Finding.make(
        rule="referenced-script-unreadable", severity="medium", path=source.path,
        line=source.line, trigger=source.trigger,
        title="Referenced shell script not fully inspected",
        evidence=redact(reference), why=reason,
        advice="Inspect the reference manually; do not treat this scan as proof of safety.",
        identity=f"{source.fingerprint}:{reference}:unreadable:{reason}",
    )

"""Bounded, passive filesystem traversal and optional git-diff filtering."""
from __future__ import annotations

import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
from typing import Iterator

from .detectors import inspect
from .models import Finding, SEVERITIES

IGNORED = frozenset({".git", "node_modules", ".venv", "venv", "__pycache__", ".next", ".nuxt",
                     "dist", "build", ".tox", ".mypy_cache", ".pytest_cache", "vendor", ".terraform"})
MAX_BYTES = 512 * 1024
MAX_DEPTH = 16
MAX_FILES = 100_000


class ScanError(Exception):
    pass


def recognized(relative: str) -> bool:
    parts = PurePosixPath(relative).parts
    if not parts:
        return False
    basename = parts[-1]
    return (basename == "package.json" or
            (basename == "tasks.json" and ".vscode" in parts[:-1]) or
            (basename == "devcontainer.json" and ".devcontainer" in parts[:-1]) or
            (basename == "settings.json" and ".claude" in parts[:-1]) or
            (basename in ("mcp.json", ".mcp.json") or basename.endswith(".mcp.json")))


def _safe_git_environment() -> dict[str, str]:
    """Discard Git-specific environment overrides supplied by the host.

    Repository scans should honor neither GIT_CONFIG_* injection from a
    calling process nor global settings that can dispatch executable Git
    helpers. Git still reads its own local repository configuration, so
    changed_paths() also overrides known execution-capable settings.
    """
    environment = {
        key: value for key, value in os.environ.items()
        if not key.upper().startswith(("GIT_", "SSH_", "LD_", "DYLD_"))
        and key.upper() not in {"PYTHONPATH", "PYTHONSTARTUP"}
    }
    environment["GIT_CONFIG_NOSYSTEM"] = "1"
    environment["GIT_CONFIG_GLOBAL"] = os.devnull
    environment["GIT_TERMINAL_PROMPT"] = "0"
    environment["GIT_PAGER"] = "cat"
    return environment


def changed_paths(root: Path, ref: str) -> set[str]:
    if not re.fullmatch(r"[a-zA-Z0-9_][a-zA-Z0-9_./~^-]*", ref) or ref.startswith("-") or ".." in ref:
        raise ScanError("Invalid git ref; use a branch, tag or SHA")
    try:
        # Git repository-local config is untrusted. In particular, ordinary
        # git diff can invoke core.fsmonitor, even with --name-only. The
        # configured monitor is code execution, violating passive scanning.
        argv = [
            "git",
            "-c", "core.fsmonitor=false",
            "-c", f"core.hooksPath={os.devnull}",
            "-c", "diff.external=",
            "-c", "protocol.ext.allow=never",
            "-c", "protocol.file.allow=never",
            "-C", str(root),
            "diff", "--no-ext-diff", "--no-textconv",
            "--name-only", "-z", "--diff-filter=ACMR", ref, "--",
        ]
        proc = subprocess.run(
            argv, capture_output=True, timeout=15, check=False,
            stdin=subprocess.DEVNULL, env=_safe_git_environment(),
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        raise ScanError(f"git diff is unavailable: {exc}") from exc
    if proc.returncode != 0:
        raise ScanError("git diff failed: " + proc.stderr.decode("utf-8", "replace")[:300])
    return {p.decode("utf-8", "surrogateescape").replace("\\", "/") for p in proc.stdout.split(b"\0") if p}


def walk(root: Path) -> Iterator[tuple[str, Path]]:
    seen = 0
    def error_on_unreadable_directory(exc: OSError) -> None:
        raise ScanError(f"Unable to traverse directory: {type(exc).__name__}: {exc.strerror}") from exc

    for base, dirs, files in os.walk(root, followlinks=False, onerror=error_on_unreadable_directory):
        path = Path(base)
        try:
            depth = len(path.relative_to(root).parts)
        except ValueError:
            continue
        dirs[:] = sorted(d for d in dirs if d not in IGNORED and not (path / d).is_symlink() and depth < MAX_DEPTH)
        for name in sorted(files):
            seen += 1
            if seen > MAX_FILES:
                raise ScanError(f"Scan exceeds {MAX_FILES:,} files; narrow the project root")
            file_path = path / name
            if file_path.is_symlink():
                continue
            relative = file_path.relative_to(root).as_posix()
            if recognized(relative):
                yield relative, file_path


def read_regular_config(path: Path) -> bytes | None:
    """Read a bounded regular file without following symlinks where supported.

    A FIFO/device must never block the scanner. Read limits are enforced on
    actual bytes, not just an earlier potentially stale file size.
    """
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise OSError("Not a regular file")
        if metadata.st_size > MAX_BYTES:
            return None
        with os.fdopen(fd, "rb") as stream:
            fd = -1
            data = stream.read(MAX_BYTES + 1)
        return data if len(data) <= MAX_BYTES else None
    finally:
        if fd >= 0:
            os.close(fd)


def scan(root: Path, since: str | None = None) -> tuple[list[Finding], int, int]:
    if not root.is_dir() or root.is_symlink():
        raise ScanError(f"Not a directory (or symlink root): {root}")
    root = root.resolve()
    changed = changed_paths(root, since) if since else None
    findings: list[Finding] = []
    scanned = skipped = 0
    for relative, path in walk(root):
        if changed is not None and relative not in changed:
            continue
        try:
            data = read_regular_config(path)
            if data is None:
                skipped += 1
                findings.append(Finding.make(rule="oversize-config", severity="medium", path=relative,
                                             line=1, trigger="Static analysis", title="Config too large to scan",
                                             evidence=f"Maximum supported size: {MAX_BYTES} bytes",
                                             why="A possibly executable configuration was skipped.",
                                             advice="Review this file manually or reduce its size.", identity="oversize"))
                continue
            content = data.decode("utf-8-sig")
            scanned += 1
            findings.extend(inspect(relative, content))
        except (OSError, UnicodeError) as exc:
            skipped += 1
            findings.append(Finding.make(rule="unreadable-config", severity="medium", path=relative,
                                         line=1, trigger="Static analysis", title="Config could not be read",
                                         evidence=type(exc).__name__, why="The file was not inspected.",
                                         advice="Inspect it manually and confirm its encoding and permissions.",
                                         identity="unreadable"))
    findings.sort(key=lambda f: (-SEVERITIES[f.severity], f.path, f.line, f.rule, f.fingerprint))
    return findings, scanned, skipped

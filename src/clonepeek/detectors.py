"""Static execution-trigger detectors. No shell, imports or repository code run."""
from __future__ import annotations

import json
from pathlib import PurePosixPath
import re
from typing import Any

from .formats import line_for, load_json, redact
from .models import Finding

FETCH_EXEC = re.compile(r"(?is)(?:curl|wget|iwr|invoke-webrequest)\b[^\n|]{0,350}\|\s*(?:sudo\s+)?(?:ba?sh|zsh|sh|python\d?|node|pwsh|powershell|cmd|iex|invoke-expression)\b|\b(?:bash|sh|pwsh|powershell)\s+<(?:\(|\s)*\s*(?:curl|wget)\b")
# PowerShell download/execute also appears as iex (iwr URI).Content, not
# just the common iwr URI | iex pipe. This is a narrow static heuristic:
# it requires an Invoke-WebRequest call nested in Invoke-Expression.
POWERSHELL_EVAL_FETCH = re.compile(
    r"(?is)\b(?:iex|invoke-expression)\s*\(\s*(?:iwr|invoke-webrequest)\b[^)]{0,350}\)"
)
CREDENTIALS = re.compile(r"(?i)(?:\$\{?(?:[A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|API_KEY|PRIVATE_KEY|CREDENTIAL)[A-Z0-9_]*)\}?|process\.env|os\.environ|\.env\b|id_rsa\b|\.aws/credentials|\.ssh/)")
DESTRUCTIVE = re.compile(r"(?i)(?:\brm\s+-[a-z]*r[a-z]*f\b|\brm\s+-[a-z]*f[a-z]*r\b|\bformat\s+[a-z]:|\bmkfs\.|\bdel\s+/[fsq]|\bremove-item\b[^\n]{0,120}-(?:recurse|r)\b)")
ENCODED = re.compile(r"(?i)(?:base64\s+(?:-d|--decode)|\batob\s*\(|\bfrombase64string\s*\(|\beval\s*\(|\bexec\s*\(|\b(?:powershell|pwsh)(?:\.exe)?\b[^\n]{0,140}-(?:encodedcommand|enc)\b)")
NETWORK = re.compile(r"(?i)\b(?:curl|wget|fetch|iwr|invoke-webrequest)\b|https?://")
SHELL = re.compile(r"(?i)\b(?:bash|sh|zsh|pwsh|powershell|cmd(?:\.exe)?)\b")


def assess(command: str, base: str) -> tuple[str, str, str]:
    """Return severity, reason, and recommendation. Heuristics, not proof."""
    if FETCH_EXEC.search(command) or POWERSHELL_EVAL_FETCH.search(command):
        return "critical", "A network response appears to be piped directly to a command interpreter.", "Remove fetch-and-execute. Download, verify and pin artifacts before running."
    if CREDENTIALS.search(command) and NETWORK.search(command):
        return "critical", "Credentials and a network destination appear together; review for exfiltration.", "Inspect the full command and all referenced files before trusting it."
    if DESTRUCTIVE.search(command):
        return "high", "This command contains a potentially destructive filesystem operation.", "Verify paths and scope; avoid automatic destructive commands."
    if ENCODED.search(command):
        return "high", "Encoded or dynamic execution makes behavior harder to inspect.", "Replace opaque execution with reviewable source and locked dependencies."
    if NETWORK.search(command) and SHELL.search(command):
        return "high", "This command combines shell execution and network access.", "Inspect downloaded resources, destinations and privileges."
    if NETWORK.search(command):
        return max_severity(base, "medium"), "This command appears to contact the network.", "Verify destinations and pin any remote dependencies."
    return base, "An execution-capable lifecycle or configuration entry point exists.", "Review the command and anything it invokes before proceeding."


def max_severity(a: str, b: str) -> str:
    order = ["info", "low", "medium", "high", "critical"]
    return order[max(order.index(a), order.index(b))]


def flatten(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return " ".join(flatten(v) for v in value)
    if isinstance(value, dict):
        return " ; ".join(f"{key} {flatten(v)}" for key, v in value.items())
    return str(value)


def emit(*, rule: str, path: str, text: str, needle: str, trigger: str,
         title: str, command: str, base: str, start: int = 0,
         identity: str | None = None) -> Finding:
    severity, why, advice = assess(command, base)
    return Finding.make(rule=rule, severity=severity, path=path,
                        line=line_for(text, needle, start), trigger=trigger,
                        title=title, evidence=redact(command), why=why,
                        advice=advice, identity=identity or command)


def inspect(path: str, text: str) -> list[Finding]:
    """Inspect a recognized config file, reporting malformed configs as warnings."""
    p = PurePosixPath(path)
    result: list[Finding] = []
    is_vscode = p.name == "tasks.json" and ".vscode" in p.parts
    is_devcontainer = p.name == "devcontainer.json" and ".devcontainer" in p.parts
    is_package = p.name == "package.json"
    is_mcp = p.name in ("mcp.json", ".mcp.json") or (p.name.endswith(".mcp.json"))
    is_claude = p.name == "settings.json" and ".claude" in p.parts
    if not (is_vscode or is_devcontainer or is_package or is_mcp or is_claude):
        return result
    try:
        obj = load_json(text, jsonc=is_vscode or is_devcontainer or is_mcp)
        if not isinstance(obj, dict):
            raise ValueError("Expected a JSON object")
    except (json.JSONDecodeError, ValueError, RecursionError) as exc:
        return [Finding.make(rule="config-parse", severity="medium", path=path, line=1,
                             trigger="Static analysis", title="Configuration could not be parsed",
                             evidence=f"{type(exc).__name__}: {redact(str(exc))}",
                             why="This file could contain execution entry points not covered by the scan.",
                             advice="Fix the syntax and scan again; do not treat it as clean.",
                             identity="parse-error")]
    if is_vscode:
        tasks = obj.get("tasks", [])
        if isinstance(tasks, list):
            cursor = 0
            for index, task in enumerate(tasks):
                if not isinstance(task, dict):
                    continue
                if not isinstance(task.get("runOptions"), dict) or task["runOptions"].get("runOn") != "folderOpen":
                    continue
                commands = [flatten(task.get("command", "")), flatten(task.get("args", []))]
                for platform in ("linux", "osx", "windows"):
                    if isinstance(task.get(platform), dict):
                        commands.append(flatten(task[platform].get("command", "")))
                        commands.append(flatten(task[platform].get("args", [])))
                command = " ".join(filter(None, commands)) or "<task refers to another entry point>"
                hidden = isinstance(task.get("presentation"), dict) and task["presentation"].get("reveal") in ("silent", "never")
                evidence = command + (" [hidden terminal output]" if hidden else "")
                start = text.find('"runOn"', cursor)
                if start >= 0:
                    cursor = start + 7
                finding = emit(rule="vscode-folder-open", path=path, text=text, needle='"runOn"',
                               start=max(0, start), trigger="Opening/trusting folder in VS Code-compatible editor",
                               title=f"Auto-run editor task: {redact(str(task.get('label', index)), 70)}",
                               command=evidence, base="high", identity=f"{index}:{command}:{hidden}")
                if hidden and finding.severity == "high":
                    finding = Finding.make(rule=finding.rule, severity="high", path=path, line=finding.line,
                                           trigger=finding.trigger, title=finding.title,
                                           evidence=finding.evidence, why="This folder-open task hides terminal output.",
                                           advice="Disable automatic tasks and inspect this task before trusting the workspace.",
                                           identity=f"{index}:{command}:{hidden}")
                result.append(finding)
    if is_package:
        scripts = obj.get("scripts", {})
        if isinstance(scripts, dict):
            events = {"preinstall": "npm install (before install)", "install": "npm install", "postinstall": "npm install (after install)",
                      "prepare": "npm install/pack in supported npm workflows", "prepack": "npm pack/publish", "postpack": "npm pack/publish",
                      "prepublishOnly": "npm publish", "prepublish": "npm install/publish (legacy)"}
            for key, trigger in events.items():
                if isinstance(scripts.get(key), str):
                    result.append(emit(rule="npm-lifecycle", path=path, text=text,
                                       needle=f'"{key}"', trigger=trigger,
                                       title=f"npm lifecycle script: {key}", command=scripts[key],
                                       base="medium", identity=f"{key}:{scripts[key]}"))
    if is_devcontainer:
        events = {"initializeCommand": "Starting devcontainer setup on host", "onCreateCommand": "First container creation",
                  "updateContentCommand": "Container content update", "postCreateCommand": "After container creation",
                  "postStartCommand": "Every devcontainer start", "postAttachCommand": "Attaching to devcontainer"}
        for key, trigger in events.items():
            if key in obj:
                cmd = flatten(obj[key])
                result.append(emit(rule="devcontainer-lifecycle", path=path, text=text,
                                   needle=f'"{key}"', trigger=trigger,
                                   title=f"Devcontainer command: {key}", command=cmd,
                                   base="medium", identity=f"{key}:{cmd}"))
        features = obj.get("features", {})
        if isinstance(features, dict):
            for name in features:
                result.append(Finding.make(rule="devcontainer-feature", severity="low", path=path,
                                           line=line_for(text, '"features"'), trigger="Building a devcontainer",
                                           title="Devcontainer feature installs extra code",
                                           evidence=redact(str(name)), why="Features can run installation code during container setup.",
                                           advice="Review the feature source and pin its version.", identity=str(name)))
    if is_claude:
        hooks = obj.get("hooks", {})
        if isinstance(hooks, dict):
            cursor = 0
            for event, groups in hooks.items():
                if not isinstance(groups, list):
                    continue
                for group_index, group in enumerate(groups):
                    if not isinstance(group, dict) or not isinstance(group.get("hooks"), list):
                        continue
                    matcher = group.get("matcher", "*")
                    for hook_index, hook in enumerate(group["hooks"]):
                        if not isinstance(hook, dict) or hook.get("type") != "command":
                            continue
                        if not isinstance(hook.get("command"), str):
                            continue
                        command = " ".join(filter(None, [hook["command"], flatten(hook.get("args", []))]))
                        key = re.search(r'"command"\s*:', text[cursor:])
                        start = cursor + key.start() if key else 0
                        if key:
                            cursor += key.end()
                        result.append(emit(rule="claude-hook-command", path=path, text=text,
                                           needle='"command"', start=max(0, start),
                                           trigger=f"Claude Code {redact(str(event), 45)} event (matcher: {redact(str(matcher), 55)})",
                                           title=f"Claude Code command hook: {redact(str(event), 60)}",
                                           command=command,
                                           base="high" if event in ("SessionStart", "Setup") else "medium",
                                           identity=f"{event}:{group_index}:{hook_index}:{matcher}:{command}"))
    if is_mcp:
        servers = obj.get("mcpServers", obj.get("servers", {}))
        if isinstance(servers, dict):
            for name, cfg in servers.items():
                if not isinstance(cfg, dict) or not isinstance(cfg.get("command"), str):
                    continue
                cmd = " ".join([cfg["command"], flatten(cfg.get("args", []))])
                result.append(emit(rule="mcp-server-process", path=path, text=text,
                                   needle=f'"{name}"', trigger="Agent client starts/approves a local MCP server",
                                   title=f"MCP server process: {redact(str(name), 60)}",
                                   command=cmd, base="medium", identity=f"{name}:{cmd}"))
    return result

"""GitHub composite action adapter. No shell commands run from the target.

This file is loaded from the immutable action checkout, *not* from the
repository being scanned. It uses ClonePeek's Python API and no network calls.
"""
from __future__ import annotations

from collections import Counter
import json
import os
from pathlib import Path
import sys
from typing import Mapping

# Avoid installing dependencies or importing packages from the untrusted tree.
sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from clonepeek import __version__
from clonepeek.formats import load_baseline, render_text, sarif
from clonepeek.models import SEVERITIES
from clonepeek.scanner import ScanError, scan


def perform(env: Mapping[str, str] | None = None) -> int:
    """Return 0=success, 1=threshold exceeded, 2=scan/config error."""
    if env is None:
        env = os.environ
    path = env.get("CLONEPEEK_INPUT_PATH") or "."
    threshold = (env.get("CLONEPEEK_INPUT_FAIL_ON") or "none").lower()
    format_name = (env.get("CLONEPEEK_INPUT_FORMAT") or "text").lower()
    output = env.get("CLONEPEEK_INPUT_OUTPUT") or ""
    since = env.get("CLONEPEEK_INPUT_CHANGED_SINCE") or None
    baseline_file = env.get("CLONEPEEK_INPUT_BASELINE") or None
    if threshold not in {*SEVERITIES, "none"}:
        print("clonepeek action: fail-on must be none, low, medium, high or critical", file=sys.stderr)
        return 2
    if format_name not in {"text", "json", "sarif"}:
        print("clonepeek action: format must be text, json or sarif", file=sys.stderr)
        return 2

    try:
        if any(char in output for char in "\r\n"):
            raise ValueError("Output path must not contain line breaks")
        findings, scanned, skipped = scan(Path(path), since)
        known = load_baseline(Path(baseline_file)) if baseline_file else set()
        if format_name == "text":
            rendered = render_text(findings, scanned, skipped, known if baseline_file else None)
        elif format_name == "sarif":
            rendered = json.dumps(sarif(findings), indent=2)
        else:
            rendered = json.dumps({
                "tool": "clonepeek", "version": __version__, "scanned": scanned,
                "skipped": skipped,
                "findings": [dict(f.to_dict(), status="known" if f.fingerprint in known else "new")
                             for f in findings],
            }, indent=2)
        if output:
            report = Path(output)
            # Only workflow authors control the output path. Do not assume it
            # is safe to publish the content to GitHub artifacts or PR logs.
            report.parent.mkdir(parents=True, exist_ok=True)
            report.write_text(rendered + "\n", encoding="utf-8")
            print(f"ClonePeek {__version__}: report saved to {report}")
        else:
            print(rendered)
        counts = Counter(f.severity for f in findings)
        novel = [f for f in findings if f.fingerprint not in known]
        fields = {
            "findings": len(findings), "new-findings": len(novel),
            "critical": counts["critical"], "high": counts["high"],
            "scanned": scanned, "report-path": output,
        }
        if env.get("GITHUB_OUTPUT"):
            with open(env["GITHUB_OUTPUT"], "a", encoding="utf-8") as stream:
                for key, value in fields.items():
                    stream.write(f"{key}={value}\n")
        if env.get("GITHUB_STEP_SUMMARY"):
            with open(env["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as stream:
                stream.write("## ClonePeek — passive repository audit\n\n")
                stream.write(f"**{len(findings)}** findings, **{len(novel)}** new, ")
                stream.write(f"**{scanned}** configs inspected, **{skipped}** skipped.\n\n")
                stream.write("| Critical | High | Medium | Low | Info |\n| ---: | ---: | ---: | ---: | ---: |\n")
                stream.write("| " + " | ".join(str(counts[s]) for s in ("critical", "high", "medium", "low", "info")) + " |\n\n")
                stream.write("Heuristic execution-surface review, **not** malware detection or proof of safety. ")
                stream.write("Reports may contain source excerpts: review before publishing.\n")
        if threshold != "none" and any(
            SEVERITIES[f.severity] >= SEVERITIES[threshold] for f in novel
        ):
            print(f"clonepeek action: {threshold}+ threshold exceeded by new finding(s)", file=sys.stderr)
            return 1
        return 0
    except (ScanError, OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        print(f"clonepeek action: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(perform())

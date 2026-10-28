"""CLI with predictable exit codes and no implicit telemetry or network calls."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from . import __version__
from .formats import baseline, load_baseline, render_text, sarif
from .models import SEVERITIES
from .scanner import ScanError, scan


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="clonepeek", description="Know what can run before opening, installing or trusting a repository.")
    parser.add_argument("path", nargs="?", default=".", help="Local repository directory (default: current directory)")
    parser.add_argument("--format", choices=("text", "json", "sarif"), default="text", help="Report format")
    parser.add_argument("--output", type=Path, help="Write report to file instead of stdout")
    parser.add_argument("--fail-on", choices=("low", "medium", "high", "critical"), help="Exit 1 for NEW findings at or above level")
    parser.add_argument("--baseline", type=Path, help="Suppress existing fingerprints from --fail-on (but still report them)")
    parser.add_argument("--write-baseline", type=Path, help="Write baseline with all current findings")
    parser.add_argument("--changed-since", metavar="REF", help="Inspect tracked configs changed since a git ref (excludes untracked files)")
    parser.add_argument("--version", action="version", version=f"ClonePeek {__version__}")
    return parser


def run(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.output and args.write_baseline and args.output.resolve() == args.write_baseline.resolve():
            raise ValueError("--output and --write-baseline must use different paths")
        if args.output and args.baseline and args.output.resolve() == args.baseline.resolve():
            raise ValueError("--output must not overwrite the input baseline")
        findings, scanned, skipped = scan(Path(args.path), args.changed_since)
        known = load_baseline(args.baseline) if args.baseline else set()
        if args.write_baseline:
            args.write_baseline.write_text(json.dumps(baseline(findings), indent=2) + "\n", encoding="utf-8")
        if args.format == "json":
            content = json.dumps({"tool": "clonepeek", "version": __version__, "scanned": scanned,
                                  "skipped": skipped, "findings": [dict(f.to_dict(), status="known" if f.fingerprint in known else "new") for f in findings]},
                                 indent=2)
        elif args.format == "sarif":
            content = json.dumps(sarif(findings), indent=2)
        else:
            content = render_text(findings, scanned, skipped, known if args.baseline else None)
        if args.output:
            args.output.write_text(content + "\n", encoding="utf-8")
        else:
            print(content)
        if args.fail_on and any(SEVERITIES[f.severity] >= SEVERITIES[args.fail_on] and f.fingerprint not in known for f in findings):
            return 1
        return 0
    except (ScanError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"clonepeek: {exc}", file=sys.stderr)
        return 2


def main() -> int:
    return run()

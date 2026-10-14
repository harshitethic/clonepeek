"""Transparent synthetic configuration evaluation, NOT real-world accuracy."""
from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
from tempfile import TemporaryDirectory

from clonepeek.scanner import recognized, scan

CASES_PATH = Path(__file__).parent / "cases.json"
RULES = (
    "vscode-folder-open",
    "npm-lifecycle",
    "devcontainer-lifecycle",
    "devcontainer-feature",
    "mcp-server-process",
    "claude-hook-command",
    "config-parse",
    "oversize-config",
    "unreadable-config",
)


def _score(expected: list[bool], predicted: list[bool]) -> dict:
    """Case-level binary confusion metrics; never interpret as malware truth."""
    if len(expected) != len(predicted):
        raise ValueError("Expected and predicted lengths differ")
    tp = sum(e and p for e, p in zip(expected, predicted))
    fp = sum(not e and p for e, p in zip(expected, predicted))
    fn = sum(e and not p for e, p in zip(expected, predicted))
    tn = len(expected) - tp - fp - fn
    return {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": tp / (tp + fp) if tp + fp else None,
        "recall": tp / (tp + fn) if tp + fn else None,
        "support": tp + fn,
    }


def _wilson_interval(success: int, trials: int) -> list[float] | None:
    """Wilson score 95% interval for a tiny binomial *fixture sample*.

    These intervals describe sampling uncertainty under a hypothetical
    independent representative sample, an assumption the curated corpus
    does NOT satisfy. They are diagnostic, not field-performance estimates.
    """
    if trials == 0:
        return None
    z = 1.959963984540054
    phat = success / trials
    denom = 1 + z * z / trials
    center = (phat + z * z / (2 * trials)) / denom
    margin = z * math.sqrt(phat * (1 - phat) / trials + z * z / (4 * trials * trials)) / denom
    return [max(0.0, center - margin), min(1.0, center + margin)]


def _evaluate_cases(cases: list[dict]) -> dict:
    if not isinstance(cases, list) or not cases:
        raise ValueError("Corpus must be a non-empty array")
    ids: set[str] = set()
    outcomes = []
    for case in cases:
        if not isinstance(case, dict):
            raise ValueError("Each fixture must be an object")
        case_id = case.get("id")
        path = case.get("path")
        rules = case.get("expected_rules")
        if not isinstance(case_id, str) or not case_id or case_id in ids:
            raise ValueError("Fixture ID missing or duplicated")
        if not isinstance(path, str) or not recognized(path):
            raise ValueError(f"Invalid or unrecognized fixture path for {case_id}")
        if ".." in Path(path).parts or Path(path).is_absolute():
            raise ValueError(f"Fixture attempts path traversal: {case_id}")
        if not isinstance(case.get("content"), str) or not isinstance(case.get("high_risk"), bool):
            raise ValueError(f"Fixture content or high-risk classification invalid: {case_id}")
        if not isinstance(case.get("why"), str) or len(case["why"].strip()) < 12:
            raise ValueError(f"Fixture is missing an independent rationale: {case_id}")
        if not isinstance(rules, list) or any(
            not isinstance(r, str) or r not in RULES for r in rules
        ) or len(set(rules)) != len(rules):
            raise ValueError(f"Invalid expected rule labels: {case_id}")
        ids.add(case_id)
        with TemporaryDirectory(prefix="clonepeek-fixture-") as work:
            destination = Path(work) / path
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(case["content"], encoding="utf-8")
            findings, inspected, skipped = scan(Path(work))
        if skipped:
            raise RuntimeError(f"Fixture unexpectedly skipped: {case_id}")
        if inspected != 1:
            raise RuntimeError(f"Fixture should inspect exactly one file: {case_id}")
        detected_rules = sorted({finding.rule for finding in findings})
        predicted = any(f.severity in ("high", "critical") for f in findings)
        outcomes.append({
            "id": case_id,
            "expected_high_risk": case["high_risk"],
            "predicted_high_risk": predicted,
            "expected_rules": sorted(rules),
            "rules": detected_rules,
            "severities": [f.severity for f in findings],
            "why": case["why"],
        })

    overall = _score(
        [x["expected_high_risk"] for x in outcomes],
        [x["predicted_high_risk"] for x in outcomes],
    )
    by_rule = {}
    for rule in RULES:
        by_rule[rule] = _score(
            [rule in x["expected_rules"] for x in outcomes],
            [rule in x["rules"] for x in outcomes],
        )
        per_rule = by_rule[rule]
        per_rule["precision_wilson_95"] = _wilson_interval(
            per_rule["tp"], per_rule["tp"] + per_rule["fp"]
        )
        per_rule["recall_wilson_95"] = _wilson_interval(
            per_rule["tp"], per_rule["tp"] + per_rule["fn"]
        )

    return {
        "disclaimer": "Hand-authored synthetic fixtures. NOT measured real-world security or malware detection accuracy.",
        "cases": len(outcomes),
        "threshold": "high",
        **overall,
        "by_rule": by_rule,
        "outcomes": outcomes,
    }


def evaluate() -> dict:
    return _evaluate_cases(json.loads(CASES_PATH.read_text(encoding="utf-8")))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--format", choices=("text", "json"), default="text")
    args = parser.parse_args()
    report = evaluate()
    if args.format == "json":
        print(json.dumps(report, indent=2))
    else:
        print("HAND-AUTHORED SYNTHETIC FIXTURES ONLY — not real-world detection accuracy")
        print("Cases: {cases} | TP {tp} | FP {fp} | FN {fn} | TN {tn}".format(**report))
        print("High-risk fixture precision: {:.1%} | recall: {:.1%}".format(
            report["precision"], report["recall"]
        ))
        print("Rule presence per fixture (not maliciousness classification):")
        for rule, detail in report["by_rule"].items():
            if detail["support"] == 0 and detail["fp"] == 0:
                continue
            precision = "n/a" if detail["precision"] is None else f'{detail["precision"]:.1%}'
            recall = "n/a" if detail["recall"] is None else f'{detail["recall"]:.1%}'
            print(
                f'  {rule}: support={detail["support"]}, '
                f'TP={detail["tp"]} FP={detail["fp"]} FN={detail["fn"]} '
                f'precision={precision} recall={recall}'
            )
        for case in report["outcomes"]:
            if case["expected_high_risk"] != case["predicted_high_risk"]:
                print(f'RISK MISS: {case["id"]} — {case["why"]}')
            if set(case["expected_rules"]) != set(case["rules"]):
                print(f'RULE MISMATCH: {case["id"]} '
                      f'expected={case["expected_rules"]} observed={case["rules"]}')


if __name__ == "__main__":
    main()

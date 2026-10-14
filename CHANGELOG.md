# Changelog

## 0.2.2 — 2026-10-14

- Expand the labeled, synthetic evaluation corpus from 12 to 46 cases,
  including benign and suspicious Windows PowerShell scenarios.
- Fix a reproduced false negative: `iex (iwr ...).Content` and
  `Invoke-Expression (Invoke-WebRequest ...).Content` now receive
  critical fetch-and-execute urgency.
- Add per-rule recognition confusion matrices, fixture support,
  Wilson 95% intervals and clear invalid/zero-support handling.
- Preserve measured high-risk false positives and false negatives,
  explicitly distinguishing review urgency from real-world security.
- Add corpus validation and CLI regression tests across CI platforms.


## 0.2.1 — 2026-10-14

- Fix unsafe Git filesystem monitor execution during passive changed-file scans.
- Add adversarial regression for repository-local/global config and inherited Git environment overrides.
- Document reproduction, mitigation, and remaining Git trust limitations.

## 0.2.0 — 2026-10-14

- Add Claude Code project command-hook detection with lifecycle triggers and corrected line mapping.
- Add PowerShell fetch-and-execute, encoded-command, and recursive file-deletion heuristics.
- Reject special files including FIFOs, cap bytes actually read, and avoid following symlinks where supported.
- Publish a 12-case labeled **synthetic** evaluation, including a documented false positive and false negative.
- Expand regression coverage and include evaluation in the cross-platform CI matrix.

## 0.1.0 — 2026-10-14

- First-run static scanner for VS Code automatic tasks, npm lifecycle scripts, devcontainer lifecycle commands/features and local MCP server commands.
- JSON/JSONC parser, stable fingerprints, baselines, changed-files inspection, JSON/SARIF output, CI severity thresholds.
- Deterministic standard-library runtime; bounded filesystem traversal with no symlink following.
- Sample fixture, cross-platform CI matrix and documented threat model.

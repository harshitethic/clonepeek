# Changelog

## 0.5.1 — 2026-10-16

- Improve best-effort evidence masking for common credential-bearing CLI flags, quoted assignments and HTTP Bearer headers in text, JSON, and SARIF output. **Review reports before sharing:** custom secret formats can still leak.
- Publish machine-readable versioned JSON scan-report v1 schema and an inert example for CI integration. Schema version is independent of package version and does not establish scanner accuracy.
- Add nine targeted regression tests across redaction and JSON contract / Action output checks; preserve a standard-library-only runtime.
- Refresh CLI, reusable GitHub Action and website installation instructions to the patched tag, without rewriting historical v0.5.0 reproducibility records.

## 0.5.0 — 2026-10-15

- Ship an install-free composite GitHub Action that runs the Python scanner from the versioned action checkout against the user’s repository.
- Add configurable report-only and severity-gated modes, JSON/SARIF/text output, changed-ref and baseline inputs.
- Emit count-only GitHub Step Summary and declared machine-readable outputs without leaking source excerpts in the summary.
- Validate Windows, Linux and macOS reusable action execution in a separate CI workflow, including expected failure thresholds.
- Add action-runner security regression tests and documentation with a pinned example workflow.

## 0.4.1 — 2026-10-15

- Fix `--changed-since` to inspect a tracked `.sh` script when its text changes but the configuration that references it does not.
- Keep unchanged configuration findings out of diff-only results; emit script-specific findings with their correct origin.
- Add a real temporary Git repository regression test and preserve passive, bounded script reading.

## 0.4.0 — 2026-10-15

- Add one-hop, read-only review of explicit local shell-script references from modeled editor/package/agent lifecycle configurations.
- Report risky referenced script lines with original path, line, and entry-point trigger; warn for missing, symlinked, unreadable, or oversized scripts.
- Bound inspection to 32 references per scan, 128 KiB and 2,000 lines per script; reject path escapes and avoid executing anything.
- Add an illustrative `.invalid` example, integration/regression tests, and explicit threat-model caveats.
- Keep the existing 51-case synthetic evaluation separate from multi-file integration tests; do not misrepresent toy scores as field accuracy.

## 0.3.0 — 2026-10-15

- Add Cursor project command-hook scanning for `.cursor/hooks.json`, including trusted workspace open, session and tool events, trigger descriptions, and source-line evidence.
- Add Claude `.claude/settings.local.json` detection and fix SARIF version metadata to reflect the installed package.
- Extend transparent synthetic evaluation to 51 cases, including both benign and suspicious Cursor hooks; document known false positives and limitations.
- Provide a combined agent-hooks demonstration, an authentic terminal preview, and explicit documentation.
- Add regression tests for Cursor configuration, JSONC, scoped detection, and version metadata.

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

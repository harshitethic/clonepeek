# Rules and confidence

ClonePeek uses static rules. Severity reflects *review urgency*, not proof that an artifact is malicious.

| Rule | Default | Trigger | Notes |
| --- | --- | --- | --- |
| `vscode-folder-open` | High | `runOn: folderOpen` task | Includes platform-specific commands and hidden `presentation.reveal`. Trust settings vary by editor/version. |
| `npm-lifecycle` | Medium | npm lifecycle scripts | Covers preinstall/install/postinstall, preprepare/prepare/postprepare, prepack/postpack, prepublish/prepublishOnly/publish/postpublish, and dependencies. Other package managers can differ. |
| `devcontainer-lifecycle` | Medium | setup/start/attach lifecycle commands | `initializeCommand` runs on host; other commands run in the container context. |
| `devcontainer-feature` | Low | devcontainer feature installation | Version pinning is important; feature implementation is not analyzed. |
| `mcp-server-process` | Medium | client starts/approves configured local MCP process | Remote URL-only servers are currently out of scope. |
| `claude-hook-command` | Medium; High for `SessionStart`/`Setup` | Claude Code lifecycle event triggers a `type: command` hook | Parses `.claude/settings.json`, reports event, matcher and command. Prompt, HTTP and MCP hooks are out of scope. |
| `cursor-hook-command` | Medium; High for `workspaceOpen`/`sessionStart` | Cursor project hook commands in `.cursor/hooks.json` | Event and matcher are shown; prompt hooks are not shell execution. |
| `referenced-shell-risk` | High/Critical | A recognized entry point explicitly launches a local `.sh` file whose text contains a heuristic match | First-hop only, no execution, no parsing of shell control flow. |
| `referenced-script-unreadable` | Medium | Missing, excluded, or oversized referenced script; reference budget exhausted | This is incomplete coverage, not proof of danger. |
| `config-parse`, `oversize-config`, `unreadable-config` | Medium | incomplete scan | Fail visibility: a skipped/invalid relevant config is never called clean. |

## Severity escalation

1. **Critical:** commands appear to pipe a remote download directly to a shell/interpreter, or reference credential data alongside network access.
2. **High:** destructive filesystem command, opaque decode/eval, or network and shell commands together. PowerShell encoded commands, `Remove-Item -Recurse`, and `iwr | iex` are explicitly covered.
3. **Medium:** network calls or executable lifecycle entries.
4. **Low:** feature setup and reviewable surfaces with lower direct impact.

These patterns are conservative and imperfect: commands can hide behavior behind scripts, aliases, language eval, alternate encodings, multi-line expressions and shell substitution. Conversely, legitimate lifecycle scripts may be high severity.

## Additional command review (October 2026)

The extended classifier adds **29 individually named static signatures**
for execution-capable configuration entries. These supplement rather than
replace the core fetch-and-execute, credential, and encoded-code rules.

- **Remote-code execution:** command substitution into shell and language
  interpreters (including `bash -c`, `eval`, Python, Node.js, Perl, and Ruby);
  PowerShell REST/WebClient expression execution; and downloaded content
  piped to BusyBox, Perl, or PHP.
- **Potential data loss:** force-clean and hard-reset Git commands,
  `find -delete` and `find -exec rm`, `rsync --delete`,
  `robocopy /MIR`, block device overwrites and erasure, recursive Windows
  directory removal, Docker volume pruning, and automatic Terraform destroy.

**Important limits:** these rules inspect command *text* only. They cannot
prove a command ran, infer every shell quoting context, or determine whether
a target path is valuable. A safe-looking wrapper can hide dangerous behavior,
and a quoted example can be flagged. The command catalog intentionally avoids
executing, resolving, or fetching anything from the scanned repository.

The regression suite in `tests/test_extended_risks.py` checks each signature
through the severity assessor and the npm lifecycle integration, plus safe
alternatives such as `git clean -ndfx`, `shred --help`, and
`wipefs --no-act`. It uses only illustrative `.invalid` URLs and
never executes the example commands.

## Output stability

Fingerprints hash the rule, relative path, trigger and raw command identity, not the line number. An inserted comment does not invalidate a baseline, while a changed command usually does. Baselines do not auto-update. `--fail-on` uses `critical > high > medium > low` and excludes exact fingerprints present in an explicit baseline.

The redactor masks **some recognizable secrets** in CLI evidence. Because command strings may contain arbitrarily encoded or unrecognized credentials, **review reports before publishing them**. Prefer storing reports as access-controlled CI artifacts.

## Labeled synthetic evaluation

Run `python -m evaluation.evaluate` after installing this package. The
51-case **hand-authored synthetic** corpus reports high-risk TP=18, FP=4,
FN=2 and TN=26 (precision 81.8%, recall 90.0%) at the `high`
threshold. Separate per-rule surface-presence counts are available in the
JSON output, including `null` when a metric is unidentifiable. These
scores are **not a statistically valid real-world security estimate**.

The corpus intentionally includes harmless VS Code folder-open tasks
flagged `high`, referenced scripts that are not transitively inspected,
and Windows PowerShell expression-style fetch-and-execute fixtures.
See [EVALUATION.md](EVALUATION.md) for exact breakdown and limits.

## Public smoke test

ClonePeek v0.3.0 was run against a public command-hook configuration from the official Cursor cookbook: 7 hook command findings, all medium. This validates that the basic format is recognized, **not** real-world security accuracy. See [REAL-WORLD-VALIDATION.md](REAL-WORLD-VALIDATION.md).

## First-hop local script review

In v0.4.0, explicit `sh scripts/setup.sh`, `bash ./scripts/setup.sh`, or `./scripts/setup.sh` references may be inspected when they appear in modeled execution configurations. The scanner analyzes at most **32** references, reads at most **128 KiB** and **2,000 lines** per referenced script, and never launches a script or follows symlinked references. It reports dangerous-looking text with its own source line and the originating configuration. These are plain-text heuristics; quoted examples and unreachable branches can generate false positives. Dynamic paths, nested scripts, PowerShell files, and interpreted code in other languages remain unsupported.


### Added high-impact operations

The command classifier also escalates irreversible or disruptive operations
in Git (force pushes), Docker (volume removal), Kubernetes (bulk deletion and
namespace removal), Helm (release removal), AWS S3 (recursive deletion and bucket
removal), Terraform (unattended apply), and Google Cloud (project deletion).

Dry-run and help-only forms are explicitly excluded where recognized. These
are static heuristics on command strings, not proof that commands will execute,
and should be reviewed in their full repository context.

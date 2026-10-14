# Rules and confidence

ClonePeek uses static rules. Severity reflects *review urgency*, not proof that an artifact is malicious.

| Rule | Default | Trigger | Notes |
| --- | --- | --- | --- |
| `vscode-folder-open` | High | `runOn: folderOpen` task | Includes platform-specific commands and hidden `presentation.reveal`. Trust settings vary by editor/version. |
| `npm-lifecycle` | Medium | npm lifecycle scripts | Only preinstall/install/postinstall/prepare/prepack/postpack/prepublishOnly/prepublish. Other package managers can differ. |
| `devcontainer-lifecycle` | Medium | setup/start/attach lifecycle commands | `initializeCommand` runs on host; other commands run in the container context. |
| `devcontainer-feature` | Low | devcontainer feature installation | Version pinning is important; feature implementation is not analyzed. |
| `mcp-server-process` | Medium | client starts/approves configured local MCP process | Remote URL-only servers are currently out of scope. |
| `claude-hook-command` | Medium; High for `SessionStart`/`Setup` | Claude Code lifecycle event triggers a `type: command` hook | Parses `.claude/settings.json`, reports event, matcher and command. Prompt, HTTP and MCP hooks are out of scope. |
| `config-parse`, `oversize-config`, `unreadable-config` | Medium | incomplete scan | Fail visibility: a skipped/invalid relevant config is never called clean. |

## Severity escalation

1. **Critical:** commands appear to pipe a remote download directly to a shell/interpreter, or reference credential data alongside network access.
2. **High:** destructive filesystem command, opaque decode/eval, or network and shell commands together. PowerShell encoded commands, `Remove-Item -Recurse`, and `iwr | iex` are explicitly covered.
3. **Medium:** network calls or executable lifecycle entries.
4. **Low:** feature setup and reviewable surfaces with lower direct impact.

These patterns are conservative and imperfect: commands can hide behavior behind scripts, aliases, language eval, alternate encodings, multi-line expressions and shell substitution. Conversely, legitimate lifecycle scripts may be high severity.

## Output stability

Fingerprints hash the rule, relative path, trigger and raw command identity, not the line number. An inserted comment does not invalidate a baseline, while a changed command usually does. Baselines do not auto-update. `--fail-on` uses `critical > high > medium > low` and excludes exact fingerprints present in an explicit baseline.

The redactor masks **some recognizable secrets** in CLI evidence. Because command strings may contain arbitrarily encoded or unrecognized credentials, **review reports before publishing them**. Prefer storing reports as access-controlled CI artifacts.

## Labeled synthetic evaluation

Run `python -m evaluation.evaluate` after installing this package. The
46-case **hand-authored synthetic** corpus reports high-risk TP=15, FP=3,
FN=2 and TN=26 (precision 83.3%, recall 88.2%) at the `high`
threshold. Separate per-rule surface-presence counts are available in the
JSON output, including `null` when a metric is unidentifiable. These
scores are **not a statistically valid real-world security estimate**.

The corpus intentionally includes harmless VS Code folder-open tasks
flagged `high`, referenced scripts that are not transitively inspected,
and Windows PowerShell expression-style fetch-and-execute fixtures.
See [EVALUATION.md](EVALUATION.md) for exact breakdown and limits.

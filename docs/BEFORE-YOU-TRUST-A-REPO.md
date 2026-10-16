# Before You Trust a Repository: A 5-Minute Execution-Hook Audit

> A practical, read-only checklist for engineers opening someone else's source code. Written by the maintainer of [ClonePeek](https://github.com/harshitethic/clonepeek). This is **not** an antivirus guide, malware verdict, or substitute for a sandbox.

You found a useful GitHub repository. Perhaps it is a job interview sample, a new development dependency, an AI-agent template, or a project you want to contribute to. Before you install its packages, trust it in your editor, or run its development container, answer one question:

**What does the repository configure other tools to run on your behalf?**

Source code does not need to be deliberately invoked through `python main.py` to become executable. Common developer workflows have built-in execution triggers, and many of them are completely legitimate. The challenge is reviewing them *before* the trigger fires.

## 1. Don't conflate downloading with trusting

Download the source in a separate directory, and **do not immediately install its dependencies, open it as a trusted IDE workspace, start a devcontainer, or activate its agent hooks**. Even a Git clone is not an isolation boundary: your machine's existing Git configuration and credential helpers may run during Git operations.

If you are reviewing truly suspicious material, use a disposable, appropriately isolated environment and inspect the source archive first. A read-only CLI scanner is **not** a containment or malware-analysis system.

## 2. Check the known execution surfaces

| File or setting | What can make it execute? | Review question |
| --- | --- | --- |
| `.vscode/tasks.json` with `runOptions.runOn: folderOpen` | Opening a **trusted** workspace if automatic tasks are enabled/approved | Which task command runs, and are its arguments trustworthy? |
| `package.json` lifecycle scripts such as `preinstall`, `install`, `postinstall`, `prepare` | Supported package-manager lifecycle events | Does the hook call another script or access the network? |
| `.devcontainer/devcontainer.json` lifecycle commands | Creating, starting, or attaching to a development container | What runs and with which container/host privileges? |
| `.cursor/hooks.json` | Cursor agent or workspace hook events | Is the command expected, local, and reviewable? |
| `.claude/settings.json` hook commands | Configured Claude Code lifecycle events | Which tool/event triggers this command? |
| MCP server process configuration | Starting an approved or configured local MCP server | What executable and arguments are launched? |

VS Code's official [task documentation](https://code.visualstudio.com/docs/debugtest/tasks#_control-automatic-task-execution) explains that `folderOpen` tasks are subject to workspace trust and automatic-task settings/approval. **A task's presence does not mean it definitely executed.** Distinguish the ability to run from actual execution.

A mundane command can still be important. For example, a `postinstall` script that says `sh ./scripts/setup.sh` gives you another file to inspect. A command's severity is context-dependent, not a verdict about its author's intent.

## 3. Perform a passive scan

ClonePeek is an MIT-licensed, standard-library-only Python CLI. The published **v0.5.1** release audits modeled execution configuration without executing the scanned repository's code:

```sh
# Install/run the trusted scanner from its versioned GitHub source.
# This first installation step needs network access; the scan itself does not.
uvx --from git+https://github.com/harshitethic/clonepeek@v0.5.1 clonepeek /path/to/unfamiliar-repo
```

On any finding, read its **trigger**, source **path and line**, the exact evidence, and the review advice. The tool can follow one hop into explicitly referenced local `.sh` scripts using strict read and path limits; it never executes them. Review both the parent configuration and any referenced script manually.

For a self-contained safe demonstration, checkout ClonePeek itself and run:

```sh
clonepeek examples/indirect-script
```

The example uses a reserved `.invalid` domain and intentionally reports a lifecycle hook plus a risky-looking command at `scripts/setup.sh:4`. Those example commands are **not executed**.

## 4. Keep pull-request checks report-only at first

Once you understand an existing repository's findings, you can review new changes with the published GitHub Action:

```yaml
name: Review execution hooks
on: [pull_request]
permissions:
  contents: read
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: harshitethic/clonepeek@v0.5.1
        with:
          changed-since: ${{ github.event.pull_request.base.sha }}
          fail-on: none
```

Start with `fail-on: none` because many legitimate repos have ordinary lifecycle hooks. Later, after a human reviews the findings and creates a considered baseline, `fail-on: high` can flag new high/critical heuristic matches. [Action guide](GITHUB-ACTION.md) explains report formats, baseline configuration, CI limitations, and output privacy.

**Review report confidentiality:** although the Action's job summary contains only counts, full reports may contain source excerpts and occasionally secret formats that best-effort redaction misses. Avoid publishing them as public artifacts without inspection.

## 5. Treat findings as review questions, not accusations

Two examples from a [reproducible cross-repository smoke test](CROSS-REPO-SMOKE.md) illustrate the distinction:

- A pinned official Cursor cookbook configuration yielded **seven medium hook-command surfaces**. That's ordinary hook inventory, **not** proof the cookbook is malicious.
- A pinned YappChat configuration yielded **two high VS Code `folderOpen` tasks**. The `high` label highlights an automatically triggered execution surface **under the appropriate trust/approval settings**, not proof of an attack.

The validation checked immutable upstream commits, exact Git blobs, observed paths/line numbers, and reusable Action outputs from a separate GitHub repository. It **did not run any upstream hooks or dependencies**. These two selected smoke tests do **not** establish field detection accuracy.

## 6. Know what the scanner cannot guarantee

ClonePeek deliberately does **not** enumerate every way source code can execute. Examples outside the current coverage include transitive or dynamic shell references, most arbitrary shell expansion, some editor extensions, CI provider-specific execution surfaces, code executed by language imports or build backends, and many remote or runtime-only events. A clean-looking report is **not a green light** to trust an unknown repository.

For its existing modeled surfaces, false positives and false negatives are documented in a [51-case, hand-authored synthetic evaluation](EVALUATION.md). Those numbers should **never** be presented as general malware-detection recall, precision, or safety assurance. The detailed [threat model](THREAT_MODEL.md) is more useful than an inflated one-number score.

## If you maintain a developer tool or GitHub Action

Which first-run config files would you add to this checklist? Do you have an **inert, redacted** fixture where an execution trigger is missed or overclassified? [File a small reproducible issue](https://github.com/harshitethic/clonepeek/issues/14) or open a PR with a test. No credentials, live malicious URLs, or claims of third-party compromise, please.

**Project:** [harshitethic/clonepeek](https://github.com/harshitethic/clonepeek) · **Release:** [v0.5.1](https://github.com/harshitethic/clonepeek/releases/tag/v0.5.1) · **License:** MIT

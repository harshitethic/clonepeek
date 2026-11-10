from clonepeek.detectors import inspect
from clonepeek.formats import render_text
def test_untrusted_path_cannot_control_terminal():
    findings=inspect('bad\x1b[2J\nFAKE/ package.json'.replace(' package','package'),'{"scripts":{"install":"echo ok"}}')
    report=render_text(findings,1,0)
    assert '\x1b' not in report
    assert '\nFAKE' not in report

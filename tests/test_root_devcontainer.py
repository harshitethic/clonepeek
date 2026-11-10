from clonepeek.scanner import scan, recognized
def test_dot_devcontainer(tmp_path):
    (tmp_path/'.devcontainer.json').write_text('{"initializeCommand":"echo setup"}')
    findings,count,skipped=scan(tmp_path)
    assert (count,skipped)==(1,0)
    assert findings[0].rule=='devcontainer-lifecycle'
    assert recognized('project/.devcontainer.json')
    assert not recognized('devcontainer.json')

import pytest
from clonepeek.scanner import scan, ScanError
def test_depth_limit_does_not_silently_claim_clean(tmp_path,monkeypatch):
    monkeypatch.setattr('clonepeek.scanner.MAX_DEPTH',1)
    deep=tmp_path/'one'/'two';deep.mkdir(parents=True)
    (deep/'package.json').write_text('{"scripts":{"install":"echo setup"}}')
    with pytest.raises(ScanError,match='depth'): scan(tmp_path)
def test_ignored_dirs_do_not_trigger_depth_error(tmp_path,monkeypatch):
    monkeypatch.setattr('clonepeek.scanner.MAX_DEPTH',0)
    (tmp_path/'node_modules').mkdir()
    assert scan(tmp_path)==([],0,0)

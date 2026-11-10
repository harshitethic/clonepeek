import pytest
from clonepeek.formats import load_baseline
def test_baseline_depth_is_bounded(tmp_path):
    path=tmp_path/'baseline.json'
    path.write_text('{"schema":"clonepeek-baseline-v1","fingerprints":[],"extra":'+ '['*129+'0'+']'*129+'}')
    with pytest.raises(ValueError,match='nesting'):
        load_baseline(path)
def test_normal_baseline(tmp_path):
    path=tmp_path/'baseline.json'
    path.write_text('{"schema":"clonepeek-baseline-v1","fingerprints":["a"]}')
    assert load_baseline(path)=={'a'}

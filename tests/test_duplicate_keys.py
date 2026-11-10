import pytest
from clonepeek.formats import load_json
from clonepeek.detectors import inspect
def test_duplicate_config_is_not_clean():
    text = '{"scripts":{"install":"bash setup.sh"},"scripts":{}}'
    assert inspect('package.json',text)[0].rule == 'config-parse'
    with pytest.raises(ValueError, match='Duplicate'):
        load_json('{"a": {"x": 1, "x": 2}}')
    assert load_json('{"a":1,"b":{"a":2}}') == {'a':1,'b':{'a':2}}

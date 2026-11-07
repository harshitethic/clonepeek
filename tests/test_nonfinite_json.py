import pytest
from clonepeek.formats import load_json
@pytest.mark.parametrize('value',['NaN','Infinity','-Infinity'])
def test_non_json_numbers(value):
    with pytest.raises(ValueError):
        load_json('{"value":'+value+'}')
def test_quoted_names_are_valid():
    assert load_json('{"value":"NaN"}') == {'value':'NaN'}

import pytest
from clonepeek.formats import load_json
@pytest.mark.parametrize('text',['{,}','[,]','{"x": [,]}'])
def test_empty_collection_comma_is_invalid(text):
    with pytest.raises(ValueError): load_json(text,True)
def test_real_trailing_commas():
    assert load_json('{"x":[1,],}',True)=={'x':[1]}

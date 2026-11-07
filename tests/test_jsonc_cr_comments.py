from clonepeek.formats import load_json, jsonc_to_json
def test_cr_terminates_line_comment():
    text = '{// comment\r"x":1}'
    assert load_json(text, jsonc=True) == {'x':1}
    assert len(jsonc_to_json(text)) == len(text)
    assert '\r' in jsonc_to_json(text)
def test_crlf_and_urls():
    assert load_json('{// x\r\n"url":"https://example.invalid"}',True)['url'].endswith('.invalid')

from clonepeek.formats import line_for
def test_line_endings():
    for sep in ('\r','\n','\r\n'):
        assert line_for(sep.join(['first','second','target']),'target')==3
    assert line_for('missing','target')==1

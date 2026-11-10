from clonepeek.script_review import literal_script_refs
def test_inline_shell_code_is_not_a_script_argument():
    assert literal_script_refs('bash -c setup.sh')==[]
    assert literal_script_refs('bash -ec setup.sh')==[]
    assert literal_script_refs('bash -e setup.sh')==['setup.sh']
    assert literal_script_refs('bash setup.sh')==['setup.sh']

import action_runner
def test_action_preserves_input_baseline(tmp_path):
    path=tmp_path/'baseline.json'
    original='{"schema":"clonepeek-baseline-v1","fingerprints":[]}'
    path.write_text(original)
    assert action_runner.perform({'CLONEPEEK_INPUT_PATH':str(tmp_path),'CLONEPEEK_INPUT_BASELINE':str(path),'CLONEPEEK_INPUT_OUTPUT':str(path)})==2
    assert path.read_text()==original

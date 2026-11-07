import action_runner
def test_output_cannot_inject_workflow_fields(tmp_path):
    outputs=tmp_path/'outputs'
    code=action_runner.perform({'CLONEPEEK_INPUT_PATH':str(tmp_path),'CLONEPEEK_INPUT_OUTPUT':str(tmp_path/'report\nforged=true'),'GITHUB_OUTPUT':str(outputs)})
    assert code==2
    assert not outputs.exists()

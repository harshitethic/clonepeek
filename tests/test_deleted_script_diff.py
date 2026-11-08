import subprocess
from clonepeek.scanner import scan
def test_deleted_referenced_script_is_reported(tmp_path):
    def git(*args):
        subprocess.run(['git','-C',str(tmp_path),*args],check=True,capture_output=True)
    git('init');git('config','user.email','test@example.invalid');git('config','user.name','Test')
    (tmp_path/'package.json').write_text('{"scripts":{"install":"bash setup.sh"}}')
    (tmp_path/'setup.sh').write_text('echo harmless')
    git('add','.');git('commit','-m','fixture')
    (tmp_path/'setup.sh').unlink()
    findings,_,_=scan(tmp_path,'HEAD')
    assert any(f.rule=='referenced-script-unreadable' for f in findings)

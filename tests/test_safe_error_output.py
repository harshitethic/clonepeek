from clonepeek.cli import run
import action_runner
def test_cli_error_sanitizes_untrusted_path(tmp_path,capsys):
    assert run([str(tmp_path/'missing\x1b[2J\nFAKE')])==2
    err=capsys.readouterr().err
    assert '\x1b' not in err and '\nFAKE' not in err
def test_action_error_sanitizes_untrusted_path(tmp_path,capsys):
    assert action_runner.perform({'CLONEPEEK_INPUT_PATH':str(tmp_path/'missing\x1b[2J\nFAKE')})==2
    err=capsys.readouterr().err
    assert '\x1b' not in err and '\nFAKE' not in err

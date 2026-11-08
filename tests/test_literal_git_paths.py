from unittest.mock import patch
from subprocess import CompletedProcess
from pathlib import Path
from clonepeek.scanner import changed_paths
def test_literal_backslash_is_not_a_separator():
    with patch('clonepeek.scanner.subprocess.run',return_value=CompletedProcess([],0,b'a\\b/package.json\0',b'')):
        assert changed_paths(Path('.'),'HEAD')=={'a\\b/package.json'}

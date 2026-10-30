"""Subprocess input isolation, bounded execution, and unusual source filenames."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from bypass_scanner.contracts import MANIFEST
from bypass_scanner.discovery.codeql import execute
from bypass_scanner.repository.snapshot import snapshot


class ExecutionTests(unittest.TestCase):
    def test_build_and_git_cannot_consume_the_parent_protocol_input(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root/'a.py').write_text('safe')
            git = root/'git'
            git.write_text('#!'+sys.executable+'\nimport sys\nassert sys.stdin.buffer.read() == b""\nsys.stdout.buffer.write(b"a.py\\0")\n')
            git.chmod(0o755)
            script = '''
import sys, threading
from pathlib import Path
from bypass_scanner.discovery.codeql import execute
from bypass_scanner.repository.snapshot import snapshot
root=Path(sys.argv[1])
execute([sys.executable,'-c','import sys; assert sys.stdin.buffer.read() == b""'],root,root/'logs','build',threading.Event(),2)
assert list(snapshot(root)['files']) == ['a.py']
sys.stdout.buffer.write(sys.stdin.buffer.read())
'''
            frame = b'{"jsonrpc":"2.0","id":17,"method":"ping"}\n'
            result = subprocess.run([sys.executable, '-c', script, str(root)], input=frame, capture_output=True,
                                    env={**os.environ, 'PATH':str(root)}, timeout=8)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual(result.stdout, frame)

    def test_subprocess_has_a_finite_default_timeout(self):
        with tempfile.TemporaryDirectory() as temporary, patch.dict(MANIFEST['resourceDefaults'], {'timeoutSeconds':.1}):
            root = Path(temporary)
            with self.assertRaisesRegex(RuntimeError, 'exceeded its configured timeout'):
                execute([sys.executable, '-c', 'import time; time.sleep(20)'], root, root, 'hang', threading.Event())

    def test_cancellation_still_reports_cancel_when_child_exits_during_signal(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cancel = Mock()
            cancel.is_set.side_effect = [False, True, True]
            child = Mock(pid=123)
            child.poll.side_effect = [None, 0]
            with patch('bypass_scanner.discovery.codeql.subprocess.Popen', return_value=child), \
                 patch('bypass_scanner.discovery.codeql.os.killpg', side_effect=ProcessLookupError):
                with self.assertRaises(InterruptedError):
                    execute(['unused'], root, root, 'cancel', cancel)
            child.wait.assert_called()

    def test_non_utf8_filename_is_audited_without_losing_valid_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            (root/'a.py').write_text('safe')
            # Raw byte names are valid on Linux but cannot be created on every
            # developer filesystem. Exercise both inventory sources explicitly.
            invalid = 'invalid-\udcff.py'
            entries = list(os.scandir(root)) + [SimpleNamespace(name=invalid, path=str(root/invalid))]
            for fallback in (False, True):
                with self.subTest(fallback=fallback), \
                     patch('bypass_scanner.repository.snapshot.subprocess.run',
                           **({'side_effect':OSError('git unavailable')} if fallback else
                              {'return_value':SimpleNamespace(returncode=0, stdout=b'a.py\0invalid-\xff.py\0')})), \
                     patch('bypass_scanner.repository.snapshot.os.scandir', return_value=entries):
                    result = snapshot(root)
                self.assertEqual(list(result['files']), ['a.py'])
                self.assertTrue(any(item['reason']=='filename is not valid UTF-8' for item in result['exclusions']))
                json.dumps(result).encode('utf-8')

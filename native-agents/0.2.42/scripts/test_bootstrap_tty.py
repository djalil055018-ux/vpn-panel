"""Real Linux controlling-terminal regression tests; no network or service calls."""
import errno
import os
from pathlib import Path
import pty
import select
import signal
import subprocess
import sys
import termios
import time
import unittest

ROOT = Path(__file__).resolve().parent
TOKEN = 'fixture-private-bootstrap-token'
LOAD = "import importlib.util; s=importlib.util.spec_from_file_location('tool',%r); t=importlib.util.module_from_spec(s); s.loader.exec_module(t); "


class BootstrapTerminalTests(unittest.TestCase):
    def exercise(self, before=False, redirect_stdin=False, token=TOKEN):
        name = 'vpn-node-tool.before.py' if before else 'vpn-node-tool.py'
        code = LOAD % str(ROOT/name)
        if redirect_stdin:
            code += "import os; f=os.open('/dev/null',os.O_RDONLY); os.dup2(f,0); os.close(f); "
        code += "\ntry:\n value=t.read_bootstrap_credential(); print('MATCH' if value==%r else 'MISMATCH')\nexcept t.ToolError:\n print('REJECTED')\n" % token
        pid, fd = pty.fork()
        if pid == 0:
            os.execv(sys.executable, [sys.executable, '-B', '-c', code])
        output = b''
        sent = False
        status = None
        deadline = time.monotonic()+10
        try:
            while time.monotonic() < deadline:
                if select.select([fd], [], [], .1)[0]:
                    try:
                        chunk = os.read(fd, 8192)
                    except OSError as error:
                        if error.errno == errno.EIO:
                            break
                        raise
                    if not chunk:
                        break
                    output += chunk
                    if b'Bootstrap token (hidden): ' in output and not sent:
                        self.assertFalse(termios.tcgetattr(fd)[3] & termios.ECHO)
                        os.write(fd, token.encode()+b'\n')
                        sent = True
                done, status = os.waitpid(pid, os.WNOHANG)
                if done:
                    pid = None
                    break
            if pid:
                done, status = os.waitpid(pid, os.WNOHANG)
                if done:
                    pid = None
            self.assertEqual(status, 0)
            self.assertNotIn(token.encode(), output)
            self.assertTrue(termios.tcgetattr(fd)[3] & termios.ECHO)
            return output, sent
        finally:
            os.close(fd)
            if pid:
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                os.waitpid(pid, 0)

    def test_original_failure_reproduced_before_prompt(self):
        output, sent = self.exercise(before=True)
        self.assertIn(b'REJECTED', output)
        self.assertFalse(sent)

    def test_hidden_input_and_terminal_restored(self):
        output, sent = self.exercise()
        self.assertIn(b'MATCH', output)
        self.assertTrue(sent)

    def test_redirected_stdin_uses_controlling_terminal(self):
        output, sent = self.exercise(redirect_stdin=True)
        self.assertIn(b'MATCH', output)
        self.assertTrue(sent)

    def test_invalid_token_rejected_without_echo(self):
        output, sent = self.exercise(token='invalid token with spaces')
        self.assertIn(b'REJECTED', output)
        self.assertTrue(sent)

    def test_no_terminal_rejected_without_reading_piped_secret(self):
        code = LOAD % str(ROOT/'vpn-node-tool.py')
        code += "\ntry:\n t.read_bootstrap_credential(); raise AssertionError('unsafe input')\nexcept t.ToolError:\n print('REJECTED')\n"
        p = subprocess.run([sys.executable, '-B', '-c', code], input=TOKEN.encode(), capture_output=True, start_new_session=True, timeout=10)
        self.assertEqual(p.returncode, 0)
        self.assertEqual(p.stdout.strip(), b'REJECTED')
        self.assertNotIn(TOKEN.encode(), p.stdout+p.stderr)


if __name__ == '__main__':
    unittest.main()

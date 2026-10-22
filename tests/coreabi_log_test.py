import ast
import io
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
from types import SimpleNamespace
import unittest


class CoreAbiLogTest(unittest.TestCase):
    def load_runner(self, output, console):
        workflow = (Path(__file__).resolve().parents[1] / '.github/workflows/coreabi.yml').read_text()
        step = workflow.split('      - name: Verify formal C ABI, protocol session and authentication\n', 1)[1]
        source = textwrap.dedent(step.split('        run: |\n', 1)[1].split('\n      - name:', 1)[0])
        function = next(node for node in ast.parse(source).body if isinstance(node, ast.FunctionDef) and node.name == 'run')
        namespace = {'output': output, 'subprocess': subprocess, 'sys': SimpleNamespace(stdout=SimpleNamespace(buffer=console), exit=sys.exit)}
        exec(compile(ast.Module(body=[function], type_ignores=[]), '<coreabi workflow>', 'exec'), namespace)
        return namespace['run']

    def test_partial_output_reaches_console_and_artifact_before_command_finishes(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder)
            console = io.BytesIO()
            run = self.load_runner(output, console)
            release = output / 'release'
            code = ('import pathlib,sys,time; print("in-progress", end="", flush=True); '
                    'release=pathlib.Path(sys.argv[1]); '
                    '\nwhile not release.exists(): time.sleep(0.01)')
            errors = []
            def invoke():
                try:
                    run('build', [sys.executable, '-c', code, str(release)])
                except BaseException as error:
                    errors.append(error)
            worker = threading.Thread(target=invoke)
            worker.start()
            try:
                deadline = time.monotonic() + 5
                log = output / 'build.log'
                while time.monotonic() < deadline and (not log.exists() or log.read_bytes() != b'in-progress' or console.getvalue() != b'in-progress'):
                    time.sleep(0.01)
                self.assertTrue(worker.is_alive(), 'fixture must still be running when progress is observed')
                self.assertTrue(log.exists(), 'artifact log must be available while the command is still running')
                self.assertEqual(log.read_bytes(), b'in-progress')
                self.assertEqual(console.getvalue(), b'in-progress')
            finally:
                release.touch()
                worker.join(5)
            self.assertFalse(worker.is_alive())
            self.assertEqual(errors, [])

    def test_failure_keeps_stderr_and_exit_status(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder)
            console = io.BytesIO()
            run = self.load_runner(output, console)
            with self.assertRaises(SystemExit) as error:
                run('build', [sys.executable, '-c', 'import sys; sys.stderr.buffer.write(b"compile failed\\n"); sys.exit(7)'])
            self.assertEqual(error.exception.code, 7)
            self.assertEqual((output / 'build.log').read_bytes(), b'compile failed\n')
            self.assertEqual(console.getvalue(), b'compile failed\n')


if __name__ == '__main__':
    unittest.main()

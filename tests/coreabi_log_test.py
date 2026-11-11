import importlib.util
import io
from pathlib import Path
from unittest.mock import patch
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest


spec = importlib.util.spec_from_file_location(
    'run_coreabi', Path(__file__).resolve().parent / 'platform/run_coreabi.py')
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class CoreAbiLogTest(unittest.TestCase):
    def test_partial_output_reaches_console_and_artifact_before_command_finishes(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder)
            console = io.BytesIO()
            release = output / 'release'
            code = ('import pathlib,sys,time; print("in-progress", end="", flush=True); '
                    'release=pathlib.Path(sys.argv[1]); '
                    '\nwhile not release.exists(): time.sleep(0.01)')
            errors = []
            def invoke():
                try:
                    with patch.object(runner, 'sys', SimpleNamespace(stdout=SimpleNamespace(buffer=console), exit=sys.exit)):
                        runner.run(output, 'build', [sys.executable, '-c', code, str(release)])
                except BaseException as error:
                    errors.append(error)
            worker = threading.Thread(target=invoke)
            worker.start()
            try:
                deadline = time.monotonic() + 5
                log = output / 'build.log'
                while time.monotonic() < deadline and (not log.exists() or log.read_bytes() != b'in-progress' or console.getvalue() != b'RUN: build\nin-progress'):
                    time.sleep(0.01)
                self.assertTrue(worker.is_alive(), 'fixture must still be running when progress is observed')
                self.assertTrue(log.exists(), 'artifact log must be available while the command is still running')
                self.assertEqual(log.read_bytes(), b'in-progress')
                self.assertEqual(console.getvalue(), b'RUN: build\nin-progress')
            finally:
                release.touch()
                worker.join(5)
            self.assertFalse(worker.is_alive())
            self.assertEqual(errors, [])

    def test_failure_keeps_stderr_and_exit_status(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder)
            console = io.BytesIO()
            with patch.object(runner, 'sys', SimpleNamespace(stdout=SimpleNamespace(buffer=console), exit=sys.exit)), \
                    self.assertRaises(SystemExit) as error:
                runner.run(output, 'build', [sys.executable, '-c', 'import sys; sys.stderr.buffer.write(b"compile failed\\n"); sys.exit(7)'])
            self.assertEqual(error.exception.code, 7)
            self.assertEqual((output / 'build.log').read_bytes(), b'compile failed\n')
            self.assertEqual(console.getvalue(), b'RUN: build\ncompile failed\n')


if __name__ == '__main__':
    unittest.main()

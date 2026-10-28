"""Check local signing-key cleanup; native signature/service checks run on macOS."""
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(sys.platform == 'linux' and shutil.which('openssl'), 'Linux signing lifecycle check')
class MacSigningLifecycleTest(unittest.TestCase):
    def test_local_identity_cleanup_on_success_import_and_sign_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tools = root / 'tools'
            tools.mkdir()
            driver = tools / 'platform-tool'
            driver.write_text('''#!/usr/bin/env python3
import json, os, pathlib, sys
name=pathlib.Path(sys.argv[0]).name
args=sys.argv[1:]
if name=='uuidgen':
    import uuid
    print(uuid.uuid4())
elif name=='security':
    if args[0]=='create-keychain': pathlib.Path(args[-1]).touch()
    elif args[0]=='delete-keychain': pathlib.Path(args[-1]).unlink()
    elif args[0]=='import' and os.environ['FAIL_PHASE']=='import': sys.exit(17)
elif name=='codesign':
    keychain=pathlib.Path(args[args.index('--keychain')+1])
    assert keychain.is_file() and (keychain.parent/'identity.key').is_file()
    with open(os.environ['SIGN_LOG'],'a') as log:
        log.write(json.dumps({'keychain':str(keychain),'signer':args[args.index('--sign')+1]})+'\\n')
    if os.environ['FAIL_PHASE']=='sign': sys.exit(17)
    if os.environ['FAIL_PHASE']=='cancel':
        import time
        time.sleep(20)
''')
            driver.chmod(0o700)
            for name in ('security', 'uuidgen', 'codesign'):
                (tools / name).symlink_to(driver)
            bundle = root / 'JustConnect.app'
            bundle.mkdir()
            scratch = root / 'scratch'
            scratch.mkdir()
            sentinel = scratch / 'keep'
            sentinel.write_text('unrelated')
            log = root / 'signatures.jsonl'
            for phase in ('', 'import', 'sign', 'cancel'):
                with self.subTest(phase=phase):
                    log.unlink(missing_ok=True)
                    environment = dict(os.environ, PATH=str(tools)+os.pathsep+os.environ['PATH'],
                        TMPDIR=str(scratch), SIGN_LOG=str(log), FAIL_PHASE=phase)
                    process = subprocess.Popen(['bash', str(ROOT / 'scripts/macos-sign-app.sh'), str(bundle)],
                        cwd=ROOT, env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
                    try:
                        if phase == 'cancel':
                            deadline = time.monotonic()+5
                            while not log.exists() and process.poll() is None and time.monotonic() < deadline:
                                time.sleep(.01)
                            self.assertTrue(log.exists(), 'Signing did not reach the cancellation point')
                            os.killpg(process.pid, signal.SIGTERM)
                        _, error = process.communicate(timeout=30)
                    finally:
                        if process.poll() is None:
                            os.killpg(process.pid, signal.SIGKILL)
                            process.communicate()
                    self.assertEqual(process.returncode, 143 if phase == 'cancel' else 17 if phase else 0,
                                     error.decode(errors='replace'))
                    self.assertEqual(list(scratch.iterdir()), [sentinel], 'Temporary private key or keychain survived')
                    self.assertEqual(sentinel.read_text(), 'unrelated')
                    if not phase:
                        signatures = [json.loads(line) for line in log.read_text().splitlines()]
                        self.assertEqual(len(signatures), 3)
                        self.assertEqual(len({item['signer'] for item in signatures}), 1)
                        self.assertEqual(len(signatures[0]['signer']), 40)
                        self.assertTrue(all(not Path(item['keychain']).exists() for item in signatures))


if __name__ == '__main__':
    unittest.main()

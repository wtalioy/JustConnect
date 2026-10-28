"""Exercise the production signing script with real Mach-O files and Keychain."""
import hashlib
import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def run(*args, **kwargs):
    try:
        return subprocess.run(list(map(str, args)), check=True, capture_output=True, timeout=60, **kwargs)
    except subprocess.CalledProcessError as error:
        sys.stderr.buffer.write(error.stdout+error.stderr)
        raise


def main():
    assert sys.platform == 'darwin', 'This signing check requires native macOS'
    layout = json.loads((ROOT / 'resource/network-helper-macos.json').read_text())
    app_id = plistlib.loads((ROOT / 'resource/Info.plist').read_bytes())['CFBundleIdentifier']
    keychains = run('/usr/bin/security', 'list-keychains', '-d', 'user').stdout
    with tempfile.TemporaryDirectory(prefix='justconnect-signing-') as directory:
        root = Path(directory)
        app = root / 'JustConnect.app'
        binaries = app / 'Contents/MacOS'
        binaries.mkdir(parents=True)
        host = binaries / 'JustConnect'
        run('/usr/bin/clang', '-x', 'c', '-', '-o', host, input=b'int main(void) { return 0; }\n')
        helper = binaries / layout['executable']
        shutil.copy2(host, helper)

        def info(path, identifier, executable, kind='APPL'):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(plistlib.dumps(dict(CFBundleIdentifier=identifier, CFBundleExecutable=executable,
                CFBundlePackageType=kind, CFBundleVersion='1', CFBundleShortVersionString='1')))

        info(app / 'Contents/Info.plist', app_id, host.name)
        framework = app / 'Contents/Frameworks/QtWebEngineCore.framework'
        version = framework / 'Versions/A'
        version.mkdir(parents=True)
        library = version / 'QtWebEngineCore'
        run('/usr/bin/clang', '-dynamiclib', '-x', 'c', '-', '-o', library,
            '-install_name', '@rpath/QtWebEngineCore.framework/Versions/A/QtWebEngineCore',
            input=b'int fixture(void) { return 0; }\n')
        info(version / 'Resources/Info.plist', app_id+'.signing.framework', library.name, 'FMWK')
        (framework / 'Versions/Current').symlink_to('A')
        for name in ('QtWebEngineCore', 'Resources', 'Helpers'):
            (framework / name).symlink_to('Versions/Current/'+name)
        web = version / 'Helpers/QtWebEngineProcess.app'
        (web / 'Contents/MacOS').mkdir(parents=True)
        (web / 'Contents/Resources').mkdir()
        web_host = web / 'Contents/MacOS/QtWebEngineProcess'
        shutil.copy2(host, web_host)
        info(web / 'Contents/Info.plist', app_id+'.signing.webengine', web_host.name)
        (web / 'Contents/Resources/QtWebEngineProcess.entitlements').write_bytes(plistlib.dumps({}))

        scratch = root / 'private-signing'
        scratch.mkdir()
        run('/bin/bash', ROOT / 'scripts/macos-sign-app.sh', app, cwd=ROOT,
            env=dict(os.environ, TMPDIR=str(scratch)))
        run('/usr/bin/codesign', '--verify', '--deep', '--strict', app)
        leaves = []
        for index, path in enumerate((app, helper, web_host)):
            facts = run('/usr/bin/codesign', '--display', '--verbose=4', path).stderr.decode()
            assert 'runtime' in facts, facts
            if path == helper:
                assert 'Identifier='+app_id+layout['service_suffix'] in facts, facts
            prefix = root / ('certificate-'+str(index))
            run('/usr/bin/codesign', '--display', '--extract-certificates='+str(prefix), path)
            leaves.append(hashlib.sha256(Path(str(prefix)+'0').read_bytes()).hexdigest())
        assert len(set(leaves)) == 1, 'App/helper/WebEngine have different signing identities'
        assert not list(scratch.iterdir()), 'Private signing material survived'
    assert run('/usr/bin/security', 'list-keychains', '-d', 'user').stdout == keychains
    print('PASS: real local signing, same leaf, hardened roles, deep verification and key cleanup; no external credentials')


if __name__ == '__main__':
    main()

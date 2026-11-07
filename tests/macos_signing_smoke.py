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
    assert os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('RUNNER_OS') == 'macOS', \
        'Service registration checks require a disposable runner'
    layout = json.loads((ROOT / 'resource/network-helper-macos.json').read_text())
    app_id = plistlib.loads((ROOT / 'resource/Info.plist').read_bytes())['CFBundleIdentifier']
    keychains = run('/usr/bin/security', 'list-keychains', '-d', 'user').stdout
    with tempfile.TemporaryDirectory(prefix='justconnect-signing-') as directory:
        root = Path(directory)
        app = root / 'JustConnect.app'
        binaries = app / 'Contents/MacOS'
        binaries.mkdir(parents=True)
        host = binaries / 'JustConnect'
        source = b'''
#import <Foundation/Foundation.h>
#import <ServiceManagement/ServiceManagement.h>
#include <stdio.h>
#include <string.h>
extern int fixture(void);
int main(int argc, char **argv) {
    if (fixture() != 42) return 2;
    if (argc != 3 || strcmp(argv[1], "--registration-probe")) return 0;
    @autoreleasepool {
        SMAppService *service = [SMAppService daemonServiceWithPlistName:[NSString stringWithUTF8String:argv[2]]];
        if (service.status != SMAppServiceStatusNotRegistered && service.status != SMAppServiceStatusNotFound) {
            fprintf(stderr, "Refuse pre-existing service registration: %ld\\n", (long)service.status);
            return 1;
        }
        NSError *error = nil;
        BOOL registered = [service registerAndReturnError:&error];
        SMAppServiceStatus status = service.status;
        fprintf(stderr, "SMAppService registered=%d status=%ld error=%s\\n", registered, (long)status,
            error ? error.description.UTF8String : "none");
        BOOL accepted = status == SMAppServiceStatusEnabled || status == SMAppServiceStatusRequiresApproval;
        if (registered || accepted) {
            error = nil;
            if (![service unregisterAndReturnError:&error]) {
                fprintf(stderr, "Cannot remove owned registration: %s\\n", error.description.UTF8String);
                return 1;
            }
        }
        return accepted ? 0 : 1;
    }
}
'''
        helper = binaries / layout['executable']

        def info(path, identifier, executable, kind='APPL'):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(plistlib.dumps(dict(CFBundleIdentifier=identifier, CFBundleExecutable=executable,
                CFBundlePackageType=kind, CFBundleVersion='1', CFBundleShortVersionString='1')))

        info(app / 'Contents/Info.plist', app_id, host.name)
        daemon_name = app_id+layout['service_suffix']+'.plist'
        daemon = app / 'Contents/Library/LaunchDaemons' / daemon_name
        daemon.parent.mkdir(parents=True)
        launch = (ROOT / 'resource/network-helper-macos.plist.in').read_text().replace(
            '@JC_MAC_HELPER_ID@', app_id+layout['service_suffix']).replace('@JC_MAC_HELPER_EXECUTABLE@', helper.name)
        daemon.write_text(launch)
        framework = app / 'Contents/Frameworks/QtCore.framework'
        version = framework / 'Versions/A'
        version.mkdir(parents=True)
        library = version / 'QtCore'
        run('/usr/bin/clang', '-dynamiclib', '-x', 'c', '-', '-o', library,
            '-install_name', '@rpath/QtCore.framework/Versions/A/QtCore',
            input=b'int fixture(void) { return 42; }\n')
        run('/usr/bin/clang', '-x', 'objective-c', '-', '-x', 'none', library,
            '-Wl,-rpath,@executable_path/../Frameworks', '-framework', 'Foundation',
            '-framework', 'ServiceManagement', '-o', host, input=source)
        shutil.copy2(host, helper)
        info(version / 'Resources/Info.plist', app_id+'.signing.framework', library.name, 'FMWK')
        (framework / 'Versions/Current').symlink_to('A')
        for name in ('QtCore', 'Resources'):
            (framework / name).symlink_to('Versions/Current/'+name)
        scratch = root / 'private-signing'
        scratch.mkdir()
        run('/bin/bash', ROOT / 'scripts/macos-sign-app.sh', app, cwd=ROOT,
            env=dict(os.environ, TMPDIR=str(scratch)))
        run('/usr/bin/codesign', '--verify', '--deep', '--strict', app)
        leaves = []
        for index, path in enumerate((app, helper, library)):
            facts = run('/usr/bin/codesign', '--display', '--verbose=4', path).stderr.decode()
            assert 'runtime' in facts, facts
            if path == helper:
                assert 'Identifier='+app_id+layout['service_suffix'] in facts, facts
            prefix = root / ('certificate-'+str(index))
            run('/usr/bin/codesign', '--display', '--extract-certificates='+str(prefix), path)
            leaves.append(hashlib.sha256(Path(str(prefix)+'0').read_bytes()).hexdigest())
        assert len(set(leaves)) == 1, 'App/helper/framework have different signing identities'
        assert not list(scratch.iterdir()), 'Private signing material survived'
        run(helper)
        registration = run(host, '--registration-probe', daemon_name)
        print(registration.stderr.decode(), end='')
    assert run('/usr/bin/security', 'list-keychains', '-d', 'user').stdout == keychains
    print('PASS: local signing, same leaf, hardened roles, library loading, service registration and key cleanup')


if __name__ == '__main__':
    main()

"""Exercise the production signing script with real Mach-O files and Keychain."""
import base64
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
#import <Security/Security.h>
#import <ServiceManagement/ServiceManagement.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
extern int fixture(void);
static int cache(const char *operation, const char *path) {
    SecKeychainRef keychain = NULL;
    OSStatus status = SecKeychainOpen(path, &keychain);
    if (status != errSecSuccess || SecKeychainSetUserInteractionAllowed(false) != errSecSuccess) return 4;
    NSMutableDictionary *query = [@{(id)kSecClass:(id)kSecClassGenericPassword,
        (id)kSecAttrService:@"JustConnect signing fixture", (id)kSecAttrAccount:@"one-account",
        (id)kSecUseAuthenticationUI:(id)kSecUseAuthenticationUIFail} mutableCopy];
    NSData *expected = [@"fixture" dataUsingEncoding:NSUTF8StringEncoding];
    bool writing = !strcmp(operation, "--write-cache");
    CFTypeRef data = NULL;
    if (writing) {
        query[(id)kSecUseKeychain] = (id)keychain;
        query[(id)kSecValueData] = expected;
        status = SecItemAdd((CFDictionaryRef)query, NULL);
    } else {
        query[(id)kSecMatchSearchList] = @[(id)keychain];
        query[(id)kSecReturnData] = @YES;
        status = SecItemCopyMatching((CFDictionaryRef)query, &data);
    }
    bool denied = !strcmp(operation, "--deny-cache");
    bool okay = denied ? (status == errSecAuthFailed || status == errSecInteractionNotAllowed)
        : status == errSecSuccess && (writing || (data && CFEqual(data, expected)));
    if (!okay) fprintf(stderr, "Keychain %s failed: %d\\n", operation, (int)status);
    if (data) CFRelease(data);
    CFRelease(keychain);
    return okay ? 0 : 5;
}
int main(int argc, char **argv) {
    if (fixture() != 42) return 2;
    if (argc == 2 && !strcmp(argv[1], "--fixture-version")) return FIXTURE_VERSION;
    if (argc == 3 && (!strcmp(argv[1], "--write-cache") || !strcmp(argv[1], "--read-cache")
        || !strcmp(argv[1], "--deny-cache"))) {
        @autoreleasepool { return cache(argv[1], argv[2]); }
    }
    if (argc == 3 && !strcmp(argv[1], "--load-foreign")) {
        void *handle = dlopen(argv[2], RTLD_NOW);
        if (handle) {
            dlclose(handle);
            return 3;
        }
        fprintf(stderr, "%s\\n", dlerror());
        return 0;
    }
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
        frameworks = app / 'Contents/Frameworks'
        frameworks.mkdir()
        library = frameworks / 'foreign.dylib'
        run('/usr/bin/clang', '-dynamiclib', '-x', 'c', '-', '-o', library,
            input=b'int foreign(void) { return 91; }\n')
        fixture = root / 'fixture.o'
        run('/usr/bin/clang', '-c', '-x', 'c', '-', '-o', fixture,
            input=b'int fixture(void) { return 42; }\n')
        def compile_host(version):
            run('/usr/bin/clang', f'-DFIXTURE_VERSION={version}', '-x', 'objective-c', '-', '-x', 'none', fixture,
                '-framework', 'Foundation', '-framework', 'Security', '-framework', 'ServiceManagement', '-o', host, input=source)

        compile_host(1)
        shutil.copy2(host, helper)
        scratch = root / 'private-signing'
        scratch.mkdir()
        def sign(identity=''):
            run('/bin/bash', ROOT / 'scripts/macos-sign-app.sh', app, cwd=ROOT,
                env=dict(os.environ, TMPDIR=str(scratch), JC_MAC_SIGNING_P12=identity))
            assert not list(scratch.iterdir()), 'Private signing material survived'

        sign()
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
        run(helper)
        rejection = run(host, '--load-foreign', library).stderr.decode()
        assert 'team' in rejection.lower(), rejection
        registration = run(host, '--registration-probe', daemon_name)
        print(registration.stderr.decode(), end='')

        key, certificate, bundle = (root / name for name in ('fixture.key', 'fixture.pem', 'fixture.p12'))
        run('/usr/bin/openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
            '-config', '/dev/stdin', '-keyout', key, '-out', certificate,
            input=b'[req]\nprompt=no\ndistinguished_name=dn\nx509_extensions=ext\n[dn]\nCN=JustConnect local build\n'
                  b'[ext]\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=codeSigning\n')
        run('/usr/bin/openssl', 'pkcs12', '-export', '-inkey', key, '-in', certificate,
            '-out', bundle, '-passout', 'pass:')
        identity = base64.b64encode(bundle.read_bytes()).decode()
        cache_keychain = root / 'cache.keychain-db'
        run('/usr/bin/security', 'create-keychain', '-p', 'fixture', cache_keychain)
        try:
            run('/usr/bin/security', 'unlock-keychain', '-p', 'fixture', cache_keychain)
            sign(identity)
            first = run('/usr/bin/codesign', '--display', '-r-', app).stderr
            run(host, '--write-cache', cache_keychain)
            run(host, '--read-cache', cache_keychain)
            old_binary = hashlib.sha256(host.read_bytes()).digest()
            compile_host(2)
            sign(identity)
            assert hashlib.sha256(host.read_bytes()).digest() != old_binary
            run('/usr/bin/codesign', '--verify', '--deep', '--strict', app)
            assert run('/usr/bin/codesign', '--display', '-r-', app).stderr == first
            run(host, '--read-cache', cache_keychain)
            sign()
            run(host, '--deny-cache', cache_keychain)
        finally:
            run('/usr/bin/security', 'delete-keychain', cache_keychain)
    assert run('/usr/bin/security', 'list-keychains', '-d', 'user').stdout == keychains
    print('PASS: hardened roles, service registration, key cleanup, upgrade cache reuse and rejection of a different signer')


if __name__ == '__main__':
    main()

import copy
import importlib.util
import json
import os
from pathlib import Path
import plistlib
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('verify_package', ROOT / 'scripts/verify-package.py')
package = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package)


class VerifyPackageTest(unittest.TestCase):
    def test_rejects_wrong_source_abi_platform_and_test_driver(self):
        contract = json.loads((ROOT / 'corelib/abi/contract.json').read_text())
        go = next(x.split()[1] for x in (ROOT / 'corelib/go.mod').read_text().splitlines() if x.startswith('go '))
        report = {'ok': True, 'application_version': 'preview', 'core': {
            'test_driver': False, 'abi_version': contract['abi_version'],
            'capabilities': {'embedded_vpn': True}, 'build': {
                'revision': 'a' * 40, 'source_state': 'clean', 'upstream_commit': contract['upstream_commit'],
                'go_version': 'go' + go + '-X:cgocheck2', 'os': 'linux', 'arch': 'arm64'}}}
        package.validate_report(report, 'a' * 40, 'preview', 'linux', 'arm64')
        for path, value in [('ok', False), ('application_version', 'old'), ('core.test_driver', True),
                            ('core.abi_version', 999), ('core.capabilities.embedded_vpn', False),
                            ('core.build.source_state', 'dirty'), ('core.build.revision', 'b' * 40),
                            ('core.build.os', 'windows'), ('core.build.arch', 'amd64'),
                            ('core.build.go_version', 'go0'), ('core.build.upstream_commit', 'bad')]:
            with self.subTest(path=path):
                changed = copy.deepcopy(report)
                target = changed
                keys = path.split('.')
                for key in keys[:-1]:
                    target = target[key]
                target[keys[-1]] = value
                with self.assertRaises(RuntimeError):
                    package.validate_report(changed, 'a' * 40, 'preview', 'linux', 'arm64')

    def test_sdk_environment_cannot_supply_runtime_dependencies(self):
        with patch.dict(os.environ, {'QT_PLUGIN_PATH': '/sdk', 'QML2_IMPORT_PATH': '/sdk',
                                     'LD_LIBRARY_PATH': '/sdk', 'DYLD_FRAMEWORK_PATH': '/sdk',
                                     'PATH': '/sdk', 'TOKEN': 'keep'}):
            env = package.clean_environment()
        self.assertEqual(env['TOKEN'], 'keep')
        for name in ('QT_PLUGIN_PATH', 'QML2_IMPORT_PATH', 'LD_LIBRARY_PATH', 'DYLD_FRAMEWORK_PATH'):
            self.assertNotIn(name, env)
        self.assertNotIn('/sdk', env['PATH'])

    def test_linux_rejects_missing_and_sdk_supplied_qt(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            host = root / 'app'
            def run(*args, **kwargs):
                if args[:2] == ('readelf', '-h'):
                    return 'Machine: AArch64'
                if args[:2] == ('readelf', '-d'):
                    return '(NEEDED) Qt6Core'
                return dependencies
            for dependencies in ('libQt6Core => not found', 'libQt6Core => /usr/lib/libQt6Core.so (0x1)',
                                 'libQt6Core => /opt/sdk/libQt6Core.so (0x1)'):
                with self.subTest(dependencies=dependencies), patch.object(package, 'run', side_effect=run):
                    with self.assertRaises(RuntimeError):
                        package.linux_audit([host], root, 'arm64', {})

    def test_macos_binary_cannot_require_newer_system_than_bundle_declares(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'Contents').mkdir()
            (root / 'Contents/Info.plist').write_bytes(plistlib.dumps({'LSMinimumSystemVersion': '14.4'}))
            def run(*args, **kwargs):
                return {'lipo': 'arm64', 'otool': ('cmd LC_BUILD_VERSION\n minos 26.0\n'
                                                  if args[1] == '-l' else 'app:\n')}[args[0]]
            with patch.object(package, 'run', side_effect=run):
                with self.assertRaisesRegex(RuntimeError, 'Invalid macOS floor'):
                    package.macos_audit([root / 'app'], root, 'arm64', {}, False)

    def test_macos_helper_resolves_its_own_executable_directory(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            helper = root / 'Contents/Helpers/Helper.app/Contents/MacOS/helper'
            dependency = root / 'Contents/Frameworks/libQt.dylib'
            helper.parent.mkdir(parents=True)
            dependency.parent.mkdir(parents=True)
            dependency.touch()
            (root / 'Contents/Info.plist').write_bytes(plistlib.dumps({'LSMinimumSystemVersion': '14.4'}))
            relative = Path(os.path.relpath(dependency, helper.parent)).as_posix()
            def run(*args, **kwargs):
                if args[0] == 'lipo':
                    return 'arm64'
                if args[0] == 'otool':
                    return ('cmd LC_BUILD_VERSION\n minos 14.4.0\n' if args[1] == '-l'
                            else f'helper:\n @executable_path/{relative} (compatibility version 1.0)\n')
                return ''
            with patch.object(package, 'run', side_effect=run), \
                    patch.object(package.platform, 'mac_ver', return_value=('26.0', (), '')), \
                    patch.object(package.subprocess, 'run', return_value=SimpleNamespace(stderr=b'Signature=adhoc')):
                audit = package.macos_audit([helper], root, 'arm64', {}, False)
            self.assertEqual(package.version(audit['binary_minimum']), package.version('14.4'))


if __name__ == '__main__':
    unittest.main()

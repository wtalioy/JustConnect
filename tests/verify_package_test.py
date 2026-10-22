import copy
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import sys
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('verify_package', ROOT / 'scripts/verify-package.py')
package = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package)


class VerifyPackageTest(unittest.TestCase):
    def test_installed_proxy_recovery_worker_is_required_and_runs_with_a_budget(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            facts = {'worker': 'system-proxy-recovery', 'protocol': 1, 'qt': '6.12.0'}
            for platform_name in ('win32', 'darwin', 'linux'):
                with self.subTest(platform=platform_name), patch.object(package.sys, 'platform', platform_name):
                    worker = root / ('JustConnectProxyRecovery.exe' if platform_name == 'win32' else 'JustConnectProxyRecovery')
                    with self.assertRaisesRegex(RuntimeError, 'Missing packaged system proxy recovery worker'):
                        package.check_proxy_recovery(root, {})
                    worker.touch()
                    with patch.object(package, 'run', return_value=json.dumps(facts)) as run:
                        self.assertEqual(package.check_proxy_recovery(root, {}), facts)
                        run.assert_called_once_with(worker, '--version', env={}, timeout=5)
                    for invalid in ([], {}, dict(facts, protocol=True), dict(facts, protocol=2), dict(facts, qt=6)):
                        with patch.object(package, 'run', return_value=json.dumps(invalid)), self.assertRaisesRegex(RuntimeError, 'runtime check'):
                            package.check_proxy_recovery(root, {})
                    with patch.object(package, 'run', side_effect=TimeoutError('worker startup budget')), self.assertRaises(TimeoutError):
                        package.check_proxy_recovery(root, {})
                    worker.unlink()

    def test_installed_dns_reader_is_required_bounded_and_complete(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            with self.assertRaisesRegex(RuntimeError, 'Missing packaged native DNS reader'):
                package.check_windows_dns_reader(root, {})
            reader = root / 'JustConnectDnsReader.exe'
            reader.touch()
            facts = {'interfaces': [], 'clients': [], 'global': {}, 'nrpt': [], 'doh_supported': False, 'doh': []}
            with patch.object(package, 'run', return_value=json.dumps(facts)) as run:
                self.assertEqual(package.check_windows_dns_reader(root, {}), {'interfaces': 0, 'effective_nrpt': 0})
                run.assert_called_once_with(reader, env={}, timeout=10)
            for invalid in ({'interfaces': [], 'nrpt': []}, dict(facts, doh_supported='false')):
                with patch.object(package, 'run', return_value=json.dumps(invalid)), \
                        self.assertRaisesRegex(RuntimeError, 'complete native facts'):
                    package.check_windows_dns_reader(root, {})
            with patch.object(package, 'run', side_effect=TimeoutError('native read budget')), \
                    self.assertRaises(TimeoutError):
                package.check_windows_dns_reader(root, {})

    def test_rejects_obsolete_runtime_anywhere_in_package(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / "package"
            root.mkdir()
            archive = Path(folder) / "package.zip"
            archive.write_bytes(b"archive fixture")
            host = root / 'JustConnect'
            host.touch()
            worker = root / 'JustConnectProxyRecovery'
            worker.touch()
            (root / 'source-revision.txt').write_bytes(b'revision\r\n')
            (root / 'core-toolchain.txt').write_bytes(b'CGO_ENABLED=1\r\n')
            notices = root / 'licenses'
            notices.mkdir()
            for name in ('LICENSE', 'LICENSE.zju-connect', 'LICENSE.ping', 'UPSTREAM.md'):
                (notices / name).touch()
            nested = root / 'nested'
            nested.mkdir()
            output = Path(folder) / "report.json"
            def run(args, **kwargs):
                payload = ({'worker': 'system-proxy-recovery', 'protocol': 1, 'qt': '6.12.0'}
                           if Path(args[0]) == worker else {'runtime': 'static'})
                return SimpleNamespace(returncode=0, stderr=b'', stdout=json.dumps(payload).encode())
            with patch.object(package.subprocess, 'run', side_effect=run), \
                    patch.object(package, 'validate_report'), \
                    patch.object(package, 'linux_audit', return_value={}), \
                    patch.object(package.platform, 'machine', return_value='x86_64'), \
                    patch.object(package.sys, 'platform', 'linux'):
                package.verify(root, host, 'revision', 'preview', output, archive)
                report = json.loads(output.read_text())
                self.assertEqual(report['size_bytes']['archive'], archive.stat().st_size)
                self.assertEqual(report['size_bytes']['installed'], len(b'revision\r\nCGO_ENABLED=1\r\n'))
                self.assertGreater(report['offline_self_test_wall_ms'], 0)
                archive.rename(archive.with_suffix('.hidden'))
                with self.assertRaises(FileNotFoundError):
                    package.verify(root, host, 'revision', 'preview', output, archive)
                archive.with_suffix('.hidden').rename(archive)
                output.unlink()
                for name in ('zju-connect', 'zju-connect.exe', 'ZJU-Connect.EXE', 'core-provenance', 'Wintun.dll'):
                    with self.subTest(name=name):
                        obsolete = nested / name
                        if name == 'core-provenance':
                            obsolete.mkdir()
                        else:
                            obsolete.touch()
                        with self.assertRaisesRegex(RuntimeError, 'Obsolete runtime in package'):
                            package.verify(root, host, 'revision', 'preview', output, archive)
                        self.assertFalse(output.exists())
                        if obsolete.is_dir():
                            obsolete.rmdir()
                        else:
                            obsolete.unlink()

    def test_webengine_probe_uses_bundled_resources_and_cleans_up_on_failure(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            locales = root / 'translations/qtwebengine_locales'
            locales.mkdir(parents=True)
            probe = root / 'source-probe.exe'
            probe.write_bytes(b'probe fixture')
            with self.assertRaisesRegex(RuntimeError, 'Missing WebEngine locale'):
                package.check_windows_webengine(root, probe, {})
            for language in ('en-US', 'zh-CN'):
                (locales / f'{language}.pak').touch()
            def run(args, **kwargs):
                self.assertEqual(Path(args[0]).parent, root)
                self.assertEqual(Path(args[0]).read_bytes(), probe.read_bytes())
                self.assertNotEqual(Path(kwargs['cwd']), root)
                env = kwargs['env']
                for key in ('QTWEBENGINEPROCESS_PATH', 'QTWEBENGINE_RESOURCES_PATH',
                            'QTWEBENGINE_LOCALES_PATH', 'QT_QPA_PLATFORM_PLUGIN_PATH'):
                    self.assertTrue(Path(env[key]).is_relative_to(root))
                self.assertNotIn('QT_PLUGIN_PATH', env)
                return SimpleNamespace(returncode=0, stdout=b'', stderr=b'')
            with patch.object(package.subprocess, 'run', side_effect=run) as called:
                self.assertEqual(package.check_windows_webengine(root, probe, {}), ['en-US', 'zh-CN'])
                self.assertEqual([call.kwargs['env']['QTWEBENGINE_CHROMIUM_FLAGS'] for call in called.call_args_list],
                                 ['--disable-gpu --lang=en-US', '--disable-gpu --lang=zh-CN'])
            with patch.object(package.subprocess, 'run', side_effect=RuntimeError('probe failed')):
                with self.assertRaisesRegex(RuntimeError, 'probe failed'):
                    package.check_windows_webengine(root, probe, {})
            self.assertEqual(list(root.glob('*.exe')), [probe])

    def test_failed_native_command_preserves_utf8_diagnostics(self):
        with self.assertRaisesRegex(RuntimeError, '签名失败'):
            package.run(sys.executable, '-c',
                        "import sys; sys.stderr.buffer.write('签名失败'.encode('utf-8')); sys.exit(7)")

    @unittest.skipUnless(sys.platform == 'win32', 'Windows Authenticode integration')
    def test_native_signature_host_inspects_unsigned_file(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'unsigned.ps1'
            path.write_text('# unsigned signature fixture\n')
            self.assertEqual(package.windows_signature(path), 'NotSigned')

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

    def test_macos_rejects_embedded_sdk_search_path(self):
        def run(*args, **kwargs):
            return 'arm64' if args[0] == 'lipo' else 'cmd LC_RPATH\n path /opt/Qt/lib (offset 12)\n'
        with tempfile.TemporaryDirectory() as folder, patch.object(package, 'run', side_effect=run):
            root = Path(folder)
            with self.assertRaisesRegex(RuntimeError, 'Non-relocatable Mach-O search path'):
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

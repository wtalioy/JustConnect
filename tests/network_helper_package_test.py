import importlib.util
import io
from pathlib import Path, PurePosixPath
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('network_helper_package', ROOT / 'scripts/network_helper_package.py')
package = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package)


def archive(entries):
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode='w:gz') as output:
        for entry, contents in entries:
            entry.size = len(contents)
            output.addfile(entry, io.BytesIO(contents) if entry.isfile() else None)
    return data.getvalue()


class NetworkHelperPackageTest(unittest.TestCase):
    def test_release_metadata_requires_runtime_dependencies_and_exact_source(self):
        revision = 'a' * 40
        policy = (ROOT / 'resource/network-helper.policy.in').read_text().replace('@JC_NETWORK_HELPER_ACTION@', package.LAYOUT['action']).replace('@JC_NETWORK_HELPER_PATH@', package.LAYOUT['executable']).encode()
        metadata = ('Package: justconnect-network-helper\nVersion: 0~git1.' + revision + '\nSection: net\nPriority: optional\n'
                    'Architecture: amd64\nInstalled-Size: 1\nMaintainer: JustConnect\nDescription: System helper\n'
                    'Homepage: https://github.com/wtalioy/JustConnect\nDepends: iproute2, pkexec | policykit-1, systemd, libc6, libstdc++6, libqt6core6t64\n')

        def regular(name, contents):
            entry = tarfile.TarInfo(name)
            entry.mode = 0o755 if name == package.EXECUTABLE else 0o644
            return entry, contents

        files = {package.EXECUTABLE: b'\x7fELF', package.POLICY: policy, package.DOCUMENTATION + 'LICENSE': b'GPL',
                 package.DOCUMENTATION + 'source-revision.txt': (revision + '\n').encode()}
        for kind in ('service', 'timer'):
            text = (ROOT / f'resource/network-helper-recovery.{kind}.in').read_text()
            for key, value in {'JC_NETWORK_HELPER_PATH': package.LAYOUT['executable'],
                               'JC_NETWORK_HELPER_STATE': package.LAYOUT['state_directory'],
                               'JC_NETWORK_HELPER_STATE_RELATIVE': str(PurePosixPath(package.LAYOUT['state_directory']).relative_to('/var/lib')),
                               'JC_NETWORK_HELPER_STATE_PARENT': str(PurePosixPath(package.LAYOUT['state_directory']).relative_to('/var/lib').parent),
                               'JC_NETWORK_HELPER_RECOVERY_UNIT': package.LAYOUT['recovery_unit']}.items():
                text = text.replace('@' + key + '@', value)
            files[package.RECOVERY_UNIT + '.' + kind] = text.encode()
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'helper.deb'
            path.write_bytes(b'archive-hash-fixture')
            for mutation in ('valid', 'runtime', 'architecture', 'side-effect', 'duplicate', 'source', 'version',
                             'manager', 'recovery-executable', 'recovery-privilege', 'recovery-path', 'recovery-dependency', 'timer'):
                text = metadata
                payload = dict(files)
                if mutation == 'runtime':
                    text = text.replace(', libqt6core6t64', '')
                elif mutation == 'architecture':
                    text = text.replace('amd64', 'i386')
                elif mutation == 'side-effect':
                    text += 'Conflicts: unrelated-application\n'
                elif mutation == 'duplicate':
                    text += 'Package: another-package\n'
                elif mutation == 'source':
                    payload[package.DOCUMENTATION + 'source-revision.txt'] = ('b' * 40 + '\n').encode()
                elif mutation == 'version':
                    text = text.replace('0~git1.' + revision, '0~git1.' + 'b' * 40)
                elif mutation == 'manager':
                    text = text.replace(', systemd,', ', libsystemd0,')
                elif mutation.startswith('recovery-'):
                    key = package.RECOVERY_UNIT + '.service'
                    before, after = {'recovery-executable': (package.LAYOUT['executable'], '/bin/sh'),
                                     'recovery-privilege': ('CAP_NET_ADMIN', 'CAP_SYS_ADMIN'),
                                     'recovery-path': (package.LAYOUT['state_directory'], '/'),
                                     'recovery-dependency': ('Description=', 'Requires=unrelated.service\nDescription=')}[mutation]
                    payload[key] = payload[key].replace(before.encode(), after.encode())
                elif mutation == 'timer':
                    key = package.RECOVERY_UNIT + '.timer'
                    payload[key] = payload[key].replace((package.LAYOUT['recovery_unit'] + '.service').encode(), b'unrelated.service')
                responses = [b'debian-binary\ncontrol.tar.xz\ndata.tar.xz\n', b'2.0\n', archive([regular('control', text.encode())]),
                             archive([regular(name, contents) for name, contents in payload.items()])]
                responses[0] = responses[0].decode()
                with self.subTest(mutation=mutation), patch.object(package.subprocess, 'check_output', side_effect=responses):
                    if mutation == 'valid':
                        self.assertEqual(package.inspect_package(path, revision)[0], files)
                    else:
                        with self.assertRaises(ValueError):
                            package.inspect_package(path, revision)

    def test_privileged_archive_rejects_aliases_links_writable_or_foreign_files(self):
        name = package.EXECUTABLE
        entry = tarfile.TarInfo(name)
        entry.mode = 0o755
        self.assertEqual(package.read_tar(archive([(entry, b'ELF')]), {name}, name), {name: b'ELF'})
        for mutation in ('traversal', 'absolute', 'duplicate', 'link', 'owner', 'group', 'writable', 'setuid', 'unexpected'):
            with self.subTest(mutation=mutation):
                value = tarfile.TarInfo(name)
                value.mode = 0o755
                if mutation == 'traversal':
                    value.name = '../' + name
                elif mutation == 'absolute':
                    value.name = '/' + name
                elif mutation == 'link':
                    value.type = tarfile.SYMTYPE
                    value.linkname = '/bin/sh'
                elif mutation == 'owner':
                    value.uid = 1000
                elif mutation == 'group':
                    value.gid = 1000
                elif mutation == 'writable':
                    value.mode |= 0o020
                elif mutation == 'setuid':
                    value.mode |= 0o4000
                elif mutation == 'unexpected':
                    value.name = 'usr/bin/arbitrary-helper'
                rows = [(value, b'ELF')] * (2 if mutation == 'duplicate' else 1)
                with self.assertRaises(ValueError):
                    package.read_tar(archive(rows), {name}, name)
        directory = tarfile.TarInfo('./')
        directory.type, directory.mode, directory.uid = tarfile.DIRTYPE, 0o777, 1000
        with self.assertRaises(ValueError):
            package.read_tar(archive([(directory, b'')]), {name}, name)
        script = tarfile.TarInfo('postinst')
        script.mode = 0o755
        with self.assertRaises(ValueError):
            package.read_tar(archive([(script, b'#!/bin/sh\n')]), {'control', 'md5sums'})

    def test_authorization_cannot_expand_target_account_or_retain_privilege(self):
        policy = (ROOT / 'resource/network-helper.policy.in').read_text().replace('@JC_NETWORK_HELPER_ACTION@', package.LAYOUT['action']).replace('@JC_NETWORK_HELPER_PATH@', package.LAYOUT['executable'])
        package.verify_policy(policy)
        for invalid in (
            policy.replace('<allow_any>no', '<allow_any>yes'),
            policy.replace('<allow_inactive>no', '<allow_inactive>auth_admin'),
            policy.replace('<allow_active>auth_admin', '<allow_active>auth_admin_keep'),
            policy.replace(package.LAYOUT['executable'], '/home/user/JustConnectNetworkHelper'),
            policy.replace('</action>', '<annotate key="org.freedesktop.policykit.exec.allow_gui">true</annotate></action>'),
            policy.replace('</policyconfig>', policy[policy.index('  <action'):policy.index('</policyconfig>')] + '</policyconfig>'),
        ):
            with self.subTest(policy=invalid), self.assertRaises(ValueError):
                package.verify_policy(invalid)


if __name__ == '__main__':
    unittest.main()
